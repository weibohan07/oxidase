//! Validation-only, finite C scenarios. These are ordinary authenticated
//! control operations and wire clients, never a second runtime publisher.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, Write as _};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, header};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use oxidase_runtime::{AdminBearerToken, MAX_ADMIN_BEARER_TOKEN_BYTES};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio_rustls::rustls;

use super::client::{self, ResourceDataClient, ResourceRequest};
use super::resource_campaign::{FaultInterval, Faults, resource_source};
use super::resource_evidence::JsonLines;
use super::resource_identity::monotonic_ns;
use super::{
    FixtureCommand, FixtureProcess, HEALTHY_DNS_TTL_SECONDS, ResourceArguments, ResourceCampaign,
    SoakError, fail, io_error, json_error,
};

pub(super) struct ControlPlan<'a> {
    pub args: &'a ResourceArguments,
    pub root: &'a Path,
    pub a: &'a str,
    pub b: &'a str,
    pub faults: &'a Faults,
    pub gateway_address: SocketAddr,
    pub h1: Arc<rustls::ClientConfig>,
    pub h2: Arc<rustls::ClientConfig>,
}

const ADMIN_DEADLINE: Duration = Duration::from_secs(3);
const CONTROL_WIRE_DEADLINE: Duration = Duration::from_secs(9);
const STATE_DEADLINE: Duration = Duration::from_secs(6);
// Fixed before measurement, not extended because an observed error is awkward:
// 8 s logical deadline + 500 ms ejection + at most 1 s fixture refresh, rounded up.
const SETTLING: Duration = Duration::from_secs(10);
const RECOVERY_NS: u64 = 12_000_000_000;
// A validation witness, not a replacement for any production request timeout.
// All before/probe/after operations must finish inside this fixed window.
const SRV_AAAA_WITNESS_NS: u64 = 30_000_000_000;
const SRV_POSITIVE_METRIC: &str =
    "oxidase_discovery_queries_total{cluster=\"upstream\",family=\"srv\",result=\"positive\"}";
const MAX_PROBE_FILE: u64 = 64 * 1024 * 1024;
const MAX_PROBE_ROW: usize = 64 * 1024;

struct Driver(Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>);
impl Driver {
    async fn close(&mut self) -> Value {
        let Some(task) = self.0.as_mut() else {
            return json!({"result":"not_created","join_acknowledged":true,"abort_requested":false});
        };
        let abort_requested = !task.is_finished();
        if abort_requested {
            task.abort();
        }
        let exit = match tokio::time::timeout(Duration::from_secs(1), task).await {
            Ok(Ok(Ok(()))) => "completed",
            Ok(Ok(Err(_))) => "error",
            Ok(Err(error)) if error.is_cancelled() => "cancelled",
            Ok(Err(_)) => "panicked",
            Err(_) => "timeout",
        };
        if exit != "timeout" {
            self.0.take();
        }
        json!({"result":exit,"join_acknowledged":exit!="timeout","abort_requested":abort_requested,"exit_ns":monotonic_ns().ok()})
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

async fn admin(root: &Path, path: &'static str) -> Result<Bytes, SoakError> {
    let mut operation = ControlOperation::begin("admin_read", json!({"path":path}))?;
    let mut driver = Driver(None);
    let mut status = None;
    let mut received = 0_u64;
    let result = async {
        let credential = root.join("admin.token");
        let metadata = std::fs::symlink_metadata(&credential).map_err(io_error)?;
        if !metadata.is_file() || metadata.len() > MAX_ADMIN_BEARER_TOKEN_BYTES as u64 + 2 {
            return Err(fail("resource.control_admin_token_shape"));
        }
        let mut bytes = std::fs::read(credential).map_err(io_error)?;
        let token = AdminBearerToken::parse_file_bytes(&bytes)
            .map_err(|_| fail("resource.control_admin_token_invalid"));
        bytes.fill(0);
        let token = token?;
        tokio::time::timeout(ADMIN_DEADLINE, async {
            let io = tokio::net::UnixStream::connect(root.join("admin.sock"))
                .await
                .map_err(io_error)?;
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
                .await
                .map_err(io_error)?;
            driver.0 = Some(tokio::spawn(connection));
            let response = sender
                .send_request(
                    Request::builder()
                        .uri(path)
                        .header(header::HOST, "admin.test")
                        .header(header::AUTHORIZATION, token.authorization_header())
                        .body(Empty::<Bytes>::new())
                        .map_err(io_error)?,
                )
                .await
                .map_err(io_error)?;
            status = Some(response.status().as_u16());
            if !response.status().is_success() {
                return Err(fail("resource.control_admin_rejected"));
            }
            let mut body = response.into_body();
            let mut result = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(io_error)?;
                if frame.trailers_ref().is_some() {
                    return Err(fail("resource.control_admin_trailers"));
                }
                if let Some(data) = frame.data_ref() {
                    received = received.saturating_add(data.len() as u64);
                    if result
                        .len()
                        .checked_add(data.len())
                        .is_none_or(|size| size > 2 * 1024 * 1024)
                    {
                        return Err(fail("resource.control_admin_limit"));
                    }
                    result.extend_from_slice(data);
                }
            }
            drop(body);
            drop(sender);
            Ok(Bytes::from(result))
        })
        .await
        .map_err(|_| fail("resource.control_admin_timeout"))?
    }
    .await;
    let exit = driver.close().await;
    let result = if exit["join_acknowledged"] != true
        || matches!(
            exit["result"].as_str(),
            Some("error" | "panicked" | "timeout")
        )
        || exit["result"] == "cancelled" && exit["abort_requested"] != true
    {
        Err(fail("resource.control_admin_driver_failure"))
    } else {
        result
    };
    operation.finish(if result.is_ok() { "completed" } else { "failed" }, json!({"status":status,"body_bytes":received,"body_complete":result.is_ok(),"driver_exit":exit,"error":result.as_ref().err().map(ToString::to_string)}))?;
    result
}

async fn document(root: &Path, path: &'static str) -> Result<Value, SoakError> {
    serde_json::from_slice(&admin(root, path).await?).map_err(json_error)
}
async fn runtime(root: &Path) -> Result<Value, SoakError> {
    document(root, "/api/v1/runtime").await
}
async fn clusters(root: &Path) -> Result<Value, SoakError> {
    document(root, "/api/v1/clusters").await
}
async fn metrics(root: &Path) -> Result<String, SoakError> {
    String::from_utf8(admin(root, "/metrics").await?.to_vec()).map_err(io_error)
}

fn upstream_cluster(value: &Value) -> Result<&Value, SoakError> {
    let mut matching = value["clusters"]
        .as_array()
        .ok_or_else(|| fail("resource.control_cluster_unavailable"))?
        .iter()
        .filter(|row| row["cluster"] == "upstream");
    let cluster = matching
        .next()
        .ok_or_else(|| fail("resource.control_cluster_unavailable"))?;
    if matching.next().is_some() {
        return Err(fail("resource.control_cluster_duplicate"));
    }
    Ok(cluster)
}
fn endpoint_counter(value: &Value, name: &str) -> Result<u64, SoakError> {
    upstream_cluster(value)?["endpoints"]
        .as_array()
        .ok_or_else(|| fail("resource.control_endpoints_unavailable"))?
        .iter()
        .try_fold(0_u64, |sum, row| {
            sum.checked_add(
                row[name]
                    .as_u64()
                    .ok_or_else(|| fail(format!("resource.control_counter_unavailable:{name}")))?,
            )
            .ok_or_else(|| fail("resource.control_counter_overflow"))
        })
}
fn counter(value: &Value, name: &str) -> Result<u64, SoakError> {
    value[name]
        .as_u64()
        .ok_or_else(|| fail(format!("resource.control_counter_unavailable:{name}")))
}
fn metric(text: &str, key: &str) -> Result<u64, SoakError> {
    let mut matching = text
        .lines()
        .filter_map(|line| line.rsplit_once(' ').filter(|(name, _)| *name == key));
    let (_, value) = matching
        .next()
        .ok_or_else(|| fail(format!("resource.control_metric_unavailable:{key}")))?;
    if matching.next().is_some() {
        return Err(fail("resource.control_metric_duplicate"));
    }
    value
        .parse::<u64>()
        .map_err(|_| fail("resource.control_metric_noninteger"))
}

fn coverage(events: &mut JsonLines, name: &str, evidence: Value) -> Result<(), SoakError> {
    events
        .write(json!({"kind":"coverage","t_ns":monotonic_ns()?,"name":name,"evidence":evidence}))?;
    events.flush()
}
fn fixture_coverage(
    events: &mut JsonLines,
    name: &str,
    field: &str,
    before: &Value,
    after: &Value,
) -> Result<(), SoakError> {
    let first = counter(before, field)?;
    let last = counter(after, field)?;
    if last <= first {
        return Err(fail(format!("resource.control_not_triggered:{name}")));
    }
    coverage(
        events,
        name,
        json!({"source":"fixture_counter","name":field,"before":first,"after":last,"before_raw":before,"after_raw":after}),
    )
}
fn metric_coverage(
    events: &mut JsonLines,
    name: &str,
    key: &str,
    before: &str,
    after: &str,
) -> Result<(), SoakError> {
    let first = metric(before, key)?;
    let last = metric(after, key)?;
    if last <= first {
        return Err(fail(format!("resource.control_not_triggered:{name}")));
    }
    coverage(
        events,
        name,
        json!({"source":"metrics_counter","name":key,"before":first,"after":last,"before_metrics":before,"after_metrics":after}),
    )
}

async fn dns_change(
    plan: &ControlPlan<'_>,
    dns: &mut FixtureProcess,
    mode: &str,
    ttl: u32,
    round: usize,
    events: &mut JsonLines,
) -> Result<Value, SoakError> {
    let before = runtime(plan.root).await?;
    let ack = dns
        .recorded_command(FixtureCommand::Dns {
            mode: mode.into(),
            ttl,
        })
        .await?;
    let after = runtime(plan.root).await?;
    events.write(json!({"kind":"control","t_ns":monotonic_ns()?,"action":"dns","request_id":round,"mode":mode,"ttl":ttl,"before_runtime":before,"after_runtime":after,"fixture_ack":ack}))?;
    events.flush()?;
    if before != after {
        return Err(fail("resource.control_dns_changed_published_runtime"));
    }
    Ok(ack)
}

/// A sole controller appends this journal. No registry or process-owned resource
/// is cached to recover its sequence: only the last bounded raw row is read.
struct ProbeJournal {
    file: File,
    bytes: u64,
    sequence: u64,
    schema: &'static str,
}
impl ProbeJournal {
    fn open(output: &Path) -> Result<Self, SoakError> {
        Self::named(
            output,
            "control-probes.jsonl",
            "oxidase.resource-control-probe/v1",
        )
    }
    fn named(output: &Path, name: &'static str, schema: &'static str) -> Result<Self, SoakError> {
        let path = output.join(name);
        if std::fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
            return Err(fail("resource.control_probe_file_shape"));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(io_error)?;
        let bytes = file.metadata().map_err(io_error)?.len();
        if bytes > MAX_PROBE_FILE {
            return Err(fail("resource.control_probe_capacity"));
        }
        let mut sequence = 0;
        if bytes > 0 {
            let count = bytes.min(MAX_PROBE_ROW as u64);
            file.seek(std::io::SeekFrom::End(-(count as i64)))
                .map_err(io_error)?;
            let mut tail = vec![0; count as usize];
            file.read_exact(&mut tail).map_err(io_error)?;
            if tail.last() != Some(&b'\n') {
                return Err(fail("resource.control_probe_truncated"));
            }
            let row = tail
                .split(|byte| *byte == b'\n')
                .rev()
                .find(|row| !row.is_empty())
                .ok_or_else(|| fail("resource.control_probe_empty"))?;
            let row: Value = serde_json::from_slice(row).map_err(json_error)?;
            if row["schema_version"] != schema {
                return Err(fail("resource.control_journal_schema"));
            }
            sequence = row["writer_seq"]
                .as_u64()
                .ok_or_else(|| fail("resource.control_probe_sequence"))?;
        }
        Ok(Self {
            file,
            bytes,
            sequence,
            schema,
        })
    }
    fn write(&mut self, mut row: Value) -> Result<(), SoakError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| fail("resource.control_probe_sequence"))?;
        row["schema_version"] = self.schema.into();
        row["writer_seq"] = self.sequence.into();
        let mut bytes = serde_json::to_vec(&row).map_err(json_error)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_PROBE_ROW {
            return Err(fail("resource.control_probe_row_limit"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= MAX_PROBE_FILE)
            .ok_or_else(|| fail("resource.control_probe_capacity"))?;
        self.file.write_all(&bytes).map_err(io_error)?;
        self.file.flush().map_err(io_error)?;
        Ok(())
    }
}

tokio::task_local! {
    static CONTROL_JOURNAL: Arc<std::sync::Mutex<ProbeJournal>>;
}

/// This denominator is deliberately separate from ordinary requests and wire
/// probes. It covers this module's Admin reads, fixture IPC, and CLI mutations.
/// It holds an evidence file only, never a gateway object or driver.
struct ControlOperation {
    journal: Arc<std::sync::Mutex<ProbeJournal>>,
    id: String,
    start: u64,
    terminal: bool,
}
impl ControlOperation {
    fn begin(operation: &'static str, request: Value) -> Result<Self, SoakError> {
        let journal = CONTROL_JOURNAL
            .try_with(Arc::clone)
            .map_err(|_| fail("resource.control_journal_scope_missing"))?;
        let start = monotonic_ns()?;
        let mut file = journal
            .lock()
            .map_err(|_| fail("resource.control_journal_lock"))?;
        let id = format!(
            "control-io-{}",
            file.sequence
                .checked_add(1)
                .ok_or_else(|| fail("resource.control_journal_sequence"))?
        );
        file.write(json!({"kind":"started","operation_id":id,"start_ns":start,"operation":operation,"request":request}))?;
        drop(file);
        Ok(Self {
            journal,
            id,
            start,
            terminal: false,
        })
    }
    fn finish(&mut self, classification: &str, raw: Value) -> Result<(), SoakError> {
        self.journal.lock().map_err(|_| fail("resource.control_journal_lock"))?
            .write(json!({"kind":"terminal","operation_id":self.id,"start_ns":self.start,"end_ns":monotonic_ns()?,"classification":classification,"raw":raw}))?;
        self.terminal = true;
        Ok(())
    }
}
impl Drop for ControlOperation {
    fn drop(&mut self) {
        if !self.terminal
            && let Ok(mut file) = self.journal.lock()
        {
            // Future cancellation cannot run an async join. This is explicitly
            // unknown retirement, not a fabricated successful cancellation ACK.
            if let Err(error) = file.write(json!({"kind":"terminal","operation_id":self.id,"start_ns":self.start,"end_ns":monotonic_ns().ok(),"classification":"cancelled","raw":{"reason":"future_dropped","driver_exit":{"result":"unavailable","join_acknowledged":false}}})) {
                eprintln!("{}", json!({"event":"control_evidence_failure","code":"resource.control_cancel_evidence","message":error.to_string()}));
            }
        }
    }
}

impl FixtureProcess {
    async fn recorded_command(&mut self, command: FixtureCommand) -> Result<Value, SoakError> {
        let mut operation = ControlOperation::begin(
            "fixture_ipc",
            json!({"role":self.ready.role,"command":command}),
        )?;
        let result = self.command(command).await;
        operation.finish(if result.is_ok() { "completed" } else { "failed" }, json!({"fixture_ack":result.as_ref().ok(),"error":result.as_ref().err().map(ToString::to_string)}))?;
        result
    }
}

struct ProbeSpec<'a> {
    scenario: &'a str,
    grpc: bool,
    h2: bool,
    window: Option<&'a str>,
}
struct Probe {
    id: String,
    raw: Value,
}
struct Scene<'a> {
    round: usize,
    name: &'a str,
}
async fn probe(
    plan: &ControlPlan<'_>,
    upstream: &FixtureProcess,
    round: usize,
    sequence: &mut u64,
    journal: &mut ProbeJournal,
    spec: ProbeSpec<'_>,
) -> Result<Probe, SoakError> {
    // Validate the local fixture recipe before offering an operation. After
    // Started every connection/body outcome, including timeout, gets Terminal.
    let alternate = upstream
        .ready
        .alternate
        .ok_or_else(|| fail("resource.control_fixture_b_missing"))?;
    *sequence = sequence
        .checked_add(1)
        .ok_or_else(|| fail("resource.control_operation_sequence"))?;
    let id = format!("control-{round}-{}", *sequence);
    let start = monotonic_ns()?;
    let recipe = if spec.grpc { "grpc" } else { "download" };
    let path = format!(
        "/resource/{}?b=2&a=1&a=3",
        if spec.grpc { "grpc" } else { "payload" }
    );
    let protocol = if spec.h2 { "h2" } else { "http1" };
    journal.write(json!({"kind":"started","operation_id":id,"start_ns":start,"phase":"steady","scenario":spec.scenario,"recipe":recipe,"protocol":protocol,"target":"upstream","window_id":spec.window,"request":{"path":path,"grpc":spec.grpc,"upload_bytes":0,"payload_bytes":plan.args.payload_size}}))?;
    let mut client = None;
    let mut admitted = false;
    let config = if spec.h2 {
        Arc::clone(&plan.h2)
    } else {
        Arc::clone(&plan.h1)
    };
    let mut targets = vec![
        ("a".into(), upstream.ready.address),
        ("b".into(), alternate),
    ];
    if let Some(address) = upstream.ready.ipv6 {
        targets.push(("ipv6".into(), address));
    }
    let result = tokio::time::timeout(CONTROL_WIRE_DEADLINE, async {
        let connected =
            ResourceDataClient::connect(plan.gateway_address, config, spec.h2, targets).await?;
        client = Some(connected);
        admitted = true;
        let raw = client
            .as_mut()
            .expect("connected client")
            .measure(ResourceRequest {
                operation_id: id.clone(),
                path,
                grpc: spec.grpc,
                cancel_after_first_data: false,
                payload_size: plan.args.payload_size,
                upload_bytes: 0,
            })
            .await;
        serde_json::to_value(raw).map_err(json_error)
    })
    .await;
    let mut raw = match result {
        Ok(Ok(raw)) => raw,
        Ok(Err(error)) => {
            json!({"status":null,"eof":null,"body_bytes":null,"body_sha256":null,"error_stage":"connection","error_code":"connect_failure","error":error.to_string(),"admitted":false,"connection_attempted":true})
        }
        Err(_) => {
            json!({"status":null,"eof":null,"body_bytes":null,"body_sha256":null,"error_stage":"control_deadline","error_code":"control_operation_timeout","admitted":null,"connection_attempted":true})
        }
    };
    if raw["error_code"] != "control_operation_timeout" {
        raw["admitted"] = admitted.into();
    }
    raw["connection_attempted"] = true.into();
    let closed = if let Some(client) = client {
        client.close_receipt().await
    } else {
        json!({"result":"not_created","join_acknowledged":true,"exit_ns":null,"abort_requested":false})
    };
    let end = monotonic_ns()?;
    journal.write(json!({"kind":"terminal","operation_id":id,"start_ns":start,"head_ns":raw["head_ns"],"end_ns":end,"phase":"steady","scenario":spec.scenario,"recipe":recipe,"protocol":protocol,"target":"upstream","window_id":spec.window,"connection_attempts":1,"admitted":raw["admitted"],"raw":raw,"driver_exit":closed}))?;
    if raw["error_code"] == "control_operation_timeout" {
        return Err(fail("resource.control_probe_deadline"));
    }
    if closed["join_acknowledged"] != true
        || matches!(
            closed["result"].as_str(),
            Some("panicked" | "unavailable" | "cancelled" | "timeout")
        )
    {
        return Err(fail("resource.control_probe_driver_exit"));
    }
    Ok(Probe { id, raw })
}

fn full_response(raw: &Value, payload: usize, grpc: bool, peer: Option<SocketAddr>) -> bool {
    if raw["status"] != 200
        || raw["eof"] != true
        || !raw["error_code"].is_null()
        || raw["diagnostics"]
            .as_array()
            .is_none_or(|values| !values.is_empty())
    {
        return false;
    }
    if raw["content_type"]
        != if grpc {
            "application/grpc"
        } else {
            "application/octet-stream"
        }
        || raw["authority"] != "gateway.example.test"
        || raw["server_name"] != "gateway.example.test"
        || raw["path"]
            != format!(
                "/base/resource/{}?b=2&a=1&a=3",
                if grpc { "grpc" } else { "payload" }
            )
        || peer.is_some_and(|peer| raw["upstream_peer"] != peer.to_string())
    {
        return false;
    }
    let mut hash = Sha256::new();
    if grpc {
        hash.update([0]);
        hash.update((payload as u32).to_be_bytes());
    }
    let block = [b'x'; 4096];
    let mut remaining = payload;
    while remaining > 0 {
        let bytes = remaining.min(block.len());
        hash.update(&block[..bytes]);
        remaining -= bytes;
    }
    let digest = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    raw["body_bytes"] == payload as u64 + if grpc { 5 } else { 0 }
        && raw["body_sha256"] == digest
        && (!grpc
            || raw["trailers"]["grpc-status"] == "0" && raw["trailers"]["grpc-message"] == "ok")
}

async fn full_peer(
    plan: &ControlPlan<'_>,
    upstream: &FixtureProcess,
    round: usize,
    sequence: &mut u64,
    journal: &mut ProbeJournal,
    peer: SocketAddr,
    scenario: &str,
) -> Result<Probe, SoakError> {
    let deadline = monotonic_ns()?
        .checked_add(RECOVERY_NS)
        .ok_or_else(|| fail("resource.control_clock_overflow"))?;
    for _ in 0..8 {
        let seen = probe(
            plan,
            upstream,
            round,
            sequence,
            journal,
            ProbeSpec {
                scenario,
                grpc: false,
                h2: true,
                window: None,
            },
        )
        .await?;
        if full_response(&seen.raw, plan.args.payload_size, false, Some(peer)) {
            return Ok(seen);
        }
        if monotonic_ns()? > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(fail(format!(
        "resource.control_peer_recovery_unproven:{scenario}"
    )))
}

struct Window<'a> {
    faults: &'a Faults,
    id: String,
    start: u64,
    closed: bool,
}
impl<'a> Window<'a> {
    fn begin(faults: &'a Faults, id: String) -> Result<Self, SoakError> {
        let start = monotonic_ns()?;
        let mut windows = faults
            .lock()
            .map_err(|_| fail("resource.control_fault_lock"))?;
        if windows.len() >= 256 || windows.iter().any(|window| window.end.is_none()) {
            return Err(fail("resource.control_fault_capacity_or_overlap"));
        }
        windows.push(FaultInterval {
            id: id.clone(),
            start,
            end: None,
        });
        drop(windows);
        Ok(Self {
            faults,
            id,
            start,
            closed: false,
        })
    }
    fn close(&mut self) -> Result<u64, SoakError> {
        let mut windows = self
            .faults
            .lock()
            .map_err(|_| fail("resource.control_fault_lock"))?;
        let end = monotonic_ns()?;
        let window = windows
            .iter_mut()
            .find(|window| window.id == self.id)
            .ok_or_else(|| fail("resource.control_fault_missing"))?;
        if window.end.is_some() {
            return Err(fail("resource.control_fault_closed_twice"));
        }
        window.end = Some(end);
        self.closed = true;
        Ok(end)
    }
}
impl Drop for Window<'_> {
    fn drop(&mut self) {
        if !self.closed
            && let Ok(end) = monotonic_ns()
            && let Ok(mut windows) = self.faults.lock()
            && let Some(window) = windows.iter_mut().find(|window| window.id == self.id)
        {
            window.end = Some(end);
        }
    }
}

async fn healthy(upstream: &mut FixtureProcess, retry: bool) -> Result<Value, SoakError> {
    upstream
        .recorded_command(FixtureCommand::Health {
            healthy_a: true,
            healthy_b: true,
            retry_a: retry,
        })
        .await
}
async fn fault_off(upstream: &mut FixtureProcess) -> Result<Value, SoakError> {
    upstream
        .recorded_command(FixtureCommand::ResourceFault {
            mode: "none".into(),
            target: "all".into(),
            delay_ms: 0,
            after_bytes: 0,
            case_id: 0,
        })
        .await
}

async fn mutation(
    plan: &ControlPlan<'_>,
    action: &str,
    digest: Option<&str>,
    round: usize,
    sequence: &mut u64,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let before = runtime(plan.root).await?;
    let start = monotonic_ns()?;
    let operation = if let Some(digest) = digest {
        vec![action, digest]
    } else {
        vec![action]
    };
    let mut command = client::ctl(plan.root, &operation);
    command.splice(
        1..1,
        [
            "--if-match".into(),
            before["etag"]
                .as_str()
                .ok_or_else(|| fail("resource.control_etag_missing"))?
                .into(),
        ],
    );
    let mut operation =
        ControlOperation::begin("cli_mutation", json!({"action":action,"digest":digest}))?;
    let receipt =
        client::command_json(&plan.args.gateway, &command, &plan.args.output, sequence).await;
    operation.finish(if receipt.is_ok() { "completed" } else { "failed" }, json!({"mutation_receipt":receipt.as_ref().ok(),"error":receipt.as_ref().err().map(ToString::to_string)}))?;
    let receipt = receipt?;
    let after = runtime(plan.root).await?;
    events.write(json!({"kind":"control","t_ns":monotonic_ns()?,"action":action,"request_id":round,"before_runtime":before,"after_runtime":after,"mutation_receipt":receipt}))?;
    if before["etag"] == after["etag"]
        || before["runtime_revision"]
            .as_u64()
            .zip(after["runtime_revision"].as_u64())
            .is_none_or(|(before, after)| after <= before)
    {
        return Err(fail("resource.control_publication_unproven"));
    }
    if digest.is_some_and(|digest| {
        after["bundle_digest"] != digest || after["origin"]["kind"] != "bundle"
    }) || digest.is_none() && after["origin"]["kind"] != "source"
    {
        return Err(fail("resource.control_publication_wrong_origin"));
    }
    coverage(
        events,
        match action {
            "activate" => "signed_activate",
            "rollback" => "signed_rollback",
            _ => "source_reload",
        },
        json!({"source":"runtime_publication","action":action,"digest":digest,"started_ns":start,"ended_ns":monotonic_ns()?,"before_runtime":before,"after_runtime":after,"mutation_receipt":receipt}),
    )
}

async fn weights(
    plan: &ControlPlan<'_>,
    dns: &mut FixtureProcess,
    round: usize,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let equal_before = dns.recorded_command(FixtureCommand::Status).await?;
    dns_change(
        plan,
        dns,
        "weights_equal",
        HEALTHY_DNS_TTL_SECONDS,
        round,
        events,
    )
    .await?;
    let deadline = tokio::time::Instant::now() + STATE_DEADLINE;
    let (before, equal_after) = loop {
        let before = clusters(plan.root).await?;
        let after = dns.recorded_command(FixtureCommand::Status).await?;
        if srv_weights(&before, 1, 1)?
            && counter(&after, "srv_equal_weight_answers")?
                > counter(&equal_before, "srv_equal_weight_answers")?
        {
            break (before, after);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail("resource.control_srv_equal_weight_unproven"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    dns_change(plan, dns, "weights", HEALTHY_DNS_TTL_SECONDS, round, events).await?;
    let deadline = tokio::time::Instant::now() + STATE_DEADLINE;
    loop {
        let after = clusters(plan.root).await?;
        let dns_after = dns.recorded_command(FixtureCommand::Status).await?;
        if srv_weights(&after, 3, 1)?
            && counter(&dns_after, "srv_weighted_answers")?
                > counter(&equal_after, "srv_weighted_answers")?
        {
            fixture_coverage(
                events,
                "srv_equal_answers",
                "srv_equal_weight_answers",
                &equal_before,
                &equal_after,
            )?;
            fixture_coverage(
                events,
                "srv_weighted_answers",
                "srv_weighted_answers",
                &equal_after,
                &dns_after,
            )?;
            return coverage(
                events,
                "srv_weight_change",
                json!({"source":"cluster_membership","before_raw":before,"after_raw":after}),
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail("resource.control_srv_weight_unproven"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn srv_weights(document: &Value, a: u16, b: u16) -> Result<bool, SoakError> {
    Ok(upstream_cluster(document)?["discovery"]["srv_targets"]
        .as_array()
        .is_some_and(|targets| {
            targets.len() == 2
                && targets.iter().any(|row| {
                    row["target"] == "a.discovery.test."
                        && row["weight"] == a
                        && row["priority"] == 0
                })
                && targets.iter().any(|row| {
                    row["target"] == "b.discovery.test."
                        && row["weight"] == b
                        && row["priority"] == 0
                })
        }))
}

fn srv_aaaa_refresh(
    before_clusters: &Value,
    after_clusters: &Value,
    before_metrics: &str,
    after_metrics: &str,
    before_fixture: &Value,
    after_fixture: &Value,
) -> Result<bool, SoakError> {
    let before = &upstream_cluster(before_clusters)?["discovery"];
    let after = &upstream_cluster(after_clusters)?["discovery"];
    // The configured supervisor resolves SRV. Its internal target AAAA query is
    // proved by the real fixture, never by inventing a top-level AAAA metric.
    Ok(before["name"] == "_https._tcp.api.discovery.test."
        && after["name"] == before["name"]
        && before["generation"]
            .as_u64()
            .zip(after["generation"].as_u64())
            .is_some_and(|(before, after)| after > before)
        && after["resolution"] == "fresh"
        && after["eligible_endpoints"]
            .as_u64()
            .is_some_and(|count| count > 0)
        && metric(after_metrics, SRV_POSITIVE_METRIC)?
            > metric(before_metrics, SRV_POSITIVE_METRIC)?
        && counter(after_fixture, "positive_aaaa_answers")?
            > counter(before_fixture, "positive_aaaa_answers")?)
}

fn allowed_data_failures(mode: &str, target: &str) -> Value {
    let mut allowed = if mode == "mid_body_error" {
        vec![json!({"error_stage":"response_body","error_code":"body_error"})]
    } else {
        vec![json!({"status":504})]
    };
    // An A-only failure leaves B eligible. A 503 then is an unexpected
    // availability failure, not a permission granted by temporal proximity.
    if target == "all" {
        allowed.push(json!({"status":503}));
    }
    Value::Array(allowed)
}

async fn active_health(
    plan: &ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    round: usize,
    sequence: &mut u64,
    journal: &mut ProbeJournal,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    weights(plan, dns, round, events).await?;
    healthy(upstream, false).await?;
    let before = clusters(plan.root).await?;
    let fixture_before = upstream.recorded_command(FixtureCommand::Status).await?;
    upstream
        .recorded_command(FixtureCommand::Health {
            healthy_a: false,
            healthy_b: true,
            retry_a: false,
        })
        .await?;
    let result=async {
        let deadline=tokio::time::Instant::now()+STATE_DEADLINE;
        loop {
            let after=clusters(plan.root).await?;
            if endpoint_counter(&after,"active_health_failures")?>endpoint_counter(&before,"active_health_failures")? && upstream_cluster(&after)?["endpoints"].as_array().is_some_and(|rows|rows.iter().any(|row|row["health"]=="unhealthy")) {
                coverage(events,"active_health_failure",json!({"source":"cluster_counter","name":"active_health_failures","before":endpoint_counter(&before,"active_health_failures")?,"after":endpoint_counter(&after,"active_health_failures")?,"before_raw":before,"after_raw":after,"fixture_before":fixture_before,"fixture_after":upstream.recorded_command(FixtureCommand::Status).await?}))?;
                return Ok::<_,SoakError>(after);
            }
            if tokio::time::Instant::now()>=deadline {return Err(fail("resource.control_health_failure_unproven"));}
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }.await;
    healthy(upstream, false).await?;
    let failed = result?;
    let deadline = tokio::time::Instant::now() + STATE_DEADLINE;
    loop {
        let recovered = clusters(plan.root).await?;
        if endpoint_counter(&recovered, "active_health_successes")?
            > endpoint_counter(&failed, "active_health_successes")?
            && upstream_cluster(&recovered)?["endpoints"]
                .as_array()
                .is_some_and(|rows| {
                    rows.len() >= 2 && rows.iter().all(|row| row["health"] == "healthy")
                })
        {
            coverage(
                events,
                "active_health_recovery",
                json!({"source":"cluster_counter","name":"active_health_successes","before":endpoint_counter(&failed,"active_health_successes")?,"after":endpoint_counter(&recovered,"active_health_successes")?,"before_raw":failed,"after_raw":recovered}),
            )?;
            let wire = full_peer(
                plan,
                upstream,
                round,
                sequence,
                journal,
                upstream.ready.address,
                "recovery_a",
            )
            .await?;
            return coverage(
                events,
                "recovery_a",
                json!({"source":"control_probe","operation_id":wire.id,"expected_peer":upstream.ready.address.to_string()}),
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(fail("resource.control_health_recovery_unproven"));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn data_fault(
    plan: &ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    scene: Scene<'_>,
    sequence: &mut u64,
    journal: &mut ProbeJournal,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let Scene {
        round,
        name: scenario,
    } = scene;
    weights(plan, dns, round, events).await?;
    healthy(upstream, false).await?;
    let mode = if scenario == "post_head_error" {
        "mid_body_error"
    } else {
        "header_delay"
    };
    let target = if scenario == "deadline_timeout" {
        "all"
    } else {
        "a"
    };
    let field = if mode == "mid_body_error" {
        "resource_mid_body_errors_emitted"
    } else {
        "resource_header_delays_started"
    };
    let before = upstream.recorded_command(FixtureCommand::Status).await?;
    let before_metrics = metrics(plan.root).await?;
    let mut window = Window::begin(plan.faults, format!("{scenario}-{round}"))?;
    upstream
        .recorded_command(FixtureCommand::ResourceFault {
            mode: mode.into(),
            target: target.into(),
            delay_ms: if mode == "mid_body_error" { 150 } else { 6000 },
            after_bytes: 1024,
            case_id: round as u64,
        })
        .await?;
    let result = async {
        for _ in 0..8 {
            let seen = probe(
                plan,
                upstream,
                round,
                sequence,
                journal,
                ProbeSpec {
                    scenario,
                    grpc: scenario != "deadline_timeout",
                    h2: true,
                    window: Some(&window.id),
                },
            )
            .await?;
            let observed = if scenario == "post_head_error" {
                seen.raw["status"] == 200
                    && seen.raw["error_stage"] == "response_body"
                    && seen.raw["error_code"] == "body_error"
                    && seen.raw["fault_case_id"] == round as u64
            } else {
                seen.raw["status"] == 504
            };
            if observed {
                coverage(
                    events,
                    scenario,
                    json!({"source":"control_probe","operation_id":seen.id,"window_id":window.id}),
                )?;
                return Ok::<_, SoakError>(());
            }
        }
        Err(fail(format!(
            "resource.control_fault_wire_unproven:{scenario}"
        )))
    }
    .await;
    let after = upstream.recorded_command(FixtureCommand::Status).await?;
    let after_metrics = metrics(plan.root).await?;
    fault_off(upstream).await?;
    healthy(upstream, false).await?;
    tokio::time::sleep(SETTLING).await;
    let end = window.close()?;
    let first = counter(&before, field)?;
    let last = counter(&after, field)?;
    let peers = if target == "all" {
        vec![
            upstream.ready.address.to_string(),
            upstream
                .ready
                .alternate
                .ok_or_else(|| fail("resource.control_fixture_b_missing"))?
                .to_string(),
        ]
    } else {
        vec![upstream.ready.address.to_string()]
    };
    events.write(json!({"kind":"fault_window","t_ns":monotonic_ns()?,"id":window.id,"start_ns":window.start,"end_ns":end,"recovery_deadline_ns":end+RECOVERY_NS,"recovery_peers":peers,"failure_peers":peers,"fault_case_id":round as u64,"target":"upstream","lanes":["churn","cancel"],"allowed":allowed_data_failures(mode,target),"trigger":{"source":"fixture_counter","name":field,"before":first,"after":last},"fixture_before":before,"fixture_after":after,"timeout_metrics_before":before_metrics,"timeout_metrics_after":after_metrics}))?;
    if last <= first {
        return Err(fail("resource.control_fault_fixture_not_triggered"));
    }
    result?;
    if scenario == "deadline_timeout" {
        metric_coverage(
            events,
            "total_deadline_counter",
            "oxidase_upstream_timeouts_total{phase=\"total\"}",
            &before_metrics,
            &after_metrics,
        )?;
    }
    if scenario == "response_header_timeout" {
        metric_coverage(
            events,
            "header_deadline_counter",
            "oxidase_upstream_timeouts_total{phase=\"response_header\"}",
            &before_metrics,
            &after_metrics,
        )?;
    }
    for peer in peers {
        let peer = peer.parse().map_err(io_error)?;
        let recovered = full_peer(
            plan,
            upstream,
            round,
            sequence,
            journal,
            peer,
            "fault_recovery",
        )
        .await?;
        coverage(
            events,
            "fault_recovery",
            json!({"source":"control_probe","operation_id":recovered.id,"window_id":window.id,"expected_peer":peer.to_string()}),
        )?;
    }
    Ok(())
}

fn dns_fault_recipe(mode: &str) -> Result<(&'static str, u32, &'static str), SoakError> {
    match mode {
        "nxdomain" => Ok(("nxdomain_answers", 1, "dns_nxdomain")),
        "withdraw" => Ok(("withdraw_answers", 1, "dns_all_withdraw")),
        "ttl0" => Ok(("ttl_zero_answers", 0, "dns_ttl_zero")),
        _ => Err(fail("resource.control_unknown_dns_fault")),
    }
}

async fn dns_window(
    plan: &ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    scene: Scene<'_>,
    sequence: &mut u64,
    journal: &mut ProbeJournal,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let Scene { round, name: mode } = scene;
    healthy(upstream, false).await?;
    let before = dns.recorded_command(FixtureCommand::Status).await?;
    let (field, ttl, behavior) = dns_fault_recipe(mode)?;
    let mut window = Window::begin(plan.faults, format!("dns-{mode}-{round}"))?;
    let result = async {
        dns_change(plan, dns, mode, ttl, round, events).await?;
        tokio::time::sleep(Duration::from_secs(3)).await;
        let seen = probe(
            plan,
            upstream,
            round,
            sequence,
            journal,
            ProbeSpec {
                scenario: "dns_withdraw",
                grpc: false,
                h2: true,
                window: Some(&window.id),
            },
        )
        .await?;
        if seen.raw["status"] != 503 {
            return Err(fail("resource.control_dns_withdraw_wire_unproven"));
        }
        coverage(
            events,
            "dns_withdraw",
            json!({"source":"control_probe","operation_id":seen.id,"window_id":window.id}),
        )
    }
    .await;
    let after = dns.recorded_command(FixtureCommand::Status).await?;
    dns_change(plan, dns, "weights", HEALTHY_DNS_TTL_SECONDS, round, events).await?;
    tokio::time::sleep(SETTLING).await;
    let end = window.close()?;
    events.write(json!({"kind":"fault_window","t_ns":monotonic_ns()?,"id":window.id,"start_ns":window.start,"end_ns":end,"recovery_deadline_ns":end+RECOVERY_NS,"recovery_peers":[upstream.ready.address.to_string(),upstream.ready.alternate.ok_or_else(||fail("resource.control_fixture_b_missing"))?.to_string()],"target":"upstream","lanes":["churn","cancel"],"allowed":[{"status":503}],"trigger":{"source":"fixture_counter","name":field,"before":counter(&before,field)?,"after":counter(&after,field)?},"fixture_before":before,"fixture_after":after}))?;
    fixture_coverage(events, behavior, field, &before, &after)?;
    result?;
    for peer in [
        upstream.ready.address,
        upstream
            .ready
            .alternate
            .ok_or_else(|| fail("resource.control_fixture_b_missing"))?,
    ] {
        let seen = full_peer(plan, upstream, round, sequence, journal, peer, "dns_readd").await?;
        coverage(
            events,
            "dns_readd",
            json!({"source":"control_probe","operation_id":seen.id,"window_id":window.id,"expected_peer":peer.to_string()}),
        )?;
    }
    Ok(())
}

pub(super) async fn control_round(
    plan: ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    round: usize,
    sequence: &mut u64,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let journal = Arc::new(std::sync::Mutex::new(ProbeJournal::named(
        &plan.args.output,
        "control-operations.jsonl",
        "oxidase.resource-control-operation/v1",
    )?));
    CONTROL_JOURNAL
        .scope(
            journal,
            control_round_inner(plan, dns, upstream, round, sequence, events),
        )
        .await
}

async fn control_round_inner(
    plan: ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    round: usize,
    sequence: &mut u64,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    if !matches!(plan.args.campaign, ResourceCampaign::PublishOnly) {
        let modes = ["both", "reverse", "v6", "both_v6", "a", "b", "both"];
        dns_change(
            &plan,
            dns,
            modes[(round.wrapping_add(plan.args.seed as usize)) % modes.len()],
            HEALTHY_DNS_TTL_SECONDS,
            round,
            events,
        )
        .await?;
    }
    if matches!(
        plan.args.campaign,
        ResourceCampaign::Churn | ResourceCampaign::PublishOnly
    ) && round.is_multiple_of(4)
    {
        let (action, digest) = if round.is_multiple_of(8) {
            ("rollback", plan.a)
        } else {
            ("activate", plan.b)
        };
        mutation(&plan, action, Some(digest), round, sequence, events).await?;
    }
    if !matches!(plan.args.campaign, ResourceCampaign::Churn) {
        return Ok(());
    }
    let mut journal = ProbeJournal::open(&plan.args.output)?;
    match round.wrapping_add(plan.args.seed as usize) % 12 {
        0 => {
            let source = resource_source(
                plan.root,
                dns.ready.address,
                upstream,
                plan.args.campaign,
                0x4000 + round as u64,
            );
            std::fs::write(plan.root.join("gateway.yaml"), source).map_err(io_error)?;
            mutation(&plan, "reload-source", None, round, sequence, events).await?;
        }
        1 => active_health(&plan, dns, upstream, round, sequence, &mut journal, events).await?,
        2 => {
            data_fault(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "response_header_timeout",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?
        }
        3 => {
            data_fault(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "post_head_error",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?
        }
        4 => {
            data_fault(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "deadline_timeout",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?
        }
        5 => {
            dns_window(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "nxdomain",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?
        }
        6 => {
            dns_window(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "withdraw",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?
        }
        7 => {
            let witness_start = monotonic_ns()?;
            let before = metrics(plan.root).await?;
            let fixture_before = dns.recorded_command(FixtureCommand::Status).await?;
            let before_clusters = clusters(plan.root).await?;
            dns_change(&plan, dns, "v6", HEALTHY_DNS_TTL_SECONDS, round, events).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let peer = upstream
                .ready
                .ipv6
                .ok_or_else(|| fail("resource.control_ipv6_unavailable"))?;
            let seen = full_peer(
                &plan,
                upstream,
                round,
                sequence,
                &mut journal,
                peer,
                "positive_aaaa",
            )
            .await?;
            let after = metrics(plan.root).await?;
            let fixture_after = dns.recorded_command(FixtureCommand::Status).await?;
            let after_clusters = clusters(plan.root).await?;
            let witness_end = monotonic_ns()?;
            let witness_deadline = witness_start
                .checked_add(SRV_AAAA_WITNESS_NS)
                .ok_or_else(|| fail("resource.control_aaaa_witness_clock"))?;
            if witness_end > witness_deadline
                || !srv_aaaa_refresh(
                    &before_clusters,
                    &after_clusters,
                    &before,
                    &after,
                    &fixture_before,
                    &fixture_after,
                )?
            {
                return Err(fail("resource.control_srv_aaaa_refresh_unproven"));
            }
            fixture_coverage(
                events,
                "positive_aaaa_answers",
                "positive_aaaa_answers",
                &fixture_before,
                &fixture_after,
            )?;
            metric_coverage(
                events,
                "positive_srv_round_counter",
                SRV_POSITIVE_METRIC,
                &before,
                &after,
            )?;
            coverage(
                events,
                "positive_aaaa",
                json!({"source":"control_probe","operation_id":seen.id,"expected_peer":peer.to_string(),"observation_window":{"start_ns":witness_start,"end_ns":witness_end,"deadline_ns":witness_deadline},"before_metrics":before,"after_metrics":after,"before_raw":fixture_before,"after_raw":fixture_after,"before_clusters":before_clusters,"after_clusters":after_clusters}),
            )?;
        }
        8 => weights(&plan, dns, round, events).await?,
        9 => {
            dns_window(
                &plan,
                dns,
                upstream,
                Scene {
                    round,
                    name: "ttl0",
                },
                sequence,
                &mut journal,
                events,
            )
            .await?;
        }
        10 => {
            dns_change(&plan, dns, "b", HEALTHY_DNS_TTL_SECONDS, round, events).await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            dns_change(
                &plan,
                dns,
                "weights",
                HEALTHY_DNS_TTL_SECONDS,
                round,
                events,
            )
            .await?;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let seen = full_peer(
                &plan,
                upstream,
                round,
                sequence,
                &mut journal,
                upstream.ready.address,
                "dns_readd",
            )
            .await?;
            coverage(
                events,
                "dns_readd",
                json!({"source":"control_probe","operation_id":seen.id,"expected_peer":upstream.ready.address.to_string()}),
            )?;
        }
        _ => {
            weights(&plan, dns, round, events).await?;
            let before = upstream.recorded_command(FixtureCommand::Status).await?;
            let before_metrics = metrics(plan.root).await?;
            healthy(upstream, true).await?;
            let result = async {
                for _ in 0..16 {
                    let seen = probe(
                        &plan,
                        upstream,
                        round,
                        sequence,
                        &mut journal,
                        ProbeSpec {
                            scenario: "retry",
                            grpc: false,
                            h2: false,
                            window: None,
                        },
                    )
                    .await?;
                    if !full_response(&seen.raw, plan.args.payload_size, false, None) {
                        return Err(fail("resource.control_retry_wire_failed"));
                    }
                    let after = upstream.recorded_command(FixtureCommand::Status).await?;
                    let after_metrics = metrics(plan.root).await?;
                    if counter(&after, "retryable_status_replies")?
                        > counter(&before, "retryable_status_replies")?
                    {
                        fixture_coverage(
                            events,
                            "retryable_status",
                            "retryable_status_replies",
                            &before,
                            &after,
                        )?;
                        return metric_coverage(
                            events,
                            "actual_retry",
                            "oxidase_cluster_retry_attempts_total{cluster=\"upstream\"}",
                            &before_metrics,
                            &after_metrics,
                        );
                    }
                }
                Err(fail("resource.control_retry_not_triggered"))
            }
            .await;
            healthy(upstream, false).await?;
            result?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ttl_zero_uses_the_same_finite_recovery_contract_as_withdrawal() {
        assert_eq!(
            dns_fault_recipe("ttl0").expect("explicit zero lease"),
            ("ttl_zero_answers", 0, "dns_ttl_zero")
        );
        assert_eq!(
            dns_fault_recipe("withdraw").expect("withdrawal"),
            ("withdraw_answers", 1, "dns_all_withdraw")
        );
        assert!(
            dns_fault_recipe("positive").is_err(),
            "healthy traffic cannot invent a fault window"
        );
        assert_eq!(HEALTHY_DNS_TTL_SECONDS, 5);
        assert!(SETTLING >= Duration::from_secs(10));
        assert!(RECOVERY_NS > 0 && RECOVERY_NS <= 12_000_000_000);
    }
    #[test]
    fn srv_target_aaaa_witness_requires_real_refresh_and_exact_metric_scope() {
        let before = json!({"clusters":[{"cluster":"upstream","discovery":{"name":"_https._tcp.api.discovery.test.","generation":4,"resolution":"fresh","eligible_endpoints":2}}]});
        let duplicate =
            json!({"clusters":[before["clusters"][0].clone(),before["clusters"][0].clone()]});
        assert!(upstream_cluster(&duplicate).is_err());
        let mut after = before.clone();
        after["clusters"][0]["discovery"]["generation"] = 5.into();
        let before_metric = format!(
            "{SRV_POSITIVE_METRIC} 10\noxidase_discovery_queries_total{{cluster=\"upstream\",family=\"aaaa\",result=\"positive\"}} 0\n"
        );
        let after_metric = before_metric.replace(" 10\n", " 11\n");
        let first = json!({"positive_aaaa_answers":0});
        let last = json!({"positive_aaaa_answers":3});
        assert!(
            srv_aaaa_refresh(
                &before,
                &after,
                &before_metric,
                &after_metric,
                &first,
                &last
            )
            .expect("actual SRV target AAAA")
        );
        assert!(
            !srv_aaaa_refresh(
                &before,
                &after,
                &before_metric,
                &before_metric,
                &first,
                &last
            )
            .expect("no supervisor refresh")
        );
        assert!(
            !srv_aaaa_refresh(&before, &after, &before_metric, &after_metric, &last, &last)
                .expect("no actual AAAA answer")
        );
        assert!(
            !srv_aaaa_refresh(
                &before,
                &before,
                &before_metric,
                &after_metric,
                &first,
                &last
            )
            .expect("no membership generation")
        );
        after["clusters"][0]["discovery"]["name"] = "other.discovery.test.".into();
        assert!(
            !srv_aaaa_refresh(
                &before,
                &after,
                &before_metric,
                &after_metric,
                &first,
                &last
            )
            .expect("wrong declared origin")
        );
        after["clusters"][0]["discovery"]["name"] = "_https._tcp.api.discovery.test.".into();
        after["clusters"][0]["discovery"]["resolution"] = "stale".into();
        assert!(
            !srv_aaaa_refresh(
                &before,
                &after,
                &before_metric,
                &after_metric,
                &first,
                &last
            )
            .expect("stale data")
        );
        after["clusters"][0]["discovery"]["resolution"] = "fresh".into();
        after["clusters"][0]["discovery"]["eligible_endpoints"] = 0.into();
        assert!(
            !srv_aaaa_refresh(
                &before,
                &after,
                &before_metric,
                &after_metric,
                &first,
                &last
            )
            .expect("no usable endpoint")
        );
    }

    fn control_journal(directory: &Path) -> Arc<std::sync::Mutex<ProbeJournal>> {
        Arc::new(std::sync::Mutex::new(
            ProbeJournal::named(
                directory,
                "control-operations.jsonl",
                "oxidase.resource-control-operation/v1",
            )
            .expect("journal"),
        ))
    }
    #[tokio::test]
    async fn control_denominator_keeps_completed_failed_and_unknown_cancellation_distinct() {
        let directory = tempfile::tempdir().expect("fixture");
        CONTROL_JOURNAL.scope(control_journal(directory.path()), async {
            let mut complete=ControlOperation::begin("fixture_ipc",json!({"role":"dns","command":{"op":"status"}})).expect("Started");
            complete.finish("completed",json!({"fixture_ack":{"ok":true}})).expect("Terminal");
            let mut failed=ControlOperation::begin("admin_read",json!({"path":"/api/v1/runtime"})).expect("Started");
            failed.finish("failed",json!({"error":"connect_failure","driver_exit":{"result":"not_created","join_acknowledged":true}})).expect("Terminal");
            let cancelled=ControlOperation::begin("admin_read",json!({"path":"/metrics"})).expect("Started");
            drop(cancelled);
        }).await;
        let rows = std::fs::read_to_string(directory.path().join("control-operations.jsonl"))
            .expect("original records")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("JSON"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 6);
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["writer_seq"], index as u64 + 1);
        }
        for pair in rows.as_chunks::<2>().0 {
            assert_eq!(pair[0]["kind"], "started");
            assert_eq!(pair[1]["kind"], "terminal");
            assert_eq!(pair[0]["operation_id"], pair[1]["operation_id"]);
            assert_eq!(pair[0]["start_ns"], pair[1]["start_ns"]);
        }
        assert_eq!(rows[1]["classification"], "completed");
        assert_eq!(rows[3]["classification"], "failed");
        assert_eq!(rows[5]["classification"], "cancelled");
        assert_eq!(rows[5]["raw"]["driver_exit"]["result"], "unavailable");
        assert_eq!(rows[5]["raw"]["driver_exit"]["join_acknowledged"], false);
        assert!(ControlOperation::begin("admin_read", json!({})).is_err());
    }
    #[tokio::test]
    async fn admin_preparation_failure_is_accounted_without_a_fabricated_driver() {
        let directory = tempfile::tempdir().expect("fixture");
        let error = CONTROL_JOURNAL
            .scope(
                control_journal(directory.path()),
                admin(directory.path(), "/metrics"),
            )
            .await;
        assert!(error.is_err());
        let rows = std::fs::read_to_string(directory.path().join("control-operations.jsonl"))
            .expect("original records")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("JSON"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1]["classification"], "failed");
        assert_eq!(rows[1]["raw"]["body_complete"], false);
        assert!(rows[1]["raw"]["status"].is_null());
        assert_eq!(rows[1]["raw"]["driver_exit"]["result"], "not_created");
    }
    #[tokio::test]
    async fn admin_driver_retirement_reports_actual_completion_abort_and_panic() {
        let mut completed = Driver(Some(tokio::spawn(async { Ok(()) })));
        tokio::task::yield_now().await;
        let exit = completed.close().await;
        assert_eq!(exit["result"], "completed");
        assert_eq!(exit["join_acknowledged"], true);
        let mut aborted = Driver(Some(tokio::spawn(std::future::pending())));
        let exit = aborted.close().await;
        assert_eq!(exit["result"], "cancelled");
        assert_eq!(exit["abort_requested"], true);
        assert_eq!(exit["join_acknowledged"], true);
        let mut panicked = Driver(Some(tokio::spawn(async {
            panic!("test-only driver panic")
        })));
        tokio::task::yield_now().await;
        let exit = panicked.close().await;
        assert_eq!(exit["result"], "panicked");
        assert_eq!(exit["join_acknowledged"], true);
    }
    #[test]
    fn full_response_requires_complete_content_metadata_peer_and_trailers() {
        let peer = "127.0.0.1:1200".parse().expect("peer");
        let mut hash = Sha256::new();
        hash.update([0, 0, 0, 0, 2, b'x', b'x']);
        let digest = hash
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut raw = json!({"status":200,"eof":true,"error_code":null,"diagnostics":[],"content_type":"application/grpc","authority":"gateway.example.test","server_name":"gateway.example.test","path":"/base/resource/grpc?b=2&a=1&a=3","upstream_peer":"127.0.0.1:1200","body_bytes":7,"body_sha256":digest,"trailers":{"grpc-status":"0","grpc-message":"ok"}});
        assert!(full_response(&raw, 2, true, Some(peer)));
        assert!(!full_response(
            &raw,
            2,
            true,
            Some("127.0.0.1:1201".parse().expect("other peer"))
        ));
        for (field, wrong) in [
            ("status", json!(503)),
            ("eof", json!(false)),
            ("body_bytes", json!(6)),
            ("body_sha256", json!("00")),
            ("error_code", json!("body_error")),
            ("authority", json!("unverified.test")),
            ("server_name", Value::Null),
            ("diagnostics", json!(["wire_violation"])),
            ("trailers", json!({"grpc-status":"0"})),
        ] {
            let original = raw[field].clone();
            raw[field] = wrong;
            assert!(!full_response(&raw, 2, true, Some(peer)), "{field}");
            raw[field] = original;
        }
    }
    #[test]
    fn srv_weight_oracle_rejects_priority_or_identity_changes() {
        // Literal canonical target representation observed in the actual Linux
        // Admin artifact, not an unqualified-name fixture invented by this
        // oracle. DNS target identity/priority must remain exact.
        let mut raw = json!({"clusters":[{"cluster":"upstream","discovery":{"srv_targets":[{"target":"a.discovery.test.","priority":0,"weight":1},{"target":"b.discovery.test.","priority":0,"weight":1}]}}]});
        assert!(srv_weights(&raw, 1, 1).expect("equal weights"));
        assert!(!srv_weights(&raw, 3, 1).expect("not weighted"));
        raw["clusters"][0]["discovery"]["srv_targets"][0]["weight"] = 3.into();
        assert!(srv_weights(&raw, 3, 1).expect("weighted"));
        raw["clusters"][0]["discovery"]["srv_targets"][0]["target"] = "a.discovery.test".into();
        assert!(!srv_weights(&raw, 3, 1).expect("unqualified metadata is not canonical"));
        raw["clusters"][0]["discovery"]["srv_targets"][0]["target"] = "a.discovery.test.".into();
        raw["clusters"][0]["discovery"]["srv_targets"][1]["priority"] = 1.into();
        assert!(!srv_weights(&raw, 3, 1).expect("changed priority"));
        raw["clusters"][0]["discovery"]["srv_targets"][1]["priority"] = 0.into();
        raw["clusters"][0]["discovery"]["srv_targets"][1]["target"] = "other.test".into();
        assert!(!srv_weights(&raw, 3, 1).expect("changed identity"));
        assert!(srv_weights(&json!({}), 1, 1).is_err());
    }
    #[test]
    fn missing_counter_never_becomes_zero_and_metric_labels_are_exact() {
        assert!(counter(&json!({}), "health_failure_replies").is_err());
        assert_eq!(
            metric(
                "x{phase=\"total\"} 2\nx{phase=\"connect\"} 4\n",
                "x{phase=\"total\"}"
            )
            .expect("counter"),
            2
        );
        assert!(metric("x 2\nx 3\n", "x").is_err());
        assert!(metric("x NaN\n", "x").is_err());
    }
    #[test]
    fn healthy_b_cannot_be_hidden_by_an_a_fault_window() {
        assert_eq!(
            allowed_data_failures("header_delay", "a"),
            json!([{"status":504}])
        );
        assert_eq!(
            allowed_data_failures("mid_body_error", "a"),
            json!([{"error_stage":"response_body","error_code":"body_error"}])
        );
        assert_eq!(
            allowed_data_failures("header_delay", "all"),
            json!([{"status":504},{"status":503}])
        );
    }
    #[test]
    fn journal_continues_exact_sequence_and_rejects_partial_original_data() {
        let directory = tempfile::tempdir().expect("fixture");
        {
            let mut journal = ProbeJournal::open(directory.path()).expect("journal");
            journal
                .write(json!({"kind":"started","operation_id":"a"}))
                .expect("start");
        }
        {
            let mut journal = ProbeJournal::open(directory.path()).expect("reopen");
            journal
                .write(json!({"kind":"terminal","operation_id":"a"}))
                .expect("terminal");
        }
        let path = directory.path().join("control-probes.jsonl");
        let text = std::fs::read_to_string(&path).expect("original");
        let rows = text
            .lines()
            .map(|row| serde_json::from_str::<Value>(row).expect("JSON"))
            .collect::<Vec<_>>();
        assert_eq!(rows[0]["writer_seq"], 1);
        assert_eq!(rows[1]["writer_seq"], 2);
        std::fs::write(&path, text.trim_end()).expect("partial fixture");
        assert!(ProbeJournal::open(directory.path()).is_err());
    }
    #[test]
    fn fault_registration_is_bounded_nonoverlapping_and_actual_drop_closes_state() {
        let faults = Arc::new(std::sync::Mutex::new(Vec::new()));
        {
            let _window = Window::begin(&faults, "first".into()).expect("start");
            assert!(Window::begin(&faults, "nested".into()).is_err());
        }
        assert!(faults.lock().expect("state")[0].end.is_some());
        let mut window = Window::begin(&faults, "second".into()).expect("next");
        window.close().expect("close");
        assert!(window.close().is_err());
    }
}
