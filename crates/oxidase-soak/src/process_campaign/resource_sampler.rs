//! Independent, bounded observation process. OS sampling does not wait for an
//! Admin scrape or for the load/controller's control-plane operations.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use http::{Request, header};
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::TokioIo;
use oxidase_runtime::{AdminBearerToken, MAX_ADMIN_BEARER_TOKEN_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot, watch};

use super::resource_identity::{
    self, ProcessIdentity, ProcessReference, ProcessRole, monotonic_ns,
};
use super::{SoakError, fail};

#[derive(Debug, Clone, Parser)]
pub(super) struct ResourceSamplerArguments {
    #[arg(long)]
    pub root: PathBuf,
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long)]
    pub identity_file: PathBuf,
    #[arg(long, default_value_t = 1000)]
    pub interval_ms: u64,
    #[arg(long, default_value_t = 1000)]
    pub admin_interval_ms: u64,
    #[arg(long, default_value_t = 10000)]
    pub smaps_interval_ms: u64,
    #[arg(long, default_value_t = 536_870_912)]
    pub max_artifact_bytes: u64,
    #[arg(long, default_value_t = 100_000)]
    pub max_records: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Bootstrap,
    Warmup,
    Steady,
    Recovery,
    Quiet,
    PostDrain,
}

#[derive(Clone)]
struct PhaseState {
    sequence: u64,
    phase: Phase,
    effective_ns: u64,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Phase {
        sequence: u64,
        phase: Phase,
        at_ns: u64,
    },
    Checkpoint {
        id: String,
    },
    Stop,
}

fn change_phase(
    current: &mut PhaseState,
    sequence: u64,
    next: Phase,
    at_ns: u64,
) -> Result<u64, SoakError> {
    if sequence
        != current
            .sequence
            .checked_add(1)
            .ok_or_else(|| fail("resource.phase_sequence"))?
    {
        return Err(fail("resource.phase_sequence"));
    }
    if !matches!(
        (current.phase, next),
        (Phase::Bootstrap, Phase::Warmup)
            | (Phase::Warmup, Phase::Steady)
            | (Phase::Steady, Phase::Recovery)
            | (Phase::Recovery, Phase::Quiet)
            | (Phase::Quiet, Phase::PostDrain)
    ) {
        return Err(fail("resource.phase_order"));
    }
    let now = monotonic_ns()?;
    if at_ns > now || at_ns < current.effective_ns {
        return Err(fail("resource.phase_time"));
    }
    *current = PhaseState {
        sequence,
        phase: next,
        effective_ns: now,
    };
    Ok(now)
}

#[derive(Debug, Serialize)]
struct Capture {
    schema_version: &'static str,
    writer_seq: u64,
    source: &'static str,
    planned_ns: u64,
    start_ns: u64,
    end_ns: u64,
    phase: Phase,
    phase_sequence: u64,
    phase_event_ns: u64,
    process: ProcessReference,
    gateway_pid: u32,
    gateway_start_ticks: Option<u64>,
    identity_valid: Option<bool>,
    identity_checks: Vec<ProcessCheck>,
    gaps_ns: Option<u64>,
    late_ns: u64,
    skipped_ticks: u64,
    checkpoint: Option<String>,
    rss_kib: Option<u64>,
    open_fds: Option<u64>,
    os_threads: Option<u64>,
    pss_kib: Option<u64>,
    private_dirty_kib: Option<u64>,
    smaps_due: bool,
    resources: Option<Value>,
    metrics: Option<String>,
    clusters: Option<Value>,
    runtime: Option<Value>,
    history: Option<Value>,
    liveness: Option<Value>,
    readiness: Option<Value>,
    scrapes: BTreeMap<&'static str, Scrape>,
    error: Option<String>,
    errors: Vec<ReadError>,
}

#[derive(Clone, Debug, Serialize)]
struct ReadError {
    source: &'static str,
    code: String,
}

#[derive(Debug, Serialize)]
struct ProcessCheck {
    stage: &'static str,
    process: ProcessReference,
    valid: Option<bool>,
    error: Option<String>,
}

impl Capture {
    fn new(
        source: &'static str,
        planned_ns: u64,
        phase: &Arc<Mutex<PhaseState>>,
        identity: &ProcessIdentity,
    ) -> Result<Self, SoakError> {
        let phase = phase.lock().map_err(|_| fail("resource.phase_lock"))?;
        let start_ns = monotonic_ns()?;
        Ok(Self {
            schema_version: "oxidase.resource-sample/v1",
            writer_seq: 0,
            source,
            planned_ns,
            start_ns,
            end_ns: start_ns,
            phase: phase.phase,
            phase_sequence: phase.sequence,
            phase_event_ns: phase.effective_ns,
            process: identity.reference(),
            gateway_pid: identity.pid,
            gateway_start_ticks: identity.start_ticks,
            identity_valid: None,
            identity_checks: Vec::new(),
            gaps_ns: None,
            late_ns: start_ns
                .checked_sub(planned_ns)
                .ok_or_else(|| fail("resource.clock_reversed"))?,
            skipped_ticks: 0,
            checkpoint: None,
            rss_kib: None,
            open_fds: None,
            os_threads: None,
            pss_kib: None,
            private_dirty_kib: None,
            smaps_due: false,
            resources: None,
            metrics: None,
            clusters: None,
            runtime: None,
            history: None,
            liveness: None,
            readiness: None,
            scrapes: BTreeMap::new(),
            error: None,
            errors: Vec::new(),
        })
    }

    fn error(&mut self, source: &'static str, code: impl Into<String>) {
        let code = code.into();
        if self.error.is_none() {
            self.error = Some(code.clone());
        }
        self.errors.push(ReadError { source, code });
    }
}

#[derive(Debug, Serialize)]
struct Scrape {
    start_ns: u64,
    end_ns: u64,
    status: Option<u16>,
    bytes: Option<u64>,
    etag: Option<String>,
    ok: bool,
    error: Option<String>,
}

struct ReadReply {
    scrape: Scrape,
    body: Option<Bytes>,
}

struct DriverGuard(Option<tokio::task::JoinHandle<()>>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        if let Some(driver) = &self.0 {
            driver.abort();
        }
    }
}

impl DriverGuard {
    async fn finish(&mut self) {
        if let Some(driver) = self.0.take() {
            driver.abort();
            let _ = driver.await;
        }
    }
}

const READ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;

async fn read_admin(
    root: &Path,
    token: &AdminBearerToken,
    path: &'static str,
) -> Result<ReadReply, SoakError> {
    let start_ns = monotonic_ns()?;
    let mut status = None;
    let mut etag = None;
    let mut received_bytes = None;
    let read = tokio::time::timeout(READ_TIMEOUT, async {
        let socket = tokio::net::UnixStream::connect(root.join("admin.sock"))
            .await
            .map_err(|_| "resource.admin_connect")?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket))
            .await
            .map_err(|_| "resource.admin_handshake")?;
        let mut driver = DriverGuard(Some(tokio::spawn(async move {
            let _ = connection.await;
        })));
        let response = sender
            .send_request(
                Request::builder()
                    .uri(path)
                    .header(header::HOST, "admin.test")
                    .header(header::AUTHORIZATION, token.authorization_header())
                    .body(Empty::<Bytes>::new())
                    .map_err(|_| "resource.admin_request")?,
            )
            .await
            .map_err(|_| "resource.admin_send")?;
        status = Some(response.status().as_u16());
        received_bytes = Some(0_u64);
        etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let allowed = response.status().is_success()
            || (path == "/health/ready"
                && response.status() == http::StatusCode::SERVICE_UNAVAILABLE);
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| "resource.admin_body")?;
            if frame.trailers_ref().is_some() {
                return Err("resource.admin_unexpected_trailers");
            }
            if let Some(data) = frame.data_ref() {
                received_bytes =
                    received_bytes.and_then(|bytes| bytes.checked_add(data.len() as u64));
                if bytes
                    .len()
                    .checked_add(data.len())
                    .is_none_or(|size| size > MAX_READ_BYTES)
                {
                    return Err("resource.admin_body_limit");
                }
                bytes.extend_from_slice(data);
            }
        }
        drop(body);
        drop(sender);
        driver.finish().await;
        if !allowed {
            return Err("resource.admin_status");
        }
        Ok::<_, &'static str>(Bytes::from(bytes))
    })
    .await;
    let end_ns = monotonic_ns()?;
    let (body, error) = match read {
        Ok(Ok(body)) => (Some(body), None),
        Ok(Err(code)) => (None, Some(code.to_owned())),
        Err(_) => (None, Some("resource.admin_timeout".to_owned())),
    };
    Ok(ReadReply {
        scrape: Scrape {
            start_ns,
            end_ns,
            status,
            bytes: received_bytes,
            etag,
            ok: error.is_none(),
            error,
        },
        body,
    })
}

async fn admin_capture(
    args: &ResourceSamplerArguments,
    identity: &ProcessIdentity,
    phase: &Arc<Mutex<PhaseState>>,
    token: &AdminBearerToken,
    planned_ns: u64,
    checkpoint: Option<String>,
) -> Result<Capture, SoakError> {
    let mut record = Capture::new("admin", planned_ns, phase, identity)?;
    record.checkpoint = checkpoint;
    verify_capture_identity(&mut record, identity, "before");
    let (resources, metrics, clusters, runtime, history, live, ready) = tokio::join!(
        read_admin(&args.root, token, "/api/v1/resources"),
        read_admin(&args.root, token, "/metrics"),
        read_admin(&args.root, token, "/api/v1/clusters"),
        read_admin(&args.root, token, "/api/v1/runtime"),
        read_admin(&args.root, token, "/api/v1/snapshots"),
        read_admin(&args.root, token, "/health/live"),
        read_admin(&args.root, token, "/health/ready"),
    );
    for (name, reply) in [
        ("resources", resources),
        ("metrics", metrics),
        ("clusters", clusters),
        ("runtime", runtime),
        ("history", history),
        ("liveness", live),
        ("readiness", ready),
    ] {
        let mut reply = reply?;
        if let Some(code) = &reply.scrape.error {
            record.error(name, code.clone());
        }
        if let Some(body) = reply.body.take() {
            if name == "metrics" {
                match String::from_utf8(body.to_vec()) {
                    Ok(text) => record.metrics = Some(text),
                    Err(_) => {
                        reply.scrape.ok = false;
                        reply.scrape.error = Some("resource.admin_utf8".to_owned());
                        record.error(name, "resource.admin_utf8");
                    }
                }
            } else if matches!(name, "liveness" | "readiness") {
                let value =
                    json!({"status": reply.scrape.status, "body": String::from_utf8_lossy(&body)});
                if name == "liveness" {
                    record.liveness = Some(value);
                } else {
                    record.readiness = Some(value);
                }
            } else {
                match serde_json::from_slice::<Value>(&body) {
                    Ok(value) => match name {
                        "resources" => record.resources = Some(value),
                        "clusters" => record.clusters = Some(value),
                        "runtime" => record.runtime = Some(value),
                        "history" => record.history = Some(value),
                        _ => unreachable!(),
                    },
                    Err(_) => {
                        reply.scrape.ok = false;
                        reply.scrape.error = Some("resource.admin_json".to_owned());
                        record.error(name, "resource.admin_json");
                    }
                }
            }
        }
        record.scrapes.insert(name, reply.scrape);
    }
    verify_capture_identity(&mut record, identity, "after");
    record.end_ns = monotonic_ns()?;
    Ok(record)
}

fn verify_capture_identity(record: &mut Capture, identity: &ProcessIdentity, stage: &'static str) {
    match resource_identity::verify(identity) {
        Ok(()) => {
            if record.identity_valid != Some(false) {
                record.identity_valid = Some(true);
            }
            record.identity_checks.push(ProcessCheck {
                stage,
                process: identity.reference(),
                valid: Some(true),
                error: None,
            });
        }
        Err(error) => {
            record.identity_valid = if cfg!(target_os = "linux") {
                Some(false)
            } else {
                None
            };
            record.identity_checks.push(ProcessCheck {
                stage,
                process: identity.reference(),
                valid: record.identity_valid,
                error: Some(error.to_string()),
            });
            record.error("identity", error.to_string());
        }
    }
}

fn status_number(text: &str, field: &str, kib: bool) -> Option<u64> {
    let mut values = text
        .lines()
        .find(|line| line.starts_with(field))?
        .split_whitespace();
    values.next()?;
    let value = values.next()?.parse().ok()?;
    if kib && values.next()? != "kB" {
        return None;
    }
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn os_capture(
    mut record: Capture,
    identity: &ProcessIdentity,
    smaps_due: bool,
    processes: &[ProcessIdentity],
) -> Result<Capture, SoakError> {
    record.smaps_due = smaps_due;
    for process in processes {
        verify_capture_identity(&mut record, process, "before");
    }
    let directory = Path::new("/proc").join(identity.pid.to_string());
    match std::fs::read_to_string(directory.join("status")) {
        Ok(status) => {
            record.rss_kib = status_number(&status, "VmRSS:", true);
            record.os_threads = status_number(&status, "Threads:", false);
            if record.rss_kib.is_none() {
                record.error("rss", "resource.proc_rss_missing");
            }
            if record.os_threads.is_none() {
                record.error("threads", "resource.proc_threads_missing");
            }
        }
        Err(_) => record.error("status", "resource.proc_status_unavailable"),
    }
    record.open_fds = std::fs::read_dir(directory.join("fd"))
        .ok()
        .and_then(|mut entries| {
            entries.try_fold(0_u64, |count, entry| {
                entry.ok()?;
                count.checked_add(1)
            })
        });
    if record.open_fds.is_none() {
        record.error("fd", "resource.proc_fd_unavailable");
    }
    if smaps_due {
        match std::fs::read_to_string(directory.join("smaps_rollup")) {
            Ok(smaps) => {
                record.pss_kib = status_number(&smaps, "Pss:", true);
                record.private_dirty_kib = status_number(&smaps, "Private_Dirty:", true);
                if record.pss_kib.is_none() || record.private_dirty_kib.is_none() {
                    record.error("smaps", "resource.proc_smaps_missing");
                }
            }
            Err(_) => record.error("smaps", "resource.proc_smaps_unavailable"),
        }
    }
    for process in processes {
        verify_capture_identity(&mut record, process, "after");
    }
    record.end_ns = monotonic_ns()?;
    Ok(record)
}

struct WriteRequest {
    capture: Capture,
    acknowledged: Option<oneshot::Sender<Result<(), &'static str>>>,
}

#[derive(Debug, Default, Serialize)]
struct WriterSummary {
    records: u64,
    os_records: u64,
    admin_records: u64,
    bytes: u64,
}

async fn sample_file(args: &ResourceSamplerArguments) -> Result<tokio::fs::File, SoakError> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output.join("samples.jsonl"))
        .await
        .map_err(|_| fail("resource.sample_file_create"))
}

async fn writer(
    args: &ResourceSamplerArguments,
    mut received: mpsc::Receiver<WriteRequest>,
    mut file: tokio::fs::File,
) -> Result<WriterSummary, SoakError> {
    let mut summary = WriterSummary::default();
    while let Some(mut request) = received.recv().await {
        summary.records = summary
            .records
            .checked_add(1)
            .ok_or_else(|| fail("resource.record_overflow"))?;
        if summary.records > args.max_records {
            return Err(fail("resource.record_limit"));
        }
        request.capture.writer_seq = summary.records;
        let mut bytes =
            serde_json::to_vec(&request.capture).map_err(|_| fail("resource.sample_json"))?;
        bytes.push(b'\n');
        summary.bytes = summary
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|bytes| *bytes <= args.max_artifact_bytes)
            .ok_or_else(|| fail("resource.artifact_limit"))?;
        file.write_all(&bytes)
            .await
            .map_err(|_| fail("resource.sample_write"))?;
        match request.capture.source {
            "os" => summary.os_records += 1,
            "admin" => summary.admin_records += 1,
            _ => return Err(fail("resource.sample_source")),
        }
        if let Some(acknowledged) = request.acknowledged {
            file.flush()
                .await
                .map_err(|_| fail("resource.sample_flush"))?;
            file.sync_data()
                .await
                .map_err(|_| fail("resource.sample_sync"))?;
            let _ = acknowledged.send(Ok(()));
        }
    }
    file.flush()
        .await
        .map_err(|_| fail("resource.sample_flush"))?;
    file.sync_all()
        .await
        .map_err(|_| fail("resource.sample_sync"))?;
    Ok(summary)
}

async fn persist(
    sent: &mpsc::Sender<WriteRequest>,
    capture: Capture,
    acknowledge: bool,
) -> Result<(), SoakError> {
    let (acknowledged, receive) = oneshot::channel();
    tokio::time::timeout(
        Duration::from_secs(5),
        sent.send(WriteRequest {
            capture,
            acknowledged: acknowledge.then_some(acknowledged),
        }),
    )
    .await
    .map_err(|_| fail("resource.sample_queue_timeout"))?
    .map_err(|_| fail("resource.sample_writer_closed"))?;
    if acknowledge {
        receive
            .await
            .map_err(|_| fail("resource.sample_ack_missing"))?
            .map_err(fail)?;
    }
    Ok(())
}

fn next_tick(due_ns: u64, interval_ms: u64, finished_ns: u64) -> Result<(u64, u64), SoakError> {
    let interval = interval_ms
        .checked_mul(1_000_000)
        .filter(|value| *value > 0)
        .ok_or_else(|| fail("resource.interval_invalid"))?;
    let next = due_ns
        .checked_add(interval)
        .ok_or_else(|| fail("resource.schedule_overflow"))?;
    if finished_ns < next {
        return Ok((next, 0));
    }
    let skipped = (finished_ns - next) / interval + 1;
    let next = interval
        .checked_mul(skipped)
        .and_then(|skip| next.checked_add(skip))
        .ok_or_else(|| fail("resource.schedule_overflow"))?;
    Ok((next, skipped))
}

async fn sleep_until(due_ns: u64) -> Result<(), SoakError> {
    let now = monotonic_ns()?;
    if let Some(delay) = due_ns.checked_sub(now) {
        tokio::time::sleep(Duration::from_nanos(delay)).await;
    }
    Ok(())
}

async fn os_loop(
    args: ResourceSamplerArguments,
    identity: ProcessIdentity,
    phase: Arc<Mutex<PhaseState>>,
    mut stop: watch::Receiver<bool>,
    sent: mpsc::Sender<WriteRequest>,
    processes: Arc<Vec<ProcessIdentity>>,
) -> Result<(), SoakError> {
    let mut due = monotonic_ns()?;
    let mut previous = None;
    let mut smaps_due = due;
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! { biased; _ = stop.changed() => break, ready = sleep_until(due) => ready?, }
        let record = Capture::new("os", due, &phase, &identity)?;
        let include_smaps = args.smaps_interval_ms > 0 && record.start_ns >= smaps_due;
        let observed = identity.clone();
        let observed_processes = Arc::clone(&processes);
        let mut record = tokio::task::spawn_blocking(move || {
            os_capture(record, &observed, include_smaps, &observed_processes)
        })
        .await
        .map_err(|_| fail("resource.os_worker_panic"))??;
        record.gaps_ns = previous
            .map(|previous| {
                record
                    .start_ns
                    .checked_sub(previous)
                    .ok_or_else(|| fail("resource.clock_reversed"))
            })
            .transpose()?;
        previous = Some(record.start_ns);
        if include_smaps {
            smaps_due = record
                .start_ns
                .checked_add(args.smaps_interval_ms * 1_000_000)
                .ok_or_else(|| fail("resource.schedule_overflow"))?;
        }
        let (next, skipped) = next_tick(due, args.interval_ms, record.end_ns)?;
        record.skipped_ticks = skipped;
        let identity_failed = record.identity_valid == Some(false);
        persist(&sent, record, false).await?;
        if identity_failed {
            return Err(fail("resource.process_identity_lost"));
        }
        due = next;
    }
    Ok(())
}

struct Checkpoint {
    id: String,
    finished: oneshot::Sender<Result<(), &'static str>>,
}

async fn admin_loop(
    args: ResourceSamplerArguments,
    identity: ProcessIdentity,
    phase: Arc<Mutex<PhaseState>>,
    token: AdminBearerToken,
    mut stop: watch::Receiver<bool>,
    mut checkpoints: mpsc::Receiver<Checkpoint>,
    sent: mpsc::Sender<WriteRequest>,
) -> Result<(), SoakError> {
    let mut due = monotonic_ns()?;
    let mut previous = None;
    loop {
        if *stop.borrow() {
            break;
        }
        let checkpoint = tokio::select! {
            biased;
            _ = stop.changed() => break,
            checkpoint = checkpoints.recv() => Some(checkpoint.ok_or_else(|| fail("resource.checkpoint_channel_closed"))?),
            ready = sleep_until(due), if args.admin_interval_ms > 0 => { ready?; None },
        };
        let planned = if checkpoint.is_some() {
            monotonic_ns()?
        } else {
            due
        };
        let mut record = admin_capture(
            &args,
            &identity,
            &phase,
            &token,
            planned,
            checkpoint.as_ref().map(|checkpoint| checkpoint.id.clone()),
        )
        .await?;
        record.gaps_ns = previous
            .map(|previous| {
                record
                    .start_ns
                    .checked_sub(previous)
                    .ok_or_else(|| fail("resource.clock_reversed"))
            })
            .transpose()?;
        previous = Some(record.start_ns);
        if args.admin_interval_ms > 0 {
            let (next, skipped) = next_tick(due, args.admin_interval_ms, record.end_ns)?;
            due = next;
            record.skipped_ticks = skipped;
        }
        let identity_failed = record.identity_valid == Some(false);
        persist(&sent, record, checkpoint.is_some()).await?;
        if let Some(checkpoint) = checkpoint {
            let _ = checkpoint.finished.send(Ok(()));
        }
        if identity_failed {
            return Err(fail("resource.gateway_identity_lost"));
        }
    }
    Ok(())
}

async fn checkpoint(sent: &mpsc::Sender<Checkpoint>, id: String) -> Result<(), SoakError> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(fail("resource.checkpoint_invalid"));
    }
    let (finished, wait) = oneshot::channel();
    tokio::time::timeout(
        Duration::from_secs(5),
        sent.send(Checkpoint { id, finished }),
    )
    .await
    .map_err(|_| fail("resource.checkpoint_queue_timeout"))?
    .map_err(|_| fail("resource.checkpoint_unavailable"))?;
    tokio::time::timeout(Duration::from_secs(10), wait)
        .await
        .map_err(|_| fail("resource.checkpoint_timeout"))?
        .map_err(|_| fail("resource.checkpoint_incomplete"))?
        .map_err(fail)
}

fn token(root: &Path) -> Result<AdminBearerToken, SoakError> {
    let path = root.join("admin.token");
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| fail("resource.token_unreadable"))?;
    if !metadata.is_file() || metadata.len() > MAX_ADMIN_BEARER_TOKEN_BYTES as u64 + 2 {
        return Err(fail("resource.token_not_regular_or_large"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(fail("resource.token_permissions"));
        }
    }
    let mut bytes = std::fs::read(&path).map_err(|_| fail("resource.token_unreadable"))?;
    let token =
        AdminBearerToken::parse_file_bytes(&bytes).map_err(|_| fail("resource.token_invalid"));
    bytes.fill(0); // Best effort only, not a guarantee about compiler copies.
    token
}

async fn line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> Result<Option<Vec<u8>>, SoakError> {
    let mut line = Vec::new();
    loop {
        let bytes = reader
            .fill_buf()
            .await
            .map_err(|_| fail("resource.command_read"))?;
        if bytes.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(fail("resource.command_truncated"))
            };
        }
        let count = bytes
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |index| index + 1);
        if line
            .len()
            .checked_add(count)
            .is_none_or(|length| length > 4096)
        {
            return Err(fail("resource.command_limit"));
        }
        let done = bytes[count - 1] == b'\n';
        line.extend_from_slice(&bytes[..count]);
        reader.consume(count);
        if done {
            return Ok(Some(line));
        }
    }
}

async fn emit(value: Value) -> Result<(), SoakError> {
    let mut bytes = serde_json::to_vec(&value).map_err(|_| fail("resource.reply_json"))?;
    bytes.push(b'\n');
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(&bytes)
        .await
        .map_err(|_| fail("resource.reply_write"))?;
    stdout
        .flush()
        .await
        .map_err(|_| fail("resource.reply_flush"))
}

// Helper-process jobs own no gateway resources. This guard still prevents a
// rejected IPC/output operation from detaching sampler tasks until process exit.
struct OwnedTask<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

impl<T> OwnedTask<T> {
    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        self.0.take().expect("owned task joined once").await
    }
}

struct FailureNotice {
    sent: mpsc::Sender<String>,
    source: &'static str,
    finished: bool,
}

impl Drop for FailureNotice {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self
                .sent
                .try_send(format!("resource.{}_worker_abandoned", self.source));
        }
    }
}

fn worker<T: Send + 'static>(
    future: impl Future<Output = Result<T, SoakError>> + Send + 'static,
    failures: mpsc::Sender<String>,
    source: &'static str,
) -> OwnedTask<Result<T, SoakError>> {
    OwnedTask(Some(tokio::spawn(async move {
        let mut notice = FailureNotice {
            sent: failures,
            source,
            finished: false,
        };
        let result = future.await;
        if let Err(error) = &result {
            let _ = notice.sent.try_send(error.to_string());
        }
        notice.finished = true;
        result
    })))
}

pub(super) async fn run_sampler(args: ResourceSamplerArguments) -> Result<(), SoakError> {
    let validation_started_ns = monotonic_ns()?;
    eprintln!(
        "{}",
        json!({"event":"sampler_startup_progress","schema_version":"oxidase.resource-sampler/v1","stage":"validation_started","t_ns":validation_started_ns})
    );
    if !(100..=60000).contains(&args.interval_ms)
        || args.admin_interval_ms > 60000
        || (args.admin_interval_ms > 0 && args.admin_interval_ms < 100)
        || args.smaps_interval_ms > 600000
        || (args.smaps_interval_ms > 0 && args.smaps_interval_ms < args.interval_ms)
        || !(4096..=2 * 1024 * 1024 * 1024).contains(&args.max_artifact_bytes)
        || args.max_records == 0
        || args.max_records > 1_000_000
    {
        return Err(fail("resource.sampler_arguments"));
    }
    let mut document = Vec::new();
    std::fs::File::open(&args.identity_file)
        .map_err(|_| fail("resource.identity_file"))?
        .take(64 * 1024 + 1)
        .read_to_end(&mut document)
        .map_err(|_| fail("resource.identity_file"))?;
    if document.len() > 64 * 1024 {
        return Err(fail("resource.identity_file_limit"));
    }
    let document: Value =
        serde_json::from_slice(&document).map_err(|_| fail("resource.identity_json"))?;
    if document["clock"] != "CLOCK_MONOTONIC" {
        return Err(fail("resource.identity_clock"));
    }
    let mut processes: Vec<ProcessIdentity> = serde_json::from_value(document["processes"].clone())
        .map_err(|_| fail("resource.identity_processes"))?;
    if processes.len() != 4
        || [
            ProcessRole::Gateway,
            ProcessRole::Controller,
            ProcessRole::Dns,
            ProcessRole::Upstream,
        ]
        .into_iter()
        .any(|role| {
            processes
                .iter()
                .filter(|process| process.role == role)
                .count()
                != 1
        })
        || processes.iter().enumerate().any(|(index, process)| {
            processes[..index]
                .iter()
                .any(|prior| prior.pid == process.pid)
        })
    {
        return Err(fail("resource.identity_roles"));
    }
    if cfg!(target_os = "linux") {
        for process in &processes {
            resource_identity::verify(process)?;
        }
    }
    let identity = processes
        .iter()
        .find(|process| process.role == ProcessRole::Gateway)
        .expect("role checked")
        .clone();
    let capture_started_ns = monotonic_ns()?;
    eprintln!(
        "{}",
        json!({"event":"sampler_startup_progress","schema_version":"oxidase.resource-sampler/v1","stage":"self_identity_capture_started","t_ns":capture_started_ns,"validation_duration_ns":capture_started_ns.checked_sub(validation_started_ns)})
    );
    let own = resource_identity::capture(
        ProcessRole::Sampler,
        std::process::id(),
        &std::env::current_exe().map_err(|_| fail("resource.sampler_executable"))?,
    )?;
    let capture_completed_ns = monotonic_ns()?;
    eprintln!(
        "{}",
        json!({"event":"sampler_startup_progress","schema_version":"oxidase.resource-sampler/v1","stage":"self_identity_capture_completed","t_ns":capture_completed_ns,"capture_duration_ns":capture_completed_ns.checked_sub(capture_started_ns)})
    );
    processes.push(own.clone());
    let boot_ns = monotonic_ns()?;
    let phase = Arc::new(Mutex::new(PhaseState {
        sequence: 0,
        phase: Phase::Bootstrap,
        effective_ns: boot_ns,
    }));
    let token = token(&args.root)?;
    let file = sample_file(&args).await?;
    let (stop, stopped) = watch::channel(false);
    let (samples, received) = mpsc::channel(128);
    let (failures, mut failed) = mpsc::channel(3);
    let writer_args = args.clone();
    let writer = worker(
        async move { writer(&writer_args, received, file).await },
        failures.clone(),
        "writer",
    );
    let os = worker(
        os_loop(
            args.clone(),
            identity.clone(),
            Arc::clone(&phase),
            stopped.clone(),
            samples.clone(),
            Arc::new(processes),
        ),
        failures.clone(),
        "os",
    );
    let (checkpoints, requested) = mpsc::channel(16);
    let admin = worker(
        admin_loop(
            args.clone(),
            identity,
            Arc::clone(&phase),
            token,
            stopped,
            requested,
            samples.clone(),
        ),
        failures,
        "admin",
    );
    let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
    let mut commanded_stop = false;
    let commands = async {
        emit(json!({"event":"sampler_ready", "schema_version":"oxidase.resource-sampler/v1", "clock":"CLOCK_MONOTONIC", "ready_ns":boot_ns, "identity":own})).await?;
        checkpoint(&checkpoints, "initial".to_owned()).await?;
        while let Some(bytes) = line(&mut reader).await? {
            match serde_json::from_slice::<Command>(&bytes)
                .map_err(|_| fail("resource.command_json"))?
            {
                Command::Phase {
                    sequence,
                    phase: next,
                    at_ns,
                } => {
                    let effective_ns = {
                        let mut current = phase.lock().map_err(|_| fail("resource.phase_lock"))?;
                        change_phase(&mut current, sequence, next, at_ns)?
                    };
                    emit(json!({"event":"phase_ack","sequence":sequence,"phase":next,"requested_ns":at_ns,"effective_ns":effective_ns})).await?;
                }
                Command::Checkpoint { id } => {
                    checkpoint(&checkpoints, id.clone()).await?;
                    emit(json!({"event":"checkpoint_ack","id":id,"completed_ns":monotonic_ns()?}))
                        .await?;
                }
                Command::Stop => {
                    commanded_stop = true;
                    break;
                }
            }
        }
        if !commanded_stop {
            return Err(fail("resource.command_eof_before_stop"));
        }
        checkpoint(&checkpoints, "final".to_owned()).await
    };
    let result = tokio::select! {
        biased;
        error = failed.recv() => Err(fail(error.unwrap_or_else(|| "resource.workers_unavailable".to_owned()))),
        result = commands => result,
    };
    stop.send_replace(true);
    drop(checkpoints);
    drop(samples);
    let os_result = os.join().await;
    let admin_result = admin.join().await;
    let writer_result = writer.join().await;
    result?;
    os_result.map_err(|_| fail("resource.os_task_panic"))??;
    admin_result.map_err(|_| fail("resource.admin_task_panic"))??;
    let summary = writer_result.map_err(|_| fail("resource.writer_panic"))??;
    emit(json!({"event":"sampler_stopped", "schema_version":"oxidase.resource-sampler/v1", "completed_ns":monotonic_ns()?, "summary":summary})).await
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http::{Response, StatusCode};
    use http_body_util::Full;
    use hyper::service::service_fn;
    use tokio::sync::Notify;

    use super::*;

    const TEST_TOKEN: &[u8] = b"test-only-public-sampler-token\n";

    struct AdminFixture {
        root: tempfile::TempDir,
        requests: Arc<AtomicUsize>,
        entered: Arc<Notify>,
        release: Arc<Notify>,
        task: OwnedTask<()>,
    }

    impl AdminFixture {
        async fn start(slow: bool) -> Self {
            use std::os::unix::fs::PermissionsExt as _;
            let root = tempfile::tempdir().expect("fixture");
            std::fs::write(root.path().join("admin.token"), TEST_TOKEN).expect("fixture token");
            std::fs::set_permissions(
                root.path().join("admin.token"),
                std::fs::Permissions::from_mode(0o600),
            )
            .expect("private token file");
            let listener = tokio::net::UnixListener::bind(root.path().join("admin.sock"))
                .expect("fixture listener");
            let requests = Arc::new(AtomicUsize::new(0));
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            let seen = Arc::clone(&requests);
            let began = Arc::clone(&entered);
            let finish = Arc::clone(&release);
            let task = OwnedTask(Some(tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        result = listener.accept() => {
                            let (socket, _) = result.expect("fixture accept");
                            let seen = Arc::clone(&seen);
                            let began = Arc::clone(&began);
                            let finish = Arc::clone(&finish);
                            connections.spawn(async move {
                                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                                    let seen = Arc::clone(&seen);
                                    let began = Arc::clone(&began);
                                    let finish = Arc::clone(&finish);
                                    async move {
                                        let expected = AdminBearerToken::parse_file_bytes(TEST_TOKEN).expect("fixture token");
                                        assert_eq!(request.headers().get(header::AUTHORIZATION), Some(&expected.authorization_header()));
                                        seen.fetch_add(1, Ordering::SeqCst);
                                        if slow && request.uri().path() == "/api/v1/resources" {
                                            began.notify_one();
                                            finish.notified().await;
                                        }
                                        let body = if request.uri().path() == "/metrics" { Bytes::from_static(b"oxidase_active_requests 0\n") } else { Bytes::from_static(br#"{"fixture":true}"#) };
                                        let status = if request.uri().path() == "/health/ready" { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK };
                                        Ok::<_, Infallible>(Response::builder().status(status).header(header::ETAG, "\"fixture\"").body(Full::new(body)).expect("fixture response"))
                                    }
                                });
                                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                            });
                        }
                        _ = connections.join_next(), if !connections.is_empty() => {}
                    }
                }
            })));
            Self {
                root,
                requests,
                entered,
                release,
                task,
            }
        }

        fn arguments(&self) -> ResourceSamplerArguments {
            ResourceSamplerArguments {
                root: self.root.path().to_owned(),
                output: self.root.path().to_owned(),
                identity_file: self.root.path().join("identity.json"),
                interval_ms: 100,
                admin_interval_ms: 0,
                smaps_interval_ms: 0,
                max_artifact_bytes: 1_000_000,
                max_records: 100,
            }
        }

        async fn finish(self) {
            let task = self.task.0.as_ref().expect("fixture task");
            task.abort();
            assert!(
                self.task
                    .join()
                    .await
                    .expect_err("fixture shutdown is cancellation")
                    .is_cancelled()
            );
        }
    }

    fn identity_and_phase() -> (ProcessIdentity, Arc<Mutex<PhaseState>>) {
        let identity = resource_identity::capture(
            ProcessRole::Gateway,
            std::process::id(),
            &std::env::current_exe().expect("executable"),
        )
        .expect("fixture process identity");
        let phase = Arc::new(Mutex::new(PhaseState {
            sequence: 0,
            phase: Phase::Bootstrap,
            effective_ns: monotonic_ns().expect("clock"),
        }));
        (identity, phase)
    }

    async fn received(receiver: &mut mpsc::Receiver<WriteRequest>) -> WriteRequest {
        tokio::time::timeout(Duration::from_secs(3), receiver.recv())
            .await
            .expect("bounded sample deadline")
            .expect("sample")
    }

    #[test]
    fn absolute_schedule_reports_missed_ticks_without_burst_or_shift() {
        assert_eq!(next_tick(100, 1, 101).expect("schedule"), (1_000_100, 0));
        assert_eq!(
            next_tick(100, 1, 3_000_100).expect("missed"),
            (4_000_100, 3)
        );
        assert!(next_tick(u64::MAX, 1, u64::MAX).is_err());
        assert!(next_tick(1, 0, 2).is_err());
    }

    #[test]
    fn proc_numbers_require_exact_units_and_never_supply_missing_zero() {
        assert_eq!(
            status_number("VmRSS: 12 kB\nThreads: 3\n", "VmRSS:", true),
            Some(12)
        );
        assert_eq!(status_number("Threads: 3\n", "Threads:", false), Some(3));
        assert_eq!(status_number("VmRSS: 12 MB\n", "VmRSS:", true), None);
        assert_eq!(status_number("VmRSS: x kB\n", "VmRSS:", true), None);
        assert_eq!(status_number("", "VmRSS:", true), None);
    }

    #[test]
    fn command_schema_is_narrow_and_no_credential_is_in_a_sample() {
        assert!(
            serde_json::from_str::<Command>(
                r#"{"op":"phase","sequence":1,"phase":"steady","at_ns":1}"#
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<Command>(
                r#"{"op":"phase","sequence":1,"phase":"steady","at_ns":1,"token":"bad"}"#
            )
            .is_err()
        );
        let identity = ProcessIdentity {
            role: ProcessRole::Gateway,
            pid: 99,
            start_ticks: None,
            boot_id: None,
            binary_sha256: "binary".to_owned(),
            exe_sha256: None,
            proc_verified: false,
            executable_identity: None,
        };
        let phase = Arc::new(Mutex::new(PhaseState {
            sequence: 0,
            phase: Phase::Bootstrap,
            effective_ns: 1,
        }));
        let capture = Capture::new("os", 1, &phase, &identity).expect("capture");
        let json = serde_json::to_string(&capture).expect("JSON");
        assert!(!json.contains("Bearer"));
        assert!(!json.contains("admin.token"));
        assert!(!json.contains("binary_sha256"));
        assert!(capture.resources.is_none());
    }

    #[test]
    fn phase_ack_boundary_is_monotonic_and_rejects_skip_replay_or_future() {
        let mut phase = PhaseState {
            sequence: 0,
            phase: Phase::Bootstrap,
            effective_ns: monotonic_ns().expect("clock"),
        };
        assert!(
            change_phase(&mut phase, 1, Phase::Steady, monotonic_ns().expect("clock")).is_err()
        );
        let effective = change_phase(&mut phase, 1, Phase::Warmup, monotonic_ns().expect("clock"))
            .expect("phase");
        assert_eq!(phase.effective_ns, effective);
        assert!(change_phase(&mut phase, 1, Phase::Steady, effective).is_err());
        assert!(change_phase(&mut phase, 2, Phase::Steady, u64::MAX).is_err());
        assert!(
            Capture::new(
                "os",
                u64::MAX,
                &Arc::new(Mutex::new(phase)),
                &identity_and_phase().0
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn os_samples_continue_while_authenticated_admin_response_is_blocked() {
        let fixture = AdminFixture::start(true).await;
        let args = fixture.arguments();
        let (identity, phase) = identity_and_phase();
        let capture_args = args.clone();
        let capture_identity = identity.clone();
        let capture_phase = Arc::clone(&phase);
        let authorization = token(&args.root).expect("private credential");
        let admin = OwnedTask(Some(tokio::spawn(async move {
            admin_capture(
                &capture_args,
                &capture_identity,
                &capture_phase,
                &authorization,
                monotonic_ns().expect("clock"),
                None,
            )
            .await
        })));
        tokio::time::timeout(Duration::from_secs(3), fixture.entered.notified())
            .await
            .expect("admin reached fixture barrier");
        let (stop, stopped) = watch::channel(false);
        let (sent, mut records) = mpsc::channel(8);
        let processes = Arc::new(vec![identity.clone()]);
        let os = OwnedTask(Some(tokio::spawn(os_loop(
            args, identity, phase, stopped, sent, processes,
        ))));
        for _ in 0..3 {
            let record = received(&mut records).await.capture;
            assert_eq!(record.source, "os");
            assert!(record.resources.is_none());
            assert!(record.end_ns >= record.start_ns);
            #[cfg(target_os = "linux")]
            {
                assert_eq!(record.identity_valid, Some(true));
                assert!(record.rss_kib.is_some());
                assert!(record.open_fds.is_some());
            }
        }
        assert!(!admin.0.as_ref().expect("admin task").is_finished());
        fixture.release.notify_one();
        let record = admin
            .join()
            .await
            .expect("admin task")
            .expect("admin capture");
        assert!(record.resources.is_some());
        assert_eq!(
            record.readiness.as_ref().expect("ready metadata")["status"],
            503
        );
        assert!(record.scrapes["readiness"].ok);
        assert_eq!(
            record.scrapes["resources"].etag.as_deref(),
            Some("\"fixture\"")
        );
        stop.send_replace(true);
        os.join().await.expect("OS task").expect("OS sampling");
        fixture.finish().await;
    }

    #[tokio::test]
    async fn zero_periodic_scrape_keeps_os_ticks_and_only_explicit_admin_checkpoints() {
        let fixture = AdminFixture::start(false).await;
        let args = fixture.arguments();
        let (identity, phase) = identity_and_phase();
        let (stop, stopped) = watch::channel(false);
        let (samples, mut received_samples) = mpsc::channel(16);
        let (checkpoints, requested) = mpsc::channel(2);
        let admin = OwnedTask(Some(tokio::spawn(admin_loop(
            args.clone(),
            identity.clone(),
            Arc::clone(&phase),
            token(&args.root).expect("credential"),
            stopped.clone(),
            requested,
            samples.clone(),
        ))));
        let processes = Arc::new(vec![identity.clone()]);
        let os = OwnedTask(Some(tokio::spawn(os_loop(
            args.clone(),
            identity,
            phase,
            stopped,
            samples.clone(),
            processes,
        ))));
        for _ in 0..3 {
            assert_eq!(received(&mut received_samples).await.capture.source, "os");
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 0);
        for id in ["initial", "final"] {
            let (finished, wait) = oneshot::channel();
            checkpoints
                .send(Checkpoint {
                    id: id.to_owned(),
                    finished,
                })
                .await
                .expect("checkpoint admitted");
            loop {
                let sample = received(&mut received_samples).await;
                if sample.capture.source == "admin" {
                    assert_eq!(sample.capture.checkpoint.as_deref(), Some(id));
                    assert!(sample.capture.resources.is_some());
                    assert!(sample.capture.metrics.is_some());
                    assert_eq!(sample.capture.scrapes.len(), 7);
                    sample
                        .acknowledged
                        .expect("checkpoint durable writer ack")
                        .send(Ok(()))
                        .expect("ack receiver");
                    break;
                }
            }
            wait.await
                .expect("checkpoint completed")
                .expect("checkpoint OK");
        }
        assert_eq!(fixture.requests.load(Ordering::SeqCst), 14);
        stop.send_replace(true);
        drop(checkpoints);
        os.join().await.expect("OS task").expect("OS sampling");
        admin
            .join()
            .await
            .expect("admin task")
            .expect("admin sampling");
        drop(samples);
        fixture.finish().await;
    }

    #[tokio::test]
    async fn writer_ack_means_synced_record_and_artifact_limits_fail_not_truncate_silently() {
        let fixture = AdminFixture::start(false).await;
        let mut args = fixture.arguments();
        let (identity, phase) = identity_and_phase();
        let (samples, received) = mpsc::channel(2);
        let file = sample_file(&args).await.expect("new sample file");
        let writer_args = args.clone();
        let written = OwnedTask(Some(tokio::spawn(async move {
            writer(&writer_args, received, file).await
        })));
        persist(
            &samples,
            Capture::new("os", monotonic_ns().expect("clock"), &phase, &identity).expect("sample"),
            true,
        )
        .await
        .expect("durable record acknowledgement");
        let recorded =
            std::fs::read_to_string(args.output.join("samples.jsonl")).expect("acknowledged file");
        let record: Value =
            serde_json::from_str(recorded.trim()).expect("full newline JSON record");
        assert_eq!(record["writer_seq"], 1);
        drop(samples);
        let summary = written
            .join()
            .await
            .expect("writer task")
            .expect("writer flush");
        assert_eq!(summary.records, 1);
        assert_eq!(summary.bytes as usize, recorded.len());
        assert!(sample_file(&args).await.is_err());

        args.output = args.root.join("overflow");
        std::fs::create_dir(&args.output).expect("overflow directory");
        args.max_artifact_bytes = 4;
        let (samples, received) = mpsc::channel(2);
        samples
            .send(WriteRequest {
                capture: Capture::new("os", monotonic_ns().expect("clock"), &phase, &identity)
                    .expect("sample"),
                acknowledged: None,
            })
            .await
            .expect("sample admitted");
        drop(samples);
        let error = writer(&args, received, sample_file(&args).await.expect("file"))
            .await
            .expect_err("artifact cap is a failure");
        assert_eq!(error.to_string(), "resource.artifact_limit");
        assert_eq!(
            std::fs::metadata(args.output.join("samples.jsonl"))
                .expect("partial artifact")
                .len(),
            0
        );
        fixture.finish().await;
    }

    #[tokio::test]
    async fn commands_are_size_bounded_and_truncated_ipc_is_an_error() {
        let bytes = b"{\"op\":\"stop\"}\n";
        assert_eq!(
            line(&mut tokio::io::BufReader::new(&bytes[..]))
                .await
                .expect("command"),
            Some(bytes.to_vec())
        );
        assert!(
            line(&mut tokio::io::BufReader::new(&bytes[..bytes.len() - 1]))
                .await
                .is_err()
        );
        assert!(
            line(&mut tokio::io::BufReader::new(&vec![b'a'; 4097][..]))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn owned_helper_task_is_cancelled_even_before_its_first_poll() {
        struct Completion(Option<oneshot::Sender<()>>);
        impl Drop for Completion {
            fn drop(&mut self) {
                if let Some(sent) = self.0.take() {
                    let _ = sent.send(());
                }
            }
        }
        let (finished, wait) = oneshot::channel();
        let owned = Completion(Some(finished));
        let task = OwnedTask(Some(tokio::spawn(async move {
            let _owned = owned;
            std::future::pending::<()>().await;
        })));
        drop(task);
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .expect("owned future cancellation is bounded")
            .expect("actual owned future drop");
    }

    #[tokio::test]
    async fn failed_writer_notifies_control_instead_of_silently_stopping_samples() {
        let (sent, mut received) = mpsc::channel(3);
        let job = worker(
            async { Err::<(), _>(fail("resource.artifact_limit")) },
            sent,
            "writer",
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), received.recv())
                .await
                .expect("bounded failure report")
                .expect("failure code"),
            "resource.artifact_limit"
        );
        assert_eq!(
            job.join()
                .await
                .expect("worker join")
                .expect_err("failed writer is not success")
                .to_string(),
            "resource.artifact_limit"
        );
    }
}
