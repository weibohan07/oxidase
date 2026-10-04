//! Separate-process Running resource qualification. This controller owns no
//! gateway publisher, resolver, endpoint, client pool or admission state.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use super::client::{self, GatewayProcess, ResourceDataClient, ResourceRequest};
use super::resource_evidence::{self, JsonLines, OperationEvent};
use super::resource_identity::{self, ProcessRole, monotonic_ns};
use super::{
    Campaign, FixtureCommand, FixtureProcess, ResourceArguments, ResourceCampaign, SoakError, fail,
    io_error, json_error,
};
use crate::common::{client_config, identity, write_identity};

const PHASES: [&str; 5] = ["warmup", "steady", "recovery", "quiet", "post_drain"];

#[derive(Clone)]
struct FaultInterval {
    id: String,
    start: u64,
    end: Option<u64>,
}
type Faults = Arc<Mutex<Vec<FaultInterval>>>;

#[derive(Default)]
struct LoadAdmission {
    state: Mutex<(bool, usize)>,
    changed: tokio::sync::Notify,
}
struct OperationGuard(Arc<LoadAdmission>);
impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1 = state
            .1
            .checked_sub(1)
            .expect("load admission guard underflow");
        drop(state);
        self.0.changed.notify_waiters();
    }
}
impl LoadAdmission {
    async fn begin(
        self: &Arc<Self>,
        stop: &tokio::sync::watch::Receiver<bool>,
        failed: &AtomicBool,
    ) -> Option<OperationGuard> {
        loop {
            let changed = self.changed.notified();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *stop.borrow() || failed.load(Ordering::Acquire) {
                    return None;
                }
                if !state.0 {
                    state.1 += 1;
                    return Some(OperationGuard(Arc::clone(self)));
                }
            }
            changed.await;
        }
    }
    async fn pause(&self) -> Result<(), SoakError> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = true;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                let changed = self.changed.notified();
                if self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .1
                    == 0
                {
                    break;
                }
                changed.await;
            }
        })
        .await
        .map_err(|_| fail("phase transition could not collect already-started operations"))
    }
    fn resume(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0 = false;
        self.changed.notify_waiters();
    }
}

fn fault_at(faults: &Faults, raw: &Value) -> Option<String> {
    let at = raw["head_ns"]
        .as_u64()
        .or_else(|| raw["ended_ns"].as_u64())?;
    faults
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .rev()
        .find(|window| window.start <= at && window.end.is_none_or(|end| at <= end))
        .map(|window| window.id.clone())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn file_digest(path: &Path) -> Result<String, SoakError> {
    let mut input = std::fs::File::open(path).map_err(io_error)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut input, &mut DigestWriter(&mut hash)).map_err(io_error)?;
    Ok(hex(&hash.finalize()))
}

struct DigestWriter<'a>(&'a mut Sha256);
impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn source_identity() -> Result<Value, SoakError> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(io_error)?;
    let execute = |args: &[&str]| -> Result<String, SoakError> {
        let output = std::process::Command::new("git")
            .current_dir(&root)
            .args(args)
            .output()
            .map_err(io_error)?;
        if !output.status.success() {
            return Err(fail("source identity git command failed"));
        }
        String::from_utf8(output.stdout).map_err(io_error)
    };
    let commit = execute(&["rev-parse", "HEAD"])?;
    let dirty = !execute(&["status", "--porcelain=v1", "--untracked-files=normal"])?
        .trim()
        .is_empty();
    let listed = execute(&["ls-files", "--cached", "--others", "--exclude-standard"])?;
    let mut files = BTreeMap::new();
    for path in listed.lines() {
        if path.ends_with(".rs")
            || path.ends_with("Cargo.toml")
            || path.ends_with("Cargo.lock")
            || path.starts_with("tools/qualification/")
            || path.starts_with(".github/workflows/")
        {
            files.insert(path.to_owned(), file_digest(&root.join(path))?);
        }
    }
    let source_files: Vec<_> = files
        .into_iter()
        .map(|(path, sha256)| json!({"path":path,"sha256":sha256}))
        .collect();
    let encoded = serde_json::to_vec(&source_files).map_err(json_error)?;
    Ok(
        json!({"commit":commit.trim(),"dirty":dirty,"source_set_sha256":digest(&encoded),"source_files":source_files}),
    )
}

/// This records a completed build's identity; it does not itself perform or
/// certify a build. The workflow must retain the preceding locked build log.
pub(super) fn build_record(gateway: &Path, output: &Path) -> Result<(), SoakError> {
    let identity = source_identity()?;
    let executable = std::env::current_exe().map_err(io_error)?;
    let value = json!({"schema_version":"oxidase.resource-build/v1","source":identity,
        "gateway_sha256":file_digest(gateway)?,"tool_sha256":file_digest(&executable)?,
        "build_claim":"identity recorded after caller's documented build; no independent compile attestation",
        "rustc":std::process::Command::new("rustc").arg("-Vv").output().map_err(io_error).and_then(|r|String::from_utf8(r.stdout).map_err(io_error))?});
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(io_error)?;
    file.write_all(&serde_json::to_vec_pretty(&value).map_err(json_error)?)
        .map_err(io_error)?;
    Ok(())
}

struct Sampler {
    child: Child,
    input: ChildStdin,
    output: tokio::io::Lines<BufReader<ChildStdout>>,
    ready: Value,
    sequence: u64,
}

impl Sampler {
    async fn spawn(
        root: &Path,
        args: &ResourceArguments,
        identity: &Path,
    ) -> Result<Self, SoakError> {
        let stderr =
            std::fs::File::create(args.output.join("sampler.stderr.log")).map_err(io_error)?;
        let mut child = Command::new(std::env::current_exe().map_err(io_error)?)
            .arg("resource-sampler")
            .arg("--root")
            .arg(root)
            .arg("--output")
            .arg(&args.output)
            .arg("--identity-file")
            .arg(identity)
            .arg("--interval-ms")
            .arg(args.sample_interval_ms.to_string())
            .arg("--admin-interval-ms")
            .arg(args.scrape_interval_ms.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(io_error)?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| fail("sampler input absent"))?;
        let mut output = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| fail("sampler output absent"))?,
        )
        .lines();
        let line = tokio::time::timeout(Duration::from_secs(10), output.next_line())
            .await
            .map_err(|_| fail("sampler readiness deadline"))?
            .map_err(io_error)?
            .ok_or_else(|| fail("sampler exited before ready"))?;
        let ready: Value = serde_json::from_str(&line).map_err(json_error)?;
        if ready["event"] != "sampler_ready" {
            return Err(fail("sampler readiness rejected"));
        }
        Ok(Self {
            child,
            input,
            output,
            ready,
            sequence: 0,
        })
    }

    async fn command(&mut self, mut value: Value) -> Result<Value, SoakError> {
        if value["op"] == "phase" {
            self.sequence += 1;
            value["sequence"] = self.sequence.into();
        }
        let mut bytes = serde_json::to_vec(&value).map_err(json_error)?;
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.map_err(io_error)?;
        self.input.flush().await.map_err(io_error)?;
        let line = tokio::time::timeout(Duration::from_secs(15), self.output.next_line())
            .await
            .map_err(|_| fail("sampler command timeout"))?
            .map_err(io_error)?
            .ok_or_else(|| fail("sampler command EOF"))?;
        if line.len() > 1024 * 1024 {
            return Err(fail("sampler command exceeds limit"));
        }
        let reply: Value = serde_json::from_str(&line).map_err(json_error)?;
        if !matches!(
            reply["event"].as_str(),
            Some("phase_ack" | "checkpoint_ack" | "sampler_stopped")
        ) {
            return Err(fail(format!("sampler command failed: {reply}")));
        }
        Ok(reply)
    }

    async fn phase(&mut self, name: &str, events: &mut JsonLines) -> Result<u64, SoakError> {
        let requested = monotonic_ns()?;
        let reply = self
            .command(json!({"op":"phase","phase":name,"at_ns":requested}))
            .await?;
        let effective = reply["effective_ns"]
            .as_u64()
            .ok_or_else(|| fail("sampler phase clock missing"))?;
        events
            .write(json!({"t_ns":effective,"kind":"phase","name":name,"requested_ns":requested}))?;
        events.flush()?;
        Ok(effective)
    }

    async fn stop(mut self) -> Result<(), SoakError> {
        self.command(json!({"op":"stop"})).await?;
        let status = tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .map_err(|_| fail("sampler required forced exit"))?
            .map_err(io_error)?;
        if !status.success() {
            return Err(fail("sampler unsuccessful exit"));
        }
        Ok(())
    }
}

fn validate(args: &ResourceArguments) -> Result<(), SoakError> {
    if !cfg!(target_os = "linux") {
        return Err(fail(
            "resource qualification requires Linux /proc identity; missing values cannot become zero",
        ));
    }
    if args.concurrency == 0
        || args.concurrency > 128
        || args.payload_size == 0
        || args.payload_size > 16 * 1024 * 1024
        || args.upload_size > 16 * 1024 * 1024
        || args.sample_interval_ms < 100
        || args.sample_interval_ms > 60000
        || args.scrape_interval_ms > 60000
        || (args.scrape_interval_ms > 0 && args.scrape_interval_ms < 100)
        || args.control_interval < Duration::from_secs(2)
    {
        return Err(fail(
            "resource campaign parameters outside bounded validation range",
        ));
    }
    for duration in [
        args.duration,
        args.warm_up,
        args.recovery_running,
        args.quiet_running,
        args.post_drain,
    ] {
        if duration.is_zero() || duration > Duration::from_secs(7200) {
            return Err(fail("each phase must be nonzero and at most two hours"));
        }
    }
    if args.formal
        && (args.warm_up < Duration::from_secs(180)
            || args.duration < Duration::from_secs(3600)
            || args.recovery_running
                < Duration::from_secs(if matches!(args.campaign, ResourceCampaign::Churn) {
                    900
                } else {
                    600
                })
            || args.quiet_running < Duration::from_secs(300)
            || args.post_drain < Duration::from_secs(300))
    {
        return Err(fail(
            "formal H/C phases shorter than declared acceptance minima",
        ));
    }
    if args.formal
        && !matches!(
            args.campaign,
            ResourceCampaign::Healthy | ResourceCampaign::Churn
        )
    {
        return Err(fail(
            "formal resource qualification is defined only for separate H and C jobs",
        ));
    }
    Ok(())
}

pub(super) async fn run(args: ResourceArguments) -> Result<(), SoakError> {
    validate(&args)?;
    std::fs::create_dir(&args.output).map_err(io_error)?;
    let source = source_identity()?;
    if args.formal && source["dirty"] == true {
        return Err(fail("formal campaign requires frozen clean source"));
    }
    let build: Value =
        serde_json::from_slice(&std::fs::read(&args.build_record).map_err(io_error)?)
            .map_err(json_error)?;
    let executable = std::env::current_exe().map_err(io_error)?;
    if build["source"] != source
        || build["gateway_sha256"] != file_digest(&args.gateway)?
        || build["tool_sha256"] != file_digest(&executable)?
    {
        return Err(fail(
            "build/source/binary identity mismatch; rebuild on frozen source and record exact binaries",
        ));
    }
    let mut receipt = json!({"schema_version":"oxidase.resource-qualification/v1","implementation_commit":source["commit"],"tool_commit":source["commit"],"source_set_sha256":source["source_set_sha256"],"source_files":source["source_files"],"git_dirty":source["dirty"],"build_record":build,"complete":false,"artifact_truncated":false,"controller_result":"running",
        "parameters":{"campaign":match args.campaign{ResourceCampaign::Healthy=>"H",ResourceCampaign::Churn=>"C",_=>"I"},"isolation":args.campaign,"seed":args.seed,"concurrency":args.concurrency,"payload_bytes":args.payload_size,"upload_bytes":args.upload_size,"formal":args.formal,"sample_interval_ns":args.sample_interval_ms*1_000_000,"max_sample_gap_ns":args.sample_interval_ms*4_000_000,"scrape_interval_ns":args.scrape_interval_ms*1_000_000,"durations_ns":{"warmup":args.warm_up.as_nanos()as u64,"steady":args.duration.as_nanos()as u64,"recovery":args.recovery_running.as_nanos()as u64,"quiet":args.quiet_running.as_nanos()as u64,"post_drain":args.post_drain.as_nanos()as u64}},
        "bounds":bounds(args.concurrency),"required_gauges":["oxidase_active_requests","oxidase_active_connections","oxidase_http2_active_streams","oxidase_active_tunnels"],"coverage_required":[],"fatal_errors":[]});
    if matches!(
        args.campaign,
        ResourceCampaign::Healthy | ResourceCampaign::Churn
    ) {
        receipt["coverage_required"] = json!([
            "tls_http1",
            "tls_h2",
            "grpc_trailers",
            "large_upload",
            "complete_download",
            "client_cancellation",
            "upgrade",
            "old_held_grpc_and_upgrade"
        ]);
    }
    persist_receipt(&args.output, &receipt)?;
    let result = run_inner(&args, &mut receipt).await;
    receipt["complete"] = result.is_ok().into();
    receipt["controller_result"] = if result.is_ok() {
        "completed_pending_independent_analysis"
    } else {
        "fail"
    }
    .into();
    if let Err(error) = &result {
        receipt["fatal_errors"] = json!([error.to_string()]);
    }
    persist_receipt(&args.output, &receipt)?;
    result
}

fn persist_receipt(output: &Path, value: &Value) -> Result<(), SoakError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(json_error)?;
    std::fs::write(output.join("receipt.pending.json"), bytes).map_err(io_error)?;
    std::fs::rename(
        output.join("receipt.pending.json"),
        output.join("receipt.json"),
    )
    .map_err(io_error)
}

fn bounds(concurrency: usize) -> Value {
    // Frozen structural bounds, never maxima derived from observed data. More
    // detailed attribution narrows these in phase 7A.3 without hiding raw rows.
    let mut bounds = serde_json::Map::new();
    for (kind, max, quiet) in [
        ("snapshot", concurrency + 8, 1),
        ("health_supervisor", 8, 1),
        ("discovery_supervisor", 8, 1),
        ("proxy_pool_family", 1024 + concurrency * 2, 1024),
        ("health_pool_family", 1024 + 128, 1024),
        ("cluster_permit", 128, 0),
        ("endpoint_permit", 128, 0),
        ("retry_permit", 8, 0),
        ("response_body", concurrency + 8, 0),
        ("tunnel", concurrency + 4, 0),
    ] {
        bounds.insert(kind.into(),json!({"live_max":max,"quiet_live_max":quiet,"post_drain_live_max":quiet,"retired_exit_budget_ms":120000,"exiting_exit_budget_ms":120000}));
    }
    Value::Object(bounds)
}

fn recipes(
    payload: usize,
    upload: usize,
    peers: &[(String, std::net::SocketAddr)],
    campaign: ResourceCampaign,
) -> Value {
    let mut recipes = serde_json::Map::new();
    for (name, path, grpc, bodybytes, fill) in [
        ("download", "payload", false, payload, 120),
        ("grpc", "grpc", true, payload, 120),
        ("upload", "upload", false, payload, 120),
        ("cancel", "cancel", false, payload, 120),
    ] {
        let mut recipe = json!({"status":200,"content_type":if grpc{"application/grpc"}else{"application/octet-stream"},"body":{"kind":if grpc{"grpc"}else{"repeat"},"payload_bytes":bodybytes,"fill_byte":fill},"trailers":if grpc{json!({"grpc-status":"0","grpc-message":"ok"})}else{json!({})},"allowed_peers":peers.iter().map(|(_,address)|address.to_string()).collect::<Vec<_>>(),"authority":"gateway.example.test","server_name":"gateway.example.test","path":format!("/base/resource/{path}?b=2&a=1&a=3")});
        if name == "upload" {
            recipe["upload"] =
                json!({"body":{"kind":"repeat","payload_bytes":upload,"fill_byte":117},"eof":true});
        }
        recipes.insert(name.into(), recipe);
    }
    recipes.insert("upgrade".into(),json!({"status":101,"body":{"kind":"utf8","text":"qualification-tunnel".repeat(4)},"trailers":{},"allowed_peers":peers.iter().map(|(_,address)|address.to_string()).collect::<Vec<_>>(),"authority":"gateway.example.test","server_name":"gateway.example.test","path":"/base/ws"}));
    if matches!(campaign, ResourceCampaign::Respond) {
        recipes.insert("respond".into(),json!({"status":200,"content_type":"text/plain; charset=utf-8","body":{"kind":"utf8","text":"resource-respond"},"trailers":{},"allowed_peers":[null]}));
    }
    Value::Object(recipes)
}

async fn run_inner(args: &ResourceArguments, receipt: &mut Value) -> Result<(), SoakError> {
    let private = tempfile::tempdir().map_err(io_error)?;
    let root = private.path().canonicalize().map_err(io_error)?;
    let certificate = identity()?;
    write_identity(&root, &certificate)?;
    std::fs::write(
        root.join("admin.token"),
        b"test-only-qualification-bearer-token\n",
    )
    .map_err(io_error)?;
    std::fs::write(root.join("signing.key"), [31u8; 32]).map_err(io_error)?;
    std::fs::write(root.join("fixture-plan.json"),serde_json::to_vec(&json!({"payload_size":args.payload_size,"request_read_delay_ms":0,"resource_mode":true})).map_err(json_error)?).map_err(io_error)?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        for file in ["admin.token", "signing.key", "gateway-key.pem"] {
            std::fs::set_permissions(root.join(file), std::fs::Permissions::from_mode(0o600))
                .map_err(io_error)?;
        }
    }
    let key =
        oxidase_bundle::BundleSigningKey::read_file(root.join("signing.key")).map_err(io_error)?;
    std::fs::write(root.join("operator.pub"), key.verification_key().as_bytes())
        .map_err(io_error)?;
    let mut upstream = FixtureProcess::spawn("upstream", &root, &args.output).await?;
    std::fs::write(
        root.join("upstream.json"),
        serde_json::to_vec(&upstream.ready).map_err(json_error)?,
    )
    .map_err(io_error)?;
    let mut dns = FixtureProcess::spawn("dns", &root, &args.output).await?;
    let source = resource_source(&root, dns.ready.address, &upstream, args.campaign, 0);
    std::fs::write(root.join("gateway.yaml"), &source).map_err(io_error)?;
    std::fs::write(
        args.output.join("seed-config.yaml"),
        source.replace(
            root.to_str().ok_or_else(|| fail("fixture root encoding"))?,
            "DEPLOYMENT_ROOT",
        ),
    )
    .map_err(io_error)?;
    let gateway = GatewayProcess::spawn_with_observation(
        &args.gateway,
        &root,
        &args.output,
        !args.observation_disabled,
    )
    .await?;
    let tool = std::env::current_exe().map_err(io_error)?;
    let mut identities = Vec::new();
    for (role, pid, path) in [
        (ProcessRole::Gateway, gateway.pid, args.gateway.as_path()),
        (ProcessRole::Controller, std::process::id(), tool.as_path()),
        (ProcessRole::Dns, dns.ready.pid, tool.as_path()),
        (ProcessRole::Upstream, upstream.ready.pid, tool.as_path()),
    ] {
        identities.push(
            serde_json::to_value(resource_identity::capture(role, pid, path)?)
                .map_err(json_error)?,
        );
    }
    let identity_path = args.output.join("identity.json");
    std::fs::write(&identity_path,serde_json::to_vec(&json!({"clock":"CLOCK_MONOTONIC","boot_id":identities[0]["boot_id"],"processes":identities})).map_err(json_error)?).map_err(io_error)?;
    let mut sampler = Sampler::spawn(&root, args, &identity_path).await?;
    identities.push(sampler.ready["identity"].clone());
    receipt["binaries"] = json!(
        identities
            .iter()
            .map(|p| json!({"role":p["role"],"sha256":p["binary_sha256"]}))
            .collect::<Vec<_>>()
    );
    std::fs::write(&identity_path,serde_json::to_vec_pretty(&json!({"clock":"CLOCK_MONOTONIC","boot_id":identities[0]["boot_id"],"processes":identities})).map_err(json_error)?).map_err(io_error)?;
    let mut events = JsonLines::create(&args.output.join("events.jsonl"), 64 * 1024 * 1024)?;
    let phase = Arc::new(AtomicUsize::new(0));
    let faults: Faults = Arc::new(Mutex::new(Vec::new()));
    let admission = Arc::new(LoadAdmission::default());
    let start = sampler.phase("warmup", &mut events).await?;
    let h1 = client_config(&[&certificate], &[b"http/1.1"])?;
    let h2 = client_config(&[&certificate], &[b"h2"])?;
    let mut command_sequence = 0;
    let a = client::bundle(
        &args.gateway,
        &root,
        &args.output,
        &resource_source(&root, dns.ready.address, &upstream, args.campaign, 1),
        "a",
        &mut command_sequence,
    )
    .await?;
    let b = client::bundle(
        &args.gateway,
        &root,
        &args.output,
        &resource_source(&root, dns.ready.address, &upstream, args.campaign, 2),
        "b",
        &mut command_sequence,
    )
    .await?;
    client::command_json(
        &args.gateway,
        &client::ctl(&root, &["activate", &a]),
        &args.output,
        &mut command_sequence,
    )
    .await?;
    // The legacy proof remains a real controlled stream/Upgrade assertion, and
    // now runs while the independent sampler is already collecting evidence.
    if matches!(
        args.campaign,
        ResourceCampaign::Healthy | ResourceCampaign::Churn
    ) {
        dns.command(FixtureCommand::Dns {
            mode: "a".into(),
            ttl: 1,
        })
        .await?;
        let retained = client::resource_retained_stream_proof(
            client::RetainedProofPlan {
                gateway: &args.gateway,
                gateway_address: gateway.address,
                root: &root,
                results: &args.output,
                a: &a,
                b: &b,
                h1: Arc::clone(&h1),
                h2: Arc::clone(&h2),
                payload_size: args.payload_size,
            },
            &mut dns,
            &mut upstream,
            &mut command_sequence,
        )
        .await?;
        events.write(json!({"kind":"coverage","t_ns":monotonic_ns()?,"name":"old_held_grpc_and_upgrade","evidence":{"source":"wire","successful_new_b_streams":retained["successful_new_b_streams"],"raw":retained}}))?;
    }
    dns.command(FixtureCommand::Dns {
        mode: "both".into(),
        ttl: 1,
    })
    .await?;
    upstream
        .command(FixtureCommand::Health {
            healthy_a: true,
            healthy_b: true,
            retry_a: false,
        })
        .await?;
    let mut targets = vec![
        ("a".to_owned(), upstream.ready.address),
        (
            "b".to_owned(),
            upstream
                .ready
                .alternate
                .ok_or_else(|| fail("upstream B missing"))?,
        ),
    ];
    if let Some(address) = upstream.ready.ipv6 {
        targets.push(("ipv6".to_owned(), address));
    }
    receipt["fixture_peers"] = json!(
        targets
            .iter()
            .map(|(name, address)| (name.clone(), address.to_string()))
            .collect::<BTreeMap<_, _>>()
    );
    receipt["recipes"] = recipes(args.payload_size, args.upload_size, &targets, args.campaign);
    persist_receipt(&args.output, receipt)?;
    let failed = Arc::new(AtomicBool::new(false));
    let (send, receive) = tokio::sync::mpsc::channel(256);
    let output = args.output.clone();
    let collector_failed = Arc::clone(&failed);
    let collector = tokio::spawn(async move {
        resource_evidence::collect(&output, receive, collector_failed).await
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut workers = tokio::task::JoinSet::new();
    let load_enabled = !matches!(
        args.campaign,
        ResourceCampaign::BackgroundOnly | ResourceCampaign::ScrapeOnly
    );
    receipt["parameters"]["traffic_required"] = load_enabled.into();
    let extra_lanes = matches!(
        args.campaign,
        ResourceCampaign::Healthy
            | ResourceCampaign::Churn
            | ResourceCampaign::DnsOnly
            | ResourceCampaign::PublishOnly
            | ResourceCampaign::StaticProxy
    );
    receipt["parameters"]["admitted_worker_count"] = if load_enabled {
        args.concurrency + if extra_lanes { 2 } else { 0 }
    } else {
        0
    }
    .into();
    receipt["parameters"]["actual_worker_count"] =
        receipt["parameters"]["admitted_worker_count"].clone();
    if load_enabled {
        for worker in 0..args.concurrency + if extra_lanes { 2 } else { 0 } {
            let send = send.clone();
            let stopped = stopped.clone();
            let phase = Arc::clone(&phase);
            let failed = Arc::clone(&failed);
            let lane = if matches!(args.campaign, ResourceCampaign::UpgradeOnly)
                || extra_lanes && worker == args.concurrency + 1
            {
                "upgrade"
            } else if extra_lanes && worker == args.concurrency {
                "cancel"
            } else {
                "complete"
            };
            let config = if lane == "upgrade" || lane != "cancel" && worker.is_multiple_of(4) {
                Arc::clone(&h1)
            } else {
                Arc::clone(&h2)
            };
            let address = gateway.address;
            let mut targets = targets.clone();
            let payload = args.payload_size;
            let upload = args.upload_size;
            let campaign = args.campaign;
            if matches!(campaign, ResourceCampaign::Respond) {
                targets.clear();
            }
            workers.spawn(worker_loop(
                WorkerPlan {
                    worker,
                    lane,
                    address,
                    config,
                    ack_config: Arc::clone(&h1),
                    targets,
                    payload,
                    upload,
                    campaign,
                },
                send,
                stopped,
                phase,
                failed,
                Arc::clone(&faults),
                Arc::clone(&admission),
            ));
        }
    }
    drop(send);
    let control_result: Result<(), SoakError> = async {
        let mut control = 0usize;
        for (index, duration) in [args.warm_up, args.duration, args.recovery_running]
            .into_iter()
            .enumerate()
        {
            if index != 0 {
                admission.pause().await?;
                sampler.phase(PHASES[index], &mut events).await?;
                phase.store(index, Ordering::Release);
                admission.resume();
            }
            let end = if index == 0 {
                start.saturating_add(duration.as_nanos() as u64)
            } else {
                monotonic_ns()?.saturating_add(duration.as_nanos() as u64)
            };
            while monotonic_ns()? < end {
                if failed.load(Ordering::Acquire) {
                    break;
                }
                if index == 1
                    && matches!(
                        args.campaign,
                        ResourceCampaign::Churn
                            | ResourceCampaign::DnsOnly
                            | ResourceCampaign::PublishOnly
                    )
                {
                    control += 1;
                    control_round(
                        ControlPlan {
                            args,
                            root: &root,
                            a: &a,
                            b: &b,
                            faults: &faults,
                        },
                        &mut dns,
                        &mut upstream,
                        control,
                        &mut command_sequence,
                        &mut events,
                    )
                    .await?;
                }
                tokio::time::sleep(
                    args.control_interval
                        .min(Duration::from_nanos(end.saturating_sub(monotonic_ns()?))),
                )
                .await;
            }
            if index == 1 {
                // Running recovery fixes existing healthy config; no special empty
                // snapshot, restart, drain, timeout reduction or forced pool sweep.
                upstream
                    .command(FixtureCommand::ResourceFault {
                        mode: "none".into(),
                        target: "all".into(),
                        delay_ms: 0,
                        after_bytes: 0,
                        case_id: 0,
                    })
                    .await?;
                upstream
                    .command(FixtureCommand::Health {
                        healthy_a: true,
                        healthy_b: true,
                        retry_a: false,
                    })
                    .await?;
                dns.command(FixtureCommand::Dns {
                    mode: "both".into(),
                    ttl: 1,
                })
                .await?;
            }
        }
        Ok(())
    }
    .await;
    stop.send_replace(true);
    admission.resume();
    let mut worker_errors = Vec::new();
    if let Err(error) = control_result {
        worker_errors.push(error.to_string());
    }
    loop {
        match tokio::time::timeout(Duration::from_secs(45), workers.join_next()).await {
            Ok(Some(joined)) => {
                if let Err(error) = joined.map_err(io_error).and_then(|result| result) {
                    worker_errors.push(error.to_string());
                }
            }
            Ok(None) => break,
            Err(_) => {
                worker_errors.push("started load work exceeded collection deadline; remaining operations classified abandoned".into());
                workers.abort_all();
                while let Some(joined) = workers.join_next().await {
                    if let Err(error) = joined {
                        worker_errors.push(error.to_string());
                    }
                }
                break;
            }
        }
    }
    let collected = tokio::time::timeout(Duration::from_secs(45), collector)
        .await
        .map_err(|_| fail("continuous result collector timeout"))?
        .map_err(io_error)??;
    receipt["final_counts"] = collected.json();
    receipt["artifact_truncated"] = collected.artifact_truncated.into();
    worker_errors.extend(collected.fatal_errors);
    persist_receipt(&args.output, receipt)?;
    for error in &worker_errors {
        events.write(json!({"kind":"fatal","t_ns":monotonic_ns()?,"message":error}))?;
    }
    if !worker_errors.is_empty() {
        // Collection and the accounting receipt precede any process teardown.
        // Cleanup attempts all roles even if an earlier one fails.
        let sample_stop = sampler.stop().await;
        let gateway_stop = gateway.stop().await;
        let dns_stop = dns.stop().await;
        let upstream_stop = upstream.stop().await;
        events.flush()?;
        for result in [sample_stop, gateway_stop, dns_stop, upstream_stop] {
            if let Err(error) = result {
                worker_errors.push(error.to_string());
            }
        }
        return Err(fail(format!(
            "qualification failed after collecting started work: {worker_errors:?}"
        )));
    }
    sampler.phase("quiet", &mut events).await?;
    phase.store(3, Ordering::Release);
    tokio::time::sleep(args.quiet_running).await;
    let before = read_runtime(&root).await?;
    if before["serving_state"] != "running" {
        return Err(fail("quiet window not Running"));
    }
    let drain_start = monotonic_ns()?;
    let drain_receipt = client::command_json(
        &args.gateway,
        &client::ctl(&root, &["drain"]),
        &args.output,
        &mut command_sequence,
    )
    .await?;
    let drain_ack = monotonic_ns()?;
    let drained = read_runtime(&root).await?;
    events.write(json!({"kind":"control","t_ns":monotonic_ns()?,"action":"drain","before_runtime":before,"after_runtime":drained,"mutation_receipt":drain_receipt}))?;
    let post_start = sampler.phase("post_drain", &mut events).await?;
    events.write(json!({"kind":"drain_transition","t_ns":monotonic_ns()?,"start_ns":drain_start,"end_ns":post_start,"mutation_ack_ns":drain_ack,"before_runtime":before,"after_runtime":drained}))?;
    phase.store(4, Ordering::Release);
    tokio::time::sleep(args.post_drain).await;
    let dns_status = dns.command(FixtureCommand::Status).await?;
    let upstream_status = upstream.command(FixtureCommand::Status).await?;
    events.write(json!({"kind":"fixture_final","t_ns":monotonic_ns()?,"dns":dns_status,"upstream":upstream_status}))?;
    sampler.stop().await?;
    events.write(json!({"kind":"end","t_ns":monotonic_ns()?}))?;
    events.flush()?;
    gateway.stop().await?;
    dns.stop().await?;
    upstream.stop().await?;
    if !worker_errors.is_empty() {
        return Err(fail(format!("workers failed: {worker_errors:?}")));
    }
    if source_identity()? != receipt["build_record"]["source"] {
        return Err(fail("source changed during campaign"));
    }
    Ok(())
}

fn resource_source(
    root: &Path,
    dns: std::net::SocketAddr,
    upstream: &FixtureProcess,
    campaign: ResourceCampaign,
    generation: u64,
) -> String {
    let source = client::source(
        root,
        dns,
        upstream.ready.address.port(),
        if matches!(campaign, ResourceCampaign::Churn) {
            Campaign::Protocol
        } else {
            Campaign::Discovery
        },
        generation,
    )
    .replace(
        "      health:\n",
        "      load_balance:\n        policy: weighted_round_robin\n      health:\n",
    );
    if matches!(campaign, ResourceCampaign::Respond) {
        let begin = source
            .find("      service:\n        type: proxy")
            .expect("known fixture source");
        let suffix = source
            .split_once("listeners:\n")
            .expect("known fixture source")
            .1;
        format!(
            "{}      service:\n        type: respond\n        headers:\n          set:\n            Content-Type: text/plain; charset=utf-8\n        body:\n          text: resource-respond\nlisteners:\n{suffix}",
            &source[..begin]
        )
    } else if matches!(
        campaign,
        ResourceCampaign::StaticProxy | ResourceCampaign::PublishOnly
    ) {
        let start = source
            .find("      discovery:\n")
            .expect("fixture discovery");
        let end = source.find("      health:\n").expect("fixture health");
        format!(
            "{}      endpoints:\n        - name: a\n          url: https://{}/base\n{}",
            &source[..start],
            upstream.ready.address,
            &source[end..]
        )
    } else {
        source
    }
}

struct WorkerPlan {
    worker: usize,
    lane: &'static str,
    address: std::net::SocketAddr,
    config: Arc<tokio_rustls::rustls::ClientConfig>,
    ack_config: Arc<tokio_rustls::rustls::ClientConfig>,
    targets: Vec<(String, std::net::SocketAddr)>,
    payload: usize,
    upload: usize,
    campaign: ResourceCampaign,
}

async fn worker_loop(
    plan: WorkerPlan,
    send: tokio::sync::mpsc::Sender<OperationEvent>,
    stop: tokio::sync::watch::Receiver<bool>,
    phase: Arc<AtomicUsize>,
    failed: Arc<AtomicBool>,
    faults: Faults,
    admission: Arc<LoadAdmission>,
) -> Result<(), SoakError> {
    let mut sequence = 0u64;
    let mut client = None;
    let h2 = plan.lane == "cancel" || plan.lane != "upgrade" && !plan.worker.is_multiple_of(4);
    loop {
        if *stop.borrow() || failed.load(Ordering::Acquire) {
            break;
        }
        let Some(guard) = admission.begin(&stop, &failed).await else {
            break;
        };
        sequence += 1;
        let started = monotonic_ns()?;
        let operation_phase = PHASES[phase.load(Ordering::Acquire)];
        send.send(OperationEvent::Started {
            worker: plan.worker,
            sequence,
            start_ns: started,
        })
        .await
        .map_err(io_error)?;
        let mut connection_attempts = 0;
        let mut connection_error = None;
        if plan.lane != "upgrade" && client.is_none() {
            connection_attempts = 1;
            match tokio::time::timeout(
                Duration::from_secs(5),
                ResourceDataClient::connect(
                    plan.address,
                    Arc::clone(&plan.config),
                    h2,
                    plan.targets.clone(),
                ),
            )
            .await
            {
                Ok(Ok(connected)) => client = Some(connected),
                Ok(Err(error)) => connection_error = Some(error.to_string()),
                Err(_) => connection_error = Some("connection deadline".into()),
            }
        }
        // A dedicated low-frequency lane, not an escape from validating ordinary
        // responses and not high-throughput cancellation churn disguised as H.
        let cancelled = plan.lane == "cancel";
        let upgrade = plan.lane == "upgrade";
        let grpc = !matches!(plan.campaign, ResourceCampaign::Respond)
            && (matches!(plan.campaign, ResourceCampaign::GrpcOnly)
                || (h2 && plan.worker % 4 == 2 && !cancelled && !upgrade));
        let uploaded = !matches!(plan.campaign, ResourceCampaign::Respond)
            && h2
            && plan.worker % 4 == 3
            && !cancelled
            && !grpc
            && !upgrade;
        let recipe = if upgrade {
            "upgrade"
        } else if matches!(plan.campaign, ResourceCampaign::Respond) {
            "respond"
        } else if cancelled {
            "cancel"
        } else if grpc {
            "grpc"
        } else if uploaded {
            "upload"
        } else {
            "download"
        };
        let lane = if upgrade {
            "upgrade"
        } else if cancelled {
            "cancel"
        } else if operation_phase == "steady" && matches!(plan.campaign, ResourceCampaign::Churn) {
            "churn"
        } else {
            "healthy"
        };
        let mut admitted = client.is_some();
        let mut raw = if upgrade {
            connection_attempts = 1;
            let facts = client::measure_resource_upgrade(
                plan.address,
                Arc::clone(&plan.ack_config),
                format!("{}:{sequence}", plan.worker),
            )
            .await;
            admitted = facts.request_head_sent;
            serde_json::to_value(facts).map_err(json_error)?
        } else if let Some(client) = &mut client {
            serde_json::to_value(
                client
                    .measure(ResourceRequest {
                        operation_id: format!("{}:{sequence}", plan.worker),
                        path: format!("/resource/{recipe}?b=2&a=1&a=3"),
                        grpc,
                        cancel_after_first_data: cancelled,
                        payload_size: plan.payload,
                        upload_bytes: if uploaded { plan.upload } else { 0 },
                    })
                    .await,
            )
            .map_err(json_error)?
        } else {
            json!({"status":null,"eof":false,"body_bytes":0,"body_sha256":digest(b""),"error_stage":"connection","error_code":"connect_failure","error":connection_error})
        };
        raw["connection_attempted"] = (connection_attempts != 0).into();
        raw["admitted"] = admitted.into();
        if raw["cancelled"] == true
            && let Some(peer) = raw["upstream_peer"].as_str().and_then(|p| p.parse().ok())
        {
            match client::await_fixture_cancel_receipt(
                peer,
                Arc::clone(&plan.ack_config),
                &format!("{}:{sequence}", plan.worker),
            )
            .await
            {
                Ok(ack) => {
                    raw["fixture_cancel_ack"] = (ack["body_dropped_after_data"] == true).into();
                    raw["cancel_ack"] = ack;
                }
                Err(error) => {
                    raw["error_stage"] = "fixture_ack".into();
                    raw["error_code"] = "cancellation_ack_missing".into();
                    raw["error"] = error.to_string().into();
                }
            }
        }
        let window_id = fault_at(&faults, &raw);
        if !upgrade
            && raw["error_code"].as_str().is_some()
            && let Some(broken) = client.take()
        {
            let closed = broken.close_receipt().await;
            if !matches!(closed["result"].as_str(), Some("completed" | "error"))
                || closed["join_acknowledged"] != true
            {
                raw["error_stage"] = "client_driver".into();
                raw["error_code"] = "driver_cleanup_failed".into();
                failed.store(true, Ordering::Release);
            }
            raw["driver_exit"] = closed;
        }
        send.send(OperationEvent::Terminal {
            worker: plan.worker,
            sequence,
            start_ns: started,
            end_ns: monotonic_ns()?,
            phase: operation_phase,
            lane,
            protocol: if upgrade {
                "upgrade"
            } else if h2 {
                "h2"
            } else {
                "http1"
            },
            recipe,
            connection_attempts,
            admitted,
            window_id,
            raw,
        })
        .await
        .map_err(io_error)?;
        drop(guard);
        if cancelled || upgrade {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    if let Some(client) = client {
        client.close().await?;
    }
    Ok(())
}

async fn read_runtime(root: &Path) -> Result<Value, SoakError> {
    serde_json::from_slice(&client::admin_read(root, "/api/v1/runtime").await?).map_err(json_error)
}

struct ControlPlan<'a> {
    args: &'a ResourceArguments,
    root: &'a Path,
    a: &'a str,
    b: &'a str,
    faults: &'a Faults,
}
async fn control_round(
    plan: ControlPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    round: usize,
    sequence: &mut u64,
    events: &mut JsonLines,
) -> Result<(), SoakError> {
    let ControlPlan {
        args,
        root,
        a,
        b,
        faults,
    } = plan;
    let before = read_runtime(root).await?;
    if !matches!(args.campaign, ResourceCampaign::PublishOnly) {
        let modes = ["both", "reverse", "v6", "both_v6", "a", "b", "both"];
        let mode = modes[(round.wrapping_add(args.seed as usize)) % modes.len()];
        let mode = if round.is_multiple_of(9) {
            "weights"
        } else {
            mode
        };
        let acknowledged = dns
            .command(FixtureCommand::Dns {
                mode: mode.into(),
                ttl: 1,
            })
            .await?;
        let after = read_runtime(root).await?;
        events.write(json!({"kind":"control","t_ns":monotonic_ns()?,"action":"dns","request_id":round,"before_runtime":before,"after_runtime":after,"fixture_ack":acknowledged,"mode":mode}))?;
        if before != after {
            return Err(fail("DNS observation changed complete PublishedRuntime"));
        }
    }
    if matches!(
        args.campaign,
        ResourceCampaign::Churn | ResourceCampaign::PublishOnly
    ) && round.is_multiple_of(4)
    {
        let operation = if round.is_multiple_of(8) {
            ["rollback", a]
        } else {
            ["activate", b]
        };
        let mut command = client::ctl(root, &operation);
        command.splice(
            1..1,
            [
                "--if-match".into(),
                before["etag"]
                    .as_str()
                    .ok_or_else(|| fail("published ETag missing"))?
                    .into(),
            ],
        );
        let mutation_receipt =
            client::command_json(&args.gateway, &command, &args.output, sequence).await?;
        let after = read_runtime(root).await?;
        events.write(json!({"kind":"control","t_ns":monotonic_ns()?,"action":operation[0],"request_id":round,"before_runtime":before,"after_runtime":after,"mutation_receipt":mutation_receipt}))?;
    }
    if matches!(args.campaign, ResourceCampaign::Churn) && round.is_multiple_of(12) {
        // B stays healthy and eligible. Faults affect A's data path; a finite
        // separately declared all-withdrawal window is a different experiment.
        dns.command(FixtureCommand::Dns {
            mode: "weights".into(),
            ttl: 1,
        })
        .await?;
        upstream
            .command(FixtureCommand::Health {
                healthy_a: true,
                healthy_b: true,
                retry_a: false,
            })
            .await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let start = monotonic_ns()?;
        let id = format!("fault-{round}");
        {
            let mut windows = faults
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if windows.len() >= 256 {
                return Err(fail("named fault window capacity exhausted"));
            }
            windows.push(FaultInterval {
                id: id.clone(),
                start,
                end: None,
            });
        }
        let mode = if round.is_multiple_of(24) {
            "header_delay"
        } else {
            "mid_body_error"
        };
        let counter = if mode == "header_delay" {
            "resource_header_delays_started"
        } else {
            "resource_mid_body_errors_emitted"
        };
        let before_status = upstream.command(FixtureCommand::Status).await?;
        upstream
            .command(FixtureCommand::ResourceFault {
                mode: mode.into(),
                target: "a".into(),
                delay_ms: 6000,
                after_bytes: 1024,
                case_id: round as u64,
            })
            .await?;
        tokio::time::sleep(Duration::from_secs(7)).await;
        upstream
            .command(FixtureCommand::ResourceFault {
                mode: "none".into(),
                target: "all".into(),
                delay_ms: 0,
                after_bytes: 0,
                case_id: 0,
            })
            .await?;
        // Frozen before measurement: eight-second logical pre-response total
        // plus 500 ms ejection and one resolver refresh slot. No retrospective
        // allowance expansion or logical-request deadline refresh.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let end = monotonic_ns()?;
        if let Some(window) = faults
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last_mut()
        {
            window.end = Some(end);
        }
        let after_status = upstream.command(FixtureCommand::Status).await?;
        events.write(json!({"kind":"fault_window","t_ns":end,"id":id,"start_ns":start,"end_ns":end,"recovery_deadline_ns":end+12_000_000_000u64,"target":"upstream","lanes":["churn","cancel"],"allowed":if mode=="header_delay"{json!([{"status":504},{"status":503}])}else{json!([{"error_stage":"response_body","error_code":"body_error"},{"status":503}])},"trigger":{"source":"fixture_counter","name":counter,"before":before_status[counter],"after":after_status[counter]},"fixture_before":before_status,"fixture_after":after_status}))?;
    }
    Ok(())
}
