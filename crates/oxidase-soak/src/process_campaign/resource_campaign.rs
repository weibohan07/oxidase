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
use super::resource_controls::{ControlPlan, control_round};
use super::resource_evidence::{self, JsonLines, OperationEvent};
use super::resource_identity::{self, ProcessRole, monotonic_ns};
use super::{
    Campaign, FixtureCommand, FixtureProcess, ResourceArguments, ResourceCampaign, SoakError, fail,
    io_error, json_error,
};
use crate::common::{client_config, identity, write_identity};

const PHASES: [&str; 5] = ["warmup", "steady", "recovery", "quiet", "post_drain"];

#[derive(Clone)]
pub(super) struct FaultInterval {
    pub(super) id: String,
    pub(super) start: u64,
    pub(super) end: Option<u64>,
}
pub(super) type Faults = Arc<Mutex<Vec<FaultInterval>>>;

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
        "profile":if cfg!(debug_assertions){"debug"}else{"release"},
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
        // Debug executables on CI are large. Identity verification deliberately
        // full-hashes the running executable, before measured workload phases.
        // A distinct debug-only startup allowance is not a production timeout
        // change or a relaxation of the resource retirement budget.
        let startup_budget = if cfg!(debug_assertions) {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(15)
        };
        let line = tokio::time::timeout(startup_budget, output.next_line())
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
        || args.operation_interval_ms > 60000
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
        "bounds":bounds(args.concurrency),"required_gauges":["oxidase_active_requests","oxidase_active_connections{listener=\"qualification\",protocol=\"http1\"}","oxidase_active_connections{listener=\"qualification\",protocol=\"h2\"}","oxidase_http2_active_streams{listener=\"qualification\"}","oxidase_active_tunnels{listener=\"qualification\"}"],"coverage_required":[],"fatal_errors":[]});
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
    } else {
        // Isolations intentionally omit particular protocols or all business
        // traffic. Their on-demand listener series may never be instantiated;
        // that is unavailable, not a fabricated zero. Raw series/census remain
        // recorded, and an I run cannot grant formal H/C qualification.
        receipt["required_gauges"] = json!(["oxidase_active_requests"]);
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
        let pool = matches!(kind, "proxy_pool_family" | "health_pool_family");
        // hyper-util 0.1.20 checks age >90 s on a 90 s sweep. A 120 s
        // observation deadline is therefore not its idle-retirement contract.
        // Reserve the two sweeps plus this fixture's 10 s body/8 s head bounds
        // and measurement/control scheduling. This is an experiment deadline,
        // not a promised hard wall-clock guarantee of a private library driver.
        let retire_ms = if pool { 210000 } else { 120000 };
        bounds.insert(kind.into(),json!({"live_max":max,"quiet_live_max":quiet,"post_drain_live_max":quiet,"retired_exit_budget_ms":retire_ms,"exiting_exit_budget_ms":120000,
            "basis":if pool{"registry <=1024; active clone families additionally held by bounded fixture work; private idle sweeps are not exact timer guarantees"}else{"fixed fixture concurrency/owners; not a global deployment capacity guarantee"}}));
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
    if matches!(
        campaign,
        ResourceCampaign::Respond | ResourceCampaign::ScrapeOnly
    ) {
        recipes.insert("respond".into(),json!({"status":200,"content_type":"text/plain; charset=utf-8","body":{"kind":"utf8","text":"resource-respond"},"trailers":{},"allowed_peers":[null],"upstream_expected":false}));
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
    // Establish the old-flow fixture policy before the actual runtime can query
    // DNS/cache membership. Changing `both` to `a` after publication does not
    // prove convergence and can let weighted RR open the supposed old-A tunnel
    // on B. The client and independent oracle still validate the actual peer.
    dns.command(FixtureCommand::Dns {
        mode: initial_dns_mode(args.campaign).into(),
        ttl: 1,
    })
    .await?;
    receipt["parameters"]["operation_interval_ns"] =
        (args.operation_interval_ms * 1_000_000).into();
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
    let preparation:Result<(String,String),SoakError>=async {
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
        receipt["prelude_counts"]=retained["prelude_counts"].clone();
    }
    Ok((a,b))
    }.await;
    let (a, b) = match preparation {
        Ok(result) => result,
        Err(error) => {
            events.write(json!({"kind":"fatal","t_ns":monotonic_ns()?,"message":error.to_string(),"stage":"prelude"}))?;
            events.flush()?;
            // No worker operation was admitted yet, but the independently
            // started sampler/probes still get a bounded durable close.
            let results = [
                sampler.stop().await,
                gateway.stop().await,
                dns.stop().await,
                upstream.stop().await,
            ];
            receipt["cleanup_errors"] = json!(
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
            );
            return Err(error);
        }
    };
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
        ResourceCampaign::BackgroundOnly
            | ResourceCampaign::HealthOnly
            | ResourceCampaign::DnsBackgroundOnly
            | ResourceCampaign::ScrapeOnly
    );
    receipt["parameters"]["traffic_required"] = load_enabled.into();
    let extra_cancel = matches!(
        args.campaign,
        ResourceCampaign::Healthy
            | ResourceCampaign::Churn
            | ResourceCampaign::DnsOnly
            | ResourceCampaign::PublishOnly
            | ResourceCampaign::StaticProxy
            | ResourceCampaign::H2Cancel
    );
    let extra_upgrade = extra_cancel && !matches!(args.campaign, ResourceCampaign::H2Cancel);
    let extra_workers = usize::from(extra_cancel) + usize::from(extra_upgrade);
    receipt["parameters"]["admitted_worker_count"] = if load_enabled {
        args.concurrency + extra_workers
    } else {
        0
    }
    .into();
    receipt["parameters"]["actual_worker_count"] =
        receipt["parameters"]["admitted_worker_count"].clone();
    if load_enabled {
        for worker in 0..args.concurrency + extra_workers {
            let send = send.clone();
            let stopped = stopped.clone();
            let phase = Arc::clone(&phase);
            let failed = Arc::clone(&failed);
            let lane = if matches!(args.campaign, ResourceCampaign::UpgradeOnly)
                || extra_upgrade && worker == args.concurrency + 1
            {
                "upgrade"
            } else if extra_cancel && worker == args.concurrency {
                "cancel"
            } else {
                "complete"
            };
            let config = if lane == "upgrade"
                || lane != "cancel"
                    && worker.is_multiple_of(4)
                    && !matches!(
                        args.campaign,
                        ResourceCampaign::H2Only | ResourceCampaign::H2Cancel
                    ) {
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
                    operation_interval: Duration::from_millis(args.operation_interval_ms),
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
                            gateway_address: gateway.address,
                            h1: Arc::clone(&h1),
                            h2: Arc::clone(&h2),
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

pub(super) fn resource_source(
    root: &Path,
    dns: std::net::SocketAddr,
    upstream: &FixtureProcess,
    campaign: ResourceCampaign,
    generation: u64,
) -> String {
    resource_source_for_address(root, dns, upstream.ready.address, campaign, generation)
}

fn resource_source_for_address(
    root: &Path,
    dns: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    campaign: ResourceCampaign,
    generation: u64,
) -> String {
    let mut source = client::source(
        root,
        dns,
        upstream.port(),
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
    if matches!(
        campaign,
        ResourceCampaign::StaticProxy
            | ResourceCampaign::PublishOnly
            | ResourceCampaign::HealthOnly
    ) {
        let start = source
            .find("      discovery:\n")
            .expect("fixture discovery");
        let end = source.find("      health:\n").expect("fixture health");
        source.replace_range(
            start..end,
            &format!(
                "      endpoints:\n        - name: a\n          url: https://{upstream}/base\n"
            ),
        );
    }
    if matches!(campaign, ResourceCampaign::DnsBackgroundOnly) {
        let start = source.find("      health:\n").expect("fixture health");
        let end = source.find("      retry:\n").expect("fixture retry");
        source.replace_range(start..end, "");
    }
    if matches!(
        campaign,
        ResourceCampaign::Respond | ResourceCampaign::ScrapeOnly
    ) {
        let begin = source
            .find("      service:\n        type: proxy")
            .expect("known fixture source");
        let suffix = source
            .split_once("listeners:\n")
            .expect("known fixture source")
            .1;
        let mut local = format!(
            "{}      service:\n        type: respond\n        headers:\n          set:\n            Content-Type: text/plain; charset=utf-8\n        body:\n          text: resource-respond\nlisteners:\n{suffix}",
            &source[..begin]
        );
        // Unused resources are still prepared/supervised by the real runtime.
        // A local-response/scrape isolation must remove the whole Cluster plan,
        // not merely route business traffic around its DNS and health tasks.
        let clusters = local.find("  clusters:\n").expect("fixture Cluster");
        let services = local.find("services:\n").expect("fixture Services");
        local.replace_range(clusters..services, "");
        local
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
    operation_interval: Duration,
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
    let h2 = plan.lane == "cancel"
        || plan.lane != "upgrade"
            && (!plan.worker.is_multiple_of(4)
                || matches!(
                    plan.campaign,
                    ResourceCampaign::H2Only | ResourceCampaign::H2Cancel
                ));
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
            match tokio::time::timeout(Duration::from_secs(5), async {
                if matches!(plan.campaign, ResourceCampaign::Respond) {
                    ResourceDataClient::connect_local(plan.address, Arc::clone(&plan.config), h2)
                        .await
                } else {
                    ResourceDataClient::connect(
                        plan.address,
                        Arc::clone(&plan.config),
                        h2,
                        plan.targets.clone(),
                    )
                    .await
                }
            })
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
                        path: format!(
                            "/resource/{}?b=2&a=1&a=3",
                            if recipe == "download" {
                                "payload"
                            } else {
                                recipe
                            }
                        ),
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
        let delay = if cancelled || upgrade {
            Duration::from_secs(1)
        } else {
            Duration::from_nanos(
                started
                    .saturating_add(plan.operation_interval.as_nanos() as u64)
                    .saturating_sub(monotonic_ns()?),
            )
        };
        wait_for_pacing(delay, &stop).await;
    }
    if let Some(client) = client {
        client.close().await?;
    }
    Ok(())
}

async fn read_runtime(root: &Path) -> Result<Value, SoakError> {
    serde_json::from_slice(&client::admin_read(root, "/api/v1/runtime").await?).map_err(json_error)
}

fn initial_dns_mode(campaign: ResourceCampaign) -> &'static str {
    if matches!(
        campaign,
        ResourceCampaign::Healthy | ResourceCampaign::Churn
    ) {
        "a"
    } else {
        "both"
    }
}

async fn wait_for_pacing(delay: Duration, stop: &tokio::sync::watch::Receiver<bool>) {
    if delay.is_zero() || *stop.borrow() {
        return;
    }
    let mut stopped = stop.clone();
    tokio::select! {
        _ = tokio::time::sleep(delay) => {},
        _ = stopped.changed() => {},
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn retained_flow_setup_is_single_a_before_any_runtime_resolution() {
        assert_eq!(initial_dns_mode(ResourceCampaign::Healthy), "a");
        assert_eq!(initial_dns_mode(ResourceCampaign::Churn), "a");
        assert_eq!(initial_dns_mode(ResourceCampaign::StaticProxy), "both");
    }

    #[tokio::test]
    async fn pacing_does_not_delay_stop_or_leave_an_active_operation() {
        let (signal, stop) = tokio::sync::watch::channel(false);
        let (entered, started) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            entered.send(()).expect("waiter exists");
            wait_for_pacing(Duration::from_secs(60), &stop).await;
        });
        started.await.expect("issued waiter");
        signal.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("no minute-long delay after stop")
            .expect("waiter joined");
        let (_, already_stopped) = tokio::sync::watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_pacing(Duration::from_secs(60), &already_stopped),
        )
        .await
        .expect("already stopped admission is not paced");
    }

    #[test]
    fn isolation_sources_compile_without_hidden_cluster_work() {
        let directory = tempfile::tempdir().expect("isolated fixture source");
        let root = directory.path();
        write_identity(root, &identity().expect("test-only identity")).expect("test material");
        std::fs::write(
            root.join("admin.token"),
            b"test-only-resource-fixture-token\n",
        )
        .expect("test-only token");
        std::fs::write(root.join("signing.key"), [31u8; 32]).expect("test-only key");
        let key = oxidase_bundle::BundleSigningKey::read_file(root.join("signing.key"))
            .expect("test-only signing key");
        std::fs::write(root.join("operator.pub"), key.verification_key().as_bytes())
            .expect("public test key");
        let dns = "127.0.0.1:5300".parse().expect("syntax only; no dial");
        let upstream = "127.0.0.1:8443".parse().expect("syntax only; no dial");
        for campaign in [
            ResourceCampaign::Respond,
            ResourceCampaign::ScrapeOnly,
            ResourceCampaign::HealthOnly,
            ResourceCampaign::DnsBackgroundOnly,
            ResourceCampaign::H2Only,
            ResourceCampaign::H2Cancel,
            ResourceCampaign::StaticProxy,
        ] {
            let source = resource_source_for_address(root, dns, upstream, campaign, 0);
            let path = root.join("gateway.yaml");
            std::fs::write(&path, &source).expect("fixture source");
            let compiled = oxidase_config::Compiler::compile_path(path)
                .unwrap_or_else(|error| panic!("{campaign:?} isolation source: {error}"));
            match campaign {
                ResourceCampaign::Respond | ResourceCampaign::ScrapeOnly => {
                    assert!(
                        compiled.resources.clusters.is_empty(),
                        "no hidden supervisors"
                    );
                }
                ResourceCampaign::HealthOnly | ResourceCampaign::StaticProxy => {
                    assert!(!source.contains("      discovery:\n"));
                    assert!(source.contains("      endpoints:\n"));
                    assert!(source.contains("      health:\n"));
                }
                ResourceCampaign::DnsBackgroundOnly => {
                    assert!(source.contains("      discovery:\n"));
                    assert!(!source.contains("      health:\n"));
                }
                _ => assert_eq!(compiled.resources.clusters.len(), 1),
            }
        }
    }

    #[tokio::test]
    async fn phase_barrier_collects_old_work_before_reopening_admission() {
        let admission = Arc::new(LoadAdmission::default());
        let (_, stop) = tokio::sync::watch::channel(false);
        let failed = AtomicBool::new(false);
        let old = admission.begin(&stop, &failed).await.expect("old phase");
        let (entered, entering) = tokio::sync::oneshot::channel();
        let paused = Arc::clone(&admission);
        let mut transition = tokio::spawn(async move {
            entered.send(()).expect("observed task entry");
            paused.pause().await
        });
        entering.await.expect("transition scheduled");
        tokio::task::yield_now().await;
        assert!(admission.state.lock().expect("state").0);
        assert_eq!(admission.state.lock().expect("state").1, 1);
        assert!(
            !transition.is_finished(),
            "started work cannot be discarded"
        );
        drop(old);
        tokio::time::timeout(Duration::from_secs(1), &mut transition)
            .await
            .expect("actual old guard release")
            .expect("task")
            .expect("collected boundary");
        assert_eq!(admission.state.lock().expect("state").1, 0);
        admission.resume();
        let next = admission.begin(&stop, &failed).await.expect("new phase");
        assert_eq!(admission.state.lock().expect("state").1, 1);
        drop(next);
        assert_eq!(admission.state.lock().expect("state").1, 0);
    }

    #[tokio::test]
    async fn stop_only_rejects_new_admission_and_preserves_issued_guard() {
        let admission = Arc::new(LoadAdmission::default());
        let (signal, stop) = tokio::sync::watch::channel(false);
        let failed = AtomicBool::new(false);
        let issued = admission.begin(&stop, &failed).await.expect("issued");
        signal.send_replace(true);
        assert!(admission.begin(&stop, &failed).await.is_none());
        assert_eq!(admission.state.lock().expect("state").1, 1);
        drop(issued);
        assert_eq!(admission.state.lock().expect("state").1, 0);
    }
}
