use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, header};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::Instant;
use tokio_rustls::{TlsConnector, rustls};

use super::{
    Campaign, FixtureCommand, FixtureProcess, ProcessArguments, SoakError, fail, io_error,
    json_error, monitor,
};
use crate::common::{XorShift64, client_config, identity, write_identity};

const TOKEN: &str = "test-only-qualification-bearer-token";

struct FixtureModePlan {
    name: &'static str,
    healthy_a: bool,
    healthy_b: bool,
    target_a: bool,
    target_b: bool,
    valid_answer: bool,
    retry_a: bool,
    require_two_members: bool,
}
impl FixtureModePlan {
    fn unavailable(&self) -> bool {
        !(self.valid_answer
            && ((self.target_a && self.healthy_a) || (self.target_b && self.healthy_b)))
    }
}

fn fixture_mode_plan(campaign: Campaign, change: usize) -> FixtureModePlan {
    let modes: &[&str] = match campaign {
        Campaign::Discovery => &[
            "a", "b", "both", "reverse", "tcp", "ttl0", "nxdomain", "nodata", "servfail", "cname",
            "both",
        ],
        Campaign::Protocol => &[
            "a", "b", "both", "reverse", "tcp", "ttl0", "nxdomain", "nodata", "servfail", "cname",
            "withdraw", "both",
        ],
    };
    let name = modes[change % modes.len()];
    let healthy_a = !change.is_multiple_of(4) || name == "cname";
    let healthy_b = true;
    let valid_answer = !matches!(
        name,
        "ttl0" | "nxdomain" | "nodata" | "servfail" | "withdraw"
    );
    let (target_a, target_b) = match name {
        "a" => (true, false),
        "b" => (false, true),
        "cname" if matches!(campaign, Campaign::Discovery) => (true, false),
        "both" | "reverse" | "tcp" | "cname" => (true, true),
        _ => (false, false),
    };
    let eligible_a = valid_answer && target_a && healthy_a;
    let eligible_b = valid_answer && target_b && healthy_b;
    let retry_a = matches!(campaign, Campaign::Discovery)
        && change.is_multiple_of(3)
        && eligible_a
        && eligible_b;
    FixtureModePlan {
        name,
        healthy_a,
        healthy_b,
        target_a,
        target_b,
        valid_answer,
        retry_a,
        require_two_members: matches!(campaign, Campaign::Discovery)
            && valid_answer
            && target_a
            && target_b,
    }
}

struct GatewayProcess {
    child: Child,
    pid: u32,
    address: SocketAddr,
    reader: tokio::task::JoinHandle<Result<(), SoakError>>,
}

impl GatewayProcess {
    async fn spawn(executable: &Path, root: &Path, results: &Path) -> Result<Self, SoakError> {
        let stderr = std::fs::File::create(results.join("gateway.stderr.log")).map_err(io_error)?;
        let mut child = Command::new(executable)
            .arg("serve")
            .arg(root.join("gateway.yaml"))
            .env("RUST_LOG", "warn")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true)
            .spawn()
            .map_err(io_error)?;
        let pid = child.id().ok_or_else(|| fail("gateway PID missing"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| fail("gateway stdout missing"))?;
        let (ready, receive) = tokio::sync::oneshot::channel();
        let log = results.join("gateway.stdout.log");
        let reader = tokio::spawn(async move {
            let mut ready = Some(ready);
            let mut lines = BufReader::new(stdout).lines();
            let mut file = tokio::fs::File::create(log).await.map_err(io_error)?;
            let mut count = 0usize;
            while let Some(line) = lines.next_line().await.map_err(io_error)? {
                count = count.saturating_add(line.len());
                if count > 2 * 1024 * 1024 {
                    return Err(fail("gateway stdout log exceeds bounded artifact size"));
                }
                file.write_all(format!("{line}\n").as_bytes())
                    .await
                    .map_err(io_error)?;
                if let Some(address) = parse_listener(&line)
                    && let Some(sender) = ready.take()
                {
                    let _ = sender.send(address);
                }
            }
            file.flush().await.map_err(io_error)?;
            Ok(())
        });
        let address = tokio::time::timeout(Duration::from_secs(15), receive)
            .await
            .map_err(|_| fail("gateway readiness deadline"))?
            .map_err(|_| fail("gateway exited before readiness"))?;
        Ok(Self {
            child,
            pid,
            address,
            reader,
        })
    }
    async fn stop(mut self) -> Result<(), SoakError> {
        if let Some(status) = self.child.try_wait().map_err(io_error)? {
            return Err(fail(format!(
                "gateway exited before graceful signal: {status}"
            )));
        }
        #[cfg(unix)]
        {
            let raw = i32::try_from(self.pid).map_err(io_error)?;
            let pid =
                rustix::process::Pid::from_raw(raw).ok_or_else(|| fail("invalid gateway PID"))?;
            rustix::process::kill_process(pid, rustix::process::Signal::INT).map_err(io_error)?;
        }
        #[cfg(not(unix))]
        return Err(fail(
            "process qualification currently requires Unix signaling",
        ));
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .map_err(|_| fail("gateway required forced termination"))?
            .map_err(io_error)?;
        tokio::time::timeout(Duration::from_secs(3), self.reader)
            .await
            .map_err(|_| fail("gateway log reader did not finish"))?
            .map_err(|error| fail(format!("gateway log reader failed: {error}")))??;
        if !status.success() {
            return Err(fail(format!("gateway graceful exit failed: {status}")));
        }
        Ok(())
    }
}

fn parse_listener(line: &str) -> Option<SocketAddr> {
    line.starts_with("listener qualification accepting ")
        .then_some(())?;
    line.rsplit_once(" on ")?.1.parse().ok()
}

async fn command_json(
    executable: &Path,
    args: &[String],
    results: &Path,
    sequence: &mut u64,
) -> Result<Value, SoakError> {
    *sequence += 1;
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        Command::new(executable)
            .arg("--diagnostic-format")
            .arg("json")
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| fail("CLI operation timeout"))?
    .map_err(io_error)?;
    if output.stdout.len() > 2 * 1024 * 1024 || output.stderr.len() > 2 * 1024 * 1024 {
        return Err(fail("CLI operation output limit"));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(json_error)?;
    std::fs::write(
        results.join(format!("receipt-{:04}.json", sequence)),
        serde_json::to_vec_pretty(
            &json!({"command":args.first(),"success":output.status.success(),"response":value}),
        )
        .map_err(json_error)?,
    )
    .map_err(io_error)?;
    if !output.status.success() {
        return Err(fail(format!(
            "CLI operation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(value)
}

fn ctl(root: &Path, operation: &[&str]) -> Vec<String> {
    let mut args = vec![
        "ctl".into(),
        "--unix".into(),
        root.join("admin.sock").display().to_string(),
        "--token-file".into(),
        root.join("admin.token").display().to_string(),
        "--timeout".into(),
        "15s".into(),
    ];
    args.extend(operation.iter().map(|v| (*v).to_owned()));
    args
}

async fn admin_read(root: &Path, path: &str) -> Result<Bytes, SoakError> {
    let socket = UnixStream::connect(root.join("admin.sock"))
        .await
        .map_err(io_error)?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(socket))
        .await
        .map_err(io_error)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .uri(path)
                .header(header::HOST, "admin.test")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Full::new(Bytes::new()))
                .map_err(io_error)?,
        )
        .await
        .map_err(io_error)?;
    if !response.status().is_success() {
        driver.abort();
        return Err(fail("authenticated administration read rejected"));
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(io_error)?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > 2 * 1024 * 1024 {
                driver.abort();
                return Err(fail("administration read size limit"));
            }
            bytes.extend_from_slice(&data);
        }
    }
    drop(sender);
    driver.abort();
    let _ = driver.await;
    Ok(Bytes::from(bytes))
}

async fn record_sample(
    root: &Path,
    pid: u32,
    start: Instant,
    phase: &'static str,
    results: &Path,
    samples: &mut Vec<monitor::Sample>,
) -> Result<(), SoakError> {
    let metrics = tokio::time::timeout(Duration::from_secs(2), admin_read(root, "/metrics"))
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|b| String::from_utf8(b.to_vec()).ok());
    let clusters =
        tokio::time::timeout(Duration::from_secs(2), admin_read(root, "/api/v1/clusters"))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let sample = monitor::sample(
        pid,
        crate::millis(start.elapsed()),
        phase,
        metrics.as_deref(),
        clusters.as_ref(),
    );
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(results.join("samples.jsonl"))
        .await
        .map_err(io_error)?;
    file.write_all(format!("{}\n", serde_json::to_string(&sample).map_err(json_error)?).as_bytes())
        .await
        .map_err(io_error)?;
    if let Some(metrics) = metrics {
        let mut raw = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(results.join("metrics-samples.jsonl"))
            .await
            .map_err(io_error)?;
        raw.write_all(format!("{}\n", serde_json::to_string(&json!({"elapsed_ms":sample.elapsed_ms,"phase":phase,"gateway_pid":pid,"metrics":metrics,"clusters":clusters})).map_err(json_error)?).as_bytes())
            .await.map_err(io_error)?;
        tokio::fs::write(results.join("metrics-latest.prom"), metrics)
            .await
            .map_err(io_error)?;
    }
    samples.push(sample);
    Ok(())
}

fn source(root: &Path, dns: SocketAddr, port: u16, campaign: Campaign, generation: u64) -> String {
    let declaration = match campaign {
        Campaign::Discovery => {
            format!("name: api.discovery.test\n          record: a_aaaa\n          port: {port}")
        }
        Campaign::Protocol => "name: _https._tcp.api.discovery.test\n          record: srv".into(),
    };
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    ingress:
      cert_chain: gateway.pem
      private_key: gateway-key.pem
  trust_stores:
    fixture:
      ca_bundle: gateway.pem
  secrets:
    admin-token:
      file: admin.token
  clusters:
    upstream:
      protocol: h2
      tls:
        server_name: gateway.example.test
        trust:
          system_roots: false
          trust_store: fixture
      discovery:
        dns:
          {declaration}
          origin: https://gateway.example.test/base
          resolver:
            nameservers: ["{dns}"]
            query_timeout: 500ms
          refresh:
            min_interval: 200ms
            max_interval: 1s
            jitter_percent: 10
            stale_if_error: 500ms
          limits:
            max_endpoints: 8
            max_targets: 8
          address_policy:
            allow_private: true
            allow_loopback: true
            allow_link_local: false
      health:
        active:
          path: /healthz
          interval: 200ms
          timeout: 500ms
          healthy_statuses: ["200-299"]
          healthy_threshold: 1
          unhealthy_threshold: 1
        passive:
          consecutive_failures: 2
          eject_for: 500ms
      retry:
        max_attempts: 2
        methods: [GET, HEAD]
        retry_on: [connect_failure, response_header_timeout, refused_stream, reset]
        statuses: [503]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 8
      limits:
        max_in_flight: 128
        max_in_flight_per_endpoint: 64
        queue_timeout: 20ms
      timeouts:
        connect: 1s
        tls_handshake: 1s
        request_body_idle: 5s
        response_header: 5s
        response_body_idle: 10s
        pre_response_total: 8s
services:
  root:
    type: observe
    name: qualification
    service:
      type: transform
      response:
        headers:
          set:
            X-Qualification-Generation: "{generation}"
      service:
        type: proxy
        cluster: upstream
listeners:
  - name: qualification
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: ingress
    http:
      versions: [h2, http1]
    service:
      ref: root
admin:
  listen:
    unix:
      path: {socket}
      mode: "0600"
  auth:
    mode: bearer
    token_secret: admin-token
  storage:
    directory: {storage}
  bundle_trust:
    verification_keys: [operator.pub]
    deployment_root: {root_path}
  permissions:
    read: true
    stage: true
    activate: true
    rollback: true
    drain: true
    reload_source: true
  audit:
    destination: file
    file: {audit}
"#,
        socket = root.join("admin.sock").display(),
        storage = root.join("state").display(),
        root_path = root.display(),
        audit = root.join("audit.jsonl").display()
    )
}

async fn bundle(
    gateway: &Path,
    root: &Path,
    results: &Path,
    source: &str,
    label: &str,
    sequence: &mut u64,
) -> Result<String, SoakError> {
    let path = root.join(format!("{label}.yaml"));
    let output = root.join(format!("{label}.oxb"));
    std::fs::write(&path, source).map_err(io_error)?;
    command_json(
        gateway,
        &[
            "bundle".into(),
            "build".into(),
            path.display().to_string(),
            "--output".into(),
            output.display().to_string(),
            "--deployment-root".into(),
            root.display().to_string(),
        ],
        results,
        sequence,
    )
    .await?;
    command_json(
        gateway,
        &[
            "bundle".into(),
            "sign".into(),
            output.display().to_string(),
            "--key".into(),
            root.join("signing.key").display().to_string(),
        ],
        results,
        sequence,
    )
    .await?;
    // Build may legitimately emit a diagnostics document when warnings exist;
    // inspect supplies the actual stable public Bundle digest in either case.
    let inspected = command_json(
        gateway,
        &[
            "bundle".into(),
            "inspect".into(),
            output.display().to_string(),
        ],
        results,
        sequence,
    )
    .await?;
    let digest = inspected["content_digest"]
        .as_str()
        .ok_or_else(|| fail("Bundle inspection digest missing"))?
        .to_owned();
    command_json(
        gateway,
        &ctl(
            root,
            &[
                "stage",
                output
                    .to_str()
                    .ok_or_else(|| fail("UTF8 test path required"))?,
            ],
        ),
        results,
        sequence,
    )
    .await?;
    command_json(
        gateway,
        &ctl(root, &["validate", &digest]),
        results,
        sequence,
    )
    .await?;
    Ok(digest)
}

enum Sender {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}
struct DataClient {
    sender: Sender,
    driver: tokio::task::JoinHandle<()>,
    h2: bool,
    targets: [SocketAddr; 2],
    last_upstream: Option<&'static str>,
    payload_size: usize,
}
struct PayloadValidator {
    grpc: bool,
    length: usize,
    upstream: u8,
    seen: usize,
}
impl PayloadValidator {
    fn new(grpc: bool, length: usize, upstream: u8) -> Self {
        Self {
            grpc,
            length,
            upstream,
            seen: 0,
        }
    }
    fn push(&mut self, data: &Bytes) -> Result<(), SoakError> {
        let length = u32::try_from(self.length).map_err(io_error)?.to_be_bytes();
        for byte in data {
            let expected = if self.grpc {
                match self.seen {
                    0 => 0,
                    1..=4 => length[self.seen - 1],
                    _ => b'x',
                }
            } else if self.seen == 0 {
                self.upstream
            } else {
                b'x'
            };
            if self.seen >= self.length + if self.grpc { 5 } else { 0 } || *byte != expected {
                return Err(fail(
                    "opaque response DATA bytes were changed, duplicated or overlong",
                ));
            }
            self.seen += 1;
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), SoakError> {
        if self.seen != self.length + if self.grpc { 5 } else { 0 } {
            return Err(fail("opaque response DATA was truncated"));
        }
        Ok(())
    }
}
struct HeldGrpc {
    body: hyper::body::Incoming,
    validator: PayloadValidator,
}
impl Drop for DataClient {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl DataClient {
    async fn connect(
        address: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        h2: bool,
        targets: [SocketAddr; 2],
        payload_size: usize,
    ) -> Result<Self, SoakError> {
        let tcp = TcpStream::connect(address).await.map_err(io_error)?;
        let name = rustls::pki_types::ServerName::try_from("gateway.example.test".to_owned())
            .map_err(io_error)?;
        let tls = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(io_error)?;
        if h2 {
            let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(io_error)?;
            Ok(Self {
                sender: Sender::H2(sender),
                driver: tokio::spawn(async move {
                    let _ = connection.await;
                }),
                h2,
                targets,
                last_upstream: None,
                payload_size,
            })
        } else {
            let (sender, connection) = http1::handshake(TokioIo::new(tls))
                .await
                .map_err(io_error)?;
            Ok(Self {
                sender: Sender::H1(sender),
                driver: tokio::spawn(async move {
                    let _ = connection.await;
                }),
                h2,
                targets,
                last_upstream: None,
                payload_size,
            })
        }
    }
    async fn request(
        &mut self,
        grpc: bool,
        cancel: bool,
        expected_upstream: Option<&str>,
    ) -> Result<(u16, u64, bool), SoakError> {
        let path = format!(
            "/{}?b=2&a=1&a=3",
            if cancel {
                "cancel"
            } else if grpc {
                "soak.Service/Call"
            } else {
                "payload"
            }
        );
        let mut builder = Request::builder()
            .uri(if self.h2 {
                format!("https://gateway.example.test{path}")
            } else {
                path.clone()
            })
            .header(header::HOST, "gateway.example.test");
        if grpc {
            builder = builder
                .method(http::Method::POST)
                .header(header::CONTENT_TYPE, "application/grpc")
                .header(header::TE, "trailers");
        }
        let request = builder
            .body(Full::new(if grpc {
                Bytes::from_static(&[0, 0, 0, 0, 2, b'h', b'i'])
            } else {
                Bytes::new()
            }))
            .map_err(io_error)?;
        let response = match &mut self.sender {
            Sender::H1(sender) => sender.send_request(request).await,
            Sender::H2(sender) => sender.send_request(request).await,
        }
        .map_err(io_error)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Ok((status, 0, false));
        }
        if grpc
            && response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_none_or(|value| value != "application/grpc")
        {
            return Err(fail("opaque gRPC Content-Type was changed"));
        }
        let upstream = response
            .headers()
            .get("x-fixture-upstream")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| fail("actual upstream identity missing"))?;
        let target = match upstream {
            "a" => {
                self.last_upstream = Some("a");
                self.targets[0]
            }
            "b" => {
                self.last_upstream = Some("b");
                self.targets[1]
            }
            _ => return Err(fail("unknown actual upstream identity")),
        };
        if expected_upstream.is_some_and(|expected| expected != upstream) {
            return Err(fail("new request selected a withdrawn endpoint"));
        }
        if response
            .headers()
            .get("x-fixture-peer")
            .and_then(|v| v.to_str().ok())
            != Some(target.to_string().as_str())
        {
            return Err(fail(
                "actual upstream socket differs from approved DNS target",
            ));
        }
        for (name, expected) in [
            ("x-fixture-authority", "gateway.example.test".to_owned()),
            ("x-fixture-sni", "gateway.example.test".to_owned()),
            ("x-fixture-path", format!("/base{path}")),
        ] {
            if response.headers().get(name).and_then(|v| v.to_str().ok()) != Some(expected.as_str())
            {
                return Err(fail(format!("actual upstream {name} mismatch")));
            }
        }
        let mut bytes = 0u64;
        let mut validator = PayloadValidator::new(grpc, self.payload_size, upstream.as_bytes()[0]);
        let mut trailer = false;
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(io_error)?;
            if let Some(data) = frame.data_ref() {
                validator.push(data)?;
                bytes = bytes.saturating_add(data.len() as u64);
                if cancel {
                    drop(body);
                    return Ok((status, bytes, true));
                }
            }
            if let Some(trailers) = frame.trailers_ref() {
                trailer = trailers.get("grpc-status").is_some_and(|v| v == "0")
                    && trailers.get("grpc-message").is_some_and(|v| v == "ok");
            }
        }
        if grpc && !trailer {
            return Err(fail("gRPC status trailer missing"));
        }
        validator.finish()?;
        Ok((status, bytes, false))
    }

    async fn hold_grpc(&mut self) -> Result<Option<HeldGrpc>, SoakError> {
        let Sender::H2(sender) = &mut self.sender else {
            return Err(fail("held gRPC proof requires negotiated H2"));
        };
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("https://gateway.example.test/hold?b=2&a=1&a=3")
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 2, b'h', b'i'])))
            .map_err(io_error)?;
        let response = sender.send_request(request).await.map_err(io_error)?;
        if response.status() == http::StatusCode::SERVICE_UNAVAILABLE {
            return Ok(None);
        }
        if response.status() != http::StatusCode::OK
            || response
                .headers()
                .get(header::CONTENT_TYPE)
                .is_none_or(|value| value != "application/grpc")
            || response
                .headers()
                .get("x-fixture-upstream")
                .is_none_or(|v| v != "a")
            || response
                .headers()
                .get("x-fixture-peer")
                .and_then(|v| v.to_str().ok())
                != Some(self.targets[0].to_string().as_str())
            || response
                .headers()
                .get("x-fixture-sni")
                .is_none_or(|v| v != "gateway.example.test")
        {
            return Err(fail(
                "initial held gRPC stream did not use actual fixture A",
            ));
        }
        let mut body = response.into_body();
        let first = body
            .frame()
            .await
            .ok_or_else(|| fail("held stream ended before DATA"))?
            .map_err(io_error)?;
        if first.data_ref().is_none_or(Bytes::is_empty) {
            return Err(fail("held stream lacks its first gRPC DATA frame"));
        }
        let mut validator = PayloadValidator::new(true, self.payload_size, b'a');
        validator.push(first.data_ref().expect("validated first DATA"))?;
        Ok(Some(HeldGrpc { body, validator }))
    }
}

async fn open_upgrade(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> Result<Option<tokio_rustls::client::TlsStream<TcpStream>>, SoakError> {
    let socket = TcpStream::connect(address).await.map_err(io_error)?;
    let name = rustls::pki_types::ServerName::try_from("gateway.example.test".to_owned())
        .map_err(io_error)?;
    let mut socket = TlsConnector::from(config)
        .connect(name, socket)
        .await
        .map_err(io_error)?;
    socket.write_all(b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.map_err(io_error)?;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = socket.read_u8().await.map_err(io_error)?;
        head.push(byte);
        if head.len() > 16384 {
            return Err(fail("Upgrade header limit"));
        }
    }
    if head.starts_with(b"HTTP/1.1 503") {
        return Ok(None);
    }
    if !head.starts_with(b"HTTP/1.1 101") {
        return Err(fail("trusted Proxy Upgrade handshake failed"));
    }
    Ok(Some(socket))
}

async fn echo_upgrade(
    socket: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(), SoakError> {
    for _ in 0..4 {
        let bytes = b"qualification-tunnel";
        socket.write_all(bytes).await.map_err(io_error)?;
        let mut echoed = vec![0; bytes.len()];
        socket.read_exact(&mut echoed).await.map_err(io_error)?;
        if echoed != bytes {
            return Err(fail("Upgrade bidirectional byte mismatch"));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

async fn websocket(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> Result<bool, SoakError> {
    let Some(mut socket) = open_upgrade(address, config).await? else {
        return Ok(false);
    };
    echo_upgrade(&mut socket).await?;
    socket.shutdown().await.map_err(io_error)?;
    Ok(true)
}

async fn join_workers(workers: &mut tokio::task::JoinSet<()>) -> Result<(), SoakError> {
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(result) = workers.join_next().await {
            result.map_err(|error| fail(format!("load worker failed: {error}")))?;
        }
        Ok::<(), SoakError>(())
    })
    .await
    .map_err(|_| fail("load workers required forced termination"))?
}

/// Planned campaign stop closes admission between operations. It does not
/// manufacture an upload reset by dropping an already-started bounded request.
pub(super) async fn complete_bounded_request<T, E: std::fmt::Display>(
    operation: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, String> {
    tokio::time::timeout(Duration::from_secs(12), operation)
        .await
        .map_err(|_| "request timeout".to_owned())?
        .map_err(|error| error.to_string())
}

struct RetainedProofPlan<'a> {
    gateway: &'a Path,
    gateway_address: SocketAddr,
    root: &'a Path,
    results: &'a Path,
    a: &'a str,
    b: &'a str,
    h1: Arc<rustls::ClientConfig>,
    h2: Arc<rustls::ClientConfig>,
    payload_size: usize,
}

fn validate_completed_new_b_stream(
    response: (u16, u64, bool),
    payload_size: usize,
) -> Result<(), SoakError> {
    let (status, bytes, was_cancelled) = response;
    let expected_bytes = u64::try_from(payload_size)
        .ok()
        .and_then(|size| size.checked_add(5))
        .ok_or_else(|| fail("new B stream proof payload size overflow"))?;
    if status != 200 || was_cancelled || bytes != expected_bytes {
        return Err(fail(format!(
            "new B stream proof requires a complete validated 200 response: status={status}, bytes={bytes}, cancelled={was_cancelled}"
        )));
    }
    Ok(())
}

async fn retained_stream_proof(
    plan: RetainedProofPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    sequence: &mut u64,
) -> Result<Value, SoakError> {
    let RetainedProofPlan {
        gateway,
        gateway_address,
        root,
        results,
        a,
        b,
        h1,
        h2,
        payload_size,
    } = plan;
    let targets = [
        upstream.ready.address,
        upstream
            .ready
            .alternate
            .ok_or_else(|| fail("fixture B missing"))?,
    ];
    let mut client = DataClient::connect(gateway_address, h2, true, targets, payload_size).await?;
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut held = loop {
        if let Some(body) = client.hold_grpc().await? {
            break body;
        }
        if Instant::now() >= deadline {
            return Err(fail("initial discovery failed to become available"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let mut tunnel = open_upgrade(gateway_address, h1)
        .await?
        .ok_or_else(|| fail("initial Upgrade fixture unavailable"))?;
    echo_upgrade(&mut tunnel).await?;
    let before: Value =
        serde_json::from_slice(&admin_read(root, "/api/v1/runtime").await?).map_err(json_error)?;
    dns.command(FixtureCommand::Dns {
        mode: "b".into(),
        ttl: 1,
    })
    .await?;
    // A and AAAA complete independently. A newly observed B is not evidence
    // that the previously valid A was withdrawn. Wait out the fixture's old
    // one-second TTL and bounded 500 ms query, plus one minimum refresh slot.
    tokio::time::sleep(Duration::from_millis(1700)).await;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let (status, _, _) = client.request(true, false, None).await?;
        if status == 200 && client.last_upstream == Some("b") {
            break;
        }
        if Instant::now() >= deadline {
            return Err(fail("DNS withdrawal failed to move new streams to B"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let mut successful_new_b_streams = 0;
    for _ in 0..8 {
        // request() has already checked the actual B socket, fixed SNI,
        // authority, path, every opaque gRPC byte and the final trailers. A
        // non-200 response skips those checks, so it cannot count as proof.
        let response = client.request(true, false, Some("b")).await?;
        validate_completed_new_b_stream(response, payload_size)?;
        successful_new_b_streams += 1;
    }
    let normal_drops = upstream.command(FixtureCommand::Status).await?["body_drops"]
        .as_u64()
        .ok_or_else(|| fail("upstream drop counter missing"))?;
    if normal_drops != 0 {
        return Err(fail(
            "completed fixture response was falsely counted as cancelled",
        ));
    }
    let cancellation_before =
        String::from_utf8(admin_read(root, "/metrics").await?.to_vec()).map_err(io_error)?;
    let cancelled_before = monitor::body_terminations(&cancellation_before, "cancelled")
        .ok_or_else(|| fail("gateway cancellation counter unavailable"))?;
    let completed_before = monitor::body_terminations(&cancellation_before, "completed")
        .ok_or_else(|| fail("gateway completion counter unavailable"))?;
    if cancelled_before != 0 || completed_before < 8 {
        return Err(fail(
            "normal complete streams did not produce completed-only gateway telemetry",
        ));
    }
    let cancelled_response = client.request(true, true, Some("b")).await?;
    if cancelled_response.0 != 200 || !cancelled_response.2 {
        return Err(fail(
            "explicit cancellation did not receive its partial 200 DATA",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let cancelled_delta = loop {
        let scrape =
            String::from_utf8(admin_read(root, "/metrics").await?.to_vec()).map_err(io_error)?;
        let count = monitor::body_terminations(&scrape, "cancelled")
            .ok_or_else(|| fail("gateway cancellation counter unavailable"))?;
        let drops = upstream.command(FixtureCommand::Status).await?["body_drops"]
            .as_u64()
            .ok_or_else(|| fail("upstream drop counter missing"))?;
        if count > cancelled_before && drops == normal_drops + 1 {
            break count - cancelled_before;
        }
        if Instant::now() >= deadline {
            return Err(fail(
                "client cancellation lacked actual gateway termination and upstream drop acknowledgements",
            ));
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let after_dns: Value =
        serde_json::from_slice(&admin_read(root, "/api/v1/runtime").await?).map_err(json_error)?;
    if before != after_dns {
        return Err(fail("DNS changed immutable published runtime metadata"));
    }
    let mut activate = ctl(root, &["activate", b]);
    activate.splice(
        1..1,
        [
            "--if-match".into(),
            before["etag"]
                .as_str()
                .ok_or_else(|| fail("runtime ETag missing"))?
                .into(),
        ],
    );
    command_json(gateway, &activate, results, sequence).await?;
    echo_upgrade(&mut tunnel).await?;
    tunnel.shutdown().await.map_err(io_error)?;
    upstream.command(FixtureCommand::Release).await?;
    let mut status_trailer = false;
    while let Some(frame) = held.body.frame().await {
        let frame = frame.map_err(io_error)?;
        if let Some(data) = frame.data_ref() {
            held.validator.push(data)?;
        }
        if let Some(trailers) = frame.trailers_ref() {
            status_trailer |= trailers.get("grpc-status").is_some_and(|v| v == "0")
                && trailers.get("grpc-message").is_some_and(|v| v == "ok");
        }
    }
    if !status_trailer {
        return Err(fail(
            "old pinned gRPC stream lost its trailer after withdrawal/publication",
        ));
    }
    held.validator.finish()?;
    if upstream.command(FixtureCommand::Status).await?["body_drops"] != normal_drops + 1 {
        return Err(fail(
            "released completed gRPC stream was falsely counted as cancelled",
        ));
    }
    drop(client);
    let after_activate = command_json(gateway, &ctl(root, &["status"]), results, sequence).await?;
    if after_activate["etag"] == before["etag"] || after_activate["bundle_digest"] != b {
        return Err(fail("authenticated activation did not publish B"));
    }
    let mut rollback = ctl(root, &["rollback", a]);
    rollback.splice(
        1..1,
        [
            "--if-match".into(),
            after_activate["etag"]
                .as_str()
                .ok_or_else(|| fail("runtime ETag missing"))?
                .into(),
        ],
    );
    command_json(gateway, &rollback, results, sequence).await?;
    dns.command(FixtureCommand::Dns {
        mode: "both".into(),
        ttl: 3,
    })
    .await?;
    Ok(
        json!({"held_h2_grpc_completed":true,"grpc_status_trailer":true,"opaque_grpc_bytes_verified":true,"gateway_cancelled_termination_delta":cancelled_delta,"fixture_unreleased_body_drop_delta":1,"upgrade_across_withdrawal_and_publication":true,"successful_new_b_streams":successful_new_b_streams,"withdrawn_endpoint_new_streams":0,"unchanged_dns_runtime":before,"after_dns":after_dns,"after_activate":after_activate}),
    )
}

pub(super) async fn run_controller(args: ProcessArguments) -> Result<(), SoakError> {
    validate_arguments(&args)?;
    match std::fs::read_dir(&args.output) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(fail("qualification output directory must be empty"));
            }
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(io_error(error)),
        _ => {}
    }
    std::fs::create_dir_all(&args.output).map_err(io_error)?;
    let result = run_inner(&args).await;
    if let Err(error) = &result {
        let summary_path = args.output.join("summary.json");
        let mut summary = std::fs::read(&summary_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .unwrap_or_else(
                || json!({"schema_version":"oxidase.discovery-soak/v1","result":"fail"}),
            );
        summary["error"] = json!(error.to_string());
        summary["result"] = json!("fail");
        std::fs::write(
            summary_path,
            serde_json::to_vec_pretty(&summary).map_err(json_error)?,
        )
        .map_err(io_error)?;
    }
    result
}

fn validate_arguments(args: &ProcessArguments) -> Result<(), SoakError> {
    if args.duration.is_zero()
        || args.duration > Duration::from_secs(24 * 3600)
        || args.concurrency == 0
        || args.concurrency > 256
        || args.payload_size == 0
        || args.payload_size > 16 * 1024 * 1024
        || args.reload_interval < Duration::from_millis(100)
        || args.reload_interval > Duration::from_secs(3600)
        || args.sample_interval < Duration::from_millis(100)
        || args.sample_interval > Duration::from_secs(60)
        || args.warm_up > Duration::from_secs(600)
        || args.cooldown > Duration::from_secs(600)
        || (args.duration + args.warm_up + args.cooldown).as_millis()
            / args.sample_interval.as_millis().max(1)
            > 100_000
        || args.duration.as_millis() / args.reload_interval.as_millis().max(1) > 50_000
    {
        return Err(fail("qualification parameters outside bounded ranges"));
    }
    Ok(())
}

async fn run_inner(args: &ProcessArguments) -> Result<(), SoakError> {
    // Qualification-only fault injection; absent in normal campaigns and never
    // part of the Gateway DSL. Bound it below all configured phase deadlines.
    let fixture_read_delay_ms = std::env::var("OXIDASE_SOAK_REQUEST_READ_DELAY_MS")
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|delay| *delay <= 500)
                .ok_or_else(|| fail("fixture request read delay must be 0..=500 ms"))
        })
        .transpose()?
        .unwrap_or(0);
    let directory = tempfile::tempdir().map_err(io_error)?;
    let root = directory.path().canonicalize().map_err(io_error)?;
    let identity = identity()?;
    write_identity(&root, &identity)?;
    std::fs::write(root.join("admin.token"), format!("{TOKEN}\n")).map_err(io_error)?;
    std::fs::write(
        root.join("fixture-plan.json"),
        serde_json::to_vec(&json!({"payload_size":args.payload_size,"request_read_delay_ms":fixture_read_delay_ms})).map_err(json_error)?,
    )
    .map_err(io_error)?;
    std::fs::write(root.join("signing.key"), [31u8; 32]).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for name in ["admin.token", "signing.key", "gateway-key.pem"] {
            std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o600))
                .map_err(io_error)?;
        }
    }
    let signing =
        oxidase_bundle::BundleSigningKey::read_file(root.join("signing.key")).map_err(io_error)?;
    std::fs::write(
        root.join("operator.pub"),
        signing.verification_key().as_bytes(),
    )
    .map_err(io_error)?;
    let mut upstream = FixtureProcess::spawn("upstream", &root, &args.output).await?;
    std::fs::write(
        root.join("upstream.json"),
        serde_json::to_vec(&upstream.ready).map_err(json_error)?,
    )
    .map_err(io_error)?;
    let mut dns = FixtureProcess::spawn("dns", &root, &args.output).await?;
    let source0 = source(
        &root,
        dns.ready.address,
        upstream.ready.address.port(),
        args.campaign,
        0,
    );
    std::fs::write(root.join("gateway.yaml"), &source0).map_err(io_error)?;
    std::fs::write(
        args.output.join("seed-config.yaml"),
        source0.replace(
            root.to_str().ok_or_else(|| fail("UTF8 test root"))?,
            "DEPLOYMENT_ROOT",
        ),
    )
    .map_err(io_error)?;
    let gateway = GatewayProcess::spawn(&args.gateway, &root, &args.output).await?;
    let mut sequence = 0;
    let initial = command_json(
        &args.gateway,
        &ctl(&root, &["status"]),
        &args.output,
        &mut sequence,
    )
    .await?;
    let a = bundle(
        &args.gateway,
        &root,
        &args.output,
        &source(
            &root,
            dns.ready.address,
            upstream.ready.address.port(),
            args.campaign,
            1,
        ),
        "a",
        &mut sequence,
    )
    .await?;
    let b = bundle(
        &args.gateway,
        &root,
        &args.output,
        &source(
            &root,
            dns.ready.address,
            upstream.ready.address.port(),
            args.campaign,
            2,
        ),
        "b",
        &mut sequence,
    )
    .await?;
    dns.command(FixtureCommand::Dns {
        mode: "a".into(),
        ttl: 1,
    })
    .await?;
    command_json(
        &args.gateway,
        &ctl(&root, &["activate", &a]),
        &args.output,
        &mut sequence,
    )
    .await?;
    let h1 = client_config(&[&identity], &[b"http/1.1"])?;
    let h2 = client_config(&[&identity], &[b"h2"])?;
    let retained = tokio::time::timeout(
        Duration::from_secs(30),
        retained_stream_proof(
            RetainedProofPlan {
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
            &mut sequence,
        ),
    )
    .await
    .map_err(|_| fail("retained stream qualification deadline"))??;
    std::fs::write(
        args.output.join("retained-streams.json"),
        serde_json::to_vec_pretty(&retained).map_err(json_error)?,
    )
    .map_err(io_error)?;
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut requests = 0u64;
    let mut success = 0u64;
    let mut cancelled = 0u64;
    let mut expected = 0u64;
    let mut failures = 0u64;
    let mut unexpected_samples = Vec::new();
    let mut bytes = 0u64;
    let mut grpc = 0u64;
    let mut grpc_completed = 0u64;
    let mut grpc_cancelled = 0u64;
    let mut tunnels = 1u64;
    let mut upgrade_unavailable = 0u64;
    let mut upgrade_errors = 0u64;
    let mut activations = 2u64;
    let mut rollbacks = 1u64;
    let expected_unavailable = Arc::new(AtomicBool::new(true));
    let control_epoch = Arc::new(AtomicU64::new(0));
    let (events, mut received) =
        tokio::sync::mpsc::channel::<(bool, bool, Result<(u16, u64, bool), String>)>(256);
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut workers = tokio::task::JoinSet::new();
    let targets = [
        upstream.ready.address,
        upstream
            .ready
            .alternate
            .ok_or_else(|| fail("second upstream socket missing"))?,
    ];
    for worker in 0..args.concurrency {
        let events = events.clone();
        let mut stop = stopped.clone();
        let address = gateway.address;
        let h1 = Arc::clone(&h1);
        let h2 = Arc::clone(&h2);
        let campaign = args.campaign;
        let seed = args.seed ^ (worker as u64);
        let expected = Arc::clone(&expected_unavailable);
        let epoch = Arc::clone(&control_epoch);
        let payload_size = args.payload_size;
        workers.spawn(async move {
            let mut random=XorShift64::new(seed);let mut client=None;let mut operations=0u64;
            // Keep one negotiated protocol per worker. Switching on every
            // operation creates artificial TIME_WAIT/ephemeral-port churn.
            let use_h2=worker%4!=0;
            loop {
                if *stop.borrow(){break;}
                let cancel=random.next().is_multiple_of(17);let is_grpc=matches!(campaign,Campaign::Protocol);
                if client.is_none()||operations.is_multiple_of(128){client=tokio::select!{_=stop.changed()=>break,connection=tokio::time::timeout(Duration::from_secs(5),DataClient::connect(address,if use_h2{Arc::clone(&h2)}else{Arc::clone(&h1)},use_h2,targets,payload_size))=>connection.ok().and_then(Result::ok)};}
                let expected_now=expected.load(Ordering::Acquire);
                let started_epoch = epoch.load(Ordering::Acquire);
                let result=if let Some(client)=&mut client{complete_bounded_request(client.request(is_grpc,cancel,None)).await}else{Err("client connection failure".into())};
                if result.is_err()||(!use_h2&&cancel){client=None;}
                let expected_now = expected_now || expected.load(Ordering::Acquire) || epoch.load(Ordering::Acquire) != started_epoch;
                tokio::select! {
                    _ = stop.changed() => break,
                    sent = events.send((is_grpc,expected_now,result)) => {
                        if sent.is_err() { break; }
                    }
                }
                operations+=1;tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }
    drop(events);
    let end = start + args.warm_up + args.duration;
    let steady_start = start + args.warm_up;
    let mut sample_next = start;
    let mut change_next = steady_start;
    let mut changes = 0usize;
    let mut probe = tokio::time::timeout(
        Duration::from_secs(5),
        DataClient::connect(
            gateway.address,
            Arc::clone(&h2),
            true,
            targets,
            args.payload_size,
        ),
    )
    .await
    .map_err(|_| fail("availability probe connection timeout"))??;
    while Instant::now() < end {
        let now = Instant::now();
        if now >= sample_next {
            record_sample(
                &root,
                gateway.pid,
                start,
                if now < steady_start {
                    "warmup"
                } else {
                    "steady"
                },
                &args.output,
                &mut samples,
            )
            .await?;
            sample_next = Instant::now() + args.sample_interval;
        }
        if now >= change_next {
            let mode_plan = fixture_mode_plan(args.campaign, changes);
            let mode = mode_plan.name;
            let before: Value =
                serde_json::from_slice(&admin_read(&root, "/api/v1/runtime").await?)
                    .map_err(json_error)?;
            expected_unavailable.store(true, Ordering::Release);
            control_epoch.fetch_add(1, Ordering::AcqRel);
            dns.command(FixtureCommand::Dns {
                mode: mode.into(),
                ttl: 3,
            })
            .await?;
            upstream
                .command(FixtureCommand::Health {
                    healthy_a: mode_plan.healthy_a,
                    healthy_b: mode_plan.healthy_b,
                    retry_a: mode_plan.retry_a,
                })
                .await?;
            tokio::time::sleep(Duration::from_millis(600)).await;
            let after_dns: Value =
                serde_json::from_slice(&admin_read(&root, "/api/v1/runtime").await?)
                    .map_err(json_error)?;
            if before["etag"] != after_dns["etag"] || before["origin"] != after_dns["origin"] {
                return Err(fail(
                    "DNS operational refresh changed publication ETag/origin",
                ));
            }
            let unavailable = mode_plan.unavailable();
            if !unavailable {
                let deadline = Instant::now() + Duration::from_secs(4);
                loop {
                    if mode_plan.require_two_members {
                        let clusters: Value =
                            serde_json::from_slice(&admin_read(&root, "/api/v1/clusters").await?)
                                .map_err(json_error)?;
                        if clusters["clusters"][0]["discovery"]["endpoint_count"] != 2 {
                            if Instant::now() >= deadline {
                                return Err(fail(
                                    "two-target retry mode did not publish both fresh endpoints",
                                ));
                            }
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            continue;
                        }
                    }
                    if tokio::time::timeout(
                        Duration::from_secs(2),
                        probe.request(matches!(args.campaign, Campaign::Protocol), false, None),
                    )
                    .await
                    .map_err(|_| fail("availability probe request timeout"))??
                    .0 == 200
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(fail(format!(
                            "positive DNS/health mode {mode} did not become available"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            expected_unavailable.store(unavailable, Ordering::Release);
            let mut action = ctl(
                &root,
                &[
                    if changes.is_multiple_of(2) {
                        "activate"
                    } else {
                        "rollback"
                    },
                    if changes.is_multiple_of(4) { &b } else { &a },
                ],
            );
            action.splice(
                1..1,
                [
                    "--if-match".to_owned(),
                    before["etag"]
                        .as_str()
                        .ok_or_else(|| fail("runtime ETag missing"))?
                        .to_owned(),
                ],
            );
            if changes.is_multiple_of(2) {
                command_json(&args.gateway, &action, &args.output, &mut sequence).await?;
                activations += 1;
            } else {
                command_json(&args.gateway, &action, &args.output, &mut sequence).await?;
                rollbacks += 1;
            }
            std::fs::write(
                args.output.join(format!("change-{changes:04}.json")),
                serde_json::to_vec_pretty(
                    &json!({"mode":mode,"before":before,"after_dns":after_dns,"at_ms":crate::millis(start.elapsed())}),
                )
                .map_err(json_error)?,
            )
            .map_err(io_error)?;
            if matches!(args.campaign, Campaign::Protocol) {
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    websocket(gateway.address, Arc::clone(&h1)),
                )
                .await
                {
                    Ok(Ok(true)) => tunnels += 1,
                    Ok(Ok(false)) if expected_unavailable.load(Ordering::Acquire) => {
                        upgrade_unavailable += 1
                    }
                    other => {
                        upgrade_errors += 1;
                        if unexpected_samples.len() < 32 {
                            unexpected_samples
                                .push(json!({"upgrade":format!("{other:?}"), "mode":mode}));
                        }
                    }
                }
            }
            changes += 1;
            change_next = Instant::now() + args.reload_interval;
        }
        tokio::select! {Some((is_grpc,expected_now,result))=received.recv()=>{requests+=1;if is_grpc{grpc+=1;}match result{Ok((200,n,was_cancelled))=>{if was_cancelled{cancelled+=1;if is_grpc{grpc_cancelled+=1;}}else{success+=1;if is_grpc{grpc_completed+=1;}}bytes+=n;},Ok((503,_,_)) if expected_now=>expected+=1,other=>{failures+=1;if unexpected_samples.len()<32{unexpected_samples.push(json!({"result":format!("{other:?}"),"expected_unavailable":expected_now,"grpc":is_grpc,"at_ms":crate::millis(start.elapsed())}));}}}},_=tokio::time::sleep(Duration::from_millis(10))=>{}}
    }
    let _ = stop.send(true);
    join_workers(&mut workers).await?;
    drop(probe);
    while let Ok((is_grpc, expected_now, result)) = received.try_recv() {
        requests += 1;
        if is_grpc {
            grpc += 1;
        }
        match result {
            Ok((200, n, was_cancelled)) => {
                if was_cancelled {
                    cancelled += 1;
                    if is_grpc {
                        grpc_cancelled += 1;
                    }
                } else {
                    success += 1;
                    if is_grpc {
                        grpc_completed += 1;
                    }
                }
                bytes += n;
            }
            Ok((503, _, _)) if expected_now => expected += 1,
            _ => failures += 1,
        }
    }
    upstream.command(FixtureCommand::Release).await?;
    command_json(
        &args.gateway,
        &ctl(&root, &["drain"]),
        &args.output,
        &mut sequence,
    )
    .await?;
    let drained = command_json(
        &args.gateway,
        &ctl(&root, &["status"]),
        &args.output,
        &mut sequence,
    )
    .await?;
    if drained["serving_state"] != "drained" {
        return Err(fail("actual manager drain did not complete"));
    }
    let cooldown = Instant::now() + args.cooldown;
    while Instant::now() < cooldown {
        record_sample(
            &root,
            gateway.pid,
            start,
            "cooldown",
            &args.output,
            &mut samples,
        )
        .await?;
        tokio::time::sleep(args.sample_interval).await;
    }
    record_sample(
        &root,
        gateway.pid,
        start,
        "cooldown",
        &args.output,
        &mut samples,
    )
    .await?;
    let dns_stats = dns.command(FixtureCommand::Status).await?;
    let upstream_stats = upstream.command(FixtureCommand::Status).await?;
    let unexpected_errors = failures
        .checked_add(upgrade_errors)
        .ok_or_else(|| fail("operation counter overflow"))?;
    let accounted_workers = success
        .checked_add(cancelled)
        .and_then(|total| total.checked_add(expected))
        .and_then(|total| total.checked_add(failures))
        .ok_or_else(|| fail("worker counter overflow"))?;
    if requests != accounted_workers {
        return Err(fail(format!(
            "worker accounting mismatch: requests={requests}, classified={accounted_workers}"
        )));
    }
    std::fs::write(
        args.output.join("final-evidence.json"),
        serde_json::to_vec_pretty(&json!({
            "requests":requests,"success":success,"cancelled_responses":cancelled,
            "unexpected_errors":unexpected_errors,"worker_errors":failures,"upgrade_unavailable":upgrade_unavailable,"upgrade_errors":upgrade_errors,"dns":dns_stats,"upstream":upstream_stats,
            "last_sample":samples.last(),"gateway_pid":gateway.pid,
        }))
        .map_err(json_error)?,
    )
    .map_err(io_error)?;
    let coverage = json!({
        "full_control_cycle": changes >= if matches!(args.campaign,Campaign::Protocol) {12} else {11},
        "active_health_successes_max_observed": samples.iter().filter_map(|sample|sample.active_health_successes).max(),
        "active_health_failures_max_observed": samples.iter().filter_map(|sample|sample.active_health_failures).max(),
        "health_transitions_max_observed": samples.iter().filter_map(|sample|sample.health_transitions).max(),
        "retry_attempts_max_observed": samples.iter().filter_map(|sample|sample.retry_attempts).max(),
        "wire_counts":dns_stats,
    });
    if coverage["full_control_cycle"] == true {
        for field in ["health_success_replies", "health_failure_replies"] {
            if upstream_stats[field]
                .as_u64()
                .is_none_or(|count| count == 0)
            {
                return Err(fail(format!(
                    "full-cycle fixture did not receive and answer {field}"
                )));
            }
        }
        for field in [
            "active_health_successes_max_observed",
            "active_health_failures_max_observed",
            "health_transitions_max_observed",
        ] {
            if coverage[field].as_u64().is_none_or(|count| count == 0) {
                return Err(fail(format!("full-cycle campaign did not observe {field}")));
            }
        }
        if matches!(args.campaign, Campaign::Discovery)
            && coverage["retry_attempts_max_observed"]
                .as_u64()
                .is_none_or(|count| count == 0)
        {
            return Err(fail(
                "full-cycle discovery campaign did not observe an actual retry",
            ));
        }
        for field in [
            "tcp_queries",
            "cname_answers",
            "ttl_zero_answers",
            "truncated_udp_answers",
        ] {
            if dns_stats[field].as_u64().is_none_or(|count| count == 0) {
                return Err(fail(format!("full-cycle campaign did not emit {field}")));
            }
        }
        if matches!(args.campaign, Campaign::Protocol) {
            for field in ["srv_queries", "withdraw_answers", "reversed_srv_answers"] {
                if dns_stats[field].as_u64().is_none_or(|count| count == 0) {
                    return Err(fail(format!(
                        "full-cycle SRV campaign did not emit {field}"
                    )));
                }
            }
        }
    }
    let final_sample = samples
        .last()
        .ok_or_else(|| fail("qualification produced no final sample"))?;
    for (name, count) in [
        ("requests", final_sample.active_requests),
        ("connections", final_sample.active_connections),
        ("streams", final_sample.active_streams),
        ("tunnels", final_sample.active_tunnels),
        ("discovery supervisors", final_sample.discovery_tasks),
        ("cluster permits", final_sample.cluster_permits),
        ("retry permits", final_sample.retry_permits),
        (
            "retired admission counters",
            final_sample.retired_admission_counters,
        ),
    ] {
        if count != Some(0) {
            return Err(fail(format!("drain did not prove zero {name}: {count:?}")));
        }
    }
    if success == 0
        || upstream_stats["body_drops"]
            .as_u64()
            .is_none_or(|count| count == 0)
        || upstream_stats["active_tunnels"] != 0
        || upstream_stats["request_faults"] != 0
        || dns_stats["queries"].as_u64().is_none_or(|count| count == 0)
    {
        return Err(fail(format!(
            "qualification did not prove live traffic, real cancellation, DNS queries and tunnel cleanup: success={success}, body_drops={}, active_tunnels={}, request_faults={}, dns_queries={}",
            upstream_stats["body_drops"],
            upstream_stats["active_tunnels"],
            upstream_stats["request_faults"],
            dns_stats["queries"],
        )));
    }
    let pids = json!({"gateway":gateway.pid,"generator":std::process::id(),"dns":dns.ready.pid,"upstream":upstream.ready.pid});
    gateway.stop().await?;
    dns.stop().await?;
    upstream.stop().await?;
    let summary = json!({
        "schema_version":"oxidase.discovery-soak/v1", "result":if unexpected_errors==0{"pass"}else{"fail"},
        "parameters":{"campaign":args.campaign,"duration_ms":crate::millis(args.duration),"warmup_ms":crate::millis(args.warm_up),"cooldown_ms":crate::millis(args.cooldown),"concurrency":args.concurrency,"seed":args.seed,"sample_interval_ms":crate::millis(args.sample_interval),"reload_interval_ms":crate::millis(args.reload_interval),"payload_size":args.payload_size},
        "elapsed_ms":crate::millis(start.elapsed()),"pids":pids,"initial_runtime":initial,"drained_runtime":drained,
        "requests":requests,"success":success,"cancelled_responses":cancelled,"expected_unavailable":expected,
        "unexpected_errors":unexpected_errors,"worker_errors":failures,"unexpected_samples":unexpected_samples,"bytes":bytes,
        "grpc_attempted":grpc,"grpc_completed":grpc_completed,"grpc_cancelled":grpc_cancelled,
        "upgrade_tunnels":tunnels,"upgrade_unavailable":upgrade_unavailable,"upgrade_errors":upgrade_errors,"retained_stream_proof":retained,"final_sample":final_sample,
        "activations":activations,"rollbacks":rollbacks,"dns":dns_stats,"upstream":upstream_stats,
        "observed_coverage":coverage,
        "fixture_request_read_delay_ms":fixture_read_delay_ms,
        "fixture_request_stream_window":if fixture_read_delay_ms>0{Some(1)}else{None},
        "rss_kib":monitor::curve(&samples,|s|s.rss_kib),"open_fds":monitor::curve(&samples,|s|s.open_fds),
        "gateway_exited":true,"post_exit_rss":null,"post_exit_fds":null,
    });
    std::fs::write(
        args.output.join("summary.json"),
        serde_json::to_vec_pretty(&summary).map_err(json_error)?,
    )
    .map_err(io_error)?;
    println!("{summary}");
    if unexpected_errors > 0 {
        return Err(fail("qualification observed unexpected request failures"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_fixture_cycles_keep_health_retry_and_declared_availability_consistent() {
        // Two complete LCM(11 modes, 4 health toggles, 3 retry toggles) cycles;
        // the separate twelve-mode SRV schedule is also checked in full.
        for campaign in [Campaign::Discovery, Campaign::Protocol] {
            for change in 0..264 {
                let plan = fixture_mode_plan(campaign, change);
                if plan.retry_a {
                    assert!(
                        plan.valid_answer
                            && plan.target_a
                            && plan.target_b
                            && plan.healthy_a
                            && plan.healthy_b
                    );
                    assert!(plan.require_two_members && !plan.unavailable());
                }
                if !plan.unavailable() {
                    assert!(
                        plan.valid_answer
                            && ((plan.target_a && plan.healthy_a)
                                || (plan.target_b && plan.healthy_b))
                    );
                }
                if plan.name == "cname" {
                    assert!(plan.healthy_a && !plan.unavailable());
                }
                if !plan.valid_answer {
                    assert!(plan.unavailable() && !plan.retry_a);
                }
                if matches!(campaign, Campaign::Protocol) {
                    assert!(!plan.retry_a);
                }
            }
        }
    }
    #[test]
    fn readiness_uses_actual_cli_prefix() {
        assert_eq!(
            parse_listener(
                "listener qualification accepting HTTPS (h2, http/1.1) on 127.0.0.1:12345"
            ),
            Some("127.0.0.1:12345".parse().expect("fixture address"))
        );
        assert!(parse_listener("admin listener accepting HTTP/1.1 on 127.0.0.1:12345").is_none());
    }
    #[test]
    fn opaque_grpc_validator_checks_fragmented_header_and_every_payload_byte() {
        let mut valid = PayloadValidator::new(true, 2, b'a');
        valid
            .push(&Bytes::from_static(&[0, 0]))
            .expect("partial header");
        assert!(valid.finish().is_err());
        valid
            .push(&Bytes::from_static(&[0, 0, 2, b'x', b'x']))
            .expect("remaining exact frame");
        valid.finish().expect("exact opaque frame");
        assert!(valid.push(&Bytes::from_static(b"x")).is_err());
        let mut invalid = PayloadValidator::new(true, 2, b'a');
        assert!(
            invalid
                .push(&Bytes::from_static(&[1, 0, 0, 0, 2, b'x', b'x']))
                .is_err()
        );
        let mut wrong_payload = PayloadValidator::new(true, 2, b'a');
        assert!(
            wrong_payload
                .push(&Bytes::from_static(&[0, 0, 0, 0, 2, b'x', b'y']))
                .is_err()
        );
    }
    #[test]
    fn new_b_stream_proof_requires_complete_validated_200_without_cancellation() {
        validate_completed_new_b_stream((200, 32773, false), 32768)
            .expect("complete five-byte gRPC header and validated payload");
        for response in [
            (503, 0, false),
            (503, 32773, false),
            (206, 32773, false),
            (200, 0, false),
            (200, 32772, false),
            (200, 32774, false),
            (200, 32773, true),
        ] {
            assert!(
                validate_completed_new_b_stream(response, 32768).is_err(),
                "invalid response cannot contribute to the eight-stream proof: {response:?}"
            );
        }
    }
    #[test]
    fn campaign_argument_limits_bound_memory_and_control_artifacts() {
        let mut args = ProcessArguments {
            gateway: "gateway".into(),
            campaign: Campaign::Discovery,
            duration: Duration::from_secs(600),
            concurrency: 8,
            seed: 1,
            reload_interval: Duration::from_secs(3),
            warm_up: Duration::from_secs(30),
            cooldown: Duration::from_secs(120),
            sample_interval: Duration::from_secs(1),
            payload_size: 32768,
            output: "results".into(),
        };
        validate_arguments(&args).expect("documented qualification arguments");
        args.concurrency = 257;
        assert!(validate_arguments(&args).is_err());
        args.concurrency = 8;
        args.duration = Duration::ZERO;
        assert!(validate_arguments(&args).is_err());
        args.duration = Duration::from_secs(24 * 3600);
        args.sample_interval = Duration::from_millis(100);
        assert!(validate_arguments(&args).is_err());
    }
    #[tokio::test]
    async fn existing_artifacts_are_never_reused_or_overwritten() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let summary = directory.path().join("summary.json");
        std::fs::write(&summary, b"{\"result\":\"pass\"}").expect("previous evidence");
        let args = ProcessArguments {
            gateway: "missing".into(),
            campaign: Campaign::Discovery,
            duration: Duration::from_secs(1),
            concurrency: 1,
            seed: 1,
            reload_interval: Duration::from_secs(1),
            warm_up: Duration::ZERO,
            cooldown: Duration::ZERO,
            sample_interval: Duration::from_secs(1),
            payload_size: 1,
            output: directory.path().to_owned(),
        };
        assert!(
            run_controller(args)
                .await
                .expect_err("reject reused evidence")
                .to_string()
                .contains("must be empty")
        );
        assert_eq!(
            std::fs::read(summary).expect("preserved evidence"),
            b"{\"result\":\"pass\"}"
        );
    }
    #[tokio::test]
    async fn a_panicked_load_worker_cannot_be_counted_as_campaign_success() {
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async {
            panic!("injected qualification worker panic");
        });
        assert!(
            join_workers(&mut workers)
                .await
                .expect_err("worker panic must fail")
                .to_string()
                .contains("load worker failed")
        );
    }
}
