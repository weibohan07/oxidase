use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::{Child, Command};
use tokio::time::Instant;
use tokio_rustls::{TlsConnector, rustls};

use super::{
    Campaign, FixtureCommand, FixtureProcess, ProcessArguments, SoakError, fail, io_error,
    json_error, monitor,
};
use crate::common::{XorShift64, client_config, identity, write_identity};

pub(super) const TOKEN: &str = "test-only-qualification-bearer-token";
type WorkerEvent = (bool, bool, Result<(u16, u64, bool), String>);

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

pub(super) struct GatewayProcess {
    child: Child,
    pub(super) pid: u32,
    pub(super) address: SocketAddr,
    reader: tokio::task::JoinHandle<Result<(), SoakError>>,
}

impl GatewayProcess {
    pub(super) async fn spawn(
        executable: &Path,
        root: &Path,
        results: &Path,
    ) -> Result<Self, SoakError> {
        Self::spawn_with_observation(executable, root, results, true).await
    }

    pub(super) async fn spawn_with_observation(
        executable: &Path,
        root: &Path,
        results: &Path,
        enabled: bool,
    ) -> Result<Self, SoakError> {
        let stderr = std::fs::File::create(results.join("gateway.stderr.log")).map_err(io_error)?;
        let mut child = Command::new(executable)
            .arg("serve")
            .arg(root.join("gateway.yaml"))
            .env("RUST_LOG", "warn")
            .env(
                "OXIDASE_RESOURCE_OBSERVATION",
                if enabled { "on" } else { "off" },
            )
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
    pub(super) async fn stop(mut self) -> Result<(), SoakError> {
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

/// Facts recorded by the additive resource qualification client. The offline
/// verifier compares these bytes/metadata to its own recipe; no `pass` flag is
/// provided. Missing values remain unavailable rather than fabricated zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ResourceResponseFacts {
    pub(super) operation_id: String,
    pub(super) protocol: String,
    pub(super) started_ns: Option<u64>,
    pub(super) head_ns: Option<u64>,
    pub(super) ended_ns: Option<u64>,
    pub(super) status: Option<u16>,
    pub(super) eof: bool,
    pub(super) body_bytes: u64,
    pub(super) body_sha256: String,
    pub(super) content_type: Option<String>,
    pub(super) trailers: BTreeMap<String, String>,
    pub(super) upstream_peer: Option<String>,
    pub(super) upstream_name: Option<String>,
    pub(super) authority: Option<String>,
    pub(super) server_name: Option<String>,
    pub(super) path: Option<String>,
    pub(super) error_stage: Option<String>,
    pub(super) error_code: Option<String>,
    pub(super) cancelled: bool,
    pub(super) data_observed: bool,
    pub(super) fixture_cancel_ack: bool,
    pub(super) upload: ResourceUploadFacts,
    pub(super) diagnostics: Vec<String>,
    pub(super) fault_case_id: Option<u64>,
    pub(super) upgrade_headers: BTreeMap<String, String>,
    pub(super) tunnel_client_shutdown: bool,
    pub(super) tunnel_close_result: Option<String>,
    pub(super) echo_iterations: u8,
    /// Actual complete Upgrade request-head write, not merely a built request.
    pub(super) request_head_sent: bool,
}

impl ResourceResponseFacts {
    fn blank(operation_id: String, protocol: &str) -> Self {
        Self {
            operation_id,
            protocol: protocol.into(),
            started_ns: None,
            head_ns: None,
            ended_ns: None,
            status: None,
            eof: false,
            body_bytes: 0,
            body_sha256: String::new(),
            content_type: None,
            trailers: BTreeMap::new(),
            upstream_peer: None,
            upstream_name: None,
            authority: None,
            server_name: None,
            path: None,
            error_stage: None,
            error_code: None,
            cancelled: false,
            data_observed: false,
            fixture_cancel_ack: false,
            upload: ResourceUploadFacts::default(),
            diagnostics: Vec::new(),
            fault_case_id: None,
            upgrade_headers: BTreeMap::new(),
            tunnel_client_shutdown: false,
            tunnel_close_result: None,
            echo_iterations: 0,
            request_head_sent: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(super) struct ResourceUploadFacts {
    pub(super) body_bytes: Option<u64>,
    pub(super) body_sha256: Option<String>,
    pub(super) eof: Option<bool>,
    pub(super) fixture_ack: bool,
}

#[derive(Debug, Clone)]
pub(super) struct ResourceRequest {
    pub(super) operation_id: String,
    pub(super) path: String,
    pub(super) grpc: bool,
    pub(super) cancel_after_first_data: bool,
    pub(super) payload_size: usize,
    pub(super) upload_bytes: usize,
}

struct GeneratedUpload {
    prefix: Option<Bytes>,
    remaining: usize,
}

impl GeneratedUpload {
    fn new(grpc: bool, length: usize) -> Self {
        let prefix = grpc.then(|| {
            let mut prefix = vec![0];
            prefix.extend_from_slice(&(length as u32).to_be_bytes());
            Bytes::from(prefix)
        });
        Self {
            prefix,
            remaining: length,
        }
    }
}

impl Body for GeneratedUpload {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let length = self.remaining.min(1024);
        self.remaining -= length;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![b'u'; length])))))
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_none() && self.remaining == 0
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact((self.remaining + self.prefix.as_ref().map_or(0, Bytes::len)) as u64)
    }
}

enum ResourceSender {
    H1(http1::SendRequest<GeneratedUpload>),
    H2(http2::SendRequest<GeneratedUpload>),
}

/// A Rust fixture client only, not another gateway or proxy implementation.
pub(super) struct ResourceDataClient {
    sender: Option<ResourceSender>,
    driver: Option<tokio::task::JoinHandle<Result<(), String>>>,
    h2: bool,
    targets: Vec<(String, SocketAddr)>,
    local_response: bool,
}

impl Drop for ResourceDataClient {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

impl ResourceDataClient {
    pub(super) async fn connect(
        address: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        h2: bool,
        targets: Vec<(String, SocketAddr)>,
    ) -> Result<Self, SoakError> {
        Self::connect_inner(address, config, h2, targets, false).await
    }

    pub(super) async fn connect_local(
        address: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        h2: bool,
    ) -> Result<Self, SoakError> {
        Self::connect_inner(address, config, h2, Vec::new(), true).await
    }

    async fn connect_inner(
        address: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        h2: bool,
        targets: Vec<(String, SocketAddr)>,
        local_response: bool,
    ) -> Result<Self, SoakError> {
        if (!local_response && targets.is_empty())
            || targets.len() > 3
            || (local_response && !targets.is_empty())
        {
            return Err(fail(
                "Proxy requires 1..=3 peers; local response mode is explicit",
            ));
        }
        let tcp = TcpStream::connect(address).await.map_err(io_error)?;
        let name = rustls::pki_types::ServerName::try_from("gateway.example.test".to_owned())
            .map_err(io_error)?;
        let tls = TlsConnector::from(config)
            .connect(name, tcp)
            .await
            .map_err(io_error)?;
        let expected_alpn: &[u8] = if h2 { b"h2" } else { b"http/1.1" };
        if tls.get_ref().1.alpn_protocol() != Some(expected_alpn) {
            return Err(fail("resource client ALPN mismatch"));
        }
        let (sender, driver) = if h2 {
            let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(io_error)?;
            (
                ResourceSender::H2(sender),
                tokio::spawn(async move {
                    connection
                        .await
                        .map_err(|_| "http2_driver_error".to_owned())
                }),
            )
        } else {
            let (sender, connection) = http1::handshake(TokioIo::new(tls))
                .await
                .map_err(io_error)?;
            (
                ResourceSender::H1(sender),
                tokio::spawn(async move {
                    connection
                        .await
                        .map_err(|_| "http1_driver_error".to_owned())
                }),
            )
        };
        Ok(Self {
            sender: Some(sender),
            driver: Some(driver),
            h2,
            targets,
            local_response,
        })
    }

    pub(super) async fn close(self) -> Result<(), SoakError> {
        let receipt = self.close_receipt().await;
        if receipt["result"] == "completed"
            && receipt["join_acknowledged"] == true
            && receipt["exit_ns"].as_u64().is_some()
        {
            Ok(())
        } else {
            Err(fail(
                receipt["code"]
                    .as_str()
                    .unwrap_or("resource client driver close failed"),
            ))
        }
    }

    /// Tool-side connection cleanup facts are separate from an upstream logical
    /// request's deadline. An injected HTTP/1 body failure may correctly produce
    /// a driver error; callers retain that actual result in the same operation.
    pub(super) async fn close_receipt(mut self) -> Value {
        self.sender.take();
        let Some(mut driver) = self.driver.take() else {
            return json!({"result":"unavailable","code":"driver_unavailable","exit_ns":null,"join_acknowledged":false,"abort_requested":false});
        };
        let (result, code, join_acknowledged, abort_requested) =
            match tokio::time::timeout(Duration::from_secs(2), &mut driver).await {
                Ok(Ok(Ok(()))) => ("completed", None, true, false),
                Ok(Ok(Err(code))) => ("error", Some(code), true, false),
                Ok(Err(error)) => (
                    if error.is_cancelled() {
                        "cancelled"
                    } else {
                        "panicked"
                    },
                    Some("client_driver_join_error".to_owned()),
                    true,
                    false,
                ),
                Err(_) => {
                    driver.abort();
                    let acknowledged = tokio::time::timeout(Duration::from_secs(1), driver)
                        .await
                        .is_ok();
                    (
                        "timeout",
                        Some("client_driver_close_timeout".to_owned()),
                        acknowledged,
                        true,
                    )
                }
            };
        let exit_ns = if join_acknowledged {
            super::resource_identity::monotonic_ns().ok()
        } else {
            None
        };
        json!({"result":result,"code":code,"exit_ns":exit_ns,"join_acknowledged":join_acknowledged,"abort_requested":abort_requested})
    }

    async fn cancellation_receipt(&mut self, operation_id: &str) -> Result<Value, SoakError> {
        let path = "/__resource_cancel_ack";
        let request = Request::builder()
            .uri(if self.h2 {
                format!("https://gateway.example.test{path}")
            } else {
                path.to_owned()
            })
            .header(header::HOST, "gateway.example.test")
            .header("x-resource-operation-id", operation_id)
            .body(GeneratedUpload::new(false, 0))
            .map_err(io_error)?;
        let response = match self.sender.as_mut() {
            Some(ResourceSender::H1(sender)) => sender.send_request(request).await,
            Some(ResourceSender::H2(sender)) => sender.send_request(request).await,
            None => return Err(fail("fixture acknowledgement client closed")),
        }
        .map_err(io_error)?;
        if response.status() != http::StatusCode::OK {
            return Err(fail("fixture acknowledgement rejected"));
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(io_error)?;
            if let Some(data) = frame.data_ref() {
                if bytes
                    .len()
                    .checked_add(data.len())
                    .is_none_or(|size| size > 4096)
                {
                    return Err(fail("fixture acknowledgement exceeded bound"));
                }
                bytes.extend_from_slice(data);
            }
        }
        let receipt: Value = serde_json::from_slice(&bytes).map_err(json_error)?;
        if receipt["operation_id"].as_str() != Some(operation_id) {
            return Err(fail("fixture acknowledgement operation identity mismatch"));
        }
        receipt["body_dropped_after_data"]
            .as_bool()
            .ok_or_else(|| fail("fixture acknowledgement missing actual body drop fact"))?;
        Ok(receipt)
    }

    pub(super) async fn measure(&mut self, request: ResourceRequest) -> ResourceResponseFacts {
        let mut facts = ResourceResponseFacts::blank(
            request.operation_id.clone(),
            if self.h2 { "h2" } else { "http1" },
        );
        let mut digest = Sha256::new();
        match super::resource_identity::monotonic_ns() {
            Ok(now) => facts.started_ns = Some(now),
            Err(_) => {
                resource_error(&mut facts, "clock", "monotonic_unavailable");
            }
        }
        if facts.error_code.is_none() {
            let result = tokio::time::timeout(
                Duration::from_secs(15),
                self.measure_inner(&request, &mut facts, &mut digest),
            )
            .await;
            if result.is_err() {
                let stage = if facts.status.is_some() {
                    "response_body"
                } else {
                    "response_head"
                };
                resource_error(&mut facts, stage, "client_operation_timeout");
            }
        }
        facts.body_sha256 = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        match super::resource_identity::monotonic_ns() {
            Ok(now) => facts.ended_ns = Some(now),
            Err(_) => resource_error(&mut facts, "clock", "monotonic_unavailable"),
        }
        facts
    }

    async fn measure_inner(
        &mut self,
        request: &ResourceRequest,
        facts: &mut ResourceResponseFacts,
        digest: &mut Sha256,
    ) {
        if request.operation_id.len() > 128
            || request.payload_size == 0
            || request.payload_size > 16 * 1024 * 1024
            || request.upload_bytes > 16 * 1024 * 1024
            || !request.path.starts_with("/resource/")
        {
            resource_error(facts, "request", "request_parameters_invalid");
            return;
        }
        let mut builder = Request::builder()
            .uri(if self.h2 {
                format!("https://gateway.example.test{}", request.path)
            } else {
                request.path.clone()
            })
            .method(if request.grpc || request.upload_bytes > 0 {
                http::Method::POST
            } else {
                http::Method::GET
            })
            .header(header::HOST, "gateway.example.test")
            .header(
                header::CONTENT_TYPE,
                if request.grpc {
                    "application/grpc"
                } else {
                    "application/octet-stream"
                },
            )
            .header("x-resource-operation-id", &request.operation_id)
            .header("x-resource-upload-length", request.upload_bytes)
            .header("x-resource-response-length", request.payload_size);
        if request.grpc {
            builder = builder.header(header::TE, "trailers");
        }
        let built = builder.body(GeneratedUpload::new(request.grpc, request.upload_bytes));
        let Ok(built) = built else {
            resource_error(facts, "request", "request_headers_invalid");
            return;
        };
        let response = match self.sender.as_mut() {
            Some(ResourceSender::H1(sender)) => sender.send_request(built).await,
            Some(ResourceSender::H2(sender)) => sender.send_request(built).await,
            None => {
                resource_error(facts, "response_head", "client_closed");
                return;
            }
        };
        let Ok(response) = response else {
            resource_error(facts, "response_head", "transport_error");
            return;
        };
        facts.status = Some(response.status().as_u16());
        match super::resource_identity::monotonic_ns() {
            Ok(now) => facts.head_ns = Some(now),
            Err(_) => resource_error(facts, "clock", "monotonic_unavailable"),
        }
        let text = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        facts.content_type = text("content-type");
        facts.upstream_peer = text("x-fixture-peer");
        facts.upstream_name = text("x-fixture-upstream");
        facts.authority = text("x-fixture-authority");
        facts.server_name = text("x-fixture-sni");
        facts.path = text("x-fixture-path");
        facts.fault_case_id = text("x-resource-fault-case-id").and_then(|v| v.parse().ok());
        facts.upload.body_bytes = text("x-resource-upload-bytes").and_then(|v| v.parse().ok());
        facts.upload.body_sha256 = text("x-resource-upload-sha256");
        facts.upload.eof = text("x-resource-upload-eof").and_then(|v| match v.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        });
        facts.upload.fixture_ack = facts.upload.body_bytes.is_some()
            && facts.upload.body_sha256.is_some()
            && facts.upload.eof == Some(true);
        self.check_peer_metadata(facts, &request.path);
        let mut body = response.into_body();
        let cap = if facts.status == Some(200) && !self.local_response {
            (request.payload_size + if request.grpc { 5 } else { 0 }) as u64
        } else {
            64 * 1024
        };
        let mut trailers_seen = false;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                resource_error(facts, "response_body", "body_error");
                return;
            };
            if let Some(data) = frame.data_ref() {
                if trailers_seen {
                    resource_error(facts, "response_body", "data_after_trailers");
                    return;
                }
                let Some(received) = facts.body_bytes.checked_add(data.len() as u64) else {
                    resource_error(facts, "response_body", "body_limit_or_overflow");
                    return;
                };
                digest.update(data);
                facts.body_bytes = received;
                facts.data_observed |= !data.is_empty();
                if received > cap {
                    resource_error(facts, "response_body", "body_limit_or_overflow");
                    return;
                }
                if request.cancel_after_first_data && !data.is_empty() {
                    facts.cancelled = true;
                    drop(body);
                    return;
                }
            }
            if let Some(trailers) = frame.trailers_ref() {
                if trailers_seen {
                    resource_error(facts, "response_body", "duplicate_trailer_frame");
                    return;
                }
                trailers_seen = true;
                if trailers.len() > 16 {
                    resource_error(facts, "trailers", "trailer_limit");
                    return;
                }
                for (name, value) in trailers {
                    let Ok(value) = value.to_str() else {
                        resource_error(facts, "trailers", "trailer_value_invalid");
                        return;
                    };
                    if value.len() > 1024
                        || facts
                            .trailers
                            .insert(name.to_string(), value.to_owned())
                            .is_some()
                    {
                        resource_error(facts, "trailers", "duplicate_or_large_trailer");
                        return;
                    }
                }
            }
        }
        facts.eof = true;
    }

    fn check_peer_metadata(&self, facts: &mut ResourceResponseFacts, path: &str) {
        if facts.status == Some(200) && self.local_response {
            if facts.upstream_peer.is_some()
                || facts.upstream_name.is_some()
                || facts.authority.is_some()
                || facts.server_name.is_some()
                || facts.path.is_some()
            {
                facts
                    .diagnostics
                    .push("unexpected_upstream_metadata_for_local_response".into());
            }
        } else if facts.status == Some(200) {
            if !self.targets.iter().any(|(name, peer)| {
                facts.upstream_name.as_deref() == Some(name.as_str())
                    && facts.upstream_peer.as_deref() == Some(peer.to_string().as_str())
            }) {
                facts.diagnostics.push("physical_peer_mismatch".into());
            }
            if facts.authority.as_deref() != Some("gateway.example.test") {
                facts.diagnostics.push("authority_mismatch".into());
            }
            if facts.server_name.as_deref() != Some("gateway.example.test") {
                facts.diagnostics.push("sni_mismatch".into());
            }
            if facts.path.as_deref() != Some(format!("/base{path}").as_str()) {
                facts.diagnostics.push("path_mismatch".into());
            }
        }
    }
}

/// Return the fixture's parsed, operation-bound receipt, not an inferred status
/// or a client-side cancellation flag. Missing/evicted evidence is an error.
pub(super) async fn await_fixture_cancel_receipt(
    peer: SocketAddr,
    h1_config: Arc<rustls::ClientConfig>,
    operation_id: &str,
) -> Result<Value, SoakError> {
    if operation_id.is_empty() || operation_id.len() > 128 {
        return Err(fail("fixture acknowledgement operation identity invalid"));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    tokio::time::timeout_at(deadline, async {
        let mut client =
            ResourceDataClient::connect(peer, h1_config, false, vec![("ack".into(), peer)]).await?;
        loop {
            let receipt = client.cancellation_receipt(operation_id).await?;
            if receipt["body_dropped_after_data"] == true {
                client.close().await?;
                return Ok(receipt);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .map_err(|_| fail("fixture body drop acknowledgement deadline"))?
}

fn resource_error(facts: &mut ResourceResponseFacts, stage: &str, code: &str) {
    if facts.error_code.is_none() {
        facts.error_stage = Some(stage.to_owned());
        facts.error_code = Some(code.to_owned());
    }
}

fn resource_head_facts<B>(
    response: &http::Response<B>,
    operation_id: &str,
    protocol: &str,
    started_ns: Option<u64>,
) -> ResourceResponseFacts {
    let mut facts = ResourceResponseFacts::blank(operation_id.into(), protocol);
    facts.started_ns = started_ns;
    facts.head_ns = super::resource_identity::monotonic_ns().ok();
    facts.status = Some(response.status().as_u16());
    let value = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    facts.content_type = value("content-type");
    facts.upstream_peer = value("x-fixture-peer");
    facts.upstream_name = value("x-fixture-upstream");
    facts.authority = value("x-fixture-authority");
    facts.server_name = value("x-fixture-sni");
    facts.path = value("x-fixture-path");
    if facts.head_ns.is_none() {
        resource_error(&mut facts, "clock", "monotonic_unavailable");
    }
    facts
}

/// `eof` is an actual clean peer EOF, not an inference from half-close or
/// registry counts. An exact TLS UnexpectedEof after all verified echoes and
/// planned client shutdown is recorded separately; graceful TLS closure remains
/// unproven, while the later resource census can independently check reclamation.
pub(super) async fn measure_resource_upgrade(
    address: SocketAddr,
    h1_config: Arc<rustls::ClientConfig>,
    operation_id: String,
) -> ResourceResponseFacts {
    let mut facts = ResourceResponseFacts::blank(operation_id, "upgrade");
    let mut digest = Sha256::new();
    let mut stage = "connect";
    match super::resource_identity::monotonic_ns() {
        Ok(now) => facts.started_ns = Some(now),
        Err(_) => resource_error(&mut facts, "clock", "monotonic_unavailable"),
    }
    if facts.error_code.is_none() {
        match tokio::time::timeout(Duration::from_secs(5), async {
            let tcp = TcpStream::connect(address).await.map_err(io_error)?;
            stage = "tls";
            let name = rustls::pki_types::ServerName::try_from("gateway.example.test".to_owned()).map_err(io_error)?;
            let mut socket = TlsConnector::from(h1_config).connect(name, tcp).await.map_err(io_error)?;
            if socket.get_ref().1.alpn_protocol() != Some(b"http/1.1") { return Err(fail("Upgrade ALPN mismatch")); }
            stage = "response_head";
            socket.write_all(b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.map_err(io_error)?;
            facts.request_head_sent = true;
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let byte = socket.read_u8().await.map_err(io_error)?;
                head.push(byte);
                if head.len() > 16384 { return Err(fail("Upgrade head bound")); }
            }
            let text = std::str::from_utf8(&head).map_err(io_error)?;
            let mut lines = text.split("\r\n");
            let status = lines.next().and_then(|line| line.strip_prefix("HTTP/1.1 ")).and_then(|line| line.split_once(' ')).and_then(|(code,_)|code.parse::<u16>().ok()).ok_or_else(||fail("Upgrade status invalid"))?;
            facts.status = Some(status);
            facts.head_ns = Some(super::resource_identity::monotonic_ns()?);
            for line in lines.filter(|line|!line.is_empty()) {
                let (name,value) = line.split_once(':').ok_or_else(||fail("Upgrade header invalid"))?;
                let name = name.to_ascii_lowercase();
                if facts.upgrade_headers.len() >= 32 || facts.upgrade_headers.insert(name,value.trim().to_owned()).is_some() { return Err(fail("Upgrade header duplicate or limit")); }
            }
            facts.upstream_peer = facts.upgrade_headers.get("x-fixture-peer").cloned();
            facts.upstream_name = facts.upgrade_headers.get("x-fixture-upstream").cloned();
            facts.authority = facts.upgrade_headers.get("x-fixture-authority").cloned();
            facts.server_name = facts.upgrade_headers.get("x-fixture-sni").cloned();
            facts.path = facts.upgrade_headers.get("x-fixture-path").cloned();
            if status != 101 { return Ok::<(),SoakError>(()); }
            if !facts.upgrade_headers.get("upgrade").is_some_and(|value|value.eq_ignore_ascii_case("websocket"))
                || !facts.upgrade_headers.get("connection").is_some_and(|value|value.eq_ignore_ascii_case("upgrade"))
                || facts.upgrade_headers.get("sec-websocket-accept").map(String::as_str) != Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
                facts.diagnostics.push("upgrade_handshake_metadata_invalid".into());
                return Err(fail("Upgrade handshake metadata invalid"));
            }
            stage = "tunnel";
            for _ in 0..4 {
                let expected = b"qualification-tunnel";
                socket.write_all(expected).await.map_err(io_error)?;
                let mut seen = 0;
                let mut buffer = [0u8; 20];
                while seen < expected.len() {
                    let size = socket.read(&mut buffer[..expected.len()-seen]).await.map_err(io_error)?;
                    if size == 0 { return Err(fail("Upgrade echo truncated")); }
                    digest.update(&buffer[..size]); facts.body_bytes += size as u64; facts.data_observed = true;
                    if buffer[..size] != expected[seen..seen+size] { facts.diagnostics.push("upgrade_echo_content_mismatch".into()); return Err(fail("Upgrade echo content mismatch")); }
                    seen += size;
                }
                facts.echo_iterations += 1;
            }
            stage = "tunnel_close";
            observe_tunnel_close(&mut socket,&mut facts,4).await?;
            Ok(())
        }).await {
            Ok(Ok(())) => {},
            Ok(Err(_)) => resource_error(&mut facts, stage, "transport_or_protocol_error"),
            Err(_) => {
                if stage=="tunnel_close" {facts.tunnel_close_result=Some("timeout".into());}
                resource_error(&mut facts, stage, "client_operation_timeout");
            },
        }
    }
    facts.body_sha256 = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    match super::resource_identity::monotonic_ns() {
        Ok(now) => facts.ended_ns = Some(now),
        Err(_) => resource_error(&mut facts, "clock", "monotonic_unavailable"),
    }
    facts
}

/// The existing gateway cancels the opposite copy on first EOF. A peer TCP
/// close without TLS close-notify after the complete, explicitly closed echo
/// operation is recorded as that exact boundary, never as a clean TLS EOF.
async fn observe_tunnel_close<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut S,
    raw: &mut ResourceResponseFacts,
    expected_echoes: u8,
) -> Result<(), SoakError> {
    if raw.status != Some(101)
        || raw.echo_iterations != expected_echoes
        || raw.body_bytes != u64::from(expected_echoes) * 20
    {
        return Err(fail("tunnel close cannot precede complete echo exchange"));
    }
    if socket.shutdown().await.is_err() {
        raw.tunnel_close_result = Some("error".into());
        return Err(fail("tunnel client shutdown failed"));
    }
    raw.tunnel_client_shutdown = true;
    let mut tail = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(3), socket.read(&mut tail)).await {
        Ok(Ok(0)) => {
            raw.eof = true;
            raw.tunnel_close_result = Some("clean_eof".into());
            Ok(())
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            raw.eof = false;
            raw.tunnel_close_result = Some("peer_closed_without_close_notify".into());
            Ok(())
        }
        Ok(Ok(_)) | Ok(Err(_)) => {
            raw.tunnel_close_result = Some("error".into());
            Err(fail("tunnel close transport error or trailing data"))
        }
        Err(_) => {
            raw.tunnel_close_result = Some("timeout".into());
            Err(fail("tunnel peer close deadline"))
        }
    }
}

fn parse_listener(line: &str) -> Option<SocketAddr> {
    line.starts_with("listener qualification accepting ")
        .then_some(())?;
    line.rsplit_once(" on ")?.1.parse().ok()
}

pub(super) async fn command_json(
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

pub(super) fn ctl(root: &Path, operation: &[&str]) -> Vec<String> {
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

pub(super) async fn admin_read(root: &Path, path: &str) -> Result<Bytes, SoakError> {
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

pub(super) fn source(
    root: &Path,
    dns: SocketAddr,
    port: u16,
    campaign: Campaign,
    generation: u64,
) -> String {
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

pub(super) async fn bundle(
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
pub(super) struct DataClient {
    sender: Sender,
    driver: Option<tokio::task::JoinHandle<Result<(), String>>>,
    h2: bool,
    targets: [SocketAddr; 2],
    last_upstream: Option<&'static str>,
    payload_size: usize,
    capture_raw: bool,
    last_raw: Option<ResourceResponseFacts>,
    prelude: Option<Arc<Mutex<PreludeRecorder>>>,
}

/// Only the additive prelude uses this bounded scalar evidence journal. It has
/// no reference to a gateway resource, socket, body or future.
#[derive(Default)]
struct PreludeRecorder {
    operations: Vec<PreludeOperation>,
    violations: Vec<&'static str>,
}

#[derive(Serialize)]
struct PreludeOperation {
    operation_id: String,
    role: &'static str,
    terminal: Option<&'static str>,
    cause: Option<&'static str>,
    raw: ResourceResponseFacts,
    acknowledgement: Option<Value>,
}

struct PreludeGuard {
    recorder: Arc<Mutex<PreludeRecorder>>,
    index: usize,
    operation_id: String,
    started_ns: u64,
    finished: bool,
}

impl PreludeGuard {
    fn begin(
        recorder: &Arc<Mutex<PreludeRecorder>>,
        role: &'static str,
        protocol: &str,
    ) -> Result<Self, SoakError> {
        let started_ns = super::resource_identity::monotonic_ns()?;
        let mut journal = recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if journal.operations.len() >= 4096 {
            return Err(fail("prelude operation evidence capacity exhausted"));
        }
        let index = journal.operations.len();
        let operation_id = format!("prelude:{}", index + 1);
        let mut raw = ResourceResponseFacts::blank(operation_id.clone(), protocol);
        raw.started_ns = Some(started_ns);
        journal.operations.push(PreludeOperation {
            operation_id: operation_id.clone(),
            role,
            terminal: None,
            cause: None,
            raw,
            acknowledgement: None,
        });
        Ok(Self {
            recorder: Arc::clone(recorder),
            index,
            operation_id,
            started_ns,
            finished: false,
        })
    }

    fn update(&self, raw: &ResourceResponseFacts) -> Result<(), SoakError> {
        let mut journal = self
            .recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if raw.operation_id != self.operation_id
            || journal.operations[self.index].terminal.is_some()
        {
            journal
                .violations
                .push("duplicate_terminal_or_identity_mismatch");
            return Err(fail("prelude raw identity/terminal mismatch"));
        }
        journal.operations[self.index].raw = raw.clone();
        Ok(())
    }

    fn finish(
        &mut self,
        raw: &ResourceResponseFacts,
        terminal: &'static str,
        cause: &'static str,
    ) -> Result<(), SoakError> {
        self.update(raw)?;
        let mut journal = self
            .recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal.operations[self.index].terminal = Some(terminal);
        journal.operations[self.index].cause = Some(cause);
        self.finished = true;
        Ok(())
    }

    fn fail(&mut self, stage: &str, code: &str) -> Result<(), SoakError> {
        let mut raw = self
            .recorder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .operations[self.index]
            .raw
            .clone();
        resource_error(&mut raw, stage, code);
        raw.ended_ns = super::resource_identity::monotonic_ns().ok();
        self.finish(&raw, "failed", "operation_error")
    }
}

impl Drop for PreludeGuard {
    fn drop(&mut self) {
        if !self.finished {
            let mut journal = self
                .recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let operation = &mut journal.operations[self.index];
            resource_error(&mut operation.raw, "collection", "prelude_abandoned");
            operation.raw.ended_ns = super::resource_identity::monotonic_ns().ok();
            operation.terminal = Some("abandoned");
            operation.cause = Some("future_dropped_before_terminal");
        }
    }
}

impl PreludeRecorder {
    fn acknowledge_cancel(&mut self, operation_id: &str, receipt: Value) -> Result<(), SoakError> {
        let operation = self
            .operations
            .iter_mut()
            .find(|operation| operation.operation_id == operation_id && operation.role == "cancel")
            .ok_or_else(|| fail("prelude cancellation operation missing"))?;
        if operation.terminal != Some("cancelled_after_data")
            || receipt["operation_id"] != operation_id
            || receipt["body_dropped_after_data"] != true
            || receipt["body_bytes"]
                .as_u64()
                .is_none_or(|bytes| bytes < operation.raw.body_bytes || bytes == 0)
            || receipt["dropped_ns"].as_u64().is_none()
        {
            return Err(fail("prelude cancellation receipt invalid"));
        }
        if operation.acknowledgement.is_some() {
            self.violations.push("duplicate_cancel_ack");
            return Err(fail("prelude duplicate cancellation receipt"));
        }
        operation.raw.fixture_cancel_ack = true;
        operation.acknowledgement = Some(receipt);
        Ok(())
    }

    fn evidence(&self) -> Result<Value, SoakError> {
        let mut by_role = BTreeMap::<&str, Value>::new();
        for operation in &self.operations {
            let counts = by_role
                .entry(operation.role)
                .or_insert_with(|| json!({"offered":0,"classified":0,"abandoned":0}));
            for (name, increment) in [
                ("offered", true),
                ("classified", operation.terminal.is_some()),
                ("abandoned", operation.terminal == Some("abandoned")),
            ] {
                counts[name] =
                    json!(counts[name].as_u64().expect("fixed count") + u64::from(increment));
            }
        }
        Ok(
            json!({"prelude_counts":{"scope":"prelude_data_plane_and_connection_prepare","offered":self.operations.len(),"classified":self.operations.iter().filter(|op|op.terminal.is_some()).count(),"abandoned":self.operations.iter().filter(|op|op.terminal==Some("abandoned")).count(),"by_role":by_role,"violations":self.violations},"prelude_operations":serde_json::to_value(&self.operations).map_err(json_error)?}),
        )
    }
}
struct PayloadValidator {
    grpc: bool,
    length: usize,
    upstream: u8,
    seen: usize,
    digest: Option<Sha256>,
}
impl PayloadValidator {
    fn new(grpc: bool, length: usize, upstream: u8) -> Self {
        Self {
            grpc,
            length,
            upstream,
            seen: 0,
            digest: None,
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
        if let Some(digest) = &mut self.digest {
            digest.update(data);
        }
        Ok(())
    }
    fn finish(&self) -> Result<(), SoakError> {
        if self.seen != self.length + if self.grpc { 5 } else { 0 } {
            return Err(fail("opaque response DATA was truncated"));
        }
        Ok(())
    }

    fn capture(&mut self) {
        self.digest = Some(Sha256::new());
    }
    fn digest(&self) -> Option<String> {
        self.digest.as_ref().map(|digest| {
            digest
                .clone()
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        })
    }
}
struct HeldGrpc {
    body: hyper::body::Incoming,
    validator: PayloadValidator,
    raw: Option<ResourceResponseFacts>,
    prelude: Option<PreludeGuard>,
}

async fn capture_bounded_prelude_body<B: Body<Data = Bytes> + Unpin>(
    mut body: B,
    raw: &mut ResourceResponseFacts,
    prelude: Option<&PreludeGuard>,
) -> Result<u64, SoakError> {
    let mut digest = Sha256::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| fail("prelude rejection body error"))?;
        if let Some(data) = frame.data_ref() {
            raw.body_bytes = raw
                .body_bytes
                .checked_add(data.len() as u64)
                .ok_or_else(|| fail("prelude rejection byte count overflow"))?;
            digest.update(data);
            raw.data_observed |= !data.is_empty();
            raw.body_sha256 = digest
                .clone()
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if let Some(guard) = prelude {
                guard.update(raw)?;
            }
            if raw.body_bytes > 64 * 1024 {
                return Err(fail("prelude rejection body exceeds bound"));
            }
        }
        if let Some(trailers) = frame.trailers_ref() {
            if trailers.len() > 16 {
                return Err(fail("prelude rejection trailers exceed bound"));
            }
            for (name, value) in trailers {
                let value = value.to_str().map_err(io_error)?;
                if value.len() > 1024
                    || raw
                        .trailers
                        .insert(name.to_string(), value.to_owned())
                        .is_some()
                {
                    return Err(fail("prelude rejection trailer value/duplicate"));
                }
            }
        }
        if let Some(guard) = prelude {
            guard.update(raw)?;
        }
    }
    raw.body_sha256 = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    raw.eof = true;
    raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
    Ok(raw.body_bytes)
}
impl Drop for DataClient {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}
impl DataClient {
    pub(super) async fn connect(
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
                driver: Some(tokio::spawn(async move {
                    connection
                        .await
                        .map_err(|_| "retained_http2_driver_error".into())
                })),
                h2,
                targets,
                last_upstream: None,
                payload_size,
                capture_raw: false,
                last_raw: None,
                prelude: None,
            })
        } else {
            let (sender, connection) = http1::handshake(TokioIo::new(tls))
                .await
                .map_err(io_error)?;
            Ok(Self {
                sender: Sender::H1(sender),
                driver: Some(tokio::spawn(async move {
                    connection
                        .await
                        .map_err(|_| "retained_http1_driver_error".into())
                })),
                h2,
                targets,
                last_upstream: None,
                payload_size,
                capture_raw: false,
                last_raw: None,
                prelude: None,
            })
        }
    }
    /// Capture-only cleanup acknowledges actual driver exit. Legacy callers
    /// retain their original drop-abort behavior and schema.
    async fn close_captured(mut self) -> Result<(), SoakError> {
        let mut driver = self
            .driver
            .take()
            .ok_or_else(|| fail("retained driver missing"))?;
        driver.abort();
        match tokio::time::timeout(Duration::from_secs(3), &mut driver).await {
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(code))) => Err(fail(code)),
            Ok(Err(_)) => Err(fail("retained driver panicked")),
            Err(_) => Err(fail(
                "retained driver cancellation acknowledgement deadline",
            )),
        }
    }
    pub(super) async fn request(
        &mut self,
        grpc: bool,
        cancel: bool,
        expected_upstream: Option<&str>,
    ) -> Result<(u16, u64, bool), SoakError> {
        let mut prelude = self
            .prelude
            .as_ref()
            .map(|recorder| {
                PreludeGuard::begin(
                    recorder,
                    if cancel { "cancel" } else { "probe" },
                    if self.h2 { "h2" } else { "http1" },
                )
            })
            .transpose()?;
        self.last_raw = None;
        let result = if self.capture_raw {
            match tokio::time::timeout(
                Duration::from_secs(8),
                self.request_inner(grpc, cancel, expected_upstream, prelude.as_ref()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    if let Some(guard) = &mut prelude {
                        guard.fail("request", "prelude_deadline")?;
                    }
                    return Err(fail("bounded prelude request deadline"));
                }
            }
        } else {
            self.request_inner(grpc, cancel, expected_upstream, None)
                .await
        };
        if let Some(guard) = &mut prelude {
            if result.is_ok() {
                let raw = self
                    .last_raw
                    .as_ref()
                    .ok_or_else(|| fail("prelude complete request raw missing"))?;
                guard.finish(
                    raw,
                    if raw.cancelled {
                        "cancelled_after_data"
                    } else {
                        "response_complete"
                    },
                    if raw.cancelled {
                        "explicit_cancel"
                    } else {
                        "response_eof"
                    },
                )?;
            } else {
                guard.fail("request", "prelude_operation_error")?;
            }
        }
        result
    }

    async fn request_inner(
        &mut self,
        grpc: bool,
        cancel: bool,
        expected_upstream: Option<&str>,
        prelude: Option<&PreludeGuard>,
    ) -> Result<(u16, u64, bool), SoakError> {
        let started = if let Some(guard) = prelude {
            Some(guard.started_ns)
        } else if self.capture_raw {
            Some(super::resource_identity::monotonic_ns()?)
        } else {
            None
        };
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
        if let Some(guard) = prelude {
            builder = builder.header("x-resource-operation-id", &guard.operation_id);
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
        let mut raw = self.capture_raw.then(|| {
            resource_head_facts(
                &response,
                prelude.map_or("retained:request", |guard| guard.operation_id.as_str()),
                if self.h2 { "h2" } else { "http1" },
                started,
            )
        });
        if let (Some(guard), Some(raw)) = (prelude, raw.as_ref()) {
            guard.update(raw)?;
        }
        if status != 200 {
            if let Some(raw) = &mut raw {
                let bytes =
                    capture_bounded_prelude_body(response.into_body(), raw, prelude).await?;
                self.last_raw = Some(raw.clone());
                return Ok((status, bytes, false));
            }
            self.last_raw = raw;
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
        if self.capture_raw {
            validator.capture();
        }
        let mut trailer = false;
        let mut observed_digest = self.capture_raw.then(Sha256::new);
        let mut body = response.into_body();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(io_error)?;
            if let Some(data) = frame.data_ref() {
                if let (Some(raw), Some(digest)) = (&mut raw, &mut observed_digest) {
                    digest.update(data);
                    raw.body_bytes = raw
                        .body_bytes
                        .checked_add(data.len() as u64)
                        .ok_or_else(|| fail("prelude byte count overflow"))?;
                    raw.data_observed |= !data.is_empty();
                    raw.body_sha256 = digest
                        .clone()
                        .finalize()
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    if let Some(guard) = prelude {
                        guard.update(raw)?;
                    }
                }
                validator.push(data)?;
                bytes = bytes.saturating_add(data.len() as u64);
                if cancel {
                    drop(body);
                    if let Some(raw) = &mut raw {
                        raw.body_bytes = bytes;
                        raw.body_sha256 = validator.digest().expect("capture enabled");
                        raw.data_observed = bytes > 0;
                        raw.cancelled = true;
                        raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
                    }
                    self.last_raw = raw;
                    return Ok((status, bytes, true));
                }
            }
            if let Some(trailers) = frame.trailers_ref() {
                if let Some(raw) = &mut raw {
                    for (name, value) in trailers {
                        raw.trailers.insert(
                            name.to_string(),
                            value.to_str().map_err(io_error)?.to_owned(),
                        );
                    }
                    if let Some(guard) = prelude {
                        guard.update(raw)?;
                    }
                }
                trailer = trailers.get("grpc-status").is_some_and(|v| v == "0")
                    && trailers.get("grpc-message").is_some_and(|v| v == "ok");
            }
        }
        if grpc && !trailer {
            return Err(fail("gRPC status trailer missing"));
        }
        validator.finish()?;
        if let Some(raw) = &mut raw {
            raw.body_bytes = bytes;
            raw.body_sha256 = validator.digest().expect("capture enabled");
            raw.data_observed = bytes > 0;
            raw.eof = true;
            raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
        }
        self.last_raw = raw;
        Ok((status, bytes, false))
    }

    async fn hold_grpc(&mut self) -> Result<Option<HeldGrpc>, SoakError> {
        let mut prelude = self
            .prelude
            .as_ref()
            .map(|recorder| PreludeGuard::begin(recorder, "held", "h2"))
            .transpose()?;
        self.last_raw = None;
        let result = if self.capture_raw {
            match tokio::time::timeout(
                Duration::from_secs(8),
                self.hold_grpc_inner(prelude.as_ref()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    if let Some(guard) = &mut prelude {
                        guard.fail("request", "prelude_deadline")?;
                    }
                    return Err(fail("bounded initial held prelude deadline"));
                }
            }
        } else {
            self.hold_grpc_inner(None).await
        };
        match result {
            Ok(Some(mut held)) => {
                held.prelude = prelude;
                Ok(Some(held))
            }
            Ok(None) => {
                if let Some(guard) = &mut prelude {
                    guard.finish(
                        self.last_raw
                            .as_ref()
                            .ok_or_else(|| fail("held rejection raw missing"))?,
                        "response_complete",
                        "response_eof",
                    )?;
                }
                Ok(None)
            }
            Err(error) => {
                if let Some(guard) = &mut prelude {
                    guard.fail("request", "prelude_operation_error")?;
                }
                Err(error)
            }
        }
    }

    async fn hold_grpc_inner(
        &mut self,
        prelude: Option<&PreludeGuard>,
    ) -> Result<Option<HeldGrpc>, SoakError> {
        let started = if let Some(guard) = prelude {
            Some(guard.started_ns)
        } else if self.capture_raw {
            Some(super::resource_identity::monotonic_ns()?)
        } else {
            None
        };
        let Sender::H2(sender) = &mut self.sender else {
            return Err(fail("held gRPC proof requires negotiated H2"));
        };
        let mut builder = Request::builder()
            .method(http::Method::POST)
            .uri("https://gateway.example.test/hold?b=2&a=1&a=3")
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers");
        if let Some(guard) = prelude {
            builder = builder.header("x-resource-operation-id", &guard.operation_id);
        }
        let request = builder
            .body(Full::new(Bytes::from_static(&[0, 0, 0, 0, 2, b'h', b'i'])))
            .map_err(io_error)?;
        let response = sender.send_request(request).await.map_err(io_error)?;
        let mut raw = self.capture_raw.then(|| {
            resource_head_facts(
                &response,
                prelude.map_or("retained:held-grpc", |guard| guard.operation_id.as_str()),
                "h2",
                started,
            )
        });
        if let (Some(guard), Some(raw)) = (prelude, raw.as_ref()) {
            guard.update(raw)?;
        }
        if response.status() != http::StatusCode::OK && self.capture_raw {
            let status = response.status();
            capture_bounded_prelude_body(
                response.into_body(),
                raw.as_mut().expect("capture enabled"),
                prelude,
            )
            .await?;
            self.last_raw = raw;
            return if status == http::StatusCode::SERVICE_UNAVAILABLE {
                Ok(None)
            } else {
                Err(fail("initial held response unexpectedly rejected"))
            };
        }
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
        if self.capture_raw {
            validator.capture();
        }
        validator.push(first.data_ref().expect("validated first DATA"))?;
        if let Some(raw) = &mut raw {
            raw.body_bytes = validator.seen as u64;
            raw.body_sha256 = validator.digest().expect("capture enabled");
            raw.data_observed = raw.body_bytes > 0;
            if let Some(guard) = prelude {
                guard.update(raw)?;
            }
        }
        Ok(Some(HeldGrpc {
            body,
            validator,
            raw,
            prelude: None,
        }))
    }
}

async fn open_upgrade(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> Result<Option<tokio_rustls::client::TlsStream<TcpStream>>, SoakError> {
    open_upgrade_capture(address, config, false, None)
        .await
        .map(|value| value.0)
}

async fn open_upgrade_capture(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
    capture: bool,
    prelude: Option<&PreludeGuard>,
) -> Result<
    (
        Option<tokio_rustls::client::TlsStream<TcpStream>>,
        Option<ResourceResponseFacts>,
    ),
    SoakError,
> {
    let started = if let Some(guard) = prelude {
        Some(guard.started_ns)
    } else if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    let socket = TcpStream::connect(address).await.map_err(io_error)?;
    let name = rustls::pki_types::ServerName::try_from("gateway.example.test".to_owned())
        .map_err(io_error)?;
    let mut socket = TlsConnector::from(config)
        .connect(name, socket)
        .await
        .map_err(io_error)?;
    socket.write_all(b"GET /ws HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.map_err(io_error)?;
    if let Some(guard) = prelude {
        let mut raw = ResourceResponseFacts::blank(guard.operation_id.clone(), "upgrade");
        raw.started_ns = Some(guard.started_ns);
        raw.request_head_sent = true;
        guard.update(&raw)?;
    }
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = socket.read_u8().await.map_err(io_error)?;
        head.push(byte);
        if head.len() > 16384 {
            return Err(fail("Upgrade header limit"));
        }
    }
    if !capture && head.starts_with(b"HTTP/1.1 503") {
        return Ok((None, None));
    }
    if !capture && !head.starts_with(b"HTTP/1.1 101") {
        return Err(fail("trusted Proxy Upgrade handshake failed"));
    }
    let mut raw = if capture {
        let mut facts = ResourceResponseFacts::blank(
            prelude
                .map_or("retained:upgrade", |guard| guard.operation_id.as_str())
                .into(),
            "upgrade",
        );
        facts.started_ns = started;
        facts.head_ns = Some(super::resource_identity::monotonic_ns()?);
        facts.request_head_sent = true;
        let text = std::str::from_utf8(&head).map_err(io_error)?;
        facts.status = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("HTTP/1.1 "))
            .and_then(|line| line.split_once(' '))
            .and_then(|(code, _)| code.parse().ok());
        if facts.status.is_none() {
            return Err(fail("captured Upgrade status invalid"));
        }
        for line in text.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| fail("captured Upgrade header invalid"))?;
            if facts
                .upgrade_headers
                .insert(name.to_ascii_lowercase(), value.trim().to_owned())
                .is_some()
            {
                return Err(fail("captured Upgrade header duplicated"));
            }
        }
        facts.upstream_peer = facts.upgrade_headers.get("x-fixture-peer").cloned();
        facts.upstream_name = facts.upgrade_headers.get("x-fixture-upstream").cloned();
        facts.authority = facts.upgrade_headers.get("x-fixture-authority").cloned();
        facts.server_name = facts.upgrade_headers.get("x-fixture-sni").cloned();
        facts.path = facts.upgrade_headers.get("x-fixture-path").cloned();
        if let Some(guard) = prelude {
            guard.update(&facts)?;
        }
        Some(facts)
    } else {
        None
    };
    if let Some(raw) = &mut raw
        && raw.status != Some(101)
    {
        let length = raw
            .upgrade_headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value <= 64 * 1024)
            .ok_or_else(|| fail("captured Upgrade rejection framing unavailable"))?;
        if raw.upgrade_headers.contains_key("transfer-encoding") {
            return Err(fail("captured Upgrade rejection ambiguous framing"));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 1024];
        while raw.body_bytes < (length as u64) {
            let size = socket
                .read(&mut buffer[..(length - raw.body_bytes as usize).min(1024)])
                .await
                .map_err(io_error)?;
            if size == 0 {
                return Err(fail("captured Upgrade rejection truncated"));
            }
            digest.update(&buffer[..size]);
            raw.body_bytes += size as u64;
            raw.data_observed = true;
            raw.body_sha256 = digest
                .clone()
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if let Some(guard) = prelude {
                guard.update(raw)?;
            }
        }
        raw.body_sha256 = digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        raw.eof = true;
        raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
        if let Some(guard) = prelude {
            guard.update(raw)?;
        }
        return Ok((None, Some(raw.clone())));
    }
    Ok((Some(socket), raw))
}

async fn echo_upgrade(
    socket: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(), SoakError> {
    echo_upgrade_capture(socket, None, None, None).await
}

fn retained_upgrade_uses_fixture_a(raw: &ResourceResponseFacts, fixture_a: SocketAddr) -> bool {
    raw.status == Some(101)
        && raw.request_head_sent
        && raw.upstream_name.as_deref() == Some("a")
        && raw.upstream_peer.as_deref() == Some(fixture_a.to_string().as_str())
        && raw.authority.as_deref() == Some("gateway.example.test")
        && raw.server_name.as_deref() == Some("gateway.example.test")
        && raw.path.as_deref() == Some("/base/ws")
}

/// This additional qualification precondition never substitutes the requested
/// endpoint for the actual response metadata. A wrong peer remains a failed,
/// fully journalled operation, not a hidden retry or proof of an old A lease.
async fn verify_captured_retained_upgrade(
    socket: &mut tokio_rustls::client::TlsStream<TcpStream>,
    raw: &mut ResourceResponseFacts,
    prelude: Option<&mut PreludeGuard>,
    fixture_a: SocketAddr,
) -> Result<(), SoakError> {
    if retained_upgrade_uses_fixture_a(raw, fixture_a) {
        return Ok(());
    }
    resource_error(raw, "response_head", "retained_upgrade_identity_mismatch");
    raw.tunnel_client_shutdown = matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.shutdown()).await,
        Ok(Ok(()))
    );
    if !raw.tunnel_client_shutdown {
        raw.diagnostics
            .push("retained_upgrade_rejection_shutdown_failed".into());
    }
    // shutdown is an action, not an observed peer EOF or complete echo exchange.
    raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
    if let Some(guard) = prelude {
        guard.finish(raw, "failed", "identity_mismatch")?;
    }
    Err(fail("captured old Upgrade did not use actual fixture A"))
}

async fn echo_upgrade_capture(
    socket: &mut tokio_rustls::client::TlsStream<TcpStream>,
    mut raw: Option<&mut ResourceResponseFacts>,
    mut digest: Option<&mut Sha256>,
    prelude: Option<&PreludeGuard>,
) -> Result<(), SoakError> {
    for _ in 0..4 {
        let bytes = b"qualification-tunnel";
        socket.write_all(bytes).await.map_err(io_error)?;
        let mut echoed = vec![0; bytes.len()];
        if raw.is_some() {
            let mut received = 0;
            while received < echoed.len() {
                let size = socket
                    .read(&mut echoed[received..])
                    .await
                    .map_err(io_error)?;
                if size == 0 {
                    return Err(fail("captured Upgrade echo truncated"));
                }
                if let Some(digest) = digest.as_deref_mut() {
                    digest.update(&echoed[received..received + size]);
                }
                if let Some(raw) = raw.as_deref_mut() {
                    raw.body_bytes += size as u64;
                    raw.data_observed = true;
                    if let Some(digest) = digest.as_deref() {
                        raw.body_sha256 = digest
                            .clone()
                            .finalize()
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                    }
                    if let Some(guard) = prelude {
                        guard.update(raw)?;
                    }
                }
                received += size;
            }
        } else {
            socket.read_exact(&mut echoed).await.map_err(io_error)?;
        }
        if echoed != bytes {
            return Err(fail("Upgrade bidirectional byte mismatch"));
        }
        if let Some(raw) = raw.as_mut() {
            raw.echo_iterations += 1;
            if let Some(guard) = prelude {
                guard.update(raw)?;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

pub(super) async fn websocket(
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

async fn send_completed_worker_event(
    events: &tokio::sync::mpsc::Sender<WorkerEvent>,
    event: WorkerEvent,
) -> Result<(), SoakError> {
    tokio::time::timeout(Duration::from_secs(30), events.send(event))
        .await
        .map_err(|_| fail("completed worker result delivery timed out"))?
        .map_err(|_| fail("completed worker result receiver closed"))
}

async fn collect_finished_workers(
    workers: &mut tokio::task::JoinSet<Result<(), SoakError>>,
    events: &mut tokio::sync::mpsc::Receiver<WorkerEvent>,
    mut record: impl FnMut(WorkerEvent),
) -> Result<(), SoakError> {
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    let mut events_closed = false;
    while !workers.is_empty() || !events_closed {
        tokio::select! {
            _ = &mut deadline => return Err(fail("load workers/result collector required forced termination")),
            event = events.recv(), if !events_closed => match event {
                Some(event) => record(event),
                None => events_closed = true,
            },
            joined = workers.join_next(), if !workers.is_empty() => {
                joined.expect("nonempty worker set").map_err(|error|fail(format!("load worker failed: {error}")))??;
            }
        }
    }
    Ok(())
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

pub(super) struct RetainedProofPlan<'a> {
    pub(super) gateway: &'a Path,
    pub(super) gateway_address: SocketAddr,
    pub(super) root: &'a Path,
    pub(super) results: &'a Path,
    pub(super) a: &'a str,
    pub(super) b: &'a str,
    pub(super) h1: Arc<rustls::ClientConfig>,
    pub(super) h2: Arc<rustls::ClientConfig>,
    pub(super) payload_size: usize,
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

pub(super) async fn retained_stream_proof(
    plan: RetainedProofPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    sequence: &mut u64,
) -> Result<Value, SoakError> {
    retained_stream_proof_inner(plan, dns, upstream, sequence, false, None).await
}

pub(super) async fn resource_retained_stream_proof(
    plan: RetainedProofPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    sequence: &mut u64,
) -> Result<Value, SoakError> {
    let results = plan.results.to_owned();
    let recorder = Arc::new(Mutex::new(PreludeRecorder::default()));
    let result = retained_stream_proof_inner(
        plan,
        dns,
        upstream,
        sequence,
        true,
        Some(Arc::clone(&recorder)),
    )
    .await;
    // Preserve all issued operations even when the proof aborts on a body,
    // metadata, control or collection failure. This is raw evidence, not a PASS.
    let evidence = recorder
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .evidence()?;
    let bytes=serde_json::to_vec(&json!({"schema_version":"oxidase.resource-prelude/v1","result":if result.is_ok(){"collected"}else{"failed"},"evidence":evidence})).map_err(json_error)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(fail("prelude artifact capacity exhausted"));
    }
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(results.join("prelude-operations.json"))
            .map_err(io_error)?;
        file.write_all(&bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
    }
    let mut result = result?;
    result["prelude_counts"] = evidence["prelude_counts"].clone();
    result["prelude_operations"] = evidence["prelude_operations"].clone();
    if evidence["prelude_counts"]["abandoned"] != 0
        || evidence["prelude_counts"]["violations"]
            .as_array()
            .is_none_or(|violations| !violations.is_empty())
    {
        return Err(fail("prelude has missing/duplicate terminal evidence"));
    }
    Ok(result)
}

async fn retained_stream_proof_inner(
    plan: RetainedProofPlan<'_>,
    dns: &mut FixtureProcess,
    upstream: &mut FixtureProcess,
    sequence: &mut u64,
    capture: bool,
    recorder: Option<Arc<Mutex<PreludeRecorder>>>,
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
    let mut prepare = recorder
        .as_ref()
        .map(|journal| PreludeGuard::begin(journal, "control", "h2"))
        .transpose()?;
    let connected = if capture {
        match tokio::time::timeout(
            Duration::from_secs(5),
            DataClient::connect(gateway_address, h2, true, targets, payload_size),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(fail("bounded prelude connection deadline")),
        }
    } else {
        DataClient::connect(gateway_address, h2, true, targets, payload_size).await
    };
    if let Some(guard) = &mut prepare {
        if connected.is_ok() {
            let mut raw = ResourceResponseFacts::blank(guard.operation_id.clone(), "h2");
            raw.started_ns = Some(guard.started_ns);
            raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
            guard.finish(&raw, "prepared", "connection_ready")?;
        } else {
            guard.fail("connection", "prelude_connection_failure")?;
        }
    }
    let mut client = connected?;
    client.capture_raw = capture;
    client.prelude = recorder.clone();
    let initialization_start_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut held = loop {
        let response = client.hold_grpc().await?;
        if capture && Instant::now() > deadline {
            return Err(fail(
                "initial held operation exceeded declared initialization window",
            ));
        }
        if let Some(body) = response {
            break body;
        }
        if Instant::now() >= deadline {
            return Err(fail("initial discovery failed to become available"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let initialization_end_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    let mut upgrade_operation = recorder
        .as_ref()
        .map(|journal| PreludeGuard::begin(journal, "upgrade", "upgrade"))
        .transpose()?;
    let opened = if capture {
        match tokio::time::timeout(
            Duration::from_secs(8),
            open_upgrade_capture(
                gateway_address,
                Arc::clone(&h1),
                capture,
                upgrade_operation.as_ref(),
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                if let Some(guard) = &mut upgrade_operation {
                    guard.fail("upgrade", "prelude_deadline")?;
                }
                return Err(fail("bounded prelude Upgrade deadline"));
            }
        }
    } else {
        open_upgrade_capture(gateway_address, Arc::clone(&h1), capture, None).await
    };
    let (tunnel, mut upgrade_raw) = match opened {
        Ok(value) => value,
        Err(error) => {
            if let Some(guard) = &mut upgrade_operation {
                guard.fail("upgrade", "prelude_operation_error")?;
            }
            return Err(error);
        }
    };
    if let (Some(guard), Some(raw)) = (&upgrade_operation, &mut upgrade_raw) {
        raw.operation_id = guard.operation_id.clone();
        raw.started_ns = Some(guard.started_ns);
        guard.update(raw)?;
    }
    let mut tunnel = match tunnel {
        Some(tunnel) => tunnel,
        None => {
            if let (Some(guard), Some(raw)) = (&mut upgrade_operation, upgrade_raw.as_ref()) {
                guard.finish(raw, "response_complete", "response_eof")?;
            }
            return Err(fail("initial Upgrade fixture unavailable"));
        }
    };
    if capture {
        verify_captured_retained_upgrade(
            &mut tunnel,
            upgrade_raw
                .as_mut()
                .ok_or_else(|| fail("captured retained Upgrade raw head missing"))?,
            upgrade_operation.as_mut(),
            targets[0],
        )
        .await?;
    }
    let mut upgrade_digest = Sha256::new();
    echo_upgrade_capture(
        &mut tunnel,
        upgrade_raw.as_mut(),
        capture.then_some(&mut upgrade_digest),
        upgrade_operation.as_ref(),
    )
    .await?;
    if let (Some(guard), Some(raw)) = (&upgrade_operation, &mut upgrade_raw) {
        raw.body_sha256 = upgrade_digest
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        guard.update(raw)?;
    }
    let before: Value =
        serde_json::from_slice(&admin_read(root, "/api/v1/runtime").await?).map_err(json_error)?;
    let withdrawal_start_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
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
        if capture && Instant::now() > deadline {
            return Err(fail(
                "DNS withdrawal probe exceeded declared availability window",
            ));
        }
        if status == 200 && client.last_upstream == Some("b") {
            break;
        }
        if Instant::now() >= deadline {
            return Err(fail("DNS withdrawal failed to move new streams to B"));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let withdrawal_end_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    let mut successful_new_b_streams = 0;
    let mut new_b_streams_raw = Vec::new();
    for _ in 0..8 {
        // request() has already checked the actual B socket, fixed SNI,
        // authority, path, every opaque gRPC byte and the final trailers. A
        // non-200 response skips those checks, so it cannot count as proof.
        let response = client.request(true, false, Some("b")).await?;
        validate_completed_new_b_stream(response, payload_size)?;
        if capture {
            let raw = client
                .last_raw
                .clone()
                .ok_or_else(|| fail("new B raw response missing"))?;
            new_b_streams_raw.push(raw);
        }
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
    let cancelled_operation = client.last_raw.as_ref().map(|raw| raw.operation_id.clone());
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
    if let Some(journal) = &recorder {
        let operation_id = cancelled_operation
            .as_deref()
            .ok_or_else(|| fail("prelude cancellation raw missing"))?;
        let ack = await_fixture_cancel_receipt(targets[1], Arc::clone(&h1), operation_id).await?;
        journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .acknowledge_cancel(operation_id, ack)?;
    }
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
    let publication_before_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    command_json(gateway, &activate, results, sequence).await?;
    let publication_after_ns = if capture {
        Some(super::resource_identity::monotonic_ns()?)
    } else {
        None
    };
    echo_upgrade_capture(
        &mut tunnel,
        upgrade_raw.as_mut(),
        capture.then_some(&mut upgrade_digest),
        upgrade_operation.as_ref(),
    )
    .await?;
    if let (Some(guard), Some(raw)) = (&upgrade_operation, &mut upgrade_raw) {
        raw.body_sha256 = upgrade_digest
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        guard.update(raw)?;
    }
    if let Some(raw) = &mut upgrade_raw {
        raw.body_sha256 = upgrade_digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if let Err(error) = observe_tunnel_close(&mut tunnel, raw, 8).await {
            if let Some(guard) = &mut upgrade_operation {
                guard.update(raw)?;
                guard.fail("tunnel_close", "prelude_tunnel_close_error")?;
            }
            return Err(error);
        }
        raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
        if let Some(guard) = &mut upgrade_operation {
            guard.finish(
                raw,
                if raw.eof {
                    "response_complete"
                } else {
                    "tunnel_cancelled"
                },
                if raw.eof {
                    "peer_eof"
                } else {
                    "planned_client_close_peer_abort"
                },
            )?;
        }
    } else {
        tunnel.shutdown().await.map_err(io_error)?;
    }
    upstream.command(FixtureCommand::Release).await?;
    let mut status_trailer = false;
    while let Some(frame) = held.body.frame().await {
        let frame = frame.map_err(io_error)?;
        if let Some(data) = frame.data_ref() {
            held.validator.push(data)?;
            if let Some(raw) = &mut held.raw {
                raw.body_bytes = held.validator.seen as u64;
                raw.body_sha256 = held.validator.digest().expect("captured held validator");
                if let Some(guard) = &held.prelude {
                    guard.update(raw)?;
                }
            }
        }
        if let Some(trailers) = frame.trailers_ref() {
            if let Some(raw) = &mut held.raw {
                for (name, value) in trailers {
                    raw.trailers.insert(
                        name.to_string(),
                        value.to_str().map_err(io_error)?.to_owned(),
                    );
                }
                if let Some(guard) = &held.prelude {
                    guard.update(raw)?;
                }
            }
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
    if let Some(raw) = &mut held.raw {
        raw.body_bytes = held.validator.seen as u64;
        raw.body_sha256 = held.validator.digest().expect("captured held validator");
        raw.data_observed = raw.body_bytes > 0;
        raw.eof = true;
        raw.ended_ns = Some(super::resource_identity::monotonic_ns()?);
        if let Some(guard) = &mut held.prelude {
            guard.finish(raw, "response_complete", "response_eof")?;
        }
    }
    if upstream.command(FixtureCommand::Status).await?["body_drops"] != normal_drops + 1 {
        return Err(fail(
            "released completed gRPC stream was falsely counted as cancelled",
        ));
    }
    if capture {
        client.close_captured().await?;
    } else {
        drop(client);
    }
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
    let mut result = json!({"held_h2_grpc_completed":true,"grpc_status_trailer":true,"opaque_grpc_bytes_verified":true,"gateway_cancelled_termination_delta":cancelled_delta,"fixture_unreleased_body_drop_delta":1,"upgrade_across_withdrawal_and_publication":true,"successful_new_b_streams":successful_new_b_streams,"withdrawn_endpoint_new_streams":0,"unchanged_dns_runtime":before,"after_dns":after_dns,"after_activate":after_activate});
    if capture {
        result["new_b_streams_raw"] =
            serde_json::to_value(new_b_streams_raw).map_err(json_error)?;
        result["held_grpc_raw"] = serde_json::to_value(held.raw).map_err(json_error)?;
        result["upgrade_raw"] = serde_json::to_value(upgrade_raw).map_err(json_error)?;
        result["publication_window"] =
            json!({"before_ns":publication_before_ns,"after_ns":publication_after_ns});
        result["initialization_window"] = json!({"start_ns":initialization_start_ns,"end_ns":initialization_end_ns,"deadline_ns":initialization_start_ns.map(|start|start+8_000_000_000),"roles":["held"],"allowed_statuses":[503]});
        result["withdrawal_window"] = json!({"start_ns":withdrawal_start_ns,"end_ns":withdrawal_end_ns,"deadline_ns":withdrawal_start_ns.map(|start|start+10_000_000_000),"roles":["probe"],"allowed_statuses":[503]});
    }
    Ok(result)
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
    let (events, mut received) = tokio::sync::mpsc::channel::<WorkerEvent>(256);
    let started_operations = Arc::new(AtomicU64::new(0));
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
        let started = Arc::clone(&started_operations);
        workers.spawn(async move {
            let mut random=XorShift64::new(seed);let mut client=None;let mut operations=0u64;
            // Keep one negotiated protocol per worker. Switching on every
            // operation creates artificial TIME_WAIT/ephemeral-port churn.
            let use_h2=worker%4!=0;
            loop {
                if *stop.borrow(){break;}
                let cancel=random.next().is_multiple_of(17);let is_grpc=matches!(campaign,Campaign::Protocol);
                if client.is_none()||operations.is_multiple_of(128){client=tokio::select!{_=stop.changed()=>break,connection=tokio::time::timeout(Duration::from_secs(5),DataClient::connect(address,if use_h2{Arc::clone(&h2)}else{Arc::clone(&h1)},use_h2,targets,payload_size))=>connection.ok().and_then(Result::ok)};}
                // Connection preparation is not an admitted HTTP operation.
                // Once admitted, stop cannot discard either its work or result.
                if *stop.borrow(){break;}
                started.fetch_add(1,Ordering::Release);
                let expected_now=expected.load(Ordering::Acquire);
                let started_epoch = epoch.load(Ordering::Acquire);
                let result=if let Some(client)=&mut client{complete_bounded_request(client.request(is_grpc,cancel,None)).await}else{Err("client connection failure".into())};
                if result.is_err()||(!use_h2&&cancel){client=None;}
                let expected_now = expected_now || expected.load(Ordering::Acquire) || epoch.load(Ordering::Acquire) != started_epoch;
                send_completed_worker_event(&events,(is_grpc,expected_now,result)).await?;
                operations+=1;tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<(),SoakError>(())
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
    drop(probe);
    collect_finished_workers(&mut workers,&mut received,|(is_grpc,expected_now,result)| {
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
            other => { failures += 1; if unexpected_samples.len()<32 { unexpected_samples.push(json!({"result":format!("{other:?}"),"expected_unavailable":expected_now,"grpc":is_grpc,"at_ms":crate::millis(start.elapsed()),"phase":"worker_shutdown"})); } },
        }
    }).await?;
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
    let started_operations = started_operations.load(Ordering::Acquire);
    if started_operations != requests {
        return Err(fail(format!(
            "worker operation receipts missing: started={started_operations}, recorded={requests}"
        )));
    }
    std::fs::write(
        args.output.join("final-evidence.json"),
        serde_json::to_vec_pretty(&json!({
            "requests":requests,"started_operations":started_operations,"success":success,"cancelled_responses":cancelled,
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
        "requests":requests,"started_operations":started_operations,"success":success,"cancelled_responses":cancelled,"expected_unavailable":expected,
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
    fn retained_upgrade_requires_actual_a_socket_and_all_logical_metadata() {
        let fixture_a: SocketAddr = "127.0.0.1:43210".parse().expect("numeric fixture address");
        let mut raw = ResourceResponseFacts::blank("retained:a".into(), "upgrade");
        raw.status = Some(101);
        raw.request_head_sent = true;
        raw.upstream_name = Some("a".into());
        raw.upstream_peer = Some(fixture_a.to_string());
        raw.authority = Some("gateway.example.test".into());
        raw.server_name = Some("gateway.example.test".into());
        raw.path = Some("/base/ws".into());
        assert!(retained_upgrade_uses_fixture_a(&raw, fixture_a));
        for field in ["name", "peer", "authority", "sni", "path", "missing"] {
            let mut invalid = raw.clone();
            match field {
                "name" => invalid.upstream_name = Some("b".into()),
                "peer" => invalid.upstream_peer = Some("127.0.0.2:43210".into()),
                "authority" => invalid.authority = Some("other.example.test".into()),
                "sni" => invalid.server_name = Some("other.example.test".into()),
                "path" => invalid.path = Some("/base/ws?unexpected=1".into()),
                "missing" => invalid.upstream_peer = None,
                _ => unreachable!(),
            }
            assert!(
                !retained_upgrade_uses_fixture_a(&invalid, fixture_a),
                "{field}"
            );
        }
    }

    #[tokio::test]
    async fn captured_retained_upgrade_rejects_real_wrong_peer_without_hidden_retry() {
        use rustls::pki_types::pem::PemObject as _;
        let identity = identity().expect("test-only identity");
        let client = client_config(&[&identity], &[b"http/1.1"]).expect("verified fixture client");
        let key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())
                .expect("test-only key");
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![identity.certificate_der.clone()], key)
        .expect("matching test certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let fixture_a = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("distinct physical fixture A");
        let expected_a = fixture_a.local_addr().expect("actual A socket");
        let fixture_b = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("distinct physical fixture B");
        let actual_b = fixture_b.local_addr().expect("actual B socket");
        let task = tokio::spawn(async move {
            let (socket, _) = fixture_b.accept().await.expect("one actual connection");
            assert_eq!(socket.local_addr().expect("accepted socket"), actual_b);
            let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .expect("verified TLS handshake");
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(socket.read_u8().await.expect("real request head"));
                assert!(head.len() <= 16384);
            }
            assert!(head.starts_with(b"GET /ws HTTP/1.1\r\n"));
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nX-Fixture-Upstream: b\r\nX-Fixture-Peer: {actual_b}\r\nX-Fixture-Authority: gateway.example.test\r\nX-Fixture-Sni: gateway.example.test\r\nX-Fixture-Path: /base/ws\r\n\r\n"
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("real 101 head");
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).await.expect("actual client closure"),
                0
            );
            socket
                .shutdown()
                .await
                .expect("actual fixture TLS shutdown");
        });
        let recorder = Arc::new(Mutex::new(PreludeRecorder::default()));
        let mut guard = PreludeGuard::begin(&recorder, "upgrade", "upgrade")
            .expect("operation identity before network");
        let (socket, raw) = open_upgrade_capture(actual_b, client, true, Some(&guard))
            .await
            .expect("real captured B handshake");
        let mut socket = socket.expect("actual 101 tunnel");
        let mut raw = raw.expect("actual response metadata");
        assert_eq!(
            raw.upstream_peer.as_deref(),
            Some(actual_b.to_string().as_str())
        );
        assert!(
            verify_captured_retained_upgrade(&mut socket, &mut raw, Some(&mut guard), expected_a)
                .await
                .is_err()
        );
        drop(socket);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("fixture acknowledged closure")
            .expect("fixture did not panic");
        drop(guard);
        let evidence = recorder.lock().expect("journal").evidence().expect("facts");
        assert_eq!(evidence["prelude_counts"]["offered"], 1);
        assert_eq!(evidence["prelude_counts"]["classified"], 1);
        assert_eq!(evidence["prelude_counts"]["abandoned"], 0);
        let operation = &evidence["prelude_operations"][0];
        assert_eq!(operation["terminal"], "failed");
        assert_eq!(operation["cause"], "identity_mismatch");
        assert_eq!(operation["raw"]["upstream_name"], "b");
        assert_eq!(operation["raw"]["upstream_peer"], actual_b.to_string());
        assert_eq!(
            operation["raw"]["error_code"],
            "retained_upgrade_identity_mismatch"
        );
        assert_eq!(operation["raw"]["status"], 101);
        assert_eq!(operation["raw"]["body_bytes"], 0);
        assert_eq!(operation["raw"]["eof"], false);
        assert_eq!(operation["raw"]["tunnel_client_shutdown"], true);
        assert!(operation["raw"]["tunnel_close_result"].is_null());
    }

    #[test]
    fn explicit_local_response_accepts_null_metadata_without_weakening_proxy_peer_checks() {
        let local = ResourceDataClient {
            sender: None,
            driver: None,
            h2: true,
            targets: Vec::new(),
            local_response: true,
        };
        let mut facts = ResourceResponseFacts::blank("local".into(), "h2");
        facts.status = Some(200);
        local.check_peer_metadata(&mut facts, "/resource/respond");
        assert!(facts.diagnostics.is_empty());
        assert!(
            facts.upstream_peer.is_none()
                && facts.server_name.is_none()
                && facts.authority.is_none()
        );
        facts.upstream_peer = Some("127.0.0.1:8080".into());
        local.check_peer_metadata(&mut facts, "/resource/respond");
        assert!(
            facts
                .diagnostics
                .iter()
                .any(|code| code == "unexpected_upstream_metadata_for_local_response")
        );
        let proxy = ResourceDataClient {
            sender: None,
            driver: None,
            h2: true,
            targets: vec![("a".into(), "127.0.0.1:8080".parse().expect("numeric peer"))],
            local_response: false,
        };
        let mut missing = ResourceResponseFacts::blank("proxy".into(), "h2");
        missing.status = Some(200);
        proxy.check_peer_metadata(&mut missing, "/resource/payload");
        assert!(
            missing
                .diagnostics
                .iter()
                .any(|code| code == "physical_peer_mismatch"),
            "Proxy never infers local response from absent metadata"
        );
    }

    #[tokio::test]
    async fn proxy_connect_rejects_empty_peer_table_before_any_network_io() {
        let identity = identity().expect("test-only identity");
        let config = client_config(&[&identity], &[b"h2"]).expect("verified client");
        let result = ResourceDataClient::connect(
            "127.0.0.1:0".parse().expect("invalid dial port unused"),
            config,
            true,
            Vec::new(),
        )
        .await;
        assert!(
            result
                .err()
                .expect("empty peers must fail")
                .to_string()
                .contains("Proxy requires 1..=3")
        );
    }

    #[tokio::test]
    async fn explicit_local_client_records_actual_response_even_when_proxy_payload_cap_is_smaller()
    {
        use rustls::pki_types::pem::PemObject as _;
        let identity = identity().expect("test-only TLS identity");
        for h2 in [false, true] {
            let alpn: &[u8] = if h2 { b"h2" } else { b"http/1.1" };
            let config = client_config(&[&identity], &[alpn]).expect("verified client identity");
            let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
                identity.private_key_pem.as_bytes(),
            )
            .expect("ephemeral key");
            let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("TLS versions")
            .with_no_client_auth()
            .with_single_cert(vec![identity.certificate_der.clone()], key)
            .expect("matching test identity");
            server.alpn_protocols = vec![alpn.to_vec()];
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("ephemeral fixture");
            let address = listener.local_addr().expect("actual fixture socket");
            let task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.expect("real client");
                let socket = tokio_rustls::TlsAcceptor::from(Arc::new(server))
                    .accept(socket)
                    .await
                    .expect("real TLS");
                let service =
                    hyper::service::service_fn(|_request: Request<hyper::body::Incoming>| async {
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                                .body(Full::new(Bytes::from_static(b"resource-respond")))
                                .expect("local fixture response"),
                        )
                    });
                if h2 {
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(socket), service)
                        .await
                        .expect("HTTP2 server");
                } else {
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await
                        .expect("HTTP1 server");
                }
            });
            let mut client = ResourceDataClient::connect_local(address, config, h2)
                .await
                .expect("explicit local transport");
            let raw = client
                .measure(ResourceRequest {
                    operation_id: "local-wire".into(),
                    path: "/resource/respond".into(),
                    grpc: false,
                    cancel_after_first_data: false,
                    payload_size: 1,
                    upload_bytes: 0,
                })
                .await;
            assert_eq!(raw.status, Some(200));
            assert!(raw.eof && raw.error_code.is_none() && raw.diagnostics.is_empty());
            assert_eq!(raw.body_bytes, 16);
            let expected: String = Sha256::digest(b"resource-respond")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(raw.body_sha256, expected);
            assert_eq!(
                raw.content_type.as_deref(),
                Some("text/plain; charset=utf-8")
            );
            assert!(
                raw.upstream_peer.is_none()
                    && raw.upstream_name.is_none()
                    && raw.authority.is_none()
                    && raw.server_name.is_none()
                    && raw.path.is_none(),
                "local response does not fabricate fixture metadata from transport"
            );
            client.close().await.expect("actual client driver exit");
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("actual fixture driver exit")
                .expect("fixture did not panic");
        }
    }

    #[test]
    fn prelude_journal_keeps_all_started_operations_and_detects_lost_or_duplicate_terminals() {
        let recorder = Arc::new(Mutex::new(PreludeRecorder::default()));
        let mut completed =
            PreludeGuard::begin(&recorder, "probe", "h2").expect("first ID before send");
        let mut raw = ResourceResponseFacts::blank(completed.operation_id.clone(), "h2");
        raw.started_ns = Some(completed.started_ns);
        raw.status = Some(503);
        raw.eof = true;
        raw.ended_ns = Some(super::super::resource_identity::monotonic_ns().expect("actual clock"));
        completed
            .finish(&raw, "response_complete", "response_eof")
            .expect("one terminal");
        assert!(
            completed
                .finish(&raw, "response_complete", "response_eof")
                .is_err(),
            "duplicate cannot overwrite a terminal"
        );
        let abandoned = PreludeGuard::begin(&recorder, "held", "h2").expect("second ID");
        let abandoned_id = abandoned.operation_id.clone();
        drop(abandoned);
        let mut failed = PreludeGuard::begin(&recorder, "probe", "h2").expect("third ID");
        failed
            .fail("response_head", "prelude_deadline")
            .expect("explicit failure terminal");
        let evidence = recorder
            .lock()
            .expect("journal")
            .evidence()
            .expect("raw evidence");
        assert_eq!(evidence["prelude_counts"]["offered"], 3);
        assert_eq!(evidence["prelude_counts"]["classified"], 3);
        assert_eq!(evidence["prelude_counts"]["abandoned"], 1);
        assert_eq!(
            evidence["prelude_counts"]["violations"]
                .as_array()
                .expect("violations")
                .len(),
            1
        );
        let rows = evidence["prelude_operations"]
            .as_array()
            .expect("all issued IDs");
        let ids: std::collections::BTreeSet<_> = rows
            .iter()
            .map(|row| row["operation_id"].as_str().expect("unique ID"))
            .collect();
        assert_eq!(ids.len(), 3);
        let abandoned = rows
            .iter()
            .find(|row| row["operation_id"] == abandoned_id)
            .expect("lost future has raw row");
        assert_eq!(abandoned["terminal"], "abandoned");
        assert_eq!(abandoned["raw"]["error_code"], "prelude_abandoned");
        assert!(abandoned["raw"]["status"].is_null());
        assert_eq!(abandoned["raw"]["eof"], false);
    }

    #[tokio::test]
    async fn prelude_non_200_bodies_have_actual_eof_size_hash_and_strict_bound() {
        let recorder = Arc::new(Mutex::new(PreludeRecorder::default()));
        let mut operation = PreludeGuard::begin(&recorder, "probe", "h2").expect("offered probe");
        let mut raw = ResourceResponseFacts::blank(operation.operation_id.clone(), "h2");
        raw.started_ns = Some(operation.started_ns);
        raw.status = Some(503);
        let bytes = b"upstream unavailable";
        let size = capture_bounded_prelude_body(
            Full::new(Bytes::from_static(bytes)),
            &mut raw,
            Some(&operation),
        )
        .await
        .expect("full safe rejection body");
        assert_eq!(size, bytes.len() as u64);
        let expected: String = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(raw.body_sha256, expected);
        assert!(raw.eof && raw.data_observed);
        operation
            .finish(&raw, "response_complete", "response_eof")
            .expect("classified rejection, not healthy 200");
        let mut too_large = ResourceResponseFacts::blank("overflow".into(), "h2");
        assert!(
            capture_bounded_prelude_body(
                Full::new(Bytes::from(vec![b'x'; 64 * 1024 + 1])),
                &mut too_large,
                None
            )
            .await
            .is_err()
        );
        assert_eq!(
            too_large.body_bytes,
            64 * 1024 + 1,
            "actually observed over-limit bytes are not zero"
        );
        assert!(!too_large.eof, "bound failure cannot claim full response");
    }

    #[tokio::test]
    async fn tunnel_close_preserves_unclean_eof_and_rejects_other_errors_or_incomplete_echoes() {
        struct CloseIo(std::io::ErrorKind);
        impl AsyncRead for CloseIo {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.0 == std::io::ErrorKind::Other {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(std::io::Error::from(self.0)))
                }
            }
        }
        impl AsyncWrite for CloseIo {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        for (kind, result, clean, allowed) in [
            (std::io::ErrorKind::Other, "clean_eof", true, true),
            (
                std::io::ErrorKind::UnexpectedEof,
                "peer_closed_without_close_notify",
                false,
                true,
            ),
            (std::io::ErrorKind::ConnectionReset, "error", false, false),
        ] {
            let mut raw = ResourceResponseFacts::blank("close".into(), "upgrade");
            raw.status = Some(101);
            raw.echo_iterations = 4;
            raw.body_bytes = 80;
            assert_eq!(
                observe_tunnel_close(&mut CloseIo(kind), &mut raw, 4)
                    .await
                    .is_ok(),
                allowed
            );
            assert_eq!(raw.eof, clean);
            assert_eq!(raw.tunnel_close_result.as_deref(), Some(result));
            assert!(raw.tunnel_client_shutdown);
        }
        let mut incomplete = ResourceResponseFacts::blank("incomplete".into(), "upgrade");
        incomplete.status = Some(101);
        incomplete.echo_iterations = 3;
        incomplete.body_bytes = 60;
        assert!(
            observe_tunnel_close(
                &mut CloseIo(std::io::ErrorKind::UnexpectedEof),
                &mut incomplete,
                4
            )
            .await
            .is_err()
        );
        assert!(!incomplete.tunnel_client_shutdown && !incomplete.eof);
        assert!(incomplete.tunnel_close_result.is_none());
    }

    #[tokio::test]
    async fn resource_uploads_have_exact_wire_size_and_bounded_frames() {
        for grpc in [false, true] {
            for size in [0usize, 1, 1024, 1025, 16 * 1024 * 1024] {
                let mut body = GeneratedUpload::new(grpc, size);
                let expected = size + if grpc { 5 } else { 0 };
                assert_eq!(body.size_hint().exact(), Some(expected as u64));
                let mut seen = 0usize;
                let prefix = [
                    0,
                    (size >> 24) as u8,
                    (size >> 16) as u8,
                    (size >> 8) as u8,
                    size as u8,
                ];
                while let Some(frame) = body.frame().await {
                    let frame = frame.expect("generated upload is infallible");
                    let data = frame.data_ref().expect("only DATA in this recipe");
                    assert!(data.len() <= 1024);
                    for byte in data {
                        let wanted = if grpc && seen < 5 { prefix[seen] } else { b'u' };
                        assert_eq!(*byte, wanted, "every wire byte is independently checked");
                        seen += 1;
                    }
                    assert_eq!(body.size_hint().exact(), Some((expected - seen) as u64));
                }
                assert_eq!(seen, expected);
                assert!(body.is_end_stream());
            }
        }
    }

    #[tokio::test]
    async fn resource_driver_close_receipt_preserves_actual_completion_error_and_cancellation() {
        for expected in ["completed", "error", "cancelled", "panicked"] {
            let driver = tokio::spawn(async move {
                match expected {
                    "completed" => Ok(()),
                    "error" => Err("http1_driver_error".to_owned()),
                    "panicked" => panic!("test-only driver panic must not become completed"),
                    _ => std::future::pending().await,
                }
            });
            if expected == "cancelled" {
                driver.abort();
            }
            let client = ResourceDataClient {
                sender: None,
                driver: Some(driver),
                h2: false,
                targets: Vec::new(),
                local_response: false,
            };
            let receipt = client.close_receipt().await;
            assert_eq!(receipt["result"], expected);
            assert_eq!(receipt["join_acknowledged"], true);
            assert!(receipt["exit_ns"].as_u64().is_some());
            assert_eq!(receipt["abort_requested"], false);
            if expected == "error" {
                assert_eq!(receipt["code"], "http1_driver_error");
            }
        }
        let unavailable = ResourceDataClient {
            sender: None,
            driver: None,
            h2: false,
            targets: Vec::new(),
            local_response: false,
        }
        .close_receipt()
        .await;
        assert_eq!(unavailable["result"], "unavailable");
        assert_eq!(unavailable["join_acknowledged"], false);
        assert!(
            unavailable["exit_ns"].is_null(),
            "no observed exit is not fabricated"
        );
    }

    #[test]
    fn raw_missing_metadata_stays_null_and_captured_digest_is_independent_of_legacy_flag() {
        let facts = ResourceResponseFacts::blank("op-1".into(), "h2");
        let raw = serde_json::to_value(&facts).expect("valid raw JSON");
        for key in [
            "status",
            "started_ns",
            "upstream_peer",
            "authority",
            "server_name",
            "path",
        ] {
            assert!(raw[key].is_null(), "unavailable {key} is not fabricated");
        }
        assert!(!facts.request_head_sent && !facts.eof && !facts.fixture_cancel_ack);
        let mut validator = PayloadValidator::new(false, 3, b'a');
        assert!(
            validator.digest().is_none(),
            "ordinary legacy requests do not hash bodies"
        );
        validator.capture();
        validator
            .push(&Bytes::from_static(b"axx"))
            .expect("exact legacy recipe");
        validator.finish().expect("complete recipe");
        let expected: String = Sha256::digest(b"axx")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(validator.digest().as_deref(), Some(expected.as_str()));
    }

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
        let (events, mut received) = tokio::sync::mpsc::channel::<WorkerEvent>(1);
        drop(events);
        workers.spawn(async {
            panic!("injected qualification worker panic");
        });
        assert!(
            collect_finished_workers(&mut workers, &mut received, |_| {})
                .await
                .expect_err("worker panic must fail")
                .to_string()
                .contains("load worker failed")
        );
    }
    #[tokio::test]
    async fn full_result_channel_and_stop_cannot_hide_completed_validator_error() {
        let (events, mut received) = tokio::sync::mpsc::channel::<WorkerEvent>(1);
        events
            .try_send((false, false, Ok((200, 1, false))))
            .expect("first recorded operation fills channel");
        let started = Arc::new(AtomicU64::new(1));
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let (attempt, attempted) = tokio::sync::oneshot::channel();
        let mut workers = tokio::task::JoinSet::new();
        let started_worker = Arc::clone(&started);
        let worker = workers.spawn(async move {
            started_worker.fetch_add(1, Ordering::Release);
            let mut validator = PayloadValidator::new(true, 2, b'a');
            let error = validator
                .push(&Bytes::from_static(&[0, 0, 0, 0, 2, b'x', b'y']))
                .expect_err("real opaque DATA validation error")
                .to_string();
            attempt
                .send(())
                .expect("completed outcome exists before stop");
            send_completed_worker_event(&events, (true, false, Err(error))).await
        });
        attempted.await.expect("bounded source acknowledgment");
        stop.send(true)
            .expect("planned stop while result channel is full");
        tokio::task::yield_now().await;
        assert!(*stopped.borrow());
        assert!(
            !worker.is_finished(),
            "result must wait for capacity, not discard on stop"
        );
        let mut recorded = 0u64;
        let mut errors = 0u64;
        collect_finished_workers(&mut workers, &mut received, |(_, _, result)| {
            recorded += 1;
            if let Err(error) = result {
                assert!(error.contains("opaque response DATA"));
                errors += 1;
            }
        })
        .await
        .expect("concurrent join/drain cannot deadlock");
        assert_eq!(recorded, started.load(Ordering::Acquire));
        assert_eq!(recorded, 2);
        assert_eq!(
            errors, 1,
            "completed error must make final campaign result FAIL"
        );
    }
    #[tokio::test]
    async fn closed_result_receiver_makes_worker_join_fail_instead_of_silent_stop() {
        let (events, mut received) = tokio::sync::mpsc::channel::<WorkerEvent>(1);
        received.close();
        let mut workers = tokio::task::JoinSet::new();
        workers.spawn(async move {
            send_completed_worker_event(&events, (false, false, Ok((200, 1, false)))).await
        });
        assert!(
            collect_finished_workers(&mut workers, &mut received, |_| {})
                .await
                .expect_err("closed receiver cannot yield PASS")
                .to_string()
                .contains("result receiver closed")
        );
    }
}
