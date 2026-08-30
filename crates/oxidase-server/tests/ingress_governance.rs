//! Black-box coverage for protective Service wrappers at the HTTP data plane.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct FrameBody {
    frames: VecDeque<Frame<Bytes>>,
}

impl FrameBody {
    fn data(chunks: &[&'static [u8]]) -> Self {
        Self {
            frames: chunks
                .iter()
                .map(|chunk| Frame::data(Bytes::from_static(chunk)))
                .collect(),
        }
    }
}

impl Body for FrameBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front().map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.frames.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
    certificate_der: CertificateDer<'static>,
}

fn identity(name: &str) -> TestIdentity {
    // Generated exclusively for this test process; never production material.
    let GeneratedCertificate { cert, signing_key } =
        generate_simple_self_signed(vec![name.to_owned()])
            .expect("test-only TLS identity can be generated");
    TestIdentity {
        certificate_pem: cert.pem(),
        private_key_pem: signing_key.serialize_pem(),
        certificate_der: cert.der().clone(),
    }
}

fn client_config(identity: &TestIdentity) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(identity.certificate_der.clone())
        .expect("test certificate can be trusted");
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

#[derive(Debug)]
struct UpstreamAttempt {
    body_bytes: usize,
}

struct UpstreamFixture {
    address: SocketAddr,
    attempts: mpsc::UnboundedReceiver<UpstreamAttempt>,
    release_first: Arc<Semaphore>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

struct EarlyResponseUpstream {
    address: SocketAddr,
    task: tokio::task::JoinHandle<usize>,
}

impl EarlyResponseUpstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("early-response upstream binds to loopback");
        let address = listener.local_addr().expect("fixture address is known");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("gateway connects upstream");
            let mut received = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .expect("upstream request prefix is readable");
                assert!(
                    read != 0,
                    "gateway closed before forwarding the exact-limit prefix"
                );
                received.extend_from_slice(&buffer[..read]);
                if received
                    .windows(b"\r\n4\r\nabcd\r\n".len())
                    .any(|window| window == b"\r\n4\r\nabcd\r\n")
                {
                    break;
                }
                assert!(
                    received.len() <= 64 * 1024,
                    "upstream request head is bounded"
                );
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nearly\r\n")
                .await
                .expect("early response head and first chunk can be written");
            let mut after_head = 0_usize;
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => after_head = after_head.saturating_add(read),
                }
            }
            after_head
        });
        Self { address, task }
    }

    async fn finish(self) -> usize {
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("upstream connection is cancelled after post-head overflow")
            .expect("early-response fixture task does not panic")
    }
}

impl UpstreamFixture {
    async fn start(block_first_response: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream fixture binds to loopback");
        let address = listener.local_addr().expect("fixture address is known");
        let release_first = Arc::new(Semaphore::new(0));
        let release_for_task = Arc::clone(&release_first);
        let attempts_seen = Arc::new(AtomicUsize::new(0));
        let (attempt_sender, attempts) = mpsc::unbounded_channel();
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        let attempt_sender = attempt_sender.clone();
                        let release = Arc::clone(&release_for_task);
                        let attempts_seen = Arc::clone(&attempts_seen);
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let attempt_sender = attempt_sender.clone();
                                let release = Arc::clone(&release);
                                let sequence = attempts_seen.fetch_add(1, Ordering::AcqRel);
                                async move {
                                    let body = request.into_body().collect().await.map_err(|error| {
                                        io::Error::new(io::ErrorKind::InvalidData, error)
                                    })?.to_bytes();
                                    let _ = attempt_sender.send(UpstreamAttempt {
                                        body_bytes: body.len(),
                                    });
                                    if block_first_response && sequence == 0 {
                                        let permit = release.acquire().await.map_err(|_| {
                                            io::Error::new(io::ErrorKind::BrokenPipe, "gate closed")
                                        })?;
                                        permit.forget();
                                    }
                                    Ok::<_, io::Error>(
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .body(Full::new(Bytes::from(format!(
                                                "received:{}",
                                                body.len()
                                            ))))
                                            .expect("fixture response is valid"),
                                    )
                                }
                            });
                            let _ = server_http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            attempts,
            release_first,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn next_attempt(&mut self) -> UpstreamAttempt {
        tokio::time::timeout(Duration::from_secs(2), self.attempts.recv())
            .await
            .expect("upstream observes an attempt before timeout")
            .expect("attempt channel remains open")
    }

    async fn shutdown(mut self) {
        self.release_first.add_permits(1);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("upstream fixture task exits");
    }
}

struct TestGateway {
    _directory: TempDir,
    config: PathBuf,
    address: SocketAddr,
    admin: SocketAddr,
    running: RunningServer,
}

impl TestGateway {
    async fn plain(listener_bind: &str, upstream: Option<SocketAddr>, service: &str) -> Self {
        let directory = tempdir().expect("temporary gateway directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_plain_gateway(&config, listener_bind, upstream, service);
        Self::bind(directory, config).await
    }

    async fn h2(identity: &TestIdentity, upstream: SocketAddr, service: &str) -> Self {
        Self::h2_with_limits(identity, upstream, service, "").await
    }

    async fn h2_with_limits(
        identity: &TestIdentity,
        upstream: SocketAddr,
        service: &str,
        limits: &str,
    ) -> Self {
        let directory = tempdir().expect("temporary gateway directory is available");
        fs::write(
            directory.path().join("server.pem"),
            &identity.certificate_pem,
        )
        .expect("test certificate can be written");
        fs::write(
            directory.path().join("server-key.pem"),
            &identity.private_key_pem,
        )
        .expect("test key can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    test:
      cert_chain: server.pem
      private_key: server-key.pem
  clusters:
    upstream:
      protocol: http1
      endpoints:
        - http://{upstream}
services:
  root:
{service}
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
{limits}    tls:
      default_certificate: test
    http:
      versions: [h2]
      http2:
        max_concurrent_streams: 64
        max_header_list_size: 64KiB
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      ref: root
"#
            ),
        )
        .expect("H2 gateway source can be written");
        Self::bind(directory, config).await
    }

    async fn bind(directory: TempDir, config: PathBuf) -> Self {
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("governed gateway source compiles"),
        )
        .expect("governed gateway snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("governed gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("governed admin listener binds");
        let admin = server.admin_address().expect("admin address is available");
        let running = server.spawn();
        let address = running.local_addresses()[0].1;
        Self {
            _directory: directory,
            config,
            address,
            admin,
            running,
        }
    }

    async fn rewrite_and_reload(
        &self,
        listener_bind: &str,
        upstream: Option<SocketAddr>,
        service: &str,
    ) {
        write_plain_gateway(&self.config, listener_bind, upstream, service);
        self.running
            .reload_path(&self.config)
            .await
            .expect("governance candidate commits");
    }
}

fn write_plain_gateway(
    path: &Path,
    listener_bind: &str,
    upstream: Option<SocketAddr>,
    service: &str,
) {
    let resources = upstream.map_or_else(String::new, |address| {
        format!(
            "resources:\n  clusters:\n    upstream:\n      protocol: http1\n      endpoints:\n        - http://{address}\n"
        )
    });
    fs::write(
        path,
        format!(
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\n{resources}services:\n  root:\n{service}\nlisteners:\n  - name: public\n    bind: {listener_bind}\n    service:\n      ref: root\n"
        ),
    )
    .expect("plain gateway source can be written");
}

const BODY_LIMIT_SERVICE: &str = r#"    type: request_body_limit
    max_bytes: 4B
    service:
      type: proxy
      cluster: upstream"#;

const CONCURRENCY_SERVICE: &str = r#"    type: concurrency_limit
    name: integration
    max_in_flight: 1
    queue_timeout: 0ms
    on_reject:
      status: 503
    service:
      type: proxy
      cluster: upstream"#;

fn rate_service(body: &str) -> String {
    format!(
        r#"    type: rate_limit
    name: peer-bucket
    key:
      source: peer_ip
    rate:
      requests: 1
      per: 60s
    burst: 2
    state:
      max_keys: 8
      idle_ttl: 120s
    service:
      type: respond
      body:
        text: {body}"#
    )
}

#[derive(Debug)]
struct WireResponse {
    status: StatusCode,
    body: Bytes,
}

async fn raw_http1(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(3), async move {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("raw HTTP/1 client connects");
        stream
            .write_all(request)
            .await
            .expect("raw HTTP/1 request can be written");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("raw HTTP/1 response is readable");
        response
    })
    .await
    .expect("raw HTTP/1 exchange completes before timeout")
}

async fn read_http1_head(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut response = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            let read = stream
                .read(&mut byte)
                .await
                .expect("HTTP/1 response head is readable");
            assert!(read != 0, "connection closed before response head");
            response.push(byte[0]);
            assert!(response.len() <= 64 * 1024, "response head is bounded");
            if response.ends_with(b"\r\n\r\n") {
                return response;
            }
        }
    })
    .await
    .expect("HTTP/1 response head arrives before timeout")
}

fn raw_status(response: &[u8]) -> StatusCode {
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .expect("response has a status line");
    let line = std::str::from_utf8(&response[..line_end]).expect("status line is ASCII");
    let code = line
        .split_ascii_whitespace()
        .nth(1)
        .expect("status line has a status code")
        .parse::<u16>()
        .expect("status code is numeric");
    StatusCode::from_u16(code).expect("status code is valid")
}

async fn plain_get(address: SocketAddr, path: &str) -> Vec<u8> {
    raw_http1(
        address,
        format!("GET {path} HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
}

async fn wait_for_metric(address: SocketAddr, expected: &str) -> String {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = raw_http1(
                address,
                b"GET /metrics HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n",
            )
            .await;
            let response = String::from_utf8(response).expect("metrics response is UTF-8");
            if response.contains(expected) {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("metric did not reach expected value: {expected}"))
}

async fn h2_post(
    address: SocketAddr,
    identity: &TestIdentity,
    chunks: &[&'static [u8]],
) -> WireResponse {
    let tcp = TcpStream::connect(address)
        .await
        .expect("H2 client connects to loopback");
    let server_name =
        ServerName::try_from("gateway.example.test".to_owned()).expect("test DNS name is valid");
    let tls = TlsConnector::from(client_config(identity))
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake succeeds");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("POST")
        .uri("https://gateway.example.test/upload")
        .body(FrameBody::data(chunks))
        .expect("HTTP/2 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/2 response head arrives");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("HTTP/2 response body completes")
        .to_bytes();
    drop(sender);
    driver.abort();
    WireResponse { status, body }
}

async fn open_h2_connection(
    address: SocketAddr,
    identity: &TestIdentity,
) -> (
    client_http2::SendRequest<Empty<Bytes>>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpStream::connect(address)
        .await
        .expect("H2 client connects to loopback");
    let server_name =
        ServerName::try_from("gateway.example.test".to_owned()).expect("test DNS name is valid");
    let tls = TlsConnector::from(client_config(identity))
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake succeeds");
    let (sender, connection) =
        client_http2::handshake::<_, _, Empty<Bytes>>(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

#[tokio::test]
async fn http1_request_body_limit_has_known_and_chunked_wire_boundaries() {
    let mut upstream = UpstreamFixture::start(false).await;
    let gateway =
        TestGateway::plain("127.0.0.1:0", Some(upstream.address), BODY_LIMIT_SERVICE).await;

    let exact = raw_http1(
        gateway.address,
        b"POST /known HTTP/1.1\r\nHost: gateway.example.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nabcd",
    )
    .await;
    assert_eq!(raw_status(&exact), StatusCode::OK);
    assert_eq!(upstream.next_attempt().await.body_bytes, 4);

    let known_over = raw_http1(
        gateway.address,
        b"POST /known-over HTTP/1.1\r\nHost: gateway.example.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
    )
    .await;
    assert_eq!(raw_status(&known_over), StatusCode::PAYLOAD_TOO_LARGE);

    let chunked_exact = raw_http1(
        gateway.address,
        b"POST /chunked HTTP/1.1\r\nHost: gateway.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(raw_status(&chunked_exact), StatusCode::OK);
    assert_eq!(upstream.next_attempt().await.body_bytes, 4);

    let chunked_over = raw_http1(
        gateway.address,
        b"POST /chunked-over HTTP/1.1\r\nHost: gateway.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(raw_status(&chunked_over), StatusCode::PAYLOAD_TOO_LARGE);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn http2_request_body_limit_has_streaming_wire_boundary() {
    let identity = identity("gateway.example.test");
    let mut upstream = UpstreamFixture::start(false).await;
    let gateway = TestGateway::h2(&identity, upstream.address, BODY_LIMIT_SERVICE).await;

    let exact = h2_post(gateway.address, &identity, &[b"ab", b"cd"]).await;
    assert_eq!(exact.status, StatusCode::OK);
    assert_eq!(exact.body, "received:4");
    assert_eq!(upstream.next_attempt().await.body_bytes, 4);

    let over = h2_post(gateway.address, &identity, &[b"ab", b"cde"]).await;
    assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn http2_connections_share_the_listener_and_peer_admission_limits() {
    let identity = identity("gateway.example.test");
    let upstream = UpstreamFixture::start(false).await;
    let limits = "    limits:\n      max_connections: 1\n      max_connections_per_ip: 1\n";
    let gateway =
        TestGateway::h2_with_limits(&identity, upstream.address, BODY_LIMIT_SERVICE, limits).await;
    let (first_sender, first_driver) = open_h2_connection(gateway.address, &identity).await;

    let second_tcp = TcpStream::connect(gateway.address)
        .await
        .expect("excess TCP connection reaches the listener");
    let server_name =
        ServerName::try_from("gateway.example.test".to_owned()).expect("test DNS name is valid");
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        TlsConnector::from(client_config(&identity)).connect(server_name, second_tcp),
    )
    .await
    .expect("excess H2 connection is rejected promptly");
    assert!(
        second.is_err(),
        "the per-peer connection slot is already held"
    );

    drop(first_sender);
    first_driver.abort();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let tcp = TcpStream::connect(gateway.address)
                .await
                .expect("replacement TCP connection reaches the listener");
            let server_name = ServerName::try_from("gateway.example.test".to_owned())
                .expect("test DNS name is valid");
            if TlsConnector::from(client_config(&identity))
                .connect(server_name, tcp)
                .await
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("dropping the first H2 connection releases admission");

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn post_head_request_body_overflow_never_forges_a_413() {
    let upstream = EarlyResponseUpstream::start().await;
    let gateway =
        TestGateway::plain("127.0.0.1:0", Some(upstream.address), BODY_LIMIT_SERVICE).await;
    let mut client = TcpStream::connect(gateway.address)
        .await
        .expect("streaming upload client connects");
    client
        .write_all(
            b"POST /early HTTP/1.1\r\nHost: gateway.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nabcd\r\n",
        )
        .await
        .expect("exact-limit request prefix can be written");
    let head = read_http1_head(&mut client).await;
    assert!(
        head.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "upstream response head must be preserved: {}",
        String::from_utf8_lossy(&head)
    );
    client
        .write_all(b"1\r\ne\r\n0\r\n\r\n")
        .await
        .expect("limit+1 suffix reaches the gateway after the response head");
    let mut remainder = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut remainder))
        .await
        .expect("post-head overflow terminates the downstream exchange");
    let mut wire = head;
    wire.extend_from_slice(&remainder);
    assert!(
        !String::from_utf8_lossy(&wire).contains("413 Payload Too Large"),
        "an already-sent 200 head cannot be replaced"
    );
    assert_eq!(
        upstream.finish().await,
        0,
        "the byte beyond the limit is never forwarded upstream"
    );

    let metrics = wait_for_metric(
        gateway.admin,
        "oxidase_response_body_terminations_total{reason=\"error\"} 1",
    )
    .await;
    assert!(metrics.contains("oxidase_active_requests 0"));
    assert!(metrics.contains(
        "oxidase_governance_total{kind=\"request_body_limit\",name=\"service:root\",result=\"evaluated\"} 1"
    ));
    assert!(metrics.contains(
        "oxidase_governance_total{kind=\"request_body_limit\",name=\"service:root\",result=\"admitted\"} 0"
    ));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn concurrency_limit_rejects_overlap_then_releases_for_the_next_request() {
    let mut upstream = UpstreamFixture::start(true).await;
    let gateway =
        TestGateway::plain("127.0.0.1:0", Some(upstream.address), CONCURRENCY_SERVICE).await;
    let address = gateway.address;
    let first = tokio::spawn(async move { plain_get(address, "/first").await });
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);

    let overlap = plain_get(gateway.address, "/overlap").await;
    assert_eq!(raw_status(&overlap), StatusCode::SERVICE_UNAVAILABLE);

    upstream.release_first.add_permits(1);
    assert_eq!(
        raw_status(&first.await.expect("first client task completes")),
        StatusCode::OK
    );
    let after = plain_get(gateway.address, "/after").await;
    assert_eq!(raw_status(&after), StatusCode::OK);
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn active_concurrency_state_is_shared_across_compatible_reload() {
    let mut upstream = UpstreamFixture::start(true).await;
    let initial = CONCURRENCY_SERVICE.replace("max_in_flight: 1", "max_in_flight: 2");
    let gateway = TestGateway::plain("127.0.0.1:0", Some(upstream.address), &initial).await;
    let address = gateway.address;
    let first = tokio::spawn(async move { plain_get(address, "/old-snapshot").await });
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);

    gateway
        .rewrite_and_reload("127.0.0.1:0", Some(upstream.address), CONCURRENCY_SERVICE)
        .await;
    let rejected = plain_get(gateway.address, "/new-snapshot").await;
    assert_eq!(raw_status(&rejected), StatusCode::SERVICE_UNAVAILABLE);

    upstream.release_first.add_permits(1);
    assert_eq!(
        raw_status(&first.await.expect("old request completes")),
        StatusCode::OK
    );
    assert_eq!(
        raw_status(&plain_get(gateway.address, "/after-release").await),
        StatusCode::OK
    );
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn concurrency_permit_is_released_when_the_downstream_disconnects_before_head() {
    let mut upstream = UpstreamFixture::start(true).await;
    let gateway =
        TestGateway::plain("127.0.0.1:0", Some(upstream.address), CONCURRENCY_SERVICE).await;
    let mut cancelled = TcpStream::connect(gateway.address)
        .await
        .expect("cancelling client connects");
    cancelled
        .write_all(
            b"GET /cancel HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("cancelling request can be written");
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);
    drop(cancelled);

    let after = tokio::time::timeout(
        Duration::from_secs(2),
        plain_get(gateway.address, "/after-cancel"),
    )
    .await
    .expect("a cancelled exchange releases its concurrency permit");
    assert_eq!(raw_status(&after), StatusCode::OK);
    assert_eq!(upstream.next_attempt().await.body_bytes, 0);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn peer_ip_rate_limit_emits_429_retry_after_and_reuses_state_across_reload() {
    let initial_service = rate_service("old");
    let gateway = TestGateway::plain("127.0.0.1:0", None, &initial_service).await;
    assert_eq!(
        raw_status(&plain_get(gateway.address, "/first?secret=value").await),
        StatusCode::OK
    );
    assert_eq!(
        raw_status(&plain_get(gateway.address, "/second?secret=value").await),
        StatusCode::OK
    );

    let updated_service = rate_service("new");
    gateway
        .rewrite_and_reload("127.0.0.1:0", None, &updated_service)
        .await;
    let rejected = plain_get(gateway.address, "/third?secret=value").await;
    assert_eq!(raw_status(&rejected), StatusCode::TOO_MANY_REQUESTS);
    let response = String::from_utf8(rejected).expect("wire response is ASCII");
    assert!(
        response
            .lines()
            .any(|line| line.eq_ignore_ascii_case("retry-after: 60")),
        "rate rejection must include a conservative Retry-After: {response}"
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn peer_ip_rate_limit_accepts_ipv6_loopback_as_a_bounded_key() {
    let service = rate_service("ipv6").replace("burst: 2", "burst: 1");
    let gateway = TestGateway::plain("\"[::1]:0\"", None, &service).await;
    assert_eq!(
        raw_status(&plain_get(gateway.address, "/first").await),
        StatusCode::OK
    );
    let rejected = plain_get(gateway.address, "/second").await;
    assert_eq!(raw_status(&rejected), StatusCode::TOO_MANY_REQUESTS);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}
