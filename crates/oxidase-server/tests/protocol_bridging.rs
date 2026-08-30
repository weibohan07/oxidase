//! Black-box protocol-bridging tests for HTTP/2 trailers and transparent gRPC.
//!
//! The TLS identity generated here is ephemeral, test-only material. It is
//! never suitable for production use and is deleted with its temporary directory.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{BufMut as _, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct FrameBody {
    frames: VecDeque<Result<Frame<Bytes>, io::Error>>,
    terminal_error_gate: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl FrameBody {
    fn new(frames: impl IntoIterator<Item = Frame<Bytes>>) -> Self {
        Self {
            frames: frames.into_iter().map(Ok).collect(),
            terminal_error_gate: None,
        }
    }

    fn with_gated_terminal_error(
        frames: impl IntoIterator<Item = Frame<Bytes>>,
        gate: Arc<Notify>,
    ) -> Self {
        let mut frames = frames.into_iter().map(Ok).collect::<VecDeque<_>>();
        frames.push_back(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "fixture upstream disconnected after response head",
        )));
        Self {
            frames,
            terminal_error_gate: Some(Box::pin(async move {
                gate.notified().await;
            })),
        }
    }
}

impl Body for FrameBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.frames.front().is_some_and(Result::is_err)
            && let Some(gate) = &mut self.terminal_error_gate
        {
            if gate.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.terminal_error_gate = None;
        }
        Poll::Ready(self.frames.pop_front())
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

struct TestGateway {
    _directory: TempDir,
    address: std::net::SocketAddr,
    running: RunningServer,
}

#[derive(Debug)]
struct ObservedRequest {
    version: Version,
    content_type: Option<HeaderValue>,
    te: Option<HeaderValue>,
    data: Bytes,
    trailers: Option<HeaderMap>,
}

struct ResponsePlan {
    content_type: HeaderValue,
    chunks: Vec<Bytes>,
    trailers: HeaderMap,
    declare_trailers: bool,
    body_error_gate: Option<Arc<Notify>>,
}

struct UpstreamFixture {
    address: std::net::SocketAddr,
    observed: mpsc::UnboundedReceiver<ObservedRequest>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl UpstreamFixture {
    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("upstream fixture task exits");
    }
}

fn identity() -> TestIdentity {
    // rcgen output is intentionally generated per test and is never a production identity.
    let GeneratedCertificate { cert, signing_key } =
        generate_simple_self_signed(vec!["gateway.example.test".to_owned()])
            .expect("test-only TLS identity can be generated");
    TestIdentity {
        certificate_pem: cert.pem(),
        private_key_pem: signing_key.serialize_pem(),
        certificate_der: cert.der().clone(),
    }
}

fn tls_client_config(identity: &TestIdentity) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(identity.certificate_der.clone())
        .expect("test certificate can be trusted");
    let provider = Arc::new(default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

async fn start_gateway(upstream: std::net::SocketAddr, identity: &TestIdentity) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    fs::write(
        directory.path().join("default.pem"),
        &identity.certificate_pem,
    )
    .expect("test-only certificate can be written");
    fs::write(
        directory.path().join("default-key.pem"),
        &identity.private_key_pem,
    )
    .expect("test-only private key can be written");
    let config = directory.path().join("oxidase.yaml");
    fs::write(
        &config,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
  clusters:
    upstream:
      protocol: h2
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 2s
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: default
    http:
      versions: [h2]
      http2:
        max_concurrent_streams: 32
        max_header_list_size: 64KiB
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      ref: root
"#
        ),
    )
    .expect("gateway source can be written");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("protocol bridge gateway source compiles"),
    )
    .expect("protocol bridge gateway prepares");
    let running = GatewayServer::bind(snapshot)
        .await
        .expect("protocol bridge gateway binds")
        .spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        address,
        running,
    }
}

async fn start_http1_gateway(upstream: std::net::SocketAddr) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    let config = directory.path().join("oxidase.yaml");
    fs::write(
        &config,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      protocol: h2
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 2s
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: plain
    bind: 127.0.0.1:0
    protocol: http
    http:
      versions: [http1]
      http1:
        header_read_timeout: 30s
    service:
      ref: root
"#
        ),
    )
    .expect("gateway source can be written");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("HTTP/1 protocol bridge source compiles"),
    )
    .expect("HTTP/1 protocol bridge gateway prepares");
    let running = GatewayServer::bind(snapshot)
        .await
        .expect("HTTP/1 protocol bridge gateway binds")
        .spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        address,
        running,
    }
}

async fn h1_client(
    address: std::net::SocketAddr,
) -> (
    client_http1::SendRequest<FrameBody>,
    tokio::task::JoinHandle<()>,
) {
    let stream = TcpStream::connect(address)
        .await
        .expect("HTTP/1 client connects to loopback listener");
    let (sender, connection) = client_http1::handshake(TokioIo::new(stream))
        .await
        .expect("HTTP/1 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

async fn raw_http1_request(address: std::net::SocketAddr, request: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("raw HTTP/1 client connects to loopback listener");
        stream
            .write_all(request)
            .await
            .expect("raw HTTP/1 request can be written");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("raw HTTP/1 response bytes are readable");
        response
    })
    .await
    .expect("raw HTTP/1 exchange finishes before timeout")
}

async fn h2_client(
    address: std::net::SocketAddr,
    identity: &TestIdentity,
) -> (
    client_http2::SendRequest<FrameBody>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = TcpStream::connect(address)
        .await
        .expect("TLS client connects to loopback listener");
    let server_name =
        ServerName::try_from("gateway.example.test".to_owned()).expect("test DNS name is valid");
    let tls = TlsConnector::from(tls_client_config(identity))
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake succeeds");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (sender, connection) = client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, driver)
}

async fn spawn_h2_upstream(response: ResponsePlan) -> UpstreamFixture {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream fixture binds");
    let address = listener.local_addr().expect("fixture address is known");
    let response = Arc::new(response);
    let (observed_sender, observed) = mpsc::unbounded_channel();
    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let response = response.clone();
                    let observed_sender = observed_sender.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let response = response.clone();
                            let observed_sender = observed_sender.clone();
                            async move {
                                let version = request.version();
                                let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
                                let te = request.headers().get(header::TE).cloned();
                                let collected = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .expect("upstream request body is readable");
                                let trailers = collected.trailers().cloned();
                                let _ = observed_sender.send(ObservedRequest {
                                    version,
                                    content_type,
                                    te,
                                    data: collected.to_bytes(),
                                    trailers,
                                });

                                let frames = response
                                    .chunks
                                    .iter()
                                    .cloned()
                                    .map(Frame::data)
                                    .collect::<Vec<_>>();
                                let body = if let Some(gate) = &response.body_error_gate {
                                    FrameBody::with_gated_terminal_error(frames, gate.clone())
                                } else {
                                    FrameBody::new(
                                        frames
                                            .into_iter()
                                            .chain([Frame::trailers(response.trailers.clone())]),
                                    )
                                };
                                let mut outgoing = Response::new(body);
                                *outgoing.status_mut() = StatusCode::OK;
                                outgoing.headers_mut().insert(
                                    header::CONTENT_TYPE,
                                    response.content_type.clone(),
                                );
                                if response.declare_trailers {
                                    outgoing.headers_mut().insert(
                                        header::TRAILER,
                                        HeaderValue::from_static("grpc-status, grpc-message"),
                                    );
                                }
                                Ok::<_, Infallible>(outgoing)
                            }
                        });
                        let _ = server_http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    UpstreamFixture {
        address,
        observed,
        shutdown: Some(shutdown),
        task,
    }
}

fn grpc_message(payload: &[u8]) -> Bytes {
    let mut encoded = BytesMut::with_capacity(5 + payload.len());
    encoded.put_u8(0);
    encoded.put_u32(payload.len() as u32);
    encoded.extend_from_slice(payload);
    encoded.freeze()
}

fn grpc_trailers(status: &'static str, message: &'static str) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static(status));
    trailers.insert("grpc-message", HeaderValue::from_static(message));
    trailers
}

async fn collect_frames(
    mut body: Incoming,
) -> Result<(Vec<Bytes>, Option<HeaderMap>), hyper::Error> {
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        match frame.into_data() {
            Ok(bytes) => data.push(bytes),
            Err(frame) => {
                if let Ok(headers) = frame.into_trailers() {
                    trailers = Some(headers);
                }
            }
        }
    }
    Ok((data, trailers))
}

#[tokio::test]
async fn http2_proxy_preserves_request_and_response_trailer_frames() {
    let response_data = Bytes::from_static(b"response-data");
    let response_trailers = grpc_trailers("0", "complete");
    let mut upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/octet-stream"),
        chunks: vec![response_data.clone()],
        trailers: response_trailers.clone(),
        declare_trailers: true,
        body_error_gate: None,
    })
    .await;
    let identity = identity();
    let gateway = start_gateway(upstream.address, &identity).await;
    let (mut sender, _driver) = h2_client(gateway.address, &identity).await;

    let request_data = Bytes::from_static(b"request-data");
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert(
        "x-request-checksum",
        HeaderValue::from_static("sha256:test"),
    );
    let request = Request::builder()
        .method("POST")
        .uri("https://gateway.example.test/frames")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::TE, "trailers")
        .body(FrameBody::new([
            Frame::data(request_data.clone()),
            Frame::trailers(request_trailers.clone()),
        ]))
        .expect("HTTP/2 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("response head crosses the proxy");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    let (response_chunks, observed_trailers) = collect_frames(response.into_body())
        .await
        .expect("response stream is readable");
    assert_eq!(response_chunks.concat(), response_data);
    assert_eq!(observed_trailers.as_ref(), Some(&response_trailers));

    let observed = tokio::time::timeout(Duration::from_secs(1), upstream.observed.recv())
        .await
        .expect("upstream observes the request")
        .expect("observation channel remains open");
    assert_eq!(observed.version, Version::HTTP_2);
    assert_eq!(
        observed.te.as_ref().and_then(|value| value.to_str().ok()),
        Some("trailers")
    );
    assert_eq!(observed.data, request_data);
    assert_eq!(observed.trailers.as_ref(), Some(&request_trailers));

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn grpc_data_and_status_trailers_are_forwarded_without_interpretation() {
    let first_response = grpc_message(b"first response");
    let second_response = grpc_message(b"second response");
    let response_trailers = grpc_trailers("0", "all%20done");
    let mut upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/grpc"),
        chunks: vec![first_response.clone(), second_response.clone()],
        trailers: response_trailers.clone(),
        declare_trailers: true,
        body_error_gate: None,
    })
    .await;
    let identity = identity();
    let gateway = start_gateway(upstream.address, &identity).await;
    let (mut sender, _driver) = h2_client(gateway.address, &identity).await;

    let request_message = grpc_message(b"opaque protobuf request");
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-grpc-request-end", HeaderValue::from_static("true"));
    let request = Request::builder()
        .method("POST")
        .uri("https://gateway.example.test/example.Echo/Stream")
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .body(FrameBody::new([
            Frame::data(request_message.clone()),
            Frame::trailers(request_trailers.clone()),
        ]))
        .expect("gRPC request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("gRPC response head crosses the proxy");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/grpc");
    let (response_chunks, observed_trailers) = collect_frames(response.into_body())
        .await
        .expect("gRPC response stream is readable");
    assert_eq!(
        response_chunks.concat(),
        [first_response, second_response].concat()
    );
    assert_eq!(observed_trailers.as_ref(), Some(&response_trailers));

    let observed = tokio::time::timeout(Duration::from_secs(1), upstream.observed.recv())
        .await
        .expect("gRPC upstream observes the request")
        .expect("observation channel remains open");
    assert_eq!(observed.version, Version::HTTP_2);
    assert_eq!(
        observed
            .content_type
            .as_ref()
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc")
    );
    assert_eq!(observed.data, request_message);
    assert_eq!(observed.trailers.as_ref(), Some(&request_trailers));

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn http1_chunked_request_trailers_cross_to_http2_upstream() {
    let mut upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/octet-stream"),
        chunks: vec![Bytes::from_static(b"accepted")],
        trailers: HeaderMap::new(),
        declare_trailers: false,
        body_error_gate: None,
    })
    .await;
    let gateway = start_http1_gateway(upstream.address).await;
    let (mut sender, _driver) = h1_client(gateway.address).await;

    let request_data = Bytes::from_static(b"chunked-request-data");
    let mut request_trailers = HeaderMap::new();
    request_trailers.insert("x-request-checksum", HeaderValue::from_static("verified"));
    let request = Request::builder()
        .method("POST")
        .uri("/upload")
        .header(header::HOST, "gateway.example.test")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::TE, "trailers")
        .header(header::TRAILER, "x-request-checksum")
        .body(FrameBody::new([
            Frame::data(request_data.clone()),
            Frame::trailers(request_trailers.clone()),
        ]))
        .expect("HTTP/1 chunked request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/1 response head arrives");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .into_body()
        .collect()
        .await
        .expect("HTTP/1 response body completes");

    let observed = tokio::time::timeout(Duration::from_secs(1), upstream.observed.recv())
        .await
        .expect("upstream observes the bridged request")
        .expect("observation channel remains open");
    assert_eq!(observed.version, Version::HTTP_2);
    assert_eq!(observed.data, request_data);
    assert_eq!(observed.trailers.as_ref(), Some(&request_trailers));
    assert_eq!(
        observed.te.as_ref().and_then(|value| value.to_str().ok()),
        Some("trailers")
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn declared_http2_response_trailers_cross_to_accepting_http1_client() {
    let response_data = Bytes::from_static(b"response-with-trailers");
    let response_trailers = grpc_trailers("0", "complete");
    let upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/grpc"),
        chunks: vec![response_data.clone()],
        trailers: response_trailers.clone(),
        declare_trailers: true,
        body_error_gate: None,
    })
    .await;
    let gateway = start_http1_gateway(upstream.address).await;
    let (mut sender, _driver) = h1_client(gateway.address).await;

    let request = Request::builder()
        .uri("/grpc")
        .header(header::HOST, "gateway.example.test")
        .header(header::TE, "trailers")
        .body(FrameBody::new([]))
        .expect("HTTP/1 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/1 response head arrives");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(
        response.headers()[header::TRAILER],
        "grpc-message, grpc-status"
    );
    assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
    let collected = response
        .into_body()
        .collect()
        .await
        .expect("declared HTTP/1 trailer stream completes");
    assert_eq!(collected.trailers(), Some(&response_trailers));
    assert_eq!(collected.to_bytes(), response_data);

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn undeclared_http2_trailers_fail_http1_exchange_instead_of_being_dropped() {
    let response_data = Bytes::from_static(b"partial-before-undeclared-trailer");
    let upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/grpc"),
        chunks: vec![response_data],
        trailers: grpc_trailers("0", "must-not-be-silently-dropped"),
        declare_trailers: false,
        body_error_gate: None,
    })
    .await;
    let gateway = start_http1_gateway(upstream.address).await;
    let response = raw_http1_request(
        gateway.address,
        b"GET /grpc HTTP/1.1\r\nHost: gateway.example.test\r\nTE: trailers\r\nConnection: close\r\n\r\n",
    )
    .await;
    let response = String::from_utf8(response).expect("wire response head and DATA are UTF-8");
    assert!(
        response.is_empty() || response.starts_with("HTTP/1.1 200 OK\r\n"),
        "the HTTP/1 driver may reject before flushing the head or truncate after it: {response:?}"
    );
    assert!(!response.contains("502 Bad Gateway"), "{response:?}");
    assert!(!response.contains("grpc-status"), "{response:?}");
    assert!(
        !response.ends_with("0\r\n\r\n"),
        "the body must end with incomplete chunked framing, not silent success: {response:?}"
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn upstream_failure_after_response_head_remains_a_body_error_not_502() {
    let response_data = Bytes::from_static(b"partial-response-data");
    let body_error_gate = Arc::new(Notify::new());
    let upstream = spawn_h2_upstream(ResponsePlan {
        content_type: HeaderValue::from_static("application/octet-stream"),
        chunks: vec![response_data.clone()],
        trailers: HeaderMap::new(),
        declare_trailers: false,
        body_error_gate: Some(body_error_gate.clone()),
    })
    .await;
    let identity = identity();
    let gateway = start_gateway(upstream.address, &identity).await;
    let (mut sender, _driver) = h2_client(gateway.address, &identity).await;

    let request = Request::builder()
        .uri("https://gateway.example.test/disconnect")
        .body(FrameBody::new([]))
        .expect("HTTP/2 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("the already-produced response head must arrive");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "head must not become 502"
    );
    let mut body = response.into_body();
    let first = body
        .frame()
        .await
        .expect("partial DATA frame arrives")
        .expect("partial DATA frame is valid")
        .into_data()
        .expect("first frame is DATA");
    assert_eq!(first, response_data);
    body_error_gate.notify_one();
    body.frame()
        .await
        .expect("stream produces an error after the partial DATA")
        .expect_err("upstream reset must remain a downstream body error");

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}
