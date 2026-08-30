use std::convert::Infallible;
use std::future::Future as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{BufMut as _, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client_http2;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, ReloadHandle};
use tempfile::tempdir;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::common::{
    Fixture, ResourceMonitor, TestIdentity, XorShift64, client_config, identity, write_identity,
};
use crate::{Arguments, CampaignParameters, CampaignSummary, SoakError};

type FixtureBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    successes: AtomicU64,
    errors: AtomicU64,
    bytes: AtomicU64,
    reloads: AtomicU64,
    rotations: AtomicU64,
    grpc: AtomicU64,
    websocket: AtomicU64,
}

struct GrpcBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
    trailer_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl GrpcBody {
    fn new(payload_size: usize) -> Result<Self, SoakError> {
        let message_length = u32::try_from(payload_size).map_err(|_| {
            SoakError::message("protocol payload_size exceeds the gRPC u32 message limit")
        })?;
        let mut data = BytesMut::with_capacity(payload_size.saturating_add(5));
        data.put_u8(0);
        data.put_u32(message_length);
        data.resize(payload_size.saturating_add(5), b'g');
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers.insert("grpc-message", HeaderValue::from_static("ok"));
        Ok(Self {
            data: Some(data.freeze()),
            trailers: Some(trailers),
            trailer_delay: None,
        })
    }
}

impl Body for GrpcBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(data) = self.data.take() {
            self.trailer_delay = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(delay) = &mut self.trailer_delay {
            if delay.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.trailer_delay = None;
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        self.data.as_ref().map_or_else(SizeHint::default, |data| {
            SizeHint::with_exact(u64::try_from(data.len()).unwrap_or(u64::MAX))
        })
    }
}

fn boxed_full(bytes: impl Into<Bytes>) -> FixtureBody {
    Full::new(bytes.into()).boxed_unsync()
}

async fn spawn_grpc_upstream(payload_size: usize) -> Result<(SocketAddr, Fixture), SoakError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| SoakError::message(format!("bind gRPC fixture: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| SoakError::message(format!("read gRPC fixture address: {error}")))?;
    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    connections.spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| async move {
                            let is_grpc = request
                                .headers()
                                .get(header::CONTENT_TYPE)
                                .is_some_and(|value| value.as_bytes().starts_with(b"application/grpc"));
                            let _ = request.into_body().collect().await;
                            if !is_grpc {
                                let mut response = Response::new(boxed_full("not grpc"));
                                *response.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                                return Ok::<_, Infallible>(response);
                            }
                            let body = match GrpcBody::new(payload_size) {
                                Ok(body) => body.boxed_unsync(),
                                Err(_) => boxed_full(Bytes::new()),
                            };
                            let mut response = Response::new(body);
                            response.headers_mut().insert(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/grpc"),
                            );
                            Ok(response)
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
    Ok((address, Fixture::new(shutdown, task)))
}

async fn read_http1_head<I>(io: &mut I) -> Result<String, SoakError>
where
    I: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = io
            .read(&mut byte)
            .await
            .map_err(|error| SoakError::message(format!("read HTTP/1 head: {error}")))?;
        if read == 0 {
            return Err(SoakError::message(
                "connection closed before HTTP/1 head completed",
            ));
        }
        bytes.push(byte[0]);
        if bytes.len() > 64 * 1024 {
            return Err(SoakError::message("HTTP/1 head exceeded 64 KiB"));
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return String::from_utf8(bytes)
                .map_err(|error| SoakError::message(format!("HTTP/1 head is not UTF-8: {error}")));
        }
    }
}

async fn spawn_websocket_upstream() -> Result<(SocketAddr, Fixture), SoakError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| SoakError::message(format!("bind Upgrade fixture: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| SoakError::message(format!("read Upgrade fixture address: {error}")))?;
    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    connections.spawn(async move {
                        let Ok(head) = read_http1_head(&mut stream).await else { return };
                        let lower = head.to_ascii_lowercase();
                        if !lower.contains("connection: upgrade\r\n")
                            || !lower.contains("upgrade: websocket\r\n")
                        {
                            return;
                        }
                        if stream
                            .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let mut buffer = vec![0u8; 16 * 1024];
                        while let Ok(read) = stream.read(&mut buffer).await {
                            if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Ok((address, Fixture::new(shutdown, task)))
}

fn gateway_source(grpc: SocketAddr, websocket: SocketAddr, generation: u64) -> String {
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    gateway:
      cert_chain: gateway.pem
      private_key: gateway-key.pem
  clusters:
    grpc:
      protocol: h2
      endpoints:
        - http://{grpc}
      connect_timeout: 1s
      response_timeout: 2s
    websocket:
      protocol: http1
      endpoints:
        - http://{websocket}
      connect_timeout: 1s
      response_timeout: 2s
services:
  grpc:
    type: observe
    name: grpc-soak-{generation_mod}
    service:
      type: proxy
      cluster: grpc
  websocket:
    type: proxy
    cluster: websocket
listeners:
  - name: grpc
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: gateway
    http:
      versions: [h2]
      http2:
        max_concurrent_streams: 256
        max_header_list_size: 64KiB
        keep_alive_interval: 5s
        keep_alive_timeout: 2s
    service:
      ref: grpc
  - name: websocket
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: gateway
    http:
      versions: [http1]
      http1:
        header_read_timeout: 10s
    service:
      ref: websocket
"#,
        generation_mod = generation % 2,
    )
}

async fn write_gateway(
    path: &Path,
    grpc: SocketAddr,
    websocket: SocketAddr,
    generation: u64,
) -> Result<(), SoakError> {
    tokio::fs::write(path, gateway_source(grpc, websocket, generation))
        .await
        .map_err(|error| SoakError::message(format!("write protocol gateway config: {error}")))
}

async fn connect_tls(
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SoakError> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| SoakError::message(format!("connect protocol listener: {error}")))?;
    let name = ServerName::try_from("gateway.example.test".to_owned())
        .map_err(|error| SoakError::message(format!("build test server name: {error}")))?;
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|error| SoakError::message(format!("protocol TLS handshake: {error}")))
}

async fn grpc_request(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    payload_size: usize,
    cancel: bool,
) -> Result<(u64, bool), SoakError> {
    let tls = connect_tls(address, config).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(SoakError::message("gRPC campaign negotiated wrong ALPN"));
    }
    let (mut sender, connection) = client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .map_err(|error| SoakError::message(format!("gRPC H2 handshake: {error}")))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let message_length = u32::try_from(payload_size)
        .map_err(|_| SoakError::message("payload_size exceeds gRPC u32 message limit"))?;
    let mut message = BytesMut::with_capacity(payload_size.saturating_add(5));
    message.put_u8(0);
    message.put_u32(message_length);
    message.resize(payload_size.saturating_add(5), b'q');
    let request = Request::builder()
        .method("POST")
        .uri("https://gateway.example.test/soak.Service/Stream")
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .body(Full::new(message.freeze()))
        .map_err(|error| SoakError::message(format!("build gRPC request: {error}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| SoakError::message(format!("send gRPC request: {error}")))?;
    if response.status() != StatusCode::OK {
        driver.abort();
        return Err(SoakError::message(format!(
            "gRPC response status {}",
            response.status()
        )));
    }
    let mut body = response.into_body();
    let mut bytes = 0u64;
    let mut grpc_status = None;
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|error| SoakError::message(format!("read gRPC response frame: {error}")))?;
        if let Some(data) = frame.data_ref() {
            bytes = bytes.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
            if cancel {
                drop(body);
                driver.abort();
                return Ok((bytes, true));
            }
        }
        if let Some(trailers) = frame.trailers_ref() {
            grpc_status = trailers
                .get("grpc-status")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
        }
    }
    driver.abort();
    if grpc_status.as_deref() != Some("0") {
        return Err(SoakError::message("gRPC response lost grpc-status trailer"));
    }
    Ok((bytes, false))
}

async fn websocket_request(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    payload_size: usize,
) -> Result<u64, SoakError> {
    let mut tls = connect_tls(address, config).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(SoakError::message(
            "WebSocket campaign negotiated wrong ALPN",
        ));
    }
    tls.write_all(
        b"GET /tunnel HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await
    .map_err(|error| SoakError::message(format!("write Upgrade request: {error}")))?;
    let head = read_http1_head(&mut tls).await?;
    if !head.starts_with("HTTP/1.1 101") {
        return Err(SoakError::message(format!(
            "Upgrade response was not 101: {}",
            head.lines().next().unwrap_or("empty response")
        )));
    }
    let payload = vec![0x5A; payload_size];
    tls.write_all(&payload)
        .await
        .map_err(|error| SoakError::message(format!("write tunnel bytes: {error}")))?;
    let mut echoed = vec![0; payload_size];
    tls.read_exact(&mut echoed)
        .await
        .map_err(|error| SoakError::message(format!("read tunnel echo: {error}")))?;
    if echoed != payload {
        return Err(SoakError::message("Upgrade tunnel changed payload bytes"));
    }
    tls.shutdown()
        .await
        .map_err(|error| SoakError::message(format!("close tunnel: {error}")))?;
    Ok(u64::try_from(echoed.len()).unwrap_or(u64::MAX))
}

struct WorkerPlan {
    grpc_address: SocketAddr,
    websocket_address: SocketAddr,
    h2: Arc<ClientConfig>,
    h1: Arc<ClientConfig>,
    payload_size: usize,
    deadline: Instant,
    seed: u64,
    counters: Arc<Counters>,
}

async fn worker(plan: WorkerPlan) {
    let mut random = XorShift64::new(plan.seed);
    let mut grpc_cancellation_pending = true;
    while Instant::now() < plan.deadline {
        let value = random.next();
        plan.counters.requests.fetch_add(1, Ordering::Relaxed);
        if value & 1 == 0 {
            plan.counters.grpc.fetch_add(1, Ordering::Relaxed);
            let cancel = grpc_cancellation_pending || value.is_multiple_of(17);
            grpc_cancellation_pending = false;
            match grpc_request(
                plan.grpc_address,
                Arc::clone(&plan.h2),
                plan.payload_size,
                cancel,
            )
            .await
            {
                Ok((bytes, _)) => {
                    plan.counters.successes.fetch_add(1, Ordering::Relaxed);
                    plan.counters.bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                Err(_) => {
                    plan.counters.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            plan.counters.websocket.fetch_add(1, Ordering::Relaxed);
            match websocket_request(
                plan.websocket_address,
                Arc::clone(&plan.h1),
                plan.payload_size,
            )
            .await
            {
                Ok(bytes) => {
                    plan.counters.successes.fetch_add(1, Ordering::Relaxed);
                    plan.counters.bytes.fetch_add(bytes, Ordering::Relaxed);
                }
                Err(_) => {
                    plan.counters.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

struct RotationPlan {
    config: PathBuf,
    directory: PathBuf,
    grpc: SocketAddr,
    websocket: SocketAddr,
    identities: [Arc<TestIdentity>; 2],
    reload: ReloadHandle,
    interval: Duration,
    deadline: Instant,
    counters: Arc<Counters>,
}

async fn rotate_and_reload(plan: RotationPlan) {
    let mut generation = 1u64;
    loop {
        tokio::time::sleep(plan.interval).await;
        if Instant::now() >= plan.deadline {
            break;
        }
        let identity = &plan.identities[usize::try_from(generation % 2).unwrap_or(0)];
        let certificate = tokio::fs::write(
            plan.directory.join("gateway.pem"),
            &identity.certificate_pem,
        )
        .await;
        let key = tokio::fs::write(
            plan.directory.join("gateway-key.pem"),
            &identity.private_key_pem,
        )
        .await;
        let config = write_gateway(&plan.config, plan.grpc, plan.websocket, generation).await;
        if certificate.is_ok()
            && key.is_ok()
            && config.is_ok()
            && plan.reload.reload_path(&plan.config).await.is_ok()
        {
            plan.counters.reloads.fetch_add(1, Ordering::Relaxed);
            plan.counters.rotations.fetch_add(1, Ordering::Relaxed);
        } else {
            plan.counters.errors.fetch_add(1, Ordering::Relaxed);
        }
        generation = generation.saturating_add(1);
    }
}

async fn body_cancellations(address: SocketAddr) -> Result<u64, SoakError> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| SoakError::message(format!("connect admin listener: {error}")))?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| SoakError::message(format!("write metrics request: {error}")))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .map_err(|error| SoakError::message(format!("read metrics response: {error}")))?;
    Ok(response
        .lines()
        .find(|line| {
            line.starts_with("oxidase_response_body_terminations_total{reason=\"cancelled\"}")
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0))
}

pub(crate) async fn run(arguments: Arguments) -> Result<CampaignSummary, SoakError> {
    let first_identity = Arc::new(identity()?);
    let second_identity = Arc::new(identity()?);
    let directory = tempdir()
        .map_err(|error| SoakError::message(format!("create protocol directory: {error}")))?;
    write_identity(directory.path(), &first_identity)?;

    let (grpc_upstream, grpc_fixture) = spawn_grpc_upstream(arguments.payload_size).await?;
    let (websocket_upstream, websocket_fixture) = spawn_websocket_upstream().await?;
    let config = directory.path().join("oxidase.yaml");
    write_gateway(&config, grpc_upstream, websocket_upstream, 0).await?;
    let compiled = Compiler::compile_path(&config)
        .map_err(|error| SoakError::message(format!("compile protocol gateway: {error}")))?;
    let snapshot = RuntimeSnapshot::prepare(compiled)
        .map_err(|error| SoakError::message(format!("prepare protocol gateway: {error}")))?;
    let server = GatewayServer::bind(snapshot)
        .await
        .map_err(|error| SoakError::message(format!("bind protocol gateway: {error}")))?
        .with_admin_listener(
            "127.0.0.1:0"
                .parse()
                .map_err(|error| SoakError::message(format!("parse admin address: {error}")))?,
        )
        .await
        .map_err(|error| SoakError::message(format!("bind admin listener: {error}")))?;
    let running = server.spawn();
    let grpc_address = running
        .local_addresses()
        .iter()
        .find(|(name, _)| name == "grpc")
        .map(|(_, address)| *address)
        .ok_or_else(|| SoakError::message("gRPC listener address missing"))?;
    let websocket_address = running
        .local_addresses()
        .iter()
        .find(|(name, _)| name == "websocket")
        .map(|(_, address)| *address)
        .ok_or_else(|| SoakError::message("WebSocket listener address missing"))?;
    let admin = running
        .admin_address()
        .ok_or_else(|| SoakError::message("protocol admin address missing"))?;
    let h2 = client_config(&[&first_identity, &second_identity], &[b"h2"])?;
    let h1 = client_config(&[&first_identity, &second_identity], &[b"http/1.1"])?;

    // Warm both bridges before recording the resource baseline.
    let _ = grpc_request(grpc_address, Arc::clone(&h2), arguments.payload_size, false).await?;
    let _ = websocket_request(websocket_address, Arc::clone(&h1), arguments.payload_size).await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let monitor = ResourceMonitor::start();
    let started = Instant::now();
    let deadline = started + arguments.duration;
    let counters = Arc::new(Counters::default());
    let rotation = tokio::spawn(rotate_and_reload(RotationPlan {
        config: config.clone(),
        directory: directory.path().to_path_buf(),
        grpc: grpc_upstream,
        websocket: websocket_upstream,
        identities: [Arc::clone(&first_identity), Arc::clone(&second_identity)],
        reload: running.reload_handle(),
        interval: arguments.reload_interval,
        deadline,
        counters: Arc::clone(&counters),
    }));
    let mut workers = tokio::task::JoinSet::new();
    for worker_index in 0..arguments.concurrency {
        workers.spawn(worker(WorkerPlan {
            grpc_address,
            websocket_address,
            h2: Arc::clone(&h2),
            h1: Arc::clone(&h1),
            payload_size: arguments.payload_size,
            deadline,
            seed: arguments.seed
                ^ u64::try_from(worker_index)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0xD1B5_4A32),
            counters: Arc::clone(&counters),
        }));
    }
    while workers.join_next().await.is_some() {}
    let _ = rotation.await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let cancellations = body_cancellations(admin).await?;
    running
        .shutdown()
        .await
        .map_err(|error| SoakError::message(format!("shutdown protocol gateway: {error}")))?;
    grpc_fixture.shutdown().await;
    websocket_fixture.shutdown().await;
    let process = monitor.finish().await;

    Ok(CampaignSummary {
        schema_version: "oxidase.soak/v1",
        parameters: CampaignParameters::from(&arguments),
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        requests: counters.requests.load(Ordering::Relaxed),
        successes: counters.successes.load(Ordering::Relaxed),
        errors: counters.errors.load(Ordering::Relaxed),
        retries: 0,
        health_transitions: 0,
        body_cancellations: cancellations,
        bytes: counters.bytes.load(Ordering::Relaxed),
        reloads: counters.reloads.load(Ordering::Relaxed),
        certificate_rotations: counters.rotations.load(Ordering::Relaxed),
        http1_requests: counters.websocket.load(Ordering::Relaxed),
        http2_requests: counters.grpc.load(Ordering::Relaxed),
        grpc_requests: counters.grpc.load(Ordering::Relaxed),
        websocket_tunnels: counters.websocket.load(Ordering::Relaxed),
        process,
    })
}
