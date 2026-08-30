use std::convert::Infallible;
use std::future::Future as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt as _, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, ReloadHandle};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::common::{
    Fixture, ResourceMonitor, TestIdentity, XorShift64, client_config, identity, metric_sum,
    write_identity,
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
    http1: AtomicU64,
    http2: AtomicU64,
}

struct ChunkBody {
    remaining: usize,
    chunk_size: usize,
    fill: u8,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl ChunkBody {
    fn new(length: usize, fill: u8) -> Self {
        Self {
            remaining: length,
            chunk_size: 1024,
            fill,
            delay: None,
        }
    }
}

impl Body for ChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(delay) = &mut self.delay {
            if delay.as_mut().poll(context).is_pending() {
                return Poll::Pending;
            }
            self.delay = None;
        }
        if self.remaining == 0 {
            return Poll::Ready(None);
        }
        let length = self.remaining.min(self.chunk_size);
        self.remaining -= length;
        if self.remaining > 0 {
            self.delay = Some(Box::pin(tokio::time::sleep(Duration::from_millis(10))));
        }
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![self.fill; length])))))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(u64::try_from(self.remaining).unwrap_or(u64::MAX))
    }
}

fn full_body(bytes: impl Into<Bytes>) -> FixtureBody {
    Full::new(bytes.into()).boxed_unsync()
}

fn response(status: StatusCode, body: FixtureBody) -> Response<FixtureBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

async fn spawn_endpoint(
    healthy: Arc<AtomicBool>,
    flaky: bool,
    payload_size: usize,
) -> Result<(SocketAddr, Fixture), SoakError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| SoakError::message(format!("bind upstream fixture: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| SoakError::message(format!("read upstream address: {error}")))?;
    let attempts = Arc::new(AtomicU64::new(0));
    let (shutdown, mut shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_receiver => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let healthy = Arc::clone(&healthy);
                    let attempts = Arc::clone(&attempts);
                    connections.spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let healthy = Arc::clone(&healthy);
                            let attempts = Arc::clone(&attempts);
                            async move {
                                if request.uri().path() == "/healthz" {
                                    let status = if healthy.load(Ordering::Relaxed) {
                                        StatusCode::NO_CONTENT
                                    } else {
                                        StatusCode::SERVICE_UNAVAILABLE
                                    };
                                    return Ok::<_, Infallible>(response(status, full_body(Bytes::new())));
                                }
                                let attempt = attempts.fetch_add(1, Ordering::Relaxed);
                                if flaky
                                    && (!healthy.load(Ordering::Relaxed)
                                        || attempt.is_multiple_of(5))
                                {
                                    return Ok(response(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        full_body("retryable"),
                                    ));
                                }
                                Ok(response(
                                    StatusCode::OK,
                                    ChunkBody::new(payload_size, if flaky { b'a' } else { b'b' })
                                        .boxed_unsync(),
                                ))
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
    Ok((address, Fixture::new(shutdown, task)))
}

fn gateway_source(first: SocketAddr, second: SocketAddr, generation: u64) -> String {
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    gateway:
      cert_chain: gateway.pem
      private_key: gateway-key.pem
  clusters:
    upstream:
      protocol: http1
      endpoints:
        - name: unstable
          url: http://{first}
          weight: 2
        - name: stable
          url: http://{second}
          weight: 1
      load_balance:
        policy: weighted_round_robin
      health:
        active:
          path: /healthz
          interval: 200ms
          timeout: 100ms
          healthy_statuses: ["200-299"]
          healthy_threshold: 1
          unhealthy_threshold: 1
        passive:
          consecutive_failures: 2
          eject_for: 1s
      retry:
        max_attempts: 2
        methods: [GET, HEAD]
        retry_on: [connect_failure, response_header_timeout, refused_stream, reset]
        statuses: [503]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 32
      limits:
        max_in_flight: 1024
        max_in_flight_per_endpoint: 512
        queue_timeout: 50ms
      connect_timeout: 1s
      response_timeout: 2s
services:
  root:
    type: observe
    name: soak-{generation_mod}
    service:
      type: proxy
      cluster: upstream
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: gateway
      handshake_timeout: 2s
    http:
      versions: [h2, http1]
      http1:
        header_read_timeout: 10s
      http2:
        max_concurrent_streams: 256
        max_header_list_size: 64KiB
        keep_alive_interval: 5s
        keep_alive_timeout: 2s
    service:
      ref: root
"#,
        generation_mod = generation % 2,
    )
}

async fn write_gateway(
    path: &Path,
    first: SocketAddr,
    second: SocketAddr,
    generation: u64,
) -> Result<(), SoakError> {
    tokio::fs::write(path, gateway_source(first, second, generation))
        .await
        .map_err(|error| SoakError::message(format!("write soak gateway config: {error}")))
}

async fn connect_tls(
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, SoakError> {
    let tcp = TcpStream::connect(address)
        .await
        .map_err(|error| SoakError::message(format!("connect TLS listener: {error}")))?;
    let name = ServerName::try_from("gateway.example.test".to_owned())
        .map_err(|error| SoakError::message(format!("build test server name: {error}")))?;
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .map_err(|error| SoakError::message(format!("TLS handshake: {error}")))
}

struct RequestOutcome {
    bytes: u64,
    cancelled: bool,
}

async fn request_http1(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    cancel: bool,
) -> Result<RequestOutcome, SoakError> {
    let tls = connect_tls(address, config).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"http/1.1".as_slice()) {
        return Err(SoakError::message("HTTP/1 campaign negotiated wrong ALPN"));
    }
    let (mut sender, connection) = client_http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|error| SoakError::message(format!("HTTP/1 handshake: {error}")))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .uri("/payload?stable=wire&order=preserved")
        .header(header::HOST, "gateway.example.test")
        .body(Empty::<Bytes>::new())
        .map_err(|error| SoakError::message(format!("build HTTP/1 request: {error}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| SoakError::message(format!("send HTTP/1 request: {error}")))?;
    if response.status() != StatusCode::OK {
        driver.abort();
        return Err(SoakError::message(format!(
            "HTTP/1 response status {}",
            response.status()
        )));
    }
    let outcome = read_or_cancel(response.into_body(), cancel).await?;
    drop(sender);
    driver.abort();
    Ok(outcome)
}

async fn request_http2(
    address: SocketAddr,
    config: Arc<ClientConfig>,
    cancel: bool,
) -> Result<RequestOutcome, SoakError> {
    let tls = connect_tls(address, config).await?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(SoakError::message("HTTP/2 campaign negotiated wrong ALPN"));
    }
    let (mut sender, connection) = client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .map_err(|error| SoakError::message(format!("HTTP/2 handshake: {error}")))?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .uri("https://gateway.example.test/payload?stable=wire&order=preserved")
        .body(Empty::<Bytes>::new())
        .map_err(|error| SoakError::message(format!("build HTTP/2 request: {error}")))?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| SoakError::message(format!("send HTTP/2 request: {error}")))?;
    if response.status() != StatusCode::OK {
        driver.abort();
        return Err(SoakError::message(format!(
            "HTTP/2 response status {}",
            response.status()
        )));
    }
    let outcome = read_or_cancel(response.into_body(), cancel).await?;
    drop(sender);
    driver.abort();
    Ok(outcome)
}

async fn read_or_cancel(mut body: Incoming, cancel: bool) -> Result<RequestOutcome, SoakError> {
    if cancel {
        let bytes = match body.frame().await {
            Some(Ok(frame)) => frame
                .into_data()
                .map_or(0, |data| u64::try_from(data.len()).unwrap_or(u64::MAX)),
            Some(Err(error)) => {
                return Err(SoakError::message(format!(
                    "read first response frame: {error}"
                )));
            }
            None => 0,
        };
        drop(body);
        return Ok(RequestOutcome {
            bytes,
            cancelled: true,
        });
    }
    let bytes = body
        .collect()
        .await
        .map_err(|error| SoakError::message(format!("collect response body: {error}")))?
        .to_bytes();
    Ok(RequestOutcome {
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        cancelled: false,
    })
}

async fn request_worker(
    address: SocketAddr,
    h1: Arc<ClientConfig>,
    h2: Arc<ClientConfig>,
    deadline: Instant,
    seed: u64,
    counters: Arc<Counters>,
) {
    let mut random = XorShift64::new(seed);
    while Instant::now() < deadline {
        let value = random.next();
        let use_h2 = value & 1 == 0;
        let cancel = value.is_multiple_of(11);
        counters.requests.fetch_add(1, Ordering::Relaxed);
        if use_h2 {
            counters.http2.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.http1.fetch_add(1, Ordering::Relaxed);
        }
        let request = if use_h2 {
            request_http2(address, Arc::clone(&h2), cancel).await
        } else {
            request_http1(address, Arc::clone(&h1), cancel).await
        };
        match request {
            Ok(outcome) => {
                counters.successes.fetch_add(1, Ordering::Relaxed);
                counters.bytes.fetch_add(outcome.bytes, Ordering::Relaxed);
                if outcome.cancelled {
                    tokio::task::yield_now().await;
                }
            }
            Err(_) => {
                counters.errors.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

struct RotationPlan {
    config: PathBuf,
    directory: PathBuf,
    first: SocketAddr,
    second: SocketAddr,
    identities: [Arc<TestIdentity>; 2],
    unhealthy: Arc<AtomicBool>,
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
        plan.unhealthy
            .store(generation.is_multiple_of(2), Ordering::Relaxed);
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
        let config = write_gateway(&plan.config, plan.first, plan.second, generation).await;
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

async fn admin_metrics(address: SocketAddr) -> Result<String, SoakError> {
    let mut stream = TcpStream::connect(address)
        .await
        .map_err(|error| SoakError::message(format!("connect admin listener: {error}")))?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|error| SoakError::message(format!("write admin request: {error}")))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|error| SoakError::message(format!("read admin response: {error}")))?;
    let response = String::from_utf8(response)
        .map_err(|error| SoakError::message(format!("admin response is not UTF-8: {error}")))?;
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .ok_or_else(|| SoakError::message("admin response did not contain a complete head"))
}

pub(crate) async fn run(arguments: Arguments) -> Result<CampaignSummary, SoakError> {
    let first_identity = Arc::new(identity()?);
    let second_identity = Arc::new(identity()?);
    let directory =
        tempdir().map_err(|error| SoakError::message(format!("create soak directory: {error}")))?;
    write_identity(directory.path(), &first_identity)?;

    let unstable_healthy = Arc::new(AtomicBool::new(true));
    let (first, first_fixture) =
        spawn_endpoint(Arc::clone(&unstable_healthy), true, arguments.payload_size).await?;
    let (second, second_fixture) = spawn_endpoint(
        Arc::new(AtomicBool::new(true)),
        false,
        arguments.payload_size,
    )
    .await?;
    let config = directory.path().join("oxidase.yaml");
    write_gateway(&config, first, second, 0).await?;

    let compiled = Compiler::compile_path(&config)
        .map_err(|error| SoakError::message(format!("compile soak gateway: {error}")))?;
    let snapshot = RuntimeSnapshot::prepare(compiled)
        .map_err(|error| SoakError::message(format!("prepare soak gateway: {error}")))?;
    let server = GatewayServer::bind(snapshot)
        .await
        .map_err(|error| SoakError::message(format!("bind soak gateway: {error}")))?
        .with_admin_listener(
            "127.0.0.1:0"
                .parse()
                .map_err(|error| SoakError::message(format!("parse admin address: {error}")))?,
        )
        .await
        .map_err(|error| SoakError::message(format!("bind admin listener: {error}")))?;
    let running = server.spawn();
    let address = running
        .local_addresses()
        .first()
        .map(|(_, address)| *address)
        .ok_or_else(|| SoakError::message("gateway exposed no listener address"))?;
    let admin = running
        .admin_address()
        .ok_or_else(|| SoakError::message("gateway exposed no admin address"))?;

    let h1 = client_config(&[&first_identity, &second_identity], &[b"http/1.1"])?;
    let h2 = client_config(&[&first_identity, &second_identity], &[b"h2"])?;

    // Warm both protocol drivers and the upstream pools before recording a baseline.
    let _ = request_http1(address, Arc::clone(&h1), false).await?;
    let _ = request_http2(address, Arc::clone(&h2), false).await?;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let monitor = ResourceMonitor::start();
    let started = Instant::now();
    let deadline = started + arguments.duration;
    let counters = Arc::new(Counters::default());
    let rotation = tokio::spawn(rotate_and_reload(RotationPlan {
        config: config.clone(),
        directory: directory.path().to_path_buf(),
        first,
        second,
        identities: [Arc::clone(&first_identity), Arc::clone(&second_identity)],
        unhealthy: Arc::clone(&unstable_healthy),
        reload: running.reload_handle(),
        interval: arguments.reload_interval,
        deadline,
        counters: Arc::clone(&counters),
    }));

    let mut workers = tokio::task::JoinSet::new();
    for worker in 0..arguments.concurrency {
        workers.spawn(request_worker(
            address,
            Arc::clone(&h1),
            Arc::clone(&h2),
            deadline,
            arguments.seed
                ^ u64::try_from(worker)
                    .unwrap_or(u64::MAX)
                    .wrapping_mul(0x9E37_79B9),
            Arc::clone(&counters),
        ));
    }
    while workers.join_next().await.is_some() {}
    let _ = rotation.await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let metrics = admin_metrics(admin).await?;
    let retries = metric_sum(&metrics, "oxidase_cluster_retry_attempts_total{");
    let health_transitions = metric_sum(&metrics, "oxidase_cluster_health_transitions_total{");
    let cancellations = metrics
        .lines()
        .find(|line| {
            line.starts_with("oxidase_response_body_terminations_total{reason=\"cancelled\"}")
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);

    running
        .shutdown()
        .await
        .map_err(|error| SoakError::message(format!("shutdown gateway: {error}")))?;
    first_fixture.shutdown().await;
    second_fixture.shutdown().await;
    let process = monitor.finish().await;
    let elapsed = started.elapsed();

    Ok(CampaignSummary {
        schema_version: "oxidase.soak/v1",
        parameters: CampaignParameters::from(&arguments),
        elapsed_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        requests: counters.requests.load(Ordering::Relaxed),
        successes: counters.successes.load(Ordering::Relaxed),
        errors: counters.errors.load(Ordering::Relaxed),
        retries,
        health_transitions,
        body_cancellations: cancellations,
        bytes: counters.bytes.load(Ordering::Relaxed),
        reloads: counters.reloads.load(Ordering::Relaxed),
        certificate_rotations: counters.rotations.load(Ordering::Relaxed),
        http1_requests: counters.http1.load(Ordering::Relaxed),
        http2_requests: counters.http2.load(Ordering::Relaxed),
        grpc_requests: 0,
        websocket_tunnels: 0,
        process,
    })
}
