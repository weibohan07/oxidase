//! Real-wire coverage of phased upstream deadlines and full-duplex responses.
//!
//! Fixtures bind ephemeral loopback sockets. TLS keys are generated only for
//! these tests; request collection is confined to the bounded fixture payloads.

use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::client::conn::{http1 as client_http1, http2 as client_http2};
use hyper::server::conn::{http1 as server_http1, http2 as server_http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_core::ResourceId;
use oxidase_runtime::{PreparedCluster, RuntimeSnapshot};
use oxidase_server::{GatewayServer, RunningServer};
use tempfile::{TempDir, tempdir};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

type FixtureBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Http1,
    H2,
}

#[derive(Clone)]
enum Behavior {
    ReadThenReply { delay: Duration },
    Early(StatusCode),
    HeldResponse(Arc<Semaphore>),
}

#[derive(Debug)]
enum Observation {
    Head { authority: String, path: String },
    End(Bytes),
}

struct Upstream {
    address: SocketAddr,
    observed: mpsc::Receiver<Observation>,
    heads: Arc<AtomicUsize>,
    ends: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(bind: &str, protocol: Protocol, behavior: Behavior) -> Self {
        let listener = TcpListener::bind(bind)
            .await
            .expect("loopback upstream binds");
        let address = listener.local_addr().expect("bound address");
        let heads = Arc::new(AtomicUsize::new(0));
        let ends = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let (observed_tx, observed) = mpsc::channel(64);
        let (stop, mut stopping) = oneshot::channel();
        let task_heads = Arc::clone(&heads);
        let task_ends = Arc::clone(&ends);
        let task_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopping => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        task_connections.fetch_add(1, Ordering::Relaxed);
                        let observed = observed_tx.clone();
                        let heads = Arc::clone(&task_heads);
                        let ends = Arc::clone(&task_ends);
                        let behavior = behavior.clone();
                        tasks.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let observed = observed.clone();
                                let heads = Arc::clone(&heads);
                                let ends = Arc::clone(&ends);
                                let behavior = behavior.clone();
                                async move {
                                    heads.fetch_add(1, Ordering::Relaxed);
                                    let authority = request.uri().authority().map_or_else(
                                        || request.headers().get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or("").to_owned(),
                                        |authority| authority.as_str().to_owned(),
                                    );
                                    let path = request.uri().path_and_query().map_or("/", http::uri::PathAndQuery::as_str).to_owned();
                                    let _ = observed.send(Observation::Head { authority, path }).await;
                                    let response = match behavior {
                                        Behavior::Early(status) => Response::builder().status(status).body(Full::new(Bytes::from_static(b"early")).boxed_unsync()).expect("early response"),
                                        Behavior::HeldResponse(release) => Response::new(HeldBody::new(release).boxed_unsync()),
                                        Behavior::ReadThenReply { delay } => {
                                            let body = match request.into_body().collect().await {
                                                Ok(body) => body.to_bytes(),
                                                Err(_) => return Ok::<_, Infallible>(Response::builder().status(StatusCode::BAD_REQUEST).body(Full::new(Bytes::new()).boxed_unsync()).expect("body-error response")),
                                            };
                                            ends.fetch_add(1, Ordering::Relaxed);
                                            let _ = observed.send(Observation::End(body)).await;
                                            tokio::time::sleep(delay).await;
                                            Response::new(Full::new(Bytes::from_static(b"complete")).boxed_unsync())
                                        }
                                    };
                                    Ok::<Response<FixtureBody>, Infallible>(response)
                                }
                            });
                            match protocol {
                                Protocol::Http1 => { let _ = server_http1::Builder::new().serve_connection(TokioIo::new(stream), service).await; }
                                Protocol::H2 => { let _ = server_http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service).await; }
                            }
                        });
                    }
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        });
        Self {
            address,
            observed,
            heads,
            ends,
            connections,
            stop: Some(stop),
            task,
        }
    }

    async fn observation(&mut self) -> Observation {
        tokio::time::timeout(Duration::from_secs(3), self.observed.recv())
            .await
            .expect("fixture event deadline")
            .expect("fixture stays open")
    }

    async fn stop(mut self) {
        let _ = self.stop.take().expect("one stop").send(());
        self.task.await.expect("upstream exits");
    }
}

struct HeldBody {
    first: bool,
    released: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl HeldBody {
    fn new(release: Arc<Semaphore>) -> Self {
        Self {
            first: true,
            released: Box::pin(async move {
                let permit = release.acquire().await.expect("body gate");
                permit.forget();
            }),
        }
    }
}

impl Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if self.first {
            self.first = false;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"prefix")))));
        }
        self.released.as_mut().poll(context).map(|()| None)
    }
}

struct ChannelBody(mpsc::Receiver<Frame<Bytes>>);

impl ChannelBody {
    fn channel() -> (mpsc::Sender<Frame<Bytes>>, Self) {
        let (sender, receiver) = mpsc::channel(8);
        (sender, Self(receiver))
    }

    fn empty() -> Self {
        let (sender, body) = Self::channel();
        drop(sender);
        body
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(context).map(|frame| frame.map(Ok))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_closed() && self.0.is_empty()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct Gateway {
    _directory: TempDir,
    address: SocketAddr,
    protocol: Protocol,
    tls_client: Option<Arc<ClientConfig>>,
    cluster: Arc<PreparedCluster>,
    running: RunningServer,
}

impl Gateway {
    async fn start(protocol: Protocol, endpoints: &[String], timing: &str, policy: &str) -> Self {
        let directory = tempdir().expect("gateway directory");
        let (certificate_resources, listener, tls_client) = match protocol {
            Protocol::Http1 => (String::new(), "    protocol: http\n".to_owned(), None),
            Protocol::H2 => {
                // Ephemeral, public test-only material. Never production credentials.
                let generated = rcgen::generate_simple_self_signed(vec![
                    "deadline-gateway.example.test".to_owned(),
                ])
                .expect("generate test identity");
                fs::write(directory.path().join("cert.pem"), generated.cert.pem())
                    .expect("test cert writes");
                fs::write(
                    directory.path().join("key.pem"),
                    generated.signing_key.serialize_pem(),
                )
                .expect("test key writes");
                let mut roots = RootCertStore::empty();
                roots.add(generated.cert.der().clone()).expect("test trust");
                let mut client = ClientConfig::builder_with_provider(Arc::new(default_provider()))
                    .with_safe_default_protocol_versions()
                    .expect("safe test TLS")
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                client.alpn_protocols = vec![b"h2".to_vec()];
                (
                    "  certificates:\n    ingress:\n      cert_chain: cert.pem\n      private_key: key.pem\n".to_owned(),
                    "    protocol: https\n    tls:\n      default_certificate: ingress\n    http:\n      versions: [h2]\n".to_owned(),
                    Some(Arc::new(client)),
                )
            }
        };
        let endpoint_source = endpoints
            .iter()
            .enumerate()
            .map(|(index, url)| format!("        - name: e{index}\n          url: {url}\n"))
            .collect::<String>();
        let upstream_protocol = match protocol {
            Protocol::Http1 => "http1",
            Protocol::H2 => "h2",
        };
        let source = format!(
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n{certificate_resources}  clusters:\n    api:\n      protocol: {upstream_protocol}\n      endpoints:\n{endpoint_source}      timeouts:\n{timing}{policy}services:\n  root:\n    type: proxy\n    cluster: api\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n{listener}    service:\n      ref: root\n"
        );
        let config = directory.path().join("oxidase.yaml");
        fs::write(&config, source).expect("config writes");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("phased config compiles"),
        )
        .expect("snapshot prepares");
        let cluster = Arc::clone(&snapshot.resources.clusters[&ResourceId::new("cluster:api")]);
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        Self {
            _directory: directory,
            address,
            protocol,
            tls_client,
            cluster,
            running,
        }
    }

    async fn client(&self) -> Client {
        let socket = TcpStream::connect(self.address)
            .await
            .expect("connect gateway");
        let (sender, task) = match self.protocol {
            Protocol::Http1 => {
                let (sender, connection) = client_http1::handshake(TokioIo::new(socket))
                    .await
                    .expect("HTTP/1 handshake");
                (
                    Sender::Http1(sender),
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            }
            Protocol::H2 => {
                let name =
                    ServerName::try_from("deadline-gateway.example.test").expect("TLS test name");
                let tls =
                    TlsConnector::from(self.tls_client.as_ref().expect("H2 test TLS").clone())
                        .connect(name, socket)
                        .await
                        .expect("test TLS handshake");
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                let (sender, connection) =
                    client_http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                        .await
                        .expect("H2 handshake");
                (
                    Sender::H2(sender),
                    tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                )
            }
        };
        Client {
            sender,
            task,
            protocol: self.protocol,
        }
    }

    async fn stop(self) {
        self.running.shutdown().await.expect("gateway shuts down");
    }
}

enum Sender {
    Http1(client_http1::SendRequest<ChannelBody>),
    H2(client_http2::SendRequest<ChannelBody>),
}

struct Client {
    sender: Sender,
    task: tokio::task::JoinHandle<()>,
    protocol: Protocol,
}

impl Client {
    async fn request(
        &mut self,
        method: Method,
        path: &str,
        body: ChannelBody,
    ) -> Response<Incoming> {
        let uri = match self.protocol {
            Protocol::Http1 => path.to_owned(),
            Protocol::H2 => format!("https://deadline-gateway.example.test{path}"),
        };
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "deadline-gateway.example.test")
            .body(body)
            .expect("valid request");
        let response = match &mut self.sender {
            Sender::Http1(sender) => {
                sender
                    .ready()
                    .await
                    .expect("same HTTP/1 dispatcher becomes ready");
                sender.send_request(request).await
            }
            Sender::H2(sender) => {
                sender
                    .ready()
                    .await
                    .expect("same H2 dispatcher becomes ready");
                sender.send_request(request).await
            }
        };
        response.expect("gateway produces a response head")
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn url(upstream: &Upstream) -> String {
    format!("http://{}", upstream.address)
}

async fn complete(response: Response<Incoming>, status: StatusCode) -> Bytes {
    assert_eq!(response.status(), status);
    response
        .into_body()
        .collect()
        .await
        .expect("response completes")
        .to_bytes()
}

async fn permits_released(cluster: &PreparedCluster) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while cluster.active_requests() != 0 || cluster.active_retries() != 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancellation-safe permits eventually release");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_response_head_attempts_share_one_absolute_total_budget() {
    let behavior = Behavior::ReadThenReply {
        delay: Duration::from_secs(3),
    };
    let a = Upstream::start("127.0.0.1:0", Protocol::Http1, behavior.clone()).await;
    let b = Upstream::start("127.0.0.1:0", Protocol::Http1, behavior.clone()).await;
    let c = Upstream::start("127.0.0.1:0", Protocol::Http1, behavior).await;
    let gateway = Gateway::start(Protocol::Http1, &[url(&a), url(&b), url(&c)],
        "        response_header: 400ms\n        pre_response_total: 900ms\n",
        "      retry:\n        max_attempts: 3\n        methods: [GET]\n        retry_on: [response_header_timeout]\n",
    ).await;
    let mut client = gateway.client().await;
    let started = Instant::now();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        client.request(Method::GET, "/retry", ChannelBody::empty()),
    )
    .await
    .expect("one bounded logical request");
    complete(response, StatusCode::GATEWAY_TIMEOUT).await;
    // This compares configured contracts, not a throughput/benchmark threshold.
    // Three independently refreshed 400ms timers would require at least1.2s.
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "total deadline was refreshed by retry: {:?}",
        started.elapsed()
    );
    assert_eq!(a.heads.load(Ordering::Relaxed), 1);
    assert_eq!(b.heads.load(Ordering::Relaxed), 1);
    assert_eq!(c.heads.load(Ordering::Relaxed), 1);
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    a.stop().await;
    b.stop().await;
    c.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn total_deadline_caps_admission_queue_without_consuming_another_attempt() {
    let release = Arc::new(Semaphore::new(0));
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::HeldResponse(Arc::clone(&release)),
    )
    .await;
    let gateway = Gateway::start(Protocol::Http1, &[url(&upstream)],
        "        pre_response_total: 200ms\n        response_body_idle: 5s\n",
        "      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 2s\n",
    ).await;
    let mut owner = gateway.client().await;
    let held = owner
        .request(Method::GET, "/hold", ChannelBody::empty())
        .await;
    assert_eq!(held.status(), StatusCode::OK);
    assert_eq!(gateway.cluster.active_requests(), 1);
    let mut waiter = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        waiter.request(Method::GET, "/queued", ChannelBody::empty()),
    )
    .await
    .expect("total deadline ends queue before2s policy");
    complete(response, StatusCode::GATEWAY_TIMEOUT).await;
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 1);
    release.add_permits(1);
    complete(held, StatusCode::OK).await;
    drop(owner);
    drop(waiter);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn total_deadline_caps_explicit_bounded_replay_buffer_before_dispatch() {
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::ReadThenReply {
            delay: Duration::ZERO,
        },
    )
    .await;
    let gateway = Gateway::start(Protocol::Http1, &[url(&upstream)],
        "        pre_response_total: 200ms\n        request_body_idle: 2s\n",
        "      retry:\n        max_attempts: 2\n        methods: [POST]\n        retry_on: [connect_failure]\n        request_body:\n          mode: buffer\n          max_bytes: 1KiB\n",
    ).await;
    let (upload, body) = ChannelBody::channel();
    upload
        .send(Frame::data(Bytes::from_static(b"unfinished")))
        .await
        .expect("initial bounded frame");
    let mut client = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(Method::POST, "/buffer", body),
    )
    .await
    .expect("buffer is inside one total deadline");
    complete(response, StatusCode::GATEWAY_TIMEOUT).await;
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 0);
    drop(upload);
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shorter_admission_timeout_is_overload_not_the_total_deadline() {
    let release = Arc::new(Semaphore::new(0));
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::HeldResponse(Arc::clone(&release)),
    )
    .await;
    let gateway = Gateway::start(
        Protocol::Http1, &[url(&upstream)],
        "        pre_response_total: 2s\n        response_body_idle: 5s\n",
        "      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 40ms\n",
    ).await;
    let mut owner = gateway.client().await;
    let held = owner
        .request(Method::GET, "/hold", ChannelBody::empty())
        .await;
    assert_eq!(held.status(), StatusCode::OK);
    let mut waiter = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        waiter.request(Method::GET, "/queue-policy", ChannelBody::empty()),
    )
    .await
    .expect("independent admission deadline");
    complete(response, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 1);
    release.add_permits(1);
    complete(held, StatusCode::OK).await;
    drop(owner);
    drop(waiter);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downstream_upload_idle_timeout_is_408_without_passive_endpoint_failure() {
    request_idle(Protocol::Http1).await;
    request_idle(Protocol::H2).await;
}

async fn request_idle(protocol: Protocol) {
    let upstream = Upstream::start(
        "127.0.0.1:0",
        protocol,
        Behavior::ReadThenReply {
            delay: Duration::ZERO,
        },
    )
    .await;
    let gateway = Gateway::start(
        protocol, &[url(&upstream)],
        "        request_body_idle: 120ms\n        pre_response_total: 2s\n",
        "      health:\n        passive:\n          consecutive_failures: 1\n          eject_for: 30s\n",
    ).await;
    let (upload, body) = ChannelBody::channel();
    upload
        .send(Frame::data(Bytes::from_static(b"no-more-progress")))
        .await
        .expect("first DATA");
    let mut client = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(Method::POST, "/request-idle", body),
    )
    .await
    .expect("requested idle read is bounded");
    complete(response, StatusCode::REQUEST_TIMEOUT).await;
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 1);
    drop(upload);
    drop(client);
    permits_released(&gateway.cluster).await;
    let status = gateway.cluster.status(Instant::now());
    assert_eq!(
        status.endpoints[0].runtime.failures, 0,
        "downstream timeout must not eject an upstream"
    );
    assert!(
        gateway.cluster.endpoints()[0]
            .health_state(Instant::now())
            .is_eligible()
    );
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn progress_upload_does_not_start_response_header_timer_until_local_eos() {
    progress_upload(Protocol::Http1).await;
    progress_upload(Protocol::H2).await;
}

async fn progress_upload(protocol: Protocol) {
    let mut upstream = Upstream::start(
        "127.0.0.1:0",
        protocol,
        Behavior::ReadThenReply {
            delay: Duration::ZERO,
        },
    )
    .await;
    let gateway = Gateway::start(protocol, &[url(&upstream)],
        "        response_header: 80ms\n        request_body_idle: 300ms\n        pre_response_total: 2s\n", "",
    ).await;
    let (upload, body) = ChannelBody::channel();
    let sending = tokio::spawn(async move {
        let mut client = gateway.client().await;
        let response = client.request(Method::POST, "/slow-upload", body).await;
        let bytes = complete(response, StatusCode::OK).await;
        drop(client);
        (gateway, bytes)
    });
    assert!(matches!(
        upstream.observation().await,
        Observation::Head { .. }
    ));
    for _ in 0..4 {
        upload
            .send(Frame::data(Bytes::from_static(b"part")))
            .await
            .expect("progress frame reaches requested upload");
        tokio::time::sleep(Duration::from_millis(120)).await;
    }
    drop(upload);
    let (gateway, bytes) = tokio::time::timeout(Duration::from_secs(3), sending)
        .await
        .expect("full duplex logical request terminates")
        .expect("request task completes");
    assert_eq!(bytes, "complete");
    let Observation::End(body) = upstream.observation().await else {
        panic!("upstream observes upload EOS")
    };
    assert_eq!(body, "partpartpartpart");
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

async fn early_response(protocol: Protocol, status: StatusCode) {
    let upstream = Upstream::start("127.0.0.1:0", protocol, Behavior::Early(status)).await;
    let gateway = Gateway::start(
        protocol,
        &[url(&upstream)],
        "        pre_response_total: 2s\n        response_header: 100ms\n",
        "",
    )
    .await;
    let (upload, body) = ChannelBody::channel();
    upload
        .send(Frame::data(Bytes::from_static(b"first-frame-not-eos")))
        .await
        .expect("first upload frame");
    let mut client = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(Method::POST, "/early", body),
    )
    .await
    .expect("response head must not wait for upload EOS");
    assert_eq!(response.status(), status);
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 1);
    assert_eq!(upstream.ends.load(Ordering::Relaxed), 0);
    complete(response, status).await;
    drop(upload);
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http1_early_200_and_413_do_not_wait_for_upload_eos() {
    early_response(Protocol::Http1, StatusCode::OK).await;
    early_response(Protocol::Http1, StatusCode::PAYLOAD_TOO_LARGE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_early_200_and_413_do_not_wait_for_upload_eos() {
    early_response(Protocol::H2, StatusCode::OK).await;
    early_response(Protocol::H2, StatusCode::PAYLOAD_TOO_LARGE).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_request_delayed_response_head_is_header_timeout_not_upload_timeout() {
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::ReadThenReply {
            delay: Duration::from_millis(400),
        },
    )
    .await;
    let gateway = Gateway::start(
        Protocol::Http1,
        &[url(&upstream)],
        "        response_header: 80ms\n        pre_response_total: 2s\n",
        "",
    )
    .await;
    let mut client = gateway.client().await;
    let response = tokio::time::timeout(
        Duration::from_secs(1),
        client.request(Method::GET, "/head-delay", ChannelBody::empty()),
    )
    .await
    .expect("empty-body header deadline");
    complete(response, StatusCode::GATEWAY_TIMEOUT).await;
    assert_eq!(upstream.ends.load(Ordering::Relaxed), 1);
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_body_idle_failure_preserves_sent_200_and_releases_permits() {
    let release = Arc::new(Semaphore::new(0));
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::HeldResponse(release),
    )
    .await;
    let gateway = Gateway::start(Protocol::Http1, &[url(&upstream)], "        response_body_idle: 100ms\n        response_header: 1s\n        pre_response_total: 2s\n", "").await;
    let mut client = gateway.client().await;
    let response = client
        .request(Method::GET, "/body-idle", ChannelBody::empty())
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let first = body
        .frame()
        .await
        .expect("first frame")
        .expect("prefix succeeds");
    assert_eq!(first.data_ref().expect("DATA frame"), "prefix");
    assert!(
        tokio::time::timeout(Duration::from_secs(1), body.collect())
            .await
            .expect("body-idle timeout closes stream")
            .is_err()
    );
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reused_http1_test_client_waits_for_dispatcher_before_its_single_send() {
    let release = Arc::new(Semaphore::new(0));
    let upstream = Upstream::start(
        "127.0.0.1:0",
        Protocol::Http1,
        Behavior::HeldResponse(Arc::clone(&release)),
    )
    .await;
    let gateway = Gateway::start(
        Protocol::Http1,
        &[url(&upstream)],
        "        pre_response_total: 2s\n        response_body_idle: 5s\n",
        "",
    )
    .await;
    let mut client = gateway.client().await;
    let first = client
        .request(Method::GET, "/first", ChannelBody::empty())
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let mut first = first.into_body();
    let frame = first.frame().await.expect("prefix frame").expect("DATA");
    assert_eq!(frame.data_ref().expect("first DATA"), "prefix");
    let Sender::Http1(sender) = &client.sender else {
        panic!("one HTTP/1 sender");
    };
    assert!(!sender.is_ready(), "held response keeps dispatcher busy");
    let (polled, first_poll) = oneshot::channel();
    let second = tokio::spawn(async move {
        let response = {
            let request = client.request(Method::GET, "/second", ChannelBody::empty());
            tokio::pin!(request);
            let mut polled = Some(polled);
            std::future::poll_fn(|context| {
                let progress = request.as_mut().poll(context);
                if let Some(polled) = polled.take() {
                    polled
                        .send(progress.is_pending())
                        .expect("first-poll observer remains alive");
                }
                progress
            })
            .await
        };
        (client, response)
    });
    // Observe the request future's actual first poll, not a scheduling delay.
    // The wire gate is still closed, so this must be Pending, never cancelled.
    let pending = tokio::time::timeout(Duration::from_secs(3), first_poll)
        .await
        .expect("request task actually polled")
        .expect("single-send request did not panic before readiness");
    assert!(
        pending,
        "second single-send must await readiness rather than be cancelled"
    );
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 1);
    assert_eq!(upstream.connections.load(Ordering::Relaxed), 1);
    release.add_permits(1);
    let first = first.collect().await.expect("first actual EOF");
    assert!(first.trailers().is_none(), "fixture emits no trailers");
    assert!(
        first.to_bytes().is_empty(),
        "first body was exactly the already-verified prefix"
    );
    let (mut client, response) = tokio::time::timeout(Duration::from_secs(3), second)
        .await
        .expect("original pending operation completes after release")
        .expect("single-send task joined");
    assert_eq!(response.status(), StatusCode::OK);
    release.add_permits(1);
    assert_eq!(complete(response, StatusCode::OK).await, "prefix");
    assert_eq!(upstream.heads.load(Ordering::Relaxed), 2);
    assert_eq!(
        upstream.connections.load(Ordering::Relaxed),
        1,
        "no retry or new connection substitutes for dispatcher readiness"
    );
    client.task.abort();
    match tokio::time::timeout(Duration::from_secs(3), &mut client.task)
        .await
        .expect("actual downstream driver exit acknowledged")
    {
        Ok(()) => {}
        Err(error) => assert!(error.is_cancelled(), "driver panicked: {error}"),
    }
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ipv6_authority_base_path_and_raw_query_survive_direct_dial_and_pool_reuse() {
    let mut upstream = Upstream::start(
        "[::1]:0",
        Protocol::Http1,
        Behavior::ReadThenReply {
            delay: Duration::ZERO,
        },
    )
    .await;
    let origin = format!("{}/base", url(&upstream));
    let gateway = Gateway::start(
        Protocol::Http1,
        &[origin],
        "        pre_response_total: 2s\n",
        "",
    )
    .await;
    let mut client = gateway.client().await;
    for _ in 0..2 {
        let response = client
            .request(Method::GET, "/child?a=%2F&z=2&a=3", ChannelBody::empty())
            .await;
        complete(response, StatusCode::OK).await;
        let Observation::Head { authority, path } = upstream.observation().await else {
            panic!("head observation")
        };
        assert_eq!(authority, upstream.address.to_string());
        assert_eq!(path, "/base/child?a=%2F&z=2&a=3");
        assert!(
            matches!(upstream.observation().await, Observation::End(bytes) if bytes.is_empty())
        );
    }
    assert_eq!(
        upstream.connections.load(Ordering::Relaxed),
        1,
        "same identity should retain its upstream pool"
    );
    drop(client);
    permits_released(&gateway.cluster).await;
    gateway.stop().await;
    upstream.stop().await;
}
