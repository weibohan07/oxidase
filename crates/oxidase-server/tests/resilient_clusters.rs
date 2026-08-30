//! Black-box coverage for resilient Cluster routing, admission, retry, and reload.
//!
//! Every upstream is an in-process Rust HTTP/1 fixture. The fixtures expose
//! deterministic response steps and retain the method/body of each attempt so
//! retry safety is asserted at the actual proxy boundary.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fs;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use tempfile::{TempDir, tempdir};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};

#[derive(Clone)]
enum ResponseStep {
    Reply {
        status: StatusCode,
        body: Bytes,
    },
    Delay {
        duration: Duration,
        status: StatusCode,
        body: Bytes,
    },
    Wait {
        release: Arc<Semaphore>,
        status: StatusCode,
        body: Bytes,
    },
}

impl ResponseStep {
    fn ok(body: &'static str) -> Self {
        Self::Reply {
            status: StatusCode::OK,
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    fn status(status: StatusCode, body: &'static str) -> Self {
        Self::Reply {
            status,
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    async fn respond(self) -> Response<Full<Bytes>> {
        let (status, body) = match self {
            Self::Reply { status, body } => (status, body),
            Self::Delay {
                duration,
                status,
                body,
            } => {
                tokio::time::sleep(duration).await;
                (status, body)
            }
            Self::Wait {
                release,
                status,
                body,
            } => {
                let permit = release
                    .acquire()
                    .await
                    .expect("scripted response gate remains open");
                permit.forget();
                (status, body)
            }
        };
        Response::builder()
            .status(status)
            .body(Full::new(body))
            .expect("scripted upstream response is valid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Attempt {
    method: Method,
    path_and_query: String,
    body: Bytes,
}

struct ScriptedEndpoint {
    address: SocketAddr,
    attempts: mpsc::UnboundedReceiver<Attempt>,
    connections: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ScriptedEndpoint {
    async fn start(steps: Vec<ResponseStep>, fallback: ResponseStep) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("scripted endpoint binds to loopback");
        let address = listener.local_addr().expect("fixture address is known");
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let fallback = Arc::new(fallback);
        let connections = Arc::new(AtomicUsize::new(0));
        let connections_for_task = Arc::clone(&connections);
        let (attempt_sender, attempts) = mpsc::unbounded_channel();
        let (shutdown, mut shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connection_tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut shutdown_receiver => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        connections_for_task.fetch_add(1, Ordering::Relaxed);
                        let steps = Arc::clone(&steps);
                        let fallback = Arc::clone(&fallback);
                        let attempt_sender = attempt_sender.clone();
                        connection_tasks.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let steps = Arc::clone(&steps);
                                let fallback = Arc::clone(&fallback);
                                let attempt_sender = attempt_sender.clone();
                                async move {
                                    let method = request.method().clone();
                                    let path_and_query = request
                                        .uri()
                                        .path_and_query()
                                        .map_or("/", http::uri::PathAndQuery::as_str)
                                        .to_owned();
                                    let body = request
                                        .into_body()
                                        .collect()
                                        .await
                                        .expect("fixture reads the complete upstream request")
                                        .to_bytes();
                                    let _ = attempt_sender.send(Attempt {
                                        method,
                                        path_and_query,
                                        body,
                                    });
                                    let step = steps
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .pop_front()
                                        .unwrap_or_else(|| fallback.as_ref().clone());
                                    Ok::<_, Infallible>(step.respond().await)
                                }
                            });
                            let _ = server_http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
            connection_tasks.abort_all();
            while connection_tasks.join_next().await.is_some() {}
        });
        Self {
            address,
            attempts,
            connections,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn next_attempt(&mut self) -> Attempt {
        tokio::time::timeout(Duration::from_secs(2), self.attempts.recv())
            .await
            .expect("fixture observes an upstream attempt before timeout")
            .expect("attempt channel remains open")
    }

    async fn assert_no_attempt(&mut self) {
        assert!(
            tokio::time::timeout(Duration::from_millis(80), self.attempts.recv())
                .await
                .is_err(),
            "endpoint unexpectedly received an upstream attempt"
        );
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Relaxed)
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("scripted endpoint task exits");
    }
}

struct TestGateway {
    _directory: TempDir,
    config: std::path::PathBuf,
    address: SocketAddr,
    admin: SocketAddr,
    running: RunningServer,
}

impl TestGateway {
    async fn start(cluster: &str, service: &str) -> Self {
        let directory = tempdir().expect("temporary gateway directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_gateway_source(&config, cluster, service);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("resilient Cluster source compiles"),
        )
        .expect("resilient Cluster snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("resilient Cluster gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("valid admin bind"))
            .await
            .expect("resilient Cluster admin listener binds");
        let running = server.spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");
        Self {
            _directory: directory,
            config,
            address,
            admin,
            running,
        }
    }

    async fn rewrite_and_reload(&self, cluster: &str, service: &str) {
        write_gateway_source(&self.config, cluster, service);
        self.running
            .reload_path(&self.config)
            .await
            .expect("candidate Cluster snapshot commits");
    }
}

fn write_gateway_source(path: &std::path::Path, cluster: &str, service: &str) {
    fs::write(
        path,
        format!(
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    upstream:\n{cluster}\nservices:\n  root:\n{service}\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n"
        ),
    )
    .expect("gateway source can be written");
}

fn shorthand_cluster(address: SocketAddr, extras: &str) -> String {
    format!("      protocol: http1\n      endpoints:\n        - http://{address}\n{extras}")
}

fn structured_cluster(endpoints: &[(&str, SocketAddr, u16)], policy: &str, extras: &str) -> String {
    let endpoints = endpoints
        .iter()
        .map(|(name, address, weight)| {
            format!(
                "        - name: {name}\n          url: http://{address}\n          weight: {weight}\n"
            )
        })
        .collect::<String>();
    format!(
        "      protocol: http1\n      endpoints:\n{endpoints}      load_balance:\n        policy: {policy}\n{extras}"
    )
}

const PROXY_SERVICE: &str = "    type: proxy\n    cluster: upstream";

fn recover_service(class: &str, body: &str) -> String {
    format!(
        "    type: recover\n    service:\n      type: proxy\n      cluster: upstream\n    handlers:\n      - classes: [{class}]\n        service:\n          type: respond\n          status: 503\n          body:\n            text: {body}"
    )
}

struct ObservedResponse {
    status: StatusCode,
    body: Bytes,
}

async fn request_once(
    address: SocketAddr,
    method: Method,
    path: &str,
    body: Bytes,
) -> ObservedResponse {
    tokio::time::timeout(Duration::from_secs(4), async move {
        let stream = TcpStream::connect(address)
            .await
            .expect("client connects to gateway");
        let (mut sender, connection) = client_http1::handshake(TokioIo::new(stream))
            .await
            .expect("HTTP/1 client handshake succeeds");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "gateway.example.test")
            .body(Full::new(body))
            .expect("gateway request is valid");
        let response = sender
            .send_request(request)
            .await
            .expect("gateway returns a response head");
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("gateway response body completes")
            .to_bytes();
        drop(sender);
        driver.abort();
        ObservedResponse { status, body }
    })
    .await
    .expect("gateway exchange completes before timeout")
}

async fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ephemeral loopback address can be reserved");
    let address = listener.local_addr().expect("reserved address is known");
    drop(listener);
    address
}

#[tokio::test]
async fn shorthand_and_structured_endpoints_both_drive_real_proxy_requests() {
    let mut shorthand = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("shorthand")).await;
    let gateway =
        TestGateway::start(&shorthand_cluster(shorthand.address, ""), PROXY_SERVICE).await;
    let response = request_once(
        gateway.address,
        Method::GET,
        "/shorthand?order=first&order=second",
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "shorthand");
    assert_eq!(
        shorthand.next_attempt().await,
        Attempt {
            method: Method::GET,
            path_and_query: "/shorthand?order=first&order=second".to_owned(),
            body: Bytes::new(),
        }
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("shorthand gateway shuts down");
    shorthand.shutdown().await;

    let mut structured = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("structured")).await;
    let gateway = TestGateway::start(
        &structured_cluster(&[("named", structured.address, 1)], "round_robin", ""),
        PROXY_SERVICE,
    )
    .await;
    let response = request_once(gateway.address, Method::GET, "/structured", Bytes::new()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "structured");
    assert_eq!(structured.next_attempt().await.method, Method::GET);
    gateway
        .running
        .shutdown()
        .await
        .expect("structured gateway shuts down");
    structured.shutdown().await;
}

#[tokio::test]
async fn round_robin_and_weighted_round_robin_select_expected_distributions() {
    let mut first = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("first")).await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("second")).await;
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        "",
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;
    let mut bodies = Vec::new();
    for _ in 0..6 {
        bodies.push(
            request_once(gateway.address, Method::GET, "/rr", Bytes::new())
                .await
                .body,
        );
    }
    assert_eq!(
        bodies,
        [
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
            Bytes::from_static(b"first"),
            Bytes::from_static(b"second"),
        ]
    );
    for _ in 0..3 {
        assert_eq!(first.next_attempt().await.method, Method::GET);
        assert_eq!(second.next_attempt().await.method, Method::GET);
    }
    assert_eq!(first.connection_count(), 1);
    assert_eq!(second.connection_count(), 1);
    gateway
        .running
        .shutdown()
        .await
        .expect("round-robin gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;

    let mut heavy = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("heavy")).await;
    let mut light = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("light")).await;
    let cluster = structured_cluster(
        &[("heavy", heavy.address, 2), ("light", light.address, 1)],
        "weighted_round_robin",
        "",
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;
    let mut heavy_count = 0;
    let mut light_count = 0;
    for _ in 0..9 {
        match request_once(gateway.address, Method::GET, "/weighted", Bytes::new())
            .await
            .body
            .as_ref()
        {
            b"heavy" => heavy_count += 1,
            b"light" => light_count += 1,
            body => panic!("unexpected weighted endpoint response: {body:?}"),
        }
    }
    assert_eq!((heavy_count, light_count), (6, 3));
    for _ in 0..6 {
        assert_eq!(heavy.next_attempt().await.method, Method::GET);
    }
    for _ in 0..3 {
        assert_eq!(light.next_attempt().await.method, Method::GET);
    }
    assert_eq!(heavy.connection_count(), 1);
    assert_eq!(light.connection_count(), 1);
    gateway
        .running
        .shutdown()
        .await
        .expect("weighted gateway shuts down");
    heavy.shutdown().await;
    light.shutdown().await;
}

#[tokio::test]
async fn least_requests_avoids_an_endpoint_with_an_active_request() {
    let release = Arc::new(Semaphore::new(0));
    let mut first = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"first"),
        }],
        ResponseStep::ok("first"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("second")).await;
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "least_requests",
        "",
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;
    let address = gateway.address;
    let blocked =
        tokio::spawn(
            async move { request_once(address, Method::GET, "/blocked", Bytes::new()).await },
        );
    assert_eq!(first.next_attempt().await.path_and_query, "/blocked");

    let concurrent = request_once(gateway.address, Method::GET, "/concurrent", Bytes::new()).await;
    assert_eq!(concurrent.status, StatusCode::OK);
    assert_eq!(concurrent.body, "second");
    assert_eq!(second.next_attempt().await.path_and_query, "/concurrent");

    release.add_permits(1);
    assert_eq!(
        blocked.await.expect("blocked request task joins").body,
        "first"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("least-requests gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn cluster_capacity_fail_fast_and_queue_timeout_are_observable_as_overload() {
    let release = Arc::new(Semaphore::new(0));
    let mut endpoint = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"released"),
        }],
        ResponseStep::ok("later"),
    )
    .await;
    let limits = "      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 0ms\n";
    let gateway = TestGateway::start(
        &shorthand_cluster(endpoint.address, limits),
        &recover_service("upstream_overloaded", "overloaded"),
    )
    .await;
    let address = gateway.address;
    let blocked =
        tokio::spawn(
            async move { request_once(address, Method::GET, "/occupy", Bytes::new()).await },
        );
    assert_eq!(endpoint.next_attempt().await.path_and_query, "/occupy");

    let rejected = request_once(gateway.address, Method::GET, "/fail-fast", Bytes::new()).await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.body, "overloaded");
    endpoint.assert_no_attempt().await;
    release.add_permits(1);
    assert_eq!(
        blocked.await.expect("occupied request task joins").body,
        "released"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("fail-fast gateway shuts down");
    endpoint.shutdown().await;

    let release = Arc::new(Semaphore::new(0));
    let mut endpoint = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"first"),
        }],
        ResponseStep::ok("queued"),
    )
    .await;
    let limits = "      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 120ms\n";
    let gateway = TestGateway::start(
        &shorthand_cluster(endpoint.address, limits),
        &recover_service("upstream_overloaded", "queue-timeout"),
    )
    .await;
    let address = gateway.address;
    let blocked =
        tokio::spawn(
            async move { request_once(address, Method::GET, "/occupy", Bytes::new()).await },
        );
    assert_eq!(endpoint.next_attempt().await.path_and_query, "/occupy");
    let started = Instant::now();
    let timed_out = request_once(
        gateway.address,
        Method::GET,
        "/wait-for-capacity",
        Bytes::new(),
    )
    .await;
    assert_eq!(timed_out.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(timed_out.body, "queue-timeout");
    assert!(
        started.elapsed() >= Duration::from_millis(90),
        "non-zero queue timeout must wait before rejecting"
    );
    endpoint.assert_no_attempt().await;
    release.add_permits(1);
    assert_eq!(blocked.await.expect("occupied request joins").body, "first");
    gateway
        .running
        .shutdown()
        .await
        .expect("queue-timeout gateway shuts down");
    endpoint.shutdown().await;
}

#[tokio::test]
async fn queue_waiter_uses_capacity_released_before_its_deadline() {
    let release = Arc::new(Semaphore::new(0));
    let mut endpoint = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"first"),
        }],
        ResponseStep::ok("queued"),
    )
    .await;
    let limits = "      limits:\n        max_in_flight: 1\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 500ms\n";
    let gateway =
        TestGateway::start(&shorthand_cluster(endpoint.address, limits), PROXY_SERVICE).await;
    let first_address = gateway.address;
    let first = tokio::spawn(async move {
        request_once(first_address, Method::GET, "/first", Bytes::new()).await
    });
    assert_eq!(endpoint.next_attempt().await.path_and_query, "/first");

    let second_address = gateway.address;
    let second = tokio::spawn(async move {
        request_once(second_address, Method::GET, "/second", Bytes::new()).await
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    release.add_permits(1);
    assert_eq!(first.await.expect("first request joins").body, "first");
    assert_eq!(endpoint.next_attempt().await.path_and_query, "/second");
    assert_eq!(second.await.expect("queued request joins").body, "queued");
    gateway
        .running
        .shutdown()
        .await
        .expect("queued gateway shuts down");
    endpoint.shutdown().await;
}

#[tokio::test]
async fn per_endpoint_capacity_is_enforced_independently_of_cluster_capacity() {
    let first_release = Arc::new(Semaphore::new(0));
    let second_release = Arc::new(Semaphore::new(0));
    let mut first = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&first_release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"first"),
        }],
        ResponseStep::ok("first"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&second_release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"second"),
        }],
        ResponseStep::ok("second"),
    )
    .await;
    let limits = "      limits:\n        max_in_flight: 3\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 0ms\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        limits,
    );
    let gateway = TestGateway::start(
        &cluster,
        &recover_service("upstream_overloaded", "endpoint-capacity"),
    )
    .await;

    let first_address = gateway.address;
    let first_request = tokio::spawn(async move {
        request_once(first_address, Method::GET, "/first", Bytes::new()).await
    });
    assert_eq!(first.next_attempt().await.path_and_query, "/first");
    let second_address = gateway.address;
    let second_request = tokio::spawn(async move {
        request_once(second_address, Method::GET, "/second", Bytes::new()).await
    });
    assert_eq!(second.next_attempt().await.path_and_query, "/second");

    let rejected = request_once(gateway.address, Method::GET, "/third", Bytes::new()).await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.body, "endpoint-capacity");
    first.assert_no_attempt().await;
    second.assert_no_attempt().await;

    first_release.add_permits(1);
    second_release.add_permits(1);
    assert_eq!(
        first_request.await.expect("first request joins").body,
        "first"
    );
    assert_eq!(
        second_request.await.expect("second request joins").body,
        "second"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("endpoint-capacity gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn passively_ejected_last_endpoint_is_recovered_as_unavailable() {
    let unavailable = unused_loopback_address().await;
    let passive = "      health:\n        passive:\n          consecutive_failures: 1\n          eject_for: 30s\n      connect_timeout: 80ms\n      response_timeout: 80ms\n";
    let gateway = TestGateway::start(
        &shorthand_cluster(unavailable, passive),
        &recover_service("upstream_unavailable", "unavailable"),
    )
    .await;

    let first = request_once(gateway.address, Method::GET, "/first-connect", Bytes::new()).await;
    assert_eq!(first.status, StatusCode::BAD_GATEWAY);
    assert_ne!(first.body, "unavailable");

    let recovered = request_once(
        gateway.address,
        Method::GET,
        "/after-ejection",
        Bytes::new(),
    )
    .await;
    assert_eq!(recovered.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(recovered.body, "unavailable");

    gateway
        .running
        .shutdown()
        .await
        .expect("unavailable gateway shuts down");
}

#[tokio::test]
async fn connect_failure_retries_an_untried_endpoint_for_zero_body_get() {
    let unavailable = unused_loopback_address().await;
    let mut healthy = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("retried")).await;
    let retry = "      connect_timeout: 80ms\n      response_timeout: 200ms\n      retry:\n        max_attempts: 2\n        methods: [GET]\n        retry_on: [connect_failure]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[
            ("unavailable", unavailable, 1),
            ("healthy", healthy.address, 1),
        ],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let response = request_once(gateway.address, Method::GET, "/connect-retry", Bytes::new()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "retried");
    assert_eq!(
        healthy.next_attempt().await,
        Attempt {
            method: Method::GET,
            path_and_query: "/connect-retry".to_owned(),
            body: Bytes::new(),
        }
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("connect-retry gateway shuts down");
    healthy.shutdown().await;
}

#[tokio::test]
async fn response_header_timeout_retries_a_different_endpoint() {
    let mut slow = ScriptedEndpoint::start(
        vec![ResponseStep::Delay {
            duration: Duration::from_millis(500),
            status: StatusCode::OK,
            body: Bytes::from_static(b"too-late"),
        }],
        ResponseStep::ok("slow"),
    )
    .await;
    let mut healthy = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("after-timeout")).await;
    let retry = "      connect_timeout: 40ms\n      response_timeout: 60ms\n      retry:\n        max_attempts: 2\n        methods: [GET]\n        retry_on: [response_header_timeout]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("slow", slow.address, 1), ("healthy", healthy.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let started = Instant::now();
    let response = request_once(
        gateway.address,
        Method::GET,
        "/header-timeout",
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "after-timeout");
    assert!(started.elapsed() >= Duration::from_millis(80));
    assert_eq!(slow.next_attempt().await.path_and_query, "/header-timeout");
    assert_eq!(
        healthy.next_attempt().await.path_and_query,
        "/header-timeout"
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("header-timeout gateway shuts down");
    slow.shutdown().await;
    healthy.shutdown().await;
}

#[tokio::test]
async fn retryable_status_switches_endpoint_and_preserves_final_response() {
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "retry-me"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("final")).await;
    let retry = "      retry:\n        max_attempts: 2\n        methods: [GET]\n        statuses: [503]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let response = request_once(gateway.address, Method::GET, "/status-retry", Bytes::new()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "final");
    assert_eq!(first.next_attempt().await.method, Method::GET);
    assert_eq!(second.next_attempt().await.method, Method::GET);
    first.assert_no_attempt().await;
    second.assert_no_attempt().await;

    gateway
        .running
        .shutdown()
        .await
        .expect("status-retry gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn retry_stops_after_all_endpoints_are_tried_once() {
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "first"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::BAD_GATEWAY, "second"),
    )
    .await;
    let retry = "      retry:\n        max_attempts: 5\n        methods: [GET]\n        statuses: [502, 503]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let response = request_once(
        gateway.address,
        Method::GET,
        "/bounded-attempts",
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert_eq!(response.body, "second");
    assert_eq!(
        first.next_attempt().await.path_and_query,
        "/bounded-attempts"
    );
    assert_eq!(
        second.next_attempt().await.path_and_query,
        "/bounded-attempts"
    );
    first.assert_no_attempt().await;
    second.assert_no_attempt().await;

    gateway
        .running
        .shutdown()
        .await
        .expect("bounded-attempt gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn retry_semaphore_stops_a_concurrent_retry_without_queueing() {
    let retry_release = Arc::new(Semaphore::new(0));
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "storm-limited"),
    )
    .await;
    let mut unused = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("unused")).await;
    let mut retry_target = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&retry_release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"retried"),
        }],
        ResponseStep::ok("retry-target"),
    )
    .await;
    let policy = "      retry:\n        max_attempts: 2\n        methods: [GET]\n        statuses: [503]\n        max_concurrent_retries: 1\n      limits:\n        max_in_flight: 3\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 0ms\n";
    let cluster = structured_cluster(
        &[
            ("first", first.address, 1),
            ("unused", unused.address, 1),
            ("retry-target", retry_target.address, 1),
        ],
        "round_robin",
        policy,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let address = gateway.address;
    let first_request = tokio::spawn(async move {
        request_once(address, Method::GET, "/first-retry", Bytes::new()).await
    });
    assert_eq!(first.next_attempt().await.path_and_query, "/first-retry");
    assert_eq!(
        retry_target.next_attempt().await.path_and_query,
        "/first-retry"
    );

    let rejected = request_once(
        gateway.address,
        Method::GET,
        "/concurrent-retry",
        Bytes::new(),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.body, "storm-limited");
    assert_eq!(
        first.next_attempt().await.path_and_query,
        "/concurrent-retry"
    );
    unused.assert_no_attempt().await;

    retry_release.add_permits(1);
    let completed = first_request.await.expect("retrying request joins");
    assert_eq!(completed.status, StatusCode::OK);
    assert_eq!(completed.body, "retried");

    let admin = request_once(gateway.admin, Method::GET, "/api/v1/clusters", Bytes::new()).await;
    let document: serde_json::Value =
        serde_json::from_slice(&admin.body).expect("Cluster admin response is valid JSON");
    assert_eq!(document["clusters"][0]["retry_attempts"], 1);
    assert_eq!(document["clusters"][0]["retry_exhausted"], 1);
    assert_eq!(document["clusters"][0]["active_retries"], 0);

    gateway
        .running
        .shutdown()
        .await
        .expect("retry-storm gateway shuts down");
    first.shutdown().await;
    unused.shutdown().await;
    retry_target.shutdown().await;
}

#[tokio::test]
async fn post_is_not_retried_unless_explicitly_listed() {
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "not-retried"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("must-not-run")).await;
    let retry = "      retry:\n        max_attempts: 2\n        methods: [GET]\n        statuses: [503]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let body = Bytes::from_static(b"unsafe-post-body");
    let response = request_once(
        gateway.address,
        Method::POST,
        "/non-idempotent",
        body.clone(),
    )
    .await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.body, "not-retried");
    assert_eq!(
        first.next_attempt().await,
        Attempt {
            method: Method::POST,
            path_and_query: "/non-idempotent".to_owned(),
            body,
        }
    );
    second.assert_no_attempt().await;

    gateway
        .running
        .shutdown()
        .await
        .expect("non-retry POST gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn explicitly_buffered_post_body_is_replayed_exactly_and_limit_is_413() {
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "retry"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("accepted")).await;
    let retry = "      retry:\n        max_attempts: 2\n        methods: [POST]\n        statuses: [503]\n        request_body:\n          mode: buffer\n          max_bytes: 8B\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;

    let replayed = Bytes::from_static(b"replay");
    let response = request_once(gateway.address, Method::POST, "/buffered", replayed.clone()).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body, "accepted");
    for attempt in [first.next_attempt().await, second.next_attempt().await] {
        assert_eq!(attempt.method, Method::POST);
        assert_eq!(attempt.path_and_query, "/buffered");
        assert_eq!(attempt.body, replayed);
    }

    let too_large = request_once(
        gateway.address,
        Method::POST,
        "/too-large",
        Bytes::from_static(b"nine-byte"),
    )
    .await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(too_large.body, "Payload Too Large");
    first.assert_no_attempt().await;
    second.assert_no_attempt().await;

    gateway
        .running
        .shutdown()
        .await
        .expect("buffered retry gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn admin_and_metrics_report_bounded_runtime_cluster_state() {
    let mut first = ScriptedEndpoint::start(
        Vec::new(),
        ResponseStep::status(StatusCode::SERVICE_UNAVAILABLE, "retry"),
    )
    .await;
    let mut second = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("accepted")).await;
    let retry = "      retry:\n        max_attempts: 2\n        methods: [GET]\n        statuses: [503]\n        max_concurrent_retries: 4\n";
    let cluster = structured_cluster(
        &[("first", first.address, 1), ("second", second.address, 1)],
        "round_robin",
        retry,
    );
    let gateway = TestGateway::start(&cluster, PROXY_SERVICE).await;
    let response = request_once(
        gateway.address,
        Method::GET,
        "/sensitive/path?user=private",
        Bytes::new(),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);
    let _ = first.next_attempt().await;
    let _ = second.next_attempt().await;

    let admin = request_once(gateway.admin, Method::GET, "/api/v1/clusters", Bytes::new()).await;
    assert_eq!(admin.status, StatusCode::OK);
    let document: serde_json::Value =
        serde_json::from_slice(&admin.body).expect("Cluster admin response is valid JSON");
    let cluster = &document["clusters"][0];
    assert_eq!(cluster["cluster"], "upstream");
    assert_eq!(cluster["protocol"], "http1");
    assert_eq!(cluster["policy"], "round_robin");
    assert_eq!(cluster["active_requests"], 0);
    assert_eq!(cluster["active_retries"], 0);
    assert_eq!(cluster["retry_attempts"], 1);
    assert_eq!(cluster["endpoints"][0]["name"], "first");
    assert_eq!(cluster["endpoints"][1]["name"], "second");
    let admin_text = String::from_utf8(admin.body.to_vec()).expect("admin JSON is UTF-8");
    assert!(!admin_text.contains("http://"));
    assert!(!admin_text.contains("sensitive"));
    assert!(!admin_text.contains("private"));

    let metrics = request_once(gateway.admin, Method::GET, "/metrics", Bytes::new()).await;
    assert_eq!(metrics.status, StatusCode::OK);
    let metrics = String::from_utf8(metrics.body.to_vec()).expect("metrics are UTF-8");
    assert!(metrics.contains(
        "oxidase_cluster_info{cluster=\"upstream\",policy=\"round_robin\",protocol=\"http1\"} 1"
    ));
    assert!(metrics.contains("oxidase_cluster_retry_attempts_total{cluster=\"upstream\"} 1"));
    assert!(metrics.contains(
        "oxidase_cluster_endpoint_selections_total{cluster=\"upstream\",endpoint=\"first\"} 1"
    ));
    assert!(metrics.contains(
        "oxidase_cluster_endpoint_selections_total{cluster=\"upstream\",endpoint=\"second\"} 1"
    ));
    assert!(!metrics.contains("sensitive"));
    assert!(!metrics.contains("private"));
    assert!(!metrics.contains("http://"));

    gateway
        .running
        .shutdown()
        .await
        .expect("admin metrics gateway shuts down");
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test]
async fn active_request_pins_old_cluster_while_reload_routes_new_requests_to_new_cluster() {
    let release = Arc::new(Semaphore::new(0));
    let mut old = ScriptedEndpoint::start(
        vec![ResponseStep::Wait {
            release: Arc::clone(&release),
            status: StatusCode::OK,
            body: Bytes::from_static(b"old"),
        }],
        ResponseStep::ok("old"),
    )
    .await;
    let mut new = ScriptedEndpoint::start(Vec::new(), ResponseStep::ok("new")).await;
    let old_cluster = structured_cluster(&[("endpoint", old.address, 1)], "round_robin", "");
    let gateway = TestGateway::start(&old_cluster, PROXY_SERVICE).await;
    let address = gateway.address;
    let in_flight = tokio::spawn(async move {
        request_once(address, Method::GET, "/during-reload", Bytes::new()).await
    });
    assert_eq!(old.next_attempt().await.path_and_query, "/during-reload");

    let new_cluster = structured_cluster(&[("endpoint", new.address, 1)], "round_robin", "");
    gateway
        .rewrite_and_reload(&new_cluster, PROXY_SERVICE)
        .await;
    let after = request_once(gateway.address, Method::GET, "/after-reload", Bytes::new()).await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.body, "new");
    assert_eq!(new.next_attempt().await.path_and_query, "/after-reload");

    release.add_permits(1);
    let old_response = in_flight.await.expect("old request task joins");
    assert_eq!(old_response.status, StatusCode::OK);
    assert_eq!(old_response.body, "old");

    gateway
        .running
        .shutdown()
        .await
        .expect("reload gateway shuts down");
    old.shutdown().await;
    new.shutdown().await;
}
