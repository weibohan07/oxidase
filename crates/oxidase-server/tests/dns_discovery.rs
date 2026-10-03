//! Real DNS→lease→pool→peer integration. No public DNS, fixed listening port,
//! system OpenSSL, or alternate gateway data plane is involved.

#[path = "support/dns_fixture.rs"]
mod dns_fixture;

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dns_fixture::{DnsFixture, FixtureReply};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::rdata::{A, AAAA, SRV};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Empty, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::client::conn::http2 as client_h2;
use hyper::server::conn::http2 as server_h2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_core::ResourceId;
use oxidase_runtime::{PreparedCluster, RuntimeOrigin, RuntimeSnapshot};
use oxidase_server::{GatewayServer, RunningServer};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

type FixtureBody = UnsyncBoxBody<Bytes, Infallible>;

#[derive(Debug)]
struct Head {
    authority: String,
    path: String,
}

struct Upstream {
    address: SocketAddr,
    observed: mpsc::Receiver<Head>,
    heads: Arc<AtomicU64>,
    connections: Arc<AtomicU64>,
    release: Arc<Semaphore>,
    healthy: Arc<AtomicBool>,
    sni: mpsc::Receiver<String>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(address: SocketAddr, marker: &'static str) -> std::io::Result<Self> {
        Self::start_transport(address, marker, None).await
    }

    async fn start_transport(
        address: SocketAddr,
        marker: &'static str,
        tls: Option<Arc<ServerConfig>>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (events, observed) = mpsc::channel(32);
        let heads = Arc::new(AtomicU64::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let release = Arc::new(Semaphore::new(0));
        let healthy = Arc::new(AtomicBool::new(true));
        let (sni_events, sni) = mpsc::channel(32);
        let task_heads = Arc::clone(&heads);
        let task_connections = Arc::clone(&connections);
        let task_release = Arc::clone(&release);
        let task_health = Arc::clone(&healthy);
        let task = tokio::spawn(async move {
            // Dropping this JoinSet aborts all accepted connection drivers.
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break; };
                        task_connections.fetch_add(1, Ordering::Relaxed);
                        let events = events.clone();
                        let heads = Arc::clone(&task_heads);
                        let release = Arc::clone(&task_release);
                        let healthy = Arc::clone(&task_health);
                        let tls = tls.clone();
                        let sni_events = sni_events.clone();
                        tasks.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let events = events.clone();
                                let heads = Arc::clone(&heads);
                                let release = Arc::clone(&release);
                                let healthy = Arc::clone(&healthy);
                                async move {
                                    let authority = request.uri().authority().map_or_else(
                                        || request.headers().get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or("").to_owned(),
                                        |authority| authority.as_str().to_owned(),
                                    );
                                    let path = request.uri().path_and_query().expect("origin form").as_str().to_owned();
                                    if path.ends_with("/health") {
                                        return Ok::<_, Infallible>(Response::builder()
                                            .status(if healthy.load(Ordering::Acquire) { 200 } else { 503 })
                                            .body(Full::new(Bytes::new()).boxed_unsync()).expect("health response"));
                                    }
                                    heads.fetch_add(1, Ordering::Relaxed);
                                    let _ = events.try_send(Head { authority, path: path.clone() });
                                    if path.starts_with("/base/delayed") {
                                        tokio::time::sleep(Duration::from_millis(800)).await;
                                    }
                                    let body: FixtureBody = if path.starts_with("/base/hold") {
                                        HeldBody::new(marker, release).boxed_unsync()
                                    } else {
                                        Full::new(Bytes::copy_from_slice(marker.as_bytes())).boxed_unsync()
                                    };
                                    Ok::<_, Infallible>(Response::new(body))
                                }
                            });
                            if let Some(config) = tls {
                                if let Ok(socket) = TlsAcceptor::from(config).accept(socket).await {
                                    let name = socket.get_ref().1.server_name().unwrap_or("").to_owned();
                                    let _ = sni_events.try_send(name);
                                    let _ = server_h2::Builder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(socket), service).await;
                                }
                            } else {
                                let _ = server_h2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(socket), service).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(Self {
            address,
            observed,
            heads,
            connections,
            release,
            healthy,
            sni,
            task,
        })
    }

    async fn head(&mut self) -> Head {
        tokio::time::timeout(Duration::from_secs(3), self.observed.recv())
            .await
            .expect("fixture head deadline")
            .expect("fixture open")
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct HeldBody {
    marker: &'static str,
    phase: u8,
    released: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl HeldBody {
    fn new(marker: &'static str, release: Arc<Semaphore>) -> Self {
        Self {
            marker,
            phase: 0,
            released: Box::pin(async move {
                release
                    .acquire()
                    .await
                    .expect("release held response")
                    .forget();
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
        match self.phase {
            0 => {
                self.phase = 1;
                Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(
                    self.marker.as_bytes(),
                )))))
            }
            1 => {
                if self.released.as_mut().poll(context).is_pending() {
                    return Poll::Pending;
                }
                self.phase = 2;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"-finished")))))
            }
            2 => {
                self.phase = 3;
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
            }
            _ => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.phase == 3
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

struct Gateway {
    _directory: TempDir,
    running: RunningServer,
    cluster: Arc<PreparedCluster>,
    client: Arc<ClientConfig>,
}

impl Gateway {
    async fn start(dns: SocketAddr, port: u16) -> Self {
        Self::start_policy(
            dns,
            &format!(
                "name: endpoint.example.invalid\n          record: a_aaaa\n          port: {port}"
            ),
            "http",
            "",
            None,
            None,
        )
        .await
    }

    async fn start_srv(dns: SocketAddr, policy: &str, upstream_ca: Option<&str>) -> Self {
        Self::start_policy(
            dns,
            "name: _http._tcp.service.example.invalid\n          record: srv",
            if upstream_ca.is_some() {
                "https"
            } else {
                "http"
            },
            policy,
            upstream_ca,
            None,
        )
        .await
    }

    async fn start_policy(
        dns: SocketAddr,
        declaration: &str,
        scheme: &str,
        policy: &str,
        upstream_ca: Option<&str>,
        deadlines: Option<(&str, &str)>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("test-only source directory");
        let generated =
            rcgen::generate_simple_self_signed(vec!["discovery-gateway.example.test".to_owned()])
                .expect("test-only TLS identity");
        std::fs::write(directory.path().join("cert.pem"), generated.cert.pem()).expect("test cert");
        std::fs::write(
            directory.path().join("key.pem"),
            generated.signing_key.serialize_pem(),
        )
        .expect("publicly-known test key only");
        let (trust, tls) = if let Some(ca) = upstream_ca {
            std::fs::write(directory.path().join("upstream-ca.pem"), ca).expect("test-only CA");
            (
                "  trust_stores:\n    upstream:\n      ca_bundle: upstream-ca.pem\n",
                "      tls:\n        server_name: verified-upstream.example.test\n        trust:\n          system_roots: false\n          trust_store: upstream\n",
            )
        } else {
            ("", "")
        };
        let (response_header, pre_response_total) = deadlines.unwrap_or(("2s", "5s"));
        let source = format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    ingress:
      cert_chain: cert.pem
      private_key: key.pem
{trust}  clusters:
    api:
      protocol: h2
{tls}{policy}
      discovery:
        dns:
          {declaration}
          origin: {scheme}://logical.example.invalid:8123/base
          resolver:
            nameservers: ["{dns}"]
            query_timeout: 500ms
          refresh:
            min_interval: 50ms
            max_interval: 100ms
            jitter_percent: 0
            stale_if_error: 200ms
          limits:
            max_endpoints: 8
            max_targets: 8
          address_policy:
            allow_private: true
            allow_loopback: true
            allow_link_local: false
      timeouts:
        connect: 1s
        tls_handshake: 1s
        request_body_idle: 2s
        response_header: {response_header}
        response_body_idle: 5s
        pre_response_total: {pre_response_total}
services:
  root:
    type: proxy
    cluster: api
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: ingress
    http:
      versions: [h2]
    service:
      ref: root
"#
        );
        let path = directory.path().join("gateway.yaml");
        std::fs::write(&path, source).expect("source writes");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&path).expect("dynamic source compiles"),
        )
        .expect("dynamic source prepares without DNS");
        let cluster = Arc::clone(&snapshot.resources.clusters[&ResourceId::new("cluster:api")]);
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin"))
            .await
            .expect("admin binds")
            .spawn();
        let mut roots = RootCertStore::empty();
        roots.add(generated.cert.der().clone()).expect("test trust");
        let mut client = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("safe TLS")
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        Self {
            _directory: directory,
            running,
            cluster,
            client: Arc::new(client),
        }
    }

    async fn client(&self) -> H2Client {
        let socket = TcpStream::connect(self.running.local_addresses()[0].1)
            .await
            .expect("gateway connect");
        let name = ServerName::try_from("discovery-gateway.example.test").expect("name");
        let tls = TlsConnector::from(Arc::clone(&self.client))
            .connect(name, socket)
            .await
            .expect("TLS");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (sender, connection) = client_h2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("H2");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        H2Client { sender, driver }
    }

    async fn wait_members(&self, expected: Option<IpAddr>) {
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let endpoints = self.cluster.endpoints();
                let matches = expected.map_or_else(
                    || endpoints.is_empty(),
                    |address| {
                        endpoints.len() == 1
                            && endpoints[0]
                                .dial_target()
                                .is_some_and(|target| target.ip() == address)
                    },
                );
                if matches {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("DNS membership converges within a bounded deadline");
    }

    async fn metrics(&self) -> String {
        let mut socket = TcpStream::connect(self.running.admin_address().expect("admin address"))
            .await
            .expect("admin connect");
        socket
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("metrics request");
        let mut metrics = String::new();
        socket
            .read_to_string(&mut metrics)
            .await
            .expect("metrics response");
        metrics
    }
}

struct H2Client {
    sender: client_h2::SendRequest<Empty<Bytes>>,
    driver: tokio::task::JoinHandle<()>,
}

impl H2Client {
    async fn request(&mut self, path: &str) -> Response<Incoming> {
        let request = Request::builder()
            .uri(format!("https://discovery-gateway.example.test{path}"))
            .body(Empty::<Bytes>::new())
            .expect("request");
        tokio::time::timeout(Duration::from_secs(4), self.sender.send_request(request))
            .await
            .expect("head deadline")
            .expect("request head")
    }
}

impl Drop for H2Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn dns_record(question: &hickory_resolver::proto::op::Query, address: IpAddr, ttl: u32) -> Record {
    let data = match address {
        IpAddr::V4(address) => RData::A(A(address)),
        IpAddr::V6(address) => RData::AAAA(AAAA(address)),
    };
    Record::from_rdata(question.name().clone(), ttl, data)
}

async fn dns_fixture(
    state: Arc<AtomicU8>,
    first: IpAddr,
    second: IpAddr,
) -> (DnsFixture, Arc<AtomicU64>) {
    let zero_queries = Arc::new(AtomicU64::new(0));
    let observed_zero = Arc::clone(&zero_queries);
    let fixture = DnsFixture::start(move |question, _| {
        let current = state.load(Ordering::Acquire);
        if current == 0 {
            return FixtureReply::code(ResponseCode::ServFail);
        }
        if current == 3 {
            return FixtureReply::code(ResponseCode::NXDomain);
        }
        let selected = if current == 2 { second } else { first };
        let expected_type = if selected.is_ipv4() {
            RecordType::A
        } else {
            RecordType::AAAA
        };
        if question.query_type() != expected_type {
            return FixtureReply::answers(Vec::new());
        }
        let ttl = if current == 4 { 0 } else { 1 };
        if current == 4 {
            observed_zero.fetch_add(1, Ordering::Release);
        }
        let mut records = vec![dns_record(question, selected, ttl)];
        if current == 5 {
            records.push(dns_record(
                question,
                "169.254.0.1".parse().expect("link local"),
                ttl,
            ));
            records.push(dns_record(
                question,
                "0.0.0.0".parse().expect("unspecified"),
                ttl,
            ));
        }
        FixtureReply::answers(records)
    })
    .await;
    (fixture, zero_queries)
}

#[tokio::test]
async fn dns_rotation_moves_new_h2_stream_to_b_while_old_a_stream_finishes_with_trailers() {
    let mut first = Upstream::start(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0), "A")
        .await
        .expect("A binds");
    let second_bind = SocketAddr::new(
        "127.0.0.2".parse().expect("second IPv4"),
        first.address.port(),
    );
    // macOS can restrict nonconfigured loopback aliases. A native IPv6
    // loopback fallback still verifies distinct physical addresses, SAME port
    // and one unchanged logical identity without skipping the wire test.
    let mut second = match Upstream::start(second_bind, "B").await {
        Ok(upstream) => upstream,
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => Upstream::start(
            SocketAddr::new("::1".parse().expect("IPv6 loopback"), first.address.port()),
            "B",
        )
        .await
        .expect("B native IPv6 binds"),
        Err(error) => panic!("B binds a distinct address on A's port: {error}"),
    };
    assert_ne!(first.address.ip(), second.address.ip());
    assert_eq!(first.address.port(), second.address.port());
    let state = Arc::new(AtomicU8::new(1));
    let (fixture, _zero_queries) =
        dns_fixture(Arc::clone(&state), first.address.ip(), second.address.ip()).await;
    let gateway = Gateway::start(fixture.address, first.address.port()).await;
    let publication = gateway.running.reload_handle().published_runtime();
    let version = publication.snapshot.config_version.clone();
    gateway.wait_members(Some(first.address.ip())).await;
    let first_generation = gateway
        .cluster
        .discovery_status()
        .expect("status")
        .generation;
    let mut client = gateway.client().await;
    let response = client.request("/hold?z=2&a=1&encoded=%2f").await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut old_body = response.into_body();
    assert_eq!(
        old_body
            .frame()
            .await
            .expect("first DATA")
            .expect("frame")
            .into_data()
            .expect("DATA"),
        "A"
    );
    let observed = first.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/hold?z=2&a=1&encoded=%2f");

    state.store(2, Ordering::Release);
    gateway.wait_members(Some(second.address.ip())).await;
    assert!(
        gateway
            .cluster
            .discovery_status()
            .expect("status")
            .generation
            > first_generation
    );
    let response = client.request("/new?order=1&order=2").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("B body")
            .to_bytes(),
        "B"
    );
    let observed = second.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/new?order=1&order=2");
    assert_eq!(
        first.heads.load(Ordering::Acquire),
        1,
        "new stream cannot checkout A's old H2 pool"
    );
    assert_eq!(first.connections.load(Ordering::Acquire), 1);
    assert_eq!(second.connections.load(Ordering::Acquire), 1);

    first.release.add_permits(1);
    let remaining = old_body.collect().await.expect("issued A stream completes");
    assert_eq!(
        remaining
            .trailers()
            .expect("A response trailers")
            .get("grpc-status"),
        Some(&HeaderValue::from_static("0"))
    );
    assert_eq!(remaining.to_bytes(), "-finished");
    assert!(
        fixture.counts.udp.load(Ordering::Acquire) >= 2,
        "real numeric fixture queries occurred"
    );
    assert!(fixture.counts.responses_for("endpoint.example.invalid.") >= 2);
    assert!(
        fixture
            .counts
            .responses_for_type("endpoint.example.invalid.", RecordType::A)
            >= 1
    );
    let current = gateway.running.reload_handle().published_runtime();
    assert!(
        Arc::ptr_eq(&publication, &current),
        "DNS does not publish RuntimeSnapshot"
    );
    assert_eq!(current.etag(), publication.etag());
    assert_eq!(current.origin, RuntimeOrigin::Source);
    assert_eq!(current.snapshot.config_version, version);
    assert!(current.ready());
    let metrics = gateway.metrics().await;
    assert!(
        !metrics.contains("endpoint=\"discovered-"),
        "dynamic identity is not a metric label"
    );
    drop(client);
    gateway.running.shutdown().await.expect("gateway shutdown");
}

#[tokio::test]
async fn cold_failure_recovers_but_nxdomain_and_zero_ttl_revoke_real_pool_use() {
    let upstream = Upstream::start("127.0.0.1:0".parse().expect("bind"), "ready")
        .await
        .expect("upstream");
    let state = Arc::new(AtomicU8::new(0));
    let (fixture, zero_queries) = dns_fixture(
        Arc::clone(&state),
        upstream.address.ip(),
        upstream.address.ip(),
    )
    .await;
    let gateway = Gateway::start(fixture.address, upstream.address.port()).await;
    let publication = gateway.running.reload_handle().published_runtime();
    let mut client = gateway.client().await;
    let response = client.request("/cold").await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(upstream.heads.load(Ordering::Acquire), 0);
    assert!(
        publication.ready(),
        "DNS availability does not rewrite readiness contract"
    );

    state.store(1, Ordering::Release);
    gateway.wait_members(Some(upstream.address.ip())).await;
    assert_eq!(
        client
            .request("/live")
            .await
            .into_body()
            .collect()
            .await
            .expect("live body")
            .to_bytes(),
        "ready"
    );
    assert_eq!(upstream.heads.load(Ordering::Acquire), 1);

    for mode in [3, 4] {
        if mode == 4 {
            state.store(1, Ordering::Release);
            gateway.wait_members(Some(upstream.address.ip())).await;
            client
                .request("/restore-before-zero")
                .await
                .into_body()
                .collect()
                .await
                .expect("restored real peer");
        }
        let heads_before = upstream.heads.load(Ordering::Acquire);
        state.store(mode, Ordering::Release);
        if mode == 4 {
            tokio::time::timeout(Duration::from_secs(3), async {
                while zero_queries.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("a real TTL0 answer was emitted");
        }
        gateway.wait_members(None).await;
        let response = client.request("/revoked").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        response
            .into_body()
            .collect()
            .await
            .expect("safe error body");
        assert_eq!(
            upstream.heads.load(Ordering::Acquire),
            heads_before,
            "cached H2 connection must not bypass current eligibility"
        );
    }
    state.store(5, Ordering::Release);
    gateway.wait_members(Some(upstream.address.ip())).await;
    assert_eq!(
        client
            .request("/mixed")
            .await
            .into_body()
            .collect()
            .await
            .expect("allowed peer body")
            .to_bytes(),
        "ready"
    );
    assert_eq!(
        gateway.cluster.endpoints().len(),
        1,
        "link-local and unspecified results are never dial targets"
    );
    let current = gateway.running.reload_handle().published_runtime();
    assert!(Arc::ptr_eq(&publication, &current));
    assert_eq!(current.etag(), publication.etag());
    assert_eq!(current.origin, publication.origin);
    assert!(fixture.counts.udp.load(Ordering::Acquire) > 2);
    drop(client);
    gateway.running.shutdown().await.expect("gateway shutdown");
}

fn srv_record(
    question: &hickory_resolver::proto::op::Query,
    target: &str,
    port: u16,
    priority: u16,
    weight: u16,
) -> Record {
    Record::from_rdata(
        question.name().clone(),
        2,
        RData::SRV(SRV::new(
            priority,
            weight,
            port,
            Name::from_ascii(target).expect("target"),
        )),
    )
}

async fn wait_priority(gateway: &Gateway, priority: u16) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if gateway
                .cluster
                .discovery_status()
                .expect("SRV status")
                .eligible_priority
                == Some(priority)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("priority transition");
}

#[tokio::test]
async fn srv_health_priority_and_admission_cannot_send_saturated_primary_traffic_to_backup() {
    let mut primary = Upstream::start("127.0.0.1:0".parse().expect("bind"), "primary")
        .await
        .expect("primary");
    let mut backup = Upstream::start("127.0.0.1:0".parse().expect("bind"), "backup")
        .await
        .expect("backup");
    let primary_port = primary.address.port();
    let backup_port = backup.address.port();
    let fixture = DnsFixture::start(move |question, _| {
        if question.query_type() == RecordType::SRV {
            FixtureReply::answers(vec![
                srv_record(question, "primary.example.invalid.", primary_port, 0, 0),
                srv_record(
                    question,
                    "backup.example.invalid.",
                    backup_port,
                    20,
                    u16::MAX,
                ),
            ])
        } else if question.query_type() == RecordType::A {
            FixtureReply::answers(vec![dns_record(
                question,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                2,
            )])
        } else {
            FixtureReply::answers(Vec::new())
        }
    })
    .await;
    let gateway = Gateway::start_srv(fixture.address, "      health:\n        active:\n          path: /health\n          interval: 50ms\n          timeout: 500ms\n          healthy_threshold: 1\n          unhealthy_threshold: 1\n      limits:\n        max_in_flight: 4\n        max_in_flight_per_endpoint: 1\n        queue_timeout: 0ms\n", None).await;
    wait_priority(&gateway, 0).await;
    let published = gateway.running.reload_handle().published_runtime();
    let mut client = gateway.client().await;
    let held = client.request("/hold?raw=%2f&x=2&x=1").await;
    assert_eq!(held.status(), StatusCode::OK);
    let observed = primary.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/hold?raw=%2f&x=2&x=1");
    let rejected = client.request("/saturated").await;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
    rejected.into_body().collect().await.expect("safe overload");
    assert_eq!(
        backup.heads.load(Ordering::Acquire),
        0,
        "capacity is not permission to cross SRV priority"
    );
    primary.release.add_permits(1);
    held.into_body()
        .collect()
        .await
        .expect("held body finishes");
    primary.healthy.store(false, Ordering::Release);
    wait_priority(&gateway, 20).await;
    assert_eq!(
        client
            .request("/backup")
            .await
            .into_body()
            .collect()
            .await
            .expect("backup body")
            .to_bytes(),
        "backup"
    );
    let observed = backup.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/backup");
    primary.healthy.store(true, Ordering::Release);
    wait_priority(&gateway, 0).await;
    assert_eq!(
        client
            .request("/recovered")
            .await
            .into_body()
            .collect()
            .await
            .expect("primary body")
            .to_bytes(),
        "primary"
    );
    assert!(Arc::ptr_eq(
        &published,
        &gateway.running.reload_handle().published_runtime()
    ));
    let metrics = gateway.metrics().await;
    assert!(metrics.contains("family=\"srv\""));
    assert!(!metrics.contains("target=\"primary.example"));
    drop(client);
    gateway.running.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn srv_weight_only_reuses_pool_but_withdrawal_and_new_target_do_not_reuse_it() {
    let mut first = Upstream::start("127.0.0.1:0".parse().expect("bind"), "A")
        .await
        .expect("A");
    let mut second = Upstream::start("127.0.0.1:0".parse().expect("bind"), "B")
        .await
        .expect("B");
    let first_port = first.address.port();
    let second_port = second.address.port();
    let state = Arc::new(AtomicU8::new(0));
    let service_queries = Arc::new(AtomicU64::new(0));
    let address_queries = Arc::new(AtomicU64::new(0));
    let mode = Arc::clone(&state);
    let srv_count = Arc::clone(&service_queries);
    let address_count = Arc::clone(&address_queries);
    let fixture = DnsFixture::start(move |question, _| {
        let mode = mode.load(Ordering::Acquire);
        if question.query_type() == RecordType::SRV {
            srv_count.fetch_add(1, Ordering::Release);
            let (target, port) = match mode {
                2 => (".", first_port),
                3 => ("second.example.invalid.", second_port),
                _ => ("first.example.invalid.", first_port),
            };
            FixtureReply::answers(vec![srv_record(
                question,
                target,
                port,
                0,
                if mode == 1 { u16::MAX } else { 0 },
            )])
        } else {
            address_count.fetch_add(1, Ordering::Release);
            if question.query_type() == RecordType::A {
                FixtureReply::answers(vec![dns_record(
                    question,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    2,
                )])
            } else {
                FixtureReply::answers(Vec::new())
            }
        }
    })
    .await;
    let gateway = Gateway::start_srv(fixture.address, "", None).await;
    wait_priority(&gateway, 0).await;
    let publication = gateway.running.reload_handle().published_runtime();
    let endpoint = Arc::clone(&gateway.cluster.endpoints()[0]);
    assert_eq!(
        endpoint.dial_target().expect("numeric target").port(),
        first_port
    );
    let mut client = gateway.client().await;
    let mut held = client.request("/hold").await.into_body();
    assert_eq!(
        held.frame()
            .await
            .expect("DATA")
            .expect("frame")
            .into_data()
            .expect("DATA"),
        "A"
    );
    first.head().await;
    let previous_queries = service_queries.load(Ordering::Acquire);
    state.store(1, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = gateway.cluster.discovery_status().expect("SRV status");
            if service_queries.load(Ordering::Acquire) > previous_queries
                && status
                    .srv_targets
                    .iter()
                    .any(|target| target.weight == u16::MAX)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("weight changes");
    assert!(
        Arc::ptr_eq(&endpoint, &gateway.cluster.endpoints()[0]),
        "weight changes do not reset endpoint identity"
    );
    assert_eq!(
        client
            .request("/same-pool")
            .await
            .into_body()
            .collect()
            .await
            .expect("A body")
            .to_bytes(),
        "A"
    );
    first.head().await;
    assert_eq!(
        first.connections.load(Ordering::Acquire),
        1,
        "existing H2 client remains reusable for unchanged physical member"
    );
    state.store(2, Ordering::Release);
    gateway.wait_members(None).await;
    assert_eq!(
        gateway
            .cluster
            .discovery_status()
            .expect("status")
            .resolution,
        oxidase_runtime::DiscoveryResolutionState::ServiceUnavailable
    );
    let address_before = address_queries.load(Ordering::Acquire);
    let service_before = service_queries.load(Ordering::Acquire);
    assert_eq!(
        client.request("/withdrawn").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while service_queries.load(Ordering::Acquire) <= service_before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("dot refresh");
    assert_eq!(
        address_queries.load(Ordering::Acquire),
        address_before,
        "dot never becomes an address lookup"
    );
    state.store(3, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if gateway.cluster.endpoints().first().is_some_and(|endpoint| {
                endpoint.dial_target().expect("target").port() == second_port
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("new SRV target");
    assert_eq!(
        client
            .request("/new?z=1&a=2")
            .await
            .into_body()
            .collect()
            .await
            .expect("B body")
            .to_bytes(),
        "B"
    );
    let observed = second.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/new?z=1&a=2");
    assert_eq!(
        first.heads.load(Ordering::Acquire),
        2,
        "removed H2 pool cannot receive new streams"
    );
    first.release.add_permits(1);
    let remainder = held.collect().await.expect("retired A stream finishes");
    assert_eq!(remainder.trailers().expect("trailers")["grpc-status"], "0");
    assert_eq!(remainder.to_bytes(), "-finished");
    assert!(Arc::ptr_eq(
        &publication,
        &gateway.running.reload_handle().published_runtime()
    ));
    drop(client);
    gateway.running.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn srv_actual_socket_preserves_fixed_tls_name_and_rejects_an_untrusted_replacement() {
    let trusted =
        rcgen::generate_simple_self_signed(vec!["verified-upstream.example.test".to_owned()])
            .expect("test cert");
    let untrusted =
        rcgen::generate_simple_self_signed(vec!["verified-upstream.example.test".to_owned()])
            .expect("untrusted test cert");
    let server_config = |identity: &rcgen::CertifiedKey<rcgen::KeyPair>| {
        let key = tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
            identity.signing_key.serialize_der(),
        )
        .into();
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![identity.cert.der().clone()], key)
            .expect("test key");
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    };
    let mut first = Upstream::start_transport(
        "127.0.0.1:0".parse().expect("bind"),
        "trusted",
        Some(server_config(&trusted)),
    )
    .await
    .expect("trusted upstream");
    let second = Upstream::start_transport(
        "127.0.0.1:0".parse().expect("bind"),
        "untrusted",
        Some(server_config(&untrusted)),
    )
    .await
    .expect("untrusted upstream");
    let first_port = first.address.port();
    let second_port = second.address.port();
    let state = Arc::new(AtomicU8::new(0));
    let mode = Arc::clone(&state);
    let fixture = DnsFixture::start(move |question, _| {
        if question.query_type() == RecordType::SRV {
            FixtureReply::answers(vec![srv_record(
                question,
                "attacker-chosen-target.example.invalid.",
                if mode.load(Ordering::Acquire) == 0 {
                    first_port
                } else {
                    second_port
                },
                0,
                1,
            )])
        } else if question.query_type() == RecordType::A {
            FixtureReply::answers(vec![dns_record(
                question,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                2,
            )])
        } else {
            FixtureReply::answers(Vec::new())
        }
    })
    .await;
    let gateway = Gateway::start_srv(fixture.address, "", Some(&trusted.cert.pem())).await;
    wait_priority(&gateway, 0).await;
    let mut client = gateway.client().await;
    assert_eq!(
        client
            .request("/secure?x=%2f")
            .await
            .into_body()
            .collect()
            .await
            .expect("trusted body")
            .to_bytes(),
        "trusted"
    );
    let observed = first.head().await;
    assert_eq!(observed.authority, "logical.example.invalid:8123");
    assert_eq!(observed.path, "/base/secure?x=%2f");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), first.sni.recv())
            .await
            .expect("SNI deadline")
            .expect("SNI"),
        "verified-upstream.example.test"
    );
    state.store(1, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !gateway
            .cluster
            .endpoints()
            .first()
            .is_some_and(|endpoint| endpoint.dial_target().expect("target").port() == second_port)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("untrusted target becomes current dial candidate");
    let response = client.request("/untrusted").await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("safe failure")
        .to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains("verified-upstream"));
    assert_eq!(
        second.heads.load(Ordering::Acquire),
        0,
        "TLS validation precedes HTTP dispatch at the actual new address"
    );
    assert_eq!(
        first.heads.load(Ordering::Acquire),
        1,
        "old authenticated H2 pool cannot bypass new target"
    );
    drop(client);
    gateway.running.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn retry_across_a_new_srv_generation_keeps_the_original_total_deadline() {
    let mut first = Upstream::start("127.0.0.1:0".parse().expect("bind"), "A")
        .await
        .expect("A");
    let mut second = Upstream::start("127.0.0.1:0".parse().expect("bind"), "B")
        .await
        .expect("B");
    let mut third = Upstream::start("127.0.0.1:0".parse().expect("bind"), "C")
        .await
        .expect("C");
    let first_port = first.address.port();
    let second_port = second.address.port();
    let third_port = third.address.port();
    let state = Arc::new(AtomicU8::new(0));
    let mode = Arc::clone(&state);
    let fixture = DnsFixture::start(move |question, _| {
        if question.query_type() == RecordType::SRV {
            let (target, port) = match mode.load(Ordering::Acquire) {
                0 => ("first.example.invalid.", first_port),
                1 => ("second.example.invalid.", second_port),
                _ => ("third.example.invalid.", third_port),
            };
            FixtureReply::answers(vec![srv_record(question, target, port, 0, 1)])
        } else if question.query_type() == RecordType::A {
            FixtureReply::answers(vec![dns_record(
                question,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                2,
            )])
        } else {
            FixtureReply::answers(Vec::new())
        }
    })
    .await;
    let gateway = Gateway::start_policy(fixture.address,
        "name: _http._tcp.service.example.invalid\n          record: srv", "http",
        "      retry:\n        max_attempts: 8\n        methods: [GET]\n        retry_on: [response_header_timeout]\n        max_concurrent_retries: 4\n",
        None, Some(("200ms", "450ms"))).await;
    wait_priority(&gateway, 0).await;
    let publication = gateway.running.reload_handle().published_runtime();
    let generation = gateway
        .cluster
        .discovery_status()
        .expect("status")
        .generation;
    let mut client = gateway.client().await;
    let pending = tokio::spawn(async move {
        let response = client.request("/delayed?wire=%2f&x=1&x=2").await;
        (
            response.status(),
            response
                .into_body()
                .collect()
                .await
                .expect("safe timeout body")
                .to_bytes(),
        )
    });
    let head = first.head().await;
    assert_eq!(head.authority, "logical.example.invalid:8123");
    assert_eq!(head.path, "/base/delayed?wire=%2f&x=1&x=2");
    state.store(1, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(3), async {
        while !gateway
            .cluster
            .endpoints()
            .first()
            .is_some_and(|endpoint| endpoint.dial_target().expect("target").port() == second_port)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("generation changes before retry");
    let head = second.head().await;
    assert_eq!(head.authority, "logical.example.invalid:8123");
    assert_eq!(head.path, "/base/delayed?wire=%2f&x=1&x=2");
    // The retry policy deliberately never repeats a tried member. Supply a
    // third real incarnation before B's header deadline so the terminal cause
    // measures the original total budget, not two-member history exhaustion.
    state.store(2, Ordering::Release);
    let head = third.head().await;
    assert_eq!(head.authority, "logical.example.invalid:8123");
    assert_eq!(head.path, "/base/delayed?wire=%2f&x=1&x=2");
    let (status, body) = pending.await.expect("request task");
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert!(!String::from_utf8_lossy(&body).contains("second.example"));
    assert!(
        gateway
            .cluster
            .discovery_status()
            .expect("status")
            .generation
            > generation
    );
    let attempts = first.heads.load(Ordering::Acquire)
        + second.heads.load(Ordering::Acquire)
        + third.heads.load(Ordering::Acquire);
    assert!(
        (3..8).contains(&attempts),
        "total budget terminates before configured attempt exhaustion"
    );
    let metrics = gateway.metrics().await;
    assert!(
        metrics.contains("oxidase_upstream_timeouts_total{phase=\"total\"} 1\n"),
        "the terminal cause is the first logical total deadline, not a fresh per-retry head timer: {metrics}"
    );
    assert!(Arc::ptr_eq(
        &publication,
        &gateway.running.reload_handle().published_runtime()
    ));
    tokio::time::timeout(Duration::from_secs(3), async {
        while gateway.cluster.active_requests() != 0
            || gateway
                .cluster
                .endpoints()
                .iter()
                .any(|endpoint| endpoint.active_requests() != 0)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("deadline releases cluster and endpoint permits");
    gateway.running.shutdown().await.expect("shutdown");
}
