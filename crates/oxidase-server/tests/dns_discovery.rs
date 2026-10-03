//! Real DNS→lease→pool→peer integration. No public DNS, fixed listening port,
//! system OpenSSL, or alternate gateway data plane is involved.

#[path = "support/dns_fixture.rs"]
mod dns_fixture;

use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dns_fixture::{DnsFixture, FixtureReply};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::rdata::{A, AAAA};
use hickory_resolver::proto::rr::{RData, Record, RecordType};
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
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

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
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(address: SocketAddr, marker: &'static str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let (events, observed) = mpsc::channel(32);
        let heads = Arc::new(AtomicU64::new(0));
        let connections = Arc::new(AtomicU64::new(0));
        let release = Arc::new(Semaphore::new(0));
        let task_heads = Arc::clone(&heads);
        let task_connections = Arc::clone(&connections);
        let task_release = Arc::clone(&release);
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
                        tasks.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let events = events.clone();
                                let heads = Arc::clone(&heads);
                                let release = Arc::clone(&release);
                                async move {
                                    heads.fetch_add(1, Ordering::Relaxed);
                                    let authority = request.uri().authority().map_or_else(
                                        || request.headers().get(header::HOST).and_then(|value| value.to_str().ok()).unwrap_or("").to_owned(),
                                        |authority| authority.as_str().to_owned(),
                                    );
                                    let path = request.uri().path_and_query().expect("origin form").as_str().to_owned();
                                    let _ = events.try_send(Head { authority, path: path.clone() });
                                    let body: FixtureBody = if path.starts_with("/base/hold") {
                                        HeldBody::new(marker, release).boxed_unsync()
                                    } else {
                                        Full::new(Bytes::copy_from_slice(marker.as_bytes())).boxed_unsync()
                                    };
                                    Ok::<_, Infallible>(Response::new(body))
                                }
                            });
                            let _ = server_h2::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(socket), service).await;
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
        let source = format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    ingress:
      cert_chain: cert.pem
      private_key: key.pem
  clusters:
    api:
      protocol: h2
      discovery:
        dns:
          name: endpoint.example.invalid
          record: a_aaaa
          port: {port}
          origin: http://logical.example.invalid:8123/base
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
        response_header: 2s
        response_body_idle: 5s
        pre_response_total: 5s
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
