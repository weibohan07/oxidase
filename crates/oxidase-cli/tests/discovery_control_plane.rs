//! Phase-six publication qualification through actual CLI/Admin and DNS I/O.

#![cfg(unix)]

#[path = "../../oxidase-server/tests/support/dns_fixture.rs"]
mod dns_fixture;

use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::io::{BufRead as _, BufReader};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use dns_fixture::{DnsFixture, FixtureReply};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::rdata::{A, AAAA, SRV};
use hickory_resolver::proto::rr::{Name, RData, Record, RecordType};
use http::{Request, Response, StatusCode, header};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_bundle::{BundleArchive, BundleLimits, BundleSigningKey};
use oxidase_config::Compiler;
use oxidase_core::ResourceId;
use oxidase_runtime::{PublishedRuntime, RuntimeOrigin, RuntimeSnapshot, ServingState};
use oxidase_server::{GatewayServer, RunningServer};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::Semaphore;

const TOKEN: &str = "test-only-discovery-control-token";

struct HeldBody {
    prefix: Option<Bytes>,
    release: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Body for HeldBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(prefix))));
        }
        self.release.as_mut().poll(cx).map(|()| None)
    }
}

struct Upstream {
    address: SocketAddr,
    release: Arc<Semaphore>,
    requests: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn bind(address: &str, marker: &'static str) -> Self {
        let listener = TcpListener::bind(address)
            .await
            .expect("ephemeral upstream");
        let address = listener.local_addr().expect("upstream address");
        let release = Arc::new(Semaphore::new(0));
        let requests = Arc::new(AtomicU64::new(0));
        let gate = Arc::clone(&release);
        let count = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break; };
                        let release = Arc::clone(&gate);
                        let count = Arc::clone(&count);
                        connections.spawn(async move {
                            let service = service_fn(move |request: Request<Incoming>| {
                                let gate = Arc::clone(&release);
                                count.fetch_add(1, Ordering::Relaxed);
                                async move {
                                    assert_eq!(request.headers()[header::HOST], "fixed-origin.qual.test:8080");
                                    let hold = request.uri().path() == "/base/hold";
                                    let body = if hold {
                                        HeldBody { prefix: Some(Bytes::from_static(marker.as_bytes())), release: Box::pin(async move {
                                            gate.acquire_owned().await.expect("fixture gate").forget();
                                        }) }.boxed_unsync()
                                    } else {
                                        Full::new(Bytes::from_static(marker.as_bytes())).boxed_unsync()
                                    };
                                    Ok::<_, Infallible>(Response::new(body))
                                }
                            });
                            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                        });
                    }
                }
            }
        });
        Self {
            address,
            release,
            requests,
            task,
        }
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct DiscoveryFixture {
    dns: DnsFixture,
    mode: Arc<AtomicU8>,
    delay_a: Arc<AtomicBool>,
    late_a: Arc<AtomicU64>,
    release_a_response: Arc<Semaphore>,
    delay_source: Arc<AtomicBool>,
    late_source: Arc<AtomicU64>,
    release_source_response: Arc<Semaphore>,
    ipv4: Upstream,
    ipv6: Upstream,
    b: Upstream,
}

impl DiscoveryFixture {
    async fn start() -> Self {
        let ipv4 = Upstream::bind("127.0.0.1:0", "peer-v4").await;
        let ipv6 = Upstream::bind(&format!("[::1]:{}", ipv4.address.port()), "peer-v6").await;
        let b = Upstream::bind("127.0.0.1:0", "peer-b").await;
        let b_port = b.address.port();
        let mode = Arc::new(AtomicU8::new(0));
        let delay_a = Arc::new(AtomicBool::new(false));
        let late_a = Arc::new(AtomicU64::new(0));
        let release_a_response = Arc::new(Semaphore::new(0));
        let delay_source = Arc::new(AtomicBool::new(false));
        let late_source = Arc::new(AtomicU64::new(0));
        let release_source_response = Arc::new(Semaphore::new(0));
        let answers = Arc::clone(&mode);
        let delayed = Arc::clone(&delay_a);
        let observed = Arc::clone(&late_a);
        let a_response_gate = Arc::clone(&release_a_response);
        let source_delayed = Arc::clone(&delay_source);
        let source_observed = Arc::clone(&late_source);
        let source_response_gate = Arc::clone(&release_source_response);
        let dns = DnsFixture::start(move |question, _| {
            let name = question.name().to_ascii();
            let mut reply = if question.query_type() == RecordType::SRV {
                FixtureReply::answers(vec![Record::from_rdata(
                    question.name().clone(),
                    1,
                    RData::SRV(SRV::new(
                        0,
                        65535,
                        b_port,
                        Name::from_ascii("b-target.qual.test.").expect("target"),
                    )),
                )])
            } else if name == "b-target.qual.test." {
                FixtureReply::answers(if question.query_type() == RecordType::A {
                    vec![Record::from_rdata(
                        question.name().clone(),
                        1,
                        RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                    )]
                } else {
                    Vec::new()
                })
            } else {
                let mode = answers.load(Ordering::Acquire);
                let records = match (mode, question.query_type()) {
                    (0, RecordType::A) => vec![Record::from_rdata(
                        question.name().clone(),
                        1,
                        RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
                    )],
                    (1, RecordType::AAAA) => vec![Record::from_rdata(
                        question.name().clone(),
                        1,
                        RData::AAAA(AAAA(std::net::Ipv6Addr::LOCALHOST)),
                    )],
                    _ => Vec::new(),
                };
                let mut reply = if records.is_empty() {
                    FixtureReply::code(ResponseCode::NoError)
                } else {
                    FixtureReply::answers(records)
                };
                // Cold-start tests need unavailable discovery, not an unrelated
                // 30-second query timeout delaying subsequent recovery.
                if mode == 2 {
                    reply.code = ResponseCode::ServFail;
                }
                reply
            };
            // The signed SRV candidate also exercises Hickory's actual UDP
            // truncation -> TCP fallback, not merely a bound TCP fixture port.
            if question.query_type() == RecordType::SRV {
                reply.truncate_udp = true;
            }
            if name == "a.qual.test."
                && question.query_type() == RecordType::A
                && delayed.load(Ordering::Acquire)
            {
                observed.fetch_add(1, Ordering::Release);
                reply.response_gate = Some(Arc::clone(&a_response_gate));
            }
            if name == "source.qual.test."
                && question.query_type() == RecordType::A
                && source_delayed.load(Ordering::Acquire)
            {
                source_observed.fetch_add(1, Ordering::Release);
                reply.response_gate = Some(Arc::clone(&source_response_gate));
            }
            reply
        })
        .await;
        Self {
            dns,
            mode,
            delay_a,
            late_a,
            release_a_response,
            delay_source,
            late_source,
            release_source_response,
            ipv4,
            ipv6,
            b,
        }
    }
}

struct Deployment {
    _directory: TempDir,
    root: PathBuf,
    config: PathBuf,
    token: PathBuf,
    socket: PathBuf,
    signer: PathBuf,
}

impl Deployment {
    fn new() -> Self {
        let directory = tempdir().expect("deployment root");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical deployment");
        let signer = root.join("test-only-signer");
        fs::write(&signer, [31; 32]).expect("public test-only signing seed");
        fs::set_permissions(&signer, fs::Permissions::from_mode(0o600))
            .expect("private fixture key");
        let key = BundleSigningKey::read_file(&signer).expect("test key");
        fs::write(root.join("operator.pub"), key.verification_key().as_bytes())
            .expect("verification key");
        let token = root.join("admin.token");
        fs::write(&token, format!("{TOKEN}\n")).expect("test-only LF token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))
            .expect("private fixture token");
        Self {
            config: root.join("oxidase.yaml"),
            socket: root.join("admin.sock"),
            _directory: directory,
            root,
            token,
            signer,
        }
    }

    fn source(
        &self,
        fixture: &DiscoveryFixture,
        label: &str,
        name: &str,
        srv: bool,
        bind: &str,
    ) -> String {
        let record = if srv {
            "          record: srv\n".to_owned()
        } else {
            format!(
                "          record: a_aaaa\n          port: {}\n",
                fixture.ipv4.address.port()
            )
        };
        format!(
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  secrets:\n    admin-token:\n      file: admin.token\n  clusters:\n    api:\n      protocol: http1\n      discovery:\n        dns:\n          name: {name}\n{record}          origin: http://fixed-origin.qual.test:8080/base/\n          resolver:\n            nameservers: [\"{}\"]\n            query_timeout: 30s\n          refresh:\n            min_interval: 20ms\n            max_interval: 50ms\n            jitter_percent: 0\n            stale_if_error: 0ms\n          address_policy:\n            allow_loopback: true\nservices:\n  root:\n    type: route\n    cases:\n      - when:\n          path: /version\n        service:\n          type: respond\n          body:\n            text: {label}\n    default:\n      type: proxy\n      cluster: api\nlisteners:\n  - name: public\n    bind: {bind}\n    protocol: http\n    service:\n      ref: root\nadmin:\n  listen:\n    unix:\n      path: {}\n      mode: \"0600\"\n  auth:\n    mode: bearer\n    token_secret: admin-token\n  storage:\n    directory: {}\n  bundle_trust:\n    verification_keys: [operator.pub]\n  permissions:\n    read: true\n    stage: true\n    activate: true\n    rollback: true\n    drain: true\n    reload_source: true\n  audit:\n    destination: file\n    file: {}\n",
            fixture.dns.address,
            self.socket.display(),
            self.root.join("state").display(),
            self.root.join("audit.jsonl").display()
        )
    }

    fn ctl_args(&self, operation: &[String], etag: Option<&str>, key: Option<&str>) -> Vec<String> {
        let mut args = vec![
            "ctl".to_owned(),
            "--unix".to_owned(),
            utf8(&self.socket),
            "--token-file".to_owned(),
            utf8(&self.token),
            "--timeout".to_owned(),
            "10s".to_owned(),
        ];
        if let Some(etag) = etag {
            args.extend(["--if-match".to_owned(), etag.to_owned()]);
        }
        if let Some(key) = key {
            args.extend(["--idempotency-key".to_owned(), key.to_owned()]);
        }
        args.extend_from_slice(operation);
        args
    }

    async fn ctl(&self, operation: &[String]) -> Value {
        cli_json(self.ctl_args(operation, None, None)).await
    }

    async fn conditional(
        &self,
        operation: &[String],
        published: &PublishedRuntime,
        key: &str,
    ) -> Value {
        cli_json(self.ctl_args(operation, Some(&published.etag()), Some(key))).await
    }

    async fn signed_bundle(&self, label: &str, source: &str) -> (PathBuf, String) {
        let input = self.root.join(format!("{label}.yaml"));
        let output = self.root.join(format!("{label}.oxb"));
        fs::write(&input, source).expect("Bundle source");
        let built = cli_json(vec![
            "bundle".to_owned(),
            "build".to_owned(),
            utf8(&input),
            "--output".to_owned(),
            utf8(&output),
            "--deployment-root".to_owned(),
            utf8(&self.root),
        ])
        .await;
        cli_json(vec![
            "bundle".to_owned(),
            "sign".to_owned(),
            utf8(&output),
            "--key".to_owned(),
            utf8(&self.signer),
        ])
        .await;
        let archive = BundleArchive::read_path(&output, &BundleLimits::default())
            .expect("CLI-produced signed archive");
        let plan: oxidase_runtime::PortableRuntimePlanV1 = archive.manifest().sections["runtime"]
            .to_serde()
            .expect("portable policy");
        assert_eq!(
            archive.manifest().required_features,
            plan.required_features()
        );
        assert_eq!(archive.signatures().signatures.len(), 1);
        let policy = serde_json::to_value(&plan.gateway.clusters["cluster:api"].discovery)
            .expect("policy JSON");
        for prohibited in ["addresses", "answers", "generation", "expires_at", "health"] {
            assert!(
                policy.get(prohibited).is_none(),
                "live {prohibited} is not a portable field"
            );
        }
        (
            output,
            built["content_digest"]
                .as_str()
                .expect("Bundle digest")
                .to_owned(),
        )
    }

    async fn metrics(&self) -> String {
        let stream = UnixStream::connect(&self.socket)
            .await
            .expect("authenticated Admin socket");
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .expect("Admin H1");
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/metrics")
                    .header(header::HOST, "admin")
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .body(Full::new(Bytes::new()))
                    .expect("metrics request"),
            )
            .await
            .expect("metrics response");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("metrics body")
            .to_bytes();
        drop(sender);
        driver.abort();
        let _ = driver.await;
        String::from_utf8(bytes.to_vec()).expect("metrics UTF-8")
    }
}

fn utf8(path: &Path) -> String {
    path.to_str().expect("UTF-8 fixture path").to_owned()
}

async fn cli_output(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .args(["--diagnostic-format", "json"])
            .args(args)
            .output()
            .expect("actual CLI process")
    })
    .await
    .expect("CLI worker")
}

async fn cli_json(args: Vec<String>) -> Value {
    let output = cli_output(args.clone()).await;
    assert!(
        output.status.success(),
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
    serde_json::from_slice(&output.stdout).expect("one CLI JSON document")
}

async fn head(
    address: SocketAddr,
    path: &str,
) -> (
    Response<Incoming>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
) {
    let stream = TcpStream::connect(address).await.expect("gateway connects");
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .expect("downstream H1");
    let task = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::builder()
                .uri(path)
                .header(header::HOST, "client.qual.test")
                .body(Full::new(Bytes::new()))
                .expect("data request"),
        )
        .await
        .expect("data head");
    (response, task)
}

async fn data(address: SocketAddr, path: &str) -> (StatusCode, Bytes) {
    let (response, driver) = head(address, path).await;
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("data body")
        .to_bytes();
    driver.abort();
    let _ = driver.await;
    (status, bytes)
}

async fn wait_peer(address: SocketAddr, marker: &str) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let (status, body) = data(address, "/").await;
            if status == StatusCode::OK && body == marker {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real DNS→selected peer becomes ready");
}

async fn wait_queries(count: &AtomicU64, minimum: u64) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while count.load(Ordering::Acquire) < minimum {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("real query observed");
}

async fn wait_positive_response(fixture: &DiscoveryFixture, name: &str, minimum: u64) {
    tokio::time::timeout(Duration::from_secs(6), async {
        while fixture.dns.counts.responses_for_type(name, RecordType::A) < minimum {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("actual delayed DNS reply-send acknowledgement");
    assert!(fixture.dns.counts.responses_for(name) >= minimum);
}

fn assert_publication_same(before: &Arc<PublishedRuntime>, running: &RunningServer) {
    let current = running.reload_handle().published_runtime();
    assert!(
        Arc::ptr_eq(before, &current),
        "DNS cannot clone or replace PublishedRuntime"
    );
    assert_eq!(current.etag(), before.etag());
    assert_eq!(current.origin, before.origin);
    assert_eq!(current.runtime_revision, before.runtime_revision);
    assert_eq!(current.source_origin, before.source_origin);
}

#[tokio::test]
async fn signed_dns_publications_preserve_cas_fence_late_owners_and_resume_only_explicitly() {
    let fixture = DiscoveryFixture::start().await;
    let deployment = Deployment::new();
    let source = deployment.source(&fixture, "source", "source.qual.test", false, "127.0.0.1:0");
    fs::write(&deployment.config, &source).expect("initial source");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&deployment.config).expect("compile Source"),
    )
    .expect("prepare Source");
    let server = GatewayServer::bind(snapshot).await.expect("real server");
    let address = server.local_addresses()[0].1;
    let running = server.spawn();
    wait_peer(address, "peer-v4").await;
    let initial = running.reload_handle().published_runtime();
    let history = deployment.ctl(&["history".to_owned()]).await;
    let source_cluster =
        Arc::clone(&initial.snapshot.resources.clusters[&ResourceId::new("cluster:api")]);
    let initial_generation = source_cluster
        .discovery_status()
        .expect("status")
        .generation;
    fixture.mode.store(1, Ordering::Release);
    wait_peer(address, "peer-v6").await;
    fixture.mode.store(0, Ordering::Release);
    wait_peer(address, "peer-v4").await;
    let calls = fixture.dns.counts.udp.load(Ordering::Acquire);
    wait_queries(&fixture.dns.counts.udp, calls + 12).await;
    assert!(
        source_cluster
            .discovery_status()
            .expect("generation")
            .generation
            > initial_generation
    );
    assert_publication_same(&initial, &running);
    assert_eq!(
        deployment.ctl(&["history".to_owned()]).await["history"],
        history["history"]
    );

    let (mut old_response, old_driver) = head(address, "/hold").await;
    assert_eq!(old_response.status(), StatusCode::OK);
    assert_eq!(
        old_response
            .body_mut()
            .frame()
            .await
            .expect("held prefix")
            .expect("prefix frame")
            .into_data()
            .expect("DATA"),
        "peer-v4"
    );
    let (a_file, a) = deployment
        .signed_bundle(
            "A",
            &deployment.source(&fixture, "A", "a.qual.test", false, "127.0.0.1:0"),
        )
        .await;
    let (b_file, b) = deployment
        .signed_bundle(
            "B",
            &deployment.source(&fixture, "B", "_http._tcp.b.qual.test", true, "127.0.0.1:0"),
        )
        .await;
    for (label, file, digest) in [("A", a_file, a.clone()), ("B", b_file, b.clone())] {
        deployment
            .conditional(
                &["stage".to_owned(), utf8(&file)],
                &initial,
                &format!("stage-{label}"),
            )
            .await;
        deployment
            .conditional(
                &["validate".to_owned(), digest],
                &initial,
                &format!("validate-{label}"),
            )
            .await;
        assert_publication_same(&initial, &running);
    }
    deployment
        .conditional(&["activate".to_owned(), a.clone()], &initial, "activate-A")
        .await;
    let published_a = running.reload_handle().published_runtime();
    assert!(matches!(published_a.origin, RuntimeOrigin::Bundle { .. }));
    assert_eq!(
        published_a
            .bundle_digest()
            .expect("Bundle origin")
            .to_string(),
        a
    );
    wait_peer(address, "peer-v4").await;
    assert_eq!(
        source_cluster
            .discovery_status()
            .expect("retired source")
            .resolution,
        oxidase_runtime::DiscoveryResolutionState::Retired
    );
    assert!(
        source_cluster.active_requests() > 0,
        "old real streaming request still pins its permit"
    );
    assert!(
        deployment
            .metrics()
            .await
            .contains("oxidase_discovery_active_supervisors 1\n")
    );

    fixture.delay_a.store(true, Ordering::Release);
    wait_queries(&fixture.late_a, 1).await;
    deployment
        .conditional(
            &["activate".to_owned(), b.clone()],
            &published_a,
            "activate-B",
        )
        .await;
    let published_b = running.reload_handle().published_runtime();
    assert_eq!(
        published_a.snapshot.resources.clusters[&ResourceId::new("cluster:api")]
            .discovery_status()
            .expect("retired A owner")
            .resolution,
        oxidase_runtime::DiscoveryResolutionState::Retired
    );
    // A positive query was received, but its reply cannot be written before
    // this explicit release, which happens strictly after owner retirement.
    let sent_a = fixture
        .dns
        .counts
        .responses_for_type("a.qual.test.", RecordType::A);
    fixture.release_a_response.add_permits(1);
    wait_peer(address, "peer-b").await;
    assert!(fixture.dns.counts.tcp.load(Ordering::Acquire) > 0);
    let old_peer_heads = fixture.ipv4.requests.load(Ordering::Acquire);
    wait_positive_response(&fixture, "a.qual.test.", sent_a + 1).await;
    assert_publication_same(&published_b, &running);
    assert_eq!(data(address, "/version").await.1, "B");
    assert_eq!(
        published_b.snapshot.resources.clusters[&ResourceId::new("cluster:api")]
            .spec()
            .discovery
            .as_ref()
            .expect("B policy")
            .record,
        oxidase_config::DnsRecordType::Srv
    );
    wait_peer(address, "peer-b").await;
    assert_eq!(
        fixture.ipv4.requests.load(Ordering::Acquire),
        old_peer_heads,
        "new traffic cannot borrow the retired A pool"
    );
    assert_eq!(
        published_a.snapshot.resources.clusters[&ResourceId::new("cluster:api")]
            .endpoints()
            .len(),
        0,
        "late old resolver reply cannot repopulate retired A"
    );
    assert!(
        deployment
            .metrics()
            .await
            .contains("oxidase_discovery_active_supervisors 1\n")
    );
    fixture.ipv4.release.add_permits(1);
    old_response
        .into_body()
        .collect()
        .await
        .expect("old Source stream completes after Bundle B");
    old_driver.abort();
    let _ = old_driver.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while source_cluster.active_requests() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stream permit returned");
    fixture.delay_a.store(false, Ordering::Release);

    let changed_source = deployment.source(
        &fixture,
        "source-latest",
        "source.qual.test",
        false,
        "127.0.0.1:0",
    );
    fs::write(&deployment.config, &changed_source).expect("candidate Source mutation");
    assert!(
        running
            .reload_handle()
            .reload_watched_path(&deployment.config)
            .await
            .is_err(),
        "watcher has no authority over Bundle publication"
    );
    assert_publication_same(&published_b, &running);
    deployment
        .conditional(&["rollback".to_owned(), a], &published_b, "rollback-A")
        .await;
    let rollback = running.reload_handle().published_runtime();
    assert!(matches!(rollback.origin, RuntimeOrigin::Bundle { .. }));
    wait_peer(address, "peer-v4").await;
    assert_eq!(data(address, "/version").await.1, "A");
    deployment
        .conditional(&["reload-source".to_owned()], &rollback, "back-to-source")
        .await;
    let current_source = running.reload_handle().published_runtime();
    assert_eq!(current_source.origin, RuntimeOrigin::Source);
    assert_eq!(data(address, "/version").await.1, "source-latest");
    wait_peer(address, "peer-v4").await;
    let refreshed = fixture.dns.counts.udp.load(Ordering::Acquire);
    wait_queries(&fixture.dns.counts.udp, refreshed + 8).await;
    assert_publication_same(&current_source, &running);
    fixture.delay_source.store(true, Ordering::Release);
    wait_queries(&fixture.late_source, 1).await;
    deployment
        .conditional(&["drain".to_owned()], &current_source, "drain-source")
        .await;
    let drained = running.reload_handle().published_runtime();
    assert_eq!(drained.serving_state, ServingState::Drained);
    assert_eq!(
        drained.snapshot.resources.clusters[&ResourceId::new("cluster:api")]
            .discovery_status()
            .expect("drained Source owner")
            .resolution,
        oxidase_runtime::DiscoveryResolutionState::Retired
    );
    let sent_source = fixture
        .dns
        .counts
        .responses_for_type("source.qual.test.", RecordType::A);
    fixture.release_source_response.add_permits(1);
    assert!(
        running
            .reload_handle()
            .reload_watched_path(&deployment.config)
            .await
            .is_err()
    );
    wait_positive_response(&fixture, "source.qual.test.", sent_source + 1).await;
    assert_publication_same(&drained, &running);
    assert!(
        TcpStream::connect(address).await.is_err(),
        "DNS/source callbacks cannot reopen accept"
    );
    assert!(
        deployment
            .metrics()
            .await
            .contains("oxidase_discovery_active_supervisors 0\n")
    );

    // Only an authorized explicit operation can resume; use the old ephemeral
    // address after its drained socket was released, not a fixed external port.
    fixture.mode.store(2, Ordering::Release);
    fixture.delay_source.store(false, Ordering::Release);
    fs::write(
        &deployment.config,
        deployment.source(
            &fixture,
            "resumed",
            "source.qual.test",
            false,
            &address.to_string(),
        ),
    )
    .expect("explicit resume source");
    deployment
        .conditional(&["reload-source".to_owned()], &drained, "explicit-resume")
        .await;
    let resumed = running.reload_handle().published_runtime();
    assert_eq!(resumed.serving_state, ServingState::Running);
    assert_ne!(resumed.etag(), drained.etag());
    assert_eq!(
        resumed.snapshot.resources.clusters[&ResourceId::new("cluster:api")]
            .endpoints()
            .len(),
        0,
        "fresh owner cannot reuse retired answers"
    );
    assert_eq!(data(address, "/").await.0, StatusCode::SERVICE_UNAVAILABLE);
    fixture.mode.store(0, Ordering::Release);
    wait_peer(address, "peer-v4").await;
    running.shutdown().await.expect("complete shutdown");
    assert!(fixture.ipv4.requests.load(Ordering::Relaxed) > 0);
    assert!(fixture.ipv6.requests.load(Ordering::Relaxed) > 0);
    assert!(fixture.b.requests.load(Ordering::Relaxed) > 0);
}

struct CliHost {
    child: Child,
    lines: std::sync::mpsc::Receiver<String>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl CliHost {
    fn start(deployment: &Deployment, bundle: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oxidase"))
            .current_dir(&deployment.root)
            .args(["serve", "--bundle"])
            .arg(bundle)
            .arg("--bundle-key")
            .arg(deployment.root.join("operator.pub"))
            .arg("--deployment-root")
            .arg(&deployment.root)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("actual CLI serve child");
        let stdout = child.stdout.take().expect("child stdout");
        let (sent, lines) = std::sync::mpsc::sync_channel(4);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = sent.try_send(line);
            }
        });
        Self {
            child,
            lines,
            reader: Some(reader),
        }
    }

    async fn address(&mut self) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                assert!(
                    self.child.try_wait().expect("child status").is_none(),
                    "actual serve child exited before listener ready"
                );
                while let Ok(line) = self.lines.try_recv() {
                    if line.starts_with("listener public accepting ")
                        && let Some((_, address)) = line.rsplit_once(" on ")
                    {
                        return address.parse().expect("actual ephemeral child address");
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("child listener ready")
    }
}

impl Drop for CliHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[tokio::test]
async fn actual_signed_bundle_process_restart_starts_cold_and_uses_new_dns_not_old_packed_ips() {
    let fixture = DiscoveryFixture::start().await;
    let deployment = Deployment::new();
    let source = deployment.source(&fixture, "child", "source.qual.test", false, "127.0.0.1:0");
    let (bundle, digest) = deployment.signed_bundle("child", &source).await;
    fs::remove_file(deployment.root.join("child.yaml")).expect("delete only fixture-owned YAML");
    let mut first = CliHost::start(&deployment, &bundle);
    let first_address = first.address().await;
    wait_peer(first_address, "peer-v4").await;
    let before = deployment.ctl(&["status".to_owned()]).await;
    assert_eq!(before["origin"]["kind"], "bundle");
    assert_eq!(before["origin"]["digest"], digest);
    drop(first); // Real SIGKILL/process exit, not reconstruction in this process.
    fixture.mode.store(2, Ordering::Release);
    let mut second = CliHost::start(&deployment, &bundle);
    let address = second.address().await;
    let cold = deployment.ctl(&["clusters".to_owned()]).await;
    assert_eq!(cold["clusters"][0]["discovery"]["endpoint_count"], 0);
    assert_eq!(cold["clusters"][0]["discovery"]["generation"], 0);
    assert_eq!(data(address, "/").await.0, StatusCode::SERVICE_UNAVAILABLE);
    let restarted = deployment.ctl(&["status".to_owned()]).await;
    assert_ne!(before["etag"], restarted["etag"], "new process epoch");
    assert_eq!(restarted["origin"]["digest"], digest);
    fixture.mode.store(1, Ordering::Release);
    wait_peer(address, "peer-v6").await;
    let ready = deployment.ctl(&["clusters".to_owned()]).await;
    assert_eq!(ready["clusters"][0]["discovery"]["endpoint_count"], 1);
    assert!(
        ready["clusters"][0]["discovery"]["generation"]
            .as_u64()
            .expect("generation")
            > 0
    );
    drop(second);
}
