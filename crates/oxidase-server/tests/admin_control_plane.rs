//! Real control-plane and data-plane flows against signed test-only Bundles.
//!
//! Tests use ephemeral listeners, credentials, and signing material exclusively.

#![cfg(unix)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body::Body;
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use oxidase_bundle::{
    AssetReferenceBase, BuildMetadata, BundleArchive, BundleBuilder, BundleCapabilities,
    BundleLimits, BundleManifest, BundleSigningKey, BundleVerificationKey, SensitiveReference,
    SensitiveReferenceKind, StableSection,
};
use oxidase_config::Compiler;
use oxidase_runtime::{
    AuditAction, CandidateOperationContext, CandidateSignaturePolicy, CandidateStore,
    CandidateStoreLimits, PORTABLE_RUNTIME_PLAN_SCHEMA_V1, RuntimeOrigin, RuntimeSnapshot,
    ServingState,
};
use oxidase_server::{AdminEndpoint, GatewayServer, RunningServer};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::{TlsConnector, rustls};

const TOKEN: &[u8] = b"test-only-control-plane-token";

struct HttpReply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl HttpReply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("Admin response is valid JSON")
    }
    fn etag(&self) -> String {
        self.headers[header::ETAG]
            .to_str()
            .expect("runtime ETag is ASCII")
            .to_owned()
    }
    fn successful(&self) {
        assert!(
            self.status.is_success(),
            "Admin returned {}: {}",
            self.status,
            String::from_utf8_lossy(&self.body)
        );
    }
}

async fn request_io<I, B>(io: I, request: Request<B>) -> HttpReply
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    tokio::time::timeout(Duration::from_secs(10), async {
        let (mut sender, connection) = http1::handshake(TokioIo::new(io))
            .await
            .expect("HTTP handshake");
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(request)
            .await
            .expect("HTTP response arrives");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response
            .into_body()
            .collect()
            .await
            .expect("HTTP response body completes")
            .to_bytes();
        drop(sender);
        driver.abort();
        let _ = driver.await;
        HttpReply {
            status,
            headers,
            body,
        }
    })
    .await
    .expect("local fixture request deadline")
}

async fn raw_admin_reply(socket: &Path, request: &[u8]) -> HttpReply {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = UnixStream::connect(socket).await.expect("raw Admin socket");
        stream.write_all(request).await.expect("raw request sent");
        let mut bytes = Vec::new();
        let (head_end, body_length, status) = loop {
            let mut buffer = [0; 4096];
            let amount = stream.read(&mut buffer).await.expect("raw response bytes");
            assert!(amount > 0, "Admin response does not end before headers");
            bytes.extend_from_slice(&buffer[..amount]);
            assert!(
                bytes.len() < 64 * 1024,
                "safe Admin error response is bounded"
            );
            if let Some(head_end) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let head = std::str::from_utf8(&bytes[..head_end]).expect("ASCII response head");
                let status = head
                    .lines()
                    .next()
                    .expect("status line")
                    .split_whitespace()
                    .nth(1)
                    .expect("status number")
                    .parse::<u16>()
                    .expect("status parses");
                let body_length = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':')
                            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .map(|(_, value)| {
                                value.trim().parse::<usize>().expect("content length")
                            })
                    })
                    .expect("Admin static error body carries length");
                break (
                    head_end + 4,
                    body_length,
                    StatusCode::from_u16(status).expect("HTTP status"),
                );
            }
        };
        assert!(body_length < 64 * 1024, "safe Admin error body is bounded");
        while bytes.len() < head_end + body_length {
            let mut buffer = [0; 4096];
            let amount = stream.read(&mut buffer).await.expect("raw error body");
            assert!(amount > 0, "body completes");
            bytes.extend_from_slice(&buffer[..amount]);
        }
        HttpReply {
            status,
            headers: HeaderMap::new(),
            body: Bytes::copy_from_slice(&bytes[head_end..head_end + body_length]),
        }
    })
    .await
    .expect("raw Admin response deadline")
}

async fn unix_request(
    socket: &Path,
    method: Method,
    path: &str,
    token: Option<&[u8]>,
    headers: &[(&str, String)],
    body: Bytes,
) -> HttpReply {
    let stream = UnixStream::connect(socket)
        .await
        .expect("Admin Unix socket connects");
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "localhost");
    if let Some(token) = token {
        let token = oxidase_runtime::AdminBearerToken::parse_file_bytes(token)
            .expect("test credential is valid");
        builder = builder.header(header::AUTHORIZATION, token.authorization_header());
    }
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    request_io(
        stream,
        builder.body(Full::new(body)).expect("test request builds"),
    )
    .await
}

async fn data_reply(address: SocketAddr) -> HttpReply {
    let stream = TcpStream::connect(address)
        .await
        .expect("data listener connects");
    request_io(
        stream,
        Request::builder()
            .uri("/")
            .header(header::HOST, "test.example")
            .body(Full::new(Bytes::new()))
            .expect("data request"),
    )
    .await
}

fn prepare(config: &Path) -> RuntimeSnapshot {
    RuntimeSnapshot::prepare(Compiler::compile_path(config).expect("fixture source compiles"))
        .expect("fixture snapshot prepares")
}

fn data_source(body: &str) -> String {
    format!(
        "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  root:\n    type: respond\n    body:\n      text: {body}\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    protocol: http\n    service:\n      ref: root\n"
    )
}

fn admin_source(
    directory: &Path,
    body: &str,
    permissions: &str,
    bundle_permissions: bool,
) -> String {
    let trust = if bundle_permissions {
        "  bundle_trust:\n    verification_keys: [operator.pub]\n"
    } else {
        ""
    };
    format!(
        "{}resources:\n  secrets:\n    control-token:\n      file: token\nadmin:\n  listen:\n    unix:\n      path: {}\n      mode: \"0600\"\n  auth:\n    mode: bearer\n    token_secret: control-token\n  storage:\n    directory: {}\n{}  permissions:\n{}  audit:\n    destination: file\n    file: {}\n",
        data_source(body),
        directory.join("admin.sock").display(),
        directory.join("store").display(),
        trust,
        permissions,
        directory.join("audit.jsonl").display()
    )
}

struct Fixture {
    directory: TempDir,
    root: PathBuf,
    config: PathBuf,
    socket: PathBuf,
    address: SocketAddr,
    signing: BundleSigningKey,
    running: RunningServer,
}

const ALL_PERMISSIONS: &str = "    read: true\n    stage: true\n    activate: true\n    rollback: true\n    drain: true\n    reload_source: true\n";

impl Fixture {
    async fn start(permissions: &str, bundle_permissions: bool, token_file: &[u8]) -> Self {
        let directory = tempdir().expect("temporary deployment root");
        let root = directory
            .path()
            .canonicalize()
            .expect("canonical deployment root");
        let signing_path = root.join("offline-test-only-key");
        fs::write(&signing_path, [11; 32]).expect("test-only signing seed");
        let signing = BundleSigningKey::read_file(&signing_path).expect("test-only signing key");
        fs::write(
            root.join("operator.pub"),
            signing.verification_key().as_bytes(),
        )
        .expect("test-only verification key");
        fs::write(root.join("token"), token_file).expect("test-only token");
        let config = root.join("oxidase.yaml");
        fs::write(
            &config,
            admin_source(&root, "initial", permissions, bundle_permissions),
        )
        .expect("source written");
        let server = GatewayServer::bind_with_origin(prepare(&config), RuntimeOrigin::Source)
            .await
            .expect("gateway and Admin bind");
        let address = server.local_addresses()[0].1;
        let socket = match server.admin_endpoint().expect("Admin endpoint") {
            AdminEndpoint::Unix(path) => path.clone(),
            _ => panic!("fixture uses Unix Admin"),
        };
        let running = server.spawn();
        Self {
            directory,
            root,
            config,
            socket,
            address,
            signing,
            running,
        }
    }

    async fn read(&self, path: &str) -> HttpReply {
        unix_request(
            &self.socket,
            Method::GET,
            path,
            Some(TOKEN),
            &[],
            Bytes::new(),
        )
        .await
    }

    async fn current(&self) -> HttpReply {
        let reply = self.read("/api/v1/snapshots/current").await;
        reply.successful();
        reply
    }

    async fn mutate(
        &self,
        path: &str,
        etag: &str,
        key: &str,
        media: &str,
        body: Bytes,
    ) -> HttpReply {
        unix_request(
            &self.socket,
            Method::POST,
            path,
            Some(TOKEN),
            &[
                ("content-type", media.to_owned()),
                ("if-match", etag.to_owned()),
                ("idempotency-key", key.to_owned()),
            ],
            body,
        )
        .await
    }

    fn signed_bundle(&self, label: &str) -> (String, Bytes) {
        self.signed_bundle_source(label, &data_source(label))
    }

    fn signed_bundle_source(&self, label: &str, source_text: &str) -> (String, Bytes) {
        let source = self.root.join(format!("candidate-{label}.yaml"));
        fs::write(&source, source_text).expect("candidate source");
        let compiled = Compiler::compile_path(&source).expect("candidate compiles");
        let snapshot = RuntimeSnapshot::prepare(compiled.clone()).expect("candidate prepares");
        let exported = snapshot
            .export_portable_at(&compiled, &self.root)
            .expect("portable candidate");
        assert!(exported.assets.is_empty());
        let mut manifest = BundleManifest::new(
            BuildMetadata {
                tool_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_commit: None,
                gateway_api: oxidase_config::API_VERSION.to_owned(),
                oxista_api: "v1".to_owned(),
            },
            env!("CARGO_PKG_VERSION"),
        );
        manifest
            .required_features
            .insert("portable-runtime".to_owned());
        manifest.sections.insert(
            "runtime".to_owned(),
            StableSection::from_serde(PORTABLE_RUNTIME_PLAN_SCHEMA_V1, true, &exported.plan)
                .expect("runtime stable section"),
        );
        for (id, secret) in &exported.plan.gateway.secrets {
            manifest.sensitive_references.insert(
                format!("secret:{id}"),
                SensitiveReference {
                    kind: SensitiveReferenceKind::Secret,
                    base: match secret.file.base.as_str() {
                        "absolute" => AssetReferenceBase::Absolute,
                        "deployment_root" => AssetReferenceBase::DeploymentRoot,
                        _ => panic!("exported path base"),
                    },
                    runtime_path: secret.file.path.clone(),
                    max_bytes: secret.max_bytes,
                },
            );
        }
        for (id, certificate) in &exported.plan.gateway.certificates {
            manifest.sensitive_references.insert(
                format!("private-key:{id}"),
                SensitiveReference {
                    kind: SensitiveReferenceKind::PrivateKey,
                    base: match certificate.private_key.base.as_str() {
                        "absolute" => AssetReferenceBase::Absolute,
                        "deployment_root" => AssetReferenceBase::DeploymentRoot,
                        _ => panic!("exported path base"),
                    },
                    runtime_path: certificate.private_key.path.clone(),
                    max_bytes: oxidase_runtime::MAX_PRIVATE_KEY_BYTES,
                },
            );
        }
        let bytes = BundleBuilder::new(manifest).build().expect("Bundle builds");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default())
            .expect("Bundle parses")
            .sign(&self.signing)
            .expect("test-only signing");
        (
            archive.content_digest().to_string(),
            Bytes::from(archive.encode().expect("signed Bundle encoded")),
        )
    }

    async fn stage_validate(&self, label: &str) -> String {
        let (digest, bytes) = self.signed_bundle(label);
        let etag = self.current().await.etag();
        self.mutate(
            "/api/v1/candidates",
            &etag,
            &format!("stage-{label}"),
            "application/vnd.oxidase.bundle",
            bytes,
        )
        .await
        .successful();
        self.mutate(
            &format!("/api/v1/candidates/{digest}/validate"),
            &etag,
            &format!("validate-{label}"),
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
        digest
    }

    async fn activate(&self, digest: &str, key: &str) -> HttpReply {
        let etag = self.current().await.etag();
        self.mutate(
            &format!("/api/v1/candidates/{digest}/activate"),
            &etag,
            key,
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
    }
}

#[tokio::test]
async fn signed_activation_history_rollback_and_data_only_bundle_preserve_admin_identity() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    fixture.activate(&a, "activate-A").await.successful();
    assert_eq!(data_reply(fixture.address).await.body, "A");
    let current_a = fixture.current().await;
    assert_eq!(current_a.json()["bundle_digest"], a);
    let b = fixture.stage_validate("B").await;
    fixture.activate(&b, "activate-B").await.successful();
    assert_eq!(data_reply(fixture.address).await.body, "B");
    let history = fixture.read("/api/v1/snapshots").await;
    history.successful();
    let history_text = history.json().to_string();
    assert!(
        history_text.contains(&a) && history_text.contains(&b),
        "retained history exposes both successful artifacts: {history_text}"
    );
    assert!(
        history_text.contains("committed_revision"),
        "history must distinguish publication revision from artifact digest"
    );
    let current_b = fixture.current().await;
    fixture
        .mutate(
            &format!("/api/v1/snapshots/{a}/rollback"),
            &current_b.etag(),
            "rollback-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(data_reply(fixture.address).await.body, "A");
    assert_eq!(fixture.current().await.json()["bundle_digest"], a);
    // Neither Bundle contains the Admin policy or token Secret; bootstrap remains authoritative.
    assert_eq!(fixture.read("/api/v1/runtime").await.status, StatusCode::OK);
    fixture.running.shutdown().await.expect("fixture shutdown");
    let audit =
        fs::read_to_string(fixture.root.join("audit.jsonl")).expect("real audit sink exists");
    assert!(!audit.contains(std::str::from_utf8(TOKEN).expect("ASCII test token")));
    for action in ["stage", "validate", "activate", "rollback"] {
        assert!(audit.contains(action), "audit records {action}");
    }
}

#[tokio::test]
async fn source_reload_between_bundle_activations_does_not_create_false_already_current() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    fixture.activate(&a, "first-A").await.successful();
    fs::write(
        &fixture.config,
        admin_source(&fixture.root, "source-B", ALL_PERMISSIONS, true),
    )
    .expect("source B written");
    let etag = fixture.current().await.etag();
    fixture
        .mutate(
            "/api/v1/reload-source",
            &etag,
            "source-B",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(data_reply(fixture.address).await.body, "source-B");
    assert_eq!(fixture.current().await.json()["origin"]["kind"], "source");
    fixture.activate(&a, "second-A").await.successful();
    assert_eq!(data_reply(fixture.address).await.body, "A");
    assert_eq!(fixture.current().await.json()["bundle_digest"], a);
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn retained_history_does_not_claim_to_be_the_runtime_after_source_restart() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    fixture.activate(&a, "first-A").await.successful();
    let previous_epoch = fixture.current().await.etag();
    fixture
        .running
        .shutdown()
        .await
        .expect("first process lifecycle ends");
    let server = GatewayServer::bind_with_origin(prepare(&fixture.config), RuntimeOrigin::Source)
        .await
        .expect("same store opens for next server lifecycle");
    let address = server.local_addresses()[0].1;
    let next = server.spawn();
    let current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    current.successful();
    assert_ne!(current.etag(), previous_epoch);
    assert_eq!(current.json()["origin"]["kind"], "source");
    assert!(current.json()["bundle_digest"].is_null());
    assert_eq!(data_reply(address).await.body, "initial");
    next.shutdown().await.expect("next lifecycle shutdown");
    drop(fixture.directory);
}

#[tokio::test]
async fn drain_only_has_independent_permission_and_readiness_cannot_be_reopened_by_watcher() {
    let permissions = "    read: true\n    drain: true\n";
    let fixture = Fixture::start(permissions, false, TOKEN).await;
    let etag = fixture.current().await.etag();
    fixture
        .mutate(
            "/api/v1/drain",
            &etag,
            "drain-only",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(fixture.read("/health/live").await.status, StatusCode::OK);
    assert_eq!(
        fixture.read("/health/ready").await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.read("/api/v1/runtime").await.status, StatusCode::OK);
    assert_eq!(
        fixture
            .running
            .reload_handle()
            .published_runtime()
            .serving_state,
        ServingState::Drained
    );
    assert!(
        TcpStream::connect(fixture.address).await.is_err(),
        "drain stops new data-plane accepts"
    );
    fs::write(
        &fixture.config,
        admin_source(&fixture.root, "watcher-new", permissions, false),
    )
    .expect("new source written");
    assert!(
        fixture
            .running
            .reload_handle()
            .reload_watched_path(&fixture.config)
            .await
            .is_err(),
        "watcher cannot revoke drain"
    );
    assert_eq!(
        fixture.read("/health/ready").await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn reload_source_only_works_without_bundle_verification_keys() {
    let permissions = "    read: true\n    reload_source: true\n";
    let fixture = Fixture::start(permissions, false, TOKEN).await;
    fs::write(
        &fixture.config,
        admin_source(&fixture.root, "source-only", permissions, false),
    )
    .expect("source replacement");
    let etag = fixture.current().await.etag();
    fixture
        .mutate(
            "/api/v1/reload-source",
            &etag,
            "source-only",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(data_reply(fixture.address).await.body, "source-only");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn readless_drain_uses_explicit_revision_without_bundle_capability() {
    let fixture = Fixture::start("    read: false\n    drain: true\n", false, TOKEN).await;
    assert_eq!(
        fixture.read("/api/v1/runtime").await.status,
        StatusCode::FORBIDDEN
    );
    let etag = fixture.running.reload_handle().published_runtime().etag();
    fixture
        .mutate(
            "/api/v1/drain",
            &etag,
            "readless-drain",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(
        fixture
            .running
            .reload_handle()
            .published_runtime()
            .serving_state,
        ServingState::Drained
    );
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn bearer_token_file_optional_lf_and_crlf_work_on_the_real_server() {
    for ending in [b"".as_slice(), b"\n", b"\r\n"] {
        let mut token = TOKEN.to_vec();
        token.extend_from_slice(ending);
        let fixture = Fixture::start("    read: true\n", false, &token).await;
        assert_eq!(fixture.read("/api/v1/runtime").await.status, StatusCode::OK);
        let unauthorized = unix_request(
            &fixture.socket,
            Method::GET,
            "/api/v1/runtime",
            Some(b"wrong-test-token"),
            &[],
            Bytes::new(),
        )
        .await;
        assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
        let duplicated = unix_request(
            &fixture.socket,
            Method::GET,
            "/api/v1/runtime",
            Some(TOKEN),
            &[(
                "authorization",
                "Bearer test-only-control-plane-token".to_owned(),
            )],
            Bytes::new(),
        )
        .await;
        assert_eq!(duplicated.status, StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(&unauthorized.body).contains("wrong-test-token"));
        fixture.running.shutdown().await.expect("fixture shutdown");
    }
}

#[tokio::test]
async fn stale_source_reload_and_drain_never_apply_side_effects() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let stale = fixture.current().await.etag();
    let a = fixture.stage_validate("A").await;
    fixture.activate(&a, "activate-A").await.successful();
    for path in ["/api/v1/drain", "/api/v1/reload-source"] {
        let reply = fixture
            .mutate(
                path,
                &stale,
                &format!("stale-{path}"),
                "application/json",
                Bytes::from_static(b"{}"),
            )
            .await;
        assert_eq!(reply.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(reply.json()["schema_version"], "oxidase.admin/v1");
        assert_eq!(data_reply(fixture.address).await.body, "A");
        assert_eq!(fixture.read("/health/ready").await.status, StatusCode::OK);
    }
    fixture.running.shutdown().await.expect("fixture shutdown");
}

struct HttpsFixture {
    _directory: TempDir,
    address: SocketAddr,
    running: RunningServer,
    root: CertificateDer<'static>,
    client: CertificateDer<'static>,
    client_key: Vec<u8>,
}

impl HttpsFixture {
    async fn start(auth: &str) -> Self {
        let directory = tempdir().expect("temporary TLS deployment");
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical TLS deployment");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("test-only CA key");
        let ca = ca_params.self_signed(&ca_key).expect("test-only CA");
        let issuer = Issuer::new(ca_params, ca_key);
        let mut server_params =
            CertificateParams::new(vec!["127.0.0.1".to_owned()]).expect("server params");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("test-only server key");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");
        let mut client_params = CertificateParams::new(vec!["operator.example.test".to_owned()])
            .expect("client params");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("test-only client key");
        let client = client_params
            .signed_by(&client_key, &issuer)
            .expect("client cert");
        fs::write(
            path.join("server.pem"),
            format!("{}{}", server_cert.pem(), ca.pem()),
        )
        .expect("test chain");
        fs::write(path.join("server.key"), server_key.serialize_pem())
            .expect("test-only private key");
        fs::write(path.join("ca.pem"), ca.pem()).expect("test CA");
        fs::write(path.join("token"), TOKEN).expect("test-only bearer");
        let require_mtls = matches!(auth, "mtls" | "bearer_and_mtls");
        let client_auth = if require_mtls {
            "      client_auth:\n        mode: required\n        trust_store: operators\n"
        } else {
            ""
        };
        let token_secret = if matches!(auth, "bearer" | "bearer_and_mtls") {
            "    token_secret: control-token\n"
        } else {
            ""
        };
        let source = format!(
            "{}resources:\n  secrets:\n    control-token:\n      file: token\n  certificates:\n    admin-cert:\n      cert_chain: server.pem\n      private_key: server.key\n  trust_stores:\n    operators:\n      ca_bundle: ca.pem\nadmin:\n  listen:\n    https:\n      bind: 127.0.0.1:0\n      certificate: admin-cert\n{}  auth:\n    mode: {auth}\n{}  permissions:\n    read: true\n  storage:\n    directory: {}\n  audit:\n    destination: file\n    file: {}\n",
            data_source("tls-data"),
            client_auth,
            token_secret,
            path.join("store").display(),
            path.join("audit.jsonl").display()
        );
        let config = path.join("oxidase.yaml");
        fs::write(&config, source).expect("TLS admin source");
        let server = GatewayServer::bind(prepare(&config))
            .await
            .expect("TLS admin binds");
        let address = match server.admin_endpoint().expect("TLS Admin endpoint") {
            AdminEndpoint::Tcp(address) => *address,
            _ => panic!("TLS fixture is TCP"),
        };
        Self {
            _directory: directory,
            address,
            running: server.spawn(),
            root: ca.der().clone(),
            client: client.der().clone(),
            client_key: client_key.serialize_der(),
        }
    }

    fn client_config(&self, client: bool, trusted_client: bool) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).expect("test server root");
        let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("safe TLS defaults")
            .with_root_certificates(roots);
        let mut config = if client {
            if trusted_client {
                builder
                    .with_client_auth_cert(
                        vec![self.client.clone(), self.root.clone()],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.client_key.clone())),
                    )
                    .expect("trusted client identity")
            } else {
                let untrusted =
                    rcgen::generate_simple_self_signed(vec!["untrusted.example.test".to_owned()])
                        .expect("test-only untrusted client");
                builder
                    .with_client_auth_cert(
                        vec![untrusted.cert.der().clone()],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                            untrusted.signing_key.serialize_der(),
                        )),
                    )
                    .expect("untrusted test identity")
            }
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    async fn request(
        &self,
        client: bool,
        trusted_client: bool,
        token: Option<&[u8]>,
    ) -> Result<HttpReply, String> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let tcp = TcpStream::connect(self.address)
                .await
                .map_err(|error| error.to_string())?;
            let tls = TlsConnector::from(self.client_config(client, trusted_client))
                .connect(ServerName::IpAddress(self.address.ip().into()), tcp)
                .await
                .map_err(|error| error.to_string())?;
            let (mut sender, connection) = http1::handshake(TokioIo::new(tls))
                .await
                .map_err(|error| error.to_string())?;
            let driver = tokio::spawn(connection);
            let mut builder = Request::builder()
                .uri("/api/v1/runtime")
                .header(header::HOST, self.address.to_string());
            if let Some(token) = token {
                builder = builder.header(
                    header::AUTHORIZATION,
                    oxidase_runtime::AdminBearerToken::parse_file_bytes(token)
                        .expect("test token")
                        .authorization_header(),
                );
            }
            let response = sender
                .send_request(builder.body(Full::new(Bytes::new())).expect("TLS request"))
                .await;
            let result = match response {
                Ok(response) => {
                    let status = response.status();
                    let headers = response.headers().clone();
                    response
                        .into_body()
                        .collect()
                        .await
                        .map(|body| HttpReply {
                            status,
                            headers,
                            body: body.to_bytes(),
                        })
                        .map_err(|error| error.to_string())
                }
                Err(error) => Err(error.to_string()),
            };
            drop(sender);
            driver.abort();
            let _ = driver.await;
            result
        })
        .await
        .map_err(|_| "TLS fixture request deadline".to_owned())?
    }
}

#[tokio::test]
async fn https_bearer_authenticates_the_real_admin_endpoint() {
    let fixture = HttpsFixture::start("bearer").await;
    assert_eq!(
        fixture
            .request(false, true, Some(TOKEN))
            .await
            .expect("HTTPS bearer request")
            .status,
        StatusCode::OK
    );
    assert_eq!(
        fixture
            .request(false, true, None)
            .await
            .expect("missing bearer HTTP response")
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .request(false, true, Some(b"wrong-test-token"))
            .await
            .expect("bad bearer HTTP response")
            .status,
        StatusCode::UNAUTHORIZED
    );
    fixture
        .running
        .shutdown()
        .await
        .expect("TLS fixture shutdown");
}

#[tokio::test]
async fn https_required_mtls_and_combined_auth_enforce_independent_credentials() {
    for auth in ["mtls", "bearer_and_mtls"] {
        let fixture = HttpsFixture::start(auth).await;
        let token = (auth == "bearer_and_mtls").then_some(TOKEN);
        assert_eq!(
            fixture
                .request(true, true, token)
                .await
                .expect("verified mTLS request")
                .status,
            StatusCode::OK
        );
        assert!(
            fixture.request(false, true, token).await.is_err(),
            "required mTLS rejects absent certificate"
        );
        assert!(
            fixture.request(true, false, token).await.is_err(),
            "required mTLS rejects wrong CA"
        );
        if auth == "bearer_and_mtls" {
            assert_eq!(
                fixture
                    .request(true, true, None)
                    .await
                    .expect("verified TLS still requires bearer")
                    .status,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                fixture
                    .request(true, true, Some(b"wrong-test-token"))
                    .await
                    .expect("verified TLS rejects incorrect bearer")
                    .status,
                StatusCode::UNAUTHORIZED
            );
        }
        fixture
            .running
            .shutdown()
            .await
            .expect("TLS fixture shutdown");
    }
}

/// Dedicated test-binary entry point for real process kill/restart tests.
#[test]
fn admin_child_host() {
    let Some(config) = std::env::var_os("OXIDASE_TEST_ADMIN_CHILD_CONFIG") else {
        return;
    };
    let ready = PathBuf::from(
        std::env::var_os("OXIDASE_TEST_ADMIN_CHILD_READY").expect("parent supplies ready path"),
    );
    tokio::runtime::Runtime::new().expect("child runtime").block_on(async {
        let server = GatewayServer::bind_with_origin(prepare(Path::new(&config)), RuntimeOrigin::Source).await.expect("child server binds");
        let address = server.local_addresses()[0].1;
        let running = server.spawn();
        fs::write(ready, serde_json::to_vec(&serde_json::json!({ "data_address": address.to_string(), "etag": running.reload_handle().published_runtime().etag() })).expect("ready document")).expect("child readiness file");
        std::future::pending::<()>().await;
    });
}

/// Crash at the durable-intent boundary while the writer still owns the store.
#[test]
fn admin_child_intent_writer() {
    let Some(config) = std::env::var_os("OXIDASE_TEST_ADMIN_CHILD_CONFIG") else {
        return;
    };
    let root = Path::new(&config)
        .parent()
        .expect("fixture deployment root");
    let ready = PathBuf::from(
        std::env::var_os("OXIDASE_TEST_ADMIN_CHILD_READY").expect("parent supplies ready path"),
    );
    let snapshot = prepare(Path::new(&config));
    let store = CandidateStore::open(
        root.join("store"),
        CandidateStoreLimits::default(),
        CandidateSignaturePolicy::require_trusted(vec![
            BundleVerificationKey::read_file(root.join("operator.pub"))
                .expect("fixture verification key"),
        ]),
        BundleCapabilities {
            supported_features: ["portable-runtime".to_owned()].into_iter().collect(),
            supported_sections: [(
                "runtime".to_owned(),
                PORTABLE_RUNTIME_PLAN_SCHEMA_V1.to_owned(),
            )]
            .into_iter()
            .collect(),
            ..BundleCapabilities::default()
        },
    )
    .expect("child exclusively opens durable store");
    let operation = store
        .begin_operation(
            &CandidateOperationContext::internal("interrupted-source-reload"),
            AuditAction::ReloadSource,
            None,
            None,
        )
        .expect("child accepts durable operation");
    let receipt = store
        .begin_intent(
            &operation.receipt.operation_id,
            store.max_recorded_revision(),
            snapshot.config_version.as_str(),
        )
        .expect("child fsyncs publication intent");
    fs::write(
        ready,
        serde_json::to_vec(&serde_json::json!({ "operation_id": receipt.operation_id }))
            .expect("intent readiness document"),
    )
    .expect("intent readiness marker");
    loop {
        std::thread::park();
    }
}

struct ChildHost(Child);

impl Drop for ChildHost {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn spawn_child_entry(config: &Path, ready: &Path, entry: &str) -> (ChildHost, Value) {
    if ready.exists() {
        fs::remove_file(ready).expect("remove previous fixture readiness marker");
    }
    let child = Command::new(std::env::current_exe().expect("integration test executable"))
        .arg("--exact")
        .arg(entry)
        .arg("--nocapture")
        .env("OXIDASE_TEST_ADMIN_CHILD_CONFIG", config)
        .env("OXIDASE_TEST_ADMIN_CHILD_READY", ready)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("child process starts");
    let mut child = ChildHost(child);
    let document = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            assert!(
                child.0.try_wait().expect("child status").is_none(),
                "child exited before ready"
            );
            if let Ok(bytes) = tokio::fs::read(ready).await
                && let Ok(ready) = serde_json::from_slice::<Value>(&bytes)
            {
                return ready;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child becomes ready");
    (child, document)
}

async fn spawn_child_host(config: &Path, ready: &Path) -> (ChildHost, SocketAddr) {
    let (child, document) = spawn_child_entry(config, ready, "admin_child_host").await;
    let address = document["data_address"]
        .as_str()
        .expect("child publishes data address")
        .parse::<SocketAddr>()
        .expect("ready socket address");
    (child, address)
}

#[tokio::test]
async fn killed_server_restart_never_confuses_artifact_history_with_live_source() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let (a, bytes) = fixture.signed_bundle("A");
    fixture
        .running
        .shutdown()
        .await
        .expect("initial setup lifecycle ends");
    let ready = fixture.root.join("child-ready.json");
    let (first, address) = spawn_child_host(&fixture.config, &ready).await;
    let current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    current.successful();
    let first_epoch = current.etag();
    let headers = [
        ("content-type", "application/vnd.oxidase.bundle".to_owned()),
        ("if-match", first_epoch.clone()),
        ("idempotency-key", "child-stage-A".to_owned()),
    ];
    unix_request(
        &fixture.socket,
        Method::POST,
        "/api/v1/candidates",
        Some(TOKEN),
        &headers,
        bytes,
    )
    .await
    .successful();
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("if-match", first_epoch.clone()),
    ];
    for action in ["validate", "activate"] {
        unix_request(
            &fixture.socket,
            Method::POST,
            &format!("/api/v1/candidates/{a}/{action}"),
            Some(TOKEN),
            &headers,
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    }
    assert_eq!(data_reply(address).await.body, "A");
    drop(first); // Kill rather than graceful Drop: durable state must survive a real process exit.
    fs::write(
        &fixture.config,
        admin_source(&fixture.root, "restart-source-B", ALL_PERMISSIONS, true),
    )
    .expect("source startup choice B");
    let (second, address) = spawn_child_host(&fixture.config, &ready).await;
    let current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    current.successful();
    assert_ne!(current.etag(), first_epoch);
    assert_eq!(current.json()["origin"]["kind"], "source");
    assert!(current.json()["bundle_digest"].is_null());
    assert_eq!(data_reply(address).await.body, "restart-source-B");
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("if-match", current.etag()),
        ("idempotency-key", "child-reactivate-A".to_owned()),
    ];
    unix_request(
        &fixture.socket,
        Method::POST,
        &format!("/api/v1/candidates/{a}/activate"),
        Some(TOKEN),
        &headers,
        Bytes::from_static(b"{}"),
    )
    .await
    .successful();
    assert_eq!(data_reply(address).await.body, "A");
    drop(second);

    let (writer, intent) =
        spawn_child_entry(&fixture.config, &ready, "admin_child_intent_writer").await;
    let operation_id = intent["operation_id"]
        .as_str()
        .expect("durable intent operation ID");
    let old_store = fixture.root.join("store");
    let journal_path = old_store.join("state.json");
    let artifact_path = old_store.join("candidates").join(format!("{a}.oxb"));
    let pending_journal = fs::read(&journal_path).expect("durable intent journal");
    let pending: Value = serde_json::from_slice(&pending_journal).expect("journal document");
    let pending_receipt = &pending["operations"][operation_id]["receipt"];
    assert_eq!(pending_receipt["phase"], "preparing");
    assert_eq!(pending_receipt["commit_intent"], true);
    assert!(pending_receipt["committed_revision"].is_null());
    drop(writer); // Kill while the durable intent and exclusive process lock are live.
    assert_eq!(
        fs::read(&journal_path).expect("crash evidence retained"),
        pending_journal
    );

    let (uncertain, address) = spawn_child_host(&fixture.config, &ready).await;
    let current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    current.successful();
    assert_eq!(current.json()["origin"]["kind"], "source");
    assert!(current.json()["bundle_digest"].is_null());
    assert_eq!(data_reply(address).await.body, "restart-source-B");
    let receipt = unix_request(
        &fixture.socket,
        Method::GET,
        &format!("/api/v1/operations/{operation_id}"),
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    receipt.successful();
    assert_eq!(receipt.json()["operation"]["phase"], "recovery_required");
    assert_eq!(
        receipt.json()["operation"]["error_code"],
        "candidate.publication_unknown"
    );
    assert!(receipt.json()["operation"]["committed_revision"].is_null());
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("if-match", current.etag()),
        ("idempotency-key", "unreconciled-source-reload".to_owned()),
    ];
    let rejected = unix_request(
        &fixture.socket,
        Method::POST,
        "/api/v1/reload-source",
        Some(TOKEN),
        &headers,
        Bytes::from_static(b"{}"),
    )
    .await;
    assert!(!rejected.status.is_success());
    assert_eq!(rejected.json()["code"], "candidate.recovery_required");
    assert_eq!(data_reply(address).await.body, "restart-source-B");
    drop(uncertain); // Stop before choosing a replacement root; never edit a live journal.

    let preserved_journal = fs::read(&journal_path).expect("preserved recovery journal");
    let preserved_artifact = fs::read(&artifact_path).expect("preserved signed artifact");
    let audit_path = fixture.root.join("audit.jsonl");
    let preserved_audit = fs::read(&audit_path).expect("preserved predecessor audit");
    let fresh_store = fixture.root.join("operator-recovery-store");
    let recovered_source = admin_source(&fixture.root, "restart-source-B", ALL_PERMISSIONS, true)
        .replace(
            old_store.to_str().expect("UTF-8 old store"),
            fresh_store.to_str().expect("UTF-8 fresh store"),
        )
        .replace(
            audit_path.to_str().expect("UTF-8 predecessor audit"),
            fixture
                .root
                .join("operator-recovery-audit.jsonl")
                .to_str()
                .expect("UTF-8 recovery audit"),
        );
    fs::write(&fixture.config, recovered_source)
        .expect("operator explicitly selects Source B and new storage");
    let (recovered, address) = spawn_child_host(&fixture.config, &ready).await;
    let recovered_current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    recovered_current.successful();
    assert_ne!(recovered_current.etag(), current.etag());
    assert_eq!(recovered_current.json()["origin"]["kind"], "source");
    assert_eq!(data_reply(address).await.body, "restart-source-B");
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("if-match", recovered_current.etag()),
        ("idempotency-key", "operator-recovered-reload".to_owned()),
    ];
    let mutation = unix_request(
        &fixture.socket,
        Method::POST,
        "/api/v1/reload-source",
        Some(TOKEN),
        &headers,
        Bytes::from_static(b"{}"),
    )
    .await;
    mutation.successful();
    assert_eq!(mutation.json()["operation"]["phase"], "committed");
    assert_eq!(data_reply(address).await.body, "restart-source-B");
    let history = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    history.successful();
    assert_eq!(history.json()["history"], serde_json::json!([]));
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        fs::metadata(&fresh_store)
            .expect("private fresh root")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::read(&journal_path).expect("old journal retained"),
        preserved_journal
    );
    assert_eq!(
        fs::read(&artifact_path).expect("old artifact retained"),
        preserved_artifact
    );
    assert_eq!(
        fs::read(&audit_path).expect("old audit retained"),
        preserved_audit
    );
    drop(recovered);
}

#[tokio::test]
async fn idempotent_committed_receipt_replays_with_old_etag_without_claiming_current_version() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    let b = fixture.stage_validate("B").await;
    let original = fixture.current().await.etag();
    let first = fixture
        .mutate(
            &format!("/api/v1/candidates/{a}/activate"),
            &original,
            "lost-response-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await;
    first.successful();
    let first = first.json();
    let operation_id = first["operation_id"]
        .as_str()
        .expect("mutation supplies operation ID")
        .to_owned();
    let committed_revision = first["operation"]["committed_revision"]
        .as_u64()
        .expect("committed receipt revision");
    fixture.activate(&b, "activate-B").await.successful();
    let current_revision = fixture.current().await.json()["runtime_revision"]
        .as_u64()
        .expect("current revision");
    assert!(current_revision > committed_revision);
    let replay = fixture
        .mutate(
            &format!("/api/v1/candidates/{a}/activate"),
            &original,
            "lost-response-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await;
    replay.successful();
    let replay = replay.json();
    assert_eq!(replay["operation_id"], operation_id);
    assert_eq!(
        replay["operation"]["committed_revision"],
        committed_revision
    );
    assert_eq!(replay["current_revision"], current_revision);
    assert_eq!(data_reply(fixture.address).await.body, "B");
    let queried = fixture
        .read(&format!("/api/v1/operations/{operation_id}"))
        .await;
    queried.successful();
    assert_eq!(
        queried.json()["operation"]["committed_revision"],
        committed_revision
    );
    assert_eq!(queried.json()["current_revision"], current_revision);
    let conflict = fixture
        .mutate(
            &format!("/api/v1/candidates/{b}/activate"),
            &original,
            "lost-response-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await;
    assert_eq!(
        conflict.status,
        StatusCode::CONFLICT,
        "same key with a different target is not an idempotent replay"
    );
    assert_eq!(data_reply(fixture.address).await.body, "B");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn concurrent_activations_cannot_publish_two_versions_from_one_revision() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    let b = fixture.stage_validate("B").await;
    let current = fixture.current().await;
    let etag = current.etag();
    let before_revision = current.json()["runtime_revision"]
        .as_u64()
        .expect("initial revision");
    let path_a = format!("/api/v1/candidates/{a}/activate");
    let path_b = format!("/api/v1/candidates/{b}/activate");
    let (a, b) = tokio::join!(
        fixture.mutate(
            &path_a,
            &etag,
            "concurrent-A",
            "application/json",
            Bytes::from_static(b"{}")
        ),
        fixture.mutate(
            &path_b,
            &etag,
            "concurrent-B",
            "application/json",
            Bytes::from_static(b"{}")
        ),
    );
    let (winner, loser, expected_body) = if a.status.is_success() {
        (&a, &b, "A")
    } else {
        (&b, &a, "B")
    };
    winner.successful();
    assert!(
        matches!(
            loser.status,
            StatusCode::PRECONDITION_FAILED | StatusCode::SERVICE_UNAVAILABLE
        ),
        "only one same-revision activation may commit: {}",
        String::from_utf8_lossy(&loser.body)
    );
    if loser.status == StatusCode::SERVICE_UNAVAILABLE {
        assert!(
            matches!(
                loser.json()["code"].as_str(),
                Some(
                    "admin.preparation_busy" | "candidate.preparation_busy" | "admin.mutation_busy"
                )
            ),
            "bounded admission rejection must be explicit: {}",
            String::from_utf8_lossy(&loser.body)
        );
    }
    assert_eq!(
        fixture.current().await.json()["runtime_revision"],
        before_revision + 1
    );
    assert_eq!(data_reply(fixture.address).await.body, expected_body);
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn readless_stage_validate_activate_uses_the_granted_mutation_permissions() {
    let fixture = Fixture::start(
        "    read: false\n    stage: true\n    activate: true\n",
        true,
        TOKEN,
    )
    .await;
    let (digest, bytes) = fixture.signed_bundle("A");
    let etag = fixture.running.reload_handle().published_runtime().etag();
    assert_eq!(
        fixture.read("/api/v1/snapshots/current").await.status,
        StatusCode::FORBIDDEN
    );
    fixture
        .mutate(
            "/api/v1/candidates",
            &etag,
            "readless-stage",
            "application/vnd.oxidase.bundle",
            bytes,
        )
        .await
        .successful();
    for action in ["validate", "activate"] {
        fixture
            .mutate(
                &format!("/api/v1/candidates/{digest}/{action}"),
                &etag,
                &format!("readless-{action}"),
                "application/json",
                Bytes::from_static(b"{}"),
            )
            .await
            .successful();
    }
    assert_eq!(data_reply(fixture.address).await.body, "A");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn admin_api_error_statuses_use_one_json_envelope_and_method_allow() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    for (method, path, headers, expected) in [
        (
            Method::GET,
            "/api/v1/does-not-exist",
            Vec::new(),
            StatusCode::NOT_FOUND,
        ),
        (
            Method::POST,
            "/api/v1/runtime",
            Vec::new(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::POST,
            "/api/v1/drain",
            vec![("content-type", "application/json".to_owned())],
            StatusCode::PRECONDITION_REQUIRED,
        ),
        (
            Method::POST,
            "/api/v1/drain",
            vec![
                ("content-type", "text/plain".to_owned()),
                ("if-match", fixture.current().await.etag()),
            ],
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            Method::POST,
            "/api/v1/drain",
            vec![
                ("content-type", "application/json".to_owned()),
                ("if-match", fixture.current().await.etag()),
                ("if-match", fixture.current().await.etag()),
            ],
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let reply = unix_request(
            &fixture.socket,
            method,
            path,
            Some(TOKEN),
            &headers,
            Bytes::from_static(b"{}"),
        )
        .await;
        assert_eq!(
            reply.status,
            expected,
            "{path}: {}",
            String::from_utf8_lossy(&reply.body)
        );
        assert_eq!(reply.json()["schema_version"], "oxidase.admin/v1");
        assert!(reply.json()["code"].is_string());
        if expected == StatusCode::METHOD_NOT_ALLOWED {
            assert!(reply.headers.contains_key(header::ALLOW));
        }
    }
    assert_eq!(data_reply(fixture.address).await.body, "initial");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn rollback_reopens_external_secret_and_private_key_before_publication() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let secret_path = fixture.root.join("application.secret");
    let private_path = fixture.root.join("application.key");
    let public_path = fixture.root.join("application.pem");
    let identity = rcgen::generate_simple_self_signed(vec!["application.example.test".to_owned()])
        .expect("test-only certificate");
    let private_key = identity.signing_key.serialize_pem();
    let secret = b"test-only-application-secret";
    fs::write(&secret_path, secret).expect("test-only application Secret");
    fs::write(&private_path, &private_key).expect("test-only application private key");
    fs::write(&public_path, identity.cert.pem()).expect("application public chain");
    let source = format!(
        "{}resources:\n  secrets:\n    app-token:\n      file: application.secret\n      max_bytes: 1KiB\n  certificates:\n    app-cert:\n      cert_chain: application.pem\n      private_key: application.key\n",
        data_source("A")
    );
    let (a, bytes) = fixture.signed_bundle_source("A-sensitive", &source);
    let original = Compiler::compile_path(fixture.root.join("candidate-A-sensitive.yaml"))
        .expect("original sensitive candidate source");
    let secret_span =
        &original.resources.secrets[&oxidase_core::ResourceId::new("secret:app-token")].file_source;
    let private_key_span = &original.resources.certificates
        [&oxidase_core::ResourceId::new("certificate:app-cert")]
        .private_key_source;
    assert!(
        !bytes.windows(secret.len()).any(|window| window == secret),
        "Bundle does not embed Secret material"
    );
    assert!(
        !bytes
            .windows(private_key.len())
            .any(|window| window == private_key.as_bytes()),
        "Bundle does not embed private-key material"
    );
    let etag = fixture.current().await.etag();
    fixture
        .mutate(
            "/api/v1/candidates",
            &etag,
            "stage-sensitive-A",
            "application/vnd.oxidase.bundle",
            bytes,
        )
        .await
        .successful();
    fixture
        .mutate(
            &format!("/api/v1/candidates/{a}/validate"),
            &etag,
            "validate-sensitive-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    fixture
        .activate(&a, "activate-sensitive-A")
        .await
        .successful();
    let b = fixture.stage_validate("B").await;
    fixture.activate(&b, "activate-B").await.successful();
    let current = fixture.current().await;
    let before_revision = current.json()["runtime_revision"]
        .as_u64()
        .expect("current revision");
    fs::remove_file(&secret_path).expect("remove test-only external Secret");
    let missing = fixture
        .mutate(
            &format!("/api/v1/snapshots/{a}/rollback"),
            &current.etag(),
            "rollback-missing-secret",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await;
    assert!(!missing.status.is_success());
    assert_eq!(data_reply(fixture.address).await.body, "B");
    assert_eq!(
        fixture.current().await.json()["runtime_revision"],
        before_revision
    );
    fs::write(&secret_path, secret).expect("restore test-only Secret");
    fs::write(&private_path, b"not a private key").expect("corrupt test-only key");
    let invalid = fixture
        .mutate(
            &format!("/api/v1/snapshots/{a}/rollback"),
            &current.etag(),
            "rollback-invalid-key",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await;
    assert!(!invalid.status.is_success());
    assert_eq!(data_reply(fixture.address).await.body, "B");
    assert_eq!(
        fixture.current().await.json()["runtime_revision"],
        before_revision
    );
    for (reply, expected_field, original_span) in [
        (missing, "resources.secrets[\"<key>\"].file", secret_span),
        (
            invalid,
            "resources.certificates[\"<key>\"].private_key",
            private_key_span,
        ),
    ] {
        let text = String::from_utf8_lossy(&reply.body);
        assert!(!text.contains(fixture.root.to_str().expect("UTF-8 test root")));
        assert!(!text.contains(secret_path.to_str().expect("UTF-8 test path")));
        assert!(!text.contains(private_path.to_str().expect("UTF-8 test path")));
        assert!(!text.contains("test-only-application-secret"));
        assert!(!text.contains("application.secret"));
        assert!(!text.contains("application.key"));
        assert!(!text.contains("application.pem"));
        assert!(!text.contains("candidate-A-sensitive.yaml"));
        let json = reply.json();
        let diagnostics = json["diagnostics"]
            .as_array()
            .expect("prepare failures retain safe structured diagnostics");
        let primary = diagnostics
            .iter()
            .find_map(|diagnostic| diagnostic["primary"].as_object())
            .expect("prepare failure preserves its source span");
        assert_eq!(primary["file"], "<source>");
        assert_eq!(primary["field_path"], expected_field);
        assert_eq!(
            primary["start"],
            serde_json::json!({
                "byte": original_span.start_byte,
                "line": original_span.line,
                "column": original_span.column,
            })
        );
        assert_eq!(
            primary["end"],
            serde_json::json!({
                "byte": original_span.end_byte,
                "line": original_span.end_line,
                "column": original_span.end_column,
            })
        );
    }
    fs::write(&private_path, &private_key).expect("restore test-only key");
    fixture
        .mutate(
            &format!("/api/v1/snapshots/{a}/rollback"),
            &current.etag(),
            "rollback-restored-A",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    assert_eq!(data_reply(fixture.address).await.body, "A");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn admin_body_size_and_trailers_are_rejected_before_mutation() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let current = fixture.current().await;
    let revision = current.json()["runtime_revision"]
        .as_u64()
        .expect("runtime revision");
    let token = std::str::from_utf8(TOKEN).expect("ASCII test token");
    let request = format!(
        "POST /api/v1/candidates HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/vnd.oxidase.bundle\r\nIf-Match: {}\r\nContent-Length: 1073741825\r\n\r\n",
        current.etag()
    );
    let reply = raw_admin_reply(&fixture.socket, request.as_bytes()).await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.json()["schema_version"], "oxidase.admin/v1");
    let request = format!(
        "POST /api/v1/drain HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIf-Match: {}\r\nTransfer-Encoding: chunked\r\nTrailer: x-invalid\r\n\r\n2\r\n{{}}\r\n0\r\nx-invalid: invalid\r\n\r\n",
        current.etag()
    );
    let reply = raw_admin_reply(&fixture.socket, request.as_bytes()).await;
    assert_eq!(
        reply.status,
        StatusCode::BAD_REQUEST,
        "Admin cannot ignore trailers: {}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(reply.json()["schema_version"], "oxidase.admin/v1");
    assert_eq!(fixture.current().await.json()["runtime_revision"], revision);
    assert_eq!(data_reply(fixture.address).await.body, "initial");
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn bundle_only_boot_does_not_guess_a_source_origin_from_summary_or_history() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let source = fs::read_to_string(&fixture.config).expect("fixture source");
    let (_, bytes) = fixture.signed_bundle_source("bootstrap", &source);
    let path = fixture.root.join("bootstrap.oxb");
    fs::write(&path, bytes).expect("signed bootstrap Bundle");
    fixture
        .running
        .shutdown()
        .await
        .expect("source setup shuts down");
    fs::remove_file(&fixture.config).expect("source document is absent at Bundle boot");
    let archive = BundleArchive::read_path(&path, &BundleLimits::default())
        .expect("signed Bundle reads without YAML");
    archive
        .verify_ed25519(
            &[fixture.signing.verification_key()],
            oxidase_bundle::SignatureRequirement::RequireAnyTrusted,
        )
        .expect("bootstrap signature verified");
    let prepared = oxidase_runtime::prepare_bundle_archive(&archive, &path, &fixture.root, None)
        .expect("bootstrap resources prepare without YAML");
    let digest = archive.content_digest().into();
    let server =
        GatewayServer::bind_with_origin(prepared.snapshot, RuntimeOrigin::Bundle { digest })
            .await
            .expect("Bundle-only gateway binds");
    let address = server.local_addresses()[0].1;
    let running = server.spawn();
    let current = unix_request(
        &fixture.socket,
        Method::GET,
        "/api/v1/snapshots/current",
        Some(TOKEN),
        &[],
        Bytes::new(),
    )
    .await;
    current.successful();
    assert_eq!(current.json()["origin"]["kind"], "bundle");
    assert!(
        running
            .reload_handle()
            .published_runtime()
            .source_origin
            .is_none()
    );
    let headers = [
        ("content-type", "application/json".to_owned()),
        ("if-match", current.etag()),
        ("idempotency-key", "bundle-only-reload".to_owned()),
    ];
    let reply = unix_request(
        &fixture.socket,
        Method::POST,
        "/api/v1/reload-source",
        Some(TOKEN),
        &headers,
        Bytes::from_static(b"{}"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::CONFLICT);
    assert_eq!(reply.json()["code"], "admin.source_unavailable");
    assert_eq!(data_reply(address).await.body, "initial");
    assert_eq!(
        running.reload_handle().published_runtime().runtime_revision,
        1
    );
    running.shutdown().await.expect("Bundle lifecycle shutdown");
}

#[tokio::test]
async fn client_disconnect_after_observed_publication_keeps_a_queryable_receipt() {
    let fixture = Fixture::start(ALL_PERMISSIONS, true, TOKEN).await;
    let a = fixture.stage_validate("A").await;
    let current = fixture.current().await;
    let before_revision = current.json()["runtime_revision"]
        .as_u64()
        .expect("initial revision");
    let old_etag = current.etag();
    let token = std::str::from_utf8(TOKEN).expect("ASCII test token");
    let raw = format!(
        "POST /api/v1/candidates/{a}/activate HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIf-Match: {old_etag}\r\nIdempotency-Key: disconnect-after-publish\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    let mut stream = UnixStream::connect(&fixture.socket)
        .await
        .expect("activation client connects");
    stream
        .write_all(raw.as_bytes())
        .await
        .expect("complete mutation request sent");
    let reload = fixture.running.reload_handle();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let published = reload.published_runtime();
            if published
                .bundle_digest()
                .is_some_and(|digest| digest.to_string() == a)
            {
                assert_eq!(published.runtime_revision, before_revision + 1);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("manager publication observed independently from HTTP response");
    // No HTTP response was read; close only after the actual snapshot has changed.
    drop(stream);
    // The original committed task can briefly still own the bounded mutation
    // gate while completing audit delivery. Retry only its unchanged request.
    let replay = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let reply = fixture
                .mutate(
                    &format!("/api/v1/candidates/{a}/activate"),
                    &old_etag,
                    "disconnect-after-publish",
                    "application/json",
                    Bytes::from_static(b"{}"),
                )
                .await;
            if reply.status == StatusCode::SERVICE_UNAVAILABLE
                && matches!(
                    reply.json()["code"].as_str(),
                    Some("admin.mutation_busy" | "admin.audit_capacity")
                )
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            break reply;
        }
    })
    .await
    .expect("committed task finishes bookkeeping and admission is released");
    replay.successful();
    let replay = replay.json();
    let operation_id = replay["operation_id"]
        .as_str()
        .expect("lost response has an operation receipt");
    assert_eq!(replay["operation"]["phase"], "committed");
    assert_eq!(
        replay["operation"]["committed_revision"],
        before_revision + 1
    );
    assert_eq!(
        fixture.current().await.json()["runtime_revision"],
        before_revision + 1,
        "retry does not publish a second generation"
    );
    let queried = fixture
        .read(&format!("/api/v1/operations/{operation_id}"))
        .await;
    queried.successful();
    assert_eq!(queried.json()["operation"]["phase"], "committed");
    assert_eq!(data_reply(fixture.address).await.body, "A");
    drop(reload);
    fixture.running.shutdown().await.expect("fixture shutdown");
    let audit = fs::read_to_string(fixture.root.join("audit.jsonl")).expect("real audit delivery");
    assert!(
        audit.contains(operation_id),
        "published operation is audited despite response loss"
    );
    assert!(!audit.contains(token));
}

#[tokio::test]
async fn repeated_drain_with_a_new_key_keeps_the_same_publication_revision() {
    let fixture = Fixture::start("    read: true\n    drain: true\n", false, TOKEN).await;
    let first = fixture.current().await;
    fixture
        .mutate(
            "/api/v1/drain",
            &first.etag(),
            "first-drain",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    let drained = fixture.current().await;
    fixture
        .mutate(
            "/api/v1/drain",
            &drained.etag(),
            "distinct-second-drain",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    let repeated = fixture.current().await;
    assert_eq!(repeated.etag(), drained.etag());
    assert_eq!(
        repeated.json()["runtime_revision"],
        drained.json()["runtime_revision"]
    );
    assert_eq!(repeated.json()["serving_state"], "drained");
    assert_eq!(fixture.read("/health/live").await.status, StatusCode::OK);
    assert_eq!(
        fixture.read("/health/ready").await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    fixture.running.shutdown().await.expect("fixture shutdown");
}

#[tokio::test]
async fn real_jsonl_audit_covers_early_failures_receipt_replay_and_control_actions_without_secrets()
{
    let permissions = "    read: true\n    stage: true\n    activate: false\n    drain: true\n    reload_source: true\n";
    let fixture = Fixture::start(permissions, true, TOKEN).await;
    let current = fixture.current().await;
    let etag = current.etag();
    let (digest, bytes) = fixture.signed_bundle("A");
    let stage = fixture
        .mutate(
            "/api/v1/candidates",
            &etag,
            "audit-stage-A",
            "application/vnd.oxidase.bundle",
            bytes.clone(),
        )
        .await;
    stage.successful();
    fixture
        .mutate(
            "/api/v1/candidates",
            &etag,
            "audit-stage-A",
            "application/vnd.oxidase.bundle",
            bytes,
        )
        .await
        .successful();
    assert_eq!(
        unix_request(
            &fixture.socket,
            Method::GET,
            "/api/v1/runtime",
            Some(b"test-only-rejected-token"),
            &[],
            Bytes::new()
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        fixture
            .mutate(
                &format!("/api/v1/candidates/{digest}/activate"),
                &etag,
                "audit-forbidden",
                "application/json",
                Bytes::from_static(b"{}")
            )
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        fixture
            .mutate(
                "/api/v1/drain",
                &etag,
                "audit-content-type",
                "text/plain",
                Bytes::from_static(b"audit-json-body-marker-not-logged")
            )
            .await
            .status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert_eq!(
        fixture
            .mutate(
                "/api/v1/drain",
                "\"runtime-stale\"",
                "audit-stale",
                "application/json",
                Bytes::from_static(b"{}")
            )
            .await
            .status,
        StatusCode::PRECONDITION_FAILED
    );
    let raw = format!(
        "POST /api/v1/candidates HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/vnd.oxidase.bundle\r\nIf-Match: {etag}\r\nContent-Length: 1073741825\r\n\r\n",
        std::str::from_utf8(TOKEN).expect("ASCII token")
    );
    assert_eq!(
        raw_admin_reply(&fixture.socket, raw.as_bytes())
            .await
            .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let marker = b"audit-invalid-bundle-marker-not-logged";
    let failed = fixture
        .mutate(
            "/api/v1/candidates",
            &etag,
            "audit-invalid-bundle",
            "application/vnd.oxidase.bundle",
            Bytes::from_static(marker),
        )
        .await;
    assert!(!failed.status.is_success());
    fs::write(
        &fixture.config,
        admin_source(
            &fixture.root,
            "audit-source-body-not-logged",
            permissions,
            true,
        ),
    )
    .expect("source reload fixture");
    fixture
        .mutate(
            "/api/v1/reload-source",
            &etag,
            "audit-reload",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    let current = fixture.current().await;
    fixture
        .mutate(
            "/api/v1/drain",
            &current.etag(),
            "audit-drain",
            "application/json",
            Bytes::from_static(b"{}"),
        )
        .await
        .successful();
    fixture
        .running
        .shutdown()
        .await
        .expect("audit worker flushes at shutdown");
    let text =
        fs::read_to_string(fixture.root.join("audit.jsonl")).expect("actual JSONL audit file");
    let events = text
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).expect("each delivered audit line is valid JSON")
        })
        .collect::<Vec<_>>();
    assert!(!events.is_empty());
    for code in [
        "admin.unauthenticated",
        "admin.forbidden",
        "admin.unsupported_media_type",
        "admin.payload_too_large",
    ] {
        assert!(
            events.iter().any(|event| event["diagnostic_code"] == code),
            "real sink contains {code}: {text}"
        );
    }
    assert!(
        events.iter().any(|event| matches!(
            event["diagnostic_code"].as_str(),
            Some("admin.precondition_failed" | "candidate.precondition")
        )),
        "stale publication is audited"
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "stage" && event["result"] == "replayed")
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "reload_source" && event["result"] == "committed")
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "drain" && event["result"] == "committed")
    );
    assert!(
        events
            .iter()
            .any(|event| event["action"] == "stage" && event["result"] == "failed")
    );
    for event in &events {
        assert!(event["request_id"].is_string());
        assert!(event["authentication"].is_string());
        assert!(event["principal"].is_string());
    }
    for sensitive in [
        std::str::from_utf8(TOKEN).expect("token ASCII"),
        "test-only-rejected-token",
        "audit-json-body-marker-not-logged",
        std::str::from_utf8(marker).expect("marker ASCII"),
        "audit-source-body-not-logged",
        fixture.root.to_str().expect("UTF-8 root"),
    ] {
        assert!(
            !text.contains(sensitive),
            "audit does not retain credentials, source/body values, or deployment paths"
        );
    }
}
