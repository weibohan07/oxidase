//! Black-box TLS and HTTP/2 transport tests.
//!
//! Every private key generated here is ephemeral, test-only material. It is
//! never suitable for production use and is deleted with its temporary directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
    certificate_der: CertificateDer<'static>,
}

struct TestGateway {
    _directory: TempDir,
    config: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
    address: std::net::SocketAddr,
    admin: std::net::SocketAddr,
    running: RunningServer,
}

struct Http1Client {
    sender: http1::SendRequest<Empty<Bytes>>,
    _driver: tokio::task::JoinHandle<()>,
    peer_leaf: Vec<u8>,
    alpn: Option<Vec<u8>>,
}

struct Http2Client {
    sender: http2::SendRequest<Empty<Bytes>>,
    _driver: tokio::task::JoinHandle<()>,
    peer_leaf: Vec<u8>,
    alpn: Option<Vec<u8>>,
}

fn identity(names: &[&str]) -> TestIdentity {
    // rcgen output is intentionally generated per test and is never a production identity.
    let GeneratedCertificate { cert, signing_key } = generate_simple_self_signed(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .expect("test-only TLS identity can be generated");
    TestIdentity {
        certificate_pem: cert.pem(),
        private_key_pem: signing_key.serialize_pem(),
        certificate_der: cert.der().clone(),
    }
}

fn write_identity(directory: &Path, name: &str, identity: &TestIdentity) -> (PathBuf, PathBuf) {
    let certificate = directory.join(format!("{name}.pem"));
    let private_key = directory.join(format!("{name}-key.pem"));
    fs::write(&certificate, &identity.certificate_pem)
        .expect("test-only certificate can be written");
    fs::write(&private_key, &identity.private_key_pem)
        .expect("test-only private key can be written");
    (certificate, private_key)
}

fn client_config(identities: &[&TestIdentity], alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for identity in identities {
        roots
            .add(identity.certificate_der.clone())
            .expect("test certificate can be trusted");
    }
    let provider = Arc::new(default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

async fn connect_tls(
    address: std::net::SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> TlsStream<TcpStream> {
    let tcp = TcpStream::connect(address)
        .await
        .expect("TLS client connects to loopback listener");
    let name = ServerName::try_from(server_name.to_owned()).expect("test DNS name is valid");
    TlsConnector::from(config)
        .connect(name, tcp)
        .await
        .expect("TLS handshake succeeds")
}

fn peer_leaf(stream: &TlsStream<TcpStream>) -> Vec<u8> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .expect("server presents a leaf certificate")
        .as_ref()
        .to_vec()
}

async fn http1_client(
    address: std::net::SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Http1Client {
    let tls = connect_tls(address, server_name, config).await;
    let peer_leaf = peer_leaf(&tls);
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let (sender, connection) = http1::handshake(TokioIo::new(tls))
        .await
        .expect("HTTP/1 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Http1Client {
        sender,
        _driver: driver,
        peer_leaf,
        alpn,
    }
}

async fn http2_client(
    address: std::net::SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Http2Client {
    let tls = connect_tls(address, server_name, config).await;
    let peer_leaf = peer_leaf(&tls);
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Http2Client {
        sender,
        _driver: driver,
        peer_leaf,
        alpn,
    }
}

async fn send_http1(sender: &mut http1::SendRequest<Empty<Bytes>>, host: &str) -> String {
    let request = Request::builder()
        .uri("/")
        .header("host", host)
        .body(Empty::new())
        .expect("HTTP/1 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/1 response head arrives");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("HTTP/1 response body is readable")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("test response body is UTF-8")
}

async fn send_http2(sender: &mut http2::SendRequest<Empty<Bytes>>, host: &str) -> String {
    let request = Request::builder()
        .uri(format!("https://{host}/"))
        .body(Empty::new())
        .expect("HTTP/2 request is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/2 response head arrives");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("HTTP/2 response body is readable")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("test response body is UTF-8")
}

fn gateway_source(body: &str, versions: &str, sni: &str) -> String {
    let http1 = if versions.contains("http1") {
        "      http1:\n        header_read_timeout: 30s\n"
    } else {
        ""
    };
    let http2 = if versions.contains("h2") {
        "      http2:\n        max_concurrent_streams: 64\n        max_header_list_size: 64KiB\n        keep_alive_interval: 30s\n        keep_alive_timeout: 10s\n"
    } else {
        ""
    };
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
{sni}services:
  root:
    type: respond
    body:
      text: "{body}"
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: default
{sni_listener}    http:
      versions: [{versions}]
{http1}{http2}    service:
      ref: root
"#,
        sni_listener = if sni.is_empty() {
            String::new()
        } else {
            "      sni:\n        api.example.test: exact\n        \"*.internal.example.test\": wildcard\n".to_owned()
        }
    )
}

fn write_gateway(path: &Path, body: &str, versions: &str, with_sni: bool) {
    let resources = if with_sni {
        "    exact:\n      cert_chain: exact.pem\n      private_key: exact-key.pem\n    wildcard:\n      cert_chain: wildcard.pem\n      private_key: wildcard-key.pem\n"
    } else {
        ""
    };
    fs::write(path, gateway_source(body, versions, resources))
        .expect("gateway source can be written");
}

async fn start_gateway(identity: &TestIdentity, body: &str, versions: &str) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    let (certificate, private_key) = write_identity(directory.path(), "default", identity);
    let config = directory.path().join("oxidase.yaml");
    write_gateway(&config, body, versions, false);
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("TLS gateway source compiles"),
    )
    .expect("TLS gateway prepares");
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("TLS gateway binds")
        .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
        .await
        .expect("admin listener binds");
    let admin = server.admin_address().expect("admin address is available");
    let running = server.spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        config,
        certificate,
        private_key,
        address,
        admin,
        running,
    }
}

async fn admin_metrics(address: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("admin client connects");
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: admin.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("metrics request can be written");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("metrics response completes")
        .expect("metrics response is readable");
    String::from_utf8(response).expect("metrics response is UTF-8")
}

#[tokio::test]
async fn negotiates_http1_and_h2_and_exposes_only_bounded_transport_metrics() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, "transport-ok", "h2, http1").await;
    let mut h1 = http1_client(
        gateway.address,
        "gateway.example.test",
        client_config(&[&identity], &[b"http/1.1"]),
    )
    .await;
    assert_eq!(h1.alpn.as_deref(), Some(b"http/1.1".as_slice()));
    assert_eq!(
        send_http1(&mut h1.sender, "gateway.example.test").await,
        "transport-ok"
    );

    let mut h2 = http2_client(
        gateway.address,
        "gateway.example.test",
        client_config(&[&identity], &[b"h2"]),
    )
    .await;
    assert_eq!(h2.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(h2.peer_leaf, identity.certificate_der.as_ref());
    assert_eq!(
        send_http2(&mut h2.sender, "gateway.example.test").await,
        "transport-ok"
    );

    let metrics = admin_metrics(gateway.admin).await;
    assert!(
        metrics.contains(
            "oxidase_connections_accepted_total{listener=\"secure\",protocol=\"http1\"} 1"
        )
    );
    assert!(
        metrics
            .contains("oxidase_connections_accepted_total{listener=\"secure\",protocol=\"h2\"} 1")
    );
    assert!(metrics.contains("oxidase_tls_alpn_total{listener=\"secure\",protocol=\"http1\"} 1"));
    assert!(metrics.contains("oxidase_tls_alpn_total{listener=\"secure\",protocol=\"h2\"} 1"));
    assert!(!metrics.contains("gateway.example.test"));
    assert!(!metrics.contains("sni="));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn honors_http1_only_and_h2_only_alpn_configuration() {
    let identity = identity(&["versions.example.test"]);

    let h1_gateway = start_gateway(&identity, "http1-only", "http1").await;
    let mut h1 = http1_client(
        h1_gateway.address,
        "versions.example.test",
        client_config(&[&identity], &[b"h2", b"http/1.1"]),
    )
    .await;
    assert_eq!(h1.alpn.as_deref(), Some(b"http/1.1".as_slice()));
    assert_eq!(
        send_http1(&mut h1.sender, "versions.example.test").await,
        "http1-only"
    );
    h1_gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");

    let h2_gateway = start_gateway(&identity, "h2-only", "h2").await;
    let mut h2 = http2_client(
        h2_gateway.address,
        "versions.example.test",
        client_config(&[&identity], &[b"http/1.1", b"h2"]),
    )
    .await;
    assert_eq!(h2.alpn.as_deref(), Some(b"h2".as_slice()));
    assert_eq!(
        send_http2(&mut h2.sender, "versions.example.test").await,
        "h2-only"
    );
    h2_gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn resolves_exact_wildcard_and_default_sni_to_distinct_leaf_certificates() {
    let default = identity(&["unknown.example.test"]);
    let exact = identity(&["api.example.test"]);
    let wildcard = identity(&["*.internal.example.test"]);
    let directory = tempdir().expect("temporary gateway directory is available");
    write_identity(directory.path(), "default", &default);
    write_identity(directory.path(), "exact", &exact);
    write_identity(directory.path(), "wildcard", &wildcard);
    let config = directory.path().join("oxidase.yaml");
    write_gateway(&config, "sni", "http1", true);
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("SNI gateway source compiles"),
    )
    .expect("SNI gateway prepares");
    let running = GatewayServer::bind(snapshot)
        .await
        .expect("SNI gateway binds")
        .spawn();
    let address = running.local_addresses()[0].1;
    let roots = [&default, &exact, &wildcard];

    let exact_client = http1_client(
        address,
        "api.example.test",
        client_config(&roots, &[b"http/1.1"]),
    )
    .await;
    assert_eq!(exact_client.peer_leaf, exact.certificate_der.as_ref());

    let wildcard_client = http1_client(
        address,
        "node.internal.example.test",
        client_config(&roots, &[b"http/1.1"]),
    )
    .await;
    assert_eq!(wildcard_client.peer_leaf, wildcard.certificate_der.as_ref());

    let default_client = http1_client(
        address,
        "unknown.example.test",
        client_config(&roots, &[b"http/1.1"]),
    )
    .await;
    assert_eq!(default_client.peer_leaf, default.certificate_der.as_ref());
    running.shutdown().await.expect("gateway shuts down");
}

#[tokio::test]
async fn h2_multiplexes_and_new_streams_pin_the_reloaded_snapshot() {
    let identity = identity(&["reload.example.test"]);
    let gateway = start_gateway(&identity, "old", "h2").await;
    let mut client = http2_client(
        gateway.address,
        "reload.example.test",
        client_config(&[&identity], &[b"h2"]),
    )
    .await;

    let mut concurrent = Vec::new();
    for _ in 0..16 {
        let mut sender = client.sender.clone();
        concurrent.push(tokio::spawn(async move {
            send_http2(&mut sender, "reload.example.test").await
        }));
    }
    for request in concurrent {
        assert_eq!(request.await.expect("H2 request task joins"), "old");
    }

    let old_response = client
        .sender
        .send_request(
            Request::builder()
                .uri("https://reload.example.test/")
                .body(Empty::new())
                .expect("old-snapshot request is valid"),
        )
        .await
        .expect("old response head arrives");
    write_gateway(&gateway.config, "new", "h2", false);
    let report = gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("same-socket H2 reload commits");
    assert_eq!(report.listeners_retained, vec!["secure"]);
    assert_eq!(
        old_response
            .into_body()
            .collect()
            .await
            .expect("old response body remains readable")
            .to_bytes(),
        Bytes::from_static(b"old")
    );
    assert_eq!(
        send_http2(&mut client.sender, "reload.example.test").await,
        "new"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn rotates_certificate_and_service_atomically_without_rebinding_the_socket() {
    let first = identity(&["rotate.example.test"]);
    let second = identity(&["rotate.example.test"]);
    let gateway = start_gateway(&first, "one", "http1").await;
    let config = client_config(&[&first, &second], &[b"http/1.1"]);
    let mut existing = http1_client(gateway.address, "rotate.example.test", config.clone()).await;
    assert_eq!(existing.peer_leaf, first.certificate_der.as_ref());
    assert_eq!(
        send_http1(&mut existing.sender, "rotate.example.test").await,
        "one"
    );

    fs::write(&gateway.certificate, &second.certificate_pem)
        .expect("rotated test certificate can be written");
    fs::write(&gateway.private_key, &second.private_key_pem)
        .expect("rotated test key can be written");
    write_gateway(&gateway.config, "two", "http1", false);
    let report = gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("certificate and Service rotation commits atomically");
    assert_eq!(report.listeners_retained, vec!["secure"]);
    assert_eq!(report.local_addresses[0].1, gateway.address);

    assert_eq!(
        send_http1(&mut existing.sender, "rotate.example.test").await,
        "two"
    );
    assert_eq!(existing.peer_leaf, first.certificate_der.as_ref());
    let mut fresh = http1_client(gateway.address, "rotate.example.test", config.clone()).await;
    assert_eq!(fresh.peer_leaf, second.certificate_der.as_ref());
    assert_eq!(
        send_http1(&mut fresh.sender, "rotate.example.test").await,
        "two"
    );

    fs::write(&gateway.certificate, &first.certificate_pem)
        .expect("mismatched candidate certificate can be written");
    fs::write(&gateway.private_key, &second.private_key_pem)
        .expect("mismatched candidate key can be written");
    write_gateway(&gateway.config, "must-not-publish", "http1", false);
    let error = gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect_err("mismatched key rotation is rejected");
    assert_eq!(error.diagnostics()[0].code, "tls.key_mismatch");

    let dependencies = gateway.running.reload_handle().watched_dependencies();
    assert!(
        dependencies.contains(
            &gateway
                .certificate
                .canonicalize()
                .expect("cert path exists")
        )
    );
    assert!(dependencies.contains(&gateway.private_key.canonicalize().expect("key path exists")));
    let mut after_failure = http1_client(gateway.address, "rotate.example.test", config).await;
    assert_eq!(after_failure.peer_leaf, second.certificate_der.as_ref());
    assert_eq!(
        send_http1(&mut after_failure.sender, "rotate.example.test").await,
        "two"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}
