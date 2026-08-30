//! Black-box HTTP/1 Upgrade tunnel tests.
//!
//! The byte sequences use WebSocket-style frames, but the fixture deliberately
//! does not parse them: Oxidase is a transparent generic HTTP/1 Upgrade bridge.
//! Every TLS private key generated here is ephemeral test-only material.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http2;
use hyper::ext::Protocol;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const CLIENT_FRAME: &[u8] = b"\x81\x04ping";
const UPSTREAM_FRAME: &[u8] = b"\x81\x04pong";

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
    certificate_der: CertificateDer<'static>,
}

struct TestGateway {
    _directory: TempDir,
    config: PathBuf,
    address: std::net::SocketAddr,
    admin: std::net::SocketAddr,
    running: RunningServer,
}

#[derive(Clone)]
enum UpstreamMode {
    Echo,
    SendThenClose(Vec<u8>),
}

struct UpgradeUpstream {
    address: std::net::SocketAddr,
    peer_closed: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl UpgradeUpstream {
    async fn finish(self) {
        tokio::time::timeout(Duration::from_secs(2), self.task)
            .await
            .expect("upstream fixture exits before timeout")
            .expect("upstream fixture task joins");
    }
}

fn identity(names: &[&str]) -> TestIdentity {
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

fn write_identity(directory: &Path, identity: &TestIdentity) {
    fs::write(directory.join("gateway.pem"), &identity.certificate_pem)
        .expect("test-only certificate can be written");
    fs::write(directory.join("gateway-key.pem"), &identity.private_key_pem)
        .expect("test-only private key can be written");
}

fn client_config(identity: &TestIdentity, alpn: &[&[u8]]) -> Arc<ClientConfig> {
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

async fn spawn_upgrade_upstream(mode: UpstreamMode) -> UpgradeUpstream {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upgrade upstream binds");
    let address = listener.local_addr().expect("upstream address is known");
    let peer_closed = Arc::new(Notify::new());
    let peer_closed_for_task = peer_closed.clone();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("gateway connects upstream");
        let request = read_http1_head(&mut stream).await;
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("GET /tunnel HTTP/1.1\r\n"), "{request}");
        assert!(lower.contains("connection: upgrade\r\n"), "{request}");
        assert!(lower.contains("upgrade: websocket\r\n"), "{request}");
        stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .expect("upstream switching response can be written");

        match mode {
            UpstreamMode::Echo => {
                let mut buffer = [0u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.expect("tunnel is readable");
                    if read == 0 {
                        peer_closed_for_task.notify_one();
                        break;
                    }
                    stream
                        .write_all(&buffer[..read])
                        .await
                        .expect("tunnel echo is writable");
                }
            }
            UpstreamMode::SendThenClose(bytes) => {
                stream
                    .write_all(&bytes)
                    .await
                    .expect("upstream tunnel bytes can be written");
                stream.shutdown().await.expect("upstream closes cleanly");
            }
        }
    });
    UpgradeUpstream {
        address,
        peer_closed,
        task,
    }
}

async fn read_http1_head<I>(io: &mut I) -> String
where
    I: AsyncRead + Unpin,
{
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = io.read(&mut byte).await.expect("HTTP/1 head is readable");
            assert!(
                read > 0,
                "connection closed before the HTTP/1 head completed"
            );
            bytes.push(byte[0]);
            assert!(bytes.len() <= 64 * 1024, "HTTP/1 fixture head is bounded");
            if bytes.ends_with(b"\r\n\r\n") {
                return String::from_utf8(bytes).expect("HTTP/1 fixture head is UTF-8");
            }
        }
    })
    .await
    .expect("HTTP/1 head arrives before timeout")
}

async fn perform_upgrade<I>(io: &mut I) -> String
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    io.write_all(
        b"GET /tunnel HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
    )
    .await
    .expect("Upgrade request can be written");
    let response = read_http1_head(io).await;
    let lower = response.to_ascii_lowercase();
    assert!(
        response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
        "{response}"
    );
    assert!(lower.contains("connection: upgrade\r\n"), "{response}");
    assert!(lower.contains("upgrade: websocket\r\n"), "{response}");
    response
}

fn write_plain_proxy(path: &Path, bind: &str, upstream: std::net::SocketAddr) {
    fs::write(
        path,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      protocol: http1
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: public
    bind: {bind}
    service:
      ref: root
"#
        ),
    )
    .expect("plain proxy config can be written");
}

fn write_plain_respond(path: &Path, bind: &str, status: u16, body: &str) {
    fs::write(
        path,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    status: {status}
    body:
      text: "{body}"
listeners:
  - name: public
    bind: {bind}
    service:
      ref: root
"#
        ),
    )
    .expect("plain response config can be written");
}

fn write_tls_proxy(path: &Path, upstream: std::net::SocketAddr, versions: &str) {
    fs::write(
        path,
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
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: public
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: gateway
    http:
      versions: [{versions}]
    service:
      ref: root
"#
        ),
    )
    .expect("TLS proxy config can be written");
}

async fn launch_gateway(directory: TempDir, config: PathBuf) -> TestGateway {
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("gateway fixture compiles"),
    )
    .expect("gateway fixture prepares");
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("gateway fixture binds")
        .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
        .await
        .expect("admin listener binds");
    let admin = server.admin_address().expect("admin address is available");
    let running = server.spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        config,
        address,
        admin,
        running,
    }
}

async fn plain_proxy_gateway(upstream: std::net::SocketAddr) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    let config = directory.path().join("oxidase.yaml");
    write_plain_proxy(&config, "127.0.0.1:0", upstream);
    launch_gateway(directory, config).await
}

async fn tls_proxy_gateway(
    upstream: std::net::SocketAddr,
    identity: &TestIdentity,
    versions: &str,
) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    write_identity(directory.path(), identity);
    let config = directory.path().join("oxidase.yaml");
    write_tls_proxy(&config, upstream, versions);
    launch_gateway(directory, config).await
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

async fn wait_for_metric(address: std::net::SocketAddr, expected: &str) -> String {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let metrics = admin_metrics(address).await;
            if metrics.contains(expected) {
                return metrics;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("metric did not reach expected value: {expected}"))
}

async fn plain_get(address: std::net::SocketAddr) -> String {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("HTTP/1 client connects");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("HTTP/1 request can be written");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("HTTP/1 response completes")
        .expect("HTTP/1 response is readable");
    String::from_utf8(response).expect("HTTP/1 response is UTF-8")
}

fn available_address() -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("temporary loopback port can be reserved");
    listener.local_addr().expect("reserved address is known")
}

#[tokio::test]
async fn plain_http1_upgrade_forwards_websocket_style_bytes_and_client_close() {
    let upstream = spawn_upgrade_upstream(UpstreamMode::Echo).await;
    let gateway = plain_proxy_gateway(upstream.address).await;
    let mut client = TcpStream::connect(gateway.address)
        .await
        .expect("Upgrade client connects");
    perform_upgrade(&mut client).await;

    client
        .write_all(CLIENT_FRAME)
        .await
        .expect("client WebSocket-style frame can be written");
    let mut echoed = vec![0u8; CLIENT_FRAME.len()];
    client
        .read_exact(&mut echoed)
        .await
        .expect("echoed frame is readable");
    assert_eq!(echoed, CLIENT_FRAME);

    client.shutdown().await.expect("client half-closes cleanly");
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), upstream.peer_closed.notified())
        .await
        .expect("client close propagates to the upstream tunnel");
    upstream.finish().await;
    let metrics = wait_for_metric(
        gateway.admin,
        "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"downstream_closed\"} 1",
    )
    .await;
    assert!(metrics.contains("oxidase_active_tunnels{listener=\"public\"} 0"));
    assert!(metrics.contains(&format!(
        "oxidase_tunnel_bytes_total{{listener=\"public\",direction=\"downstream_to_upstream\"}} {}",
        CLIENT_FRAME.len()
    )));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn tls_http1_upgrade_forwards_upstream_bytes_and_upstream_close() {
    let upstream =
        spawn_upgrade_upstream(UpstreamMode::SendThenClose(UPSTREAM_FRAME.to_vec())).await;
    let identity = identity(&["gateway.example.test"]);
    let gateway = tls_proxy_gateway(upstream.address, &identity, "http1").await;
    let mut client = connect_tls(
        gateway.address,
        "gateway.example.test",
        client_config(&identity, &[b"http/1.1"]),
    )
    .await;
    assert_eq!(
        client.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    perform_upgrade(&mut client).await;

    let mut bytes = vec![0u8; UPSTREAM_FRAME.len()];
    client
        .read_exact(&mut bytes)
        .await
        .expect("upstream frame reaches the TLS client");
    assert_eq!(bytes, UPSTREAM_FRAME);
    let mut after_close = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.read(&mut after_close))
            .await
            .expect("upstream close reaches downstream")
            .expect("TLS tunnel closes with close_notify"),
        0
    );
    upstream.finish().await;
    let metrics = wait_for_metric(
        gateway.admin,
        "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"upstream_closed\"} 1",
    )
    .await;
    assert!(metrics.contains("oxidase_active_tunnels{listener=\"public\"} 0"));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn reload_keeps_the_old_tunnel_until_retired_listener_drain_timeout() {
    let upstream = spawn_upgrade_upstream(UpstreamMode::Echo).await;
    let gateway = plain_proxy_gateway(upstream.address).await;
    let mut client = TcpStream::connect(gateway.address)
        .await
        .expect("Upgrade client connects");
    perform_upgrade(&mut client).await;
    client
        .write_all(CLIENT_FRAME)
        .await
        .expect("pre-reload tunnel frame can be written");
    let mut echoed = vec![0u8; CLIENT_FRAME.len()];
    client
        .read_exact(&mut echoed)
        .await
        .expect("pre-reload frame is echoed");
    assert_eq!(echoed, CLIENT_FRAME);

    let replacement = available_address();
    write_plain_respond(
        &gateway.config,
        &replacement.to_string(),
        StatusCode::OK.as_u16(),
        "new-snapshot",
    );
    let drain_started = Instant::now();
    let report = gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("replacement listener commits");
    assert_eq!(report.listeners_removed, ["public"]);
    assert_eq!(report.listeners_added, ["public"]);
    assert!(plain_get(replacement).await.ends_with("new-snapshot"));

    client
        .write_all(UPSTREAM_FRAME)
        .await
        .expect("old tunnel remains writable during listener drain");
    let mut post_reload = vec![0u8; UPSTREAM_FRAME.len()];
    client
        .read_exact(&mut post_reload)
        .await
        .expect("old tunnel remains readable during listener drain");
    assert_eq!(post_reload, UPSTREAM_FRAME);

    let mut after_timeout = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(12), client.read(&mut after_timeout))
        .await
        .expect("retired listener enforces its bounded drain timeout")
        .expect("retired tunnel closes without a client I/O error");
    assert_eq!(read, 0);
    assert!(
        drain_started.elapsed() >= Duration::from_millis(250),
        "the established tunnel must receive a real drain window"
    );
    tokio::time::timeout(Duration::from_secs(2), upstream.peer_closed.notified())
        .await
        .expect("forced listener drain drops the upstream side");
    upstream.finish().await;
    let metrics = wait_for_metric(
        gateway.admin,
        "oxidase_tunnel_terminations_total{listener=\"public\",reason=\"cancelled\"} 1",
    )
    .await;
    assert!(metrics.contains("oxidase_active_tunnels{listener=\"public\"} 0"));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn non_proxy_101_cannot_create_a_trusted_upgrade_tunnel() {
    let directory = tempdir().expect("temporary gateway directory is available");
    let config = directory.path().join("oxidase.yaml");
    write_plain_respond(&config, "127.0.0.1:0", 101, "forbidden-body");
    let gateway = launch_gateway(directory, config).await;
    let mut client = TcpStream::connect(gateway.address)
        .await
        .expect("Upgrade client connects");
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await
        .expect("Upgrade-shaped request can be written");
    let response = read_http1_head(&mut client).await;
    let lower = response.to_ascii_lowercase();
    assert!(response.starts_with("HTTP/1.1 101 Switching Protocols"));
    assert!(!lower.contains("connection: upgrade"), "{response}");
    assert!(!lower.contains("upgrade: websocket"), "{response}");
    assert!(!lower.contains("content-length:"), "{response}");

    let mut after_response = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), client.read(&mut after_response))
            .await
            .expect("ordinary 101 does not leave a tunnel running")
            .expect("connection closes cleanly"),
        0
    );
    let metrics = admin_metrics(gateway.admin).await;
    assert!(metrics.contains("oxidase_tunnels_started_total{listener=\"public\"} 0"));
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn h2_extended_connect_and_http1_h2c_are_rejected_before_proxying() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = tls_proxy_gateway(
        "127.0.0.1:9".parse().expect("unused endpoint is valid"),
        &identity,
        "h2",
    )
    .await;
    let tls = connect_tls(
        gateway.address,
        "gateway.example.test",
        client_config(&identity, &[b"h2"]),
    )
    .await;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut upgrade = Request::builder()
        .method(Method::CONNECT)
        .uri("gateway.example.test:443")
        .body(Empty::<Bytes>::new())
        .expect("H2 WebSocket extended CONNECT request is valid");
    upgrade
        .extensions_mut()
        .insert(Protocol::from_static("websocket"));
    let error = sender
        .send_request(upgrade)
        .await
        .expect_err("RFC 8441 extended CONNECT is rejected by the H2 driver");
    assert!(
        format!("{error:?}").contains("PROTOCOL_ERROR"),
        "extended CONNECT must receive an explicit H2 protocol reset: {error:?}"
    );

    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri("gateway.example.test:443")
        .body(Empty::<Bytes>::new())
        .expect("H2 CONNECT request is valid");
    let response = sender
        .send_request(connect)
        .await
        .expect("CONNECT rejection response arrives");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("CONNECT rejection body is readable")
            .to_bytes(),
        "Bad Request"
    );
    driver.abort();
    gateway
        .running
        .shutdown()
        .await
        .expect("TLS gateway shuts down");

    let directory = tempdir().expect("temporary gateway directory is available");
    let config = directory.path().join("oxidase.yaml");
    write_plain_respond(&config, "127.0.0.1:0", 200, "not-upgraded");
    let gateway = launch_gateway(directory, config).await;
    let mut client = TcpStream::connect(gateway.address)
        .await
        .expect("h2c-shaped client connects");
    client
        .write_all(
            b"GET / HTTP/1.1\r\nHost: gateway.example.test\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        )
        .await
        .expect("h2c-shaped request can be written");
    let response = read_http1_head(&mut client).await;
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request"),
        "{response}"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("plain gateway shuts down");
}
