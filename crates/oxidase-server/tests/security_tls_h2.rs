//! Adversarial TLS and raw HTTP/2 conformance tests.
//!
//! Test certificates and private keys are generated ephemerally and must never
//! be used outside this test process.

use std::convert::Infallible;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream as futures_stream;
use http::{HeaderMap, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Empty, Full, StreamBody};
use hyper::client::conn::http2;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FRAME_DATA: u8 = 0;
const FRAME_HEADERS: u8 = 1;
const FRAME_RST_STREAM: u8 = 3;
const FRAME_SETTINGS: u8 = 4;
const FRAME_GOAWAY: u8 = 7;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FLAG_END_STREAM: u8 = 1;
const FLAG_ACK: u8 = 1;
const FLAG_END_HEADERS: u8 = 4;

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

struct RawH2 {
    stream: TlsStream<TcpStream>,
}

#[derive(Debug)]
struct H2Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
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

fn client_config(identity: &TestIdentity, alpn: &[&[u8]], send_sni: bool) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(identity.certificate_der.clone())
        .expect("test certificate can be trusted");
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config.enable_sni = send_sni;
    Arc::new(config)
}

fn write_gateway(path: &Path, body: &str, max_concurrent_streams: u32, max_header_list_size: u32) {
    fs::write(
        path,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
services:
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
      handshake_timeout: 5s
    http:
      versions: [h2]
      http2:
        max_concurrent_streams: {max_concurrent_streams}
        max_header_list_size: {max_header_list_size}B
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      ref: root
"#
        ),
    )
    .expect("gateway source can be written");
}

async fn start_gateway(
    identity: &TestIdentity,
    max_concurrent_streams: u32,
    max_header_list_size: u32,
) -> TestGateway {
    start_gateway_with_body(
        identity,
        max_concurrent_streams,
        max_header_list_size,
        "secure",
    )
    .await
}

async fn start_gateway_with_body(
    identity: &TestIdentity,
    max_concurrent_streams: u32,
    max_header_list_size: u32,
    body: &str,
) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    let certificate = directory.path().join("default.pem");
    let private_key = directory.path().join("default-key.pem");
    fs::write(&certificate, &identity.certificate_pem)
        .expect("test-only certificate can be written");
    fs::write(&private_key, &identity.private_key_pem)
        .expect("test-only private key can be written");
    let config = directory.path().join("oxidase.yaml");
    write_gateway(&config, body, max_concurrent_streams, max_header_list_size);
    let snapshot =
        RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("TLS/H2 source compiles"))
            .expect("TLS/H2 snapshot prepares");
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("TLS/H2 gateway binds")
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

async fn start_blocking_proxy_gateway(
    identity: &TestIdentity,
    upstream: std::net::SocketAddr,
    max_concurrent_streams: u32,
) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    let certificate = directory.path().join("default.pem");
    let private_key = directory.path().join("default-key.pem");
    fs::write(&certificate, &identity.certificate_pem)
        .expect("test-only certificate can be written");
    fs::write(&private_key, &identity.private_key_pem)
        .expect("test-only private key can be written");
    let config = directory.path().join("oxidase.yaml");
    fs::write(
        &config,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
  clusters:
    blocking:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 30s
services:
  root:
    type: proxy
    cluster: blocking
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: default
    http:
      versions: [h2]
      http2:
        max_concurrent_streams: {max_concurrent_streams}
        max_header_list_size: 64KiB
        keep_alive_interval: 30s
        keep_alive_timeout: 10s
    service:
      ref: root
"#
        ),
    )
    .expect("blocking Proxy gateway source can be written");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("blocking Proxy source compiles"),
    )
    .expect("blocking Proxy snapshot prepares");
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("blocking Proxy gateway binds")
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

async fn connect_tls(
    address: std::net::SocketAddr,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(address).await?;
    let name = ServerName::try_from(server_name.to_owned())?;
    Ok(TlsConnector::from(config).connect(name, tcp).await?)
}

async fn spawn_h1_trailer_fixture() -> (
    std::net::SocketAddr,
    mpsc::UnboundedReceiver<Option<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("HTTP/1 trailer fixture binds");
    let address = listener.local_addr().expect("fixture address is known");
    let (observations, received_observations) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("gateway connects to fixture");
        let service = service_fn(move |request: Request<hyper::body::Incoming>| {
            let observations = observations.clone();
            async move {
                let observation = match request.into_body().collect().await {
                    Ok(collected) => {
                        let mut names = collected
                            .trailers()
                            .into_iter()
                            .flat_map(HeaderMap::keys)
                            .map(|name| name.as_str().to_owned())
                            .collect::<Vec<_>>();
                        names.sort_unstable();
                        Some(names)
                    }
                    Err(_) => None,
                };
                let _ = observations.send(observation);
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    (address, received_observations, task)
}

async fn send_h2_request_with_trailer(
    gateway: std::net::SocketAddr,
    identity: &TestIdentity,
    declared: bool,
) -> StatusCode {
    let stream = connect_tls(
        gateway,
        "gateway.example.test",
        client_config(identity, &[b"h2"], true),
    )
    .await
    .expect("HTTP/2 TLS connection succeeds");
    let (mut sender, connection) = http2::handshake::<_, _, BoxBody<Bytes, Infallible>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .expect("HTTP/2 client handshake succeeds");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "x-checksum",
        "complete".parse().expect("fixture value is valid"),
    );
    let body = StreamBody::new(futures_stream::iter(vec![
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"payload"))),
        Ok(Frame::trailers(trailers)),
    ]))
    .boxed();
    let mut request = Request::new(body);
    *request.method_mut() = http::Method::POST;
    *request.uri_mut() = "https://gateway.example.test/upload"
        .parse()
        .expect("fixture URI is valid");
    if declared {
        request.headers_mut().insert(
            header::TRAILER,
            "x-checksum".parse().expect("declaration is valid"),
        );
    }
    let status = sender
        .send_request(request)
        .await
        .expect("gateway returns a response head")
        .status();
    drop(sender);
    connection_task.abort();
    status
}

impl RawH2 {
    async fn connect(
        address: std::net::SocketAddr,
        server_name: &str,
        config: Arc<ClientConfig>,
    ) -> Self {
        let stream = connect_tls(address, server_name, config)
            .await
            .expect("TLS handshake succeeds");
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let mut client = Self { stream };
        client
            .stream
            .write_all(CLIENT_PREFACE)
            .await
            .expect("HTTP/2 client preface can be written");
        client
            .write_frame(FRAME_SETTINGS, 0, 0, &[])
            .await
            .expect("initial SETTINGS can be written");
        loop {
            let frame = client.read_frame().await.expect("server frame is readable");
            if frame.kind == FRAME_SETTINGS && frame.flags & FLAG_ACK == 0 {
                client
                    .write_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[])
                    .await
                    .expect("server SETTINGS can be acknowledged");
                break;
            }
        }
        client
    }

    async fn write_frame(
        &mut self,
        kind: u8,
        flags: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        assert!(payload.len() <= 0x00ff_ffff);
        let length = payload.len() as u32;
        let mut header = [0_u8; 9];
        header[0] = (length >> 16) as u8;
        header[1] = (length >> 8) as u8;
        header[2] = length as u8;
        header[3] = kind;
        header[4] = flags;
        header[5..9].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        self.stream.write_all(&header).await?;
        self.stream.write_all(payload).await
    }

    async fn read_frame(&mut self) -> io::Result<H2Frame> {
        let mut header = [0_u8; 9];
        self.stream.read_exact(&mut header).await?;
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        let mut payload = vec![0; length];
        self.stream.read_exact(&mut payload).await?;
        Ok(H2Frame {
            kind: header[3],
            flags: header[4],
            stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]])
                & 0x7fff_ffff,
            payload,
        })
    }

    async fn rejection(&mut self, stream_id: u32) -> (u8, u32, u32) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = self
                    .read_frame()
                    .await
                    .expect("rejection frame is readable");
                let error_code = match frame.kind {
                    FRAME_RST_STREAM
                        if frame.stream_id == stream_id && frame.payload.len() == 4 =>
                    {
                        u32::from_be_bytes(
                            frame
                                .payload
                                .as_slice()
                                .try_into()
                                .expect("RST_STREAM has a four-byte error code"),
                        )
                    }
                    FRAME_GOAWAY if frame.payload.len() >= 8 => u32::from_be_bytes(
                        frame.payload[4..8]
                            .try_into()
                            .expect("GOAWAY contains a four-byte error code"),
                    ),
                    _ => continue,
                };
                // A response that raced with client cancellation may complete
                // with NO_ERROR before Hyper observes the invalid follow-up
                // frame. Keep reading until the peer reports the actual
                // protocol rejection.
                if error_code != 0 {
                    break (frame.kind, frame.stream_id, error_code);
                }
            }
        })
        .await
        .expect("invalid HTTP/2 input is rejected promptly")
    }

    async fn expect_protocol_rejection(&mut self, stream_id: u32) {
        let (_, _, error_code) = self.rejection(stream_id).await;
        assert_ne!(error_code, 0, "invalid input must carry a protocol error");
    }

    async fn stream_rejection_code(&mut self, stream_id: u32) -> u32 {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = self
                    .read_frame()
                    .await
                    .expect("stream rejection frame is readable");
                if frame.kind == FRAME_RST_STREAM
                    && frame.stream_id == stream_id
                    && frame.payload.len() == 4
                {
                    let code = u32::from_be_bytes(
                        frame
                            .payload
                            .as_slice()
                            .try_into()
                            .expect("RST_STREAM has a four-byte error code"),
                    );
                    if code != 0 {
                        break code;
                    }
                }
            }
        })
        .await
        .expect("invalid stream is rejected promptly")
    }

    async fn assert_valid_request(&mut self, stream_id: u32) {
        self.write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            stream_id,
            &valid_request_headers("gateway.example.test"),
        )
        .await
        .expect("valid request HEADERS can be written");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = self.read_frame().await.expect("response frame is readable");
                assert!(
                    !(frame.kind == FRAME_RST_STREAM && frame.stream_id == stream_id)
                        && frame.kind != FRAME_GOAWAY,
                    "valid request was rejected: {frame:?}"
                );
                if frame.kind == FRAME_HEADERS && frame.stream_id == stream_id {
                    break;
                }
            }
        })
        .await
        .expect("valid response head arrives");
    }
}

fn encode_integer(output: &mut Vec<u8>, prefix_bits: u8, prefix: u8, mut value: usize) {
    let mask = (1_u8 << prefix_bits) - 1;
    if value < usize::from(mask) {
        output.push(prefix | value as u8);
        return;
    }
    output.push(prefix | mask);
    value -= usize::from(mask);
    while value >= 128 {
        output.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn encode_string(output: &mut Vec<u8>, value: &[u8]) {
    encode_integer(output, 7, 0, value.len());
    output.extend_from_slice(value);
}

fn literal_header(output: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    output.push(0);
    encode_string(output, name);
    encode_string(output, value);
}

fn authority(output: &mut Vec<u8>, value: &str) {
    encode_integer(output, 4, 0, 1);
    encode_string(output, value.as_bytes());
}

fn valid_request_headers(host: &str) -> Vec<u8> {
    let mut block = vec![0x82, 0x87, 0x84]; // :method GET, :scheme https, :path /
    authority(&mut block, host);
    block
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
    stream
        .read_to_end(&mut response)
        .await
        .expect("metrics response is readable");
    String::from_utf8(response).expect("metrics response is UTF-8")
}

fn metric_counter(rendered: &str, name: &str) -> Option<u64> {
    rendered.lines().find_map(|line| {
        line.strip_prefix(name)?
            .strip_prefix(' ')?
            .parse::<u64>()
            .ok()
    })
}

async fn wait_request_total(address: std::net::SocketAddr, expected: u64) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let rendered = admin_metrics(address).await;
            if metric_counter(&rendered, "oxidase_requests_total") == Some(expected) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("expected request count becomes visible");
}

#[tokio::test]
async fn rejects_invalid_pseudo_header_order_and_duplicates_without_poisoning_listener() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;
    let config = client_config(&identity, &[b"h2"], true);

    let mut regular_before_pseudo = Vec::new();
    literal_header(&mut regular_before_pseudo, b"x-before", b"1");
    regular_before_pseudo.extend_from_slice(&[0x82, 0x87, 0x84]);
    authority(&mut regular_before_pseudo, "gateway.example.test");

    let mut duplicate_method = vec![0x82, 0x82, 0x87, 0x84];
    authority(&mut duplicate_method, "gateway.example.test");

    for block in [regular_before_pseudo, duplicate_method] {
        let mut client =
            RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
        client
            .write_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block)
            .await
            .expect("malformed HEADERS can be written");
        client.expect_protocol_rejection(1).await;
    }

    let mut healthy =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    healthy.assert_valid_request(1).await;
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn http2_authority_canonicalizes_a_conflicting_host_before_service_execution() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway_with_body(
        &identity,
        16,
        64 * 1024,
        "{{ request.authority }}|{{ request.headers.host.first }}",
    )
    .await;
    let tls = connect_tls(
        gateway.address,
        "gateway.example.test",
        client_config(&identity, &[b"h2"], true),
    )
    .await
    .expect("TLS handshake succeeds");
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .uri("https://gateway.example.test/")
        .header(header::HOST, "conflicting.example.test")
        .body(Empty::<Bytes>::new())
        .expect("HTTP/2 authority fixture is valid");
    let response = sender
        .send_request(request)
        .await
        .expect("HTTP/2 response head arrives");
    assert_eq!(
        response
            .into_body()
            .collect()
            .await
            .expect("HTTP/2 response body completes")
            .to_bytes(),
        "gateway.example.test|gateway.example.test"
    );

    let mut duplicate_host = Request::builder()
        .uri("https://gateway.example.test/")
        .body(Empty::<Bytes>::new())
        .expect("HTTP/2 duplicate Host fixture is valid");
    duplicate_host
        .headers_mut()
        .append(header::HOST, "first.example.test".parse().expect("Host"));
    duplicate_host
        .headers_mut()
        .append(header::HOST, "second.example.test".parse().expect("Host"));
    let response = sender
        .send_request(duplicate_host)
        .await
        .expect("HTTP/2 duplicate Host rejection arrives");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    driver.abort();
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn rejects_connection_specific_headers_illegal_te_and_oversized_header_lists() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 256).await;
    let config = client_config(&identity, &[b"h2"], true);

    for (name, value) in [
        (b"connection".as_slice(), b"keep-alive".as_slice()),
        (b"te".as_slice(), b"gzip".as_slice()),
        (b"te".as_slice(), b"trailers, deflate".as_slice()),
    ] {
        let mut block = valid_request_headers("gateway.example.test");
        literal_header(&mut block, name, value);
        let mut client =
            RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
        client
            .write_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block)
            .await
            .expect("invalid HEADERS can be written");
        client.expect_protocol_rejection(1).await;
    }

    let mut oversized = valid_request_headers("gateway.example.test");
    literal_header(&mut oversized, b"x-expanded", &vec![b'a'; 1024]);
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &oversized,
        )
        .await
        .expect("oversized HEADERS can be written");
    client.expect_protocol_rejection(1).await;

    let mut healthy =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    healthy.assert_valid_request(1).await;
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn enforces_concurrent_stream_boundary_and_rejects_data_after_end_stream() {
    let identity = identity(&["gateway.example.test"]);
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("blocking upstream binds");
    let upstream_address = upstream.local_addr().expect("upstream address is known");
    let upstream_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = upstream.accept().await {
            held.push(stream);
        }
    });
    let gateway = start_blocking_proxy_gateway(&identity, upstream_address, 2).await;
    let config = client_config(&identity, &[b"h2"], true);
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    let headers = valid_request_headers("gateway.example.test");
    for stream_id in [1, 3] {
        client
            .write_frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                stream_id,
                &headers,
            )
            .await
            .expect("open request stream can be written");
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admin_metrics(gateway.admin)
                .await
                .contains("oxidase_active_requests 2")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("two blocking streams enter Service execution");
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            5,
            &headers,
        )
        .await
        .expect("excess request stream reaches the peer");
    let error_code = client.stream_rejection_code(5).await;
    assert_eq!(
        error_code, 7,
        "the excess stream receives REFUSED_STREAM instead of entering Service execution"
    );
    assert!(
        admin_metrics(gateway.admin)
            .await
            .contains("oxidase_active_requests 2"),
        "the third stream must not enter the Service graph"
    );

    for stream_id in [1, 3] {
        client
            .write_frame(FRAME_RST_STREAM, 0, stream_id, &8_u32.to_be_bytes())
            .await
            .expect("blocking request can be cancelled");
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admin_metrics(gateway.admin)
                .await
                .contains("oxidase_active_requests 0")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled streams leave Service execution");
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            7,
            &headers,
        )
        .await
        .expect("the same H2 connection accepts a later stream");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if admin_metrics(gateway.admin)
                .await
                .contains("oxidase_active_requests 1")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("later stream reaches Service execution on the same connection");
    client
        .write_frame(FRAME_RST_STREAM, 0, 7, &8_u32.to_be_bytes())
        .await
        .expect("later stream can be cancelled");
    drop(client);

    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &headers,
        )
        .await
        .expect("closed request HEADERS can be written");
    client
        .write_frame(FRAME_DATA, 0, 1, b"illegal")
        .await
        .expect("post-end-stream DATA reaches the peer");
    client.expect_protocol_rejection(1).await;

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream_task.abort();
}

#[tokio::test]
async fn rejects_closed_stream_reuse_and_non_terminating_trailer_headers_after_queued_data() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;
    let config = client_config(&identity, &[b"h2"], true);
    let headers = valid_request_headers("gateway.example.test");

    // Mirrors h2spec http2/5.1/9. The application may already have queued a
    // response DATA frame before it observes the client reset. That DATA is a
    // legal race. The safety property we can assert independently of frame
    // ordering is that reusing the closed stream never executes a second
    // Service request.
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    client
        .write_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &headers)
        .await
        .expect("initial request HEADERS can be written");
    wait_request_total(gateway.admin, 1).await;
    client
        .write_frame(FRAME_RST_STREAM, 0, 1, &8_u32.to_be_bytes())
        .await
        .expect("client reset can be written");
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &headers,
        )
        .await
        .expect("closed-stream reuse reaches the peer");
    drop(client);

    // Mirrors h2spec http2/8.1/1. A second HEADERS block is request trailers,
    // and trailers must close the request stream with END_STREAM. As above,
    // queued response DATA does not turn the trailer block into another request.
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    client
        .write_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &headers)
        .await
        .expect("request HEADERS can be written");
    wait_request_total(gateway.admin, 2).await;
    let mut trailers = Vec::new();
    literal_header(&mut trailers, b"x-trailer", b"value");
    client
        .write_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &trailers)
        .await
        .expect("non-terminating trailers reach the peer");
    drop(client);

    // Mirrors h2spec http2/8.1.2.1/3. Pseudo-header fields are forbidden in
    // trailers. Hyper may have already queued the first response, but the
    // invalid trailer block must not become another Service request.
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    client
        .write_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &headers)
        .await
        .expect("request HEADERS can be written");
    wait_request_total(gateway.admin, 3).await;
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            &[0x84], // indexed static-table `:path: /`
        )
        .await
        .expect("invalid pseudo-header trailer reaches the peer");
    drop(client);

    let mut healthy =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    healthy.assert_valid_request(1).await;
    wait_request_total(gateway.admin, 4).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        metric_counter(
            &admin_metrics(gateway.admin).await,
            "oxidase_requests_total"
        ),
        Some(4),
        "invalid follow-up HEADERS must not execute a second Service request"
    );
    drop(healthy);
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn stream_window_overflow_returns_flow_control_error() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;
    let config = client_config(&identity, &[b"h2"], true);
    let mut client = RawH2::connect(gateway.address, "gateway.example.test", config).await;
    client
        .write_frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            &valid_request_headers("gateway.example.test"),
        )
        .await
        .expect("request HEADERS can be written");
    client
        .write_frame(FRAME_WINDOW_UPDATE, 0, 1, &0x7fff_ffff_u32.to_be_bytes())
        .await
        .expect("first maximum WINDOW_UPDATE reaches the peer");
    client
        .write_frame(FRAME_WINDOW_UPDATE, 0, 1, &0x7fff_ffff_u32.to_be_bytes())
        .await
        .expect("second overflowing WINDOW_UPDATE reaches the peer");
    assert_eq!(
        client.stream_rejection_code(1).await,
        3,
        "stream flow-control overflow must return FLOW_CONTROL_ERROR"
    );
    drop(client);
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn http2_to_http1_request_trailers_are_forwarded_or_fail_explicitly() {
    let identity = identity(&["gateway.example.test"]);

    for declared in [false, true] {
        let (upstream, mut observations, upstream_task) = spawn_h1_trailer_fixture().await;
        let gateway = start_blocking_proxy_gateway(&identity, upstream, 16).await;
        let status = send_h2_request_with_trailer(gateway.address, &identity, declared).await;
        let observed = tokio::time::timeout(Duration::from_secs(2), observations.recv())
            .await
            .ok()
            .flatten();
        if declared {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(observed, Some(Some(vec!["x-checksum".to_owned()])));
        } else {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(
                !matches!(observed, Some(Some(names)) if names.iter().any(|name| name == "x-checksum")),
                "an undeclared H2 trailer must not reach the H1 upstream"
            );
        }
        gateway
            .running
            .shutdown()
            .await
            .expect("gateway shuts down");
        upstream_task.abort();
    }
}

#[tokio::test]
async fn reset_storm_releases_stream_tasks_and_keeps_the_listener_healthy() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 64, 64 * 1024).await;
    let config = client_config(&identity, &[b"h2"], true);
    let mut client =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    let headers = valid_request_headers("gateway.example.test");
    for stream_id in (1..=255).step_by(2) {
        client
            .write_frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, &headers)
            .await
            .expect("storm HEADERS can be written");
        client
            .write_frame(FRAME_RST_STREAM, 0, stream_id, &8_u32.to_be_bytes())
            .await
            .expect("storm RST_STREAM can be written");
    }
    drop(client);

    let mut healthy =
        RawH2::connect(gateway.address, "gateway.example.test", Arc::clone(&config)).await;
    healthy.assert_valid_request(1).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let metrics = admin_metrics(gateway.admin).await;
            if metrics.contains("oxidase_http2_active_streams{listener=\"secure\"} 0") {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reset stream guards are released");
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn default_certificate_supports_no_sni_and_h2_only_rejects_alpn_mismatch() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;

    let no_sni = client_config(&identity, &[b"h2"], false);
    let mut client = RawH2::connect(gateway.address, "gateway.example.test", no_sni).await;
    client.assert_valid_request(1).await;

    let mismatch = connect_tls(
        gateway.address,
        "gateway.example.test",
        client_config(&identity, &[b"http/1.1"], true),
    )
    .await
    .expect_err("an H2-only listener rejects a client without matching ALPN");
    assert!(
        mismatch.to_string().contains("application protocol")
            || mismatch.to_string().contains("alert"),
        "unexpected ALPN error: {mismatch}"
    );
    let metrics = admin_metrics(gateway.admin).await;
    assert!(
        metrics.contains(
            "oxidase_tls_handshakes_total{listener=\"secure\",result=\"alpn_mismatch\"} 1"
        ),
        "{metrics}"
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

async fn capture_client_hello(config: Arc<ClientConfig>, server_name: &str) -> Vec<u8> {
    let (client_io, mut capture) = tokio::io::duplex(32 * 1024);
    let name = ServerName::try_from(server_name.to_owned()).expect("test DNS name is valid");
    let task = tokio::spawn(async move {
        let _ = TlsConnector::from(config).connect(name, client_io).await;
    });
    let mut record_header = [0_u8; 5];
    capture
        .read_exact(&mut record_header)
        .await
        .expect("ClientHello record header is emitted");
    let length = usize::from(u16::from_be_bytes([record_header[3], record_header[4]]));
    let mut record = record_header.to_vec();
    record.resize(5 + length, 0);
    capture
        .read_exact(&mut record[5..])
        .await
        .expect("ClientHello record payload is emitted");
    task.abort();
    let _ = task.await;
    record
}

#[tokio::test]
async fn malformed_sni_is_rejected_during_tls_handshake() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;
    let mut hello = capture_client_hello(
        client_config(&identity, &[b"h2"], true),
        "gateway.example.test",
    )
    .await;
    let name = b"gateway.example.test";
    let offset = hello
        .windows(name.len())
        .position(|window| window == name)
        .expect("captured ClientHello contains its SNI name");
    hello[offset] = 0xff;

    let mut stream = TcpStream::connect(gateway.address)
        .await
        .expect("malformed TLS client connects");
    stream
        .write_all(&hello)
        .await
        .expect("mutated ClientHello can be written");
    let mut alert_header = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut alert_header))
        .await
        .expect("invalid SNI is rejected promptly")
        .expect("TLS alert is readable");
    assert_eq!(alert_header[0], 21, "server must emit a TLS alert record");

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_rotation_is_atomic_while_handshakes_are_in_flight() {
    let first = identity(&["gateway.example.test"]);
    let second = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&first, 16, 64 * 1024).await;
    let mut roots = RootCertStore::empty();
    roots
        .add(first.certificate_der.clone())
        .expect("first test certificate can be trusted");
    roots
        .add(second.certificate_der.clone())
        .expect("second test certificate can be trusted");
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let config = Arc::new(config);
    let barrier = Arc::new(tokio::sync::Barrier::new(33));
    let mut handshakes = Vec::new();
    for _ in 0..32 {
        let barrier = Arc::clone(&barrier);
        let config = Arc::clone(&config);
        let address = gateway.address;
        handshakes.push(tokio::spawn(async move {
            barrier.wait().await;
            let stream = connect_tls(address, "gateway.example.test", config)
                .await
                .expect("handshake racing rotation succeeds");
            stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certificates| certificates.first())
                .expect("server presents a leaf")
                .as_ref()
                .to_vec()
        }));
    }
    barrier.wait().await;
    fs::write(&gateway.certificate, &second.certificate_pem)
        .expect("rotated certificate can be written");
    fs::write(&gateway.private_key, &second.private_key_pem)
        .expect("rotated private key can be written");
    gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("certificate rotation commits");

    for handshake in handshakes {
        let leaf = handshake.await.expect("handshake task joins");
        assert!(
            leaf == first.certificate_der.as_ref() || leaf == second.certificate_der.as_ref(),
            "a handshake must observe one complete certificate plan"
        );
    }

    let tls = connect_tls(gateway.address, "gateway.example.test", Arc::clone(&config))
        .await
        .expect("post-rotation handshake succeeds");
    assert_eq!(
        tls.get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first()),
        Some(&second.certificate_der)
    );
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}

#[tokio::test]
async fn hyper_client_still_accepts_a_valid_h2_exchange_after_raw_adversarial_cases() {
    let identity = identity(&["gateway.example.test"]);
    let gateway = start_gateway(&identity, 16, 64 * 1024).await;
    let tls = connect_tls(
        gateway.address,
        "gateway.example.test",
        client_config(&identity, &[b"h2"], true),
    )
    .await
    .expect("TLS handshake succeeds");
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .expect("HTTP/2 client handshake succeeds");
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://gateway.example.test/")
                .body(Empty::<Bytes>::new())
                .expect("valid H2 request builds"),
        )
        .await
        .expect("valid H2 response head arrives");
    let body = response
        .into_body()
        .collect()
        .await
        .expect("valid H2 response body is readable")
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"secure"));
    drop(sender);
    driver.abort();
    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
}
