//! Black-box upstream TLS policy, mTLS, pool-identity, and health-check tests.
//!
//! All certificates and private keys are generated for one test process and
//! are never suitable for production use.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_config::Compiler;
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;

struct TestAuthority {
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

struct TestIdentity {
    certificate_pem: String,
    certificate_der: CertificateDer<'static>,
    private_key_pem: String,
}

#[derive(Clone, Debug)]
struct UpstreamObservation {
    path: String,
    verified_client: bool,
}

struct TlsUpstream {
    address: std::net::SocketAddr,
    accepts: Arc<AtomicU64>,
    observations: Arc<Mutex<Vec<UpstreamObservation>>>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

struct TestGateway {
    _directory: TempDir,
    config: PathBuf,
    address: std::net::SocketAddr,
    running: RunningServer,
}

fn authority(name: &str) -> TestAuthority {
    let mut params = CertificateParams::new(Vec::new()).expect("empty test CA SAN list is valid");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let key = KeyPair::generate().expect("test-only CA key can be generated");
    let certificate = params
        .self_signed(&key)
        .expect("test-only CA certificate can be generated");
    TestAuthority {
        certificate_pem: certificate.pem(),
        certificate_der: certificate.der().clone(),
        issuer: Issuer::new(params, key),
    }
}

fn signed_identity(
    authority: &TestAuthority,
    common_name: &str,
    dns_name: &str,
    usage: ExtendedKeyUsagePurpose,
) -> TestIdentity {
    let mut params = CertificateParams::new(vec![dns_name.to_owned()])
        .expect("test-only certificate DNS name is valid");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().expect("test-only leaf key can be generated");
    let certificate = params
        .signed_by(&key, &authority.issuer)
        .expect("test-only leaf certificate can be signed");
    TestIdentity {
        certificate_pem: certificate.pem(),
        certificate_der: certificate.der().clone(),
        private_key_pem: key.serialize_pem(),
    }
}

fn upstream_server_config(
    server: &TestIdentity,
    client_authority: Option<&TestAuthority>,
) -> Arc<ServerConfig> {
    let provider = Arc::new(default_provider());
    let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available");
    let builder = if let Some(authority) = client_authority {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots
            .add(authority.certificate_der.clone())
            .expect("test client CA can be trusted");
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .expect("test client verifier can be built");
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    Arc::new(
        builder
            .with_single_cert(
                vec![server.certificate_der.clone()],
                PrivateKeyDer::from_pem_slice(server.private_key_pem.as_bytes())
                    .expect("test server key parses"),
            )
            .expect("test upstream server identity is usable"),
    )
}

impl TlsUpstream {
    async fn spawn(server: &TestIdentity, client_authority: Option<&TestAuthority>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS upstream binds to loopback");
        let address = listener.local_addr().expect("fixture address is available");
        let acceptor = TlsAcceptor::from(upstream_server_config(server, client_authority));
        let accepts = Arc::new(AtomicU64::new(0));
        let observations = Arc::new(Mutex::new(Vec::new()));
        let task_accepts = Arc::clone(&accepts);
        let task_observations = Arc::clone(&observations);
        let (shutdown, mut shutdown_receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_receiver.changed() => {
                        if changed.is_err() || *shutdown_receiver.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        task_accepts.fetch_add(1, Ordering::Relaxed);
                        let acceptor = acceptor.clone();
                        let observations = Arc::clone(&task_observations);
                        connections.spawn(async move {
                            let Ok(tls) = acceptor.accept(stream).await else {
                                return;
                            };
                            let verified_client = tls
                                .get_ref()
                                .1
                                .peer_certificates()
                                .is_some_and(|certificates| !certificates.is_empty());
                            let service = service_fn(move |request: Request<Incoming>| {
                                let observations = Arc::clone(&observations);
                                let path = request
                                    .uri()
                                    .path_and_query()
                                    .map_or("/", |path| path.as_str())
                                    .to_owned();
                                async move {
                                    observations
                                        .lock()
                                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                                        .push(UpstreamObservation {
                                            path: path.clone(),
                                            verified_client,
                                        });
                                    let body = if path.starts_with("/healthz") {
                                        "healthy"
                                    } else {
                                        "upstream-ok"
                                    };
                                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                        Bytes::from_static(body.as_bytes()),
                                    )))
                                }
                            });
                            let _ = http1::Builder::new()
                                .serve_connection(TokioIo::new(tls), service)
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        Self {
            address,
            accepts,
            observations,
            shutdown,
            task,
        }
    }

    fn accept_count(&self) -> u64 {
        self.accepts.load(Ordering::Relaxed)
    }

    fn observations(&self) -> Vec<UpstreamObservation> {
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    async fn wait_for_path(&self, expected: &str) -> UpstreamObservation {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(observation) = self
                    .observations()
                    .into_iter()
                    .find(|observation| observation.path == expected)
                {
                    return observation;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("upstream observes the expected path")
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(true);
        self.task.await.expect("TLS upstream task exits");
    }
}

fn gateway_source(
    upstream_address: std::net::SocketAddr,
    server_name: &str,
    with_client_certificate: bool,
    with_health: bool,
) -> String {
    let client_certificate = if with_client_certificate {
        "        client_certificate: upstream-client\n"
    } else {
        ""
    };
    let health = if with_health {
        r#"      health:
        active:
          path: /healthz
          interval: 50ms
          timeout: 1s
          healthy_statuses: ["200-299"]
          healthy_threshold: 1
          unhealthy_threshold: 1
"#
    } else {
        ""
    };
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  trust_stores:
    upstream-ca:
      ca_bundle: upstream-ca.pem
  certificates:
    upstream-client:
      cert_chain: upstream-client.pem
      private_key: upstream-client-key.pem
  clusters:
    upstream:
      protocol: http1
      endpoints:
        - https://{upstream_address}
{health}      tls:
        server_name: {server_name}
        trust:
          system_roots: false
          trust_store: upstream-ca
{client_certificate}services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#
    )
}

fn write_gateway(
    path: &Path,
    upstream_address: std::net::SocketAddr,
    server_name: &str,
    with_client_certificate: bool,
    with_health: bool,
) {
    fs::write(
        path,
        gateway_source(
            upstream_address,
            server_name,
            with_client_certificate,
            with_health,
        ),
    )
    .expect("gateway source can be written");
}

async fn start_gateway(
    upstream: &TlsUpstream,
    server_authority: &TestAuthority,
    client: &TestIdentity,
    server_name: &str,
    with_client_certificate: bool,
    with_health: bool,
) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    fs::write(
        directory.path().join("upstream-ca.pem"),
        &server_authority.certificate_pem,
    )
    .expect("upstream CA bundle can be written");
    fs::write(
        directory.path().join("upstream-client.pem"),
        &client.certificate_pem,
    )
    .expect("upstream client certificate can be written");
    fs::write(
        directory.path().join("upstream-client-key.pem"),
        &client.private_key_pem,
    )
    .expect("upstream client key can be written");
    let config = directory.path().join("oxidase.yaml");
    write_gateway(
        &config,
        upstream.address,
        server_name,
        with_client_certificate,
        with_health,
    );
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("upstream TLS gateway source compiles"),
    )
    .expect("upstream TLS gateway prepares");
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("gateway binds to loopback");
    let running = server.spawn();
    let address = running.local_addresses()[0].1;
    TestGateway {
        _directory: directory,
        config,
        address,
        running,
    }
}

async fn gateway_request(address: std::net::SocketAddr) -> (u16, String) {
    let mut stream = TcpStream::connect(address)
        .await
        .expect("downstream connects to gateway");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n")
        .await
        .expect("downstream request can be written");
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .expect("gateway response completes")
        .expect("gateway response is readable");
    let response = String::from_utf8(bytes).expect("gateway response is UTF-8");
    let (head, body) = response
        .split_once("\r\n\r\n")
        .expect("HTTP response has a head and body");
    let status = head
        .split_whitespace()
        .nth(1)
        .expect("HTTP response has a status")
        .parse::<u16>()
        .expect("HTTP status is numeric");
    (status, decode_chunked_body(body))
}

fn decode_chunked_body(body: &str) -> String {
    if let Some((size, rest)) = body.split_once("\r\n")
        && let Ok(size) = usize::from_str_radix(size.trim(), 16)
        && rest.len() >= size
    {
        return rest[..size].to_owned();
    }
    body.to_owned()
}

#[tokio::test]
async fn custom_ca_and_fixed_server_name_succeed_and_policy_reload_does_not_reuse_pool() {
    let server_ca = authority("upstream server CA");
    let server_identity = signed_identity(
        &server_ca,
        "upstream.internal.test",
        "upstream.internal.test",
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let unused_client_ca = authority("unused client CA");
    let unused_client = signed_identity(
        &unused_client_ca,
        "unused client",
        "unused-client.example.test",
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let upstream = TlsUpstream::spawn(&server_identity, None).await;
    let gateway = start_gateway(
        &upstream,
        &server_ca,
        &unused_client,
        "upstream.internal.test",
        false,
        false,
    )
    .await;

    let (status, body) = gateway_request(gateway.address).await;
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "upstream-ok");
    let accepts_after_first = upstream.accept_count();
    let (status, body) = gateway_request(gateway.address).await;
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "upstream-ok");
    assert_eq!(
        upstream.accept_count(),
        accepts_after_first,
        "unchanged policy reuses its long-lived upstream pool"
    );

    write_gateway(
        &gateway.config,
        upstream.address,
        "wrong.internal.test",
        false,
        false,
    );
    gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("wrong-name policy is structurally valid and commits");
    let (status, _) = gateway_request(gateway.address).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY.as_u16());
    assert!(
        upstream.accept_count() > accepts_after_first,
        "changed verification identity creates a new transport pool"
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}

#[tokio::test]
async fn required_upstream_client_certificate_is_used_by_proxy_and_active_health() {
    let server_ca = authority("upstream server CA");
    let client_ca = authority("upstream client CA");
    let server_identity = signed_identity(
        &server_ca,
        "upstream.internal.test",
        "upstream.internal.test",
        ExtendedKeyUsagePurpose::ServerAuth,
    );
    let client_identity = signed_identity(
        &client_ca,
        "gateway upstream client",
        "gateway-client.example.test",
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let upstream = TlsUpstream::spawn(&server_identity, Some(&client_ca)).await;
    let gateway = start_gateway(
        &upstream,
        &server_ca,
        &client_identity,
        "upstream.internal.test",
        true,
        true,
    )
    .await;

    let health = upstream.wait_for_path("/healthz").await;
    assert!(health.verified_client, "health check uses upstream mTLS");
    let (status, body) = gateway_request(gateway.address).await;
    assert_eq!(status, StatusCode::OK.as_u16());
    assert_eq!(body, "upstream-ok");
    let proxy = upstream.wait_for_path("/").await;
    assert!(proxy.verified_client, "Proxy uses upstream mTLS");
    let accepts_with_identity = upstream.accept_count();

    write_gateway(
        &gateway.config,
        upstream.address,
        "upstream.internal.test",
        false,
        false,
    );
    gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("removing the upstream client identity commits");
    let (status, _) = gateway_request(gateway.address).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY.as_u16());
    assert!(
        upstream.accept_count() > accepts_with_identity,
        "removing the client identity cannot reuse an authenticated connection"
    );

    gateway
        .running
        .shutdown()
        .await
        .expect("gateway shuts down");
    upstream.shutdown().await;
}
