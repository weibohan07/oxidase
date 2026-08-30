//! Black-box inbound mTLS and verified client-identity tests.
//!
//! Every private key in this module is generated for one test process. The
//! material is intentionally ephemeral and must never be used in production.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use oxidase_config::Compiler;
use oxidase_core::{ConfigVersion, ContentDigest};
use oxidase_runtime::RuntimeSnapshot;
use oxidase_server::{GatewayServer, RunningServer};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType, date_time_ymd, generate_simple_self_signed,
};
use tempfile::{TempDir, tempdir};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

struct TestIdentity {
    certificate_pem: String,
    private_key_pem: String,
    certificate_der: CertificateDer<'static>,
}

struct TestAuthority {
    certificate_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct TestGateway {
    _directory: TempDir,
    config: PathBuf,
    trust_bundle: PathBuf,
    address: std::net::SocketAddr,
    running: RunningServer,
}

fn server_identity() -> TestIdentity {
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["gateway.example.test".to_owned()])
            .expect("test-only server identity can be generated");
    TestIdentity {
        certificate_pem: cert.pem(),
        private_key_pem: signing_key.serialize_pem(),
        certificate_der: cert.der().clone(),
    }
}

fn client_authority(name: &str) -> TestAuthority {
    let mut params =
        CertificateParams::new(Vec::new()).expect("empty CA SAN list is valid for a test CA");
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
        issuer: Issuer::new(params, key),
    }
}

fn client_identity(authority: &TestAuthority, common_name: &str) -> TestIdentity {
    let dns_name = "client.example.test";
    let mut params =
        CertificateParams::new(vec![dns_name.to_owned()]).expect("test client DNS SAN is valid");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.subject_alt_names.push(SanType::URI(
        "spiffe://example.test/workload"
            .try_into()
            .expect("test URI SAN is valid IA5 text"),
    ));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().expect("test-only client key can be generated");
    let certificate = params
        .signed_by(&key, &authority.issuer)
        .expect("test-only client certificate can be signed");
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        certificate_der: certificate.der().clone(),
    }
}

fn expired_client_identity(authority: &TestAuthority) -> TestIdentity {
    let mut params = CertificateParams::new(vec!["expired-client.example.test".to_owned()])
        .expect("expired test client DNS SAN is valid");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "expired-client");
    params.not_before = date_time_ymd(2019, 1, 1);
    params.not_after = date_time_ymd(2020, 1, 1);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().expect("test-only expired client key can be generated");
    let certificate = params
        .signed_by(&key, &authority.issuer)
        .expect("test-only expired client certificate can be signed");
    TestIdentity {
        certificate_pem: certificate.pem(),
        private_key_pem: key.serialize_pem(),
        certificate_der: certificate.der().clone(),
    }
}

fn write_identity(directory: &Path, name: &str, identity: &TestIdentity) {
    fs::write(
        directory.join(format!("{name}.pem")),
        &identity.certificate_pem,
    )
    .expect("test certificate can be written");
    fs::write(
        directory.join(format!("{name}-key.pem")),
        &identity.private_key_pem,
    )
    .expect("test private key can be written");
}

fn gateway_source(mode: &str) -> String {
    let trust_store = if mode == "none" {
        String::new()
    } else {
        "        trust_store: clients\n".to_owned()
    };
    format!(
        r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  trust_stores:
    clients:
      ca_bundle: clients-ca.pem
  certificates:
    gateway:
      cert_chain: gateway.pem
      private_key: gateway-key.pem
services:
  identity:
    type: respond
    body:
      text: '{{{{ request.tls.client.verified }}}}|{{{{ request.tls.client.sha256 }}}}|{{{{ request.tls.client.subject }}}}|{{{{ join(request.tls.client.dns_sans, ",") }}}}|{{{{ join(request.tls.client.uri_sans, ",") }}}}'
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: gateway
      client_auth:
        mode: {mode}
{trust_store}    http:
      versions: [h2, http1]
    service:
      ref: identity
"#
    )
}

async fn start_gateway(
    server: &TestIdentity,
    authority: &TestAuthority,
    mode: &str,
) -> TestGateway {
    let directory = tempdir().expect("temporary gateway directory is available");
    write_identity(directory.path(), "gateway", server);
    let trust_bundle = directory.path().join("clients-ca.pem");
    fs::write(&trust_bundle, &authority.certificate_pem).expect("test client CA can be written");
    let config = directory.path().join("oxidase.yaml");
    fs::write(&config, gateway_source(mode)).expect("gateway source can be written");
    let snapshot = RuntimeSnapshot::prepare(
        Compiler::compile_path(&config).expect("mTLS gateway source compiles"),
    )
    .expect("mTLS gateway prepares");
    let version = snapshot.config_version.clone();
    let server = GatewayServer::bind(snapshot)
        .await
        .expect("mTLS gateway binds");
    let running = server.spawn();
    let address = running.local_addresses()[0].1;
    assert_eq!(
        running.reload_handle().current_snapshot().config_version,
        version
    );
    TestGateway {
        _directory: directory,
        config,
        trust_bundle,
        address,
        running,
    }
}

fn client_config(
    server: &TestIdentity,
    client: Option<&TestIdentity>,
    alpn: &'static [u8],
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(server.certificate_der.clone())
        .expect("test server certificate can be trusted");
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .expect("safe TLS protocol versions are available")
        .with_root_certificates(roots);
    let mut config = match client {
        Some(identity) => builder
            .with_client_auth_cert(
                vec![identity.certificate_der.clone()],
                PrivateKeyDer::from_pem_slice(identity.private_key_pem.as_bytes())
                    .expect("test-only client private key parses"),
            )
            .expect("test-only client identity is usable"),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Arc::new(config)
}

async fn try_connect_tls(
    address: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    let tcp = TcpStream::connect(address).await?;
    let server_name =
        ServerName::try_from("gateway.example.test".to_owned()).expect("test DNS name is valid");
    TlsConnector::from(config).connect(server_name, tcp).await
}

async fn http1_client(
    address: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<http1::SendRequest<Empty<Bytes>>, String> {
    let tls = try_connect_tls(address, config)
        .await
        .map_err(|error| error.to_string())?;
    let (sender, connection) = http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

async fn http2_client(
    address: std::net::SocketAddr,
    config: Arc<ClientConfig>,
) -> Result<http2::SendRequest<Empty<Bytes>>, String> {
    let tls = try_connect_tls(address, config)
        .await
        .map_err(|error| error.to_string())?;
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

async fn send_http1(sender: &mut http1::SendRequest<Empty<Bytes>>) -> String {
    let response = sender
        .send_request(
            Request::builder()
                .uri("/")
                .header("host", "gateway.example.test")
                .body(Empty::new())
                .expect("test HTTP/1 request is valid"),
        )
        .await
        .expect("HTTP/1 response arrives");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("HTTP/1 response body is readable")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("identity response is UTF-8")
}

async fn http1_is_rejected(address: std::net::SocketAddr, config: Arc<ClientConfig>) -> bool {
    let Ok(mut sender) = http1_client(address, config).await else {
        return true;
    };
    let request = Request::builder()
        .uri("/")
        .header("host", "gateway.example.test")
        .body(Empty::new())
        .expect("test HTTP/1 request is valid");
    !matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sender.send_request(request),
        )
        .await,
        Ok(Ok(_))
    )
}

async fn send_http2(sender: &mut http2::SendRequest<Empty<Bytes>>) -> String {
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://gateway.example.test/")
                .body(Empty::new())
                .expect("test HTTP/2 request is valid"),
        )
        .await
        .expect("HTTP/2 response arrives");
    assert_eq!(response.status(), StatusCode::OK);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("HTTP/2 response body is readable")
        .to_bytes();
    String::from_utf8(body.to_vec()).expect("identity response is UTF-8")
}

fn assert_verified_identity(body: &str, client: &TestIdentity) {
    let fingerprint = format!(
        "sha256:{}",
        ContentDigest::of_bytes(client.certificate_der.as_ref())
    );
    assert!(body.starts_with("true|"), "body: {body}");
    assert!(body.contains(&fingerprint), "body: {body}");
    assert!(body.contains("CN=verified-client"), "body: {body}");
    assert!(body.contains("client.example.test"), "body: {body}");
    assert!(
        body.contains("spiffe://example.test/workload"),
        "body: {body}"
    );
}

#[tokio::test]
async fn none_optional_and_required_client_auth_have_distinct_h1_semantics() {
    let server = server_identity();
    let trusted_ca = client_authority("trusted clients");
    let wrong_ca = client_authority("wrong clients");
    let trusted = client_identity(&trusted_ca, "verified-client");
    let wrong = client_identity(&wrong_ca, "wrong-client");
    let expired = expired_client_identity(&trusted_ca);

    let none = start_gateway(&server, &trusted_ca, "none").await;
    let mut none_client = http1_client(
        none.address,
        client_config(&server, Some(&trusted), b"http/1.1"),
    )
    .await
    .expect("client-auth none accepts a configured client identity");
    assert!(send_http1(&mut none_client).await.starts_with("false|"));
    none.running.shutdown().await.expect("none gateway stops");

    let optional = start_gateway(&server, &trusted_ca, "optional").await;
    let mut anonymous = http1_client(optional.address, client_config(&server, None, b"http/1.1"))
        .await
        .expect("optional client auth accepts an anonymous client");
    assert!(send_http1(&mut anonymous).await.starts_with("false|"));
    let mut verified = http1_client(
        optional.address,
        client_config(&server, Some(&trusted), b"http/1.1"),
    )
    .await
    .expect("optional client auth accepts a trusted identity");
    assert_verified_identity(&send_http1(&mut verified).await, &trusted);
    assert!(
        http1_is_rejected(
            optional.address,
            client_config(&server, Some(&wrong), b"http/1.1")
        )
        .await,
        "optional auth must reject an invalid certificate when one is offered"
    );
    optional
        .running
        .shutdown()
        .await
        .expect("optional gateway stops");

    let required = start_gateway(&server, &trusted_ca, "required").await;
    assert!(
        http1_is_rejected(required.address, client_config(&server, None, b"http/1.1")).await,
        "required auth rejects an anonymous client"
    );
    assert!(
        http1_is_rejected(
            required.address,
            client_config(&server, Some(&wrong), b"http/1.1")
        )
        .await,
        "required auth rejects a client from the wrong CA"
    );
    assert!(
        http1_is_rejected(
            required.address,
            client_config(&server, Some(&expired), b"http/1.1")
        )
        .await,
        "required auth rejects an expired client certificate"
    );
    let mut verified = http1_client(
        required.address,
        client_config(&server, Some(&trusted), b"http/1.1"),
    )
    .await
    .expect("required auth accepts a trusted identity");
    assert_verified_identity(&send_http1(&mut verified).await, &trusted);
    required
        .running
        .shutdown()
        .await
        .expect("required gateway stops");
}

#[tokio::test]
async fn verified_client_metadata_is_available_on_h2_streams() {
    let server = server_identity();
    let authority = client_authority("H2 clients");
    let client = client_identity(&authority, "verified-client");
    let gateway = start_gateway(&server, &authority, "required").await;
    let mut sender = http2_client(
        gateway.address,
        client_config(&server, Some(&client), b"h2"),
    )
    .await
    .expect("trusted mTLS H2 connection succeeds");
    assert_verified_identity(&send_http2(&mut sender).await, &client);
    assert_verified_identity(&send_http2(&mut sender).await, &client);
    gateway.running.shutdown().await.expect("H2 gateway stops");
}

#[tokio::test]
async fn trust_rotation_keeps_existing_connection_and_changes_new_handshakes() {
    let server = server_identity();
    let first_ca = client_authority("first clients");
    let first_client = client_identity(&first_ca, "verified-client");
    let second_ca = client_authority("second clients");
    let second_client = client_identity(&second_ca, "verified-client");
    let gateway = start_gateway(&server, &first_ca, "required").await;
    let mut existing = http1_client(
        gateway.address,
        client_config(&server, Some(&first_client), b"http/1.1"),
    )
    .await
    .expect("first trust policy accepts its client");
    assert_verified_identity(&send_http1(&mut existing).await, &first_client);
    let before = gateway
        .running
        .reload_handle()
        .current_snapshot()
        .config_version
        .clone();

    fs::write(&gateway.trust_bundle, &second_ca.certificate_pem)
        .expect("rotated trust bundle can be written");
    let report = gateway
        .running
        .reload_path(&gateway.config)
        .await
        .expect("valid trust rotation commits");
    let after = ConfigVersion::new(report.current_version.clone());
    assert_ne!(before, after);
    assert_eq!(report.listeners_retained, vec!["secure"]);
    assert_eq!(report.local_addresses[0].1, gateway.address);

    assert_verified_identity(&send_http1(&mut existing).await, &first_client);
    assert!(
        http1_is_rejected(
            gateway.address,
            client_config(&server, Some(&first_client), b"http/1.1")
        )
        .await,
        "new connections no longer trust the first CA"
    );
    let mut fresh = http1_client(
        gateway.address,
        client_config(&server, Some(&second_client), b"http/1.1"),
    )
    .await
    .expect("new connections use the rotated trust bundle");
    assert_verified_identity(&send_http1(&mut fresh).await, &second_client);
    gateway
        .running
        .shutdown()
        .await
        .expect("rotated gateway stops");
}
