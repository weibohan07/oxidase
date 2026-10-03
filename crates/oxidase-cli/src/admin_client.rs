//! Bounded HTTP/1 client used by `oxidase ctl`.
//!
//! The control client intentionally supports only Unix sockets and authenticated
//! HTTPS. It streams staged Bundles and bounds every response body.

use std::convert::Infallible;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_util::TryStreamExt as _;
use http::{Method, Request, StatusCode, Uri, header};
use http_body::Frame;
use http_body_util::{BodyExt as _, Full, StreamBody, combinators::BoxBody};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio_rustls::TlsConnector;
use tokio_util::io::ReaderStream;
use url::Url;

const MAX_ADMIN_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CA_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENT_CERTIFICATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENT_KEY_BYTES: usize = 1024 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type RequestBody = BoxBody<Bytes, BoxError>;

#[derive(Debug, Clone)]
pub(crate) enum AdminEndpoint {
    Unix(PathBuf),
    Https(AdminHttpsEndpoint),
}

#[derive(Debug, Clone)]
pub(crate) struct AdminHttpsEndpoint {
    pub(crate) url: Url,
    pub(crate) ca_bundle: Option<PathBuf>,
    pub(crate) client_certificate: Option<PathBuf>,
    pub(crate) client_key: Option<PathBuf>,
}

#[derive(Clone)]
pub(crate) struct AdminCredentials {
    pub(crate) bearer_token: Option<Vec<u8>>,
}

impl fmt::Debug for AdminCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminCredentials")
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Drop for AdminCredentials {
    fn drop(&mut self) {
        if let Some(token) = &mut self.bearer_token {
            token.fill(0);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum AdminOperation {
    Status,
    Clusters,
    Stage { bundle: PathBuf },
    Validate { digest: String },
    Activate { digest: String },
    Rollback { digest: String },
    Drain,
}

#[derive(Debug)]
pub(crate) struct AdminResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Bytes,
}

#[derive(Debug)]
pub(crate) struct AdminClientError {
    code: &'static str,
    message: String,
}

impl AdminClientError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for AdminClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AdminClientError {}

pub(crate) async fn read_bearer_token(path: &Path) -> Result<Vec<u8>, AdminClientError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        AdminClientError::new(
            "ctl.token_read",
            format!("cannot inspect bearer-token file: {error}"),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
        return Err(AdminClientError::new(
            "ctl.token_file",
            "bearer-token path must be a regular file no larger than 64 KiB",
        ));
    }
    let mut bytes = tokio::fs::read(path).await.map_err(|error| {
        AdminClientError::new(
            "ctl.token_read",
            format!("cannot read bearer-token file: {error}"),
        )
    })?;
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes.pop();
    }
    if bytes.is_empty() || bytes.contains(&b'\r') || bytes.contains(&b'\n') {
        bytes.fill(0);
        return Err(AdminClientError::new(
            "ctl.token_value",
            "bearer-token file must contain one non-empty Header-safe value",
        ));
    }
    Ok(bytes)
}

pub(crate) async fn execute(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    operation: AdminOperation,
) -> Result<AdminResponse, AdminClientError> {
    match operation {
        AdminOperation::Status => {
            send(
                endpoint,
                credentials,
                Method::GET,
                "/api/v1/runtime",
                None,
                None,
            )
            .await
        }
        AdminOperation::Clusters => {
            send(
                endpoint,
                credentials,
                Method::GET,
                "/api/v1/clusters",
                None,
                None,
            )
            .await
        }
        AdminOperation::Stage { bundle } => {
            let version = fetch_current_version(endpoint, credentials).await?;
            let metadata = tokio::fs::symlink_metadata(&bundle)
                .await
                .map_err(|error| {
                    AdminClientError::new(
                        "ctl.bundle_read",
                        format!("cannot inspect staged Bundle: {error}"),
                    )
                })?;
            if !metadata.file_type().is_file() {
                return Err(AdminClientError::new(
                    "ctl.bundle_file",
                    "staged Bundle path must be a regular file",
                ));
            }
            let file = tokio::fs::File::open(&bundle).await.map_err(|error| {
                AdminClientError::new(
                    "ctl.bundle_read",
                    format!("cannot open staged Bundle: {error}"),
                )
            })?;
            let stream = ReaderStream::new(file)
                .map_ok(Frame::data)
                .map_err(|error| -> BoxError { Box::new(error) });
            let body = StreamBody::new(stream).boxed();
            send(
                endpoint,
                credentials,
                Method::POST,
                "/api/v1/candidates",
                Some(MutationBody {
                    content_type: "application/vnd.oxidase.bundle",
                    length: metadata.len(),
                    body,
                }),
                Some(&version),
            )
            .await
        }
        AdminOperation::Validate { digest } => {
            mutate_digest(endpoint, credentials, "candidates", &digest, "validate").await
        }
        AdminOperation::Activate { digest } => {
            mutate_digest(endpoint, credentials, "candidates", &digest, "activate").await
        }
        AdminOperation::Rollback { digest } => {
            mutate_digest(endpoint, credentials, "snapshots", &digest, "rollback").await
        }
        AdminOperation::Drain => mutate_json(endpoint, credentials, "/api/v1/drain").await,
    }
}

async fn mutate_digest(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    collection: &str,
    digest: &str,
    action: &str,
) -> Result<AdminResponse, AdminClientError> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AdminClientError::new(
            "ctl.digest",
            "candidate/snapshot digest must contain exactly 64 hexadecimal characters",
        ));
    }
    mutate_json(
        endpoint,
        credentials,
        &format!("/api/v1/{collection}/{digest}/{action}"),
    )
    .await
}

async fn mutate_json(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    path: &str,
) -> Result<AdminResponse, AdminClientError> {
    let version = fetch_current_version(endpoint, credentials).await?;
    let bytes = Bytes::from_static(b"{}");
    let length = bytes.len() as u64;
    send(
        endpoint,
        credentials,
        Method::POST,
        path,
        Some(MutationBody {
            content_type: "application/json",
            length,
            body: full_body(bytes),
        }),
        Some(&version),
    )
    .await
}

async fn fetch_current_version(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
) -> Result<String, AdminClientError> {
    let response = send(
        endpoint,
        credentials,
        Method::GET,
        "/api/v1/snapshots/current",
        None,
        None,
    )
    .await?;
    ensure_success(&response)?;
    #[derive(serde::Deserialize)]
    struct CurrentSnapshot {
        config_version: String,
    }
    serde_json::from_slice::<CurrentSnapshot>(&response.body)
        .map(|snapshot| snapshot.config_version)
        .map_err(|error| {
            AdminClientError::new(
                "ctl.response_json",
                format!("admin current-snapshot response is invalid JSON: {error}"),
            )
        })
}

struct MutationBody {
    content_type: &'static str,
    length: u64,
    body: RequestBody,
}

async fn send(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    method: Method,
    path: &str,
    mutation: Option<MutationBody>,
    if_match: Option<&str>,
) -> Result<AdminResponse, AdminClientError> {
    let authority = endpoint_authority(endpoint)?;
    let uri = path.parse::<Uri>().map_err(|error| {
        AdminClientError::new(
            "ctl.request_uri",
            format!("invalid admin request URI: {error}"),
        )
    })?;
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, authority)
        .header(header::ACCEPT, "application/json");
    if let Some(token) = &credentials.bearer_token {
        let mut value = Vec::with_capacity(7 + token.len());
        value.extend_from_slice(b"Bearer ");
        value.extend_from_slice(token);
        builder = builder.header(header::AUTHORIZATION, value);
    }
    if let Some(version) = if_match {
        builder = builder.header(header::IF_MATCH, format!("\"{version}\""));
    }
    let body = if let Some(mutation) = mutation {
        builder = builder
            .header(header::CONTENT_TYPE, mutation.content_type)
            .header(header::CONTENT_LENGTH, mutation.length);
        mutation.body
    } else {
        full_body(Bytes::new())
    };
    let request = builder.body(body).map_err(|error| {
        AdminClientError::new(
            "ctl.request",
            format!("cannot build admin request: {error}"),
        )
    })?;
    match endpoint {
        AdminEndpoint::Unix(path) => send_unix(path, request).await,
        AdminEndpoint::Https(endpoint) => send_https(endpoint, request).await,
    }
}

fn endpoint_authority(endpoint: &AdminEndpoint) -> Result<String, AdminClientError> {
    match endpoint {
        AdminEndpoint::Unix(_) => Ok("localhost".to_owned()),
        AdminEndpoint::Https(endpoint) => {
            if endpoint.url.scheme() != "https"
                || !endpoint.url.username().is_empty()
                || endpoint.url.password().is_some()
                || endpoint.url.query().is_some()
                || endpoint.url.fragment().is_some()
                || endpoint.url.path() != "/"
            {
                return Err(AdminClientError::new(
                    "ctl.https_url",
                    "admin HTTPS endpoint must be an https origin without credentials, path, query, or fragment",
                ));
            }
            endpoint.url.host_str().ok_or_else(|| {
                AdminClientError::new("ctl.https_url", "admin HTTPS endpoint has no host")
            })?;
            Ok(endpoint.url[url::Position::BeforeHost..url::Position::AfterPort].to_owned())
        }
    }
}

#[cfg(unix)]
async fn send_unix(
    path: &Path,
    request: Request<RequestBody>,
) -> Result<AdminResponse, AdminClientError> {
    let stream = UnixStream::connect(path).await.map_err(|error| {
        AdminClientError::new(
            "ctl.connect",
            format!("cannot connect to admin Unix socket: {error}"),
        )
    })?;
    send_io(stream, request).await
}

#[cfg(not(unix))]
async fn send_unix(
    _path: &Path,
    _request: Request<RequestBody>,
) -> Result<AdminResponse, AdminClientError> {
    Err(AdminClientError::new(
        "ctl.unix_unsupported",
        "admin Unix sockets are not supported on this platform",
    ))
}

async fn send_https(
    endpoint: &AdminHttpsEndpoint,
    request: Request<RequestBody>,
) -> Result<AdminResponse, AdminClientError> {
    let host = endpoint
        .url
        .host_str()
        .ok_or_else(|| AdminClientError::new("ctl.https_url", "admin HTTPS endpoint has no host"))?
        .to_owned();
    let port = endpoint.url.port_or_known_default().ok_or_else(|| {
        AdminClientError::new("ctl.https_url", "admin HTTPS endpoint has no port")
    })?;
    let stream = TcpStream::connect((host.as_str(), port))
        .await
        .map_err(|error| {
            AdminClientError::new(
                "ctl.connect",
                format!("cannot connect to admin HTTPS endpoint: {error}"),
            )
        })?;
    let server_name = ServerName::try_from(host).map_err(|_| {
        AdminClientError::new("ctl.https_name", "admin HTTPS host is not a valid TLS name")
    })?;
    let config = build_tls_config(endpoint).await?;
    let tls = TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            AdminClientError::new("ctl.tls", format!("admin TLS handshake failed: {error}"))
        })?;
    send_io(tls, request).await
}

async fn build_tls_config(
    endpoint: &AdminHttpsEndpoint,
) -> Result<Arc<ClientConfig>, AdminClientError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = &endpoint.ca_bundle {
        let bytes = bounded_read(path, MAX_CA_BUNDLE_BYTES, "ctl.ca_bundle").await?;
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                AdminClientError::new(
                    "ctl.ca_bundle",
                    format!("admin CA bundle is invalid PEM: {error}"),
                )
            })?;
        if certificates.is_empty() {
            return Err(AdminClientError::new(
                "ctl.ca_bundle",
                "admin CA bundle contains no certificates",
            ));
        }
        roots.add_parsable_certificates(certificates);
    }
    if roots.is_empty() {
        return Err(AdminClientError::new(
            "ctl.ca_bundle",
            "no usable native or configured admin TLS trust anchors are available",
        ));
    }
    let provider = Arc::new(default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            AdminClientError::new(
                "ctl.tls_config",
                format!("cannot enable safe TLS protocol versions: {error}"),
            )
        })?
        .with_root_certificates(roots);
    let mut config = match (&endpoint.client_certificate, &endpoint.client_key) {
        (None, None) => builder.with_no_client_auth(),
        (Some(certificate), Some(key)) => {
            let certificate = bounded_read(
                certificate,
                MAX_CLIENT_CERTIFICATE_BYTES,
                "ctl.client_certificate",
            )
            .await?;
            let certificates = CertificateDer::pem_slice_iter(&certificate)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    AdminClientError::new(
                        "ctl.client_certificate",
                        format!("admin client certificate is invalid PEM: {error}"),
                    )
                })?;
            if certificates.is_empty() {
                return Err(AdminClientError::new(
                    "ctl.client_certificate",
                    "admin client certificate chain is empty",
                ));
            }
            let mut key_bytes = bounded_read(key, MAX_CLIENT_KEY_BYTES, "ctl.client_key").await?;
            let mut keys = PrivateKeyDer::pem_slice_iter(&key_bytes)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| {
                    AdminClientError::new(
                        "ctl.client_key",
                        format!("admin client key is invalid PEM: {error}"),
                    )
                })?;
            if keys.len() != 1 {
                key_bytes.fill(0);
                return Err(AdminClientError::new(
                    "ctl.client_key",
                    "admin client-key file must contain exactly one private key",
                ));
            }
            let key = keys.pop().expect("one client private key was checked");
            key_bytes.fill(0);
            builder
                .with_client_auth_cert(certificates, key)
                .map_err(|error| {
                    AdminClientError::new(
                        "ctl.client_identity",
                        format!("admin client certificate/key mismatch: {error}"),
                    )
                })?
        }
        _ => {
            return Err(AdminClientError::new(
                "ctl.client_identity",
                "--client-certificate and --client-key must be supplied together",
            ));
        }
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn bounded_read(
    path: &Path,
    limit: usize,
    code: &'static str,
) -> Result<Vec<u8>, AdminClientError> {
    let metadata = tokio::fs::symlink_metadata(path).await.map_err(|error| {
        AdminClientError::new(
            code,
            format!("cannot inspect `{}`: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > limit)
    {
        return Err(AdminClientError::new(
            code,
            format!("`{}` must be a bounded regular file", path.display()),
        ));
    }
    tokio::fs::read(path).await.map_err(|error| {
        AdminClientError::new(code, format!("cannot read `{}`: {error}", path.display()))
    })
}

async fn send_io<I>(io: I, request: Request<RequestBody>) -> Result<AdminResponse, AdminClientError>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(io)).await.map_err(|error| {
        AdminClientError::new(
            "ctl.http_handshake",
            format!("admin HTTP handshake failed: {error}"),
        )
    })?;
    let driver = tokio::spawn(connection);
    let response = sender.send_request(request).await.map_err(|error| {
        AdminClientError::new(
            "ctl.request",
            format!("admin request failed before a response arrived: {error}"),
        )
    })?;
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            AdminClientError::new(
                "ctl.response_body",
                format!("admin response body failed: {error}"),
            )
        })?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > MAX_ADMIN_RESPONSE_BYTES {
                driver.abort();
                return Err(AdminClientError::new(
                    "ctl.response_too_large",
                    "admin response exceeds the 4 MiB control-client limit",
                ));
            }
            bytes.extend_from_slice(&data);
        }
    }
    drop(sender);
    driver.abort();
    Ok(AdminResponse {
        status,
        body: bytes.freeze(),
    })
}

fn full_body(bytes: Bytes) -> RequestBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

pub(crate) fn ensure_success(response: &AdminResponse) -> Result<(), AdminClientError> {
    if response.status.is_success() {
        return Ok(());
    }
    let detail = serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "admin.request_failed".to_owned());
    Err(AdminClientError::new(
        "ctl.admin_response",
        format!("admin API returned {} ({detail})", response.status),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use url::Url;

    use super::{
        AdminCredentials, AdminEndpoint, AdminHttpsEndpoint, AdminOperation, endpoint_authority,
        execute, read_bearer_token,
    };

    #[tokio::test]
    async fn token_reader_trims_one_line_without_exposing_it_in_debug() {
        let directory = tempdir().expect("temporary directory is available");
        let token = directory.path().join("token");
        fs::write(&token, b"sensitive-token\n").expect("token can be written");
        let bytes = read_bearer_token(&token).await.expect("token reads");
        let credentials = AdminCredentials {
            bearer_token: Some(bytes),
        };
        assert!(!format!("{credentials:?}").contains("sensitive-token"));
    }

    #[test]
    fn https_origin_validation_rejects_credentials_and_paths() {
        let endpoint = |value: &str| {
            AdminEndpoint::Https(AdminHttpsEndpoint {
                url: Url::parse(value).expect("fixture URL parses"),
                ca_bundle: None,
                client_certificate: None,
                client_key: None,
            })
        };
        assert_eq!(
            endpoint_authority(&endpoint("https://admin.example:7590/"))
                .expect("origin is accepted"),
            "admin.example:7590"
        );
        assert!(endpoint_authority(&endpoint("https://user@admin.example/")).is_err());
        assert!(endpoint_authority(&endpoint("https://admin.example/api")).is_err());
    }

    #[tokio::test]
    async fn digest_is_validated_before_transport_io() {
        let error = execute(
            &AdminEndpoint::Unix("/definitely/not/a/socket".into()),
            &AdminCredentials { bearer_token: None },
            AdminOperation::Activate {
                digest: "../escape".to_owned(),
            },
        )
        .await
        .expect_err("invalid digest is rejected");
        assert_eq!(error.code(), "ctl.digest");
    }
}
