//! Bounded HTTP/1 client used by `oxidase ctl`.
//!
//! The control client intentionally supports only Unix sockets and authenticated
//! HTTPS. It streams staged Bundles and bounds every response body.

use std::convert::Infallible;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::TryStreamExt as _;
use http::{Method, Request, StatusCode, Uri, header};
use http_body::Frame;
use http_body_util::{BodyExt as _, Full, StreamBody, combinators::BoxBody};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use oxidase_runtime::{AdminBearerToken, MAX_ADMIN_BEARER_TOKEN_BYTES};
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_util::io::ReaderStream;
use url::Url;
use zeroize::Zeroizing;

const MAX_ADMIN_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CA_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENT_CERTIFICATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CLIENT_KEY_BYTES: usize = 1024 * 1024;
const MAX_STAGED_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
static TLS_PREPARATION_ADMISSION: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(1)));

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
    pub(crate) bearer_token: Option<AdminBearerToken>,
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

#[derive(Debug, Clone)]
pub(crate) enum AdminOperation {
    Status,
    Clusters,
    Stage { bundle: PathBuf },
    Validate { digest: String },
    Activate { digest: String },
    Rollback { digest: String },
    Drain,
    Snapshots,
    Operation { operation_id: String },
    ReloadSource,
}

#[derive(Debug, Clone)]
pub(crate) struct AdminClientOptions {
    /// A complete strong HTTP ETag, including its quotes.
    pub(crate) if_match: Option<String>,
    pub(crate) idempotency_key: Option<String>,
    pub(crate) connect_timeout: Duration,
    pub(crate) timeout: Duration,
}

impl Default for AdminClientOptions {
    fn default() -> Self {
        Self {
            if_match: None,
            idempotency_key: None,
            connect_timeout: Duration::from_secs(5),
            timeout: Duration::from_secs(60),
        }
    }
}

#[derive(Debug)]
pub(crate) struct AdminResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Bytes,
    etag: Option<String>,
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

pub(crate) async fn read_bearer_token(path: &Path) -> Result<AdminBearerToken, AdminClientError> {
    let mut bytes = bounded_read(path, MAX_ADMIN_BEARER_TOKEN_BYTES + 2, "ctl.token_file").await?;
    let token = AdminBearerToken::parse_file_bytes(&bytes)
        .map_err(|error| AdminClientError::new("ctl.token_value", error.to_string()));
    bytes.fill(0);
    token
}

pub(crate) async fn execute(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    operation: AdminOperation,
    options: &AdminClientOptions,
) -> Result<AdminResponse, AdminClientError> {
    validate_options(options)?;
    let deadline = Instant::now() + options.timeout;
    tokio::time::timeout_at(
        deadline,
        execute_inner(endpoint, credentials, operation, options, deadline),
    )
    .await
    .map_err(|_| {
        AdminClientError::new("ctl.timeout", "Admin operation exceeded its total timeout")
    })?
}

async fn execute_inner(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    operation: AdminOperation,
    options: &AdminClientOptions,
    deadline: Instant,
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
                (options, deadline),
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
                (options, deadline),
            )
            .await
        }
        AdminOperation::Stage { bundle } => {
            let version = mutation_precondition(endpoint, credentials, options, deadline).await?;
            let (file, length) =
                open_bounded_regular_file(&bundle, MAX_STAGED_BUNDLE_BYTES, "ctl.bundle_file")
                    .await?;
            let stream = ReaderStream::new(tokio::io::AsyncReadExt::take(
                tokio::fs::File::from_std(file),
                length,
            ))
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
                    length,
                    body,
                }),
                Some(&version),
                (options, deadline),
            )
            .await
        }
        AdminOperation::Validate { digest } => {
            mutate_digest(
                endpoint,
                credentials,
                "candidates",
                &digest,
                "validate",
                options,
                deadline,
            )
            .await
        }
        AdminOperation::Activate { digest } => {
            mutate_digest(
                endpoint,
                credentials,
                "candidates",
                &digest,
                "activate",
                options,
                deadline,
            )
            .await
        }
        AdminOperation::Rollback { digest } => {
            mutate_digest(
                endpoint,
                credentials,
                "snapshots",
                &digest,
                "rollback",
                options,
                deadline,
            )
            .await
        }
        AdminOperation::Drain => {
            mutate_json(endpoint, credentials, "/api/v1/drain", options, deadline).await
        }
        AdminOperation::ReloadSource => {
            mutate_json(
                endpoint,
                credentials,
                "/api/v1/reload-source",
                options,
                deadline,
            )
            .await
        }
        AdminOperation::Snapshots => {
            send(
                endpoint,
                credentials,
                Method::GET,
                "/api/v1/snapshots",
                None,
                None,
                (options, deadline),
            )
            .await
        }
        AdminOperation::Operation { operation_id } => {
            if operation_id.is_empty()
                || operation_id.len() > 128
                || !operation_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                return Err(AdminClientError::new(
                    "ctl.operation_id",
                    "operation ID must be a bounded alphanumeric identifier",
                ));
            }
            send(
                endpoint,
                credentials,
                Method::GET,
                &format!("/api/v1/operations/{operation_id}"),
                None,
                None,
                (options, deadline),
            )
            .await
        }
    }
}

async fn mutate_digest(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    collection: &str,
    digest: &str,
    action: &str,
    options: &AdminClientOptions,
    deadline: Instant,
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
        options,
        deadline,
    )
    .await
}

async fn mutate_json(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    path: &str,
    options: &AdminClientOptions,
    deadline: Instant,
) -> Result<AdminResponse, AdminClientError> {
    let version = mutation_precondition(endpoint, credentials, options, deadline).await?;
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
        (options, deadline),
    )
    .await
}

async fn mutation_precondition(
    endpoint: &AdminEndpoint,
    credentials: &AdminCredentials,
    options: &AdminClientOptions,
    deadline: Instant,
) -> Result<String, AdminClientError> {
    if let Some(if_match) = &options.if_match {
        return Ok(if_match.clone());
    }
    let response = send(
        endpoint,
        credentials,
        Method::GET,
        "/api/v1/snapshots/current",
        None,
        None,
        (options, deadline),
    )
    .await?;
    ensure_success(&response)?;
    response
        .etag
        .filter(|value| valid_etag(value))
        .ok_or_else(|| {
            AdminClientError::new(
                "ctl.response_etag",
                "Admin current-snapshot response must carry a strong runtime revision ETag",
            )
        })
}

fn valid_etag(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 256
        && value.starts_with('"')
        && value.ends_with('"')
        && value[1..value.len() - 1]
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"')
}

fn validate_options(options: &AdminClientOptions) -> Result<(), AdminClientError> {
    if options.timeout.is_zero()
        || options.connect_timeout.is_zero()
        || options.timeout > Duration::from_secs(86400)
        || options.connect_timeout > Duration::from_secs(86400)
    {
        return Err(AdminClientError::new(
            "ctl.timeout_value",
            "timeouts must be greater than zero and at most 24 hours",
        ));
    }
    if options
        .if_match
        .as_deref()
        .is_some_and(|value| !valid_etag(value))
    {
        return Err(AdminClientError::new(
            "ctl.if_match",
            "--if-match must be one quoted strong ETag",
        ));
    }
    if options.idempotency_key.as_deref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    }) {
        return Err(AdminClientError::new(
            "ctl.idempotency_key",
            "idempotency key must contain 1..=128 visible ASCII bytes",
        ));
    }
    Ok(())
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
    timing: (&AdminClientOptions, Instant),
) -> Result<AdminResponse, AdminClientError> {
    let (options, deadline) = timing;
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
        builder = builder.header(header::AUTHORIZATION, token.authorization_header());
    }
    if let Some(version) = if_match {
        builder = builder.header(header::IF_MATCH, version);
        if let Some(key) = &options.idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
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
        AdminEndpoint::Unix(path) => send_unix(path, request, options, deadline).await,
        AdminEndpoint::Https(endpoint) => send_https(endpoint, request, options, deadline).await,
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
    options: &AdminClientOptions,
    deadline: Instant,
) -> Result<AdminResponse, AdminClientError> {
    let stream = tokio::time::timeout_at(
        deadline.min(Instant::now() + options.connect_timeout),
        UnixStream::connect(path),
    )
    .await
    .map_err(|_| {
        AdminClientError::new(
            "ctl.connect_timeout",
            "Admin connection exceeded its timeout",
        )
    })?
    .map_err(|error| {
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
    _options: &AdminClientOptions,
    _deadline: Instant,
) -> Result<AdminResponse, AdminClientError> {
    Err(AdminClientError::new(
        "ctl.unix_unsupported",
        "admin Unix sockets are not supported on this platform",
    ))
}

async fn send_https(
    endpoint: &AdminHttpsEndpoint,
    request: Request<RequestBody>,
    options: &AdminClientOptions,
    deadline: Instant,
) -> Result<AdminResponse, AdminClientError> {
    let host = endpoint.url.host().ok_or_else(|| {
        AdminClientError::new("ctl.https_url", "admin HTTPS endpoint has no host")
    })?;
    let (connect_host, server_name) = match host {
        url::Host::Domain(name) => (
            name.to_owned(),
            ServerName::try_from(name.to_owned()).map_err(|_| {
                AdminClientError::new("ctl.https_name", "admin HTTPS host is not a valid TLS name")
            })?,
        ),
        url::Host::Ipv4(ip) => (ip.to_string(), ServerName::IpAddress(ip.into())),
        url::Host::Ipv6(ip) => (ip.to_string(), ServerName::IpAddress(ip.into())),
    };
    let port = endpoint.url.port_or_known_default().ok_or_else(|| {
        AdminClientError::new("ctl.https_url", "admin HTTPS endpoint has no port")
    })?;
    // Trust-store enumeration and identity parsing belong to preparation, not
    // the async connection driver. The enclosing operation deadline covers both
    // preparation admission and execution; no socket is opened before it ends.
    let config = build_tls_config(endpoint).await?;
    let connect_deadline = deadline.min(Instant::now() + options.connect_timeout);
    let stream = tokio::time::timeout_at(
        connect_deadline,
        TcpStream::connect((connect_host.as_str(), port)),
    )
    .await
    .map_err(|_| {
        AdminClientError::new(
            "ctl.connect_timeout",
            "Admin connection exceeded its timeout",
        )
    })?
    .map_err(|error| {
        AdminClientError::new(
            "ctl.connect",
            format!("cannot connect to admin HTTPS endpoint: {error}"),
        )
    })?;
    let tls = tokio::time::timeout_at(
        connect_deadline,
        TlsConnector::from(config).connect(server_name, stream),
    )
    .await
    .map_err(|_| {
        AdminClientError::new(
            "ctl.connect_timeout",
            "Admin TLS handshake exceeded its connection timeout",
        )
    })?
    .map_err(|error| {
        AdminClientError::new("ctl.tls", format!("admin TLS handshake failed: {error}"))
    })?;
    send_io(tls, request).await
}

async fn build_tls_config(
    endpoint: &AdminHttpsEndpoint,
) -> Result<Arc<ClientConfig>, AdminClientError> {
    let endpoint = endpoint.clone();
    run_tls_preparation(Arc::clone(&TLS_PREPARATION_ADMISSION), move || {
        build_tls_config_blocking(&endpoint)
    })
    .await
}

async fn run_tls_preparation<T: Send + 'static>(
    admission: Arc<tokio::sync::Semaphore>,
    prepare: impl FnOnce() -> Result<T, AdminClientError> + Send + 'static,
) -> Result<T, AdminClientError> {
    let permit = admission.acquire_owned().await.map_err(|_| {
        AdminClientError::new(
            "ctl.tls_config",
            "Admin TLS preparation admission is closed",
        )
    })?;
    tokio::task::spawn_blocking(move || {
        // Dropping the caller cannot release admission for a still-running OS
        // trust-store read. Only this worker's actual completion releases it.
        let _permit = permit;
        prepare()
    })
    .await
    .map_err(|_| AdminClientError::new("ctl.tls_config", "Admin TLS preparation did not finish"))?
}

fn build_tls_config_blocking(
    endpoint: &AdminHttpsEndpoint,
) -> Result<Arc<ClientConfig>, AdminClientError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(path) = &endpoint.ca_bundle {
        let bytes = bounded_read_blocking(path, MAX_CA_BUNDLE_BYTES, "ctl.ca_bundle")?;
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
        for certificate in certificates {
            roots.add(certificate).map_err(|_| {
                AdminClientError::new(
                    "ctl.ca_bundle",
                    "configured Admin CA bundle contains an invalid certificate",
                )
            })?;
        }
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
            let certificate = bounded_read_blocking(
                certificate,
                MAX_CLIENT_CERTIFICATE_BYTES,
                "ctl.client_certificate",
            )?;
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
            let mut key_bytes = bounded_read_blocking(key, MAX_CLIENT_KEY_BYTES, "ctl.client_key")?;
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

fn bounded_read_blocking(
    path: &Path,
    limit: usize,
    code: &'static str,
) -> Result<Zeroizing<Vec<u8>>, AdminClientError> {
    let (file, _) = open_regular_file_checked(path, limit as u64, code)?;
    read_opened_file(file, limit, code)
}

async fn bounded_read(
    path: &Path,
    limit: usize,
    code: &'static str,
) -> Result<Zeroizing<Vec<u8>>, AdminClientError> {
    let (file, _) = open_bounded_regular_file(path, limit as u64, code).await?;
    tokio::task::spawn_blocking(move || read_opened_file(file, limit, code))
        .await
        .map_err(|_| AdminClientError::new(code, "bounded file reader did not finish"))?
}

fn read_opened_file(
    file: std::fs::File,
    limit: usize,
    code: &'static str,
) -> Result<Zeroizing<Vec<u8>>, AdminClientError> {
    use std::io::Read as _;
    let mut bytes = Zeroizing::new(Vec::new());
    if let Err(error) = file.take(limit as u64 + 1).read_to_end(&mut bytes) {
        bytes.fill(0);
        return Err(AdminClientError::new(
            code,
            format!("cannot read bounded regular file: {error}"),
        ));
    }
    if bytes.len() > limit {
        bytes.fill(0);
        return Err(AdminClientError::new(
            code,
            "file grew beyond its permitted byte limit",
        ));
    }
    Ok(bytes)
}

async fn open_bounded_regular_file(
    path: &Path,
    limit: u64,
    code: &'static str,
) -> Result<(std::fs::File, u64), AdminClientError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || open_regular_file_checked(&path, limit, code))
        .await
        .map_err(|_| AdminClientError::new(code, "regular-file opener did not finish"))?
}

fn open_regular_file_checked(
    path: &Path,
    limit: u64,
    code: &'static str,
) -> Result<(std::fs::File, u64), AdminClientError> {
    let before = std::fs::symlink_metadata(path).map_err(|error| {
        AdminClientError::new(code, format!("cannot inspect input file: {error}"))
    })?;
    if !before.is_file() || before.len() > limit {
        return Err(AdminClientError::new(
            code,
            "input must be a bounded regular file",
        ));
    }
    open_with_inspected_metadata(path, &before, limit, code)
}

fn open_with_inspected_metadata(
    path: &Path,
    before: &std::fs::Metadata,
    limit: u64,
    code: &'static str,
) -> Result<(std::fs::File, u64), AdminClientError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};
        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| {
            AdminClientError::new(code, format!("cannot safely open input file: {error}"))
        })?;
        std::fs::File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)
        .map_err(|error| AdminClientError::new(code, format!("cannot open input file: {error}")))?;
    let after = file.metadata().map_err(|error| {
        AdminClientError::new(code, format!("cannot inspect opened input file: {error}"))
    })?;
    if !after.is_file() || after.len() > limit {
        return Err(AdminClientError::new(
            code,
            "opened input is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(AdminClientError::new(
                code,
                "input file changed while opening",
            ));
        }
    }
    Ok((file, after.len()))
}

/// Cancelling any send/read future also cancels the HTTP driver and closes its IO.
struct HttpDriver(Option<tokio::task::JoinHandle<Result<(), hyper::Error>>>);

impl HttpDriver {
    async fn stop(mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl Drop for HttpDriver {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
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
    let driver = HttpDriver(Some(tokio::spawn(connection)));
    let response = sender.send_request(request).await.map_err(|error| {
        AdminClientError::new(
            "ctl.request",
            format!("admin request failed before a response arrived: {error}"),
        )
    })?;
    let status = response.status();
    let mut etags = response.headers().get_all(header::ETAG).iter();
    let etag = etags
        .next()
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if etags.next().is_some() {
        return Err(AdminClientError::new(
            "ctl.response_etag",
            "Admin response contains repeated ETag fields",
        ));
    }
    let mut body = response.into_body();
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            AdminClientError::new(
                "ctl.response_body",
                format!("admin response body failed: {error}"),
            )
        })?;
        match frame.into_data() {
            Ok(data) => {
                if bytes.len().saturating_add(data.len()) > MAX_ADMIN_RESPONSE_BYTES {
                    return Err(AdminClientError::new(
                        "ctl.response_too_large",
                        "admin response exceeds the 4 MiB control-client limit",
                    ));
                }
                bytes.extend_from_slice(&data);
            }
            Err(frame) if frame.is_trailers() => {
                return Err(AdminClientError::new(
                    "ctl.response_trailers",
                    "Admin responses must not contain trailers",
                ));
            }
            Err(_) => {
                return Err(AdminClientError::new(
                    "ctl.response_frame",
                    "Admin response contains an unsupported frame",
                ));
            }
        }
    }
    drop(sender);
    driver.stop().await;
    Ok(AdminResponse {
        status,
        body: bytes.freeze(),
        etag,
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
                .filter(|code| {
                    code.len() <= 128
                        && code.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                })
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
    use std::convert::Infallible;
    use std::fs;
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{Request, Response, StatusCode, header};
    use http_body_util::{BodyExt as _, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    };
    use rustls::RootCertStore;
    use rustls::crypto::ring::default_provider;
    use rustls::server::WebPkiClientVerifier;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    #[cfg(unix)]
    use tokio::net::UnixListener;
    use tokio_rustls::TlsAcceptor;
    use url::Url;

    use super::{
        AdminClientOptions, AdminCredentials, AdminEndpoint, AdminHttpsEndpoint, AdminOperation,
        MAX_ADMIN_RESPONSE_BYTES, endpoint_authority, execute, open_bounded_regular_file,
        open_with_inspected_metadata, read_bearer_token, read_opened_file, run_tls_preparation,
    };

    #[tokio::test]
    async fn tls_preparation_does_not_block_runtime_or_release_admission_on_cancellation() {
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let mut first = Box::pin(run_tls_preparation(Arc::clone(&admission), move || {
            started_tx
                .send(())
                .expect("worker announces its blocking boundary");
            release_rx.blocking_recv().expect("worker released by test");
            Ok(())
        }));
        tokio::select! {
            result = &mut first => panic!("blocked preparation finished early: {result:?}"),
            started = started_rx => started.expect("worker started"),
        }
        // This is a current-thread runtime. Its timer can only expire while the
        // synchronous preparation runs elsewhere, without blocking its executor.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), first)
                .await
                .is_err()
        );
        assert_eq!(admission.available_permits(), 0);
        let mut second = Box::pin(run_tls_preparation(Arc::clone(&admission), || Ok(())));
        assert!(futures_util::poll!(&mut second).is_pending());
        release_tx.send(()).expect("blocked worker is still alive");
        tokio::time::timeout(Duration::from_secs(2), second)
            .await
            .expect("waiting preparation proceeds only after the worker ends")
            .expect("second preparation succeeds");
        assert_eq!(admission.available_permits(), 1);
    }

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
            &AdminClientOptions::default(),
        )
        .await
        .expect_err("invalid digest is rejected");
        assert_eq!(error.code(), "ctl.digest");
    }

    #[tokio::test]
    async fn token_files_preserve_the_shared_contract() {
        let directory = tempdir().expect("temporary token directory");
        let path = directory.path().join("token");
        for bytes in [b"test-token".as_slice(), b"test-token\n", b"test-token\r\n"] {
            fs::write(&path, bytes).expect("token written");
            assert!(
                read_bearer_token(&path)
                    .await
                    .expect("token parses")
                    .constant_time_eq(b"test-token")
            );
        }
        for bytes in [b"".as_slice(), b"token\n\n", b"token \n", b"to ken"] {
            fs::write(&path, bytes).expect("invalid token written");
            assert_eq!(
                read_bearer_token(&path)
                    .await
                    .expect_err("invalid token rejected")
                    .code(),
                "ctl.token_value"
            );
        }
        fs::write(&path, vec![b'x'; 8193]).expect("oversized token written");
        assert!(read_bearer_token(&path).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn file_inputs_reject_symlinks_replacements_and_growth() {
        use std::os::unix::fs::symlink;
        let directory = tempdir().expect("temporary files");
        let path = directory.path().join("input");
        fs::write(&path, b"small").expect("file written");
        let link = directory.path().join("link");
        symlink(&path, &link).expect("symlink written");
        assert!(
            open_bounded_regular_file(&link, 32, "ctl.input")
                .await
                .is_err()
        );
        let before = fs::symlink_metadata(&path).expect("inspection");
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"other").expect("replacement written");
        fs::rename(&replacement, &path).expect("path replaced");
        assert!(open_with_inspected_metadata(&path, &before, 32, "ctl.input").is_err());
        let (file, _) = open_bounded_regular_file(&path, 5, "ctl.input")
            .await
            .expect("bounded open");
        fs::write(&path, b"longer").expect("same inode grows");
        assert!(
            read_opened_file(file, 5, "ctl.input").is_err(),
            "limit+1 read detects growth after metadata"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn file_inputs_reject_fifo_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};
        let directory = tempdir().expect("temporary files");
        let fifo = directory.path().join("fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO created");
        assert!(
            open_bounded_regular_file(&fifo, 32, "ctl.input")
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn explicit_precondition_does_not_read_or_retry_a_stale_mutation() {
        let directory = tempdir().expect("temporary socket");
        let path = directory.path().join("admin.sock");
        let listener = UnixListener::bind(&path).expect("Unix fixture binds");
        let token_path = directory.path().join("token");
        fs::write(&token_path, b"fixture-token\r\n").expect("token written");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client connects");
            let service = service_fn(|request: Request<Incoming>| async move {
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(request.uri().path(), "/api/v1/drain");
                assert_eq!(request.headers()[header::IF_MATCH], "\"runtime-test-1\"");
                assert_eq!(request.headers()["idempotency-key"], "test-receipt");
                assert_eq!(
                    request.headers()[header::AUTHORIZATION],
                    "Bearer fixture-token"
                );
                request.into_body().collect().await.expect("request body");
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::PRECONDITION_FAILED)
                        .body(Full::new(Bytes::from_static(
                            b"{\"code\":\"admin.precondition_failed\"}",
                        )))
                        .expect("response"),
                )
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "412 must not trigger a preliminary read or retry"
            );
        });
        let credentials = AdminCredentials {
            bearer_token: Some(read_bearer_token(&token_path).await.expect("token reads")),
        };
        let response = execute(
            &AdminEndpoint::Unix(path),
            &credentials,
            AdminOperation::Drain,
            &AdminClientOptions {
                if_match: Some("\"runtime-test-1\"".to_owned()),
                idempotency_key: Some("test-receipt".to_owned()),
                ..AdminClientOptions::default()
            },
        )
        .await
        .expect("response is returned");
        assert_eq!(response.status, StatusCode::PRECONDITION_FAILED);
        server.await.expect("fixture assertions pass");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn default_mutation_reads_the_runtime_etag_once() {
        let directory = tempdir().expect("temporary socket");
        let path = directory.path().join("admin.sock");
        let listener = UnixListener::bind(&path).expect("Unix fixture binds");
        let server = tokio::spawn(async move {
            for index in 0..2 {
                let (stream, _) = listener.accept().await.expect("client connects");
                let service = service_fn(move |request: Request<Incoming>| async move {
                    if index == 0 {
                        assert_eq!(request.method(), http::Method::GET);
                        assert_eq!(request.uri().path(), "/api/v1/snapshots/current");
                        Ok::<_, Infallible>(Response::builder().header(header::ETAG, "\"runtime-fixture-7\"").body(Full::new(Bytes::from_static(b"{\"runtime_revision\":7,\"config_version\":\"irrelevant-content-version\"}"))).expect("read response"))
                    } else {
                        assert_eq!(request.uri().path(), "/api/v1/reload-source");
                        assert_eq!(request.headers()[header::IF_MATCH], "\"runtime-fixture-7\"");
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"{}"))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        execute(
            &AdminEndpoint::Unix(path),
            &AdminCredentials { bearer_token: None },
            AdminOperation::ReloadSource,
            &AdminClientOptions::default(),
        )
        .await
        .expect("reload response");
        server.await.expect("fixture assertions pass");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn total_timeout_cancels_http_driver_during_headers_or_body() {
        for stalled_body in [false, true] {
            let directory = tempdir().expect("temporary socket");
            let path = directory.path().join("admin.sock");
            let listener = UnixListener::bind(&path).expect("Unix fixture binds");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("client connects");
                let mut request = vec![0; 1024];
                assert!(stream.read(&mut request).await.expect("request received") > 0);
                if stalled_body {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
                        .await
                        .expect("partial body sent");
                }
                let closed =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
                        .await
                        .expect("driver closes IO");
                assert_eq!(closed.expect("EOF read"), 0);
            });
            let error = execute(
                &AdminEndpoint::Unix(path),
                &AdminCredentials { bearer_token: None },
                AdminOperation::Status,
                &AdminClientOptions {
                    timeout: Duration::from_millis(100),
                    ..AdminClientOptions::default()
                },
            )
            .await
            .expect_err("stall exceeds deadline");
            assert_eq!(error.code(), "ctl.timeout");
            server.await.expect("HTTP driver reclaimed");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_response_aborts_and_joins_http_driver() {
        let directory = tempdir().expect("temporary socket");
        let path = directory.path().join("admin.sock");
        let listener = UnixListener::bind(&path).expect("Unix fixture binds");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client connects");
            let service = service_fn(|_: Request<Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![
                    b'x';
                    MAX_ADMIN_RESPONSE_BYTES
                        + 1
                ]))))
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let error = execute(
            &AdminEndpoint::Unix(path),
            &AdminCredentials { bearer_token: None },
            AdminOperation::Status,
            &AdminClientOptions::default(),
        )
        .await
        .expect_err("oversized response rejected");
        assert_eq!(error.code(), "ctl.response_too_large");
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .expect("driver released IO")
            .expect("server joins");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn control_responses_reject_ambiguous_etags_and_trailers() {
        for (raw, code) in [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nETag: \"runtime-test-1\"\r\nETag: \"runtime-test-2\"\r\n\r\n{}".as_slice(), "ctl.response_etag"),
            (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Guard\r\n\r\n2\r\n{}\r\n0\r\nX-Guard: invalid\r\n\r\n".as_slice(), "ctl.response_trailers"),
        ] {
            let directory = tempdir().expect("temporary socket");
            let path = directory.path().join("admin.sock");
            let listener = UnixListener::bind(&path).expect("fixture socket binds");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("client connects");
                let mut request = [0; 1024];
                assert!(stream.read(&mut request).await.expect("request received") > 0);
                stream.write_all(raw).await.expect("fixture response sent");
                let _ = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request)).await.expect("driver cancels response IO");
            });
            let error = execute(&AdminEndpoint::Unix(path), &AdminCredentials { bearer_token: None }, AdminOperation::Status, &AdminClientOptions::default()).await.expect_err("ambiguous response rejected");
            assert_eq!(error.code(), code);
            server.await.expect("fixture assertions pass");
        }
    }

    struct TlsFixture {
        config: Arc<rustls::ServerConfig>,
        ca_pem: String,
        client_pem: String,
        client_key: String,
    }

    fn tls_fixture(required_mtls: bool, correct_name: bool) -> TlsFixture {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("test-only CA key");
        let ca = ca_params.self_signed(&ca_key).expect("test-only CA");
        let issuer = Issuer::new(ca_params, ca_key);
        let names = if correct_name {
            vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ]
        } else {
            vec!["wrong.example.test".to_owned()]
        };
        let mut server_params = CertificateParams::new(names).expect("server params");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().expect("test-only server key");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server certificate");
        let mut client_params = CertificateParams::new(vec!["operator.example.test".to_owned()])
            .expect("client params");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().expect("test-only client key");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client certificate");
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).expect("test-only root");
        let builder = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .expect("safe TLS versions");
        let builder = if required_mtls {
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(
                    Arc::new(roots),
                    Arc::new(default_provider()),
                )
                .build()
                .expect("mTLS verifier"),
            )
        } else {
            builder.with_no_client_auth()
        };
        let mut config = builder
            .with_single_cert(
                vec![server_cert.der().clone(), ca.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("server TLS config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsFixture {
            config: Arc::new(config),
            ca_pem: ca.pem(),
            client_pem: format!("{}{}", client_cert.pem(), ca.pem()),
            client_key: client_key.serialize_pem(),
        }
    }

    async fn run_https_fixture(ip: IpAddr, required_mtls: bool) {
        let fixture = tls_fixture(required_mtls, true);
        let directory = tempdir().expect("temporary cert files");
        let ca = directory.path().join("ca.pem");
        let cert = directory.path().join("client.pem");
        let key = directory.path().join("client.key");
        fs::write(&ca, fixture.ca_pem).expect("test CA written");
        fs::write(&cert, fixture.client_pem).expect("test client cert written");
        fs::write(&key, fixture.client_key).expect("test client key written");
        let listener = TcpListener::bind((ip, 0)).await.expect("TLS fixture binds");
        let addr = listener.local_addr().expect("TLS fixture address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("TLS client connects");
            let tls = TlsAcceptor::from(fixture.config)
                .accept(stream)
                .await
                .expect("verified TLS client");
            assert_eq!(tls.get_ref().1.peer_certificates().is_some(), required_mtls);
            let service = service_fn(|_: Request<Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"{\"ok\":true}",
                ))))
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await
                .expect("TLS HTTP closes");
        });
        let endpoint = AdminEndpoint::Https(AdminHttpsEndpoint {
            url: Url::parse(&format!("https://{addr}/")).expect("origin"),
            ca_bundle: Some(ca),
            client_certificate: required_mtls.then_some(cert),
            client_key: required_mtls.then_some(key),
        });
        let response = execute(
            &endpoint,
            &AdminCredentials { bearer_token: None },
            AdminOperation::Status,
            &AdminClientOptions::default(),
        )
        .await
        .expect("verified HTTPS response");
        assert_eq!(response.status, StatusCode::OK);
        server.await.expect("TLS assertions pass");
    }

    #[tokio::test]
    async fn private_ca_https_ipv4_and_required_mtls_work() {
        run_https_fixture("127.0.0.1".parse().expect("IPv4"), false).await;
        run_https_fixture("127.0.0.1".parse().expect("IPv4"), true).await;
    }

    #[tokio::test]
    async fn private_ca_https_ipv6_uses_an_ip_verification_name() {
        run_https_fixture("::1".parse().expect("IPv6"), false).await;
    }

    #[tokio::test]
    async fn https_rejects_wrong_name_and_stalled_handshake() {
        let fixture = tls_fixture(false, false);
        let directory = tempdir().expect("temporary cert files");
        let ca = directory.path().join("ca.pem");
        fs::write(&ca, fixture.ca_pem).expect("test CA written");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("fixture binds");
        let addr = listener.local_addr().expect("fixture address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("client connects");
            assert!(
                TlsAcceptor::from(fixture.config)
                    .accept(stream)
                    .await
                    .is_err()
            );
        });
        let endpoint = AdminEndpoint::Https(AdminHttpsEndpoint {
            url: Url::parse(&format!("https://{addr}/")).expect("origin"),
            ca_bundle: Some(ca),
            client_certificate: None,
            client_key: None,
        });
        assert_eq!(
            execute(
                &endpoint,
                &AdminCredentials { bearer_token: None },
                AdminOperation::Status,
                &AdminClientOptions::default()
            )
            .await
            .expect_err("wrong name rejected")
            .code(),
            "ctl.tls"
        );
        server.await.expect("TLS failure received");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("stall fixture binds");
        let addr = listener.local_addr().expect("stall address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client connects");
            let mut buffer = vec![0; 65536];
            assert!(stream.read(&mut buffer).await.expect("ClientHello arrives") > 0);
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                    .await
                    .expect("TLS IO closes")
                    .expect("read EOF"),
                0
            );
        });
        let endpoint = AdminEndpoint::Https(AdminHttpsEndpoint {
            url: Url::parse(&format!("https://{addr}/")).expect("origin"),
            ca_bundle: None,
            client_certificate: None,
            client_key: None,
        });
        assert_eq!(
            execute(
                &endpoint,
                &AdminCredentials { bearer_token: None },
                AdminOperation::Status,
                &AdminClientOptions {
                    connect_timeout: Duration::from_millis(150),
                    ..AdminClientOptions::default()
                }
            )
            .await
            .expect_err("TLS stall rejected")
            .code(),
            "ctl.connect_timeout"
        );
        server.await.expect("TLS IO reclaimed");
    }
}
