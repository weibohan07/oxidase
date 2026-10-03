//! Security boundary shared by every administration transport.
//!
//! Transport code supplies only authenticated connection facts. This module
//! performs bearer verification, maps routes to bounded permissions, checks
//! mutation preconditions, and emits redacted audit fields. It deliberately
//! never retains or formats bearer-token bytes.

use std::fmt;

use http::{HeaderMap, Method, StatusCode, header};
use oxidase_config::{AdminAuthMode, AdminListenSpec, AdminSpec};
use oxidase_core::{ContentDigest, Diagnostic};
use oxidase_runtime::{AdminBearerToken, MAX_ADMIN_BEARER_TOKEN_BYTES, RuntimeSnapshot};

pub(crate) const ADMIN_JSON_CONTENT_TYPE: &str = "application/json";
pub(crate) const ADMIN_BUNDLE_CONTENT_TYPE: &str = "application/vnd.oxidase.bundle";
pub(crate) const DEFAULT_ADMIN_REQUEST_BODY_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminPermission {
    Read,
    Stage,
    Activate,
    Rollback,
    Drain,
    ReloadSource,
}

impl AdminPermission {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Stage => "stage",
            Self::Activate => "activate",
            Self::Rollback => "rollback",
            Self::Drain => "drain",
            Self::ReloadSource => "reload_source",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdminPermissions {
    pub(crate) read: bool,
    pub(crate) stage: bool,
    pub(crate) activate: bool,
    pub(crate) rollback: bool,
    pub(crate) drain: bool,
    pub(crate) reload_source: bool,
}

impl AdminPermissions {
    pub(crate) const fn read_only() -> Self {
        Self {
            read: true,
            stage: false,
            activate: false,
            rollback: false,
            drain: false,
            reload_source: false,
        }
    }

    pub(crate) const fn allows(self, permission: AdminPermission) -> bool {
        match permission {
            AdminPermission::Read => self.read,
            AdminPermission::Stage => self.stage,
            AdminPermission::Activate => self.activate,
            AdminPermission::Rollback => self.rollback,
            AdminPermission::Drain => self.drain,
            AdminPermission::ReloadSource => self.reload_source,
        }
    }
}

#[derive(Clone)]
pub(crate) enum AdminAuthentication {
    /// Explicit development-only mode. The compiler/server transport boundary
    /// is responsible for restricting it to loopback or a Unix socket.
    UnsafeDevelopment,
    Bearer(AdminBearerToken),
    Mtls,
    BearerAndMtls(AdminBearerToken),
}

impl fmt::Debug for AdminAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeDevelopment => formatter.write_str("UnsafeDevelopment"),
            Self::Bearer(_) => formatter.write_str("Bearer(<secret-resource>)"),
            Self::Mtls => formatter.write_str("Mtls"),
            Self::BearerAndMtls(_) => formatter.write_str("BearerAndMtls(<secret-resource>)"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AdminSecuritySnapshot {
    pub(crate) authentication: AdminAuthentication,
    pub(crate) permissions: AdminPermissions,
    pub(crate) max_body_bytes: u64,
    bootstrap: Option<ContentDigest>,
    sensitive_files: Vec<oxidase_runtime::SensitiveFileIdentity>,
}

pub(crate) type AdminSecurityPolicy = AdminSecuritySnapshot;

impl AdminSecuritySnapshot {
    pub(crate) const fn legacy_loopback_read_only() -> Self {
        Self {
            authentication: AdminAuthentication::UnsafeDevelopment,
            permissions: AdminPermissions::read_only(),
            max_body_bytes: DEFAULT_ADMIN_REQUEST_BODY_BYTES,
            bootstrap: None,
            sensitive_files: Vec::new(),
        }
    }

    /// Captures one coherent bootstrap configuration. Authentication never reads
    /// Secret resources from the request's data-plane snapshot.
    pub(crate) fn prepare(snapshot: &RuntimeSnapshot) -> Result<Self, Box<Diagnostic>> {
        let admin = snapshot.admin.as_ref().ok_or_else(|| {
            Box::new(Diagnostic::new(
                "admin.configuration_missing",
                "Admin bootstrap configuration is absent",
                oxidase_core::SourceSpan::synthetic("admin"),
            ))
        })?;
        let token = || {
            admin
                .auth
                .token_secret
                .as_ref()
                .and_then(|id| snapshot.resources.secrets.get(id))
                .ok_or_else(|| {
                    Box::new(Diagnostic::new(
                        "admin.token_missing",
                        "Admin bearer Secret is unavailable",
                        admin.auth.source.clone(),
                    ))
                })?
                .admin_bearer_token()
                .map_err(|_| {
                    Box::new(Diagnostic::new(
                        "admin.token_invalid",
                        "Admin token file does not satisfy the bearer format",
                        admin.auth.source.clone(),
                    ))
                })
        };
        let authentication = match admin.auth.mode {
            AdminAuthMode::UnsafeNone => AdminAuthentication::UnsafeDevelopment,
            AdminAuthMode::Bearer => AdminAuthentication::Bearer(token()?),
            AdminAuthMode::Mtls => AdminAuthentication::Mtls,
            AdminAuthMode::BearerAndMtls => AdminAuthentication::BearerAndMtls(token()?),
        };
        let mut sensitive_files = Vec::new();
        if let Some(secret) = admin
            .auth
            .token_secret
            .as_ref()
            .and_then(|id| snapshot.resources.secrets.get(id))
        {
            sensitive_files.push(secret.sensitive_file_identity());
        }
        if let AdminListenSpec::Https(https) = &admin.listen
            && let Some(certificate) = snapshot.resources.certificates.get(&https.certificate)
        {
            sensitive_files.push(certificate.sensitive_file_identity());
        }
        if let oxidase_config::AdminAuditDestination::File(path) = &admin.audit.destination
            && path.try_exists().unwrap_or(true)
        {
            let source = oxidase_site::AssetSource::File(path.clone());
            for sensitive in &sensitive_files {
                if sensitive.overlaps_asset(&source).unwrap_or(true) {
                    return Err(Box::new(Diagnostic::new(
                        "admin.audit_sensitive_overlap",
                        "Admin audit output must be separate from protected bootstrap files",
                        admin.audit.source.clone(),
                    )));
                }
            }
        }
        Ok(Self {
            authentication,
            permissions: AdminPermissions {
                read: admin.permissions.read,
                stage: admin.permissions.stage,
                activate: admin.permissions.activate,
                rollback: admin.permissions.rollback,
                drain: admin.permissions.drain,
                reload_source: admin.permissions.reload_source,
            },
            max_body_bytes: admin.candidates.max_candidate_bytes,
            bootstrap: Some(bootstrap_identity(admin, snapshot)?),
            sensitive_files,
        })
    }

    /// A data-plane-only candidate may omit Admin altogether. A supplied Admin
    /// plan must match the already bound bootstrap; activation cannot take over
    /// its own verifier, credential, permissions, transport, or storage.
    pub(crate) fn check_candidate(
        &self,
        candidate: &RuntimeSnapshot,
    ) -> Result<(), Box<Diagnostic>> {
        for site in candidate.resources.sites.values() {
            for source in site.asset_sources() {
                for sensitive in &self.sensitive_files {
                    match sensitive.overlaps_asset(source) {
                        Ok(false) => {}
                        Ok(true) => {
                            return Err(Box::new(Diagnostic::new(
                                "admin.sensitive_asset_overlap",
                                "candidate public Asset exposes a file protected by the Admin bootstrap",
                                oxidase_core::SourceSpan::synthetic("admin.bootstrap"),
                            )));
                        }
                        Err(_) => {
                            return Err(Box::new(Diagnostic::new(
                                "admin.sensitive_asset_identity",
                                "cannot prove candidate Assets are isolated from the Admin bootstrap",
                                oxidase_core::SourceSpan::synthetic("admin.bootstrap"),
                            )));
                        }
                    }
                }
            }
        }
        let Some(admin) = candidate.admin.as_ref() else {
            return Ok(());
        };
        let compatible = self.bootstrap == Some(bootstrap_identity(admin, candidate)?);
        let token_compatible = match &self.authentication {
            AdminAuthentication::Bearer(token) | AdminAuthentication::BearerAndMtls(token) => admin
                .auth
                .token_secret
                .as_ref()
                .and_then(|id| candidate.resources.secrets.get(id))
                .and_then(|secret| secret.admin_bearer_token().ok())
                .is_some_and(|other| token.same_credential(&other)),
            _ => true,
        };
        if compatible && token_compatible {
            Ok(())
        } else {
            Err(Box::new(Diagnostic::new(
                "admin.restart_required",
                "candidate changes the fixed Admin bootstrap; restart with the intended Admin configuration",
                admin.source.clone(),
            )))
        }
    }

    pub(crate) fn authorize(
        &self,
        headers: &HeaderMap,
        peer: &AdminPeerIdentity,
        permission: AdminPermission,
    ) -> Result<AdminPrincipal, AdminSecurityError> {
        let principal = self.authenticated_principal(headers, peer)?;
        if !self.permissions.allows(permission) {
            return Err(AdminSecurityError::Forbidden);
        }
        Ok(principal)
    }

    pub(crate) fn authenticated_principal(
        &self,
        headers: &HeaderMap,
        peer: &AdminPeerIdentity,
    ) -> Result<AdminPrincipal, AdminSecurityError> {
        let bearer = match &self.authentication {
            AdminAuthentication::Bearer(token) | AdminAuthentication::BearerAndMtls(token) => {
                Some(authenticate_bearer(headers, token)?)
            }
            AdminAuthentication::UnsafeDevelopment | AdminAuthentication::Mtls => None,
        };
        let certificate = match self.authentication {
            AdminAuthentication::Mtls | AdminAuthentication::BearerAndMtls(_) => {
                Some(authenticate_mtls(peer)?)
            }
            AdminAuthentication::UnsafeDevelopment | AdminAuthentication::Bearer(_) => None,
        };
        Ok(match (bearer, certificate) {
            (Some(()), Some(identity)) => AdminPrincipal::BearerAndMtls(identity),
            (Some(()), None) => AdminPrincipal::Bearer,
            (None, Some(identity)) => AdminPrincipal::Mtls(identity),
            (None, None) => AdminPrincipal::UnsafeDevelopment,
        })
    }
}

fn bootstrap_identity(
    admin: &AdminSpec,
    snapshot: &RuntimeSnapshot,
) -> Result<ContentDigest, Box<Diagnostic>> {
    // Source spans deliberately do not affect deployment policy equality. This
    // internal serialization is never returned, logged, or used as inspection.
    let listen = match &admin.listen {
        AdminListenSpec::Unix(unix) => serde_json::json!({
            "transport": "unix", "path": unix.path, "mode": unix.mode,
        }),
        AdminListenSpec::Https(https) => serde_json::json!({
            "transport": "https", "bind": https.bind.to_string(),
            "certificate": https.certificate.to_string(),
            "client_auth": format!("{:?}", https.client_auth.mode),
            "trust_store": https.client_auth.trust_store.as_ref().map(ToString::to_string),
            "certificate_digest": snapshot.resources.certificates.get(&https.certificate).map(|certificate| certificate.digest.to_string()),
            "trust_digest": https.client_auth.trust_store.as_ref()
                .and_then(|id| snapshot.resources.trust_stores.get(id))
                .map(|trust| ContentDigest::of_bytes(serde_json::to_vec(&trust.public_roots_der()).expect("public DER serializes")).to_string()),
        }),
    };
    let token_reference = admin
        .auth
        .token_secret
        .as_ref()
        .and_then(|id| snapshot.resources.secrets.get(id).map(|_| id.to_string()));
    let verification_key_digests = admin.bundle_trust.verification_keys.iter().map(|path| {
        oxidase_bundle::BundleVerificationKey::read_file(path).map(|key| ContentDigest::of_bytes(key.as_bytes()).to_string())
            .map_err(|_| Box::new(Diagnostic::new("admin.restart_required", "candidate Admin verification material is unavailable or changed; restart is required", admin.bundle_trust.source.clone())))
    }).collect::<Result<Vec<_>, _>>()?;
    let policy = serde_json::json!({
        "listen": listen,
        "auth": admin.auth.mode,
        "token_reference": token_reference,
        "storage": admin.storage.directory,
        "deployment_root": admin.bundle_trust.deployment_root,
        "verification_keys": admin.bundle_trust.verification_keys,
        "verification_key_digests": verification_key_digests,
        "permissions": admin.permissions,
        "candidate_count": admin.candidates.max_count,
        "candidate_bytes": admin.candidates.max_bytes,
        "upload_bytes": admin.candidates.max_candidate_bytes,
        "history_count": admin.history.max_snapshots,
        "history_bytes": admin.history.max_bytes,
        "audit_destination": match &admin.audit.destination {
            oxidase_config::AdminAuditDestination::Stderr => "stderr",
            oxidase_config::AdminAuditDestination::Stdout => "stdout",
            oxidase_config::AdminAuditDestination::File(_) => "file",
        },
        "audit_file": match &admin.audit.destination {
            oxidase_config::AdminAuditDestination::File(path) => Some(path),
            _ => None,
        },
        "audit_queue": admin.audit.queue_capacity,
    });
    Ok(ContentDigest::of_bytes(
        serde_json::to_vec(&policy).expect("bootstrap policy is serializable"),
    ))
}

#[derive(Clone, Default)]
pub(crate) struct AdminPeerIdentity {
    /// Present only after the TLS verifier accepted the presented certificate.
    pub(crate) verified_client_sha256: Option<String>,
}

impl fmt::Debug for AdminPeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminPeerIdentity")
            .field(
                "verified_client_certificate",
                &self.verified_client_sha256.is_some(),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) enum AdminPrincipal {
    UnsafeDevelopment,
    Bearer,
    Mtls(String),
    BearerAndMtls(String),
}

impl AdminPrincipal {
    /// A bounded audit identifier. It never contains a bearer token.
    pub(crate) fn audit_id(&self) -> &str {
        match self {
            Self::UnsafeDevelopment => "unsafe-development",
            Self::Bearer => "bearer",
            Self::Mtls(fingerprint) | Self::BearerAndMtls(fingerprint) => fingerprint,
        }
    }

    pub(crate) const fn authentication_kind(&self) -> &'static str {
        match self {
            Self::UnsafeDevelopment => "unsafe_development",
            Self::Bearer => "bearer",
            Self::Mtls(_) => "mtls",
            Self::BearerAndMtls(_) => "bearer_and_mtls",
        }
    }
}

impl fmt::Debug for AdminPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdminPrincipal")
            .field("authentication", &self.authentication_kind())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminSecurityError {
    Unauthenticated,
    Forbidden,
    PreconditionRequired,
    #[cfg(any(test, feature = "fuzzing"))]
    PreconditionFailed,
    UnsupportedMediaType,
    PayloadTooLarge,
    InvalidHeaders,
}

impl AdminSecurityError {
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            #[cfg(any(test, feature = "fuzzing"))]
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidHeaders => StatusCode::BAD_REQUEST,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "admin.unauthenticated",
            Self::Forbidden => "admin.forbidden",
            Self::PreconditionRequired => "admin.precondition_required",
            #[cfg(any(test, feature = "fuzzing"))]
            Self::PreconditionFailed => "admin.precondition_failed",
            Self::UnsupportedMediaType => "admin.unsupported_media_type",
            Self::PayloadTooLarge => "admin.payload_too_large",
            Self::InvalidHeaders => "admin.invalid_headers",
        }
    }
}

pub(crate) struct AdminRoute {
    pub(crate) permission: AdminPermission,
    pub(crate) mutation: bool,
    pub(crate) content_type: Option<&'static str>,
}

pub(crate) fn classify_admin_route(method: &Method, path: &str) -> Option<AdminRoute> {
    let read = matches!(method, &Method::GET | &Method::HEAD);
    if read
        && (matches!(
            path,
            "/health/live"
                | "/health/ready"
                | "/metrics"
                | "/api/v1/clusters"
                | "/api/v1/runtime"
                | "/api/v1/snapshots/current"
                | "/api/v1/snapshots"
        ) || operation_query(path))
    {
        return Some(AdminRoute {
            permission: AdminPermission::Read,
            mutation: false,
            content_type: None,
        });
    }
    if method != Method::POST {
        return None;
    }
    if path == "/api/v1/candidates" {
        return Some(AdminRoute {
            permission: AdminPermission::Stage,
            mutation: true,
            content_type: Some(ADMIN_BUNDLE_CONTENT_TYPE),
        });
    }
    if candidate_action(path, "validate") {
        return Some(json_mutation(AdminPermission::Stage));
    }
    if candidate_action(path, "activate") {
        return Some(json_mutation(AdminPermission::Activate));
    }
    if snapshot_action(path, "rollback") {
        return Some(json_mutation(AdminPermission::Rollback));
    }
    match path {
        "/api/v1/drain" => Some(json_mutation(AdminPermission::Drain)),
        "/api/v1/reload-source" => Some(json_mutation(AdminPermission::ReloadSource)),
        _ => None,
    }
}

fn json_mutation(permission: AdminPermission) -> AdminRoute {
    AdminRoute {
        permission,
        mutation: true,
        content_type: Some(ADMIN_JSON_CONTENT_TYPE),
    }
}

fn candidate_action(path: &str, action: &str) -> bool {
    resource_action(path, "/api/v1/candidates/", action)
}

fn snapshot_action(path: &str, action: &str) -> bool {
    resource_action(path, "/api/v1/snapshots/", action)
}

fn resource_action(path: &str, prefix: &str, action: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else {
        return false;
    };
    let Some((identifier, actual_action)) = rest.split_once('/') else {
        return false;
    };
    !identifier.is_empty()
        && identifier.len() == 64
        && identifier
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && actual_action == action
}

fn operation_query(path: &str) -> bool {
    path.strip_prefix("/api/v1/operations/")
        .is_some_and(|identifier| {
            !identifier.is_empty()
                && identifier.len() <= 128
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub(crate) fn allowed_admin_methods(path: &str) -> Option<&'static str> {
    if classify_admin_route(&Method::GET, path).is_some() {
        Some("GET, HEAD")
    } else if classify_admin_route(&Method::POST, path).is_some() {
        Some("POST")
    } else {
        None
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub(crate) fn validate_mutation_headers(
    headers: &HeaderMap,
    expected_content_type: &'static str,
    current_etag: &str,
    max_body_bytes: u64,
) -> Result<(), AdminSecurityError> {
    validate_mutation_header_shape(headers, expected_content_type, max_body_bytes)?;
    if headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        != Some(current_etag)
    {
        return Err(AdminSecurityError::PreconditionFailed);
    }
    Ok(())
}

pub(crate) fn validate_mutation_header_shape(
    headers: &HeaderMap,
    expected_content_type: &'static str,
    max_body_bytes: u64,
) -> Result<(), AdminSecurityError> {
    let mut idempotency_keys = headers.get_all("idempotency-key").iter();
    if let Some(key) = idempotency_keys.next()
        && (idempotency_keys.next().is_some()
            || key.as_bytes().is_empty()
            || key.as_bytes().len() > 256
            || !key
                .as_bytes()
                .iter()
                .all(|byte| (b'!'..=b'~').contains(byte)))
    {
        return Err(AdminSecurityError::InvalidHeaders);
    }
    if headers.get_all(header::CONTENT_TYPE).iter().count() != 1 {
        return Err(AdminSecurityError::UnsupportedMediaType);
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some(expected_content_type) {
        return Err(AdminSecurityError::UnsupportedMediaType);
    }
    if headers.get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return Err(AdminSecurityError::InvalidHeaders);
    }
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if headers.contains_key(header::CONTENT_LENGTH) && content_length.is_none() {
        return Err(AdminSecurityError::InvalidHeaders);
    }
    if content_length.is_some_and(|length| length > max_body_bytes) {
        return Err(AdminSecurityError::PayloadTooLarge);
    }
    let mut if_matches = headers.get_all(header::IF_MATCH).iter();
    let Some(if_match) = if_matches.next() else {
        return Err(AdminSecurityError::PreconditionRequired);
    };
    if if_matches.next().is_some() {
        return Err(AdminSecurityError::InvalidHeaders);
    }
    let Ok(if_match) = if_match.to_str() else {
        return Err(AdminSecurityError::InvalidHeaders);
    };
    let opaque = if_match
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'));
    if !opaque.is_some_and(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte == b'!' || (b'#'..=b'~').contains(&byte))
    }) {
        return Err(AdminSecurityError::InvalidHeaders);
    }
    Ok(())
}

fn authenticate_bearer(
    headers: &HeaderMap,
    token: &AdminBearerToken,
) -> Result<(), AdminSecurityError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Err(AdminSecurityError::Unauthenticated);
    };
    if values.next().is_some() {
        return Err(AdminSecurityError::Unauthenticated);
    }
    let bytes = value.as_bytes();
    let Some(candidate) = bytes.strip_prefix(b"Bearer ") else {
        return Err(AdminSecurityError::Unauthenticated);
    };
    if candidate.is_empty() || candidate.len() > MAX_ADMIN_BEARER_TOKEN_BYTES {
        return Err(AdminSecurityError::Unauthenticated);
    }
    if token.constant_time_eq(candidate) {
        Ok(())
    } else {
        Err(AdminSecurityError::Unauthenticated)
    }
}

fn authenticate_mtls(peer: &AdminPeerIdentity) -> Result<String, AdminSecurityError> {
    peer.verified_client_sha256
        .as_deref()
        .map(|fingerprint| fingerprint.strip_prefix("sha256:").unwrap_or(fingerprint))
        .filter(|fingerprint| {
            fingerprint.len() == 64 && fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(str::to_ascii_lowercase)
        .ok_or(AdminSecurityError::Unauthenticated)
}

#[cfg(unix)]
pub(crate) mod unix_socket {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::unix_trust::{DirectoryIdentity, TrustedDirectory};
    use tokio::net::UnixListener;

    /// A path-owned Unix listener whose cleanup is identity checked.
    ///
    /// Cleanup never follows symlinks and never removes a socket that replaced
    /// this listener's filesystem node after startup.
    pub(crate) struct BoundUnixAdmin {
        listener: UnixListener,
        path: PathBuf,
        device: u64,
        inode: u64,
        cleaned: bool,
        parent: DirectoryIdentity,
    }

    impl BoundUnixAdmin {
        pub(crate) async fn bind(path: &Path, mode: u32) -> io::Result<Self> {
            if mode > 0o777 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unix admin socket mode must be within 0000..0777",
                ));
            }
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unix admin socket must have a parent directory",
                )
            })?;
            let trusted = TrustedDirectory::open(parent)?;
            let file_name = path.file_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket path has no file name")
            })?;
            let path = trusted.path().join(file_name);
            reject_or_remove_stale(&path).await?;
            trusted.verify()?;
            // The socket remains inaccessible inside a 0700 directory until its
            // final mode is installed, then appears atomically at the public path.
            let staging = tempfile::Builder::new()
                .prefix(".ox-")
                .tempdir_in(trusted.path())?;
            fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
            let staging_path = staging.path().join("s");
            let listener = UnixListener::bind(&staging_path)?;
            fs::set_permissions(&staging_path, fs::Permissions::from_mode(mode))?;
            trusted.verify()?;
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &staging_path,
                rustix::fs::CWD,
                &path,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                if path.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "socket path appeared during bind",
                    ));
                }
                fs::rename(&staging_path, &path)?;
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_socket() {
                let _ = fs::remove_file(&path);
                return Err(io::Error::other(
                    "Unix admin listener path is not a socket after bind",
                ));
            }
            Ok(Self {
                listener,
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                cleaned: false,
                parent: trusted.identity(),
            })
        }

        pub(crate) fn listener(&self) -> &UnixListener {
            &self.listener
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }

        pub(crate) fn cleanup(&mut self) -> io::Result<()> {
            if self.cleaned {
                return Ok(());
            }
            self.cleaned = true;
            self.parent.verify()?;
            remove_socket_if_matches(&self.path, Some((self.device, self.inode)))
        }
    }

    impl Drop for BoundUnixAdmin {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    async fn reject_or_remove_stale(path: &Path) -> io::Result<()> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to replace a symlink at the Unix admin socket path",
            ));
        }
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "refusing to replace a non-socket at the Unix admin socket path",
            ));
        }
        match tokio::time::timeout(
            std::time::Duration::from_millis(250),
            tokio::net::UnixStream::connect(path),
        )
        .await
        {
            Ok(Ok(_)) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix admin socket is already accepting connections",
            )),
            Ok(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                remove_socket_if_matches(path, Some((metadata.dev(), metadata.ino())))
            }
            Ok(Err(error)) => Err(io::Error::new(
                error.kind(),
                format!("cannot prove Unix admin socket is stale: {error}"),
            )),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "cannot prove Unix admin socket is stale before the probe deadline",
            )),
        }
    }

    fn remove_socket_if_matches(path: &Path, identity: Option<(u64, u64)>) -> io::Result<()> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket() {
            return if identity.is_none() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unix admin socket path changed to a non-socket",
                ))
            };
        }
        if identity
            .is_some_and(|(device, inode)| device != metadata.dev() || inode != metadata.ino())
        {
            return Ok(());
        }
        fs::remove_file(path)
    }
}

#[cfg(unix)]
pub(crate) mod unix_trust {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};

    #[derive(Clone)]
    pub(crate) struct DirectoryIdentity {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl DirectoryIdentity {
        pub(crate) fn verify(&self) -> io::Result<()> {
            let metadata = fs::symlink_metadata(&self.path)?;
            if !metadata.is_dir() || metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Admin parent directory identity changed",
                ));
            }
            validate_directory_metadata(&metadata, false)
        }
    }

    pub(crate) struct TrustedDirectory {
        path: PathBuf,
        identity: DirectoryIdentity,
        _handle: File,
    }

    impl TrustedDirectory {
        pub(crate) fn open(parent: &Path) -> io::Result<Self> {
            if fs::symlink_metadata(parent)?.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Admin parent cannot be a symlink",
                ));
            }
            let path = fs::canonicalize(parent)?;
            for (index, ancestor) in path.ancestors().enumerate() {
                let metadata = fs::symlink_metadata(ancestor)?;
                if !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Admin parent chain is not a directory",
                    ));
                }
                validate_directory_metadata(&metadata, index > 0)?;
            }
            let flags = rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NONBLOCK;
            let handle = OpenOptions::new()
                .read(true)
                .custom_flags(flags.bits() as i32)
                .open(&path)?;
            let metadata = handle.metadata()?;
            let identity = DirectoryIdentity {
                path: path.clone(),
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            identity.verify()?;
            Ok(Self {
                path,
                identity,
                _handle: handle,
            })
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
        pub(crate) fn identity(&self) -> DirectoryIdentity {
            self.identity.clone()
        }
        pub(crate) fn verify(&self) -> io::Result<()> {
            self.identity.verify()
        }
        pub(crate) fn sync(&self) -> io::Result<()> {
            self._handle.sync_all()
        }
    }

    fn validate_directory_metadata(
        metadata: &fs::Metadata,
        allow_sticky_ancestor: bool,
    ) -> io::Result<()> {
        let uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != uid && metadata.uid() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Admin parent chain has an untrusted owner",
            ));
        }
        if metadata.mode() & 0o022 != 0
            && !(allow_sticky_ancestor && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Admin parent is writable by another principal",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use http::{HeaderMap, HeaderValue, Method, header};
    use oxidase_config::Compiler;
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;

    use super::{
        ADMIN_BUNDLE_CONTENT_TYPE, ADMIN_JSON_CONTENT_TYPE, AdminAuthentication, AdminPeerIdentity,
        AdminPermission, AdminPermissions, AdminPrincipal, AdminSecurityError, AdminSecurityPolicy,
        classify_admin_route, validate_mutation_headers,
    };

    fn snapshot_with_secret(value: &[u8]) -> RuntimeSnapshot {
        let directory = tempdir().expect("temporary directory is available");
        fs::write(directory.path().join("token"), value).expect("token can be written");
        fs::write(
            directory.path().join("oxidase.yaml"),
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    admin-token:
      file: token
admin:
  listen:
    unix:
      path: {socket}
  auth:
    mode: bearer
    token_secret: admin-token
  storage:
    directory: {storage}
  permissions:
    read: true
    drain: true
services:
  root:
    type: respond
    body:
      text: ok
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
                socket = directory.path().join("admin.sock").display(),
                storage = directory.path().join("storage").display()
            ),
        )
        .expect("gateway can be written");
        let gateway = Compiler::compile_path(directory.path().join("oxidase.yaml"))
            .expect("gateway compiles");
        RuntimeSnapshot::prepare(gateway).expect("snapshot prepares")
    }

    fn all_permissions() -> AdminPermissions {
        AdminPermissions {
            read: true,
            stage: true,
            activate: true,
            rollback: true,
            drain: true,
            reload_source: true,
        }
    }

    #[test]
    fn bearer_is_constant_time_checked_without_entering_principal_or_debug() {
        let snapshot = snapshot_with_secret(b"correct-token");
        let policy = AdminSecurityPolicy {
            authentication: AdminAuthentication::Bearer(
                snapshot
                    .resources
                    .secrets
                    .values()
                    .next()
                    .expect("token")
                    .admin_bearer_token()
                    .expect("valid token"),
            ),
            permissions: all_permissions(),
            max_body_bytes: super::DEFAULT_ADMIN_REQUEST_BODY_BYTES,
            bootstrap: None,
            sensitive_files: Vec::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer correct-token"),
        );
        let principal = policy
            .authorize(
                &headers,
                &AdminPeerIdentity::default(),
                AdminPermission::Read,
            )
            .expect("matching token authenticates");
        assert_eq!(principal, AdminPrincipal::Bearer);
        let debug = format!("{policy:?} {principal:?}");
        assert!(!debug.contains("correct-token"));

        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer incorrect-token"),
        );
        assert_eq!(
            policy.authorize(
                &headers,
                &AdminPeerIdentity::default(),
                AdminPermission::Read,
            ),
            Err(AdminSecurityError::Unauthenticated)
        );
    }

    #[test]
    fn combined_auth_requires_both_factors_and_rbac_is_independent() {
        let snapshot = snapshot_with_secret(b"correct-token");
        let policy = AdminSecurityPolicy {
            authentication: AdminAuthentication::BearerAndMtls(
                snapshot
                    .resources
                    .secrets
                    .values()
                    .next()
                    .expect("token")
                    .admin_bearer_token()
                    .expect("valid token"),
            ),
            permissions: AdminPermissions::read_only(),
            max_body_bytes: super::DEFAULT_ADMIN_REQUEST_BODY_BYTES,
            bootstrap: None,
            sensitive_files: Vec::new(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer correct-token"),
        );
        assert_eq!(
            policy.authorize(
                &headers,
                &AdminPeerIdentity::default(),
                AdminPermission::Read,
            ),
            Err(AdminSecurityError::Unauthenticated)
        );
        let peer = AdminPeerIdentity {
            verified_client_sha256: Some("c".repeat(64)),
        };
        let principal = policy
            .authorize(&headers, &peer, AdminPermission::Read)
            .expect("both factors authenticate");
        assert_eq!(principal.audit_id(), "c".repeat(64));
        assert_eq!(principal.authentication_kind(), "bearer_and_mtls");
        assert_eq!(
            policy.authorize(&headers, &peer, AdminPermission::Activate),
            Err(AdminSecurityError::Forbidden)
        );
        assert_eq!(
            policy.authenticated_principal(&headers, &peer),
            Ok(AdminPrincipal::BearerAndMtls("c".repeat(64)))
        );
    }

    #[test]
    fn route_classification_is_exact_and_digest_bounded() {
        let read = classify_admin_route(&Method::GET, "/api/v1/runtime")
            .expect("runtime read route exists");
        assert_eq!(read.permission, AdminPermission::Read);
        assert!(!read.mutation);
        let activate = classify_admin_route(
            &Method::POST,
            "/api/v1/candidates/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/activate",
        )
        .expect("candidate activation route exists");
        assert_eq!(activate.permission, AdminPermission::Activate);
        assert!(activate.mutation);
        assert!(
            classify_admin_route(&Method::POST, "/api/v1/candidates/../../escape/activate")
                .is_none()
        );
        assert!(classify_admin_route(&Method::DELETE, "/api/v1/runtime").is_none());
    }

    #[test]
    fn mutations_require_exact_media_type_size_and_current_version() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(ADMIN_BUNDLE_CONTENT_TYPE),
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"version-1\""));
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("64"));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"version-1\"", 64),
            Ok(())
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("65"));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"version-1\"", 64),
            Err(AdminSecurityError::PayloadTooLarge)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("64"));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"stale\""));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"version-1\"", 64),
            Err(AdminSecurityError::PreconditionFailed)
        );
        headers.remove(header::IF_MATCH);
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"version-1\"", 64),
            Err(AdminSecurityError::PreconditionRequired)
        );
    }

    #[test]
    fn cloned_snapshot_secret_is_never_serialized_or_logged() {
        let snapshot = Arc::new(snapshot_with_secret(b"never-print-this"));
        let debug = format!("{:?}", snapshot.resources.secrets);
        let json = serde_json::to_string(&snapshot.resources.secrets)
            .expect("prepared Secret map serializes redacted values");
        assert!(!debug.contains("never-print-this"));
        assert!(!json.contains("never-print-this"));
    }

    #[test]
    fn bootstrap_retains_authentication_after_data_snapshot_removes_admin_secrets() {
        let mut snapshot = snapshot_with_secret(b"fixed-token\r\n");
        let security = AdminSecurityPolicy::prepare(&snapshot).expect("bootstrap parses token");
        snapshot.admin = None;
        snapshot.resources.secrets.clear();
        security
            .check_candidate(&snapshot)
            .expect("data-only candidate is allowed");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer fixed-token"),
        );
        assert_eq!(
            security.authorize(
                &headers,
                &AdminPeerIdentity::default(),
                AdminPermission::Read
            ),
            Ok(AdminPrincipal::Bearer)
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer fixed-token"),
        );
        assert_eq!(
            security.authorize(
                &headers,
                &AdminPeerIdentity::default(),
                AdminPermission::Read
            ),
            Err(AdminSecurityError::Unauthenticated)
        );
    }

    #[test]
    fn candidate_cannot_silently_change_permissions_or_token_material() {
        let mut snapshot = snapshot_with_secret(b"fixed-token");
        let security = AdminSecurityPolicy::prepare(&snapshot).expect("bootstrap prepares");
        snapshot.admin.as_mut().expect("admin").permissions.activate = true;
        assert_eq!(
            security
                .check_candidate(&snapshot)
                .expect_err("permission change is rejected")
                .code,
            "admin.restart_required"
        );
        snapshot.admin.as_mut().expect("admin").permissions.activate = false;
        let replacement = snapshot_with_secret(b"new-token");
        snapshot.resources.secrets = replacement.resources.secrets;
        assert_eq!(
            security
                .check_candidate(&snapshot)
                .expect_err("credential change is rejected")
                .code,
            "admin.restart_required"
        );
    }

    #[test]
    fn fixed_verification_keys_cannot_rotate_under_an_unchanged_path() {
        let directory = tempdir().expect("tempdir");
        let key_path = directory.path().join("operator.pub");
        let first = oxidase_bundle::BundleSigningKey::from_bytes("operator", &[11; 32])
            .expect("signing fixture")
            .verification_key();
        fs::write(&key_path, first.as_bytes()).expect("write public key");
        let mut snapshot = snapshot_with_secret(b"fixed-token");
        snapshot
            .admin
            .as_mut()
            .expect("admin")
            .bundle_trust
            .verification_keys = vec![key_path.clone()];
        let security =
            AdminSecurityPolicy::prepare(&snapshot).expect("bootstrap captures verification bytes");
        security
            .check_candidate(&snapshot)
            .expect("same key accepted");
        let replacement = oxidase_bundle::BundleSigningKey::from_bytes("operator", &[12; 32])
            .expect("signing fixture")
            .verification_key();
        fs::write(&key_path, replacement.as_bytes()).expect("replace bytes at same path");
        assert_eq!(
            security
                .check_candidate(&snapshot)
                .expect_err("rotation needs restart")
                .code,
            "admin.restart_required"
        );
    }

    #[test]
    fn data_only_site_cannot_reexpose_fixed_admin_token_via_hardlink() {
        let directory = tempdir().expect("tempdir");
        let token = directory.path().join("distinctive-admin-token");
        fs::write(&token, b"fixed-admin-credential").expect("token");
        let source = directory.path().join("gateway.yaml");
        fs::write(
            &source,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: distinctive-admin-token
admin:
  listen:
    unix:
      path: {socket}
  auth:
    mode: bearer
    token_secret: token
  storage:
    directory: {storage}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
                socket = directory.path().join("admin.sock").display(),
                storage = directory.path().join("state").display()
            ),
        )
        .expect("bootstrap source");
        let bootstrap =
            RuntimeSnapshot::prepare(Compiler::compile_path(&source).expect("compile bootstrap"))
                .expect("prepare bootstrap");
        let security =
            AdminSecurityPolicy::prepare(&bootstrap).expect("capture independent Admin trust");
        drop(bootstrap);
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\nvisibility:\n  deny: []\n",
        )
        .expect("manifest");
        fs::hard_link(&token, site.join("public.txt")).expect("public hardlink");
        fs::write(
            &source,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: site
      site: web
"#,
        )
        .expect("data-only source");
        let candidate =
            RuntimeSnapshot::prepare(Compiler::compile_path(&source).expect("compile data-only"))
                .expect("candidate-only isolation has no token reference");
        assert!(candidate.admin.is_none());
        let error = security
            .check_candidate(&candidate)
            .expect_err("bootstrap sensitive file cannot become public");
        assert_eq!(error.code, "admin.sensitive_asset_overlap");
        assert!(!error.to_string().contains("distinctive-admin-token"));
        assert!(!error.to_string().contains("fixed-admin-credential"));
    }

    #[test]
    fn audit_output_cannot_append_to_the_bootstrap_token() {
        let directory = tempdir().expect("tempdir");
        let token = directory.path().join("token");
        fs::write(&token, b"fixed-admin-token").expect("token");
        let source = directory.path().join("gateway.yaml");
        fs::write(
            &source,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: token
admin:
  listen:
    unix:
      path: {socket}
  auth:
    mode: bearer
    token_secret: token
  storage:
    directory: {storage}
  audit:
    destination: file
    file: {token}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
                socket = directory.path().join("admin.sock").display(),
                storage = directory.path().join("state").display(),
                token = token.display()
            ),
        )
        .expect("source");
        let snapshot = RuntimeSnapshot::prepare(Compiler::compile_path(&source).expect("compile"))
            .expect("prepare resources");
        assert_eq!(
            AdminSecurityPolicy::prepare(&snapshot)
                .expect_err("audit must not append to credential")
                .code,
            "admin.audit_sensitive_overlap"
        );
        assert_eq!(
            fs::read(&token).expect("credential unchanged"),
            b"fixed-admin-token"
        );
    }

    #[test]
    fn bearer_prepare_validates_one_line_contract_and_mtls_identity_is_verified_shape() {
        for bytes in [
            b"".as_slice(),
            b"token\n\n",
            b"token ",
            b"token\r",
            b"internal space",
        ] {
            let snapshot = snapshot_with_secret(bytes);
            assert_eq!(
                AdminSecurityPolicy::prepare(&snapshot)
                    .expect_err("invalid token")
                    .code,
                "admin.token_invalid"
            );
        }
        let mut policy = AdminSecurityPolicy::legacy_loopback_read_only();
        policy.authentication = AdminAuthentication::Mtls;
        let spoof = AdminPeerIdentity {
            verified_client_sha256: Some("user-supplied-subject".to_owned()),
        };
        assert_eq!(
            policy.authorize(&HeaderMap::new(), &spoof, AdminPermission::Read),
            Err(AdminSecurityError::Unauthenticated)
        );
        let peer = AdminPeerIdentity {
            verified_client_sha256: Some("a".repeat(64)),
        };
        assert!(matches!(
            policy.authorize(&HeaderMap::new(), &peer, AdminPermission::Read),
            Ok(AdminPrincipal::Mtls(_))
        ));
        let verified_runtime_peer = AdminPeerIdentity {
            verified_client_sha256: Some(format!("sha256:{}", "A".repeat(64))),
        };
        assert_eq!(
            policy.authorize(
                &HeaderMap::new(),
                &verified_runtime_peer,
                AdminPermission::Read
            ),
            Ok(AdminPrincipal::Mtls("a".repeat(64)))
        );
    }

    #[test]
    fn duplicate_condition_and_content_type_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(ADMIN_BUNDLE_CONTENT_TYPE),
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"runtime-1\""));
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"runtime-1\""));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"runtime-1\"", 64),
            Err(AdminSecurityError::InvalidHeaders)
        );
        headers.remove(header::IF_MATCH);
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"runtime-1\""));
        headers.append(
            header::CONTENT_TYPE,
            HeaderValue::from_static(ADMIN_BUNDLE_CONTENT_TYPE),
        );
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "\"runtime-1\"", 64),
            Err(AdminSecurityError::UnsupportedMediaType)
        );
    }

    #[test]
    fn if_match_shape_and_idempotency_key_are_checked_without_blocking_proven_replay() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(ADMIN_JSON_CONTENT_TYPE),
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"older:1\""));
        assert_eq!(
            super::validate_mutation_header_shape(&headers, ADMIN_JSON_CONTENT_TYPE, 64),
            Ok(())
        );
        for invalid in [
            "*",
            "W/\"boot:1\"",
            "\"boot:1\", \"boot:2\"",
            "\"space value\"",
        ] {
            headers.insert(
                header::IF_MATCH,
                HeaderValue::from_str(invalid).expect("header value"),
            );
            assert_eq!(
                super::validate_mutation_header_shape(&headers, ADMIN_JSON_CONTENT_TYPE, 64),
                Err(AdminSecurityError::InvalidHeaders)
            );
        }
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"boot:1\""));
        for invalid in [String::new(), "two words".to_owned(), "x".repeat(257)] {
            headers.insert(
                "idempotency-key",
                HeaderValue::from_str(&invalid).expect("header value"),
            );
            assert_eq!(
                super::validate_mutation_header_shape(&headers, ADMIN_JSON_CONTENT_TYPE, 64),
                Err(AdminSecurityError::InvalidHeaders)
            );
        }
        headers.insert("idempotency-key", HeaderValue::from_static("activation-1"));
        headers.append("idempotency-key", HeaderValue::from_static("activation-1"));
        assert_eq!(
            super::validate_mutation_header_shape(&headers, ADMIN_JSON_CONTENT_TYPE, 64),
            Err(AdminSecurityError::InvalidHeaders)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_rejects_symlink_and_live_socket_and_removes_stale_socket() {
        use std::os::unix::fs::symlink;

        use super::unix_socket::BoundUnixAdmin;

        let directory = tempdir().expect("temporary directory is available");
        let target = directory.path().join("target");
        fs::write(&target, b"do-not-remove").expect("target writes");
        let symlink_path = directory.path().join("symlink.sock");
        symlink(&target, &symlink_path).expect("symlink creates");
        let error = BoundUnixAdmin::bind(&symlink_path, 0o600)
            .await
            .err()
            .expect("symlink is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).expect("target remains"), b"do-not-remove");

        let live_path = directory.path().join("live.sock");
        let live = BoundUnixAdmin::bind(&live_path, 0o600)
            .await
            .expect("first listener binds");
        let error = BoundUnixAdmin::bind(&live_path, 0o600)
            .await
            .err()
            .expect("live listener is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        drop(live);
        assert!(!live_path.exists());

        let stale_path = directory.path().join("stale.sock");
        let stale = std::os::unix::net::UnixListener::bind(&stale_path)
            .expect("stale fixture socket binds");
        drop(stale);
        let replacement = BoundUnixAdmin::bind(&stale_path, 0o620)
            .await
            .expect("stale socket is replaced");
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::symlink_metadata(replacement.path())
                .expect("socket metadata")
                .permissions()
                .mode()
                & 0o777,
            0o620
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_cleanup_does_not_remove_replacement_inode() {
        use super::unix_socket::BoundUnixAdmin;

        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("admin.sock");
        let owner = BoundUnixAdmin::bind(&path, 0o600)
            .await
            .expect("owner binds");
        fs::remove_file(&path).expect("fixture unlinks owner path");
        let replacement =
            std::os::unix::net::UnixListener::bind(&path).expect("replacement fixture binds");
        drop(owner);
        assert!(
            path.exists(),
            "identity checked cleanup preserves replacement"
        );
        drop(replacement);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_parent_permissions_and_replacement_are_checked() {
        use super::unix_socket::BoundUnixAdmin;
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempdir().expect("tempdir");
        let parent = directory.path().join("private");
        fs::create_dir(&parent).expect("parent");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).expect("mode");
        assert_eq!(
            BoundUnixAdmin::bind(&parent.join("admin.sock"), 0o600)
                .await
                .err()
                .expect("writable parent fails")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).expect("mode");
        let mut owner = BoundUnixAdmin::bind(&parent.join("admin.sock"), 0o600)
            .await
            .expect("bind private parent");
        fs::rename(&parent, directory.path().join("old")).expect("move parent");
        fs::create_dir(&parent).expect("replacement parent");
        let replacement = std::os::unix::net::UnixListener::bind(parent.join("admin.sock"))
            .expect("replacement socket");
        assert_eq!(
            owner
                .cleanup()
                .expect_err("parent replacement rejects cleanup")
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(parent.join("admin.sock").exists());
        drop(replacement);
    }
}
