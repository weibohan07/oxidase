//! Security boundary shared by every administration transport.
//!
//! Transport code supplies only authenticated connection facts. This module
//! performs bearer verification, maps routes to bounded permissions, checks
//! mutation preconditions, and emits redacted audit fields. It deliberately
//! never retains or formats bearer-token bytes.

use std::fmt;

use http::{HeaderMap, Method, StatusCode, header};
use oxidase_core::ResourceId;
use oxidase_runtime::RuntimeSnapshot;

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
    Bearer(ResourceId),
    Mtls,
    BearerAndMtls(ResourceId),
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
pub(crate) struct AdminSecurityPolicy {
    pub(crate) authentication: AdminAuthentication,
    pub(crate) permissions: AdminPermissions,
}

impl AdminSecurityPolicy {
    pub(crate) const fn legacy_loopback_read_only() -> Self {
        Self {
            authentication: AdminAuthentication::UnsafeDevelopment,
            permissions: AdminPermissions::read_only(),
        }
    }

    pub(crate) fn authorize(
        &self,
        headers: &HeaderMap,
        peer: &AdminPeerIdentity,
        snapshot: &RuntimeSnapshot,
        permission: AdminPermission,
    ) -> Result<AdminPrincipal, AdminSecurityError> {
        let bearer = match &self.authentication {
            AdminAuthentication::Bearer(secret) | AdminAuthentication::BearerAndMtls(secret) => {
                Some(authenticate_bearer(headers, snapshot, secret)?)
            }
            AdminAuthentication::UnsafeDevelopment | AdminAuthentication::Mtls => None,
        };
        let certificate = match self.authentication {
            AdminAuthentication::Mtls | AdminAuthentication::BearerAndMtls(_) => {
                Some(authenticate_mtls(peer)?)
            }
            AdminAuthentication::UnsafeDevelopment | AdminAuthentication::Bearer(_) => None,
        };
        if !self.permissions.allows(permission) {
            return Err(AdminSecurityError::Forbidden);
        }
        Ok(match (bearer, certificate) {
            (Some(()), Some(identity)) => AdminPrincipal::BearerAndMtls(identity),
            (Some(()), None) => AdminPrincipal::Bearer,
            (None, Some(identity)) => AdminPrincipal::Mtls(identity),
            (None, None) => AdminPrincipal::UnsafeDevelopment,
        })
    }
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
    PreconditionFailed,
    UnsupportedMediaType,
    PayloadTooLarge,
}

impl AdminSecurityError {
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::Unauthenticated => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "admin.unauthenticated",
            Self::Forbidden => "admin.forbidden",
            Self::PreconditionRequired => "admin.precondition_required",
            Self::PreconditionFailed => "admin.precondition_failed",
            Self::UnsupportedMediaType => "admin.unsupported_media_type",
            Self::PayloadTooLarge => "admin.payload_too_large",
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
        && matches!(
            path,
            "/health/live"
                | "/health/ready"
                | "/metrics"
                | "/api/v1/clusters"
                | "/api/v1/runtime"
                | "/api/v1/snapshots/current"
                | "/api/v1/snapshots"
        )
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
        && identifier.len() <= 128
        && identifier.bytes().all(|byte| byte.is_ascii_hexdigit())
        && actual_action == action
}

pub(crate) fn validate_mutation_headers(
    headers: &HeaderMap,
    expected_content_type: &'static str,
    current_version: &str,
    max_body_bytes: u64,
) -> Result<(), AdminSecurityError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some(expected_content_type) {
        return Err(AdminSecurityError::UnsupportedMediaType);
    }
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if content_length.is_some_and(|length| length > max_body_bytes) {
        return Err(AdminSecurityError::PayloadTooLarge);
    }
    let Some(if_match) = headers.get(header::IF_MATCH) else {
        return Err(AdminSecurityError::PreconditionRequired);
    };
    let Ok(if_match) = if_match.to_str() else {
        return Err(AdminSecurityError::PreconditionFailed);
    };
    let expected = format!("\"{current_version}\"");
    if if_match != expected {
        return Err(AdminSecurityError::PreconditionFailed);
    }
    Ok(())
}

fn authenticate_bearer(
    headers: &HeaderMap,
    snapshot: &RuntimeSnapshot,
    secret: &ResourceId,
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
    if candidate.is_empty() || candidate.len() > 8 * 1024 {
        return Err(AdminSecurityError::Unauthenticated);
    }
    let Some(prepared) = snapshot.resources.secrets.get(secret) else {
        return Err(AdminSecurityError::Unauthenticated);
    };
    if prepared.constant_time_eq(candidate) {
        Ok(())
    } else {
        Err(AdminSecurityError::Unauthenticated)
    }
}

fn authenticate_mtls(peer: &AdminPeerIdentity) -> Result<String, AdminSecurityError> {
    peer.verified_client_sha256
        .clone()
        .filter(|fingerprint| !fingerprint.is_empty() && fingerprint.len() <= 128)
        .ok_or(AdminSecurityError::Unauthenticated)
}

#[cfg(unix)]
pub(crate) mod unix_socket {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

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
    }

    impl BoundUnixAdmin {
        pub(crate) fn bind(path: &Path, mode: u32) -> io::Result<Self> {
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
            let parent_metadata = fs::metadata(parent)?;
            if !parent_metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unix admin socket parent is not a directory",
                ));
            }
            reject_or_remove_stale(path)?;
            let listener = UnixListener::bind(path)?;
            if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
                let _ = remove_socket_if_matches(path, None);
                return Err(error);
            }
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.file_type().is_socket() {
                let _ = fs::remove_file(path);
                return Err(io::Error::other(
                    "Unix admin listener path is not a socket after bind",
                ));
            }
            Ok(Self {
                listener,
                path: path.to_path_buf(),
                device: metadata.dev(),
                inode: metadata.ino(),
                cleaned: false,
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
            remove_socket_if_matches(&self.path, Some((self.device, self.inode)))
        }
    }

    impl Drop for BoundUnixAdmin {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    fn reject_or_remove_stale(path: &Path) -> io::Result<()> {
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
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "Unix admin socket is already accepting connections",
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                remove_socket_if_matches(path, Some((metadata.dev(), metadata.ino())))
            }
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("cannot prove Unix admin socket is stale: {error}"),
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use http::{HeaderMap, HeaderValue, Method, header};
    use oxidase_config::Compiler;
    use oxidase_core::ResourceId;
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;

    use super::{
        ADMIN_BUNDLE_CONTENT_TYPE, AdminAuthentication, AdminPeerIdentity, AdminPermission,
        AdminPermissions, AdminPrincipal, AdminSecurityError, AdminSecurityPolicy,
        classify_admin_route, validate_mutation_headers,
    };

    fn snapshot_with_secret(value: &[u8]) -> RuntimeSnapshot {
        let directory = tempdir().expect("temporary directory is available");
        fs::write(directory.path().join("token"), value).expect("token can be written");
        fs::write(
            directory.path().join("oxidase.yaml"),
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    admin-token:
      file: token
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
            authentication: AdminAuthentication::Bearer(ResourceId::new("secret:admin-token")),
            permissions: all_permissions(),
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
                &snapshot,
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
                &snapshot,
                AdminPermission::Read,
            ),
            Err(AdminSecurityError::Unauthenticated)
        );
    }

    #[test]
    fn combined_auth_requires_both_factors_and_rbac_is_independent() {
        let snapshot = snapshot_with_secret(b"correct-token");
        let policy = AdminSecurityPolicy {
            authentication: AdminAuthentication::BearerAndMtls(ResourceId::new(
                "secret:admin-token",
            )),
            permissions: AdminPermissions::read_only(),
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
                &snapshot,
                AdminPermission::Read,
            ),
            Err(AdminSecurityError::Unauthenticated)
        );
        let peer = AdminPeerIdentity {
            verified_client_sha256: Some("sha256-client".to_owned()),
        };
        let principal = policy
            .authorize(&headers, &peer, &snapshot, AdminPermission::Read)
            .expect("both factors authenticate");
        assert_eq!(principal.audit_id(), "sha256-client");
        assert_eq!(principal.authentication_kind(), "bearer_and_mtls");
        assert_eq!(
            policy.authorize(&headers, &peer, &snapshot, AdminPermission::Activate),
            Err(AdminSecurityError::Forbidden)
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
            "/api/v1/candidates/0123456789abcdef/activate",
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
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "version-1", 64),
            Ok(())
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("65"));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "version-1", 64),
            Err(AdminSecurityError::PayloadTooLarge)
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("64"));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"stale\""));
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "version-1", 64),
            Err(AdminSecurityError::PreconditionFailed)
        );
        headers.remove(header::IF_MATCH);
        assert_eq!(
            validate_mutation_headers(&headers, ADMIN_BUNDLE_CONTENT_TYPE, "version-1", 64),
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
            .err()
            .expect("symlink is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).expect("target remains"), b"do-not-remove");

        let live_path = directory.path().join("live.sock");
        let live = BoundUnixAdmin::bind(&live_path, 0o600).expect("first listener binds");
        let error = BoundUnixAdmin::bind(&live_path, 0o600)
            .err()
            .expect("live listener is rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        drop(live);
        assert!(!live_path.exists());

        let stale_path = directory.path().join("stale.sock");
        let stale = std::os::unix::net::UnixListener::bind(&stale_path)
            .expect("stale fixture socket binds");
        drop(stale);
        let replacement =
            BoundUnixAdmin::bind(&stale_path, 0o620).expect("stale socket is replaced");
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
        let owner = BoundUnixAdmin::bind(&path, 0o600).expect("owner binds");
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
}
