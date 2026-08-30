//! Opaque, bounded file-backed Secret resources.
//!
//! Secret bytes never enter the compiled configuration. They are read and
//! validated while preparing a candidate snapshot, then retained behind an
//! API that supports only constant-time comparison and explicit size checks.

use std::fmt;
use std::io::Read as _;
use std::sync::Arc;

use oxidase_config::SecretSpec;
use oxidase_core::{ContentDigest, Diagnostic};
use serde::{Serialize, Serializer};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::regular_file::{RegularFileOpenError, open_regular_file};

/// Opaque Secret material owned by a prepared runtime snapshot.
///
/// Clones share one allocation. The final owner zeroizes that allocation on
/// drop. This is a best-effort memory hygiene boundary: the operating system,
/// allocator, filesystem cache, and copies made outside this type are beyond
/// its control.
#[derive(Clone)]
pub struct SecretBytes(Arc<SecretStorage>);

struct SecretStorage(Zeroizing<Vec<u8>>);

impl SecretBytes {
    fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(Arc::new(SecretStorage(bytes)))
    }

    /// Compares a candidate without data-dependent early exit for equal-length
    /// inputs. Candidate length is already observable at the caller boundary.
    #[must_use]
    pub fn constant_time_eq(&self, candidate: &[u8]) -> bool {
        self.0.0.len() == candidate.len() && bool::from(self.0.0.as_slice().ct_eq(candidate))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

impl Serialize for SecretBytes {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        serializer.serialize_str("<redacted>")
    }
}

/// One validated Secret resource.
#[derive(Clone)]
pub struct PreparedSecret {
    pub id: oxidase_core::ResourceId,
    bytes: SecretBytes,
    fingerprint: ContentDigest,
    version_token: ContentDigest,
}

impl PreparedSecret {
    pub(crate) fn prepare(
        source: &SecretSpec,
    ) -> Result<PreparedSecretCandidate, SecretPreparationFailure> {
        let (file, metadata) =
            open_regular_file(&source.file).map_err(|error| secret_open_failure(source, error))?;
        if metadata.len() > source.max_bytes {
            return Err(too_large(source));
        }

        // Protect the allocation from its first byte so read errors, oversize
        // failures, and later preparation failures all zeroize the partial
        // material on drop.
        let mut bytes = Zeroizing::new(Vec::new());
        let mut bounded = file.take(source.max_bytes.saturating_add(1));
        bounded.read_to_end(&mut bytes).map_err(|error| {
            SecretPreparationFailure::new(
                SecretPreparationErrorKind::Read,
                "secret.file_read",
                format!("cannot read secret file: {error}"),
                source.file_source.clone(),
            )
        })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > source.max_bytes {
            return Err(too_large(source));
        }

        let fingerprint = ContentDigest::of_bytes(bytes.as_slice());
        let mut random_token = [0_u8; 32];
        rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random_token)
            .map_err(|_| {
                SecretPreparationFailure::new(
                    SecretPreparationErrorKind::Random,
                    "secret.version_token",
                    "cannot generate an opaque Secret version token",
                    source.source.clone(),
                )
            })?;
        let warnings = secret_permission_warnings(source, &metadata);
        Ok(PreparedSecretCandidate {
            secret: PreparedSecret {
                id: source.id.clone(),
                bytes: SecretBytes::new(bytes),
                fingerprint,
                version_token: ContentDigest::of_bytes(random_token),
            },
            warnings,
        })
    }

    #[must_use]
    pub fn value(&self) -> &SecretBytes {
        &self.bytes
    }

    #[must_use]
    pub fn constant_time_eq(&self, candidate: &[u8]) -> bool {
        self.bytes.constant_time_eq(candidate)
    }

    pub(crate) const fn fingerprint(&self) -> ContentDigest {
        self.fingerprint
    }

    pub(crate) const fn version_token(&self) -> ContentDigest {
        self.version_token
    }
}

fn secret_open_failure(
    source: &SecretSpec,
    error: RegularFileOpenError,
) -> SecretPreparationFailure {
    match error {
        RegularFileOpenError::Inspect(error) | RegularFileOpenError::Open(error) => {
            let missing = error.kind() == std::io::ErrorKind::NotFound;
            SecretPreparationFailure::new(
                if missing {
                    SecretPreparationErrorKind::Missing
                } else {
                    SecretPreparationErrorKind::Read
                },
                if missing {
                    "secret.file_missing"
                } else {
                    "secret.file_read"
                },
                if missing {
                    "secret file does not exist".to_owned()
                } else {
                    format!("cannot safely open secret file: {error}")
                },
                source.file_source.clone(),
            )
        }
        RegularFileOpenError::NotRegular | RegularFileOpenError::ChangedType => {
            SecretPreparationFailure::new(
                SecretPreparationErrorKind::NotFile,
                "secret.file_not_regular",
                "secret path must resolve to a stable regular file",
                source.file_source.clone(),
            )
        }
    }
}

impl fmt::Debug for PreparedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSecret")
            .field("id", &self.id)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Serialize for PreparedSecret {
    fn serialize<SerializerType>(
        &self,
        serializer: SerializerType,
    ) -> Result<SerializerType::Ok, SerializerType::Error>
    where
        SerializerType: Serializer,
    {
        serializer.serialize_str("<redacted>")
    }
}

#[derive(Debug)]
pub(crate) struct PreparedSecretCandidate {
    pub secret: PreparedSecret,
    pub warnings: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPreparationErrorKind {
    Missing,
    NotFile,
    Read,
    TooLarge,
    Random,
}

impl fmt::Display for SecretPreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "secret file does not exist",
            Self::NotFile => "secret path is not a regular file",
            Self::Read => "secret file cannot be read",
            Self::TooLarge => "secret file exceeds its configured size limit",
            Self::Random => "opaque Secret version-token generation failed",
        })
    }
}

#[derive(Debug)]
pub(crate) struct SecretPreparationFailure {
    pub kind: SecretPreparationErrorKind,
    pub diagnostic: Box<Diagnostic>,
}

impl SecretPreparationFailure {
    fn new(
        kind: SecretPreparationErrorKind,
        code: &'static str,
        message: impl Into<String>,
        primary: oxidase_core::SourceSpan,
    ) -> Self {
        Self {
            kind,
            diagnostic: Box::new(Diagnostic::new(code, message, primary)),
        }
    }
}

fn too_large(source: &SecretSpec) -> SecretPreparationFailure {
    SecretPreparationFailure::new(
        SecretPreparationErrorKind::TooLarge,
        "secret.file_too_large",
        format!(
            "secret file exceeds the configured {} byte limit",
            source.max_bytes
        ),
        source.max_bytes_source.clone(),
    )
}

#[cfg(unix)]
fn secret_permission_warnings(
    source: &SecretSpec,
    metadata: &std::fs::Metadata,
) -> Vec<Diagnostic> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 == 0 {
        Vec::new()
    } else {
        vec![
            Diagnostic::warning(
                "secret.file_permissions",
                format!("secret file permissions {mode:04o} allow group or other access"),
                source.file_source.clone(),
            )
            .with_help("restrict the secret file to its owning account, for example mode 0600"),
        ]
    }
}

#[cfg(not(unix))]
fn secret_permission_warnings(
    _source: &SecretSpec,
    _metadata: &std::fs::Metadata,
) -> Vec<Diagnostic> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oxidase_config::SecretSpec;
    use oxidase_core::{ResourceId, SourceSpan};
    use tempfile::tempdir;

    use super::{PreparedSecret, SecretPreparationErrorKind};

    fn spec(path: std::path::PathBuf, max_bytes: u64) -> SecretSpec {
        SecretSpec {
            id: ResourceId::new("secret:test"),
            file: path,
            max_bytes,
            file_source: SourceSpan::synthetic("resources.secrets.test.file"),
            max_bytes_source: SourceSpan::synthetic("resources.secrets.test.max_bytes"),
            source: SourceSpan::synthetic("resources.secrets.test"),
        }
    }

    #[test]
    fn prepares_exact_limit_and_compares_without_exposing_bytes() {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("token");
        fs::write(&path, b"sixteen-byte-key").expect("secret can be written");
        let candidate = PreparedSecret::prepare(&spec(path, 16)).expect("secret prepares");
        let secret = candidate.secret;

        assert!(secret.constant_time_eq(b"sixteen-byte-key"));
        assert!(!secret.constant_time_eq(b"sixteen-byte-kex"));
        assert!(!secret.constant_time_eq(b"short"));
        assert_eq!(secret.value().len(), 16);
        assert!(!secret.value().is_empty());
        assert_eq!(secret.value().to_string(), "<redacted>");
        assert_eq!(
            serde_json::to_string(secret.value()).expect("SecretBytes serializes as redacted"),
            "\"<redacted>\""
        );
        assert_eq!(
            serde_json::to_string(&secret).expect("PreparedSecret serializes as redacted"),
            "\"<redacted>\""
        );
        let debug = format!("{secret:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("sixteen-byte-key"));
    }

    #[test]
    fn rejects_limit_plus_one_without_echoing_content_or_path() {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("distinctive-secret-name");
        fs::write(&path, b"limit+1").expect("secret can be written");
        let failure = PreparedSecret::prepare(&spec(path.clone(), 6))
            .expect_err("oversized secret must fail");

        assert_eq!(failure.kind, SecretPreparationErrorKind::TooLarge);
        let rendered = failure.diagnostic.to_string();
        assert!(!rendered.contains("limit+1"));
        assert!(!rendered.contains("distinctive-secret-name"));
    }

    #[test]
    fn rejects_missing_and_non_regular_files() {
        let directory = tempdir().expect("temporary directory is available");
        let missing = PreparedSecret::prepare(&spec(directory.path().join("missing"), 64))
            .expect_err("missing secret must fail");
        assert_eq!(missing.kind, SecretPreparationErrorKind::Missing);

        let not_file = PreparedSecret::prepare(&spec(directory.path().to_path_buf(), 64))
            .expect_err("directory must fail");
        assert_eq!(not_file.kind, SecretPreparationErrorKind::NotFile);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_fifo_without_waiting_for_a_writer() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempdir().expect("temporary directory is available");
        let fifo = directory.path().join("secret.fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO can be created");

        let failure = PreparedSecret::prepare(&spec(fifo, 64))
            .expect_err("a FIFO is never a Secret regular file");
        assert_eq!(failure.kind, SecretPreparationErrorKind::NotFile);
    }

    #[cfg(unix)]
    #[test]
    fn warns_about_group_or_other_permissions() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("token");
        fs::write(&path, b"secret").expect("secret can be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("permissions can be changed");
        let candidate = PreparedSecret::prepare(&spec(path, 64)).expect("secret prepares");
        assert_eq!(candidate.warnings.len(), 1);
        assert_eq!(candidate.warnings[0].code, "secret.file_permissions");
        assert_eq!(
            candidate.warnings[0].primary.field_path,
            "resources.secrets.test.file"
        );
    }
}
