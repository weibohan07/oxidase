//! Strict custom CA-bundle preparation.

use std::fmt;
use std::io::Read as _;
use std::sync::Arc;

use oxidase_config::TrustStoreSpec;
use oxidase_core::{ContentDigest, ContentDigestBuilder, Diagnostic};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, pem::PemObject as _};

use crate::regular_file::{RegularFileOpenError, open_regular_file};

const MAX_TRUST_STORE_BYTES: u64 = 16 * 1024 * 1024;

/// A non-empty, normalized collection of custom trust anchors.
#[derive(Clone)]
pub struct PreparedTrustStore {
    pub id: oxidase_core::ResourceId,
    digest: ContentDigest,
    roots: Arc<RootCertStore>,
    certificates: Arc<Vec<CertificateDer<'static>>>,
}

impl PreparedTrustStore {
    pub(crate) fn prepare(source: &TrustStoreSpec) -> Result<Self, TrustStorePreparationFailure> {
        let (file, metadata) = open_regular_file(&source.ca_bundle)
            .map_err(|error| trust_store_open_failure(source, error))?;
        if metadata.len() > MAX_TRUST_STORE_BYTES {
            return Err(too_large(source));
        }

        let mut bytes = Vec::new();
        file.take(MAX_TRUST_STORE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                TrustStorePreparationFailure::new(
                    TrustStorePreparationErrorKind::Read,
                    "trust_store.file_read",
                    format!("cannot read trust-store CA bundle: {error}"),
                    source.ca_bundle_source.clone(),
                )
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_TRUST_STORE_BYTES {
            return Err(too_large(source));
        }
        validate_certificate_only_envelope(&bytes, source)?;

        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                TrustStorePreparationFailure::new(
                    TrustStorePreparationErrorKind::Pem,
                    "trust_store.pem",
                    format!("trust-store CA bundle is not valid PEM: {error}"),
                    source.ca_bundle_source.clone(),
                )
            })?;
        Self::prepare_certificates(source, certificates)
    }

    /// Prepares a trust store from normalized public DER carried by a verified
    /// Bundle. No source CA file is read on this path.
    pub(crate) fn prepare_with_public_roots(
        source: &TrustStoreSpec,
        certificates: &[Vec<u8>],
    ) -> Result<Self, TrustStorePreparationFailure> {
        Self::prepare_certificates(
            source,
            certificates
                .iter()
                .cloned()
                .map(CertificateDer::from)
                .collect(),
        )
    }

    fn prepare_certificates(
        source: &TrustStoreSpec,
        mut certificates: Vec<CertificateDer<'static>>,
    ) -> Result<Self, TrustStorePreparationFailure> {
        if certificates.is_empty() {
            return Err(TrustStorePreparationFailure::new(
                TrustStorePreparationErrorKind::Empty,
                "trust_store.empty",
                "trust-store CA bundle must contain at least one CERTIFICATE section",
                source.ca_bundle_source.clone(),
            ));
        }

        certificates.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        certificates.dedup_by(|left, right| left.as_ref() == right.as_ref());

        let mut roots = RootCertStore::empty();
        for certificate in &certificates {
            roots.add(certificate.clone()).map_err(|error| {
                TrustStorePreparationFailure::new(
                    TrustStorePreparationErrorKind::Certificate,
                    "trust_store.certificate",
                    format!("trust-store CA bundle contains an invalid certificate: {error}"),
                    source.ca_bundle_source.clone(),
                )
            })?;
        }

        let mut digest = ContentDigestBuilder::new("oxidase/trust-store/v1");
        digest.field_u64("certificate_count", certificates.len() as u64);
        for certificate in &certificates {
            digest.field_bytes("certificate_der", certificate.as_ref());
        }

        Ok(Self {
            id: source.id.clone(),
            digest: digest.finish(),
            roots: Arc::new(roots),
            certificates: Arc::new(certificates),
        })
    }

    #[must_use]
    pub fn certificate_count(&self) -> usize {
        self.roots.len()
    }

    #[must_use]
    pub fn roots(&self) -> Arc<RootCertStore> {
        Arc::clone(&self.roots)
    }

    /// Copies normalized public trust anchors for a portable Bundle.
    #[must_use]
    pub fn public_roots_der(&self) -> Vec<Vec<u8>> {
        self.certificates
            .iter()
            .map(|certificate| certificate.as_ref().to_vec())
            .collect()
    }

    pub(crate) const fn digest(&self) -> ContentDigest {
        self.digest
    }
}

fn trust_store_open_failure(
    source: &TrustStoreSpec,
    error: RegularFileOpenError,
) -> TrustStorePreparationFailure {
    match error {
        RegularFileOpenError::Inspect(error) | RegularFileOpenError::Open(error) => {
            let missing = error.kind() == std::io::ErrorKind::NotFound;
            TrustStorePreparationFailure::new(
                if missing {
                    TrustStorePreparationErrorKind::Missing
                } else {
                    TrustStorePreparationErrorKind::Read
                },
                if missing {
                    "trust_store.file_missing"
                } else {
                    "trust_store.file_read"
                },
                if missing {
                    "trust-store CA bundle does not exist".to_owned()
                } else {
                    format!("cannot safely open trust-store CA bundle: {error}")
                },
                source.ca_bundle_source.clone(),
            )
        }
        RegularFileOpenError::NotRegular | RegularFileOpenError::ChangedType => {
            TrustStorePreparationFailure::new(
                TrustStorePreparationErrorKind::NotFile,
                "trust_store.file_not_regular",
                "trust-store CA bundle path must resolve to a stable regular file",
                source.ca_bundle_source.clone(),
            )
        }
    }
}

fn validate_certificate_only_envelope(
    bytes: &[u8],
    source: &TrustStoreSpec,
) -> Result<(), TrustStorePreparationFailure> {
    if !bytes.is_ascii() {
        return Err(TrustStorePreparationFailure::new(
            TrustStorePreparationErrorKind::Pem,
            "trust_store.pem",
            "trust-store CA bundle must be ASCII PEM text",
            source.ca_bundle_source.clone(),
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        TrustStorePreparationFailure::new(
            TrustStorePreparationErrorKind::Pem,
            "trust_store.pem",
            "trust-store CA bundle must be ASCII PEM text",
            source.ca_bundle_source.clone(),
        )
    })?;
    let mut in_certificate = false;
    for line in text.lines() {
        let line = line.trim();
        if in_certificate {
            if line == "-----END CERTIFICATE-----" {
                in_certificate = false;
            } else if line.starts_with("-----BEGIN ") || line.starts_with("-----END ") {
                return Err(certificate_only_failure(source));
            }
        } else if line.is_empty() {
            continue;
        } else if line == "-----BEGIN CERTIFICATE-----" {
            in_certificate = true;
        } else {
            return Err(certificate_only_failure(source));
        }
    }
    if in_certificate {
        return Err(TrustStorePreparationFailure::new(
            TrustStorePreparationErrorKind::Pem,
            "trust_store.pem",
            "trust-store CA bundle has an unterminated CERTIFICATE section",
            source.ca_bundle_source.clone(),
        ));
    }
    Ok(())
}

fn certificate_only_failure(source: &TrustStoreSpec) -> TrustStorePreparationFailure {
    TrustStorePreparationFailure::new(
        TrustStorePreparationErrorKind::UnexpectedPemItem,
        "trust_store.pem_item",
        "trust-store CA bundle may contain only CERTIFICATE sections and whitespace",
        source.ca_bundle_source.clone(),
    )
}

impl fmt::Debug for PreparedTrustStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTrustStore")
            .field("id", &self.id)
            .field("certificate_count", &self.certificate_count())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustStorePreparationErrorKind {
    Missing,
    NotFile,
    Read,
    TooLarge,
    Pem,
    UnexpectedPemItem,
    Empty,
    Certificate,
}

impl fmt::Display for TrustStorePreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "trust-store CA bundle does not exist",
            Self::NotFile => "trust-store CA bundle is not a regular file",
            Self::Read => "trust-store CA bundle cannot be read",
            Self::TooLarge => "trust-store CA bundle exceeds its fixed size limit",
            Self::Pem => "trust-store CA bundle PEM is invalid",
            Self::UnexpectedPemItem => "trust-store CA bundle contains a non-certificate item",
            Self::Empty => "trust-store CA bundle is empty",
            Self::Certificate => "trust-store CA bundle contains an invalid certificate",
        })
    }
}

#[derive(Debug)]
pub(crate) struct TrustStorePreparationFailure {
    pub kind: TrustStorePreparationErrorKind,
    pub diagnostic: Box<Diagnostic>,
}

impl TrustStorePreparationFailure {
    fn new(
        kind: TrustStorePreparationErrorKind,
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

fn too_large(source: &TrustStoreSpec) -> TrustStorePreparationFailure {
    TrustStorePreparationFailure::new(
        TrustStorePreparationErrorKind::TooLarge,
        "trust_store.file_too_large",
        format!("trust-store CA bundle exceeds the fixed {MAX_TRUST_STORE_BYTES} byte limit"),
        source.ca_bundle_source.clone(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use oxidase_config::TrustStoreSpec;
    use oxidase_core::{ResourceId, SourceSpan};
    use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
    use tempfile::tempdir;

    use super::{PreparedTrustStore, TrustStorePreparationErrorKind};

    fn spec(path: std::path::PathBuf) -> TrustStoreSpec {
        TrustStoreSpec {
            id: ResourceId::new("trust-store:test"),
            ca_bundle: path,
            ca_bundle_source: SourceSpan::synthetic("resources.trust_stores.test.ca_bundle"),
            source: SourceSpan::synthetic("resources.trust_stores.test"),
        }
    }

    fn certificate(name: &str) -> String {
        let GeneratedCertificate { cert, .. } = generate_simple_self_signed(vec![name.to_owned()])
            .expect("test-only certificate can be generated");
        cert.pem()
    }

    #[test]
    fn deduplicates_der_and_has_order_stable_identity() {
        let directory = tempdir().expect("temporary directory is available");
        let first = certificate("first.example.test");
        let second = certificate("second.example.test");
        let left = directory.path().join("left.pem");
        let right = directory.path().join("right.pem");
        fs::write(&left, format!("{first}{second}{first}")).expect("first bundle can be written");
        fs::write(&right, format!("{second}{first}")).expect("second bundle can be written");

        let left = PreparedTrustStore::prepare(&spec(left)).expect("first bundle prepares");
        let right = PreparedTrustStore::prepare(&spec(right)).expect("second bundle prepares");
        assert_eq!(left.certificate_count(), 2);
        assert_eq!(right.certificate_count(), 2);
        assert_eq!(left.digest(), right.digest());
        assert_eq!(left.roots().len(), 2);
    }

    #[test]
    fn rejects_empty_and_non_certificate_pem() {
        let directory = tempdir().expect("temporary directory is available");
        let empty = directory.path().join("empty.pem");
        fs::write(&empty, b"").expect("empty bundle can be written");
        let failure =
            PreparedTrustStore::prepare(&spec(empty)).expect_err("empty trust store must fail");
        assert_eq!(failure.kind, TrustStorePreparationErrorKind::Empty);

        let private_key = directory.path().join("key.pem");
        fs::write(
            &private_key,
            include_bytes!("../tests/fixtures/test-only-rsa-key.pem"),
        )
        .expect("test-only key can be written");
        let failure = PreparedTrustStore::prepare(&spec(private_key))
            .expect_err("private key in trust store must fail");
        assert_eq!(
            failure.kind,
            TrustStorePreparationErrorKind::UnexpectedPemItem
        );

        let annotated = directory.path().join("annotated.pem");
        fs::write(
            &annotated,
            format!("operator note\n{}", certificate("note.example.test")),
        )
        .expect("annotated bundle can be written");
        let failure = PreparedTrustStore::prepare(&spec(annotated))
            .expect_err("non-PEM bundle text must fail strict preparation");
        assert_eq!(
            failure.kind,
            TrustStorePreparationErrorKind::UnexpectedPemItem
        );

        let non_ascii_whitespace = directory.path().join("non-ascii-whitespace.pem");
        fs::write(
            &non_ascii_whitespace,
            format!("\u{00a0}{}", certificate("ascii-only.example.test")),
        )
        .expect("non-ASCII fixture can be written");
        let failure = PreparedTrustStore::prepare(&spec(non_ascii_whitespace))
            .expect_err("non-ASCII whitespace is outside the strict PEM subset");
        assert_eq!(failure.kind, TrustStorePreparationErrorKind::Pem);
    }

    #[test]
    fn rejects_invalid_certificate_missing_and_directory() {
        let directory = tempdir().expect("temporary directory is available");
        let invalid = directory.path().join("invalid.pem");
        fs::write(
            &invalid,
            b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        )
        .expect("invalid certificate can be written");
        let failure =
            PreparedTrustStore::prepare(&spec(invalid)).expect_err("invalid certificate must fail");
        assert_eq!(failure.kind, TrustStorePreparationErrorKind::Certificate);

        let missing = PreparedTrustStore::prepare(&spec(directory.path().join("missing")))
            .expect_err("missing bundle must fail");
        assert_eq!(missing.kind, TrustStorePreparationErrorKind::Missing);

        let not_file = PreparedTrustStore::prepare(&spec(directory.path().to_path_buf()))
            .expect_err("directory must fail");
        assert_eq!(not_file.kind, TrustStorePreparationErrorKind::NotFile);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_a_fifo_without_waiting_for_a_writer() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempdir().expect("temporary directory is available");
        let fifo = directory.path().join("trust.fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO can be created");

        let failure = PreparedTrustStore::prepare(&spec(fifo))
            .expect_err("a FIFO is never a Trust Store regular file");
        assert_eq!(failure.kind, TrustStorePreparationErrorKind::NotFile);
    }

    #[test]
    fn debug_omits_bundle_bytes_and_paths() {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("distinctive-ca-bundle.pem");
        let certificate = certificate("debug.example.test");
        fs::write(&path, &certificate).expect("bundle can be written");
        let prepared = PreparedTrustStore::prepare(&spec(path)).expect("bundle prepares");
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("distinctive-ca-bundle"));
        assert!(!debug.contains(&certificate));
        assert!(debug.contains("certificate_count"));
    }
}
