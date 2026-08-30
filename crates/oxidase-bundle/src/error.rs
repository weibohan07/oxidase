use std::fmt;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleErrorKind {
    Io,
    Truncated,
    InvalidMagic,
    UnsupportedFormatVersion,
    UnsupportedFlags,
    LimitExceeded,
    LengthMismatch,
    InvalidManifest,
    NonCanonicalManifest,
    UnsupportedSchema,
    ContentDigestMismatch,
    BlobDigestMismatch,
    DuplicateBlob,
    InvalidSignatureEnvelope,
    NonCanonicalSignatureEnvelope,
    InvalidModel,
    UnsupportedRequiredFeature,
    UnsupportedRequiredSection,
    InvalidRuntimeVersion,
    RuntimeTooOld,
    InvalidSigningKey,
    SignatureRequired,
    SignatureVerificationFailed,
}

impl BundleErrorKind {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Io => "bundle.io",
            Self::Truncated => "bundle.truncated",
            Self::InvalidMagic => "bundle.invalid_magic",
            Self::UnsupportedFormatVersion => "bundle.unsupported_format_version",
            Self::UnsupportedFlags => "bundle.unsupported_flags",
            Self::LimitExceeded => "bundle.limit_exceeded",
            Self::LengthMismatch => "bundle.length_mismatch",
            Self::InvalidManifest => "bundle.invalid_manifest",
            Self::NonCanonicalManifest => "bundle.non_canonical_manifest",
            Self::UnsupportedSchema => "bundle.unsupported_schema",
            Self::ContentDigestMismatch => "bundle.content_digest_mismatch",
            Self::BlobDigestMismatch => "bundle.blob_digest_mismatch",
            Self::DuplicateBlob => "bundle.duplicate_blob",
            Self::InvalidSignatureEnvelope => "bundle.invalid_signature_envelope",
            Self::NonCanonicalSignatureEnvelope => "bundle.non_canonical_signature_envelope",
            Self::InvalidModel => "bundle.invalid_model",
            Self::UnsupportedRequiredFeature => "bundle.unsupported_required_feature",
            Self::UnsupportedRequiredSection => "bundle.unsupported_required_section",
            Self::InvalidRuntimeVersion => "bundle.invalid_runtime_version",
            Self::RuntimeTooOld => "bundle.runtime_too_old",
            Self::InvalidSigningKey => "bundle.invalid_signing_key",
            Self::SignatureRequired => "bundle.signature_required",
            Self::SignatureVerificationFailed => "bundle.signature_verification_failed",
        }
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct BundleError {
    kind: BundleErrorKind,
    message: String,
    offset: Option<u64>,
}

impl BundleError {
    #[must_use]
    pub fn new(kind: BundleErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            offset: None,
        }
    }

    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub const fn kind(&self) -> BundleErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        self.offset
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn io(error: std::io::Error, operation: &'static str) -> Self {
        Self::new(Self::io_kind(), format!("failed to {operation}: {error}"))
    }

    const fn io_kind() -> BundleErrorKind {
        BundleErrorKind::Io
    }
}

impl From<serde_json::Error> for BundleError {
    fn from(error: serde_json::Error) -> Self {
        Self::new(
            BundleErrorKind::InvalidManifest,
            format!("bundle manifest is not valid canonical JSON: {error}"),
        )
    }
}

impl From<fmt::Error> for BundleError {
    fn from(_error: fmt::Error) -> Self {
        Self::new(
            BundleErrorKind::InvalidModel,
            "failed to format bundle metadata",
        )
    }
}
