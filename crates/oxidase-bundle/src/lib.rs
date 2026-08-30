#![forbid(unsafe_code)]

mod error;
mod format;
mod model;
mod signature;

pub use error::{BundleError, BundleErrorKind};
pub use format::{
    BundleArchive, BundleBuilder, BundleDiff, BundleInspection, BundleLimits, BundleVerification,
    InspectionVerbosity,
};
pub use model::{
    AssetDescriptor, AssetReferenceBase, AssetStorage, BUNDLE_SCHEMA_VERSION, BuildMetadata,
    BundleCapabilities, BundleDigest, BundleManifest, CanonicalBytes, CanonicalFloat,
    CanonicalValue, SIGNATURE_SCHEMA_VERSION, SensitiveReference, SensitiveReferenceKind,
    SignatureEnvelope, SignatureRecord, SourceOrigin, StableSection,
};
pub use signature::{
    BundleSigningKey, BundleVerificationKey, DEFAULT_KEY_FILE_LIMIT, SignatureRequirement,
    SignatureVerification,
};
