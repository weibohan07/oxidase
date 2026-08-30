use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oxidase_core::ContentHasher;
use serde::Serialize;

use crate::error::{BundleError, BundleErrorKind};
use crate::model::{
    AssetReferenceBase, AssetStorage, BUNDLE_SCHEMA_VERSION, BundleCapabilities, BundleDigest,
    BundleManifest, CanonicalValue, SIGNATURE_SCHEMA_VERSION, SignatureEnvelope, SignatureRecord,
};

const MAGIC: [u8; 8] = *b"OXB\0\r\n\x1a\n";
const FORMAT_VERSION: u16 = 1;
const FLAG_SIGNATURES: u16 = 1;
const KNOWN_FLAGS: u16 = FLAG_SIGNATURES;
const HEADER_LEN: usize = 8 + 2 + 2 + 8 + 8 + 32;
const CONTENT_DOMAIN: &[u8] = b"oxidase.bundle.content/v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleLimits {
    pub max_bundle_bytes: u64,
    pub max_manifest_bytes: u64,
    pub max_signature_bytes: u64,
    pub max_blob_count: u32,
    pub max_blob_bytes: u64,
    pub max_total_blob_bytes: u64,
    pub max_assets: usize,
    pub max_sections: usize,
    pub max_origins: usize,
    pub max_sensitive_references: usize,
    pub max_json_depth: usize,
    pub max_json_nodes: usize,
    pub max_string_bytes: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            max_bundle_bytes: 8 * 1024 * 1024 * 1024,
            max_manifest_bytes: 32 * 1024 * 1024,
            max_signature_bytes: 4 * 1024 * 1024,
            max_blob_count: 100_000,
            max_blob_bytes: 4 * 1024 * 1024 * 1024,
            max_total_blob_bytes: 8 * 1024 * 1024 * 1024,
            max_assets: 1_000_000,
            max_sections: 4_096,
            max_origins: 1_000_000,
            max_sensitive_references: 100_000,
            max_json_depth: 128,
            max_json_nodes: 1_000_000,
            max_string_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
struct BlobRecord {
    bytes: Option<Arc<[u8]>>,
    file_offset: u64,
    length: u64,
}

#[derive(Clone)]
pub struct BundleArchive {
    manifest: BundleManifest,
    blobs: BTreeMap<BundleDigest, BlobRecord>,
    signatures: SignatureEnvelope,
    content_digest: BundleDigest,
    file_digest: BundleDigest,
    encoded_size: u64,
    backing_file: Option<Arc<File>>,
}

impl fmt::Debug for BundleArchive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleArchive")
            .field("schema_version", &self.manifest.schema_version)
            .field("content_digest", &self.content_digest)
            .field("file_digest", &self.file_digest)
            .field("encoded_size", &self.encoded_size)
            .field("section_count", &self.manifest.sections.len())
            .field("asset_count", &self.manifest.assets.len())
            .field("embedded_blob_count", &self.blobs.len())
            .field(
                "sensitive_reference_count",
                &self.manifest.sensitive_references.len(),
            )
            .field("signature_count", &self.signatures.signatures.len())
            .field("file_backed", &self.backing_file.is_some())
            .finish()
    }
}

impl BundleArchive {
    pub fn parse(bytes: &[u8], limits: &BundleLimits) -> Result<Self, BundleError> {
        let encoded_size = u64::try_from(bytes.len()).map_err(|_| {
            BundleError::new(
                BundleErrorKind::LimitExceeded,
                "bundle length cannot be represented as u64",
            )
        })?;
        check_limit("bundle bytes", encoded_size, limits.max_bundle_bytes, 0)?;
        if bytes.len() < HEADER_LEN {
            return Err(BundleError::new(
                BundleErrorKind::Truncated,
                "bundle is shorter than its fixed header",
            ));
        }

        let mut cursor = ByteCursor::new(bytes);
        let magic = cursor.take_array::<8>()?;
        if magic != MAGIC {
            return Err(BundleError::new(
                BundleErrorKind::InvalidMagic,
                "file does not begin with the Oxidase Bundle magic",
            ));
        }
        let version = cursor.u16()?;
        if version != FORMAT_VERSION {
            return Err(BundleError::new(
                BundleErrorKind::UnsupportedFormatVersion,
                format!(
                    "bundle format version {version} is not supported; expected {FORMAT_VERSION}"
                ),
            )
            .at_offset(8));
        }
        let flags = cursor.u16()?;
        if flags & !KNOWN_FLAGS != 0 {
            return Err(BundleError::new(
                BundleErrorKind::UnsupportedFlags,
                format!("bundle uses unknown required header flags 0x{flags:04x}"),
            )
            .at_offset(10));
        }
        let unsigned_len = cursor.u64()?;
        let signature_len = cursor.u64()?;
        check_limit(
            "signature envelope bytes",
            signature_len,
            limits.max_signature_bytes,
            20,
        )?;
        let expected_digest = BundleDigest::from_bytes(cursor.take_array::<32>()?);
        let expected_total = u64::try_from(HEADER_LEN)
            .ok()
            .and_then(|header| header.checked_add(unsigned_len))
            .and_then(|value| value.checked_add(signature_len))
            .ok_or_else(|| {
                BundleError::new(
                    BundleErrorKind::LengthMismatch,
                    "bundle section lengths overflow u64",
                )
            })?;
        if expected_total != encoded_size {
            return Err(BundleError::new(
                BundleErrorKind::LengthMismatch,
                format!(
                    "bundle header declares {expected_total} bytes but file contains {encoded_size}"
                ),
            ));
        }

        let unsigned = cursor.take_u64(unsigned_len)?;
        let signature_bytes = cursor.take_u64(signature_len)?;
        let actual_digest = digest_unsigned(unsigned);
        if actual_digest != expected_digest {
            return Err(BundleError::new(
                BundleErrorKind::ContentDigestMismatch,
                "bundle canonical content digest does not match its header",
            ));
        }

        let (manifest, blobs) = parse_unsigned(unsigned, limits, HEADER_LEN as u64)?;
        let signatures = parse_signatures(signature_bytes, flags)?;
        validate_model(&manifest, &blobs, &signatures, limits)?;

        Ok(Self {
            manifest,
            blobs,
            signatures,
            content_digest: actual_digest,
            file_digest: BundleDigest::of_bytes(bytes),
            encoded_size,
            backing_file: None,
        })
    }

    pub fn read_path(path: impl AsRef<Path>, limits: &BundleLimits) -> Result<Self, BundleError> {
        read_path_streaming(path.as_ref(), limits)
    }

    #[must_use]
    pub const fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn signatures(&self) -> &SignatureEnvelope {
        &self.signatures
    }

    #[must_use]
    pub const fn content_digest(&self) -> BundleDigest {
        self.content_digest
    }

    #[must_use]
    pub const fn signing_digest(&self) -> BundleDigest {
        self.content_digest
    }

    #[must_use]
    pub const fn file_digest(&self) -> BundleDigest {
        self.file_digest
    }

    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }

    #[must_use]
    pub fn blob(&self, digest: BundleDigest) -> Option<&[u8]> {
        self.blobs
            .get(&digest)
            .and_then(|record| record.bytes.as_deref())
    }

    #[must_use]
    pub fn blob_file_range(&self, digest: BundleDigest) -> Option<(u64, u64)> {
        self.blobs
            .get(&digest)
            .map(|record| (record.file_offset, record.length))
    }

    pub fn try_clone_backing_file(&self) -> Result<Option<File>, BundleError> {
        self.backing_file
            .as_ref()
            .map(|file| {
                file.try_clone()
                    .map_err(|error| BundleError::io(error, "clone pinned bundle handle"))
            })
            .transpose()
    }

    pub fn read_backing_at(&self, buffer: &mut [u8], offset: u64) -> Result<usize, BundleError> {
        let file = self.backing_file.as_ref().ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::InvalidModel,
                "in-memory bundle archive does not have a pinned backing file",
            )
        })?;
        read_file_at(file, buffer, offset)
            .map_err(|error| BundleError::io(error, "read pinned bundle backing file"))
    }

    pub fn verify(&self) -> Result<BundleVerification, BundleError> {
        validate_model(
            &self.manifest,
            &self.blobs,
            &self.signatures,
            &BundleLimits::default(),
        )?;
        Ok(BundleVerification {
            content_digest: self.content_digest,
            file_digest: self.file_digest,
            blob_count: self.blobs.len(),
            signature_count: self.signatures.signatures.len(),
        })
    }

    pub fn verify_capabilities(
        &self,
        capabilities: &BundleCapabilities,
    ) -> Result<(), BundleError> {
        let required_version = semver::Version::parse(&self.manifest.minimum_runtime_version)
            .map_err(|error| {
                BundleError::new(
                    BundleErrorKind::InvalidRuntimeVersion,
                    format!(
                        "bundle minimum runtime version `{}` is not valid semantic versioning: {error}",
                        self.manifest.minimum_runtime_version
                    ),
                )
            })?;
        let actual_version =
            semver::Version::parse(&capabilities.runtime_version).map_err(|error| {
                BundleError::new(
                    BundleErrorKind::InvalidRuntimeVersion,
                    format!(
                        "runtime capability version `{}` is not valid semantic versioning: {error}",
                        capabilities.runtime_version
                    ),
                )
            })?;
        if actual_version < required_version {
            return Err(BundleError::new(
                BundleErrorKind::RuntimeTooOld,
                format!(
                    "bundle requires runtime {} or newer but this runtime is {}",
                    self.manifest.minimum_runtime_version, capabilities.runtime_version
                ),
            ));
        }
        for feature in &self.manifest.required_features {
            if !capabilities.supported_features.contains(feature) {
                return Err(BundleError::new(
                    BundleErrorKind::UnsupportedRequiredFeature,
                    format!(
                        "bundle requires unsupported feature `{feature}` and runtime {} or newer",
                        self.manifest.minimum_runtime_version
                    ),
                ));
            }
        }
        for (name, section) in &self.manifest.sections {
            if section.required
                && !capabilities
                    .supported_sections
                    .get(name)
                    .is_some_and(|schema| schema == &section.schema)
            {
                return Err(BundleError::new(
                    BundleErrorKind::UnsupportedRequiredSection,
                    format!(
                        "required bundle section `{name}` uses unsupported schema `{}`",
                        section.schema
                    ),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn inspect(&self, verbosity: InspectionVerbosity) -> BundleInspection {
        let reference_assets = if verbosity == InspectionVerbosity::Verbose {
            self.manifest
                .assets
                .iter()
                .filter_map(|(name, descriptor)| match &descriptor.storage {
                    AssetStorage::Reference { path, .. } => Some((name.clone(), path.clone())),
                    AssetStorage::Embedded { .. } => None,
                })
                .collect()
        } else {
            BTreeMap::new()
        };
        BundleInspection {
            schema_version: self.manifest.schema_version.clone(),
            content_digest: self.content_digest,
            file_digest: self.file_digest,
            encoded_size: self.encoded_size,
            tool_version: self.manifest.build.tool_version.clone(),
            source_commit: self.manifest.build.source_commit.clone(),
            gateway_api: self.manifest.build.gateway_api.clone(),
            oxista_api: self.manifest.build.oxista_api.clone(),
            minimum_runtime_version: self.manifest.minimum_runtime_version.clone(),
            required_features: self.manifest.required_features.clone(),
            sections: self.manifest.sections.keys().cloned().collect(),
            assets: self.manifest.assets.len(),
            embedded_blobs: self.blobs.len(),
            sensitive_references: self
                .manifest
                .sensitive_references
                .iter()
                .map(|(name, reference)| (name.clone(), reference.kind))
                .collect(),
            reference_assets,
            signatures: self.signatures.signatures.len(),
        }
    }

    #[must_use]
    pub fn diff(&self, newer: &Self) -> BundleDiff {
        BundleDiff {
            identical_content: self.content_digest == newer.content_digest,
            minimum_runtime_version_changed: self.manifest.minimum_runtime_version
                != newer.manifest.minimum_runtime_version,
            required_features_added: key_difference(
                newer.manifest.required_features.iter(),
                self.manifest.required_features.iter(),
            ),
            required_features_removed: key_difference(
                self.manifest.required_features.iter(),
                newer.manifest.required_features.iter(),
            ),
            sections_added: key_difference(
                newer.manifest.sections.keys(),
                self.manifest.sections.keys(),
            ),
            sections_removed: key_difference(
                self.manifest.sections.keys(),
                newer.manifest.sections.keys(),
            ),
            sections_changed: changed_keys(&self.manifest.sections, &newer.manifest.sections),
            assets_added: key_difference(newer.manifest.assets.keys(), self.manifest.assets.keys()),
            assets_removed: key_difference(
                self.manifest.assets.keys(),
                newer.manifest.assets.keys(),
            ),
            assets_changed: changed_keys(&self.manifest.assets, &newer.manifest.assets),
            origins_added: key_difference(
                newer.manifest.origins.keys(),
                self.manifest.origins.keys(),
            ),
            origins_removed: key_difference(
                self.manifest.origins.keys(),
                newer.manifest.origins.keys(),
            ),
            origins_changed: changed_keys(&self.manifest.origins, &newer.manifest.origins),
            sensitive_references_added: key_difference(
                newer.manifest.sensitive_references.keys(),
                self.manifest.sensitive_references.keys(),
            ),
            sensitive_references_removed: key_difference(
                self.manifest.sensitive_references.keys(),
                newer.manifest.sensitive_references.keys(),
            ),
            sensitive_references_changed: changed_keys(
                &self.manifest.sensitive_references,
                &newer.manifest.sensitive_references,
            ),
            build_changed: self.manifest.build != newer.manifest.build,
            optional_metadata_changed: self.manifest.optional_metadata
                != newer.manifest.optional_metadata,
            signatures_changed: self.signatures != newer.signatures,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        self.to_builder()?.build()
    }

    pub fn with_signatures(&self, signatures: Vec<SignatureRecord>) -> Result<Self, BundleError> {
        let mut builder = self.to_builder()?;
        builder.set_signatures(signatures);
        let bytes = builder.build()?;
        Self::parse(&bytes, &BundleLimits::default())
    }

    pub fn write_atomic_with_signatures(
        &self,
        path: impl AsRef<Path>,
        signatures: Vec<SignatureRecord>,
    ) -> Result<BundleDigest, BundleError> {
        let mut builder = self.to_builder()?;
        builder.set_signatures(signatures);
        builder.write_atomic(path)
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>) -> Result<(), BundleError> {
        self.to_builder()?.write_atomic(path).map(|_| ())
    }

    fn to_builder(&self) -> Result<BundleBuilder, BundleError> {
        let mut builder = BundleBuilder::new(self.manifest.clone());
        builder.signatures = self.signatures.clone();
        for (digest, record) in &self.blobs {
            let input = if let Some(bytes) = &record.bytes {
                BlobInput::Bytes(bytes.clone())
            } else if let Some(file) = &self.backing_file {
                BlobInput::FileHandleSlice {
                    file: file.clone(),
                    offset: record.file_offset,
                    length: record.length,
                }
            } else {
                return Err(BundleError::new(
                    BundleErrorKind::InvalidModel,
                    "bundle blob has neither owned bytes nor an immutable backing file",
                ));
            };
            builder.blobs.insert(*digest, input);
        }
        Ok(builder)
    }
}

fn read_path_streaming(path: &Path, limits: &BundleLimits) -> Result<BundleArchive, BundleError> {
    #[cfg(unix)]
    let mut file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            BundleError::io(
                std::io::Error::from_raw_os_error(error.raw_os_error()),
                "open bundle",
            )
        })?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let mut file = File::open(path).map_err(|error| BundleError::io(error, "open bundle"))?;
    let metadata = file
        .metadata()
        .map_err(|error| BundleError::io(error, "stat opened bundle"))?;
    if !metadata.is_file() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "bundle path is not a regular file",
        ));
    }
    let encoded_size = metadata.len();
    check_limit("bundle bytes", encoded_size, limits.max_bundle_bytes, 0)?;
    if encoded_size < HEADER_LEN as u64 {
        return Err(BundleError::new(
            BundleErrorKind::Truncated,
            "bundle is shorter than its fixed header",
        ));
    }
    let mut header = [0_u8; HEADER_LEN];
    file.read_exact(&mut header)
        .map_err(|error| BundleError::io(error, "read bundle header"))?;
    let mut pinned_file = tempfile::NamedTempFile::new()
        .map_err(|error| BundleError::io(error, "create immutable bundle backing file"))?;
    pinned_file
        .write_all(&header)
        .map_err(|error| BundleError::io(error, "pin bundle header"))?;
    let mut cursor = ByteCursor::new(&header);
    if cursor.take_array::<8>()? != MAGIC {
        return Err(BundleError::new(
            BundleErrorKind::InvalidMagic,
            "file does not begin with the Oxidase Bundle magic",
        ));
    }
    let version = cursor.u16()?;
    if version != FORMAT_VERSION {
        return Err(BundleError::new(
            BundleErrorKind::UnsupportedFormatVersion,
            format!("bundle format version {version} is not supported; expected {FORMAT_VERSION}"),
        ));
    }
    let flags = cursor.u16()?;
    if flags & !KNOWN_FLAGS != 0 {
        return Err(BundleError::new(
            BundleErrorKind::UnsupportedFlags,
            format!("bundle uses unknown required header flags 0x{flags:04x}"),
        ));
    }
    let unsigned_len = cursor.u64()?;
    let signature_len = cursor.u64()?;
    check_limit(
        "signature envelope bytes",
        signature_len,
        limits.max_signature_bytes,
        20,
    )?;
    let expected_content_digest = BundleDigest::from_bytes(cursor.take_array::<32>()?);
    let expected_size = (HEADER_LEN as u64)
        .checked_add(unsigned_len)
        .and_then(|value| value.checked_add(signature_len))
        .ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::LengthMismatch,
                "bundle section lengths overflow u64",
            )
        })?;
    if expected_size != encoded_size {
        return Err(BundleError::new(
            BundleErrorKind::LengthMismatch,
            format!(
                "bundle header declares {expected_size} bytes but file contains {encoded_size}"
            ),
        ));
    }

    let mut content_hasher = ContentHasher::new();
    content_hasher.update(CONTENT_DOMAIN);
    content_hasher.update(FORMAT_VERSION.to_be_bytes());
    let mut file_hasher = ContentHasher::new();
    file_hasher.update(header);
    let mut unsigned_remaining = unsigned_len;

    let manifest_len_bytes = read_stream_field::<8>(
        &mut file,
        &mut unsigned_remaining,
        &mut content_hasher,
        &mut file_hasher,
        &mut pinned_file,
    )?;
    let manifest_len = u64::from_be_bytes(manifest_len_bytes);
    check_limit(
        "manifest bytes",
        manifest_len,
        limits.max_manifest_bytes,
        HEADER_LEN as u64,
    )?;
    let manifest_capacity = usize::try_from(manifest_len).map_err(|_| {
        BundleError::new(
            BundleErrorKind::LimitExceeded,
            "manifest is too large for this platform",
        )
    })?;
    let mut manifest_bytes = vec![0_u8; manifest_capacity];
    read_stream_bytes(
        &mut file,
        &mut manifest_bytes,
        &mut unsigned_remaining,
        &mut content_hasher,
        &mut file_hasher,
        &mut pinned_file,
    )?;
    let manifest = serde_json::from_slice::<BundleManifest>(&manifest_bytes).map_err(|error| {
        BundleError::new(
            BundleErrorKind::InvalidManifest,
            format!("bundle manifest is not valid JSON: {error}"),
        )
    })?;
    if canonical_json(&manifest, BundleErrorKind::InvalidManifest)? != manifest_bytes {
        return Err(BundleError::new(
            BundleErrorKind::NonCanonicalManifest,
            "bundle manifest JSON is not in canonical Oxidase encoding",
        ));
    }

    let blob_count = u32::from_be_bytes(read_stream_field::<4>(
        &mut file,
        &mut unsigned_remaining,
        &mut content_hasher,
        &mut file_hasher,
        &mut pinned_file,
    )?);
    check_limit(
        "blob count",
        u64::from(blob_count),
        u64::from(limits.max_blob_count),
        file.stream_position()
            .map_err(|error| BundleError::io(error, "inspect bundle position"))?,
    )?;
    let mut blobs = BTreeMap::new();
    let mut total_blob_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut previous_blob_digest = None;
    for _ in 0..blob_count {
        let declared_digest = BundleDigest::from_bytes(read_stream_field::<32>(
            &mut file,
            &mut unsigned_remaining,
            &mut content_hasher,
            &mut file_hasher,
            &mut pinned_file,
        )?);
        validate_blob_order(&mut previous_blob_digest, declared_digest)?;
        let length = u64::from_be_bytes(read_stream_field::<8>(
            &mut file,
            &mut unsigned_remaining,
            &mut content_hasher,
            &mut file_hasher,
            &mut pinned_file,
        )?);
        check_limit(
            "blob bytes",
            length,
            limits.max_blob_bytes,
            file.stream_position()
                .map_err(|error| BundleError::io(error, "inspect bundle position"))?,
        )?;
        total_blob_bytes = total_blob_bytes.checked_add(length).ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::LimitExceeded,
                "total blob bytes overflow u64",
            )
        })?;
        check_limit(
            "total blob bytes",
            total_blob_bytes,
            limits.max_total_blob_bytes,
            0,
        )?;
        if length > unsigned_remaining {
            return Err(BundleError::new(
                BundleErrorKind::Truncated,
                "blob length exceeds the unsigned payload boundary",
            ));
        }
        let file_offset = file
            .stream_position()
            .map_err(|error| BundleError::io(error, "inspect blob offset"))?;
        let mut blob_hasher = ContentHasher::new();
        let mut remaining = length;
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded by fixed buffer length");
            file.read_exact(&mut buffer[..wanted])
                .map_err(|error| BundleError::io(error, "read embedded bundle blob"))?;
            pinned_file
                .write_all(&buffer[..wanted])
                .map_err(|error| BundleError::io(error, "pin embedded bundle blob"))?;
            content_hasher.update(&buffer[..wanted]);
            file_hasher.update(&buffer[..wanted]);
            blob_hasher.update(&buffer[..wanted]);
            remaining -= wanted as u64;
            unsigned_remaining -= wanted as u64;
        }
        let actual_digest = BundleDigest::from_content_digest(blob_hasher.finish());
        if actual_digest != declared_digest {
            return Err(BundleError::new(
                BundleErrorKind::BlobDigestMismatch,
                format!("blob {declared_digest} does not match its declared digest"),
            )
            .at_offset(file_offset));
        }
        if blobs
            .insert(
                declared_digest,
                BlobRecord {
                    bytes: None,
                    file_offset,
                    length,
                },
            )
            .is_some()
        {
            return Err(BundleError::new(
                BundleErrorKind::DuplicateBlob,
                format!("blob {declared_digest} appears more than once"),
            ));
        }
    }
    if unsigned_remaining != 0 {
        return Err(BundleError::new(
            BundleErrorKind::LengthMismatch,
            format!("unsigned payload contains {unsigned_remaining} trailing bytes"),
        ));
    }
    let actual_content_digest = BundleDigest::from_content_digest(content_hasher.finish());
    if actual_content_digest != expected_content_digest {
        return Err(BundleError::new(
            BundleErrorKind::ContentDigestMismatch,
            "bundle canonical content digest does not match its header",
        ));
    }
    let signature_capacity = usize::try_from(signature_len).map_err(|_| {
        BundleError::new(
            BundleErrorKind::LimitExceeded,
            "signature envelope is too large for this platform",
        )
    })?;
    let mut signature_bytes = vec![0_u8; signature_capacity];
    file.read_exact(&mut signature_bytes)
        .map_err(|error| BundleError::io(error, "read signature envelope"))?;
    pinned_file
        .write_all(&signature_bytes)
        .map_err(|error| BundleError::io(error, "pin signature envelope"))?;
    file_hasher.update(&signature_bytes);
    let signatures = parse_signatures(&signature_bytes, flags)?;
    validate_model(&manifest, &blobs, &signatures, limits)?;
    pinned_file
        .as_file()
        .sync_data()
        .map_err(|error| BundleError::io(error, "flush immutable bundle backing file"))?;
    let immutable_backing = File::open(pinned_file.path())
        .map_err(|error| BundleError::io(error, "open immutable bundle backing file"))?;
    drop(pinned_file);

    Ok(BundleArchive {
        manifest,
        blobs,
        signatures,
        content_digest: actual_content_digest,
        file_digest: BundleDigest::from_content_digest(file_hasher.finish()),
        encoded_size,
        backing_file: Some(Arc::new(immutable_backing)),
    })
}

fn read_stream_field<const N: usize>(
    reader: &mut impl Read,
    unsigned_remaining: &mut u64,
    content_hasher: &mut ContentHasher,
    file_hasher: &mut ContentHasher,
    pinned_file: &mut impl Write,
) -> Result<[u8; N], BundleError> {
    let mut bytes = [0_u8; N];
    read_stream_bytes(
        reader,
        &mut bytes,
        unsigned_remaining,
        content_hasher,
        file_hasher,
        pinned_file,
    )?;
    Ok(bytes)
}

fn read_stream_bytes(
    reader: &mut impl Read,
    bytes: &mut [u8],
    unsigned_remaining: &mut u64,
    content_hasher: &mut ContentHasher,
    file_hasher: &mut ContentHasher,
    pinned_file: &mut impl Write,
) -> Result<(), BundleError> {
    let length = bytes.len() as u64;
    if length > *unsigned_remaining {
        return Err(BundleError::new(
            BundleErrorKind::Truncated,
            "field exceeds the unsigned payload boundary",
        ));
    }
    reader
        .read_exact(bytes)
        .map_err(|error| BundleError::io(error, "read canonical bundle content"))?;
    pinned_file
        .write_all(bytes)
        .map_err(|error| BundleError::io(error, "pin canonical bundle content"))?;
    *unsigned_remaining -= length;
    content_hasher.update(&*bytes);
    file_hasher.update(&*bytes);
    Ok(())
}

fn open_regular_input(
    path: &Path,
    operation: &'static str,
) -> Result<(File, std::fs::Metadata), BundleError> {
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags};

        let descriptor = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            BundleError::io(
                std::io::Error::from_raw_os_error(error.raw_os_error()),
                operation,
            )
        })?;
        File::from(descriptor)
    };
    #[cfg(not(unix))]
    let file = File::open(path).map_err(|error| BundleError::io(error, operation))?;

    let metadata = file
        .metadata()
        .map_err(|error| BundleError::io(error, operation))?;
    if !metadata.is_file() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "embedded asset source is not a regular file",
        ));
    }
    Ok((file, metadata))
}

fn validate_open_regular_input(
    file: &File,
    exact_length: Option<u64>,
    operation: &'static str,
) -> Result<std::fs::Metadata, BundleError> {
    let metadata = file
        .metadata()
        .map_err(|error| BundleError::io(error, operation))?;
    if !metadata.is_file() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "embedded asset source handle is not a regular file",
        ));
    }
    if let Some(exact_length) = exact_length
        && metadata.len() != exact_length
    {
        return Err(BundleError::new(
            BundleErrorKind::LengthMismatch,
            "embedded asset source length changed after it was opened",
        ));
    }
    Ok(metadata)
}

fn validate_open_regular_range(
    file: &File,
    offset: u64,
    length: u64,
    operation: &'static str,
) -> Result<(), BundleError> {
    let metadata = validate_open_regular_input(file, None, operation)?;
    let end = offset.checked_add(length).ok_or_else(|| {
        BundleError::new(
            BundleErrorKind::InvalidModel,
            "embedded asset slice offset and length overflow u64",
        )
    })?;
    if end > metadata.len() {
        return Err(BundleError::new(
            BundleErrorKind::LengthMismatch,
            "embedded asset slice exceeds its opened backing file",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum BlobInput {
    Bytes(Arc<[u8]>),
    File {
        file: Arc<File>,
        length: u64,
    },
    FileSlice {
        file: Arc<File>,
        offset: u64,
        length: u64,
    },
    FileHandleSlice {
        file: Arc<File>,
        offset: u64,
        length: u64,
    },
    #[cfg(test)]
    CountingFile {
        file: Arc<File>,
        length: u64,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    },
}

impl BlobInput {
    fn length(&self) -> u64 {
        match self {
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::File { length, .. }
            | Self::FileSlice { length, .. }
            | Self::FileHandleSlice { length, .. } => *length,
            #[cfg(test)]
            Self::CountingFile { length, .. } => *length,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BundleBuilder {
    manifest: BundleManifest,
    blobs: BTreeMap<BundleDigest, BlobInput>,
    signatures: SignatureEnvelope,
    limits: BundleLimits,
}

impl BundleBuilder {
    #[must_use]
    pub fn new(manifest: BundleManifest) -> Self {
        Self {
            manifest,
            blobs: BTreeMap::new(),
            signatures: SignatureEnvelope::default(),
            limits: BundleLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: BundleLimits) -> Self {
        self.limits = limits;
        self
    }

    #[must_use]
    pub const fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    pub fn manifest_mut(&mut self) -> &mut BundleManifest {
        &mut self.manifest
    }

    pub fn add_blob(&mut self, bytes: impl Into<Vec<u8>>) -> BundleDigest {
        let bytes = bytes.into();
        let digest = BundleDigest::of_bytes(&bytes);
        self.blobs
            .entry(digest)
            .or_insert_with(|| BlobInput::Bytes(bytes.into()));
        digest
    }

    pub fn add_blob_path(
        &mut self,
        path: impl Into<PathBuf>,
        digest: BundleDigest,
        length: u64,
    ) -> Result<(), BundleError> {
        let path = path.into();
        let (file, metadata) = open_regular_input(&path, "open embedded asset")?;
        if metadata.len() != length {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                format!(
                    "embedded asset source length {} does not match indexed length {length}",
                    metadata.len()
                ),
            ));
        }
        self.blobs.entry(digest).or_insert_with(|| BlobInput::File {
            file: Arc::new(file),
            length,
        });
        Ok(())
    }

    pub fn add_blob_file_slice(
        &mut self,
        path: impl Into<PathBuf>,
        offset: u64,
        digest: BundleDigest,
        length: u64,
    ) -> Result<(), BundleError> {
        let path = path.into();
        let (file, metadata) = open_regular_input(&path, "open embedded asset slice")?;
        let end = offset.checked_add(length).ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::InvalidModel,
                "embedded asset slice offset and length overflow u64",
            )
        })?;
        if end > metadata.len() {
            return Err(BundleError::new(
                BundleErrorKind::LengthMismatch,
                "embedded asset slice exceeds its backing file",
            ));
        }
        self.blobs
            .entry(digest)
            .or_insert_with(|| BlobInput::FileSlice {
                file: Arc::new(file),
                offset,
                length,
            });
        Ok(())
    }

    pub fn set_signatures(&mut self, mut signatures: Vec<SignatureRecord>) {
        signatures.sort_by(|left, right| {
            (&left.algorithm, &left.key_id, &left.signature).cmp(&(
                &right.algorithm,
                &right.key_id,
                &right.signature,
            ))
        });
        self.signatures = SignatureEnvelope {
            schema_version: SIGNATURE_SCHEMA_VERSION.to_owned(),
            signatures,
        };
    }

    pub fn build(&self) -> Result<Vec<u8>, BundleError> {
        let mut cursor = Cursor::new(Vec::new());
        self.write_seekable(&mut cursor)?;
        Ok(cursor.into_inner())
    }

    pub fn write_to<W>(&self, writer: &mut W) -> Result<BundleDigest, BundleError>
    where
        W: Read + Write + Seek,
    {
        self.write_seekable(writer)
            .map(|written| written.file_digest)
    }

    pub fn write_atomic(&self, path: impl AsRef<Path>) -> Result<BundleDigest, BundleError> {
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|error| BundleError::io(error, "create temporary bundle"))?;
        let written = self.write_seekable(temporary.as_file_mut())?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| BundleError::io(error, "sync temporary bundle"))?;
        temporary
            .persist(path)
            .map_err(|error| BundleError::io(error.error, "atomically replace bundle"))?;
        sync_parent(parent)?;
        Ok(written.file_digest)
    }

    fn write_seekable<W>(&self, writer: &mut W) -> Result<WrittenBundle, BundleError>
    where
        W: Read + Write + Seek,
    {
        if writer
            .seek(SeekFrom::End(0))
            .map_err(|error| BundleError::io(error, "inspect bundle output"))?
            != 0
        {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "bundle output must be an empty seekable destination",
            ));
        }
        let manifest_bytes = canonical_json(&self.manifest, BundleErrorKind::InvalidManifest)?;
        check_limit(
            "manifest bytes",
            manifest_bytes.len() as u64,
            self.limits.max_manifest_bytes,
            0,
        )?;
        let signature_bytes =
            canonical_json(&self.signatures, BundleErrorKind::InvalidSignatureEnvelope)?;
        check_limit(
            "signature envelope bytes",
            signature_bytes.len() as u64,
            self.limits.max_signature_bytes,
            0,
        )?;
        let logical_blobs = self
            .blobs
            .iter()
            .map(|(digest, input)| {
                (
                    *digest,
                    BlobRecord {
                        bytes: match input {
                            BlobInput::Bytes(bytes) => Some(bytes.clone()),
                            BlobInput::File { .. }
                            | BlobInput::FileSlice { .. }
                            | BlobInput::FileHandleSlice { .. } => None,
                            #[cfg(test)]
                            BlobInput::CountingFile { .. } => None,
                        },
                        file_offset: 0,
                        length: input.length(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        validate_model(
            &self.manifest,
            &logical_blobs,
            &self.signatures,
            &self.limits,
        )?;
        let unsigned_len = encoded_unsigned_len(manifest_bytes.len(), &self.blobs)?;
        let total_len = (HEADER_LEN as u64)
            .checked_add(unsigned_len)
            .and_then(|value| value.checked_add(signature_bytes.len() as u64))
            .ok_or_else(|| {
                BundleError::new(
                    BundleErrorKind::LimitExceeded,
                    "encoded bundle length overflows u64",
                )
            })?;
        check_limit("bundle bytes", total_len, self.limits.max_bundle_bytes, 0)?;

        writer
            .seek(SeekFrom::Start(0))
            .map_err(|error| BundleError::io(error, "seek bundle output"))?;
        writer
            .write_all(&[0_u8; HEADER_LEN])
            .map_err(|error| BundleError::io(error, "write bundle header placeholder"))?;
        let mut content_hasher = ContentHasher::new();
        content_hasher.update(CONTENT_DOMAIN);
        content_hasher.update(FORMAT_VERSION.to_be_bytes());
        write_content(
            writer,
            &(manifest_bytes.len() as u64).to_be_bytes(),
            &mut content_hasher,
        )?;
        write_content(writer, &manifest_bytes, &mut content_hasher)?;
        write_content(
            writer,
            &(self.blobs.len() as u32).to_be_bytes(),
            &mut content_hasher,
        )?;
        for (digest, input) in &self.blobs {
            write_content(writer, digest.as_bytes(), &mut content_hasher)?;
            write_content(writer, &input.length().to_be_bytes(), &mut content_hasher)?;
            let actual = copy_blob_input(input, writer, &mut content_hasher)?;
            if actual != *digest {
                return Err(BundleError::new(
                    BundleErrorKind::BlobDigestMismatch,
                    format!("embedded asset changed while building blob {digest}"),
                ));
            }
        }
        let content_digest = BundleDigest::from_content_digest(content_hasher.finish());
        writer
            .write_all(&signature_bytes)
            .map_err(|error| BundleError::io(error, "write signature envelope"))?;

        let flags = if self.signatures.signatures.is_empty() {
            0
        } else {
            FLAG_SIGNATURES
        };
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&MAGIC);
        header.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        header.extend_from_slice(&flags.to_be_bytes());
        header.extend_from_slice(&unsigned_len.to_be_bytes());
        header.extend_from_slice(&(signature_bytes.len() as u64).to_be_bytes());
        header.extend_from_slice(content_digest.as_bytes());
        writer
            .seek(SeekFrom::Start(0))
            .and_then(|_| writer.write_all(&header))
            .map_err(|error| BundleError::io(error, "finalize bundle header"))?;
        writer
            .flush()
            .map_err(|error| BundleError::io(error, "flush bundle"))?;

        writer
            .seek(SeekFrom::Start(0))
            .map_err(|error| BundleError::io(error, "seek finalized bundle"))?;
        let mut file_hasher = ContentHasher::new();
        let mut remaining = total_len;
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let wanted = usize::try_from(remaining.min(buffer.len() as u64))
                .expect("bounded by fixed buffer length");
            writer
                .read_exact(&mut buffer[..wanted])
                .map_err(|error| BundleError::io(error, "hash finalized bundle"))?;
            file_hasher.update(&buffer[..wanted]);
            remaining -= wanted as u64;
        }
        writer
            .seek(SeekFrom::Start(total_len))
            .map_err(|error| BundleError::io(error, "restore bundle output position"))?;
        Ok(WrittenBundle {
            file_digest: BundleDigest::from_content_digest(file_hasher.finish()),
        })
    }
}

struct WrittenBundle {
    file_digest: BundleDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionVerbosity {
    Safe,
    Verbose,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleInspection {
    pub schema_version: String,
    pub content_digest: BundleDigest,
    pub file_digest: BundleDigest,
    pub encoded_size: u64,
    pub tool_version: String,
    pub source_commit: Option<String>,
    pub gateway_api: String,
    pub oxista_api: String,
    pub minimum_runtime_version: String,
    pub required_features: BTreeSet<String>,
    pub sections: Vec<String>,
    pub assets: usize,
    pub embedded_blobs: usize,
    pub sensitive_references: BTreeMap<String, crate::SensitiveReferenceKind>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub reference_assets: BTreeMap<String, String>,
    pub signatures: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleVerification {
    pub content_digest: BundleDigest,
    pub file_digest: BundleDigest,
    pub blob_count: usize,
    pub signature_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BundleDiff {
    pub identical_content: bool,
    pub minimum_runtime_version_changed: bool,
    pub required_features_added: Vec<String>,
    pub required_features_removed: Vec<String>,
    pub sections_added: Vec<String>,
    pub sections_removed: Vec<String>,
    pub sections_changed: Vec<String>,
    pub assets_added: Vec<String>,
    pub assets_removed: Vec<String>,
    pub assets_changed: Vec<String>,
    pub origins_added: Vec<String>,
    pub origins_removed: Vec<String>,
    pub origins_changed: Vec<String>,
    pub sensitive_references_added: Vec<String>,
    pub sensitive_references_removed: Vec<String>,
    pub sensitive_references_changed: Vec<String>,
    pub build_changed: bool,
    pub optional_metadata_changed: bool,
    pub signatures_changed: bool,
}

fn encoded_unsigned_len(
    manifest_len: usize,
    blobs: &BTreeMap<BundleDigest, BlobInput>,
) -> Result<u64, BundleError> {
    let mut length = 8_u64
        .checked_add(manifest_len as u64)
        .and_then(|value| value.checked_add(4))
        .ok_or_else(|| BundleError::new(BundleErrorKind::LimitExceeded, "payload is too large"))?;
    for input in blobs.values() {
        length = length
            .checked_add(40)
            .and_then(|value| value.checked_add(input.length()))
            .ok_or_else(|| {
                BundleError::new(BundleErrorKind::LimitExceeded, "payload is too large")
            })?;
    }
    Ok(length)
}

fn write_content(
    writer: &mut impl Write,
    bytes: &[u8],
    hasher: &mut ContentHasher,
) -> Result<(), BundleError> {
    writer
        .write_all(bytes)
        .map_err(|error| BundleError::io(error, "write canonical bundle content"))?;
    hasher.update(bytes);
    Ok(())
}

fn copy_blob_input(
    input: &BlobInput,
    writer: &mut impl Write,
    content_hasher: &mut ContentHasher,
) -> Result<BundleDigest, BundleError> {
    let mut blob_hasher = ContentHasher::new();
    match input {
        BlobInput::Bytes(bytes) => {
            write_content(writer, bytes, content_hasher)?;
            blob_hasher.update(bytes);
        }
        BlobInput::File { file, length } => {
            validate_open_regular_input(file, Some(*length), "inspect embedded asset")?;
            copy_exact_file_range(file, 0, *length, writer, content_hasher, &mut blob_hasher)?;
            validate_open_regular_input(file, Some(*length), "reinspect embedded asset")?;
        }
        BlobInput::FileSlice {
            file,
            offset,
            length,
        } => {
            validate_open_regular_range(file, *offset, *length, "inspect backing bundle")?;
            copy_exact_file_range(
                file,
                *offset,
                *length,
                writer,
                content_hasher,
                &mut blob_hasher,
            )?;
            validate_open_regular_range(file, *offset, *length, "reinspect backing bundle")?;
        }
        BlobInput::FileHandleSlice {
            file,
            offset,
            length,
        } => {
            copy_exact_file_range(
                file,
                *offset,
                *length,
                writer,
                content_hasher,
                &mut blob_hasher,
            )?;
        }
        #[cfg(test)]
        BlobInput::CountingFile {
            file,
            length,
            reads,
        } => {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            validate_open_regular_input(file, Some(*length), "inspect counted embedded asset")?;
            copy_exact_file_range(file, 0, *length, writer, content_hasher, &mut blob_hasher)?;
        }
    }
    Ok(BundleDigest::from_content_digest(blob_hasher.finish()))
}

fn copy_exact_file_range(
    file: &File,
    offset: u64,
    length: u64,
    writer: &mut impl Write,
    content_hasher: &mut ContentHasher,
    blob_hasher: &mut ContentHasher,
) -> Result<(), BundleError> {
    let mut consumed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while consumed < length {
        let wanted = usize::try_from((length - consumed).min(buffer.len() as u64))
            .expect("bounded by fixed buffer length");
        let read_offset = offset.checked_add(consumed).ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::LengthMismatch,
                "pinned blob read offset overflows u64",
            )
        })?;
        let count = read_file_at(file, &mut buffer[..wanted], read_offset)
            .map_err(|error| BundleError::io(error, "read pinned bundle blob"))?;
        if count == 0 {
            return Err(BundleError::new(
                BundleErrorKind::Truncated,
                "pinned bundle blob is shorter than its verified range",
            ));
        }
        writer
            .write_all(&buffer[..count])
            .map_err(|error| BundleError::io(error, "write pinned bundle blob"))?;
        content_hasher.update(&buffer[..count]);
        blob_hasher.update(&buffer[..count]);
        consumed += count as u64;
    }
    Ok(())
}

#[cfg(unix)]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt as _;

    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt as _;

    file.seek_read(buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_file_at(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.read(buffer)
}

fn parse_unsigned(
    unsigned: &[u8],
    limits: &BundleLimits,
    absolute_base: u64,
) -> Result<(BundleManifest, BTreeMap<BundleDigest, BlobRecord>), BundleError> {
    let mut cursor = ByteCursor::with_base(unsigned, absolute_base);
    let manifest_len = cursor.u64()?;
    check_limit(
        "manifest bytes",
        manifest_len,
        limits.max_manifest_bytes,
        cursor.absolute_offset(),
    )?;
    let manifest_bytes = cursor.take_u64(manifest_len)?;
    let manifest = serde_json::from_slice::<BundleManifest>(manifest_bytes).map_err(|error| {
        BundleError::new(
            BundleErrorKind::InvalidManifest,
            format!("bundle manifest is not valid JSON: {error}"),
        )
        .at_offset(cursor.absolute_offset().saturating_sub(manifest_len))
    })?;
    let canonical = canonical_json(&manifest, BundleErrorKind::InvalidManifest)?;
    if canonical != manifest_bytes {
        return Err(BundleError::new(
            BundleErrorKind::NonCanonicalManifest,
            "bundle manifest JSON is not in canonical Oxidase encoding",
        ));
    }

    let blob_count = cursor.u32()?;
    check_limit(
        "blob count",
        u64::from(blob_count),
        u64::from(limits.max_blob_count),
        cursor.absolute_offset(),
    )?;
    let mut blobs = BTreeMap::new();
    let mut total_blob_bytes = 0_u64;
    let mut previous_blob_digest = None;
    for _ in 0..blob_count {
        let declared_digest = BundleDigest::from_bytes(cursor.take_array::<32>()?);
        validate_blob_order(&mut previous_blob_digest, declared_digest)?;
        let length_offset = cursor.absolute_offset();
        let length = cursor.u64()?;
        check_limit("blob bytes", length, limits.max_blob_bytes, length_offset)?;
        total_blob_bytes = total_blob_bytes.checked_add(length).ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::LimitExceeded,
                "total blob bytes overflow u64",
            )
        })?;
        check_limit(
            "total blob bytes",
            total_blob_bytes,
            limits.max_total_blob_bytes,
            length_offset,
        )?;
        let file_offset = cursor.absolute_offset();
        let bytes = cursor.take_u64(length)?;
        let actual_digest = BundleDigest::of_bytes(bytes);
        if actual_digest != declared_digest {
            return Err(BundleError::new(
                BundleErrorKind::BlobDigestMismatch,
                format!("blob {declared_digest} does not match its declared digest"),
            )
            .at_offset(file_offset));
        }
        if blobs
            .insert(
                declared_digest,
                BlobRecord {
                    bytes: Some(Arc::from(bytes)),
                    file_offset,
                    length,
                },
            )
            .is_some()
        {
            return Err(BundleError::new(
                BundleErrorKind::DuplicateBlob,
                format!("blob {declared_digest} appears more than once"),
            )
            .at_offset(file_offset));
        }
    }
    if !cursor.is_empty() {
        return Err(BundleError::new(
            BundleErrorKind::LengthMismatch,
            "unsigned payload contains trailing bytes",
        )
        .at_offset(cursor.absolute_offset()));
    }
    Ok((manifest, blobs))
}

fn validate_blob_order(
    previous: &mut Option<BundleDigest>,
    current: BundleDigest,
) -> Result<(), BundleError> {
    if let Some(previous) = *previous {
        if previous == current {
            return Err(BundleError::new(
                BundleErrorKind::DuplicateBlob,
                format!("blob {current} appears more than once"),
            ));
        }
        if previous > current {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "bundle blob records are not in canonical digest order",
            ));
        }
    }
    *previous = Some(current);
    Ok(())
}

fn parse_signatures(bytes: &[u8], flags: u16) -> Result<SignatureEnvelope, BundleError> {
    let envelope = serde_json::from_slice::<SignatureEnvelope>(bytes).map_err(|error| {
        BundleError::new(
            BundleErrorKind::InvalidSignatureEnvelope,
            format!("signature envelope is not valid JSON: {error}"),
        )
    })?;
    let canonical = canonical_json(&envelope, BundleErrorKind::InvalidSignatureEnvelope)?;
    if canonical != bytes {
        return Err(BundleError::new(
            BundleErrorKind::NonCanonicalSignatureEnvelope,
            "signature envelope JSON is not in canonical Oxidase encoding",
        ));
    }
    let has_signatures = !envelope.signatures.is_empty();
    if has_signatures != (flags & FLAG_SIGNATURES != 0) {
        return Err(BundleError::new(
            BundleErrorKind::UnsupportedFlags,
            "signature-presence flag disagrees with the signature envelope",
        ));
    }
    Ok(envelope)
}

fn canonical_json<T: Serialize>(value: &T, kind: BundleErrorKind) -> Result<Vec<u8>, BundleError> {
    serde_json::to_vec(value).map_err(|error| {
        BundleError::new(
            kind,
            format!("failed to encode canonical bundle JSON: {error}"),
        )
    })
}

fn digest_unsigned(unsigned: &[u8]) -> BundleDigest {
    let mut hasher = ContentHasher::new();
    hasher.update(CONTENT_DOMAIN);
    hasher.update(FORMAT_VERSION.to_be_bytes());
    hasher.update(unsigned);
    BundleDigest::from_content_digest(hasher.finish())
}

fn validate_model(
    manifest: &BundleManifest,
    blobs: &BTreeMap<BundleDigest, BlobRecord>,
    signatures: &SignatureEnvelope,
    limits: &BundleLimits,
) -> Result<(), BundleError> {
    if manifest.schema_version != BUNDLE_SCHEMA_VERSION {
        return Err(BundleError::new(
            BundleErrorKind::UnsupportedSchema,
            format!(
                "bundle schema `{}` is not supported; expected `{BUNDLE_SCHEMA_VERSION}`",
                manifest.schema_version
            ),
        ));
    }
    if signatures.schema_version != SIGNATURE_SCHEMA_VERSION {
        return Err(BundleError::new(
            BundleErrorKind::UnsupportedSchema,
            format!(
                "signature schema `{}` is not supported; expected `{SIGNATURE_SCHEMA_VERSION}`",
                signatures.schema_version
            ),
        ));
    }
    count_limit("asset count", manifest.assets.len(), limits.max_assets)?;
    count_limit(
        "section count",
        manifest.sections.len(),
        limits.max_sections,
    )?;
    count_limit("origin count", manifest.origins.len(), limits.max_origins)?;
    count_limit(
        "sensitive reference count",
        manifest.sensitive_references.len(),
        limits.max_sensitive_references,
    )?;
    count_limit("blob count", blobs.len(), limits.max_blob_count as usize)?;
    let mut total_blob_bytes = 0_u64;
    for record in blobs.values() {
        check_limit("blob bytes", record.length, limits.max_blob_bytes, 0)?;
        total_blob_bytes = total_blob_bytes.checked_add(record.length).ok_or_else(|| {
            BundleError::new(
                BundleErrorKind::LimitExceeded,
                "total blob bytes overflow u64",
            )
        })?;
    }
    check_limit(
        "total blob bytes",
        total_blob_bytes,
        limits.max_total_blob_bytes,
        0,
    )?;

    validate_identifier("tool version", &manifest.build.tool_version)?;
    if let Some(source_commit) = &manifest.build.source_commit {
        validate_source_commit(source_commit)?;
    }
    validate_identifier("Gateway API", &manifest.build.gateway_api)?;
    validate_identifier("Oxista API", &manifest.build.oxista_api)?;
    validate_identifier("minimum runtime version", &manifest.minimum_runtime_version)?;
    for feature in &manifest.required_features {
        validate_feature_name(feature)?;
    }

    let mut referenced_blobs = BTreeSet::new();
    for (logical_path, asset) in &manifest.assets {
        validate_logical_path(logical_path)?;
        match &asset.storage {
            AssetStorage::Embedded { blob, length } => {
                let record = blobs.get(blob).ok_or_else(|| {
                    BundleError::new(
                        BundleErrorKind::InvalidModel,
                        format!("asset `{logical_path}` refers to missing blob {blob}"),
                    )
                })?;
                if *length != record.length {
                    return Err(BundleError::new(
                        BundleErrorKind::InvalidModel,
                        format!(
                            "asset `{logical_path}` declares {length} bytes but blob {blob} contains {}",
                            record.length
                        ),
                    ));
                }
                referenced_blobs.insert(*blob);
            }
            AssetStorage::Reference {
                base,
                path,
                length: _,
                expected_digest: _,
            } => validate_reference_path(*base, path)?,
        }
    }
    if referenced_blobs.len() != blobs.len() {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "bundle contains an embedded blob that is not referenced by any asset",
        ));
    }

    let mut canonical_nodes = 0_usize;
    for (name, section) in &manifest.sections {
        validate_identifier("section name", name)?;
        validate_identifier("section schema", &section.schema)?;
        validate_canonical_value(&section.payload, limits, &mut canonical_nodes)?;
    }
    for value in manifest.optional_metadata.values() {
        validate_canonical_value(value, limits, &mut canonical_nodes)?;
    }
    for (name, reference) in &manifest.sensitive_references {
        validate_identifier("sensitive reference name", name)?;
        if reference.max_bytes == 0 {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                format!("sensitive reference `{name}` has a zero-byte limit"),
            ));
        }
        validate_reference_path(reference.base, &reference.runtime_path)?;
    }
    for (name, origin) in &manifest.origins {
        validate_identifier("source origin name", name)?;
        validate_source_path(&origin.display_path)?;
        if origin.start_byte > origin.end_byte
            || origin.start_line == 0
            || origin.start_column == 0
            || origin.end_line == 0
            || origin.end_column == 0
            || (origin.end_line, origin.end_column) < (origin.start_line, origin.start_column)
            || origin.field_path.is_empty()
            || origin.field_path.len() > 16 * 1024
            || origin.field_path.contains(['\0', '\r', '\n'])
        {
            return Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "source origin contains an invalid span",
            ));
        }
    }

    let mut previous: Option<(&str, &str, &str)> = None;
    let mut identities = BTreeSet::new();
    for signature in &signatures.signatures {
        validate_identifier("signature algorithm", &signature.algorithm)?;
        validate_identifier("signature key id", &signature.key_id)?;
        validate_signature_bytes(&signature.algorithm, &signature.signature)?;
        let current = (
            signature.algorithm.as_str(),
            signature.key_id.as_str(),
            signature.signature.as_str(),
        );
        if previous.is_some_and(|prior| prior > current) {
            return Err(BundleError::new(
                BundleErrorKind::InvalidSignatureEnvelope,
                "signature records are not in canonical order",
            ));
        }
        if !identities.insert((signature.algorithm.as_str(), signature.key_id.as_str())) {
            return Err(BundleError::new(
                BundleErrorKind::InvalidSignatureEnvelope,
                format!(
                    "signature identity `{}/{}` appears more than once",
                    signature.algorithm, signature.key_id
                ),
            ));
        }
        previous = Some(current);
    }
    Ok(())
}

fn validate_canonical_value(
    value: &CanonicalValue,
    limits: &BundleLimits,
    nodes: &mut usize,
) -> Result<(), BundleError> {
    let mut stack = vec![(value, 1_usize)];
    while let Some((value, depth)) = stack.pop() {
        *nodes = nodes.checked_add(1).ok_or_else(|| {
            BundleError::new(BundleErrorKind::LimitExceeded, "JSON node count overflow")
        })?;
        count_limit("JSON node count", *nodes, limits.max_json_nodes)?;
        count_limit("JSON depth", depth, limits.max_json_depth)?;
        match value {
            CanonicalValue::Float(value) => {
                value.value()?;
            }
            CanonicalValue::Bytes(value) => {
                count_limit(
                    "canonical byte length",
                    value.value()?.len(),
                    limits.max_string_bytes,
                )?;
            }
            CanonicalValue::String(value) => {
                validate_bounded_string("JSON string", value, limits.max_string_bytes)?;
            }
            CanonicalValue::Array(values) => {
                for child in values.iter().rev() {
                    stack.push((child, depth + 1));
                }
            }
            CanonicalValue::Object(values) => {
                for (key, child) in values.iter().rev() {
                    validate_bounded_string("JSON object key", key, limits.max_string_bytes)?;
                    stack.push((child, depth + 1));
                }
            }
            CanonicalValue::Null
            | CanonicalValue::Bool(_)
            | CanonicalValue::Integer(_)
            | CanonicalValue::Unsigned(_) => {}
        }
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), BundleError> {
    if value.is_empty() || value.len() > 512 || value.contains(['\0', '\r', '\n']) {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            format!("{label} is empty, too long, or contains a control delimiter"),
        ));
    }
    Ok(())
}

fn validate_source_commit(value: &str) -> Result<(), BundleError> {
    if !(7..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "source commit must be 7 to 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_feature_name(value: &str) -> Result<(), BundleError> {
    validate_identifier("required feature", value)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    }) {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            format!("required feature `{value}` is not a canonical feature name"),
        ));
    }
    Ok(())
}

fn validate_logical_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            format!("asset logical path `{path}` is not a normalized relative path"),
        ));
    }
    Ok(())
}

fn validate_reference_path(base: AssetReferenceBase, path: &str) -> Result<(), BundleError> {
    if path.is_empty() || path.contains(['\\', '\0', '\r', '\n']) {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "asset reference path is empty or contains a forbidden delimiter",
        ));
    }
    match base {
        AssetReferenceBase::Absolute if !path.starts_with('/') => Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "absolute asset reference must begin with `/`",
        )),
        AssetReferenceBase::DeploymentRoot
            if path.starts_with('/')
                || path.split('/').any(|component| {
                    component.is_empty() || component == "." || component == ".."
                }) =>
        {
            Err(BundleError::new(
                BundleErrorKind::InvalidModel,
                "deployment-root asset reference must be a normalized relative path",
            ))
        }
        _ => Ok(()),
    }
}

fn validate_source_path(path: &str) -> Result<(), BundleError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', '\0', '\r', '\n'])
        || path.split('/').any(|part| part == "..")
    {
        return Err(BundleError::new(
            BundleErrorKind::InvalidModel,
            "source origin path must be portable and project-relative",
        ));
    }
    Ok(())
}

fn validate_signature_bytes(algorithm: &str, value: &str) -> Result<(), BundleError> {
    if value.is_empty()
        || value.len() > 16_384
        || value.len() & 1 != 0
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSignatureEnvelope,
            "signature bytes must be non-empty lowercase hexadecimal with an even length",
        ));
    }
    if algorithm == "ed25519" && value.len() != 128 {
        return Err(BundleError::new(
            BundleErrorKind::InvalidSignatureEnvelope,
            "Ed25519 signature must contain exactly 64 bytes encoded as 128 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

fn validate_bounded_string(label: &str, value: &str, max: usize) -> Result<(), BundleError> {
    count_limit(label, value.len(), max)
}

fn check_limit(label: &str, actual: u64, maximum: u64, offset: u64) -> Result<(), BundleError> {
    if actual > maximum {
        return Err(BundleError::new(
            BundleErrorKind::LimitExceeded,
            format!("{label} {actual} exceeds configured limit {maximum}"),
        )
        .at_offset(offset));
    }
    Ok(())
}

fn count_limit(label: &str, actual: usize, maximum: usize) -> Result<(), BundleError> {
    if actual > maximum {
        return Err(BundleError::new(
            BundleErrorKind::LimitExceeded,
            format!("{label} {actual} exceeds configured limit {maximum}"),
        ));
    }
    Ok(())
}

fn key_difference<'a>(
    left: impl Iterator<Item = &'a String>,
    right: impl Iterator<Item = &'a String>,
) -> Vec<String> {
    let right = right.cloned().collect::<BTreeSet<_>>();
    left.filter(|key| !right.contains(*key)).cloned().collect()
}

fn changed_keys<T: PartialEq>(old: &BTreeMap<String, T>, new: &BTreeMap<String, T>) -> Vec<String> {
    old.iter()
        .filter_map(|(key, old_value)| {
            new.get(key)
                .filter(|new_value| *new_value != old_value)
                .map(|_| key.clone())
        })
        .collect()
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), BundleError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| BundleError::io(error, "sync bundle parent directory"))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<(), BundleError> {
    Ok(())
}

struct ByteCursor<'a> {
    bytes: &'a [u8],
    position: usize,
    absolute_base: u64,
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self::with_base(bytes, 0)
    }

    fn with_base(bytes: &'a [u8], absolute_base: u64) -> Self {
        Self {
            bytes,
            position: 0,
            absolute_base,
        }
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], BundleError> {
        let bytes = self.take(N)?;
        bytes.try_into().map_err(|_| {
            BundleError::new(BundleErrorKind::Truncated, "bundle field is truncated")
                .at_offset(self.absolute_offset())
        })
    }

    fn u16(&mut self) -> Result<u16, BundleError> {
        Ok(u16::from_be_bytes(self.take_array()?))
    }

    fn u32(&mut self) -> Result<u32, BundleError> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    fn u64(&mut self) -> Result<u64, BundleError> {
        Ok(u64::from_be_bytes(self.take_array()?))
    }

    fn take_u64(&mut self, length: u64) -> Result<&'a [u8], BundleError> {
        let length = usize::try_from(length).map_err(|_| {
            BundleError::new(
                BundleErrorKind::LimitExceeded,
                "bundle field is too large for this platform",
            )
            .at_offset(self.absolute_offset())
        })?;
        self.take(length)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BundleError> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            BundleError::new(BundleErrorKind::Truncated, "bundle offset overflow")
                .at_offset(self.absolute_offset())
        })?;
        let bytes = self.bytes.get(self.position..end).ok_or_else(|| {
            BundleError::new(BundleErrorKind::Truncated, "bundle section is truncated")
                .at_offset(self.absolute_offset())
        })?;
        self.position = end;
        Ok(bytes)
    }

    fn absolute_offset(&self) -> u64 {
        self.absolute_base
            .saturating_add(u64::try_from(self.position).unwrap_or(u64::MAX))
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::{
        AssetDescriptor, BuildMetadata, CanonicalValue, SensitiveReference, SensitiveReferenceKind,
        StableSection,
    };

    fn manifest() -> BundleManifest {
        let mut manifest = BundleManifest::new(
            BuildMetadata {
                tool_version: "0.4.0-alpha.1".to_owned(),
                source_commit: Some("0123456789abcdef".to_owned()),
                gateway_api: "oxidase.dev/v1alpha1".to_owned(),
                oxista_api: "v1".to_owned(),
            },
            "0.4.0-alpha.1",
        );
        manifest.sections.insert(
            "service_graph".to_owned(),
            StableSection {
                schema: "oxidase.service-graph/v1".to_owned(),
                required: true,
                payload: CanonicalValue::Object(BTreeMap::from([
                    ("z".to_owned(), CanonicalValue::String("last".to_owned())),
                    ("a".to_owned(), CanonicalValue::String("first".to_owned())),
                ])),
            },
        );
        manifest
    }

    fn archive_with_asset(contents: &[u8]) -> (Vec<u8>, BundleDigest) {
        let mut builder = BundleBuilder::new(manifest());
        let digest = builder.add_blob(contents.to_vec());
        builder.manifest_mut().assets.insert(
            "public/app.js".to_owned(),
            AssetDescriptor {
                storage: AssetStorage::Embedded {
                    blob: digest,
                    length: contents.len() as u64,
                },
            },
        );
        (builder.build().expect("bundle should build"), digest)
    }

    #[test]
    fn canonical_encoding_is_bit_stable_and_map_order_independent() {
        let (first, _) = archive_with_asset(b"asset");
        let (second, _) = archive_with_asset(b"asset");
        assert_eq!(first, second);

        let archive = BundleArchive::parse(&first, &BundleLimits::default()).expect("parse");
        let inspection = archive.inspect(InspectionVerbosity::Safe);
        assert_eq!(
            inspection.source_commit.as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(inspection.gateway_api, "oxidase.dev/v1alpha1");
        assert_eq!(inspection.oxista_api, "v1");
        assert_eq!(inspection.minimum_runtime_version, "0.4.0-alpha.1");

        let mut left = manifest();
        left.optional_metadata
            .insert("z".to_owned(), CanonicalValue::Bool(true));
        left.optional_metadata
            .insert("a".to_owned(), CanonicalValue::Bool(false));
        let mut right = manifest();
        right
            .optional_metadata
            .insert("a".to_owned(), CanonicalValue::Bool(false));
        right
            .optional_metadata
            .insert("z".to_owned(), CanonicalValue::Bool(true));
        assert_eq!(
            BundleBuilder::new(left).build().expect("left"),
            BundleBuilder::new(right).build().expect("right")
        );

        let mut invalid_provenance = manifest();
        invalid_provenance.build.source_commit = Some("not a commit".to_owned());
        assert_eq!(
            BundleBuilder::new(invalid_provenance)
                .build()
                .expect_err("non-canonical source provenance is rejected")
                .kind(),
            BundleErrorKind::InvalidModel
        );
    }

    #[test]
    fn canonical_node_limit_is_aggregate_across_sections_and_metadata() {
        let mut source = manifest();
        source.sections.clear();
        source.sections.insert(
            "one".to_owned(),
            StableSection {
                schema: "test.one/v1".to_owned(),
                required: false,
                payload: CanonicalValue::Null,
            },
        );
        source
            .optional_metadata
            .insert("two".to_owned(), CanonicalValue::Null);
        let limits = BundleLimits {
            max_json_nodes: 1,
            ..BundleLimits::default()
        };
        let error = validate_model(
            &source,
            &BTreeMap::new(),
            &SignatureEnvelope::default(),
            &limits,
        )
        .expect_err("the node budget is shared by every canonical value");
        assert_eq!(error.kind(), BundleErrorKind::LimitExceeded);
    }

    #[test]
    fn parser_rejects_out_of_order_blob_records() {
        let manifest_bytes =
            canonical_json(&manifest(), BundleErrorKind::InvalidManifest).expect("manifest JSON");
        let left = b"left".as_slice();
        let right = b"right".as_slice();
        let left_digest = BundleDigest::of_bytes(left);
        let right_digest = BundleDigest::of_bytes(right);
        let ((first_digest, first), (second_digest, second)) = if left_digest > right_digest {
            ((left_digest, left), (right_digest, right))
        } else {
            ((right_digest, right), (left_digest, left))
        };
        let mut unsigned = Vec::new();
        unsigned.extend_from_slice(&(manifest_bytes.len() as u64).to_be_bytes());
        unsigned.extend_from_slice(&manifest_bytes);
        unsigned.extend_from_slice(&2_u32.to_be_bytes());
        for (digest, bytes) in [(first_digest, first), (second_digest, second)] {
            unsigned.extend_from_slice(digest.as_bytes());
            unsigned.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            unsigned.extend_from_slice(bytes);
        }
        let error = parse_unsigned(&unsigned, &BundleLimits::default(), 0)
            .expect_err("blob records must be sorted by digest");
        assert_eq!(error.kind(), BundleErrorKind::InvalidModel);
    }

    #[test]
    fn writer_enforces_single_and_aggregate_blob_limits_before_output() {
        let limits = BundleLimits {
            max_bundle_bytes: 1024,
            max_blob_bytes: 10,
            max_total_blob_bytes: 10,
            ..BundleLimits::default()
        };
        let mut builder = BundleBuilder::new(manifest()).with_limits(limits);
        let digest = builder.add_blob(vec![7_u8; 20]);
        builder.manifest_mut().assets.insert(
            "large.bin".to_owned(),
            AssetDescriptor {
                storage: AssetStorage::Embedded {
                    blob: digest,
                    length: 20,
                },
            },
        );
        let error = builder
            .build()
            .expect_err("writer must reject a blob above its configured limit");
        assert_eq!(error.kind(), BundleErrorKind::LimitExceeded);
    }

    #[test]
    fn duplicate_blob_content_is_stored_once() {
        let mut builder = BundleBuilder::new(manifest());
        let first = builder.add_blob(b"identical".to_vec());
        let second = builder.add_blob(b"identical".to_vec());
        assert_eq!(first, second);
        for path in ["a.bin", "b.bin"] {
            builder.manifest_mut().assets.insert(
                path.to_owned(),
                AssetDescriptor {
                    storage: AssetStorage::Embedded {
                        blob: first,
                        length: 9,
                    },
                },
            );
        }
        let bytes = builder.build().expect("bundle");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        assert_eq!(archive.inspect(InspectionVerbosity::Safe).embedded_blobs, 1);
    }

    #[test]
    fn truncation_corruption_and_bounds_are_rejected() {
        let (bytes, _digest) = archive_with_asset(b"asset");
        for end in [0, HEADER_LEN - 1, bytes.len() - 1] {
            let error = BundleArchive::parse(&bytes[..end], &BundleLimits::default())
                .expect_err("truncation must fail");
            assert!(matches!(
                error.kind(),
                BundleErrorKind::Truncated | BundleErrorKind::LengthMismatch
            ));
        }

        let mut corrupt = bytes.clone();
        corrupt[HEADER_LEN + 12] ^= 1;
        assert_eq!(
            BundleArchive::parse(&corrupt, &BundleLimits::default())
                .expect_err("corruption")
                .kind(),
            BundleErrorKind::ContentDigestMismatch
        );

        let limits = BundleLimits {
            max_bundle_bytes: (bytes.len() - 1) as u64,
            ..BundleLimits::default()
        };
        assert_eq!(
            BundleArchive::parse(&bytes, &limits)
                .expect_err("limit")
                .kind(),
            BundleErrorKind::LimitExceeded
        );
    }

    #[test]
    fn required_features_and_sections_are_explicitly_negotiated() {
        let mut source = manifest();
        source.required_features.insert("trailers".to_owned());
        let bytes = BundleBuilder::new(source).build().expect("bundle");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let supported_runtime = BundleCapabilities {
            runtime_version: "0.4.0-alpha.1".to_owned(),
            ..BundleCapabilities::default()
        };
        let unsupported = archive
            .verify_capabilities(&supported_runtime)
            .expect_err("unknown feature");
        assert_eq!(
            unsupported.kind(),
            BundleErrorKind::UnsupportedRequiredFeature
        );

        let mut capabilities = BundleCapabilities {
            runtime_version: "0.4.0-alpha.1".to_owned(),
            supported_features: BTreeSet::from(["trailers".to_owned()]),
            ..BundleCapabilities::default()
        };
        assert_eq!(
            archive
                .verify_capabilities(&capabilities)
                .expect_err("required section")
                .kind(),
            BundleErrorKind::UnsupportedRequiredSection
        );
        capabilities.supported_sections.insert(
            "service_graph".to_owned(),
            "oxidase.service-graph/v1".to_owned(),
        );
        archive
            .verify_capabilities(&capabilities)
            .expect("all required capabilities supported");

        let mut smuggled = manifest();
        smuggled.sections.insert(
            "mandatory_policy".to_owned(),
            StableSection {
                schema: "oxidase.service-graph/v1".to_owned(),
                required: true,
                payload: CanonicalValue::Null,
            },
        );
        let smuggled = BundleArchive::parse(
            &BundleBuilder::new(smuggled)
                .build()
                .expect("smuggled-name fixture builds"),
            &BundleLimits::default(),
        )
        .expect("smuggled-name fixture parses");
        assert_eq!(
            smuggled
                .verify_capabilities(&capabilities)
                .expect_err("a known schema under an unconsumed required name is rejected")
                .kind(),
            BundleErrorKind::UnsupportedRequiredSection
        );
    }

    #[test]
    fn runtime_version_requirement_is_strict_semver() {
        let bytes = BundleBuilder::new(manifest()).build().expect("bundle");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let supported_sections = BTreeMap::from([(
            "service_graph".to_owned(),
            "oxidase.service-graph/v1".to_owned(),
        )]);
        for version in ["0.4.0-alpha.1", "0.4.0", "1.0.0"] {
            archive
                .verify_capabilities(&BundleCapabilities {
                    runtime_version: version.to_owned(),
                    supported_sections: supported_sections.clone(),
                    ..BundleCapabilities::default()
                })
                .expect("equal or newer runtime");
        }
        assert_eq!(
            archive
                .verify_capabilities(&BundleCapabilities {
                    runtime_version: "0.4.0-alpha.0".to_owned(),
                    supported_sections: supported_sections.clone(),
                    ..BundleCapabilities::default()
                })
                .expect_err("older runtime")
                .kind(),
            BundleErrorKind::RuntimeTooOld
        );
        assert_eq!(
            archive
                .verify_capabilities(&BundleCapabilities {
                    runtime_version: "not-semver".to_owned(),
                    supported_sections,
                    ..BundleCapabilities::default()
                })
                .expect_err("invalid runtime version")
                .kind(),
            BundleErrorKind::InvalidRuntimeVersion
        );

        let mut invalid_manifest = manifest();
        invalid_manifest.minimum_runtime_version = "future".to_owned();
        let invalid_bytes = BundleBuilder::new(invalid_manifest)
            .build()
            .expect("format can preserve future-invalid requirement for verifier diagnostics");
        let invalid = BundleArchive::parse(&invalid_bytes, &BundleLimits::default())
            .expect("parse invalid requirement");
        assert_eq!(
            invalid
                .verify_capabilities(&BundleCapabilities::default())
                .expect_err("invalid bundle requirement")
                .kind(),
            BundleErrorKind::InvalidRuntimeVersion
        );
    }

    #[test]
    fn unknown_optional_metadata_is_preserved_without_capability_failure() {
        let mut source = manifest();
        source.optional_metadata.insert(
            "future.vendor.annotation".to_owned(),
            CanonicalValue::Object(BTreeMap::from([(
                "answer".to_owned(),
                CanonicalValue::Unsigned(42),
            )])),
        );
        let bytes = BundleBuilder::new(source.clone()).build().expect("bundle");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        assert_eq!(
            archive.manifest().optional_metadata,
            source.optional_metadata
        );
    }

    #[test]
    fn sensitive_references_are_redacted_and_never_embed_secret_bytes() {
        let secret = "super-secret-token-material";
        let mut source = manifest();
        source.sensitive_references.insert(
            "admin-token".to_owned(),
            SensitiveReference {
                kind: SensitiveReferenceKind::Secret,
                base: AssetReferenceBase::Absolute,
                runtime_path: "/run/secrets/oxidase-admin-token".to_owned(),
                max_bytes: 4096,
            },
        );
        let bytes = BundleBuilder::new(source).build().expect("bundle");
        assert!(!String::from_utf8_lossy(&bytes).contains(secret));
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let debug = format!("{:?}", archive.manifest().sensitive_references);
        assert!(!debug.contains("/run/secrets"));
        let archive_debug = format!("{archive:?}");
        assert!(!archive_debug.contains("/run/secrets"));
        assert!(!archive_debug.contains(secret));
        let inspection = serde_json::to_string(&archive.inspect(InspectionVerbosity::Safe))
            .expect("inspection JSON");
        assert!(!inspection.contains("/run/secrets"));
        assert!(inspection.contains("admin-token"));
    }

    #[test]
    fn signature_envelope_is_separate_from_content_identity() {
        let (bytes, _) = archive_with_asset(b"asset");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let signed = archive
            .with_signatures(vec![SignatureRecord {
                algorithm: "ed25519".to_owned(),
                key_id: "release-2026".to_owned(),
                signature: "ab".repeat(64),
            }])
            .expect("signed envelope");
        assert_eq!(archive.content_digest(), signed.content_digest());
        assert_ne!(archive.file_digest(), signed.file_digest());
        assert_eq!(signed.signatures().signatures.len(), 1);
    }

    #[test]
    fn malformed_ed25519_shape_is_rejected_without_trust_configuration() {
        let mut builder = BundleBuilder::new(manifest());
        builder.set_signatures(vec![SignatureRecord {
            algorithm: "ed25519".to_owned(),
            key_id: "unknown-key".to_owned(),
            signature: "ab".repeat(63),
        }]);
        let error = builder
            .build()
            .expect_err("short Ed25519 signature must fail structural validation");
        assert_eq!(error.kind(), BundleErrorKind::InvalidSignatureEnvelope);
    }

    #[test]
    fn malformed_unknown_key_cannot_poison_an_otherwise_valid_ed25519_envelope() {
        let (bytes, _) = archive_with_asset(b"signed-content");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let signing_key =
            crate::BundleSigningKey::from_bytes("trusted", &[31_u8; 32]).expect("signing key");
        let signed = archive.sign(&signing_key).expect("valid signature");
        let mut records = signed.signatures().signatures.clone();
        records.push(SignatureRecord {
            algorithm: "ed25519".to_owned(),
            key_id: "unconfigured-key".to_owned(),
            signature: "00".repeat(63),
        });
        let error = signed
            .with_signatures(records)
            .expect_err("all Ed25519 records are structurally strict before key lookup");
        assert_eq!(error.kind(), BundleErrorKind::InvalidSignatureEnvelope);
    }

    #[test]
    fn unknown_future_signature_algorithm_retains_bounded_envelope_semantics() {
        let mut builder = BundleBuilder::new(manifest());
        builder.set_signatures(vec![SignatureRecord {
            algorithm: "future-signature-v1".to_owned(),
            key_id: "future-key".to_owned(),
            signature: "ab".repeat(8),
        }]);
        let bytes = builder
            .build()
            .expect("future algorithm remains representable");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default())
            .expect("future signature envelope remains structurally valid");
        archive.verify().expect("structural verification succeeds");
        let verification = archive
            .verify_ed25519(&[], crate::SignatureRequirement::AllowUnsigned)
            .expect("Ed25519 policy can ignore a bounded future algorithm");
        assert_eq!(verification.untrusted_signature_count, 1);
        assert!(verification.verified_key_ids.is_empty());
    }

    #[test]
    fn blob_ranges_point_at_exact_embedded_bytes() {
        let (bytes, digest) = archive_with_asset(b"0123456789");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        let (offset, length) = archive.blob_file_range(digest).expect("blob range");
        assert_eq!(length, 10);
        assert_eq!(
            &bytes[offset as usize..(offset + length) as usize],
            b"0123456789"
        );
    }

    #[test]
    fn atomic_write_round_trips() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("gateway.oxb");
        let builder = BundleBuilder::new(manifest());
        let digest = builder.write_atomic(&path).expect("atomic write");
        let archive = BundleArchive::read_path(&path, &BundleLimits::default()).expect("read");
        assert_eq!(archive.file_digest(), digest);
    }

    #[test]
    fn path_build_reads_asset_once_and_path_parse_keeps_only_an_index() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = tempfile::tempdir().expect("temporary directory");
        let asset_path = directory.path().join("large.bin");
        let bundle_path = directory.path().join("gateway.oxb");
        let mut asset = File::create(&asset_path).expect("create asset");
        let chunk = [0x5a_u8; 64 * 1024];
        let mut hasher = ContentHasher::new();
        for _ in 0..64 {
            asset.write_all(&chunk).expect("write asset chunk");
            hasher.update(chunk);
        }
        asset.sync_all().expect("sync asset");
        drop(asset);
        let length = (chunk.len() * 64) as u64;
        let digest = BundleDigest::from_content_digest(hasher.finish());
        let reads = Arc::new(AtomicUsize::new(0));

        let mut builder = BundleBuilder::new(manifest());
        let (asset_file, _) =
            open_regular_input(&asset_path, "open counted embedded asset").expect("open asset");
        builder.blobs.insert(
            digest,
            BlobInput::CountingFile {
                file: Arc::new(asset_file),
                length,
                reads: reads.clone(),
            },
        );
        builder.manifest_mut().assets.insert(
            "large.bin".to_owned(),
            AssetDescriptor {
                storage: AssetStorage::Embedded {
                    blob: digest,
                    length,
                },
            },
        );
        builder
            .write_atomic(&bundle_path)
            .expect("streaming atomic write");
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        let archive = BundleArchive::read_path(&bundle_path, &BundleLimits::default())
            .expect("streaming path parse");
        assert!(archive.blob(digest).is_none());
        let mut read_only_backing = archive
            .try_clone_backing_file()
            .expect("clone pinned backing")
            .expect("path archive has backing file");
        assert!(
            read_only_backing.write_all(b"mutation").is_err(),
            "published Bundle backing handles must not retain write access"
        );
        let (offset, indexed_length) = archive.blob_file_range(digest).expect("indexed blob");
        assert_eq!(indexed_length, length);
        assert!(offset >= HEADER_LEN as u64);
    }

    #[cfg(unix)]
    #[test]
    fn builder_pins_opened_asset_across_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let old_path = directory.path().join("old.bin");
        let new_path = directory.path().join("new.bin");
        let active_path = directory.path().join("active.bin");
        let replacement_link = directory.path().join("replacement-link");
        let old_bytes = b"old-pinned-content";
        let new_bytes = b"new-pinned-content";
        assert_eq!(old_bytes.len(), new_bytes.len());
        std::fs::write(&old_path, old_bytes).expect("old Asset writes");
        std::fs::write(&new_path, new_bytes).expect("new Asset writes");
        symlink(&old_path, &active_path).expect("active symlink targets old Asset");

        let digest = BundleDigest::of_bytes(old_bytes);
        let length = old_bytes.len() as u64;
        let mut builder = BundleBuilder::new(manifest());
        builder
            .add_blob_path(&active_path, digest, length)
            .expect("builder safely opens old Asset");
        builder.manifest_mut().assets.insert(
            "asset.bin".to_owned(),
            AssetDescriptor {
                storage: AssetStorage::Embedded {
                    blob: digest,
                    length,
                },
            },
        );

        symlink(&new_path, &replacement_link).expect("replacement symlink targets new Asset");
        std::fs::rename(&replacement_link, &active_path)
            .expect("active symlink is atomically replaced");
        let bytes = builder.build().expect("pinned builder completes");
        let archive = BundleArchive::parse(&bytes, &BundleLimits::default()).expect("parse");
        assert_eq!(archive.blob(digest), Some(old_bytes.as_slice()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn builder_rejects_fifo_inputs_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempfile::tempdir().expect("temporary directory");
        let fifo = directory.path().join("asset.fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO is created");

        let mut builder = BundleBuilder::new(manifest());
        let error = builder
            .add_blob_path(&fifo, BundleDigest::of_bytes([]), 0)
            .expect_err("FIFO cannot become an embedded Asset");
        assert_eq!(error.kind(), BundleErrorKind::InvalidModel);

        let error = builder
            .add_blob_file_slice(&fifo, 0, BundleDigest::of_bytes([]), 0)
            .expect_err("FIFO cannot become an embedded Asset slice");
        assert_eq!(error.kind(), BundleErrorKind::InvalidModel);
    }

    #[cfg(unix)]
    #[test]
    fn pinned_archive_survives_atomic_replacement_of_its_source_path() {
        fn read_indexed_blob(archive: &BundleArchive, digest: BundleDigest) -> Vec<u8> {
            let (offset, length) = archive.blob_file_range(digest).expect("blob range");
            let file = archive
                .try_clone_backing_file()
                .expect("clone backing")
                .expect("path archive has backing file");
            let mut bytes = vec![0_u8; length as usize];
            let mut consumed = 0_usize;
            while consumed < bytes.len() {
                let count = read_file_at(&file, &mut bytes[consumed..], offset + consumed as u64)
                    .expect("positional read");
                assert_ne!(count, 0);
                consumed += count;
            }
            bytes
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let active_path = directory.path().join("gateway.oxb");
        let replacement_path = directory.path().join("replacement.oxb");
        let copied_old_path = directory.path().join("copied-old.oxb");
        let (old_bytes, old_digest) = archive_with_asset(b"old-pinned-content");
        std::fs::write(&active_path, old_bytes).expect("write old archive");
        let old = BundleArchive::read_path(&active_path, &BundleLimits::default())
            .expect("open old archive");

        let (new_bytes, new_digest) = archive_with_asset(b"new-replacement-content");
        std::fs::write(&replacement_path, new_bytes).expect("write replacement");
        std::fs::rename(&replacement_path, &active_path).expect("atomically replace archive");
        let new = BundleArchive::read_path(&active_path, &BundleLimits::default())
            .expect("open new archive");

        assert_eq!(read_indexed_blob(&old, old_digest), b"old-pinned-content");
        assert_eq!(
            read_indexed_blob(&new, new_digest),
            b"new-replacement-content"
        );
        old.write_atomic(&copied_old_path)
            .expect("rewrite from pinned handle");
        let copied = BundleArchive::read_path(&copied_old_path, &BundleLimits::default())
            .expect("read copied old archive");
        assert_eq!(
            read_indexed_blob(&copied, old_digest),
            b"old-pinned-content"
        );
    }

    #[test]
    fn verified_archive_survives_in_place_source_inode_mutation() {
        fn read_pinned(archive: &BundleArchive, digest: BundleDigest) -> Vec<u8> {
            let (offset, length) = archive.blob_file_range(digest).expect("blob range");
            let mut output = vec![0_u8; length as usize];
            let mut consumed = 0_usize;
            while consumed < output.len() {
                let count = archive
                    .read_backing_at(&mut output[consumed..], offset + consumed as u64)
                    .expect("positional pinned read");
                assert_ne!(count, 0);
                consumed += count;
            }
            output
        }

        let directory = tempfile::tempdir().expect("temporary directory");
        let active_path = directory.path().join("gateway.oxb");
        let (old_bytes, old_digest) = archive_with_asset(b"old-inode-content");
        std::fs::write(&active_path, old_bytes).expect("write old archive");
        let old = BundleArchive::read_path(&active_path, &BundleLimits::default())
            .expect("verify old archive");

        let (new_bytes, new_digest) = archive_with_asset(b"new-inode-content");
        let mut same_inode = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&active_path)
            .expect("open same inode for mutation");
        same_inode
            .write_all(&new_bytes)
            .expect("overwrite same inode");
        same_inode.sync_all().expect("sync mutated inode");
        drop(same_inode);

        let new = BundleArchive::read_path(&active_path, &BundleLimits::default())
            .expect("verify new archive");
        assert_eq!(read_pinned(&old, old_digest), b"old-inode-content");
        assert_eq!(read_pinned(&new, new_digest), b"new-inode-content");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn path_reader_rejects_fifo_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempfile::tempdir().expect("temporary directory");
        let fifo = directory.path().join("candidate.oxb");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO is created");
        let error = BundleArchive::read_path(&fifo, &BundleLimits::default())
            .expect_err("a Bundle must be a regular file");
        assert_eq!(error.kind(), BundleErrorKind::InvalidModel);
    }

    #[test]
    fn diff_is_deterministic_and_does_not_expose_sensitive_paths() {
        let (left_bytes, _) = archive_with_asset(b"left");
        let (right_bytes, _) = archive_with_asset(b"right");
        let left = BundleArchive::parse(&left_bytes, &BundleLimits::default()).expect("left");
        let right = BundleArchive::parse(&right_bytes, &BundleLimits::default()).expect("right");
        let diff = left.diff(&right);
        assert_eq!(diff.assets_changed, vec!["public/app.js"]);
        assert!(!diff.identical_content);
    }

    #[test]
    fn diff_covers_runtime_features_origins_and_redacted_sensitive_references() {
        fn origin(path: &str, field_path: &str, start_byte: u64) -> crate::SourceOrigin {
            crate::SourceOrigin {
                display_path: path.to_owned(),
                start_byte,
                end_byte: start_byte + 4,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 5,
                field_path: field_path.to_owned(),
            }
        }

        let mut old_manifest = manifest();
        old_manifest.required_features = BTreeSet::from(["http2".to_owned(), "shared".to_owned()]);
        old_manifest.origins.insert(
            "changed".to_owned(),
            origin("gateway.yaml", "services.old", 10),
        );
        old_manifest.origins.insert(
            "removed".to_owned(),
            origin("old.yaml", "services.removed", 20),
        );
        old_manifest.sensitive_references.insert(
            "changed-secret".to_owned(),
            SensitiveReference {
                kind: SensitiveReferenceKind::Secret,
                base: AssetReferenceBase::Absolute,
                runtime_path: "/run/secrets/old-value".to_owned(),
                max_bytes: 1024,
            },
        );
        old_manifest.sensitive_references.insert(
            "removed-key".to_owned(),
            SensitiveReference {
                kind: SensitiveReferenceKind::PrivateKey,
                base: AssetReferenceBase::Absolute,
                runtime_path: "/run/keys/removed-private-key".to_owned(),
                max_bytes: 4096,
            },
        );

        let mut new_manifest = manifest();
        new_manifest.minimum_runtime_version = "0.5.0-alpha.1".to_owned();
        new_manifest.required_features =
            BTreeSet::from(["bundles".to_owned(), "shared".to_owned()]);
        new_manifest.origins.insert(
            "changed".to_owned(),
            origin("gateway.yaml", "services.new", 11),
        );
        new_manifest
            .origins
            .insert("added".to_owned(), origin("new.yaml", "services.added", 30));
        new_manifest.sensitive_references.insert(
            "changed-secret".to_owned(),
            SensitiveReference {
                kind: SensitiveReferenceKind::Secret,
                base: AssetReferenceBase::Absolute,
                runtime_path: "/run/secrets/new-value".to_owned(),
                max_bytes: 2048,
            },
        );
        new_manifest.sensitive_references.insert(
            "added-key".to_owned(),
            SensitiveReference {
                kind: SensitiveReferenceKind::PrivateKey,
                base: AssetReferenceBase::DeploymentRoot,
                runtime_path: "secrets/new-private-key".to_owned(),
                max_bytes: 4096,
            },
        );

        let old_bytes = BundleBuilder::new(old_manifest)
            .build()
            .expect("old bundle");
        let new_bytes = BundleBuilder::new(new_manifest)
            .build()
            .expect("new bundle");
        let old = BundleArchive::parse(&old_bytes, &BundleLimits::default()).expect("old");
        let new = BundleArchive::parse(&new_bytes, &BundleLimits::default()).expect("new");
        let diff = old.diff(&new);

        assert!(diff.minimum_runtime_version_changed);
        assert_eq!(diff.required_features_added, ["bundles"]);
        assert_eq!(diff.required_features_removed, ["http2"]);
        assert_eq!(diff.origins_added, ["added"]);
        assert_eq!(diff.origins_removed, ["removed"]);
        assert_eq!(diff.origins_changed, ["changed"]);
        assert_eq!(diff.sensitive_references_added, ["added-key"]);
        assert_eq!(diff.sensitive_references_removed, ["removed-key"]);
        assert_eq!(diff.sensitive_references_changed, ["changed-secret"]);
        let json = serde_json::to_string(&diff).expect("diff JSON");
        assert!(!json.contains("/run/secrets"));
        assert!(!json.contains("private-key"));
    }

    #[test]
    fn error_codes_are_stable_and_safe() {
        let error = BundleArchive::parse(b"not a bundle", &BundleLimits::default())
            .expect_err("invalid input");
        assert_eq!(error.code(), "bundle.truncated");
        assert!(!error.message().contains('/'));
    }
}
