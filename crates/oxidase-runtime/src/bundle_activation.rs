//! Shared, source-free Bundle activation boundary.
//!
//! Signature policy is enforced by the caller (standalone CLI or candidate
//! store). This module revalidates the canonical archive and capabilities,
//! resolves every content reference, pins Asset bytes, and performs ordinary
//! runtime preparation before a snapshot can be published.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oxidase_bundle::{
    AssetReferenceBase, AssetStorage, BundleArchive, BundleCapabilities, BundleError,
    BundleManifest, SensitiveReference, SensitiveReferenceKind,
};
use oxidase_core::{ContentDigest, ContentHasher};
use oxidase_site::{AssetSource, PortableSiteError};

use crate::{
    CandidateWorkControl, MAX_PRIVATE_KEY_BYTES, PORTABLE_RUNTIME_PLAN_SCHEMA_V1,
    PortableRuntimeError, PortableRuntimePlanV1, ResourceReuse, RuntimeSnapshot,
};

const RUNTIME_SECTION: &str = "runtime";

#[derive(Debug)]
pub enum BundleActivationError {
    Archive(BundleError),
    Runtime(PortableRuntimeError),
    Io { code: &'static str, message: String },
    Invalid { code: &'static str, message: String },
}

impl BundleActivationError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Archive(error) => error.code(),
            Self::Runtime(error) => error.code(),
            Self::Io { code, .. } | Self::Invalid { code, .. } => code,
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::Archive(error) => error.to_string(),
            Self::Runtime(error) => error.to_string(),
            Self::Io { message, .. } | Self::Invalid { message, .. } => message.clone(),
        }
    }

    #[must_use]
    pub const fn offset(&self) -> Option<u64> {
        match self {
            Self::Archive(error) => error.offset(),
            Self::Runtime(_) | Self::Io { .. } | Self::Invalid { .. } => None,
        }
    }

    #[must_use]
    pub fn structured_diagnostics(&self) -> Option<Vec<oxidase_core::Diagnostic>> {
        match self {
            Self::Runtime(PortableRuntimeError::Preparation(error)) => {
                Some(error.diagnostics().to_vec())
            }
            _ => None,
        }
    }
}

impl fmt::Display for BundleActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl std::error::Error for BundleActivationError {}

impl From<BundleError> for BundleActivationError {
    fn from(value: BundleError) -> Self {
        Self::Archive(value)
    }
}

impl From<PortableRuntimeError> for BundleActivationError {
    fn from(value: PortableRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[derive(Debug)]
pub struct PreparedBundleActivation {
    pub snapshot: RuntimeSnapshot,
    pub reuse: ResourceReuse,
}

/// Exact capabilities accepted by this runtime's source-free loader.
#[must_use]
pub fn bundle_runtime_capabilities() -> BundleCapabilities {
    BundleCapabilities {
        runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
        supported_features: BTreeSet::from([
            "portable-runtime".to_owned(),
            oxidase_config::UPSTREAM_DEADLINES_FEATURE.to_owned(),
            oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE.to_owned(),
        ]),
        supported_sections: BTreeMap::from([(
            RUNTIME_SECTION.to_owned(),
            PORTABLE_RUNTIME_PLAN_SCHEMA_V1.to_owned(),
        )]),
    }
}

/// Rebuilds a candidate snapshot from an already signature-authorized archive.
///
/// External Asset bytes are copied to anonymous immutable spools after digest
/// verification. Secret/private-key references remain external and are opened
/// by the ordinary runtime preparation transaction on every activation.
pub fn prepare_bundle_archive(
    archive: &BundleArchive,
    bundle_path: &Path,
    deployment_root: &Path,
    previous: Option<&RuntimeSnapshot>,
) -> Result<PreparedBundleActivation, BundleActivationError> {
    prepare_bundle_archive_controlled(
        archive,
        bundle_path,
        deployment_root,
        previous,
        &CandidateWorkControl::default(),
    )
}

/// Cooperative preparation for the single bounded management worker. The
/// caller keeps its admission permit inside that worker until this returns.
/// Cancellation is checked before/after decoding and at every Asset boundary;
/// external representation hashing/copying checks at most every 64 KiB.
pub fn prepare_bundle_archive_controlled(
    archive: &BundleArchive,
    bundle_path: &Path,
    deployment_root: &Path,
    previous: Option<&RuntimeSnapshot>,
    control: &CandidateWorkControl,
) -> Result<PreparedBundleActivation, BundleActivationError> {
    checkpoint(control)?;
    archive.verify()?;
    archive.verify_capabilities(&bundle_runtime_capabilities())?;
    checkpoint(control)?;
    let plan = decode_runtime_plan(archive)?;
    checkpoint(control)?;
    validate_sensitive_references(archive.manifest(), &plan)?;
    validate_asset_set(archive.manifest(), &plan)?;
    validate_deployment_root(deployment_root)?;
    validate_reference_sensitive_isolation(archive.manifest(), deployment_root)?;
    let pinned_file = Arc::new(archive.try_clone_backing_file()?.ok_or_else(|| {
        invalid(
            "bundle.backing_missing",
            "Bundle archive has no pinned backing file",
        )
    })?);
    let display_path = Arc::new(bundle_path.to_path_buf());
    let dependencies = runtime_dependencies(bundle_path, archive.manifest(), deployment_root)?;
    let mut resolver = CachedAssetResolver::new(
        archive,
        &pinned_file,
        &display_path,
        deployment_root,
        control,
    );
    let identity: ContentDigest = archive.content_digest().into();
    let (snapshot, reuse) = plan.prepare_with_assets(
        identity,
        deployment_root,
        dependencies,
        |key, digest, length| resolver.resolve(key, digest, length),
        previous,
    )?;
    checkpoint(control)?;
    Ok(PreparedBundleActivation { snapshot, reuse })
}

fn checkpoint(control: &CandidateWorkControl) -> Result<(), BundleActivationError> {
    control.checkpoint().map_err(|error| {
        invalid(
            error.code(),
            "Bundle preparation was cancelled or its deadline elapsed",
        )
    })
}

fn decode_runtime_plan(
    archive: &BundleArchive,
) -> Result<PortableRuntimePlanV1, BundleActivationError> {
    let section = archive
        .manifest()
        .sections
        .get(RUNTIME_SECTION)
        .ok_or_else(|| {
            invalid(
                "bundle.runtime_section_missing",
                "Bundle does not contain the required runtime section",
            )
        })?;
    if section.schema != PORTABLE_RUNTIME_PLAN_SCHEMA_V1 || !section.required {
        return Err(invalid(
            "bundle.runtime_section_schema",
            format!("runtime section must be required schema `{PORTABLE_RUNTIME_PLAN_SCHEMA_V1}`"),
        ));
    }
    let plan: PortableRuntimePlanV1 = section.to_serde()?;
    for feature in plan.required_features() {
        if !archive.manifest().required_features.contains(&feature) {
            return Err(invalid(
                "bundle.required_feature_missing",
                format!("runtime plan requires manifest feature `{feature}`"),
            ));
        }
    }
    Ok(plan)
}

struct CachedAssetResolver<'a> {
    archive: &'a BundleArchive,
    pinned_file: &'a Arc<File>,
    display_path: &'a Arc<PathBuf>,
    deployment_root: &'a Path,
    control: &'a CandidateWorkControl,
    cache: BTreeMap<String, (ContentDigest, u64, AssetSource)>,
}

impl<'a> CachedAssetResolver<'a> {
    fn new(
        archive: &'a BundleArchive,
        pinned_file: &'a Arc<File>,
        display_path: &'a Arc<PathBuf>,
        deployment_root: &'a Path,
        control: &'a CandidateWorkControl,
    ) -> Self {
        Self {
            archive,
            pinned_file,
            display_path,
            deployment_root,
            control,
            cache: BTreeMap::new(),
        }
    }

    fn resolve(
        &mut self,
        key: &str,
        digest: ContentDigest,
        length: u64,
    ) -> Result<AssetSource, PortableSiteError> {
        checkpoint(self.control).map_err(|error| {
            PortableSiteError::asset_resolution_with_code(error.code(), error.message())
        })?;
        if let Some((cached_digest, cached_length, source)) = self.cache.get(key) {
            if *cached_digest != digest || *cached_length != length {
                return Err(PortableSiteError::asset_resolution(format!(
                    "content key `{key}` is used with inconsistent representation metadata"
                )));
            }
            return Ok(source.clone());
        }
        let source = resolve_asset(self, key, digest, length)?;
        self.cache
            .insert(key.to_owned(), (digest, length, source.clone()));
        Ok(source)
    }
}

fn resolve_asset(
    resolver: &CachedAssetResolver<'_>,
    key: &str,
    digest: ContentDigest,
    length: u64,
) -> Result<AssetSource, PortableSiteError> {
    let descriptor = resolver.archive.manifest().assets.get(key).ok_or_else(|| {
        PortableSiteError::asset_resolution(format!("content key `{key}` is not in the manifest"))
    })?;
    match &descriptor.storage {
        AssetStorage::Embedded {
            blob,
            length: declared,
        } => {
            if blob.content_digest() != digest || *declared != length {
                return Err(PortableSiteError::asset_resolution(format!(
                    "embedded Asset `{key}` metadata disagrees with its compiled representation"
                )));
            }
            let (offset, blob_length) =
                resolver.archive.blob_file_range(*blob).ok_or_else(|| {
                    PortableSiteError::asset_resolution(format!(
                        "embedded Asset `{key}` has no verified blob range"
                    ))
                })?;
            if blob_length != length {
                return Err(PortableSiteError::asset_resolution(format!(
                    "embedded Asset `{key}` blob length is inconsistent"
                )));
            }
            Ok(AssetSource::Pinned {
                file: Arc::clone(resolver.pinned_file),
                display: Arc::clone(resolver.display_path),
                offset,
                origin: None,
            })
        }
        AssetStorage::Reference {
            base,
            path,
            expected_digest,
            length: declared,
        } => {
            if expected_digest.content_digest() != digest || *declared != length {
                return Err(PortableSiteError::asset_resolution(format!(
                    "external Asset `{key}` metadata disagrees with its compiled representation"
                )));
            }
            let path = resolve_asset_reference(*base, path, resolver.deployment_root).map_err(
                |error| {
                    PortableSiteError::asset_resolution_with_code(error.code(), error.message())
                },
            )?;
            let (file, origin) = verify_external_asset(&path, digest, length, resolver.control)
                .map_err(|error| {
                    PortableSiteError::asset_resolution_with_code(error.code(), error.message())
                })?;
            Ok(AssetSource::pinned_with_origin(file, origin, path, 0))
        }
    }
}

fn validate_sensitive_references(
    manifest: &BundleManifest,
    plan: &PortableRuntimePlanV1,
) -> Result<(), BundleActivationError> {
    let mut expected = BTreeMap::new();
    for (id, secret) in &plan.gateway.secrets {
        expected.insert(
            format!("secret:{id}"),
            SensitiveReference {
                kind: SensitiveReferenceKind::Secret,
                base: portable_base(&secret.file.base)?,
                runtime_path: secret.file.path.clone(),
                max_bytes: secret.max_bytes,
            },
        );
    }
    for (id, certificate) in &plan.gateway.certificates {
        expected.insert(
            format!("private-key:{id}"),
            SensitiveReference {
                kind: SensitiveReferenceKind::PrivateKey,
                base: portable_base(&certificate.private_key.base)?,
                runtime_path: certificate.private_key.path.clone(),
                max_bytes: MAX_PRIVATE_KEY_BYTES,
            },
        );
    }
    if manifest.sensitive_references != expected {
        return Err(invalid(
            "bundle.sensitive_reference_mismatch",
            "Bundle sensitive-reference index does not exactly match its runtime plan",
        ));
    }
    Ok(())
}

fn validate_asset_set(
    manifest: &BundleManifest,
    plan: &PortableRuntimePlanV1,
) -> Result<(), BundleActivationError> {
    let expected = plan.asset_keys();
    let actual = manifest.assets.keys().cloned().collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(invalid(
            "bundle.asset_set_mismatch",
            "Bundle Asset index does not exactly match its executable Site plans",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ReferenceFileIdentity {
    declared: PathBuf,
    canonical: Option<PathBuf>,
    #[cfg(unix)]
    device: Option<u64>,
    #[cfg(unix)]
    inode: Option<u64>,
}

impl ReferenceFileIdentity {
    fn observe(path: PathBuf) -> Self {
        let canonical = path.canonicalize().ok();
        let metadata = open_external_asset(&path)
            .ok()
            .and_then(|file| file.metadata().ok())
            .filter(std::fs::Metadata::is_file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            Self {
                declared: path,
                canonical,
                device: metadata.as_ref().map(std::fs::Metadata::dev),
                inode: metadata.as_ref().map(std::fs::Metadata::ino),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self {
                declared: path,
                canonical,
            }
        }
    }

    fn refers_to_same_file(&self, other: &Self) -> bool {
        if self.declared == other.declared
            || self
                .canonical
                .as_ref()
                .zip(other.canonical.as_ref())
                .is_some_and(|(left, right)| left == right)
        {
            return true;
        }
        #[cfg(unix)]
        if self.device.zip(self.inode).is_some()
            && self.device == other.device
            && self.inode == other.inode
        {
            return true;
        }
        false
    }
}

fn validate_reference_sensitive_isolation(
    manifest: &BundleManifest,
    deployment_root: &Path,
) -> Result<(), BundleActivationError> {
    if manifest.sensitive_references.is_empty() {
        return Ok(());
    }
    let sensitive = manifest
        .sensitive_references
        .values()
        .map(|reference| {
            resolve_reference(reference.base, &reference.runtime_path, deployment_root)
                .map(ReferenceFileIdentity::observe)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for descriptor in manifest.assets.values() {
        let AssetStorage::Reference { base, path, .. } = &descriptor.storage else {
            continue;
        };
        let asset =
            ReferenceFileIdentity::observe(resolve_asset_reference(*base, path, deployment_root)?);
        if sensitive
            .iter()
            .any(|candidate| asset.refers_to_same_file(candidate))
        {
            return Err(invalid(
                "resource.sensitive_site_asset_overlap",
                "a Bundle reference Asset overlaps a Secret or certificate private-key file",
            ));
        }
    }
    Ok(())
}

fn portable_base(value: &str) -> Result<AssetReferenceBase, BundleActivationError> {
    match value {
        "absolute" => Ok(AssetReferenceBase::Absolute),
        "deployment_root" => Ok(AssetReferenceBase::DeploymentRoot),
        _ => Err(invalid(
            "bundle.path_reference",
            "runtime plan contains an unknown path-reference base",
        )),
    }
}

fn runtime_dependencies(
    bundle_path: &Path,
    manifest: &BundleManifest,
    deployment_root: &Path,
) -> Result<Vec<PathBuf>, BundleActivationError> {
    let mut dependencies = BTreeSet::from([bundle_path.to_path_buf()]);
    for asset in manifest.assets.values() {
        if let AssetStorage::Reference { base, path, .. } = &asset.storage {
            dependencies.insert(resolve_reference(*base, path, deployment_root)?);
        }
    }
    for reference in manifest.sensitive_references.values() {
        dependencies.insert(resolve_reference(
            reference.base,
            &reference.runtime_path,
            deployment_root,
        )?);
    }
    Ok(dependencies.into_iter().collect())
}

fn verify_external_asset(
    path: &Path,
    expected_digest: ContentDigest,
    expected_length: u64,
    control: &CandidateWorkControl,
) -> Result<(File, File), BundleActivationError> {
    checkpoint(control)?;
    let mut pinned = tempfile::NamedTempFile::new().map_err(|error| BundleActivationError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot create immutable external Asset backing: {error}"),
    })?;
    let origin = copy_and_verify_external_asset(
        path,
        expected_digest,
        expected_length,
        Some(pinned.as_file_mut()),
        control,
    )?;
    checkpoint(control)?;
    pinned
        .as_file()
        .sync_data()
        .map_err(|error| BundleActivationError::Io {
            code: "bundle.asset_reference_io",
            message: format!("cannot flush immutable external Asset backing: {error}"),
        })?;
    let immutable = File::open(pinned.path()).map_err(|error| BundleActivationError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot open immutable external Asset backing: {error}"),
    })?;
    drop(pinned);
    checkpoint(control)?;
    Ok((immutable, origin))
}

fn copy_and_verify_external_asset(
    path: &Path,
    expected_digest: ContentDigest,
    expected_length: u64,
    immutable_copy: Option<&mut File>,
    control: &CandidateWorkControl,
) -> Result<File, BundleActivationError> {
    let file = open_external_asset(path).map_err(|error| BundleActivationError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot open external Bundle Asset: {error}"),
    })?;
    let metadata = file.metadata().map_err(|error| BundleActivationError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot inspect external Bundle Asset handle: {error}"),
    })?;
    copy_and_verify_opened_external_asset(
        file,
        metadata,
        expected_digest,
        expected_length,
        immutable_copy,
        control,
    )
}

fn copy_and_verify_opened_external_asset(
    mut file: File,
    metadata: std::fs::Metadata,
    expected_digest: ContentDigest,
    expected_length: u64,
    immutable_copy: Option<&mut File>,
    control: &CandidateWorkControl,
) -> Result<File, BundleActivationError> {
    if !metadata.is_file() || metadata.len() != expected_length {
        return Err(invalid(
            "bundle.asset_reference_mismatch",
            "external Bundle Asset is not a regular file of the declared length",
        ));
    }
    copy_and_hash(
        &mut file,
        immutable_copy,
        expected_digest,
        expected_length,
        control,
    )?;
    checkpoint(control)?;
    let after = file.metadata().map_err(|error| BundleActivationError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot revalidate external Bundle Asset handle: {error}"),
    })?;
    if !after.is_file() || after.len() != expected_length {
        return Err(invalid(
            "bundle.asset_reference_mismatch",
            "external Bundle Asset changed while being verified",
        ));
    }
    Ok(file)
}

fn copy_and_hash<R: std::io::Read, W: std::io::Write>(
    file: &mut R,
    mut immutable_copy: Option<&mut W>,
    expected_digest: ContentDigest,
    expected_length: u64,
    control: &CandidateWorkControl,
) -> Result<(), BundleActivationError> {
    let mut hasher = ContentHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        checkpoint(control)?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| BundleActivationError::Io {
                code: "bundle.asset_reference_io",
                message: format!("cannot read external Bundle Asset: {error}"),
            })?;
        if read == 0 {
            break;
        }
        checkpoint(control)?;
        if length.saturating_add(read as u64) > expected_length {
            return Err(invalid(
                "bundle.asset_reference_mismatch",
                "external Bundle Asset grew beyond the declared length",
            ));
        }
        if let Some(copy) = immutable_copy.as_deref_mut() {
            copy.write_all(&buffer[..read])
                .map_err(|error| BundleActivationError::Io {
                    code: "bundle.asset_reference_io",
                    message: format!("cannot pin external Bundle Asset: {error}"),
                })?;
        }
        hasher.update(&buffer[..read]);
        length = length.checked_add(read as u64).ok_or_else(|| {
            invalid(
                "bundle.asset_reference_mismatch",
                "external Bundle Asset length overflowed during verification",
            )
        })?;
    }
    if length != expected_length || hasher.finish() != expected_digest {
        return Err(invalid(
            "bundle.asset_reference_mismatch",
            "external Bundle Asset content digest does not match the manifest",
        ));
    }
    checkpoint(control)?;
    Ok(())
}

#[cfg(unix)]
fn open_external_asset(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};

    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_external_asset(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn validate_deployment_root(path: &Path) -> Result<(), BundleActivationError> {
    if !path.is_absolute() || !path.is_dir() {
        return Err(invalid(
            "bundle.deployment_root",
            "Bundle deployment root must be an existing absolute directory",
        ));
    }
    Ok(())
}

fn normalized_relative(path: &Path) -> Result<String, BundleActivationError> {
    let value = path
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or_else(|| invalid("bundle.path_encoding", "Bundle path is not UTF-8"))?;
    if value.is_empty()
        || value.starts_with('/')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(invalid(
            "bundle.path_reference",
            "Bundle deployment-relative path is not normalized",
        ));
    }
    Ok(value)
}

fn resolve_reference(
    base: AssetReferenceBase,
    path: &str,
    deployment_root: &Path,
) -> Result<PathBuf, BundleActivationError> {
    match base {
        AssetReferenceBase::Absolute => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(invalid(
                    "bundle.path_reference",
                    "absolute Bundle reference is not absolute",
                ));
            }
            Ok(path)
        }
        AssetReferenceBase::DeploymentRoot => {
            Ok(deployment_root.join(normalized_relative(Path::new(path))?))
        }
    }
}

fn resolve_asset_reference(
    base: AssetReferenceBase,
    path: &str,
    deployment_root: &Path,
) -> Result<PathBuf, BundleActivationError> {
    let declared = resolve_reference(base, path, deployment_root)?;
    let canonical = declared
        .canonicalize()
        .map_err(|error| BundleActivationError::Io {
            code: "bundle.asset_reference_io",
            message: format!("cannot resolve external Bundle Asset: {error}"),
        })?;
    if base == AssetReferenceBase::DeploymentRoot && !canonical.starts_with(deployment_root) {
        return Err(invalid(
            "bundle.asset_reference_escape",
            "deployment-relative Asset resolves outside the deployment root",
        ));
    }
    Ok(canonical)
}

fn invalid(code: &'static str, message: impl Into<String>) -> BundleActivationError {
    BundleActivationError::Invalid {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use oxidase_bundle::{BuildMetadata, BundleBuilder, BundleManifest};
    use tempfile::tempdir;

    use super::{bundle_runtime_capabilities, prepare_bundle_archive};

    #[test]
    fn runtime_capabilities_are_exact_and_versioned() {
        let capabilities = bundle_runtime_capabilities();
        assert_eq!(
            capabilities.supported_features,
            BTreeSet::from([
                "portable-runtime".to_owned(),
                oxidase_config::UPSTREAM_DEADLINES_FEATURE.to_owned(),
                oxidase_config::DNS_ADDRESS_DISCOVERY_FEATURE.to_owned(),
            ])
        );
        assert_eq!(
            capabilities.supported_sections,
            BTreeMap::from([("runtime".to_owned(), "oxidase.runtime-plan/v1".to_owned())])
        );
    }

    #[test]
    fn activation_rejects_archive_without_runtime_section() {
        let directory = tempdir().expect("temporary directory");
        let bundle = directory.path().join("candidate.oxb");
        let manifest = BundleManifest::new(
            BuildMetadata {
                tool_version: env!("CARGO_PKG_VERSION").to_owned(),
                source_commit: None,
                gateway_api: oxidase_config::API_VERSION.to_owned(),
                oxista_api: oxidase_site::SITE_API_VERSION.to_owned(),
            },
            env!("CARGO_PKG_VERSION"),
        );
        BundleBuilder::new(manifest)
            .write_atomic(&bundle)
            .expect("fixture Bundle writes");
        let archive = oxidase_bundle::BundleArchive::read_path(
            &bundle,
            &oxidase_bundle::BundleLimits::default(),
        )
        .expect("fixture Bundle parses");
        let error = prepare_bundle_archive(&archive, &bundle, directory.path(), None)
            .expect_err("missing runtime section is rejected");
        assert_eq!(error.code(), "bundle.runtime_section_missing");
    }

    #[test]
    fn external_copy_stops_at_the_next_chunk_after_cancellation() {
        struct CancellingWriter {
            bytes: Vec<u8>,
            control: crate::CandidateWorkControl,
        }
        impl std::io::Write for CancellingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.bytes.extend_from_slice(bytes);
                self.control.cancel();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let bytes = vec![b'a'; 128 * 1024];
        let control = crate::CandidateWorkControl::default();
        let mut writer = CancellingWriter {
            bytes: Vec::new(),
            control: control.clone(),
        };
        let error = super::copy_and_hash(
            &mut std::io::Cursor::new(&bytes),
            Some(&mut writer),
            oxidase_core::ContentDigest::of_bytes(&bytes),
            bytes.len() as u64,
            &control,
        )
        .expect_err("cancelled worker does not finish the second chunk");
        assert_eq!(error.code(), "candidate.cancelled");
        assert_eq!(writer.bytes.len(), 64 * 1024);
    }

    #[test]
    fn external_copy_exact_length_and_expired_deadline_are_checked_before_io() {
        let bytes = vec![b'a'; 64 * 1024];
        let mut output = Vec::new();
        super::copy_and_hash(
            &mut std::io::Cursor::new(&bytes),
            Some(&mut output),
            oxidase_core::ContentDigest::of_bytes(&bytes),
            bytes.len() as u64,
            &crate::CandidateWorkControl::default(),
        )
        .expect("exactly one chunk is valid");
        assert_eq!(output, bytes);

        struct NoIo;
        impl std::io::Read for NoIo {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("expired preparation must not read");
            }
        }
        let expired = crate::CandidateWorkControl::with_deadline(std::time::Instant::now());
        let error = super::copy_and_hash::<_, Vec<u8>>(
            &mut NoIo,
            None,
            oxidase_core::ContentDigest::of_bytes([]),
            0,
            &expired,
        )
        .expect_err("deadline equality is already expired");
        assert_eq!(error.code(), "candidate.deadline");
    }

    #[test]
    fn external_copy_never_spools_bytes_above_declared_capacity() {
        let bytes = vec![b'a'; 64 * 1024 + 1];
        let mut output = Vec::new();
        let error = super::copy_and_hash(
            &mut std::io::Cursor::new(&bytes),
            Some(&mut output),
            oxidase_core::ContentDigest::of_bytes(&bytes),
            64 * 1024,
            &crate::CandidateWorkControl::default(),
        )
        .expect_err("growth is rejected before writing an over-limit chunk");
        assert_eq!(error.code(), "bundle.asset_reference_mismatch");
        assert_eq!(output.len(), 64 * 1024);
    }
}
