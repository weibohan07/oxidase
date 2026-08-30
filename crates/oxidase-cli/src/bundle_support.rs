use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oxidase_bundle::{
    AssetDescriptor, AssetReferenceBase, AssetStorage, BuildMetadata, BundleArchive, BundleBuilder,
    BundleCapabilities, BundleDiff, BundleError, BundleInspection, BundleLimits, BundleManifest,
    BundleSigningKey, BundleVerification, BundleVerificationKey, InspectionVerbosity,
    SensitiveReference, SensitiveReferenceKind, SignatureRequirement, SignatureVerification,
    SourceOrigin, StableSection,
};
use oxidase_config::{BundleAssetMode, CompiledGateway};
use oxidase_core::{ContentDigest, ContentHasher};
use oxidase_runtime::{
    MAX_PRIVATE_KEY_BYTES, PORTABLE_RUNTIME_PLAN_SCHEMA_V1, PortableRuntimeError,
    PortableRuntimePlanV1, RuntimeSnapshot,
};
use oxidase_site::{AssetSource, PortableAssetInputV1, PortableSiteError};
use serde::Serialize;

const RUNTIME_SECTION: &str = "runtime";

#[derive(Debug)]
pub(crate) enum BundleCliError {
    Archive(BundleError),
    Runtime(PortableRuntimeError),
    Io { code: &'static str, message: String },
    Invalid { code: &'static str, message: String },
}

impl BundleCliError {
    pub(crate) fn structured_diagnostics(&self) -> Option<Vec<oxidase_core::Diagnostic>> {
        match self {
            Self::Runtime(PortableRuntimeError::Preparation(error)) => {
                Some(error.diagnostics().to_vec())
            }
            _ => None,
        }
    }

    pub(crate) const fn code(&self) -> &'static str {
        match self {
            Self::Archive(error) => error.code(),
            Self::Runtime(error) => error.code(),
            Self::Io { code, .. } | Self::Invalid { code, .. } => code,
        }
    }

    pub(crate) fn message(&self) -> String {
        match self {
            Self::Archive(error) => error.to_string(),
            Self::Runtime(error) => error.to_string(),
            Self::Io { message, .. } | Self::Invalid { message, .. } => message.clone(),
        }
    }

    pub(crate) const fn offset(&self) -> Option<u64> {
        match self {
            Self::Archive(error) => error.offset(),
            Self::Runtime(_) | Self::Io { .. } | Self::Invalid { .. } => None,
        }
    }
}

impl From<BundleError> for BundleCliError {
    fn from(value: BundleError) -> Self {
        Self::Archive(value)
    }
}

impl From<PortableRuntimeError> for BundleCliError {
    fn from(value: PortableRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleBuildOutput {
    pub output: String,
    pub file_digest: String,
    pub content_digest: String,
    pub assets: usize,
    pub embedded_blobs: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleVerifyOutput {
    #[serde(flatten)]
    pub structural: BundleVerification,
    pub verified_key_ids: BTreeSet<String>,
    pub untrusted_signature_count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleSignOutput {
    pub output: String,
    pub key_id: String,
    pub content_digest: String,
    pub file_digest: String,
}

pub(crate) struct LoadedBundle {
    pub snapshot: RuntimeSnapshot,
    pub verification: SignatureVerification,
    pub inspection: BundleInspection,
}

struct CachedAssetResolver<'a> {
    archive: &'a BundleArchive,
    pinned_file: &'a Arc<File>,
    display_path: &'a Arc<PathBuf>,
    deployment_root: &'a Path,
    reference_mode: ReferenceAssetMode,
    cache: BTreeMap<String, (ContentDigest, u64, AssetSource)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceAssetMode {
    /// Verify external bytes without retaining a second full-size spool. This
    /// is safe only for semantic validation whose compiled Site is discarded.
    ValidateOnly,
    /// Copy verified bytes to an immutable temporary backing file before the
    /// Site can be published and serve them.
    PinImmutable,
}

impl<'a> CachedAssetResolver<'a> {
    fn new(
        archive: &'a BundleArchive,
        pinned_file: &'a Arc<File>,
        display_path: &'a Arc<PathBuf>,
        deployment_root: &'a Path,
        reference_mode: ReferenceAssetMode,
    ) -> Self {
        Self {
            archive,
            pinned_file,
            display_path,
            deployment_root,
            reference_mode,
            cache: BTreeMap::new(),
        }
    }

    fn resolve(
        &mut self,
        key: &str,
        digest: ContentDigest,
        length: u64,
    ) -> Result<AssetSource, PortableSiteError> {
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

pub(crate) fn build_bundle(
    gateway: &CompiledGateway,
    snapshot: &RuntimeSnapshot,
    output: &Path,
    deployment_root: &Path,
) -> Result<BundleBuildOutput, BundleCliError> {
    let deployment_root = deployment_root
        .canonicalize()
        .map_err(|error| BundleCliError::Io {
            code: "bundle.deployment_root",
            message: format!("cannot resolve Bundle deployment root: {error}"),
        })?;
    let exported = snapshot.export_portable_at(gateway, &deployment_root)?;
    validate_bundle_output_path(output, gateway, &exported.assets)?;
    let runtime_section =
        StableSection::from_serde(PORTABLE_RUNTIME_PLAN_SCHEMA_V1, true, &exported.plan)?;
    let mut manifest = BundleManifest::new(
        BuildMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            source_commit: option_env!("OXIDASE_BUILD_COMMIT").map(str::to_owned),
            gateway_api: oxidase_config::API_VERSION.to_owned(),
            oxista_api: oxidase_site::SITE_API_VERSION.to_owned(),
        },
        env!("CARGO_PKG_VERSION"),
    );
    manifest
        .required_features
        .insert("portable-runtime".to_owned());
    manifest
        .sections
        .insert(RUNTIME_SECTION.to_owned(), runtime_section);
    add_origins(&mut manifest, &exported.plan)?;

    add_sensitive_references(&mut manifest, gateway, &deployment_root)?;
    let mut builder = BundleBuilder::new(manifest);
    for (key, asset) in exported.assets {
        let digest = asset.digest.into();
        let storage = match gateway.bundle.assets.mode {
            BundleAssetMode::Embed => {
                match asset.source {
                    AssetSource::File(path) => {
                        builder.add_blob_path(path, digest, asset.length)?;
                    }
                    AssetSource::Pinned { .. } => {
                        return Err(BundleCliError::Invalid {
                            code: "bundle.asset_source",
                            message:
                                "source-config Bundle builds cannot contain a pinned archive Asset"
                                    .to_owned(),
                        });
                    }
                }
                AssetStorage::Embedded {
                    blob: digest,
                    length: asset.length,
                }
            }
            BundleAssetMode::Reference => {
                let AssetSource::File(path) = asset.source else {
                    return Err(BundleCliError::Invalid {
                        code: "bundle.asset_reference",
                        message: "a Bundle slice cannot become an external Asset reference"
                            .to_owned(),
                    });
                };
                validate_external_asset(&path, asset.digest, asset.length)?;
                let (base, path) = portable_path_reference(&path, &deployment_root)?;
                AssetStorage::Reference {
                    base,
                    path,
                    expected_digest: digest,
                    length: asset.length,
                }
            }
        };
        builder
            .manifest_mut()
            .assets
            .insert(key, AssetDescriptor { storage });
    }
    let file_digest = builder.write_atomic(output)?;
    let archive = BundleArchive::read_path(output, &BundleLimits::default())?;
    Ok(BundleBuildOutput {
        output: display_path(output),
        file_digest: file_digest.to_string(),
        content_digest: archive.content_digest().to_string(),
        assets: archive.manifest().assets.len(),
        embedded_blobs: archive.inspect(InspectionVerbosity::Safe).embedded_blobs,
    })
}

fn validate_bundle_output_path(
    output: &Path,
    gateway: &CompiledGateway,
    assets: &BTreeMap<String, PortableAssetInputV1>,
) -> Result<(), BundleCliError> {
    let output_entry = canonical_directory_entry(output)?;
    let output_canonical = output.canonicalize().ok();

    for site in gateway.resources.sites.values() {
        let root = site
            .root
            .canonicalize()
            .map_err(|error| BundleCliError::Io {
                code: "bundle.output_path",
                message: format!("cannot resolve Site root before writing Bundle output: {error}"),
            })?;
        if output_entry.starts_with(&root)
            || output_canonical
                .as_ref()
                .is_some_and(|path| path.starts_with(&root))
        {
            return Err(BundleCliError::Invalid {
                code: "bundle.output_site_root",
                message: "Bundle output must be outside every Site root".to_owned(),
            });
        }
    }

    let mut protected = Vec::<&Path>::new();
    protected.push(gateway.source.as_path());
    protected.extend(gateway.dependencies.iter().map(PathBuf::as_path));
    for certificate in gateway.resources.certificates.values() {
        protected.push(certificate.cert_chain.as_path());
        protected.push(certificate.private_key.as_path());
    }
    protected.extend(
        gateway
            .resources
            .secrets
            .values()
            .map(|secret| secret.file.as_path()),
    );
    protected.extend(
        gateway
            .resources
            .trust_stores
            .values()
            .map(|trust| trust.ca_bundle.as_path()),
    );
    for site in gateway.resources.sites.values() {
        protected.push(site.root.as_path());
        protected.push(site.manifest.as_path());
    }
    protected.extend(assets.values().map(|asset| asset.source.display_path()));

    let mut output_aliases = BTreeSet::from([output_entry]);
    if let Some(canonical) = output_canonical {
        output_aliases.insert(canonical);
    }
    for path in protected {
        let aliases = path_aliases(path)?;
        if !output_aliases.is_disjoint(&aliases) {
            return Err(BundleCliError::Invalid {
                code: "bundle.output_conflict",
                message: "Bundle output overlaps a configuration dependency or runtime resource"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn canonical_directory_entry(path: &Path) -> Result<PathBuf, BundleCliError> {
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| BundleCliError::Invalid {
            code: "bundle.output_path",
            message: "Bundle output must name a file".to_owned(),
        })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize().map_err(|error| BundleCliError::Io {
        code: "bundle.output_path",
        message: format!("cannot resolve Bundle output directory: {error}"),
    })?;
    Ok(parent.join(file_name))
}

fn path_aliases(path: &Path) -> Result<BTreeSet<PathBuf>, BundleCliError> {
    let mut aliases = BTreeSet::from([canonical_directory_entry(path)?]);
    // Resolving the final symlink catches an output alias before the atomic
    // rename replaces that directory entry. We deliberately do not compare
    // device/inode identity here: replacing one hardlink name does not mutate
    // the protected file reachable through another hardlink.
    if let Ok(canonical) = path.canonicalize() {
        aliases.insert(canonical);
    }
    Ok(aliases)
}

pub(crate) fn inspect_bundle(
    path: &Path,
    verbose: bool,
) -> Result<BundleInspection, BundleCliError> {
    let archive = BundleArchive::read_path(path, &BundleLimits::default())?;
    Ok(archive.inspect(if verbose {
        InspectionVerbosity::Verbose
    } else {
        InspectionVerbosity::Safe
    }))
}

pub(crate) fn diff_bundles(old: &Path, new: &Path) -> Result<BundleDiff, BundleCliError> {
    let old = BundleArchive::read_path(old, &BundleLimits::default())?;
    let new = BundleArchive::read_path(new, &BundleLimits::default())?;
    Ok(old.diff(&new))
}

pub(crate) fn verify_bundle(
    path: &Path,
    keys: &[PathBuf],
    deployment_root: Option<&Path>,
) -> Result<BundleVerifyOutput, BundleCliError> {
    let archive = BundleArchive::read_path(path, &BundleLimits::default())?;
    let structural = archive.verify()?;
    let trusted = read_verification_keys(keys)?;
    let signature = archive.verify_ed25519(
        &trusted,
        if trusted.is_empty() {
            SignatureRequirement::AllowUnsigned
        } else {
            SignatureRequirement::RequireAnyTrusted
        },
    )?;
    archive.verify_capabilities(&runtime_capabilities())?;
    let plan = decode_runtime_plan(&archive)?;
    validate_sensitive_references(archive.manifest(), &plan)?;
    validate_asset_set(archive.manifest(), &plan)?;
    let deployment_root = resolve_deployment_root(deployment_root, path)?;
    validate_reference_sensitive_isolation(archive.manifest(), &deployment_root)?;
    let pinned_file =
        Arc::new(
            archive
                .try_clone_backing_file()?
                .ok_or_else(|| BundleCliError::Invalid {
                    code: "bundle.backing_missing",
                    message: "path-backed Bundle did not retain a verified file handle".to_owned(),
                })?,
        );
    let display_path = Arc::new(path.to_path_buf());
    let mut resolver = CachedAssetResolver::new(
        &archive,
        &pinned_file,
        &display_path,
        &deployment_root,
        ReferenceAssetMode::ValidateOnly,
    );
    let content_digest: ContentDigest = archive.content_digest().into();
    plan.validate_with_assets(content_digest, &deployment_root, |key, digest, length| {
        resolver.resolve(key, digest, length)
    })?;
    Ok(BundleVerifyOutput {
        structural,
        verified_key_ids: signature.verified_key_ids,
        untrusted_signature_count: signature.untrusted_signature_count,
    })
}

pub(crate) fn sign_bundle(
    path: &Path,
    key: &Path,
    output: Option<&Path>,
) -> Result<BundleSignOutput, BundleCliError> {
    let output = output.unwrap_or(path);
    if !path_aliases(output)?.is_disjoint(&path_aliases(key)?) {
        return Err(BundleCliError::Invalid {
            code: "bundle.sign_output_conflict",
            message: "signed Bundle output must not overwrite the signing key".to_owned(),
        });
    }
    let archive = BundleArchive::read_path(path, &BundleLimits::default())?;
    let signing_key = BundleSigningKey::read_file(key)?;
    let key_id = signing_key.key_id().to_owned();
    let verification_key = signing_key.verification_key();
    archive.write_signed_atomic(output, &[signing_key])?;
    let verified = BundleArchive::read_path(output, &BundleLimits::default())?;
    verified.verify_ed25519(&[verification_key], SignatureRequirement::RequireAnyTrusted)?;
    Ok(BundleSignOutput {
        output: display_path(output),
        key_id,
        content_digest: verified.content_digest().to_string(),
        file_digest: verified.file_digest().to_string(),
    })
}

pub(crate) fn load_bundle_snapshot(
    path: &Path,
    verification_keys: &[PathBuf],
    allow_unsigned: bool,
    deployment_root: Option<&Path>,
) -> Result<LoadedBundle, BundleCliError> {
    let archive = BundleArchive::read_path(path, &BundleLimits::default())?;
    archive.verify()?;
    let deployment_root = resolve_deployment_root(deployment_root, path)?;
    let pinned_file =
        Arc::new(
            archive
                .try_clone_backing_file()?
                .ok_or_else(|| BundleCliError::Invalid {
                    code: "bundle.backing_missing",
                    message: "path-backed Bundle did not retain a verified file handle".to_owned(),
                })?,
        );
    let display_path = Arc::new(path.to_path_buf());
    let trusted = read_verification_keys(verification_keys)?;
    let requirement = if allow_unsigned {
        SignatureRequirement::AllowUnsigned
    } else {
        SignatureRequirement::RequireAnyTrusted
    };
    if requirement == SignatureRequirement::RequireAnyTrusted && trusted.is_empty() {
        return Err(BundleCliError::Invalid {
            code: "bundle.signature_key_required",
            message:
                "Bundle activation requires at least one --bundle-key; use --allow-unsigned-bundle only for explicit standalone development"
                    .to_owned(),
        });
    }
    let verification = archive.verify_ed25519(&trusted, requirement)?;
    let capabilities = runtime_capabilities();
    archive.verify_capabilities(&capabilities)?;
    let plan = decode_runtime_plan(&archive)?;
    validate_sensitive_references(archive.manifest(), &plan)?;
    validate_asset_set(archive.manifest(), &plan)?;
    validate_reference_sensitive_isolation(archive.manifest(), &deployment_root)?;
    let dependencies = runtime_dependencies(path, archive.manifest(), &deployment_root)?;
    let content_digest: ContentDigest = archive.content_digest().into();
    let mut resolver = CachedAssetResolver::new(
        &archive,
        &pinned_file,
        &display_path,
        &deployment_root,
        ReferenceAssetMode::PinImmutable,
    );
    let (snapshot, _reuse) = plan.prepare_with_assets(
        content_digest,
        &deployment_root,
        dependencies,
        |key, digest, length| resolver.resolve(key, digest, length),
        None,
    )?;
    let inspection = archive.inspect(InspectionVerbosity::Safe);
    Ok(LoadedBundle {
        snapshot,
        verification,
        inspection,
    })
}

fn decode_runtime_plan(archive: &BundleArchive) -> Result<PortableRuntimePlanV1, BundleCliError> {
    let section = archive
        .manifest()
        .sections
        .get(RUNTIME_SECTION)
        .ok_or_else(|| BundleCliError::Invalid {
            code: "bundle.runtime_section_missing",
            message: "Bundle does not contain the required runtime section".to_owned(),
        })?;
    if section.schema != PORTABLE_RUNTIME_PLAN_SCHEMA_V1 || !section.required {
        return Err(BundleCliError::Invalid {
            code: "bundle.runtime_section_schema",
            message: format!(
                "runtime section must be required schema `{PORTABLE_RUNTIME_PLAN_SCHEMA_V1}`"
            ),
        });
    }
    section.to_serde().map_err(Into::into)
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
                file: resolver.pinned_file.clone(),
                display: resolver.display_path.clone(),
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
            match resolver.reference_mode {
                ReferenceAssetMode::ValidateOnly => {
                    validate_external_asset(&path, digest, length).map_err(|error| {
                        PortableSiteError::asset_resolution_with_code(error.code(), error.message())
                    })?;
                    // `PortableRuntimePlanV1::validate_with_assets` compiles and
                    // immediately drops this Site; it never executes the path.
                    Ok(AssetSource::File(path))
                }
                ReferenceAssetMode::PinImmutable => {
                    let (file, origin) =
                        verify_external_asset(&path, digest, length).map_err(|error| {
                            PortableSiteError::asset_resolution_with_code(
                                error.code(),
                                error.message(),
                            )
                        })?;
                    Ok(AssetSource::pinned_with_origin(file, origin, path, 0))
                }
            }
        }
    }
}

fn add_sensitive_references(
    manifest: &mut BundleManifest,
    gateway: &CompiledGateway,
    source_root: &Path,
) -> Result<(), BundleCliError> {
    for (id, secret) in &gateway.resources.secrets {
        let (base, runtime_path) = portable_path_reference(&secret.file, source_root)?;
        manifest.sensitive_references.insert(
            format!("secret:{id}"),
            SensitiveReference {
                kind: SensitiveReferenceKind::Secret,
                base,
                runtime_path,
                max_bytes: secret.max_bytes,
            },
        );
    }
    for (id, certificate) in &gateway.resources.certificates {
        let (base, runtime_path) = portable_path_reference(&certificate.private_key, source_root)?;
        manifest.sensitive_references.insert(
            format!("private-key:{id}"),
            SensitiveReference {
                kind: SensitiveReferenceKind::PrivateKey,
                base,
                runtime_path,
                max_bytes: MAX_PRIVATE_KEY_BYTES,
            },
        );
    }
    Ok(())
}

fn validate_sensitive_references(
    manifest: &BundleManifest,
    plan: &PortableRuntimePlanV1,
) -> Result<(), BundleCliError> {
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
        return Err(BundleCliError::Invalid {
            code: "bundle.sensitive_reference_mismatch",
            message: "Bundle sensitive-reference index does not exactly match its runtime plan"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_asset_set(
    manifest: &BundleManifest,
    plan: &PortableRuntimePlanV1,
) -> Result<(), BundleCliError> {
    let expected = plan.asset_keys();
    let actual = manifest.assets.keys().cloned().collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(BundleCliError::Invalid {
            code: "bundle.asset_set_mismatch",
            message: "Bundle Asset index does not exactly match its executable Site plans"
                .to_owned(),
        });
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

/// Proves the reference index cannot turn a Secret/private-key runtime path
/// into a public Asset before any immutable Asset spool loses the origin inode.
fn validate_reference_sensitive_isolation(
    manifest: &BundleManifest,
    deployment_root: &Path,
) -> Result<(), BundleCliError> {
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
            return Err(BundleCliError::Invalid {
                code: "resource.sensitive_site_asset_overlap",
                message:
                    "a Bundle reference Asset overlaps a Secret or certificate private-key file"
                        .to_owned(),
            });
        }
    }
    Ok(())
}

fn portable_base(value: &str) -> Result<AssetReferenceBase, BundleCliError> {
    match value {
        "absolute" => Ok(AssetReferenceBase::Absolute),
        "deployment_root" => Ok(AssetReferenceBase::DeploymentRoot),
        _ => Err(BundleCliError::Invalid {
            code: "bundle.path_reference",
            message: "runtime plan contains an unknown path-reference base".to_owned(),
        }),
    }
}

fn add_origins(
    manifest: &mut BundleManifest,
    plan: &PortableRuntimePlanV1,
) -> Result<(), BundleCliError> {
    for (index, node) in plan.graph.nodes.iter().enumerate() {
        manifest.origins.insert(
            format!("service:{index:08}:{}", node.id),
            source_origin(&node.source)?,
        );
        if let oxidase_core::portable::PortableServiceKindV1::Route { cases, .. } = &node.kind {
            for (case_index, case) in cases.iter().enumerate() {
                manifest.origins.insert(
                    format!("route:{index:08}:{case_index:08}:{}", case.id),
                    source_origin(&case.source)?,
                );
            }
        }
    }
    for (site, snapshot) in &plan.sites {
        for (template, compiled) in &snapshot.templates {
            for (parameter, span) in &compiled.param_spans {
                manifest.origins.insert(
                    format!("oxt-param:{site}:{template}:{parameter}"),
                    portable_site_origin(span),
                );
            }
            let mut ordinal = 0_u64;
            collect_include_origins(
                &mut manifest.origins,
                site,
                template,
                &compiled.nodes,
                &mut ordinal,
            );
        }
    }
    Ok(())
}

fn collect_include_origins(
    origins: &mut BTreeMap<String, SourceOrigin>,
    site: &str,
    template: &str,
    nodes: &[oxidase_site::PortableTemplateNodeV1],
    ordinal: &mut u64,
) {
    for node in nodes {
        match node {
            oxidase_site::PortableTemplateNodeV1::Text { .. }
            | oxidase_site::PortableTemplateNodeV1::Interpolation { .. } => {}
            oxidase_site::PortableTemplateNodeV1::If {
                branches,
                otherwise,
            } => {
                for branch in branches {
                    collect_include_origins(origins, site, template, &branch.body, ordinal);
                }
                collect_include_origins(origins, site, template, otherwise, ordinal);
            }
            oxidase_site::PortableTemplateNodeV1::For {
                body, otherwise, ..
            } => {
                collect_include_origins(origins, site, template, body, ordinal);
                collect_include_origins(origins, site, template, otherwise, ordinal);
            }
            oxidase_site::PortableTemplateNodeV1::With { body, .. } => {
                collect_include_origins(origins, site, template, body, ordinal);
            }
            oxidase_site::PortableTemplateNodeV1::Include { call } => {
                origins.insert(
                    format!("oxt-include:{site}:{template}:{:08}", *ordinal),
                    portable_site_origin(&call.target_span),
                );
                *ordinal = ordinal.saturating_add(1);
            }
        }
    }
}

fn source_origin(span: &oxidase_core::SourceSpan) -> Result<SourceOrigin, BundleCliError> {
    Ok(SourceOrigin {
        display_path: display_path(&span.file),
        start_byte: u64::try_from(span.start_byte).map_err(|_| origin_overflow())?,
        end_byte: u64::try_from(span.end_byte).map_err(|_| origin_overflow())?,
        start_line: u32::try_from(span.line).map_err(|_| origin_overflow())?,
        start_column: u32::try_from(span.column).map_err(|_| origin_overflow())?,
        end_line: u32::try_from(span.end_line).map_err(|_| origin_overflow())?,
        end_column: u32::try_from(span.end_column).map_err(|_| origin_overflow())?,
        field_path: span.field_path.clone(),
    })
}

fn portable_site_origin(span: &oxidase_site::PortableSourceSpanV1) -> SourceOrigin {
    SourceOrigin {
        display_path: span.file.clone(),
        start_byte: span.start_byte,
        end_byte: span.end_byte,
        start_line: span.start_line,
        start_column: span.start_column,
        end_line: span.end_line,
        end_column: span.end_column,
        field_path: span.field_path.clone(),
    }
}

fn origin_overflow() -> BundleCliError {
    BundleCliError::Invalid {
        code: "bundle.source_origin",
        message: "source position exceeds the portable Bundle origin range".to_owned(),
    }
}

fn runtime_capabilities() -> BundleCapabilities {
    BundleCapabilities {
        runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
        supported_features: BTreeSet::from(["portable-runtime".to_owned()]),
        supported_sections: BTreeMap::from([(
            RUNTIME_SECTION.to_owned(),
            PORTABLE_RUNTIME_PLAN_SCHEMA_V1.to_owned(),
        )]),
    }
}

fn runtime_dependencies(
    bundle_path: &Path,
    manifest: &BundleManifest,
    deployment_root: &Path,
) -> Result<Vec<PathBuf>, BundleCliError> {
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

fn read_verification_keys(paths: &[PathBuf]) -> Result<Vec<BundleVerificationKey>, BundleCliError> {
    paths
        .iter()
        .map(BundleVerificationKey::read_file)
        .collect::<Result<_, _>>()
        .map_err(Into::into)
}

fn verify_external_asset(
    path: &Path,
    expected_digest: ContentDigest,
    expected_length: u64,
) -> Result<(File, File), BundleCliError> {
    let mut pinned = tempfile::NamedTempFile::new().map_err(|error| BundleCliError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot create immutable external Asset backing: {error}"),
    })?;
    let origin = copy_and_verify_external_asset(
        path,
        expected_digest,
        expected_length,
        Some(pinned.as_file_mut()),
    )?;
    pinned
        .as_file()
        .sync_data()
        .map_err(|error| BundleCliError::Io {
            code: "bundle.asset_reference_io",
            message: format!("cannot flush immutable external Asset backing: {error}"),
        })?;
    let immutable = File::open(pinned.path()).map_err(|error| BundleCliError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot open immutable external Asset backing: {error}"),
    })?;
    drop(pinned);
    Ok((immutable, origin))
}

fn validate_external_asset(
    path: &Path,
    expected_digest: ContentDigest,
    expected_length: u64,
) -> Result<(), BundleCliError> {
    copy_and_verify_external_asset(path, expected_digest, expected_length, None).map(drop)
}

fn copy_and_verify_external_asset(
    path: &Path,
    expected_digest: ContentDigest,
    expected_length: u64,
    immutable_copy: Option<&mut File>,
) -> Result<File, BundleCliError> {
    let file = open_external_asset(path).map_err(|error| BundleCliError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot open external Bundle Asset: {error}"),
    })?;
    let metadata = file.metadata().map_err(|error| BundleCliError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot inspect external Bundle Asset handle: {error}"),
    })?;
    copy_and_verify_opened_external_asset(
        file,
        metadata,
        expected_digest,
        expected_length,
        immutable_copy,
    )
}

fn copy_and_verify_opened_external_asset(
    mut file: File,
    metadata: std::fs::Metadata,
    expected_digest: ContentDigest,
    expected_length: u64,
    mut immutable_copy: Option<&mut File>,
) -> Result<File, BundleCliError> {
    if !metadata.is_file() || metadata.len() != expected_length {
        return Err(BundleCliError::Invalid {
            code: "bundle.asset_reference_mismatch",
            message: "external Bundle Asset is not a regular file of the declared length"
                .to_owned(),
        });
    }
    let mut hasher = ContentHasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|error| BundleCliError::Io {
            code: "bundle.asset_reference_io",
            message: format!("cannot read external Bundle Asset: {error}"),
        })?;
        if read == 0 {
            break;
        }
        if let Some(copy) = immutable_copy.as_deref_mut() {
            copy.write_all(&buffer[..read])
                .map_err(|error| BundleCliError::Io {
                    code: "bundle.asset_reference_io",
                    message: format!("cannot pin external Bundle Asset: {error}"),
                })?;
        }
        hasher.update(&buffer[..read]);
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| BundleCliError::Invalid {
                code: "bundle.asset_reference_mismatch",
                message: "external Bundle Asset length overflowed during verification".to_owned(),
            })?;
    }
    if length != expected_length || hasher.finish() != expected_digest {
        return Err(BundleCliError::Invalid {
            code: "bundle.asset_reference_mismatch",
            message: "external Bundle Asset content digest does not match the manifest".to_owned(),
        });
    }
    let after = file.metadata().map_err(|error| BundleCliError::Io {
        code: "bundle.asset_reference_io",
        message: format!("cannot revalidate external Bundle Asset handle: {error}"),
    })?;
    if !after.is_file() || after.len() != expected_length {
        return Err(BundleCliError::Invalid {
            code: "bundle.asset_reference_mismatch",
            message: "external Bundle Asset changed while being verified".to_owned(),
        });
    }
    Ok(file)
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

fn canonical_parent(path: &Path) -> Result<PathBuf, BundleCliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent.canonicalize().map_err(|error| BundleCliError::Io {
        code: "bundle.deployment_root",
        message: format!("cannot resolve Bundle deployment root: {error}"),
    })
}

pub(crate) fn resolve_deployment_root(
    explicit: Option<&Path>,
    input: &Path,
) -> Result<PathBuf, BundleCliError> {
    let root = if let Some(explicit) = explicit {
        explicit
            .canonicalize()
            .map_err(|error| BundleCliError::Io {
                code: "bundle.deployment_root",
                message: format!("cannot resolve explicit deployment root: {error}"),
            })?
    } else {
        canonical_parent(input)?
    };
    if !root.is_absolute() || !root.is_dir() {
        return Err(BundleCliError::Invalid {
            code: "bundle.deployment_root",
            message: "Bundle deployment root must resolve to an existing absolute directory"
                .to_owned(),
        });
    }
    Ok(root)
}

fn portable_path_reference(
    path: &Path,
    deployment_root: &Path,
) -> Result<(AssetReferenceBase, String), BundleCliError> {
    if let Ok(relative) = path.strip_prefix(deployment_root) {
        let path = normalized_relative(relative)?;
        return Ok((AssetReferenceBase::DeploymentRoot, path));
    }
    let path = path
        .to_str()
        .filter(|path| path.starts_with('/') && !path.contains(['\0', '\r', '\n', '\\']))
        .ok_or_else(|| BundleCliError::Invalid {
            code: "bundle.path_encoding",
            message: "Bundle runtime reference path is not portable UTF-8".to_owned(),
        })?;
    Ok((AssetReferenceBase::Absolute, path.to_owned()))
}

fn normalized_relative(path: &Path) -> Result<String, BundleCliError> {
    let value = path
        .to_str()
        .map(|value| value.replace('\\', "/"))
        .ok_or_else(|| BundleCliError::Invalid {
            code: "bundle.path_encoding",
            message: "Bundle deployment-relative path is not UTF-8".to_owned(),
        })?;
    if value.is_empty()
        || value.starts_with('/')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(BundleCliError::Invalid {
            code: "bundle.path_reference",
            message: "Bundle deployment-relative path is not normalized".to_owned(),
        });
    }
    Ok(value)
}

fn resolve_reference(
    base: AssetReferenceBase,
    path: &str,
    deployment_root: &Path,
) -> Result<PathBuf, BundleCliError> {
    match base {
        AssetReferenceBase::Absolute => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(BundleCliError::Invalid {
                    code: "bundle.path_reference",
                    message: "absolute Bundle reference is not absolute".to_owned(),
                });
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
) -> Result<PathBuf, BundleCliError> {
    let declared = resolve_reference(base, path, deployment_root)?;
    let canonical = declared
        .canonicalize()
        .map_err(|error| BundleCliError::Io {
            code: "bundle.asset_reference_io",
            message: format!("cannot resolve external Bundle Asset: {error}"),
        })?;
    if base == AssetReferenceBase::DeploymentRoot && !canonical.starts_with(deployment_root) {
        return Err(BundleCliError::Invalid {
            code: "bundle.asset_reference_escape",
            message: "deployment-relative Asset resolves outside the deployment root".to_owned(),
        });
    }
    Ok(canonical)
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub(crate) fn json_payload(value: &impl Serialize) -> Result<String, BundleCliError> {
    serde_json::to_string_pretty(value).map_err(|error| BundleCliError::Invalid {
        code: "bundle.output_encode",
        message: format!("cannot encode Bundle command output: {error}"),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use oxidase_bundle::{
        AssetStorage, BundleArchive, BundleBuilder, BundleLimits, BundleSigningKey,
        InspectionVerbosity, StableSection,
    };
    use oxidase_config::Compiler;
    use oxidase_core::{ContentDigest, RequestFrame, RequestMetadata, ResourceId};
    use oxidase_runtime::{
        PORTABLE_RUNTIME_PLAN_SCHEMA_V1, PortableRuntimePlanV1, RuntimeSnapshot,
    };
    use oxidase_site::{AssetSource, PreparedSiteBody};
    use tempfile::tempdir;

    use super::{
        CachedAssetResolver, RUNTIME_SECTION, ReferenceAssetMode, build_bundle,
        copy_and_verify_opened_external_asset, decode_runtime_plan, inspect_bundle,
        load_bundle_snapshot, open_external_asset, resolve_asset_reference, sign_bundle,
        validate_asset_set, validate_sensitive_references, verify_bundle,
    };

    fn write_site_gateway(root: &Path, asset_mode: &str) -> PathBuf {
        fs::create_dir_all(root.join("site/_templates")).expect("Site directories can be created");
        fs::write(
            root.join("oxidase.yaml"),
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: {asset_mode}
resources:
  sites:
    web:
      root: ./site
      manifest: site.oxsite
services:
  root:
    type: site
    site: web
listeners:
  - name: public
    bind: 127.0.0.1:0
    protocol: http
    service:
      ref: root
"#,
            ),
        )
        .expect("Gateway source can be written");
        fs::write(
            root.join("site/site.oxsite"),
            r#"oxista: site/v1
paths:
  indexes: []
assets:
  etag: strong
  last_modified: false
templates:
  roots: [_templates]
  default_output: text
"#,
        )
        .expect("Site manifest can be written");
        fs::write(
            root.join("site/_templates/page.oxt"),
            r#"---
oxista: template/v1
output: text
---
portable {{ request.path }}"#,
        )
        .expect("OXT can be written");
        fs::write(
            root.join("site/page.txt.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/page.oxt
---
"#,
        )
        .expect("OXR can be written");
        fs::write(root.join("site/asset.bin"), b"portable-asset-content")
            .expect("Asset can be written");
        fs::write(root.join("site/asset-copy.bin"), b"portable-asset-content")
            .expect("duplicate-content Asset can be written");
        root.join("oxidase.yaml")
    }

    fn prepare(path: &Path) -> (oxidase_config::CompiledGateway, RuntimeSnapshot) {
        let gateway = Compiler::compile_path(path).expect("fixture Gateway compiles");
        let snapshot =
            RuntimeSnapshot::prepare(gateway.clone()).expect("fixture snapshot prepares");
        (gateway, snapshot)
    }

    #[test]
    fn bundle_output_cannot_overwrite_sources_dependencies_or_site_roots() {
        let directory = tempdir().expect("root exists");
        let config = write_site_gateway(directory.path(), "embed");
        let (gateway, snapshot) = prepare(&config);
        let config_before = fs::read(&config).expect("Gateway source reads");
        let asset = directory.path().join("site/asset.bin");
        let asset_before = fs::read(&asset).expect("Asset reads");

        let source_error = build_bundle(&gateway, &snapshot, &config, directory.path())
            .expect_err("Bundle output cannot overwrite Gateway source");
        assert_eq!(source_error.code(), "bundle.output_conflict");
        assert_eq!(
            fs::read(&config).expect("Gateway source remains"),
            config_before
        );

        let root_error = build_bundle(
            &gateway,
            &snapshot,
            &directory.path().join("site/new.oxb"),
            directory.path(),
        )
        .expect_err("Bundle output cannot be placed under a Site root");
        assert_eq!(root_error.code(), "bundle.output_site_root");

        let asset_error = build_bundle(&gateway, &snapshot, &asset, directory.path())
            .expect_err("Bundle output cannot overwrite a public Asset");
        assert_eq!(asset_error.code(), "bundle.output_site_root");
        assert_eq!(fs::read(&asset).expect("Asset remains"), asset_before);

        fs::write(directory.path().join("token.txt"), b"keep-secret-file")
            .expect("test-only Secret can be written");
        let secret_config = directory.path().join("secret-gateway.yaml");
        fs::write(
            &secret_config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: token.txt
      max_bytes: 1KiB
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        )
        .expect("Secret Gateway can be written");
        let (secret_gateway, secret_snapshot) = prepare(&secret_config);
        let secret_output = directory.path().join("token.txt");
        let secret_error = build_bundle(
            &secret_gateway,
            &secret_snapshot,
            &secret_output,
            directory.path(),
        )
        .expect_err("Bundle output cannot overwrite a Secret reference");
        assert_eq!(secret_error.code(), "bundle.output_conflict");
        assert_eq!(
            fs::read(secret_output).expect("Secret remains"),
            b"keep-secret-file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bundle_output_rejects_symlink_aliases_but_atomic_hardlink_replacement_is_safe() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("root exists");
        let config = write_site_gateway(directory.path(), "embed");
        let (gateway, snapshot) = prepare(&config);
        let source_before = fs::read(&config).expect("Gateway source reads");
        let output = directory.path().join("gateway.oxb");

        symlink(&config, &output).expect("output symlink can be created");
        let symlink_error = build_bundle(&gateway, &snapshot, &output, directory.path())
            .expect_err("a symlink to protected source is rejected");
        assert_eq!(symlink_error.code(), "bundle.output_conflict");
        assert_eq!(fs::read(&config).expect("source remains"), source_before);
        assert!(output.is_symlink());

        fs::remove_file(&output).expect("output symlink can be removed");
        fs::hard_link(&config, &output).expect("output hardlink can be created");
        build_bundle(&gateway, &snapshot, &output, directory.path())
            .expect("atomic rename safely replaces only the output hardlink name");
        assert_eq!(fs::read(&config).expect("source remains"), source_before);
        assert_ne!(fs::read(&output).expect("Bundle reads"), source_before);
    }

    #[test]
    fn embedded_bundle_is_bit_identical_across_roots_and_loads_without_sources() {
        let first = tempdir().expect("first root exists");
        let second = tempdir().expect("second root exists");
        let first_config = write_site_gateway(first.path(), "embed");
        let second_config = write_site_gateway(second.path(), "embed");
        let (first_gateway, first_snapshot) = prepare(&first_config);
        let (second_gateway, second_snapshot) = prepare(&second_config);
        let first_bundle = first.path().join("gateway.oxb");
        let second_bundle = second.path().join("gateway.oxb");
        build_bundle(&first_gateway, &first_snapshot, &first_bundle, first.path())
            .expect("first Bundle builds");
        build_bundle(
            &second_gateway,
            &second_snapshot,
            &second_bundle,
            second.path(),
        )
        .expect("second Bundle builds");
        assert_eq!(
            fs::read(&first_bundle).expect("first Bundle reads"),
            fs::read(&second_bundle).expect("second Bundle reads"),
            "identical source trees in different roots must produce identical bytes"
        );

        fs::remove_file(first.path().join("oxidase.yaml")).expect("Gateway source can disappear");
        fs::remove_dir_all(first.path().join("site")).expect("Oxista source can disappear");
        let unsigned_error =
            match load_bundle_snapshot(&first_bundle, &[], false, Some(first.path())) {
                Ok(_) => panic!("unsigned Bundle activation must be fail-closed by default"),
                Err(error) => error,
            };
        assert_eq!(unsigned_error.code(), "bundle.signature_key_required");
        let loaded = load_bundle_snapshot(&first_bundle, &[], true, Some(first.path()))
            .expect("Bundle loads without source documents");
        let site = loaded
            .snapshot
            .resources
            .sites
            .get(&ResourceId::new("site:web"))
            .expect("portable Site is prepared");
        let request = RequestFrame::new(
            RequestMetadata::try_new(
                http::Method::GET,
                "http",
                "example.test",
                "/page.txt",
                http::HeaderMap::new(),
            )
            .expect("request is valid"),
        );
        let response = site
            .execute(&request)
            .expect("portable Site executes")
            .expect("page is handled");
        let PreparedSiteBody::Bytes(body) = response.body else {
            panic!("template response is bytes")
        };
        assert_eq!(body, "portable /page.txt");

        let asset_request = RequestFrame::new(
            RequestMetadata::try_new(
                http::Method::GET,
                "http",
                "example.test",
                "/asset.bin",
                http::HeaderMap::new(),
            )
            .expect("request is valid"),
        );
        let asset = site
            .execute(&asset_request)
            .expect("portable Asset executes")
            .expect("Asset is handled");
        let PreparedSiteBody::Asset(asset) = asset.body else {
            panic!("Asset remains streaming")
        };
        assert!(matches!(asset.identity.source, AssetSource::Pinned { .. }));
    }

    #[test]
    fn reference_assets_are_verified_and_mismatch_is_rejected() {
        let directory = tempdir().expect("root exists");
        let deployment_root = directory.path().canonicalize().expect("root canonicalizes");
        let config = write_site_gateway(directory.path(), "reference");
        let (gateway, snapshot) = prepare(&config);
        let bundle = directory.path().join("gateway.oxb");
        let asset_path = directory.path().join("site/asset.bin");
        let copy_path = directory.path().join("site/asset-copy.bin");
        let original = fs::read(&asset_path).expect("Asset reads");
        let copy_original = fs::read(&copy_path).expect("duplicate Asset reads");
        fs::write(&asset_path, vec![b'x'; original.len()])
            .expect("same-length Asset mutation writes");
        fs::write(&copy_path, vec![b'x'; copy_original.len()])
            .expect("same-length duplicate Asset mutation writes");
        let error = build_bundle(&gateway, &snapshot, &bundle, &deployment_root)
            .expect_err("reference build must revalidate post-prepare content");
        assert_eq!(error.code(), "bundle.asset_reference_mismatch");
        fs::write(&asset_path, &original).expect("Asset is restored");
        fs::write(&copy_path, &copy_original).expect("duplicate Asset is restored");
        build_bundle(&gateway, &snapshot, &bundle, &deployment_root)
            .expect("reference Bundle builds");
        let archive = BundleArchive::read_path(&bundle, &BundleLimits::default())
            .expect("reference Bundle reads");
        let (content_key, descriptor) = archive
            .manifest()
            .assets
            .iter()
            .next()
            .expect("fixture has one deduplicated Asset");
        let (reference_path, expected_digest, expected_length) = match &descriptor.storage {
            AssetStorage::Reference {
                base,
                path,
                expected_digest,
                length,
            } => (
                resolve_asset_reference(*base, path, &deployment_root)
                    .expect("reference path resolves"),
                expected_digest.content_digest(),
                *length,
            ),
            AssetStorage::Embedded { .. } => panic!("fixture uses reference storage"),
        };
        let pinned_bundle = Arc::new(
            archive
                .try_clone_backing_file()
                .expect("Bundle backing clones")
                .expect("path Bundle is pinned"),
        );
        let display_path = Arc::new(bundle.clone());
        let mut validation_resolver = CachedAssetResolver::new(
            &archive,
            &pinned_bundle,
            &display_path,
            &deployment_root,
            ReferenceAssetMode::ValidateOnly,
        );
        assert!(matches!(
            validation_resolver
                .resolve(content_key, expected_digest, expected_length)
                .expect("validate-only resolver hashes the reference"),
            AssetSource::File(_)
        ));
        verify_bundle(&bundle, &[], Some(&deployment_root)).expect("reference bytes verify");
        let loaded = load_bundle_snapshot(&bundle, &[], true, Some(&deployment_root))
            .expect("reference Bundle prepares");

        let site = loaded
            .snapshot
            .resources
            .sites
            .get(&ResourceId::new("site:web"))
            .expect("portable Site exists");
        let pinned_source = |path| {
            let response = site
                .execute(&RequestFrame::new(
                    RequestMetadata::try_new(
                        http::Method::GET,
                        "http",
                        "example.test",
                        path,
                        http::HeaderMap::new(),
                    )
                    .expect("request is valid"),
                ))
                .expect("Asset executes")
                .expect("Asset is handled");
            let PreparedSiteBody::Asset(asset) = response.body else {
                panic!("Asset remains streaming")
            };
            let AssetSource::Pinned { file, .. } = asset.identity.source else {
                panic!("reference Asset is pinned")
            };
            file
        };
        let original_handle = pinned_source("/asset.bin");
        let duplicate_handle = pinned_source("/asset-copy.bin");
        assert!(
            std::sync::Arc::ptr_eq(&original_handle, &duplicate_handle),
            "one content key must be verified and pinned only once"
        );

        fs::write(&reference_path, b"tampered-asset-content")
            .expect("external Asset inode can be modified in place");

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;

            let site = loaded
                .snapshot
                .resources
                .sites
                .get(&ResourceId::new("site:web"))
                .expect("portable Site exists");
            let request = RequestFrame::new(
                RequestMetadata::try_new(
                    http::Method::GET,
                    "http",
                    "example.test",
                    "/asset.bin",
                    http::HeaderMap::new(),
                )
                .expect("request is valid"),
            );
            let response = site
                .execute(&request)
                .expect("pinned Asset executes")
                .expect("Asset is handled");
            let PreparedSiteBody::Asset(asset) = response.body else {
                panic!("Asset remains streaming")
            };
            let AssetSource::Pinned { file, offset, .. } = &asset.identity.source else {
                panic!("reference Asset is pinned")
            };
            let mut bytes = vec![0_u8; "portable-asset-content".len()];
            file.read_at(&mut bytes, *offset)
                .expect("pinned reference remains readable");
            assert_eq!(
                bytes, b"portable-asset-content",
                "the active snapshot reads its immutable verified spool"
            );
        }
        let error = verify_bundle(&bundle, &[], Some(&deployment_root))
            .expect_err("changed external Asset must fail verification");
        assert_eq!(error.code(), "bundle.asset_reference_mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn external_asset_verification_pins_opened_inode_across_symlink_replacement() {
        use std::os::unix::fs::{MetadataExt as _, symlink};

        let directory = tempdir().expect("root exists");
        let old_path = directory.path().join("old.bin");
        let new_path = directory.path().join("new.bin");
        let active_path = directory.path().join("active.bin");
        let replacement_link = directory.path().join("replacement-link");
        let old_bytes = b"old-reference-content";
        let new_bytes = b"new-reference-content";
        assert_eq!(old_bytes.len(), new_bytes.len());
        fs::write(&old_path, old_bytes).expect("old Asset writes");
        fs::write(&new_path, new_bytes).expect("new Asset writes");
        symlink(&old_path, &active_path).expect("active path targets old Asset");

        let opened = open_external_asset(&active_path).expect("Asset safely opens");
        let opened_metadata = opened.metadata().expect("opened Asset stats");
        symlink(&new_path, &replacement_link).expect("replacement targets new Asset");
        fs::rename(&replacement_link, &active_path).expect("symlink atomically swaps");

        let origin = copy_and_verify_opened_external_asset(
            opened,
            opened_metadata,
            ContentDigest::of_bytes(old_bytes),
            old_bytes.len() as u64,
            None,
        )
        .expect("verification remains pinned to the opened inode");
        let origin_metadata = origin.metadata().expect("origin handle stats");
        let old_metadata = fs::metadata(&old_path).expect("old Asset stats");
        let new_metadata = fs::metadata(&new_path).expect("new Asset stats");
        assert_eq!(
            (origin_metadata.dev(), origin_metadata.ino()),
            (old_metadata.dev(), old_metadata.ino())
        );
        assert_ne!(
            (origin_metadata.dev(), origin_metadata.ino()),
            (new_metadata.dev(), new_metadata.ino())
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn external_asset_verification_rejects_fifo_without_blocking() {
        use rustix::fs::{CWD, Mode, mkfifoat};

        let directory = tempdir().expect("root exists");
        let fifo = directory.path().join("asset.fifo");
        mkfifoat(CWD, &fifo, Mode::RUSR | Mode::WUSR).expect("test FIFO is created");
        let error = super::validate_external_asset(&fifo, ContentDigest::of_bytes([]), 0)
            .expect_err("FIFO cannot become a reference Asset");
        assert_eq!(error.code(), "bundle.asset_reference_mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn canonical_reference_bundle_cannot_publish_a_sensitive_hardlink() {
        let directory = tempdir().expect("root exists");
        let deployment_root = directory.path().canonicalize().expect("root canonicalizes");
        let config = write_site_gateway(directory.path(), "reference");
        let source = fs::read_to_string(&config).expect("Gateway source reads");
        fs::write(
            &config,
            source.replace(
                "resources:\n  sites:",
                "resources:\n  secrets:\n    token:\n      file: ./secret.txt\n      max_bytes: 1KiB\n  sites:",
            ),
        )
        .expect("Secret Resource can be inserted");
        fs::write(
            directory.path().join("secret.txt"),
            b"portable-asset-content",
        )
        .expect("test-only Secret can be written");
        fs::hard_link(
            directory.path().join("secret.txt"),
            directory.path().join("secret-hardlink.txt"),
        )
        .expect("Secret hardlink can be created");

        let (gateway, snapshot) = prepare(&config);
        let original = directory.path().join("original.oxb");
        build_bundle(&gateway, &snapshot, &original, &deployment_root)
            .expect("non-overlapping reference Bundle builds");
        let archive = BundleArchive::read_path(&original, &BundleLimits::default())
            .expect("original Bundle reads");
        let mut manifest = archive.manifest().clone();
        for descriptor in manifest.assets.values_mut() {
            let AssetStorage::Reference { base, path, .. } = &mut descriptor.storage else {
                panic!("fixture uses reference Assets")
            };
            *base = oxidase_bundle::AssetReferenceBase::DeploymentRoot;
            *path = "secret-hardlink.txt".to_owned();
        }
        let malicious = directory.path().join("malicious.oxb");
        BundleBuilder::new(manifest)
            .write_atomic(&malicious)
            .expect("malicious fixture remains a canonical Bundle");

        let verify_error = verify_bundle(&malicious, &[], Some(&deployment_root))
            .expect_err("verification must reject the sensitive hardlink before spooling");
        assert_eq!(verify_error.code(), "resource.sensitive_site_asset_overlap");
        let load_error = match load_bundle_snapshot(&malicious, &[], true, Some(&deployment_root)) {
            Ok(_) => panic!("activation must reject the sensitive hardlink"),
            Err(error) => error,
        };
        assert_eq!(load_error.code(), "resource.sensitive_site_asset_overlap");
        for message in [verify_error.message(), load_error.message()] {
            assert!(!message.contains("secret.txt"));
            assert!(!message.contains("secret-hardlink.txt"));
            assert!(!message.contains("portable-asset-content"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn deployment_relative_asset_symlink_cannot_escape_root() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("root exists");
        let outside = tempdir().expect("outside root exists");
        let config = write_site_gateway(directory.path(), "reference");
        let (gateway, snapshot) = prepare(&config);
        let bundle = directory.path().join("gateway.oxb");
        build_bundle(&gateway, &snapshot, &bundle, directory.path())
            .expect("reference Bundle builds");
        fs::rename(directory.path().join("site"), outside.path().join("site"))
            .expect("Site can move outside root");
        symlink(outside.path().join("site"), directory.path().join("site"))
            .expect("escaping symlink can be created");
        let error = verify_bundle(&bundle, &[], Some(directory.path()))
            .expect_err("escaping reference must be rejected");
        assert_eq!(error.code(), "bundle.asset_reference_escape");
    }

    #[test]
    fn signatures_support_rotation_and_reject_an_untrusted_key() {
        let directory = tempdir().expect("root exists");
        let config = write_site_gateway(directory.path(), "embed");
        let (gateway, snapshot) = prepare(&config);
        let bundle = directory.path().join("gateway.oxb");
        build_bundle(&gateway, &snapshot, &bundle, directory.path()).expect("Bundle builds");

        let first_private = directory.path().join("first.key");
        let second_private = directory.path().join("second.key");
        let wrong_private = directory.path().join("wrong.key");
        fs::write(&first_private, [1_u8; 32]).expect("first key writes");
        fs::write(&second_private, [2_u8; 32]).expect("second key writes");
        fs::write(&wrong_private, [3_u8; 32]).expect("wrong key writes");
        let first_public = directory.path().join("first.pub");
        let second_public = directory.path().join("second.pub");
        let wrong_public = directory.path().join("wrong.pub");
        for (private, public) in [
            (&first_private, &first_public),
            (&second_private, &second_public),
            (&wrong_private, &wrong_public),
        ] {
            let key = BundleSigningKey::read_file(private).expect("private key reads");
            fs::write(public, key.verification_key().as_bytes()).expect("public key writes");
        }
        let signing_key_before = fs::read(&first_private).expect("signing key reads");
        let conflict = sign_bundle(&bundle, &first_private, Some(&first_private))
            .expect_err("signed output cannot overwrite its signing key");
        assert_eq!(conflict.code(), "bundle.sign_output_conflict");
        assert_eq!(
            fs::read(&first_private).expect("signing key remains"),
            signing_key_before
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let alias = directory.path().join("signing-output-alias.oxb");
            symlink(&first_private, &alias).expect("key alias can be created");
            let conflict = sign_bundle(&bundle, &first_private, Some(&alias))
                .expect_err("symlink output cannot alias its signing key");
            assert_eq!(conflict.code(), "bundle.sign_output_conflict");
            assert_eq!(
                fs::read(&first_private).expect("signing key remains"),
                signing_key_before
            );
        }
        sign_bundle(&bundle, &first_private, None).expect("first signature is added");
        sign_bundle(&bundle, &second_private, None).expect("second signature is added");
        let verified = verify_bundle(
            &bundle,
            &[first_public.clone(), second_public.clone()],
            Some(directory.path()),
        )
        .expect("rotated trusted keys verify");
        assert_eq!(verified.verified_key_ids.len(), 2);
        let one = verify_bundle(&bundle, &[first_public], Some(directory.path()))
            .expect("one trusted key is sufficient");
        assert_eq!(one.verified_key_ids.len(), 1);
        assert_eq!(one.untrusted_signature_count, 1);
        assert!(
            verify_bundle(
                &bundle,
                std::slice::from_ref(&wrong_public),
                Some(directory.path())
            )
            .is_err()
        );
        assert!(
            load_bundle_snapshot(
                &bundle,
                std::slice::from_ref(&wrong_public),
                false,
                Some(directory.path())
            )
            .is_err(),
            "serve policy rejects signatures outside its trust set"
        );
        load_bundle_snapshot(&bundle, &[second_public], false, Some(directory.path()))
            .expect("serve policy accepts any trusted rotation key");

        let inspection = inspect_bundle(&bundle, false).expect("signed Bundle inspects");
        assert_eq!(inspection.signatures, 2);
        assert!(inspection.reference_assets.is_empty());
        assert_eq!(
            inspection,
            oxidase_bundle::BundleArchive::read_path(
                &bundle,
                &oxidase_bundle::BundleLimits::default(),
            )
            .expect("Bundle reads")
            .inspect(InspectionVerbosity::Safe)
        );
    }

    #[test]
    fn secret_and_private_key_bytes_never_enter_the_bundle() {
        let directory = tempdir().expect("root exists");
        let generated = rcgen::generate_simple_self_signed(vec!["bundle.example.test".to_owned()])
            .expect("test identity generates");
        let secret = b"distinctive-runtime-secret-never-embed";
        let private_key = generated.signing_key.serialize_pem();
        fs::write(directory.path().join("secret.bin"), secret).expect("Secret writes");
        fs::write(directory.path().join("cert.pem"), generated.cert.pem())
            .expect("certificate writes");
        fs::write(directory.path().join("key.pem"), &private_key).expect("private key writes");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: ./secret.bin
  certificates:
    unused:
      cert_chain: ./cert.pem
      private_key: ./key.pem
  trust_stores:
    internal:
      ca_bundle: ./cert.pem
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
        .expect("Gateway writes");
        let (gateway, snapshot) = prepare(&config);
        let bundle = directory.path().join("gateway.oxb");
        build_bundle(&gateway, &snapshot, &bundle, directory.path()).expect("Bundle builds");
        let bytes = fs::read(&bundle).expect("Bundle reads");
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        assert!(
            !bytes
                .windows(private_key.len())
                .any(|window| window == private_key.as_bytes())
        );
        let inspection = inspect_bundle(&bundle, false).expect("Bundle inspects safely");
        assert_eq!(inspection.sensitive_references.len(), 2);
        let encoded = serde_json::to_string(&inspection).expect("inspection serializes");
        assert!(!encoded.contains("secret.bin"));
        assert!(!encoded.contains("key.pem"));

        let archive = oxidase_bundle::BundleArchive::read_path(
            &bundle,
            &oxidase_bundle::BundleLimits::default(),
        )
        .expect("Bundle reads");
        let plan = decode_runtime_plan(&archive).expect("runtime section decodes");
        let mut mismatched = archive.manifest().clone();
        mismatched.sensitive_references.clear();
        let error = validate_sensitive_references(&mismatched, &plan)
            .expect_err("inspection index cannot diverge from runtime references");
        assert_eq!(error.code(), "bundle.sensitive_reference_mismatch");

        let rewrite_runtime = |path: &Path, plan: &PortableRuntimePlanV1| {
            let mut manifest = archive.manifest().clone();
            manifest.sections.insert(
                RUNTIME_SECTION.to_owned(),
                StableSection::from_serde(PORTABLE_RUNTIME_PLAN_SCHEMA_V1, true, plan)
                    .expect("mutated runtime plan remains structurally encodable"),
            );
            BundleBuilder::new(manifest)
                .write_atomic(path)
                .expect("mutated structural Bundle writes");
        };

        let mut invalid_certificate = plan.clone();
        invalid_certificate
            .certificate_chains
            .get_mut("certificate:unused")
            .expect("public certificate is embedded")
            .certificates_der[0] = vec![0, 1, 2];
        let invalid_certificate_bundle = directory.path().join("invalid-certificate.oxb");
        rewrite_runtime(&invalid_certificate_bundle, &invalid_certificate);
        let error = verify_bundle(&invalid_certificate_bundle, &[], Some(directory.path()))
            .expect_err("CLI verification rejects invalid embedded public certificate DER");
        assert_eq!(error.code(), "tls.certificate_x509");

        let mut invalid_trust = plan;
        invalid_trust
            .trust_stores
            .get_mut("trust_store:internal")
            .expect("public trust store is embedded")
            .certificates_der[0] = vec![0, 1, 2];
        let invalid_trust_bundle = directory.path().join("invalid-trust.oxb");
        rewrite_runtime(&invalid_trust_bundle, &invalid_trust);
        let error = verify_bundle(&invalid_trust_bundle, &[], Some(directory.path()))
            .expect_err("CLI verification rejects invalid embedded public trust DER");
        assert_eq!(error.code(), "trust_store.certificate");
    }

    #[test]
    fn executable_site_asset_set_must_exactly_match_the_manifest() {
        let directory = tempdir().expect("root exists");
        let config = write_site_gateway(directory.path(), "embed");
        let (gateway, snapshot) = prepare(&config);
        let bundle = directory.path().join("gateway.oxb");
        build_bundle(&gateway, &snapshot, &bundle, directory.path()).expect("Bundle builds");
        let archive = oxidase_bundle::BundleArchive::read_path(
            &bundle,
            &oxidase_bundle::BundleLimits::default(),
        )
        .expect("Bundle reads");
        let plan = decode_runtime_plan(&archive).expect("runtime plan decodes");
        let mut manifest = archive.manifest().clone();
        manifest.assets.insert(
            "sha256-unused".to_owned(),
            oxidase_bundle::AssetDescriptor {
                storage: oxidase_bundle::AssetStorage::Reference {
                    base: oxidase_bundle::AssetReferenceBase::Absolute,
                    path: "/unused".to_owned(),
                    expected_digest: oxidase_bundle::BundleDigest::of_bytes(b"unused"),
                    length: 6,
                },
            },
        );
        let error = validate_asset_set(&manifest, &plan)
            .expect_err("unreferenced Asset descriptors are rejected");
        assert_eq!(error.code(), "bundle.asset_set_mismatch");
    }
}
