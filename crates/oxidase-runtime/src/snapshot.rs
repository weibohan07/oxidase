use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use oxidase_config::{
    ClusterSpec, CompiledGateway, CompiledListener, ConfigTestSource, GatewaySummary, RetryBodyMode,
};
use oxidase_core::{
    ConfigVersion, ContentDigest, ContentDigestBuilder, Diagnostic, ResourceId, ServiceGraph,
    ServiceProgram, SourceSpan,
};
use oxidase_site::{AssetSource, SiteCompileError, SiteCompileFailure, SiteCompiler, SiteSnapshot};

use crate::cluster::PreparedCluster;
use crate::governance::GovernanceRegistry;
use crate::regular_file::open_regular_file;
use crate::secret::{PreparedSecret, SecretPreparationErrorKind, SecretPreparationFailure};
use crate::tls::{
    CertificatePreparationErrorKind, CertificatePreparationFailure, PreparedCertificate,
    PreparedListenerPlan, TlsListenerPreparationErrorKind, TlsListenerPreparationFailure,
};
use crate::trust::{
    PreparedTrustStore, TrustStorePreparationErrorKind, TrustStorePreparationFailure,
};
use crate::upstream_tls::{
    PreparedUpstreamTls, UpstreamTlsPreparationErrorKind, UpstreamTlsPreparationFailure,
};

#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry {
    pub secrets: BTreeMap<ResourceId, Arc<PreparedSecret>>,
    pub trust_stores: BTreeMap<ResourceId, Arc<PreparedTrustStore>>,
    pub certificates: BTreeMap<ResourceId, Arc<PreparedCertificate>>,
    pub clusters: BTreeMap<ResourceId, Arc<PreparedCluster>>,
    pub sites: BTreeMap<ResourceId, Arc<SiteSnapshot>>,
}

pub(crate) struct PortablePreparedSite {
    pub snapshot: Arc<SiteSnapshot>,
    pub fingerprint: ContentDigest,
}

/// Source-free public resources decoded from a portable Bundle.
///
/// Secret and private-key bytes are intentionally absent. Their compiler-owned
/// file references remain in `CompiledGateway` and are validated during the
/// ordinary candidate preparation transaction.
pub(crate) struct PortablePreparedResources {
    pub dependencies: Vec<std::path::PathBuf>,
    pub sites: BTreeMap<ResourceId, PortablePreparedSite>,
    pub certificate_chains: BTreeMap<ResourceId, Vec<Vec<u8>>>,
    pub trust_store_roots: BTreeMap<ResourceId, Vec<Vec<u8>>>,
}

#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub config_version: ConfigVersion,
    pub dependencies: Vec<std::path::PathBuf>,
    pub graph: Arc<ServiceGraph>,
    pub governance: GovernanceRegistry,
    pub resources: ResourceRegistry,
    pub listeners: Vec<CompiledListener>,
    pub prepared_listeners: Vec<PreparedListenerPlan>,
    pub tests: Vec<ConfigTestSource>,
    preparation_warnings: Vec<Diagnostic>,
    summary: GatewaySummary,
    secret_fingerprints: BTreeMap<ResourceId, ContentDigest>,
    trust_store_fingerprints: BTreeMap<ResourceId, ContentDigest>,
    certificate_fingerprints: BTreeMap<ResourceId, ContentDigest>,
    site_fingerprints: BTreeMap<ResourceId, ContentDigest>,
    cluster_fingerprints: BTreeMap<ResourceId, ContentDigest>,
}

impl fmt::Debug for RuntimeSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeSnapshot")
            .field("config_version", &self.config_version)
            .field("service_nodes", &self.graph.len())
            .field("secret_count", &self.resources.secrets.len())
            .field("trust_store_count", &self.resources.trust_stores.len())
            .field("certificate_count", &self.resources.certificates.len())
            .field("cluster_count", &self.resources.clusters.len())
            .field("site_count", &self.resources.sites.len())
            .field("listener_count", &self.listeners.len())
            .field("test_count", &self.tests.len())
            .field("warning_count", &self.preparation_warnings.len())
            .finish_non_exhaustive()
    }
}

impl RuntimeSnapshot {
    pub fn prepare(gateway: CompiledGateway) -> Result<Self, PreparationError> {
        Self::prepare_reusing(gateway, None).map(|(snapshot, _)| snapshot)
    }

    pub fn prepare_reusing(
        gateway: CompiledGateway,
        previous: Option<&Self>,
    ) -> Result<(Self, ResourceReuse), PreparationError> {
        Self::prepare_reusing_with_resources(gateway, previous, None)
    }

    pub(crate) fn prepare_reusing_with_resources(
        gateway: CompiledGateway,
        previous: Option<&Self>,
        portable: Option<&PortablePreparedResources>,
    ) -> Result<(Self, ResourceReuse), PreparationError> {
        let mut summary = gateway.summary();
        let mut sites = BTreeMap::new();
        let mut site_fingerprints = BTreeMap::new();
        let mut reuse = ResourceReuse::default();
        let (governance, governance_reuse) = GovernanceRegistry::prepare(
            &gateway.graph,
            previous.map(|previous| &previous.governance),
        );
        reuse.concurrency_limiters = governance_reuse.concurrency;
        reuse.rate_limiters = governance_reuse.rate_limits;
        let mut dependencies = gateway.dependencies.clone();
        if let Some(portable) = portable {
            dependencies.extend(portable.dependencies.iter().cloned());
        }
        let mut preparation_warnings = Vec::new();
        let mut sensitive_dependencies = gateway
            .resources
            .secrets
            .values()
            .flat_map(|source| dependency_path_forms(&source.file))
            .collect::<BTreeSet<_>>();
        sensitive_dependencies.extend(
            gateway
                .resources
                .certificates
                .values()
                .flat_map(|source| dependency_path_forms(&source.private_key)),
        );
        if let Some(portable) = portable {
            for (id, candidate) in &portable.sites {
                let snapshot = previous
                    .filter(|previous| {
                        previous.site_fingerprints.get(id) == Some(&candidate.fingerprint)
                    })
                    .and_then(|previous| previous.resources.sites.get(id).cloned());
                let snapshot = if let Some(snapshot) = snapshot {
                    reuse.sites += 1;
                    snapshot
                } else {
                    Arc::clone(&candidate.snapshot)
                };
                site_fingerprints.insert(id.clone(), candidate.fingerprint);
                sites.insert(id.clone(), snapshot);
            }
            summary.sites = sites.keys().map(ToString::to_string).collect();
        } else {
            for (id, source) in &gateway.resources.sites {
                let index =
                    SiteCompiler::scan(&source.root, &source.manifest).map_err(|failure| {
                        preparation_error_from_site(id, &source.source, &dependencies, failure)
                    })?;
                let fingerprint = index.fingerprint(&source.inputs).map_err(|message| {
                    let mut candidate_dependencies = dependencies.clone();
                    candidate_dependencies.extend(index.dependencies().iter().cloned());
                    normalize_dependencies(&mut candidate_dependencies);
                    let diagnostic = Diagnostic::new(
                        "site.fingerprint",
                        "cannot fingerprint the prepared Site inputs",
                        source.source.clone(),
                    )
                    .with_note(message.clone());
                    PreparationError {
                        resource: id.clone(),
                        kind: PreparationErrorKind::Fingerprint(message),
                        diagnostics: vec![diagnostic],
                        candidate_dependencies,
                    }
                })?;
                let snapshot = previous
                    .filter(|previous| previous.site_fingerprints.get(id) == Some(&fingerprint))
                    .and_then(|previous| previous.resources.sites.get(id).cloned());
                let snapshot = if let Some(snapshot) = snapshot {
                    reuse.sites += 1;
                    snapshot
                } else {
                    let compiled = SiteCompiler::compile_indexed_with_input_spans(
                        id.clone(),
                        &index,
                        source.inputs.clone(),
                        source.input_spans.clone(),
                    )
                    .map_err(|failure| {
                        preparation_error_from_site(id, &source.source, &dependencies, failure)
                    })?;
                    Arc::new(compiled)
                };
                dependencies.extend(index.dependencies().iter().cloned());
                dependencies.extend(site_directories(&snapshot));
                site_fingerprints.insert(id.clone(), fingerprint);
                sites.insert(id.clone(), snapshot);
            }
        }
        let mut secrets = BTreeMap::new();
        let mut secret_fingerprints = BTreeMap::new();
        for (id, source) in &gateway.resources.secrets {
            // Always read and validate the candidate before reuse. A missing,
            // oversized, or unreadable rotation must retain last-known-good.
            let candidate = PreparedSecret::prepare(source).map_err(|failure| {
                preparation_error_from_secret(id, &dependencies, &source.file, failure)
            })?;
            preparation_warnings.extend(candidate.warnings);
            let fingerprint = candidate.secret.fingerprint();
            let secret = previous
                .filter(|previous| previous.secret_fingerprints.get(id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.secrets.get(id).cloned());
            let secret = if let Some(secret) = secret {
                reuse.secrets += 1;
                secret
            } else {
                Arc::new(candidate.secret)
            };
            if let Ok(canonical) = source.file.canonicalize() {
                dependencies.push(canonical);
            }
            secret_fingerprints.insert(id.clone(), fingerprint);
            secrets.insert(id.clone(), secret);
        }
        let mut trust_stores = BTreeMap::new();
        let mut trust_store_fingerprints = BTreeMap::new();
        for (id, source) in &gateway.resources.trust_stores {
            let candidate = portable
                .and_then(|portable| portable.trust_store_roots.get(id))
                .map_or_else(
                    || PreparedTrustStore::prepare(source),
                    |roots| PreparedTrustStore::prepare_with_public_roots(source, roots),
                )
                .map_err(|failure| {
                    preparation_error_from_trust_store(
                        id,
                        &dependencies,
                        &source.ca_bundle,
                        failure,
                    )
                })?;
            let fingerprint = candidate.digest();
            let trust_store = previous
                .filter(|previous| previous.trust_store_fingerprints.get(id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.trust_stores.get(id).cloned());
            let trust_store = if let Some(trust_store) = trust_store {
                reuse.trust_stores += 1;
                trust_store
            } else {
                Arc::new(candidate)
            };
            if portable.is_none()
                && let Ok(canonical) = source.ca_bundle.canonicalize()
            {
                dependencies.push(canonical);
            }
            trust_store_fingerprints.insert(id.clone(), fingerprint);
            trust_stores.insert(id.clone(), trust_store);
        }
        let mut certificates = BTreeMap::new();
        let mut certificate_fingerprints = BTreeMap::new();
        for (id, source) in &gateway.resources.certificates {
            // Even when the public chain digest is unchanged, parse and validate
            // the candidate private key before deciding to reuse the old opaque
            // signing state. An invalid key-only rotation must never commit.
            let candidate = portable
                .and_then(|portable| portable.certificate_chains.get(id))
                .map_or_else(
                    || PreparedCertificate::prepare(source),
                    |chain| PreparedCertificate::prepare_with_public_chain(source, chain),
                )
                .map_err(|failure| {
                    preparation_error_from_certificate(id, &dependencies, failure)
                })?;
            let fingerprint = candidate.digest;
            let certificate = previous
                .filter(|previous| previous.certificate_fingerprints.get(id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.certificates.get(id).cloned());
            let certificate = if let Some(certificate) = certificate {
                reuse.certificates += 1;
                certificate
            } else {
                Arc::new(candidate)
            };
            let dependency_paths: &[&std::path::Path] = if portable.is_some() {
                &[source.private_key.as_path()]
            } else {
                &[source.cert_chain.as_path(), source.private_key.as_path()]
            };
            for path in dependency_paths {
                if let Ok(canonical) = path.canonicalize() {
                    dependencies.push(canonical);
                }
            }
            certificate_fingerprints.insert(id.clone(), fingerprint);
            certificates.insert(id.clone(), certificate);
        }
        validate_sensitive_site_asset_isolation(&gateway, &sites, &dependencies)?;
        let mut clusters = BTreeMap::new();
        let mut cluster_fingerprints = BTreeMap::new();
        for (id, source) in gateway.resources.clusters {
            let upstream_tls = PreparedUpstreamTls::prepare(&source, &trust_stores, &certificates)
                .map_err(|failure| {
                    preparation_error_from_upstream_tls(&id, &dependencies, failure)
                })?
                .map(Arc::new);
            let mut fingerprint_builder = ContentDigestBuilder::new("oxidase/prepared-cluster/v1");
            fingerprint_builder.field_digest("cluster_spec", cluster_fingerprint(&source));
            if let Some(tls) = &upstream_tls {
                fingerprint_builder.field_digest("upstream_tls", tls.digest());
            }
            let fingerprint = fingerprint_builder.finish();
            let previous_cluster =
                previous.and_then(|previous| previous.resources.clusters.get(&id));
            let unchanged = previous
                .filter(|previous| previous.cluster_fingerprints.get(&id) == Some(&fingerprint))
                .and_then(|_| previous_cluster.cloned());
            let cluster = if let Some(cluster) = unchanged {
                reuse.clusters += 1;
                reuse.cluster_endpoints += cluster.endpoints().len();
                cluster
            } else {
                let (cluster, reused_endpoints) = PreparedCluster::prepare_with_tls(
                    source,
                    upstream_tls,
                    previous_cluster.map(Arc::as_ref),
                );
                reuse.cluster_endpoints += reused_endpoints;
                Arc::new(cluster)
            };
            cluster_fingerprints.insert(id.clone(), fingerprint);
            clusters.insert(id, cluster);
        }
        let prepared_listeners = gateway
            .listeners
            .iter()
            .map(|listener| {
                PreparedListenerPlan::prepare(listener, &certificates, &trust_stores).map_err(
                    |failure| preparation_error_from_tls_listener(listener, &dependencies, failure),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        normalize_dependencies(&mut dependencies);
        // Inspection output must remain reproducible without turning a
        // low-entropy Secret into an offline oracle. Build one deterministic
        // public identity from source plus non-secret prepared resources, then
        // derive the live activation identity by adding opaque per-Secret
        // version tokens below.
        let mut public_version_hash =
            ContentDigestBuilder::new("oxidase/runtime-snapshot-public/v1");
        public_version_hash.field_bytes("gateway", gateway.config_version.as_str().as_bytes());
        for (id, fingerprint) in &trust_store_fingerprints {
            public_version_hash
                .field_bytes("trust_store_id", id.as_str().as_bytes())
                .field_digest("trust_store_digest", *fingerprint);
        }
        for (id, fingerprint) in &certificate_fingerprints {
            public_version_hash
                .field_bytes("certificate_id", id.as_str().as_bytes())
                .field_digest("certificate_digest", *fingerprint);
        }
        for (id, fingerprint) in &site_fingerprints {
            public_version_hash
                .field_bytes("site_id", id.as_str().as_bytes())
                .field_digest("site_digest", *fingerprint);
        }
        for (id, fingerprint) in &cluster_fingerprints {
            public_version_hash
                .field_bytes("cluster_id", id.as_str().as_bytes())
                .field_digest("cluster_digest", *fingerprint);
        }
        let public_config_version =
            ConfigVersion::new(format!("v2-sha256-{}", public_version_hash.finish()));
        summary.config_version = public_config_version.to_string();

        let mut version_hash = ContentDigestBuilder::new("oxidase/runtime-snapshot-activation/v1");
        version_hash.field_bytes(
            "public_config_version",
            public_config_version.as_str().as_bytes(),
        );
        for (id, secret) in &secrets {
            version_hash
                .field_bytes("secret_id", id.as_str().as_bytes())
                // The raw deterministic fingerprint is deliberately excluded:
                // a random token makes a rotated Secret visible to live reload
                // while remaining stable only for reuse of the same prepared Arc.
                .field_digest("secret_version_token", secret.version_token());
        }
        let config_version = ConfigVersion::new(format!("v2-sha256-{}", version_hash.finish()));
        summary.dependencies = dependencies
            .iter()
            .filter(|path| !sensitive_dependencies.contains(*path))
            .map(|path| path.display().to_string())
            .collect();
        Ok((
            Self {
                config_version,
                dependencies,
                graph: gateway.graph,
                governance,
                resources: ResourceRegistry {
                    secrets,
                    trust_stores,
                    certificates,
                    clusters,
                    sites,
                },
                listeners: gateway.listeners,
                prepared_listeners,
                tests: gateway.tests,
                preparation_warnings,
                summary,
                secret_fingerprints,
                trust_store_fingerprints,
                certificate_fingerprints,
                site_fingerprints,
                cluster_fingerprints,
            },
            reuse,
        ))
    }

    #[must_use]
    pub fn summary(&self) -> &GatewaySummary {
        &self.summary
    }

    /// Non-fatal warnings discovered while preparing file-backed resources.
    #[must_use]
    pub fn preparation_warnings(&self) -> &[Diagnostic] {
        &self.preparation_warnings
    }

    #[must_use]
    pub fn program_for(&self, listener: &str) -> Option<ServiceProgram> {
        self.listeners
            .iter()
            .find(|candidate| candidate.id.as_str() == listener || candidate.name == listener)
            .map(|listener| ServiceProgram::new(listener.service.clone(), Arc::clone(&self.graph)))
    }

    #[must_use]
    pub fn prepared_listener_for(&self, listener: &str) -> Option<&PreparedListenerPlan> {
        self.prepared_listeners
            .iter()
            .find(|candidate| candidate.id.as_str() == listener || candidate.name == listener)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceReuse {
    pub secrets: usize,
    pub trust_stores: usize,
    pub certificates: usize,
    pub sites: usize,
    pub clusters: usize,
    /// Endpoint runtime states reused even when the immutable Cluster policy changed.
    pub cluster_endpoints: usize,
    /// Concurrency counters reused by compiler-owned Service identity.
    pub concurrency_limiters: usize,
    /// Token-bucket maps reused only when their complete policy is unchanged.
    pub rate_limiters: usize,
}

pub struct PreparationError {
    pub resource: ResourceId,
    pub kind: PreparationErrorKind,
    diagnostics: Vec<Diagnostic>,
    pub candidate_dependencies: Vec<std::path::PathBuf>,
}

impl fmt::Debug for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparationError")
            .field("resource", &self.resource)
            .field("kind", &self.kind)
            .field("diagnostics", &self.diagnostics)
            .field(
                "candidate_dependency_count",
                &self.candidate_dependencies.len(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum PreparationErrorKind {
    Secret(SecretPreparationErrorKind),
    TrustStore(TrustStorePreparationErrorKind),
    Certificate(CertificatePreparationErrorKind),
    SensitiveAssetIsolation,
    Fingerprint(String),
    Site(Box<SiteCompileError>),
    TlsListener(TlsListenerPreparationErrorKind),
    UpstreamTls(UpstreamTlsPreparationErrorKind),
}

fn preparation_error_from_secret(
    resource: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
    declared_path: &std::path::Path,
    failure: SecretPreparationFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    candidate_dependencies.extend(dependency_path_forms(declared_path));
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::Secret(failure.kind),
        diagnostics: vec![*failure.diagnostic],
        candidate_dependencies,
    }
}

fn preparation_error_from_trust_store(
    resource: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
    declared_path: &std::path::Path,
    failure: TrustStorePreparationFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    candidate_dependencies.extend(dependency_path_forms(declared_path));
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::TrustStore(failure.kind),
        diagnostics: vec![*failure.diagnostic],
        candidate_dependencies,
    }
}

fn preparation_error_from_upstream_tls(
    resource: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
    failure: UpstreamTlsPreparationFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::UpstreamTls(failure.kind),
        diagnostics: vec![*failure.diagnostic],
        candidate_dependencies,
    }
}

fn preparation_error_from_certificate(
    resource: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
    failure: CertificatePreparationFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::Certificate(failure.kind),
        diagnostics: vec![*failure.diagnostic],
        candidate_dependencies,
    }
}

fn preparation_error_from_tls_listener(
    listener: &CompiledListener,
    existing_dependencies: &[std::path::PathBuf],
    failure: TlsListenerPreparationFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: ResourceId::new(format!("listener:{}", listener.name)),
        kind: PreparationErrorKind::TlsListener(failure.kind),
        diagnostics: vec![*failure.diagnostic],
        candidate_dependencies,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    canonical: Option<std::path::PathBuf>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(
        display_path: &std::path::Path,
        metadata: &std::fs::Metadata,
    ) -> Result<Self, ()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;

            Ok(Self {
                canonical: display_path.canonicalize().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                canonical: Some(display_path.canonicalize().map_err(|_| ())?),
            })
        }
    }

    fn refers_to_same_file(&self, other: &Self) -> bool {
        #[cfg(unix)]
        if self.device == other.device && self.inode == other.inode {
            return true;
        }
        self.canonical
            .as_ref()
            .zip(other.canonical.as_ref())
            .is_some_and(|(left, right)| left == right)
    }
}

fn asset_file_identity(source: &AssetSource) -> Result<FileIdentity, ()> {
    match source {
        AssetSource::File(path) => {
            let (_file, metadata) = open_regular_file(path).map_err(|_| ())?;
            FileIdentity::from_metadata(path, &metadata)
        }
        AssetSource::Pinned {
            file,
            display,
            origin,
            ..
        } => {
            // Reference-mode Assets are served from an immutable spool, but
            // the spool's inode says nothing about whether the original file
            // was a hardlink to a Secret/private key. The loader retains the
            // exact verified origin handle for this identity check only.
            let identity_file = origin.as_deref().unwrap_or(file);
            let metadata = identity_file.metadata().map_err(|_| ())?;
            if !metadata.is_file() {
                return Err(());
            }
            FileIdentity::from_metadata(display, &metadata)
        }
    }
}

fn sensitive_file_identity(path: &std::path::Path) -> Result<FileIdentity, ()> {
    let (_file, metadata) = open_regular_file(path).map_err(|_| ())?;
    FileIdentity::from_metadata(path, &metadata)
}

fn validate_sensitive_site_asset_isolation(
    gateway: &CompiledGateway,
    sites: &BTreeMap<ResourceId, Arc<SiteSnapshot>>,
    dependencies: &[std::path::PathBuf],
) -> Result<(), PreparationError> {
    if gateway.resources.secrets.is_empty() && gateway.resources.certificates.is_empty() {
        return Ok(());
    }
    let mut public_assets = Vec::new();
    for (site_id, site) in sites {
        for source in site.asset_sources() {
            let identity = asset_file_identity(source).map_err(|()| {
                sensitive_asset_identity_error(
                    site_id,
                    site_source_span(gateway, site_id),
                    dependencies,
                    true,
                )
            })?;
            public_assets.push((site_id, identity));
        }
    }

    for (resource, path, source) in gateway
        .resources
        .secrets
        .iter()
        .map(|(id, secret)| (id, secret.file.as_path(), &secret.file_source))
        .chain(
            gateway
                .resources
                .certificates
                .iter()
                .map(|(id, certificate)| {
                    (
                        id,
                        certificate.private_key.as_path(),
                        &certificate.private_key_source,
                    )
                }),
        )
    {
        let sensitive = sensitive_file_identity(path).map_err(|()| {
            sensitive_asset_identity_error(resource, source.clone(), dependencies, false)
        })?;
        if let Some((site_id, _)) = public_assets
            .iter()
            .find(|(_, asset)| sensitive.refers_to_same_file(asset))
        {
            return Err(sensitive_asset_overlap_error(
                gateway,
                resource,
                source,
                site_id,
                dependencies,
            ));
        }
    }
    Ok(())
}

fn site_source_span(gateway: &CompiledGateway, site: &ResourceId) -> SourceSpan {
    gateway
        .resources
        .sites
        .get(site)
        .map(|source| source.source.clone())
        .unwrap_or_else(|| SourceSpan::synthetic(format!("resources.sites.{site}")))
}

fn sensitive_asset_identity_error(
    resource: &ResourceId,
    source: SourceSpan,
    existing_dependencies: &[std::path::PathBuf],
    site_asset: bool,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    normalize_dependencies(&mut candidate_dependencies);
    let message = if site_asset {
        "cannot verify that a public Site Asset is isolated from sensitive resources"
    } else {
        "cannot verify that a sensitive resource is isolated from public Site Assets"
    };
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::SensitiveAssetIsolation,
        diagnostics: vec![
            Diagnostic::new("resource.sensitive_asset_identity", message, source)
                .with_help("keep Secret and private-key files outside every public Site Asset"),
        ],
        candidate_dependencies,
    }
}

fn sensitive_asset_overlap_error(
    gateway: &CompiledGateway,
    resource: &ResourceId,
    sensitive_source: &SourceSpan,
    site: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::SensitiveAssetIsolation,
        diagnostics: vec![Diagnostic::new(
            "resource.sensitive_site_asset_overlap",
            format!(
                "sensitive resource `{resource}` is also exposed as a public Asset by Site `{site}`"
            ),
            sensitive_source.clone(),
        )
        .with_related("public Site resource", site_source_span(gateway, site))
        .with_help("move the sensitive file outside the Site or deny the public Asset")],
        candidate_dependencies,
    }
}

fn preparation_error_from_site(
    resource: &ResourceId,
    resource_source: &SourceSpan,
    existing_dependencies: &[std::path::PathBuf],
    failure: SiteCompileFailure,
) -> PreparationError {
    let SiteCompileFailure {
        error,
        mut diagnostics,
        discovered_dependencies,
    } = failure;
    let mut candidate_dependencies = existing_dependencies.to_vec();
    candidate_dependencies.extend(discovered_dependencies);
    normalize_dependencies(&mut candidate_dependencies);
    if diagnostics.is_empty() {
        diagnostics.push(Diagnostic::new(
            "site.prepare",
            error.to_string(),
            resource_source.clone(),
        ));
    }
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::Site(error),
        diagnostics,
        candidate_dependencies,
    }
}

impl PreparationError {
    /// Returns the structured diagnostics produced while preparing the candidate
    /// snapshot. Dependency discovery remains a separate reload concern.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Consumes the preparation error and preserves its structured diagnostics
    /// for the CLI or another presentation boundary.
    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

fn normalize_dependencies(dependencies: &mut Vec<std::path::PathBuf>) {
    dependencies.sort();
    dependencies.dedup();
}

fn dependency_path_forms(path: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut paths = vec![path.to_path_buf()];
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        paths.push(parent.to_path_buf());
    }
    if let Ok(canonical) = path.canonicalize() {
        paths.push(canonical);
    }
    paths
}

fn cluster_fingerprint(source: &ClusterSpec) -> ContentDigest {
    let mut hash = ContentDigestBuilder::new("oxidase/cluster/v3");
    hash.field_bytes("protocol", source.protocol.as_str().as_bytes());
    hash.field_u64("endpoint_count", source.endpoints.len() as u64);
    for endpoint in &source.endpoints {
        hash.field_bytes("endpoint_name", endpoint.name.as_bytes())
            .field_bytes("endpoint_url", endpoint.url.as_str().as_bytes())
            .field_u64("endpoint_weight", u64::from(endpoint.weight));
    }
    hash.field_bytes("load_balance", source.load_balance.as_str().as_bytes());
    if let Some(active) = &source.health.active {
        hash.field_bytes("active_health", b"present")
            .field_bytes("active_path", active.path.as_bytes())
            .field_u128("active_interval_ns", active.interval.as_nanos())
            .field_u128("active_timeout_ns", active.timeout.as_nanos())
            .field_u64(
                "active_healthy_threshold",
                u64::from(active.healthy_threshold),
            )
            .field_u64(
                "active_unhealthy_threshold",
                u64::from(active.unhealthy_threshold),
            );
        let mut statuses = active.healthy_statuses.clone();
        statuses.sort_by_key(|range| (range.start, range.end));
        hash.field_u64("active_status_count", statuses.len() as u64);
        for status in statuses {
            hash.field_u64("active_status_start", u64::from(status.start))
                .field_u64("active_status_end", u64::from(status.end));
        }
    } else {
        hash.field_bytes("active_health", b"absent");
    }
    if let Some(passive) = &source.health.passive {
        hash.field_bytes("passive_health", b"present")
            .field_u64(
                "passive_consecutive_failures",
                u64::from(passive.consecutive_failures),
            )
            .field_u128("passive_eject_for_ns", passive.eject_for.as_nanos());
    } else {
        hash.field_bytes("passive_health", b"absent");
    }
    hash.field_u64("retry_max_attempts", u64::from(source.retry.max_attempts));
    let mut methods = source
        .retry
        .methods
        .iter()
        .map(http::Method::as_str)
        .collect::<Vec<_>>();
    methods.sort_unstable();
    methods.dedup();
    hash.field_u64("retry_method_count", methods.len() as u64);
    for method in methods {
        hash.field_bytes("retry_method", method.as_bytes());
    }
    let mut causes = source
        .retry
        .retry_on
        .iter()
        .map(|cause| cause.as_str())
        .collect::<Vec<_>>();
    causes.sort_unstable();
    causes.dedup();
    hash.field_u64("retry_cause_count", causes.len() as u64);
    for cause in causes {
        hash.field_bytes("retry_cause", cause.as_bytes());
    }
    let mut retry_statuses = source.retry.statuses.clone();
    retry_statuses.sort_by_key(|range| (range.start, range.end));
    hash.field_u64("retry_status_count", retry_statuses.len() as u64);
    for status in retry_statuses {
        hash.field_u64("retry_status_start", u64::from(status.start))
            .field_u64("retry_status_end", u64::from(status.end));
    }
    hash.field_bytes(
        "retry_body_mode",
        match source.retry.request_body.mode {
            RetryBodyMode::None => b"none".as_slice(),
            RetryBodyMode::Buffer => b"buffer".as_slice(),
        },
    )
    .field_u64("retry_body_max_bytes", source.retry.request_body.max_bytes)
    .field_u64(
        "retry_max_concurrent",
        u64::from(source.retry.max_concurrent_retries),
    )
    .field_u64(
        "limit_cluster_in_flight",
        u64::from(source.limits.max_in_flight),
    )
    .field_u64(
        "limit_endpoint_in_flight",
        u64::from(source.limits.max_in_flight_per_endpoint),
    )
    .field_u128(
        "limit_queue_timeout_ns",
        source.limits.queue_timeout.as_nanos(),
    );
    hash.field_u128("connect_timeout_ns", source.connect_timeout.as_nanos());
    hash.field_u128("response_timeout_ns", source.response_timeout.as_nanos());
    hash.finish()
}

fn site_directories(site: &SiteSnapshot) -> Vec<std::path::PathBuf> {
    let mut directories = BTreeMap::new();
    directories.insert(site.root.clone(), ());
    for dependency in &site.dependencies {
        let mut current = dependency.parent();
        while let Some(directory) = current {
            if !directory.starts_with(&site.root) {
                break;
            }
            directories.insert(directory.to_path_buf(), ());
            if directory == site.root {
                break;
            }
            current = directory.parent();
        }
    }
    directories.into_keys().collect()
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to prepare resource `{}`: {}",
            self.resource, self.kind
        )
    }
}

impl std::error::Error for PreparationError {}

impl fmt::Display for PreparationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret(error) => error.fmt(formatter),
            Self::TrustStore(error) => error.fmt(formatter),
            Self::Certificate(error) => error.fmt(formatter),
            Self::SensitiveAssetIsolation => {
                formatter.write_str("sensitive resource and public Site Asset isolation failed")
            }
            Self::Fingerprint(message) => formatter.write_str(message),
            Self::Site(error) => error.fmt(formatter),
            Self::TlsListener(error) => error.fmt(formatter),
            Self::UpstreamTls(error) => error.fmt(formatter),
        }
    }
}

pub struct SnapshotStore {
    current: ArcSwap<RuntimeSnapshot>,
}

impl SnapshotStore {
    #[must_use]
    pub fn new(initial: RuntimeSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Pins one immutable snapshot for the complete request lifetime.
    #[must_use]
    pub fn pin(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    pub fn publish(&self, prepared: RuntimeSnapshot) -> Arc<RuntimeSnapshot> {
        self.current.swap(Arc::new(prepared))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;
    use std::time::Duration;

    use oxidase_config::{
        ClusterEndpointSpec, ClusterHealthSpec, ClusterLimits, ClusterProtocol, ClusterSpec,
        Compiler, LoadBalancePolicy, RetryBodyMode, RetryRequestBodySpec, RetrySpec,
    };
    use oxidase_core::{ResourceId, SourceSpan};
    use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
    use tempfile::tempdir;
    use url::Url;

    use super::{PreparationErrorKind, RuntimeSnapshot, cluster_fingerprint};

    fn write_test_identity(directory: &std::path::Path, names: &[&str]) {
        let GeneratedCertificate { cert, signing_key } = generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("test-only certificate can be generated");
        fs::write(directory.join("cert.pem"), cert.pem())
            .expect("test-only certificate can be written");
        fs::write(directory.join("key.pem"), signing_key.serialize_pem())
            .expect("test-only private key can be written");
    }

    fn write_tls_gateway(directory: &std::path::Path) -> std::path::PathBuf {
        let config = directory.join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: public
    http:
      versions: [h2, http1]
    service:
      type: respond
"#,
        )
        .expect("TLS gateway can be written");
        config
    }

    fn write_secret_trust_gateway(directory: &std::path::Path) -> std::path::PathBuf {
        fs::write(directory.join("token.txt"), b"first-secret")
            .expect("test-only secret can be written");
        let GeneratedCertificate { cert, .. } =
            generate_simple_self_signed(vec!["root.example.test".to_owned()])
                .expect("test-only trust anchor can be generated");
        fs::write(directory.join("ca.pem"), cert.pem())
            .expect("test-only CA bundle can be written");
        let config = directory.join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: token.txt
      max_bytes: 64B
  trust_stores:
    internal:
      ca_bundle: ca.pem
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        )
        .expect("Secret/Trust gateway can be written");
        config
    }

    fn write_site_secret_gateway(
        directory: &std::path::Path,
        secret_path: &str,
    ) -> std::path::PathBuf {
        let site = directory.join("site");
        fs::create_dir_all(&site).expect("Site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\nvisibility:\n  deny: []\n",
        )
        .expect("Site manifest can be written");
        let config = directory.join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: {secret_path}
      max_bytes: 1KiB
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("Gateway config can be written");
        config
    }

    fn assert_sensitive_site_overlap(config: &std::path::Path, forbidden: &[&str]) {
        let gateway = Compiler::compile_path(config).expect("Gateway source compiles");
        let error = RuntimeSnapshot::prepare(gateway)
            .expect_err("a sensitive file cannot also be a public Site Asset");
        assert!(matches!(
            error.kind,
            PreparationErrorKind::SensitiveAssetIsolation
        ));
        let diagnostics = error.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "resource.sensitive_site_asset_overlap");
        let rendered = diagnostics[0].to_string();
        for value in forbidden {
            assert!(
                !rendered.contains(value),
                "sensitive diagnostic leaked forbidden value `{value}`: {rendered}"
            );
        }
    }

    #[test]
    fn rejects_literal_secret_and_private_key_public_site_assets_without_leaking_values() {
        let directory = tempdir().expect("temporary directory is available");
        let marker = "literal-secret-marker-never-bundle";
        fs::create_dir(directory.path().join("site")).expect("Site directory can be created");
        fs::write(directory.path().join("site/token.txt"), marker)
            .expect("test-only Secret can be written");
        let config = write_site_secret_gateway(directory.path(), "site/token.txt");
        assert_sensitive_site_overlap(&config, &[marker, "site/token.txt"]);

        let certificate_directory = tempdir().expect("temporary directory is available");
        let site = certificate_directory.path().join("site");
        fs::create_dir(&site).expect("Site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\nvisibility:\n  deny: []\n",
        )
        .expect("Site manifest can be written");
        let GeneratedCertificate { cert, signing_key } =
            generate_simple_self_signed(vec!["private.example.test".to_owned()])
                .expect("test-only certificate can be generated");
        fs::write(certificate_directory.path().join("cert.pem"), cert.pem())
            .expect("test-only public chain can be written");
        let private_key = signing_key.serialize_pem();
        fs::write(site.join("private-key.pem"), &private_key)
            .expect("test-only private key can be written");
        let config = certificate_directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: site/private-key.pem
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("Gateway config can be written");
        assert_sensitive_site_overlap(&config, &[private_key.trim(), "site/private-key.pem"]);
    }

    #[test]
    fn rejects_sensitive_precompressed_site_representations() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("Site directory can be created");
        fs::write(site.join("page.txt"), "identity")
            .expect("identity representation can be written");
        let marker = "brotli-secret-marker-never-bundle";
        fs::write(site.join("page.txt.br"), marker)
            .expect("precompressed representation can be written");
        let config = write_site_secret_gateway(directory.path(), "site/page.txt.br");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\nvisibility:\n  deny: []\nassets:\n  precompressed:\n    brotli: .br\n",
        )
        .expect("precompressed Site manifest can be written");
        assert_sensitive_site_overlap(&config, &[marker, "site/page.txt.br"]);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_and_hardlink_aliases_of_public_site_assets() {
        use std::os::unix::fs::symlink;

        for alias_kind in ["symlink", "hardlink"] {
            let directory = tempdir().expect("temporary directory is available");
            let public = directory.path().join("site/public.txt");
            fs::create_dir_all(public.parent().expect("public Asset has parent"))
                .expect("Site directory can be created");
            fs::write(&public, format!("{alias_kind}-secret-marker"))
                .expect("public Asset can be written");
            let alias = directory.path().join("secret-alias.txt");
            if alias_kind == "symlink" {
                symlink(&public, &alias).expect("Secret symlink can be created");
            } else {
                fs::hard_link(&public, &alias).expect("Secret hardlink can be created");
            }
            let config = write_site_secret_gateway(directory.path(), "secret-alias.txt");
            assert_sensitive_site_overlap(
                &config,
                &[&format!("{alias_kind}-secret-marker"), "secret-alias.txt"],
            );
        }
    }

    #[test]
    fn cluster_digest_is_stable_and_preserves_endpoint_preference_order() {
        let cluster = |protocol, endpoints: &[&str]| ClusterSpec {
            id: ResourceId::new("cluster:api"),
            protocol,
            endpoints: endpoints
                .iter()
                .enumerate()
                .map(|(index, endpoint)| ClusterEndpointSpec {
                    name: format!("endpoint-{index}"),
                    url: Url::parse(endpoint).expect("fixture endpoint is valid"),
                    weight: 1,
                    name_source: SourceSpan::synthetic("clusters.api.endpoints.name"),
                    url_source: SourceSpan::synthetic("clusters.api.endpoints.url"),
                    weight_source: SourceSpan::synthetic("clusters.api.endpoints.weight"),
                    source: SourceSpan::synthetic("clusters.api.endpoints"),
                })
                .collect(),
            load_balance: LoadBalancePolicy::RoundRobin,
            health: ClusterHealthSpec::default(),
            retry: RetrySpec {
                max_attempts: 1,
                methods: Vec::new(),
                retry_on: Vec::new(),
                statuses: Vec::new(),
                request_body: RetryRequestBodySpec {
                    mode: RetryBodyMode::None,
                    max_bytes: 64 * 1024,
                    source: SourceSpan::synthetic("clusters.api.retry.request_body"),
                },
                max_concurrent_retries: 32,
                source: SourceSpan::synthetic("clusters.api.retry"),
            },
            limits: ClusterLimits {
                max_in_flight: 1024,
                max_in_flight_per_endpoint: 256,
                queue_timeout: Duration::ZERO,
                source: SourceSpan::synthetic("clusters.api.limits"),
            },
            tls: None,
            connect_timeout: Duration::from_secs(1),
            response_timeout: Duration::from_secs(2),
            protocol_source: SourceSpan::synthetic("clusters.api.protocol"),
            source: SourceSpan::synthetic("clusters.api"),
        };
        let first = cluster(
            ClusterProtocol::Auto,
            &["http://127.0.0.1:3000", "https://example.test/"],
        );
        let same = cluster(
            ClusterProtocol::Auto,
            &["http://127.0.0.1:3000", "https://example.test/"],
        );
        let reordered = cluster(
            ClusterProtocol::Auto,
            &["https://example.test/", "http://127.0.0.1:3000"],
        );
        let forced_h2 = cluster(
            ClusterProtocol::H2,
            &["http://127.0.0.1:3000", "https://example.test/"],
        );
        assert_eq!(cluster_fingerprint(&first), cluster_fingerprint(&same));
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&reordered));
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&forced_h2));

        let mut policy = first.clone();
        policy.load_balance = LoadBalancePolicy::LeastRequests;
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&policy));
        let mut retry = first.clone();
        retry.retry.max_attempts = 2;
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&retry));
        let mut limits = first.clone();
        limits.limits.max_in_flight = 7;
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&limits));
    }

    #[test]
    fn reuses_unchanged_sites_and_clusters_by_content() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(site.join("site.oxsite"), "oxista: site/v1\n").expect("manifest can be written");
        fs::write(site.join("index.html"), "first").expect("asset can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://127.0.0.1:3000
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("config can be written");
        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first config compiles"),
        )
        .expect("first snapshot prepares");
        let (second, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("second config compiles"),
            Some(&first),
        )
        .expect("second snapshot prepares");
        let site_id = ResourceId::new("site:web");
        let cluster_id = ResourceId::new("cluster:api");
        assert_eq!(reuse.sites, 1);
        assert_eq!(reuse.clusters, 1);
        assert_eq!(reuse.cluster_endpoints, 1);
        assert!(Arc::ptr_eq(
            &first.resources.sites[&site_id],
            &second.resources.sites[&site_id]
        ));
        assert!(Arc::ptr_eq(
            &first.resources.clusters[&cluster_id],
            &second.resources.clusters[&cluster_id]
        ));

        fs::write(site.join("index.html"), "second").expect("asset can be updated");
        let (third, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("third config compiles"),
            Some(&second),
        )
        .expect("third snapshot prepares");
        assert_eq!(reuse.sites, 0);
        assert_eq!(reuse.clusters, 1);
        assert_eq!(reuse.cluster_endpoints, 1);
        assert!(!Arc::ptr_eq(
            &second.resources.sites[&site_id],
            &third.resources.sites[&site_id]
        ));

        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - http://127.0.0.1:3000
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("cluster protocol can be updated");
        let (fourth, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("protocol update compiles"),
            Some(&third),
        )
        .expect("protocol update prepares");
        assert_eq!(reuse.clusters, 0);
        assert!(!Arc::ptr_eq(
            &third.resources.clusters[&cluster_id],
            &fourth.resources.clusters[&cluster_id]
        ));
    }

    #[test]
    fn site_reuse_digest_includes_templates_and_compressed_representations() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir_all(site.join("_templates")).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            r#"oxista: site/v1
assets:
  precompressed:
    brotli: .br
templates:
  roots: [_templates]
"#,
        )
        .expect("manifest can be written");
        fs::write(site.join("index.html"), "identity").expect("asset can be written");
        fs::write(site.join("index.html.br"), "compressed-v1")
            .expect("compressed asset can be written");
        fs::write(
            site.join("_templates/page.oxt"),
            "---\noxista: template/v1\n---\ntemplate-v1\n",
        )
        .expect("template can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("config can be written");
        let prepare = |previous: Option<&RuntimeSnapshot>| {
            RuntimeSnapshot::prepare_reusing(
                Compiler::compile_path(&config).expect("config compiles"),
                previous,
            )
            .expect("snapshot prepares")
        };
        let (first, _) = prepare(None);
        let site_id = ResourceId::new("site:web");
        let (unchanged, reuse) = prepare(Some(&first));
        assert_eq!(reuse.sites, 1);
        assert!(Arc::ptr_eq(
            &first.resources.sites[&site_id],
            &unchanged.resources.sites[&site_id]
        ));

        fs::write(
            site.join("_templates/page.oxt"),
            "---\noxista: template/v1\n---\ntemplate-v2\n",
        )
        .expect("template can change");
        let (template_changed, reuse) = prepare(Some(&unchanged));
        assert_eq!(reuse.sites, 0);
        assert!(!Arc::ptr_eq(
            &unchanged.resources.sites[&site_id],
            &template_changed.resources.sites[&site_id]
        ));

        fs::write(site.join("index.html.br"), "compressed-v2")
            .expect("compressed asset can change");
        let (compressed_changed, reuse) = prepare(Some(&template_changed));
        assert_eq!(reuse.sites, 0);
        assert!(!Arc::ptr_eq(
            &template_changed.resources.sites[&site_id],
            &compressed_changed.resources.sites[&site_id]
        ));
    }

    #[test]
    fn preparation_preserves_structured_site_diagnostics() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\npaths:\n  trailing_slash: preserve\n",
        )
        .expect("invalid manifest can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("gateway config can be written");

        let gateway = Compiler::compile_path(&config).expect("gateway source compiles");
        let error = RuntimeSnapshot::prepare(gateway)
            .expect_err("unsupported Site field value must fail preparation");
        assert_eq!(error.diagnostics().len(), 1);
        assert_eq!(error.diagnostics()[0].code, "site.unsupported_field");
        assert_eq!(
            error.diagnostics()[0].primary.field_path,
            "paths.trailing_slash"
        );
        assert_eq!(error.diagnostics()[0].primary.line, 3);

        let diagnostics = error.into_diagnostics();
        assert_eq!(diagnostics[0].primary.column, 19);
    }

    #[test]
    fn site_input_type_diagnostics_relate_gateway_values_to_manifest_contracts() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        let manifest = site.join("site.oxsite");
        fs::write(
            &manifest,
            "oxista: site/v1\ninputs:\n  count:\n    type: int\n",
        )
        .expect("site manifest can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  sites:
    web:
      root: site
      with:
        count: wrong
services:
  root:
    type: site
    site: web
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("gateway config can be written");

        let gateway = Compiler::compile_path(&config).expect("gateway source compiles");
        let error = RuntimeSnapshot::prepare(gateway)
            .expect_err("injected string must not satisfy an integer contract");
        let diagnostic = &error.diagnostics()[0];
        assert_eq!(diagnostic.code, "site.input_type");
        assert_eq!(
            diagnostic.primary.file,
            manifest
                .canonicalize()
                .expect("manifest path canonicalizes")
        );
        assert_eq!(diagnostic.primary.field_path, "inputs.count.type");
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(
            diagnostic.labels[0].span.file,
            config.canonicalize().expect("config path canonicalizes")
        );
        assert_eq!(
            diagnostic.labels[0].span.field_path,
            "resources.sites.web.with.count"
        );
        assert_eq!(diagnostic.reference_chain.len(), 2);
        assert!(
            diagnostic
                .reference_chain
                .iter()
                .all(|reference| reference.span.is_some())
        );
    }

    #[test]
    fn certificate_dependencies_reuse_and_config_version_follow_public_chain() {
        let directory = tempdir().expect("temporary directory is available");
        write_test_identity(directory.path(), &["default.example.test"]);
        let config = write_tls_gateway(directory.path());

        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first TLS gateway compiles"),
        )
        .expect("first TLS snapshot prepares");
        let certificate_id = ResourceId::new("certificate:public");
        let certificate_path = directory
            .path()
            .join("cert.pem")
            .canonicalize()
            .expect("certificate canonicalizes");
        let private_key_path = directory
            .path()
            .join("key.pem")
            .canonicalize()
            .expect("private key canonicalizes");
        assert!(first.dependencies.contains(&certificate_path));
        assert!(first.dependencies.contains(&private_key_path));
        assert_eq!(
            first.prepared_listeners[0]
                .tls
                .as_ref()
                .expect("listener has TLS")
                .server_config
                .alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );

        let (unchanged, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("unchanged TLS gateway compiles"),
            Some(&first),
        )
        .expect("unchanged TLS snapshot prepares");
        assert_eq!(reuse.certificates, 1);
        assert_eq!(first.config_version, unchanged.config_version);
        assert!(Arc::ptr_eq(
            &first.resources.certificates[&certificate_id],
            &unchanged.resources.certificates[&certificate_id]
        ));

        write_test_identity(directory.path(), &["rotated.example.test"]);
        let (rotated, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("rotated TLS gateway compiles"),
            Some(&unchanged),
        )
        .expect("rotated TLS snapshot prepares");
        assert_eq!(reuse.certificates, 0);
        assert_ne!(unchanged.config_version, rotated.config_version);
        assert!(!Arc::ptr_eq(
            &unchanged.resources.certificates[&certificate_id],
            &rotated.resources.certificates[&certificate_id]
        ));
    }

    #[test]
    fn invalid_key_only_rotation_is_validated_before_certificate_reuse() {
        let directory = tempdir().expect("temporary directory is available");
        write_test_identity(directory.path(), &["default.example.test"]);
        let config = write_tls_gateway(directory.path());
        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first TLS gateway compiles"),
        )
        .expect("first TLS snapshot prepares");

        let GeneratedCertificate { signing_key, .. } =
            generate_simple_self_signed(vec!["other.example.test".to_owned()])
                .expect("different test-only key can be generated");
        fs::write(
            directory.path().join("key.pem"),
            signing_key.serialize_pem(),
        )
        .expect("mismatched key can be written");
        let error = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("key-rotated gateway compiles"),
            Some(&first),
        )
        .expect_err("a mismatched key must fail rather than reuse the old signing state");
        assert_eq!(error.diagnostics()[0].code, "tls.key_mismatch");
        assert!(
            error.candidate_dependencies.contains(
                &directory
                    .path()
                    .join("key.pem")
                    .canonicalize()
                    .expect("candidate private key canonicalizes")
            )
        );
    }

    #[test]
    fn secret_and_trust_resources_reuse_by_validated_content() {
        let directory = tempdir().expect("temporary directory is available");
        let config = write_secret_trust_gateway(directory.path());
        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first source compiles"),
        )
        .expect("first snapshot prepares");
        let secret_id = ResourceId::new("secret:token");
        let trust_id = ResourceId::new("trust_store:internal");
        assert!(first.resources.secrets[&secret_id].constant_time_eq(b"first-secret"));
        assert_eq!(
            first.resources.trust_stores[&trust_id].certificate_count(),
            1
        );

        let (same, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("unchanged source compiles"),
            Some(&first),
        )
        .expect("unchanged snapshot prepares");
        assert_eq!(reuse.secrets, 1);
        assert_eq!(reuse.trust_stores, 1);
        assert_eq!(first.config_version, same.config_version);
        assert!(Arc::ptr_eq(
            &first.resources.secrets[&secret_id],
            &same.resources.secrets[&secret_id]
        ));
        assert!(Arc::ptr_eq(
            &first.resources.trust_stores[&trust_id],
            &same.resources.trust_stores[&trust_id]
        ));

        fs::write(directory.path().join("token.txt"), b"next-secret!")
            .expect("rotated secret can be written");
        let (rotated, reuse) = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("rotated source compiles"),
            Some(&same),
        )
        .expect("rotated snapshot prepares");
        assert_eq!(reuse.secrets, 0);
        assert_eq!(reuse.trust_stores, 1);
        assert_ne!(same.config_version, rotated.config_version);
        assert_eq!(
            same.summary().config_version,
            rotated.summary().config_version,
            "inspection identity must not expose or vary with Secret contents"
        );
        assert!(rotated.resources.secrets[&secret_id].constant_time_eq(b"next-secret!"));
        assert!(!Arc::ptr_eq(
            &same.resources.secrets[&secret_id],
            &rotated.resources.secrets[&secret_id]
        ));
    }

    #[test]
    fn independent_secret_preparation_separates_public_and_activation_versions() {
        let directory = tempdir().expect("temporary directory is available");
        let config = write_secret_trust_gateway(directory.path());
        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first source compiles"),
        )
        .expect("first snapshot prepares");
        let independent = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("second source compiles"),
        )
        .expect("independent snapshot prepares");

        assert_ne!(first.config_version, independent.config_version);
        assert_eq!(
            first.summary().config_version,
            independent.summary().config_version,
            "deterministic inspection identity excludes opaque activation tokens"
        );
        let secret_id = ResourceId::new("secret:token");
        assert_eq!(
            first.resources.secrets[&secret_id].fingerprint(),
            independent.resources.secrets[&secret_id].fingerprint()
        );
        assert_ne!(
            first.resources.secrets[&secret_id].version_token(),
            independent.resources.secrets[&secret_id].version_token()
        );
    }

    #[test]
    fn failed_trust_rotation_retains_candidate_dependencies_and_old_resources() {
        let directory = tempdir().expect("temporary directory is available");
        let config = write_secret_trust_gateway(directory.path());
        let first = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("first source compiles"),
        )
        .expect("first snapshot prepares");
        let GeneratedCertificate { signing_key, .. } =
            generate_simple_self_signed(vec!["not-a-ca.example.test".to_owned()])
                .expect("test-only key can be generated");
        fs::write(directory.path().join("ca.pem"), signing_key.serialize_pem())
            .expect("invalid CA candidate can be written");

        let error = RuntimeSnapshot::prepare_reusing(
            Compiler::compile_path(&config).expect("candidate source compiles"),
            Some(&first),
        )
        .expect_err("non-certificate trust material must fail");
        assert_eq!(error.diagnostics()[0].code, "trust_store.pem_item");
        assert!(
            error.candidate_dependencies.contains(
                &directory
                    .path()
                    .join("ca.pem")
                    .canonicalize()
                    .expect("candidate CA path canonicalizes")
            )
        );
        assert!(
            first.resources.secrets[&ResourceId::new("secret:token")]
                .constant_time_eq(b"first-secret")
        );
    }

    #[test]
    fn snapshot_debug_and_summary_hide_secret_and_private_key_paths() {
        let directory = tempdir().expect("temporary directory is available");
        let config = write_secret_trust_gateway(directory.path());
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("source compiles"))
                .expect("snapshot prepares");
        let secret_path = directory
            .path()
            .join("token.txt")
            .canonicalize()
            .expect("secret path canonicalizes");

        let debug = format!("{snapshot:?}");
        assert!(!debug.contains("first-secret"));
        assert!(!debug.contains("token.txt"));
        assert!(snapshot.dependencies.contains(&secret_path));
        assert!(
            snapshot
                .summary()
                .dependencies
                .iter()
                .all(|dependency| !dependency.contains("token.txt"))
        );

        write_test_identity(directory.path(), &["default.example.test"]);
        let tls_config = write_tls_gateway(directory.path());
        let tls_snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&tls_config).expect("TLS source compiles"),
        )
        .expect("TLS snapshot prepares");
        let private_key_path = directory
            .path()
            .join("key.pem")
            .canonicalize()
            .expect("private key path canonicalizes");
        assert!(tls_snapshot.dependencies.contains(&private_key_path));
        assert!(
            tls_snapshot
                .summary()
                .dependencies
                .iter()
                .all(|dependency| !dependency.contains("key.pem"))
        );
        assert!(!format!("{tls_snapshot:?}").contains("key.pem"));

        fs::write(directory.path().join("key.pem"), "not private-key PEM")
            .expect("invalid private key can be written");
        let error = RuntimeSnapshot::prepare(
            Compiler::compile_path(&tls_config).expect("invalid-key source still compiles"),
        )
        .expect_err("invalid private-key material must fail preparation");
        let diagnostics_rendered = error
            .diagnostics()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        let error_debug = format!("{error:?}");
        for sensitive in ["not private-key PEM", "key.pem"] {
            assert!(!diagnostics_rendered.contains(sensitive));
            assert!(!error_debug.contains(sensitive));
        }
        assert!(error.candidate_dependencies.contains(&private_key_path));
    }
}
