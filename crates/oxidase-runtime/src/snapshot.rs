use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::sync::Arc;

use arc_swap::ArcSwap;
use oxidase_config::{
    ClusterSpec, CompiledGateway, CompiledListener, ConfigTestSource, GatewaySummary,
};
use oxidase_core::{
    ConfigVersion, ContentDigest, ContentDigestBuilder, ContentHasher, ResourceId, ServiceGraph,
    ServiceProgram,
};
use oxidase_site::{SiteCompileError, SiteCompileFailure, SiteCompiler, SiteSnapshot};

#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry {
    pub clusters: BTreeMap<ResourceId, Arc<ClusterSpec>>,
    pub sites: BTreeMap<ResourceId, Arc<SiteSnapshot>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    pub config_version: ConfigVersion,
    pub dependencies: Vec<std::path::PathBuf>,
    pub graph: Arc<ServiceGraph>,
    pub resources: ResourceRegistry,
    pub listeners: Vec<CompiledListener>,
    pub tests: Vec<ConfigTestSource>,
    summary: GatewaySummary,
    site_fingerprints: BTreeMap<ResourceId, ContentDigest>,
    cluster_fingerprints: BTreeMap<ResourceId, ContentDigest>,
}

impl RuntimeSnapshot {
    pub fn prepare(gateway: CompiledGateway) -> Result<Self, PreparationError> {
        Self::prepare_reusing(gateway, None).map(|(snapshot, _)| snapshot)
    }

    pub fn prepare_reusing(
        gateway: CompiledGateway,
        previous: Option<&Self>,
    ) -> Result<(Self, ResourceReuse), PreparationError> {
        let mut summary = gateway.summary();
        let mut sites = BTreeMap::new();
        let mut site_fingerprints = BTreeMap::new();
        let mut reuse = ResourceReuse::default();
        let mut dependencies = gateway.dependencies.clone();
        for (id, source) in &gateway.resources.sites {
            let fingerprint = match site_fingerprint(source) {
                Ok(fingerprint) => fingerprint,
                Err(message) => {
                    let mut candidate_dependencies = dependencies.clone();
                    candidate_dependencies.extend(discover_site_dependencies(source));
                    normalize_dependencies(&mut candidate_dependencies);
                    return Err(PreparationError {
                        resource: id.clone(),
                        kind: PreparationErrorKind::Fingerprint(message),
                        candidate_dependencies,
                    });
                }
            };
            let snapshot = previous
                .filter(|previous| previous.site_fingerprints.get(id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.sites.get(id).cloned());
            let snapshot = if let Some(snapshot) = snapshot {
                reuse.sites += 1;
                snapshot
            } else {
                let compiled = SiteCompiler::compile(
                    id.clone(),
                    &source.root,
                    &source.manifest,
                    source.inputs.clone(),
                )
                .map_err(|failure| preparation_error_from_site(id, &dependencies, failure))?;
                Arc::new(compiled)
            };
            dependencies.extend(snapshot.dependencies.iter().cloned());
            dependencies.extend(site_directories(&snapshot));
            site_fingerprints.insert(id.clone(), fingerprint);
            sites.insert(id.clone(), snapshot);
        }
        let mut clusters = BTreeMap::new();
        let mut cluster_fingerprints = BTreeMap::new();
        for (id, source) in gateway.resources.clusters {
            let fingerprint = cluster_fingerprint(&source);
            let cluster = previous
                .filter(|previous| previous.cluster_fingerprints.get(&id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.clusters.get(&id).cloned());
            let cluster = if let Some(cluster) = cluster {
                reuse.clusters += 1;
                cluster
            } else {
                Arc::new(source)
            };
            cluster_fingerprints.insert(id.clone(), fingerprint);
            clusters.insert(id, cluster);
        }
        normalize_dependencies(&mut dependencies);
        let mut version_hash = ContentDigestBuilder::new("oxidase/runtime-snapshot/v1");
        version_hash.field_bytes("gateway", gateway.config_version.as_str().as_bytes());
        for (id, fingerprint) in &site_fingerprints {
            version_hash
                .field_bytes("site_id", id.as_str().as_bytes())
                .field_digest("site_digest", *fingerprint);
        }
        for (id, fingerprint) in &cluster_fingerprints {
            version_hash
                .field_bytes("cluster_id", id.as_str().as_bytes())
                .field_digest("cluster_digest", *fingerprint);
        }
        let config_version = ConfigVersion::new(format!("v2-sha256-{}", version_hash.finish()));
        summary.config_version = config_version.to_string();
        summary.dependencies = dependencies
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        Ok((
            Self {
                config_version,
                dependencies,
                graph: gateway.graph,
                resources: ResourceRegistry { clusters, sites },
                listeners: gateway.listeners,
                tests: gateway.tests,
                summary,
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

    #[must_use]
    pub fn program_for(&self, listener: &str) -> Option<ServiceProgram> {
        self.listeners
            .iter()
            .find(|candidate| candidate.id.as_str() == listener || candidate.name == listener)
            .map(|listener| ServiceProgram::new(listener.service.clone(), Arc::clone(&self.graph)))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceReuse {
    pub sites: usize,
    pub clusters: usize,
}

#[derive(Debug)]
pub struct PreparationError {
    pub resource: ResourceId,
    pub kind: PreparationErrorKind,
    pub candidate_dependencies: Vec<std::path::PathBuf>,
}

#[derive(Debug)]
pub enum PreparationErrorKind {
    Fingerprint(String),
    Site(SiteCompileError),
}

fn preparation_error_from_site(
    resource: &ResourceId,
    existing_dependencies: &[std::path::PathBuf],
    failure: SiteCompileFailure,
) -> PreparationError {
    let mut candidate_dependencies = existing_dependencies.to_vec();
    candidate_dependencies.extend(failure.discovered_dependencies);
    normalize_dependencies(&mut candidate_dependencies);
    PreparationError {
        resource: resource.clone(),
        kind: PreparationErrorKind::Site(failure.error),
        candidate_dependencies,
    }
}

fn normalize_dependencies(dependencies: &mut Vec<std::path::PathBuf>) {
    dependencies.sort();
    dependencies.dedup();
}

fn discover_site_dependencies(source: &oxidase_config::SiteSpec) -> Vec<std::path::PathBuf> {
    let mut dependencies = vec![source.root.clone(), source.manifest.clone()];
    for path in [&source.root, &source.manifest] {
        if let Some(parent) = path.parent() {
            dependencies.push(parent.to_path_buf());
        }
    }
    for entry in walkdir::WalkDir::new(&source.root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        dependencies.push(entry.path().to_path_buf());
    }
    normalize_dependencies(&mut dependencies);
    dependencies
}

fn site_fingerprint(source: &oxidase_config::SiteSpec) -> Result<ContentDigest, String> {
    let mut hash = ContentDigestBuilder::new("oxidase/site-source/v1");
    hash.field_bytes(
        "manifest",
        source
            .manifest
            .strip_prefix(&source.root)
            .unwrap_or(&source.manifest)
            .to_string_lossy()
            .replace('\\', "/")
            .as_bytes(),
    );
    hash.field_bytes(
        "inputs",
        serde_json::to_vec(&source.inputs)
            .map_err(|error| format!("cannot fingerprint site inputs: {error}"))?,
    );
    let mut entries = walkdir::WalkDir::new(&source.root)
        .follow_links(false)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot scan site for reuse: {error}"))?;
    entries.sort_by(|left, right| left.path().cmp(right.path()));
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(&source.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        hash.field_bytes("path", relative.as_bytes());
        if entry.file_type().is_file() {
            hash.field_bytes("kind", b"file");
            let mut file = fs::File::open(path)
                .map_err(|error| format!("cannot fingerprint `{}`: {error}", path.display()))?;
            let mut buffer = [0u8; 16 * 1024];
            let mut content = ContentHasher::new();
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| format!("cannot fingerprint `{}`: {error}", path.display()))?;
                if read == 0 {
                    break;
                }
                content.update(&buffer[..read]);
            }
            hash.field_digest("content", content.finish());
        } else if entry.file_type().is_symlink() {
            hash.field_bytes("kind", b"symlink");
            let target = fs::read_link(path).map_err(|error| {
                format!("cannot fingerprint symlink `{}`: {error}", path.display())
            })?;
            hash.field_bytes("target", target.to_string_lossy().as_bytes());
        } else if entry.file_type().is_dir() {
            hash.field_bytes("kind", b"directory");
        } else {
            hash.field_bytes("kind", b"other");
        }
    }
    Ok(hash.finish())
}

fn cluster_fingerprint(source: &ClusterSpec) -> ContentDigest {
    let mut hash = ContentDigestBuilder::new("oxidase/cluster/v1");
    hash.field_u64("endpoint_count", source.endpoints.len() as u64);
    for endpoint in &source.endpoints {
        hash.field_bytes("endpoint", endpoint.as_str().as_bytes());
    }
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
            Self::Fingerprint(message) => formatter.write_str(message),
            Self::Site(error) => error.fmt(formatter),
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

    use oxidase_config::{ClusterSpec, Compiler};
    use oxidase_core::{ResourceId, SourceSpan};
    use tempfile::tempdir;
    use url::Url;

    use super::{RuntimeSnapshot, cluster_fingerprint};

    #[test]
    fn cluster_digest_is_stable_and_preserves_endpoint_preference_order() {
        let cluster = |endpoints: &[&str]| ClusterSpec {
            id: ResourceId::new("cluster:api"),
            endpoints: endpoints
                .iter()
                .map(|endpoint| Url::parse(endpoint).expect("fixture endpoint is valid"))
                .collect(),
            connect_timeout: Duration::from_secs(1),
            response_timeout: Duration::from_secs(2),
            source: SourceSpan::synthetic("clusters.api"),
        };
        let first = cluster(&["http://127.0.0.1:3000", "https://example.test/"]);
        let same = cluster(&["http://127.0.0.1:3000", "https://example.test/"]);
        let reordered = cluster(&["https://example.test/", "http://127.0.0.1:3000"]);
        assert_eq!(cluster_fingerprint(&first), cluster_fingerprint(&same));
        assert_ne!(cluster_fingerprint(&first), cluster_fingerprint(&reordered));
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
        assert!(!Arc::ptr_eq(
            &second.resources.sites[&site_id],
            &third.resources.sites[&site_id]
        ));
    }
}
