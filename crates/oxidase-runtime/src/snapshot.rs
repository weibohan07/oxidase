use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Read;
use std::sync::Arc;

use arc_swap::ArcSwap;
use oxidase_config::{
    ClusterSpec, CompiledGateway, CompiledListener, ConfigTestSource, GatewaySummary,
};
use oxidase_core::{ConfigVersion, ResourceId, ServiceId, ServiceNode, ServiceProgram};
use oxidase_site::{SiteCompiler, SiteSnapshot};

#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry {
    pub clusters: BTreeMap<ResourceId, Arc<ClusterSpec>>,
    pub sites: BTreeMap<ResourceId, Arc<SiteSnapshot>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    pub config_version: ConfigVersion,
    pub dependencies: Vec<std::path::PathBuf>,
    pub nodes: BTreeMap<ServiceId, ServiceNode>,
    pub resources: ResourceRegistry,
    pub listeners: Vec<CompiledListener>,
    pub tests: Vec<ConfigTestSource>,
    summary: GatewaySummary,
    site_fingerprints: BTreeMap<ResourceId, u64>,
    cluster_fingerprints: BTreeMap<ResourceId, u64>,
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
            let fingerprint = site_fingerprint(source).map_err(|message| PreparationError {
                resource: id.clone(),
                message,
            })?;
            let snapshot = previous
                .filter(|previous| previous.site_fingerprints.get(id) == Some(&fingerprint))
                .and_then(|previous| previous.resources.sites.get(id).cloned());
            let snapshot = if let Some(snapshot) = snapshot {
                reuse.sites += 1;
                snapshot
            } else {
                Arc::new(
                    SiteCompiler::compile(
                        id.clone(),
                        &source.root,
                        &source.manifest,
                        source.inputs.clone(),
                    )
                    .map_err(|error| PreparationError {
                        resource: id.clone(),
                        message: error.to_string(),
                    })?,
                )
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
        dependencies.sort();
        dependencies.dedup();
        let mut version_hash = Fnv::new();
        version_hash.update(gateway.config_version.as_str().as_bytes());
        for (id, fingerprint) in &site_fingerprints {
            version_hash.update(id.as_str().as_bytes());
            version_hash.update(&fingerprint.to_le_bytes());
        }
        for (id, fingerprint) in &cluster_fingerprints {
            version_hash.update(id.as_str().as_bytes());
            version_hash.update(&fingerprint.to_le_bytes());
        }
        let config_version = ConfigVersion::new(format!("v2-{:016x}", version_hash.finish()));
        summary.config_version = config_version.to_string();
        summary.dependencies = dependencies
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        Ok((
            Self {
                config_version,
                dependencies,
                nodes: gateway.nodes,
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
            .map(|listener| ServiceProgram {
                entry: listener.service.clone(),
                nodes: self.nodes.clone(),
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceReuse {
    pub sites: usize,
    pub clusters: usize,
}

#[derive(Debug, Clone)]
pub struct PreparationError {
    pub resource: ResourceId,
    pub message: String,
}

fn site_fingerprint(source: &oxidase_config::SiteSpec) -> Result<u64, String> {
    let mut hash = Fnv::new();
    hash.update(source.root.to_string_lossy().as_bytes());
    hash.update(source.manifest.to_string_lossy().as_bytes());
    hash.update(
        &serde_json::to_vec(&source.inputs)
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
        hash.update(path.to_string_lossy().as_bytes());
        if entry.file_type().is_file() {
            let mut file = fs::File::open(path)
                .map_err(|error| format!("cannot fingerprint `{}`: {error}", path.display()))?;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| format!("cannot fingerprint `{}`: {error}", path.display()))?;
                if read == 0 {
                    break;
                }
                hash.update(&buffer[..read]);
            }
        } else if entry.file_type().is_symlink() {
            let target = fs::read_link(path).map_err(|error| {
                format!("cannot fingerprint symlink `{}`: {error}", path.display())
            })?;
            hash.update(target.to_string_lossy().as_bytes());
        }
    }
    Ok(hash.finish())
}

fn cluster_fingerprint(source: &ClusterSpec) -> u64 {
    let mut hash = Fnv::new();
    for endpoint in &source.endpoints {
        hash.update(endpoint.as_str().as_bytes());
    }
    hash.update(&source.connect_timeout.as_nanos().to_le_bytes());
    hash.update(&source.response_timeout.as_nanos().to_le_bytes());
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

struct Fnv(u64);

impl Fnv {
    const fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    const fn finish(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to prepare resource `{}`: {}",
            self.resource, self.message
        )
    }
}

impl std::error::Error for PreparationError {}

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

    use oxidase_config::Compiler;
    use oxidase_core::ResourceId;
    use tempfile::tempdir;

    use super::RuntimeSnapshot;

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
