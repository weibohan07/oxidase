use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use oxidase_config::{
    ClusterSpec, CompiledGateway, CompiledListener, ConfigTestSource, GatewaySummary,
};
use oxidase_core::{ConfigVersion, ResourceId, ServiceId, ServiceNode, ServiceProgram};
use oxidase_site::{SiteCompiler, SiteSnapshot};

#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry {
    pub clusters: BTreeMap<ResourceId, ClusterSpec>,
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
}

impl RuntimeSnapshot {
    pub fn prepare(gateway: CompiledGateway) -> Result<Self, PreparationError> {
        let summary = gateway.summary();
        let mut sites = BTreeMap::new();
        let mut dependencies = gateway.dependencies.clone();
        for (id, source) in &gateway.resources.sites {
            let snapshot = SiteCompiler::compile(
                id.clone(),
                &source.root,
                &source.manifest,
                source.inputs.clone(),
            )
            .map_err(|error| PreparationError {
                resource: id.clone(),
                message: error.to_string(),
            })?;
            dependencies.extend(snapshot.dependencies.iter().cloned());
            sites.insert(id.clone(), Arc::new(snapshot));
        }
        dependencies.sort();
        dependencies.dedup();
        Ok(Self {
            config_version: gateway.config_version,
            dependencies,
            nodes: gateway.nodes,
            resources: ResourceRegistry {
                clusters: gateway.resources.clusters,
                sites,
            },
            listeners: gateway.listeners,
            tests: gateway.tests,
            summary,
        })
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

#[derive(Debug, Clone)]
pub struct PreparationError {
    pub resource: ResourceId,
    pub message: String,
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
