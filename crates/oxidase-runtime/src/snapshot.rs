use std::collections::BTreeMap;
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
use oxidase_site::{SiteCompileError, SiteCompileFailure, SiteCompiler, SiteSnapshot};

use crate::cluster::PreparedCluster;
use crate::tls::{
    CertificatePreparationErrorKind, CertificatePreparationFailure, PreparedCertificate,
    PreparedListenerPlan, TlsListenerPreparationErrorKind, TlsListenerPreparationFailure,
};

#[derive(Debug, Clone, Default)]
pub struct ResourceRegistry {
    pub certificates: BTreeMap<ResourceId, Arc<PreparedCertificate>>,
    pub clusters: BTreeMap<ResourceId, Arc<PreparedCluster>>,
    pub sites: BTreeMap<ResourceId, Arc<SiteSnapshot>>,
}

#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    pub config_version: ConfigVersion,
    pub dependencies: Vec<std::path::PathBuf>,
    pub graph: Arc<ServiceGraph>,
    pub resources: ResourceRegistry,
    pub listeners: Vec<CompiledListener>,
    pub prepared_listeners: Vec<PreparedListenerPlan>,
    pub tests: Vec<ConfigTestSource>,
    summary: GatewaySummary,
    certificate_fingerprints: BTreeMap<ResourceId, ContentDigest>,
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
            let index = SiteCompiler::scan(&source.root, &source.manifest).map_err(|failure| {
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
        let mut certificates = BTreeMap::new();
        let mut certificate_fingerprints = BTreeMap::new();
        for (id, source) in &gateway.resources.certificates {
            // Even when the public chain digest is unchanged, parse and validate
            // the candidate private key before deciding to reuse the old opaque
            // signing state. An invalid key-only rotation must never commit.
            let candidate = PreparedCertificate::prepare(source).map_err(|failure| {
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
            for path in [&source.cert_chain, &source.private_key] {
                if let Ok(canonical) = path.canonicalize() {
                    dependencies.push(canonical);
                }
            }
            certificate_fingerprints.insert(id.clone(), fingerprint);
            certificates.insert(id.clone(), certificate);
        }
        let mut clusters = BTreeMap::new();
        let mut cluster_fingerprints = BTreeMap::new();
        for (id, source) in gateway.resources.clusters {
            let fingerprint = cluster_fingerprint(&source);
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
                let (cluster, reused_endpoints) =
                    PreparedCluster::prepare(source, previous_cluster.map(Arc::as_ref));
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
                PreparedListenerPlan::prepare(listener, &certificates).map_err(|failure| {
                    preparation_error_from_tls_listener(listener, &dependencies, failure)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        normalize_dependencies(&mut dependencies);
        let mut version_hash = ContentDigestBuilder::new("oxidase/runtime-snapshot/v1");
        version_hash.field_bytes("gateway", gateway.config_version.as_str().as_bytes());
        for (id, fingerprint) in &certificate_fingerprints {
            version_hash
                .field_bytes("certificate_id", id.as_str().as_bytes())
                .field_digest("certificate_digest", *fingerprint);
        }
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
                resources: ResourceRegistry {
                    certificates,
                    clusters,
                    sites,
                },
                listeners: gateway.listeners,
                prepared_listeners,
                tests: gateway.tests,
                summary,
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
    pub certificates: usize,
    pub sites: usize,
    pub clusters: usize,
    /// Endpoint runtime states reused even when the immutable Cluster policy changed.
    pub cluster_endpoints: usize,
}

#[derive(Debug)]
pub struct PreparationError {
    pub resource: ResourceId,
    pub kind: PreparationErrorKind,
    diagnostics: Vec<Diagnostic>,
    pub candidate_dependencies: Vec<std::path::PathBuf>,
}

#[derive(Debug)]
pub enum PreparationErrorKind {
    Certificate(CertificatePreparationErrorKind),
    Fingerprint(String),
    Site(Box<SiteCompileError>),
    TlsListener(TlsListenerPreparationErrorKind),
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
            Self::Certificate(error) => error.fmt(formatter),
            Self::Fingerprint(message) => formatter.write_str(message),
            Self::Site(error) => error.fmt(formatter),
            Self::TlsListener(error) => error.fmt(formatter),
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

    use super::{RuntimeSnapshot, cluster_fingerprint};

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
}
