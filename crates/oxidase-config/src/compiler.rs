use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode, uri::PathAndQuery};
use oxidase_core::{
    CompiledMetadata, CompiledPattern, CompiledTemplate, ConfigVersion, ContentDigest,
    ContentDigestBuilder, DiagnosticReference, ErrorClass, Expression, HeaderPredicate,
    HeaderTransform, HeaderTransforms, ListenerId, PatternContext, PredicatePlan, RateLimitKey,
    RecoverHandler, RequestMetadataError, RequestTransform, ResourceId, RespondBody,
    ResponseTransform, RouteCase, RouteId, ServiceGraph, ServiceId, ServiceKind, ServiceNode,
    ServiceProgram, SourceSpan, Value, is_forbidden_user_header, parse_transform_authority,
    parse_transform_path_and_query, parse_transform_scheme,
};
use serde::Serialize;
use url::Url;

use oxidase_source::{FieldSpanIndex, SourceDocument, field_path_child};

use crate::API_VERSION;
use crate::diagnostic::{CompileError, Diagnostic};
use crate::source::{
    ActiveHealthSource, BodySource, BundleSource, CertificateSource, ClientAuthSource,
    ClusterEndpointSource, ClusterSource, ClusterTlsSource, ConfigTestSource, ErrorClassSource,
    GatewaySource, HeadersSource, Http1SettingsSource, Http2SettingsSource, HttpListenerSource,
    HttpVersionSource, InlineServiceSource, ListenerLimitsSource, ListenerProtocolSource,
    ListenerSource, PassiveHealthSource, PredicateSource, RateLimitKeySource, RedirectQuerySource,
    RequestTransformSource, ResourcesSource, ResponseTransformSource, RetryRequestBodySource,
    RetrySource, SecretSource, ServiceSource, SiteSource, StatusRangeSource, TlsListenerSource,
    TrustStoreSource,
};

#[derive(Clone)]
pub struct CompiledGateway {
    pub source: PathBuf,
    pub config_version: ConfigVersion,
    /// Packaging policy consumed by `oxidase bundle build`.
    pub bundle: BundleSpec,
    /// Complete filesystem dependency set used by preparation and reload.
    pub dependencies: Vec<PathBuf>,
    /// Inspection-safe dependency set with secret and private-key paths removed.
    pub summary_dependencies: Vec<PathBuf>,
    pub graph: Arc<ServiceGraph>,
    pub resources: CompiledResources,
    pub listeners: Vec<CompiledListener>,
    pub tests: Vec<ConfigTestSource>,
    /// Non-fatal structured diagnostics produced while compiling this source.
    pub warnings: Vec<Diagnostic>,
}

impl fmt::Debug for CompiledGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledGateway")
            .field("source", &self.source)
            .field("config_version", &self.config_version)
            .field("bundle_asset_mode", &self.bundle.assets.mode)
            .field("dependency_count", &self.dependencies.len())
            .field("service_node_count", &self.graph.len())
            .field("certificate_count", &self.resources.certificates.len())
            .field("secret_count", &self.resources.secrets.len())
            .field("trust_store_count", &self.resources.trust_stores.len())
            .field("cluster_count", &self.resources.clusters.len())
            .field("site_count", &self.resources.sites.len())
            .field("listener_count", &self.listeners.len())
            .field("test_count", &self.tests.len())
            .field("warning_count", &self.warnings.len())
            .finish_non_exhaustive()
    }
}

impl CompiledGateway {
    #[must_use]
    pub fn program_for(&self, listener: &str) -> Option<ServiceProgram> {
        self.listeners
            .iter()
            .find(|candidate| candidate.id.as_str() == listener || candidate.name == listener)
            .map(|listener| ServiceProgram::new(listener.service.clone(), Arc::clone(&self.graph)))
    }

    #[must_use]
    pub fn summary(&self) -> GatewaySummary {
        GatewaySummary {
            config_version: self.config_version.to_string(),
            source: self.source.display().to_string(),
            bundle: BundleSummary {
                assets: BundleAssetsSummary {
                    mode: self.bundle.assets.mode,
                },
            },
            dependencies: self
                .summary_dependencies
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            listeners: self
                .listeners
                .iter()
                .map(|listener| ListenerSummary {
                    name: listener.name.clone(),
                    bind: listener.bind.to_string(),
                    protocol: listener.protocol,
                    service: listener.service.to_string(),
                })
                .collect(),
            services: self.graph.keys().map(ToString::to_string).collect(),
            clusters: self
                .resources
                .clusters
                .values()
                .map(|cluster| ClusterSummary {
                    id: cluster.id.to_string(),
                    protocol: cluster.protocol,
                    load_balance: cluster.load_balance,
                    endpoint_count: cluster.endpoints.len(),
                    active_health: cluster.health.active.is_some(),
                    passive_health: cluster.health.passive.is_some(),
                    retry_max_attempts: cluster.retry.max_attempts,
                })
                .collect(),
            certificates: self
                .resources
                .certificates
                .keys()
                .map(ToString::to_string)
                .collect(),
            sites: self
                .resources
                .sites
                .keys()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

/// Source-controlled policy for constructing a portable Oxidase Bundle.
#[derive(Debug, Clone)]
pub struct BundleSpec {
    pub assets: BundleAssetsSpec,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct BundleAssetsSpec {
    pub mode: BundleAssetMode,
    pub mode_source: SourceSpan,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleAssetMode {
    #[default]
    Embed,
    Reference,
}

#[derive(Debug, Clone, Default)]
pub struct CompiledResources {
    pub certificates: BTreeMap<ResourceId, CertificateSpec>,
    pub secrets: BTreeMap<ResourceId, SecretSpec>,
    pub trust_stores: BTreeMap<ResourceId, TrustStoreSpec>,
    pub clusters: BTreeMap<ResourceId, ClusterSpec>,
    pub sites: BTreeMap<ResourceId, SiteSpec>,
}

/// Paths and source locations for one inbound TLS certificate resource.
///
/// Certificate and private-key bytes are deliberately not part of the
/// compiled configuration. The server preparation boundary reads and validates
/// them without making secret material inspectable through this IR.
#[derive(Clone)]
pub struct CertificateSpec {
    pub id: ResourceId,
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
    pub cert_chain_source: SourceSpan,
    pub private_key_source: SourceSpan,
    pub source: SourceSpan,
}

impl fmt::Debug for CertificateSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateSpec")
            .field("id", &self.id)
            .field("cert_chain", &self.cert_chain)
            .field("private_key", &"<redacted path>")
            .field("cert_chain_source", &self.cert_chain_source)
            .field("private_key_source", &self.private_key_source)
            .field("source", &self.source)
            .finish()
    }
}

/// A file-backed secret reference. Secret bytes are deliberately absent from
/// compiler IR and from every serializable inspection structure.
#[derive(Clone)]
pub struct SecretSpec {
    pub id: ResourceId,
    pub file: PathBuf,
    pub max_bytes: u64,
    pub file_source: SourceSpan,
    pub max_bytes_source: SourceSpan,
    pub source: SourceSpan,
}

impl fmt::Debug for SecretSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretSpec")
            .field("id", &self.id)
            .field("file", &"<redacted path>")
            .field("max_bytes", &self.max_bytes)
            .field("file_source", &self.file_source)
            .field("max_bytes_source", &self.max_bytes_source)
            .field("source", &self.source)
            .finish()
    }
}

/// One strict PEM trust-anchor bundle prepared at runtime.
#[derive(Debug, Clone)]
pub struct TrustStoreSpec {
    pub id: ResourceId,
    pub ca_bundle: PathBuf,
    pub ca_bundle_source: SourceSpan,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ClusterSpec {
    pub id: ResourceId,
    pub protocol: ClusterProtocol,
    pub endpoints: Vec<ClusterEndpointSpec>,
    pub load_balance: LoadBalancePolicy,
    pub health: ClusterHealthSpec,
    pub retry: RetrySpec,
    pub limits: ClusterLimits,
    pub tls: Option<ClusterTlsSpec>,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub protocol_source: SourceSpan,
    pub source: SourceSpan,
}

/// Rustls-free upstream TLS policy compiled for one Cluster.
#[derive(Debug, Clone)]
pub struct ClusterTlsSpec {
    pub server_name: Option<String>,
    pub trust: ClusterTlsTrustSpec,
    pub client_certificate: Option<ResourceId>,
    pub server_name_source: Option<SourceSpan>,
    pub client_certificate_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ClusterTlsTrustSpec {
    pub system_roots: bool,
    pub trust_store: Option<ResourceId>,
    pub system_roots_source: SourceSpan,
    pub trust_store_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ClusterEndpointSpec {
    pub name: String,
    pub url: Url,
    pub weight: u16,
    pub name_source: SourceSpan,
    pub url_source: SourceSpan,
    pub weight_source: SourceSpan,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancePolicy {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastRequests,
}

impl LoadBalancePolicy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::WeightedRoundRobin => "weighted_round_robin",
            Self::LeastRequests => "least_requests",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClusterHealthSpec {
    pub active: Option<ActiveHealthSpec>,
    pub passive: Option<PassiveHealthSpec>,
}

#[derive(Debug, Clone)]
pub struct ActiveHealthSpec {
    pub path: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub healthy_statuses: Vec<StatusRange>,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct PassiveHealthSpec {
    pub consecutive_failures: u32,
    pub eject_for: Duration,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StatusRange {
    pub start: u16,
    pub end: u16,
}

impl StatusRange {
    #[must_use]
    pub const fn contains(self, status: u16) -> bool {
        self.start <= status && status <= self.end
    }
}

#[derive(Debug, Clone)]
pub struct RetrySpec {
    pub max_attempts: u32,
    pub methods: Vec<Method>,
    pub retry_on: Vec<RetryCause>,
    pub statuses: Vec<StatusRange>,
    pub request_body: RetryRequestBodySpec,
    pub max_concurrent_retries: u32,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryCause {
    ConnectFailure,
    ResponseHeaderTimeout,
    RefusedStream,
    Reset,
}

impl RetryCause {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectFailure => "connect_failure",
            Self::ResponseHeaderTimeout => "response_header_timeout",
            Self::RefusedStream => "refused_stream",
            Self::Reset => "reset",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryRequestBodySpec {
    pub mode: RetryBodyMode,
    pub max_bytes: u64,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryBodyMode {
    #[default]
    None,
    Buffer,
}

#[derive(Debug, Clone)]
pub struct ClusterLimits {
    pub max_in_flight: u32,
    pub max_in_flight_per_endpoint: u32,
    pub queue_timeout: Duration,
    pub source: SourceSpan,
}

/// The transport protocol policy for an upstream Cluster.
///
/// This is compiler IR rather than a data-plane client type. `Auto` permits
/// HTTPS ALPN negotiation and otherwise uses HTTP/1.1; `Http1` and `H2` force
/// the corresponding upstream policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterProtocol {
    #[default]
    Auto,
    Http1,
    H2,
}

impl ClusterProtocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Http1 => "http1",
            Self::H2 => "h2",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SiteSpec {
    pub id: ResourceId,
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub inputs: BTreeMap<String, Value>,
    pub input_spans: BTreeMap<String, SourceSpan>,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct CompiledListener {
    pub id: ListenerId,
    pub name: String,
    pub bind: SocketAddr,
    pub protocol: ListenerProtocol,
    pub tls: Option<TlsListenerSpec>,
    pub http: HttpListenerSpec,
    pub limits: ListenerLimits,
    pub service: ServiceId,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ListenerLimits {
    pub max_connections: u32,
    pub max_connections_per_ip: u32,
    pub idle_timeout: Duration,
    pub request_body_idle_timeout: Duration,
    pub response_body_idle_timeout: Duration,
    pub max_header_bytes: u32,
    pub max_headers: u32,
    pub max_requests_per_connection: u32,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerProtocol {
    Http,
    Https,
}

#[derive(Debug, Clone)]
pub struct TlsListenerSpec {
    pub default_certificate: ResourceId,
    pub default_certificate_source: SourceSpan,
    pub sni: Vec<SniCertificateSpec>,
    pub handshake_timeout: Duration,
    pub client_auth: ClientAuthSpec,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ClientAuthSpec {
    pub mode: ClientAuthMode,
    pub trust_store: Option<ResourceId>,
    pub mode_source: SourceSpan,
    pub trust_store_source: Option<SourceSpan>,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
    #[default]
    None,
    Optional,
    Required,
}

impl TlsListenerSpec {
    /// Resolves an already-validated server name using exact-before-wildcard
    /// precedence and falls back to the configured default certificate.
    #[must_use]
    pub fn select_certificate(&self, server_name: Option<&str>) -> &ResourceId {
        let Some(server_name) = server_name else {
            return &self.default_certificate;
        };
        if let Some(rule) = self.sni.iter().find(|rule| {
            matches!(rule.pattern, SniPattern::Exact(_)) && rule.pattern.matches(server_name)
        }) {
            return &rule.certificate;
        }
        self.sni
            .iter()
            .filter(|rule| {
                matches!(rule.pattern, SniPattern::Wildcard(_)) && rule.pattern.matches(server_name)
            })
            .max_by_key(|rule| match &rule.pattern {
                SniPattern::Wildcard(suffix) => suffix.len(),
                SniPattern::Exact(_) => 0,
            })
            .map_or(&self.default_certificate, |rule| &rule.certificate)
    }
}

#[derive(Debug, Clone)]
pub struct SniCertificateSpec {
    pub pattern: SniPattern,
    pub certificate: ResourceId,
    /// Span of the configured SNI mapping key.
    pub source: SourceSpan,
    /// Span of the certificate-resource reference value.
    pub certificate_source: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SniPattern {
    Exact(String),
    /// A single-label wildcard suffix, stored without the leading `*.`.
    Wildcard(String),
}

impl SniPattern {
    #[must_use]
    pub fn matches(&self, server_name: &str) -> bool {
        let server_name = server_name.to_ascii_lowercase();
        match self {
            Self::Exact(expected) => server_name == *expected,
            Self::Wildcard(suffix) => server_name
                .strip_suffix(suffix)
                .and_then(|prefix| prefix.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        }
    }

    #[must_use]
    pub fn normalized_rule(&self) -> String {
        match self {
            Self::Exact(name) => name.clone(),
            Self::Wildcard(suffix) => format!("*.{suffix}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpListenerSpec {
    pub versions: Vec<HttpVersion>,
    pub http1: Option<Http1Settings>,
    pub http2: Option<Http2Settings>,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpVersion {
    Http1,
    H2,
}

#[derive(Debug, Clone)]
pub struct Http1Settings {
    pub header_read_timeout: Duration,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct Http2Settings {
    pub max_concurrent_streams: u32,
    pub max_header_list_size: u32,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewaySummary {
    pub config_version: String,
    pub source: String,
    pub bundle: BundleSummary,
    pub dependencies: Vec<String>,
    pub listeners: Vec<ListenerSummary>,
    pub services: Vec<String>,
    pub certificates: Vec<String>,
    pub clusters: Vec<ClusterSummary>,
    pub sites: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleSummary {
    pub assets: BundleAssetsSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleAssetsSummary {
    pub mode: BundleAssetMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterSummary {
    pub id: String,
    pub protocol: ClusterProtocol,
    pub load_balance: LoadBalancePolicy,
    pub endpoint_count: usize,
    pub active_health: bool,
    pub passive_health: bool,
    pub retry_max_attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListenerSummary {
    pub name: String,
    pub bind: String,
    pub protocol: ListenerProtocol,
    pub service: String,
}

#[derive(Debug, Default)]
pub struct Compiler;

impl Compiler {
    pub fn compile_path(path: impl AsRef<Path>) -> Result<CompiledGateway, CompileError> {
        let requested = path.as_ref();
        let path = canonical_input(requested).map_err(|error| {
            error.with_discovered_dependencies(candidate_dependencies(requested))
        })?;
        let mut loader = Loader::default();
        if let Err(error) = loader.load(&path) {
            return Err(error.with_discovered_dependencies(loader.discovered_dependencies()));
        }
        let discovered_dependencies = loader.discovered_dependencies();
        let merged = loader.finish(path.clone());
        let mut discovered_dependencies = discovered_dependencies;
        discovered_dependencies.extend(merged.dependency_candidates.iter().cloned());
        discovered_dependencies.sort();
        discovered_dependencies.dedup();
        let result = (|| {
            validate_document_identity(&merged)?;
            let bundle = compile_bundle(&merged)?;
            let (resources, warnings) = compile_resources(&merged)?;
            let summary_dependencies = summary_dependencies(&merged);

            let mut builder = ProgramBuilder::new(&merged, &resources);
            let listeners = builder.compile_listeners()?;
            builder.compile_all_named()?;
            let graph = Arc::new(ServiceGraph::new(builder.nodes));
            for listener in &listeners {
                ServiceProgram::new(listener.service.clone(), Arc::clone(&graph))
                    .validate()
                    .map_err(|error| {
                        CompileError::one(Diagnostic::new(
                            "service.graph",
                            error.to_string(),
                            listener.source.clone(),
                        ))
                    })?;
            }

            Ok(CompiledGateway {
                source: path,
                config_version: ConfigVersion::new(format!("v2-sha256-{}", merged.hash)),
                bundle,
                dependencies: merged.dependencies,
                summary_dependencies,
                graph,
                resources,
                listeners,
                tests: merged
                    .tests
                    .into_iter()
                    .map(|located| located.value)
                    .collect(),
                warnings,
            })
        })();
        result.map_err(|error: CompileError| {
            error.with_discovered_dependencies(discovered_dependencies)
        })
    }

    pub fn parse_request_file(
        path: impl AsRef<Path>,
    ) -> Result<crate::ExplainRequestSource, CompileError> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(|error| {
            CompileError::one(Diagnostic::new(
                "request.read",
                format!("cannot read request file: {error}"),
                span(path, "request"),
            ))
        })?;
        parse_yaml(path, &source, "request")
    }
}

fn canonical_input(path: &Path) -> Result<PathBuf, CompileError> {
    path.canonicalize().map_err(|error| {
        CompileError::one(Diagnostic::new(
            "config.read",
            format!("cannot resolve configuration file: {error}"),
            span(path, ""),
        ))
    })
}

fn candidate_dependencies(path: &Path) -> Vec<PathBuf> {
    let mut dependencies = vec![path.to_path_buf()];
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        dependencies.push(parent.to_path_buf());
    }
    dependencies
}

#[derive(Debug, Clone)]
struct Located<T> {
    value: T,
    file: PathBuf,
    field_path: String,
    spans: Arc<FieldSpanIndex>,
}

impl<T> Located<T> {
    fn span(&self) -> SourceSpan {
        indexed_span(&self.file, &self.field_path, &self.spans)
    }

    fn span_at(&self, field_path: &str) -> SourceSpan {
        indexed_span(&self.file, field_path, &self.spans)
    }
}

/// Compiler-owned identity for one canonical source file.
///
/// The ordinal is assigned from the sorted canonical dependency set. This keeps
/// generated IDs deterministic without exposing an absolute checkout path in
/// diagnostics, explain output, or manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SourceFileId(usize);

#[derive(Debug, Clone, Copy)]
struct SourceNodeKey<'a> {
    file: SourceFileId,
    field_path: &'a str,
}

#[derive(Clone, Copy)]
struct SourceContext<'a> {
    file: &'a Path,
    spans: Option<&'a FieldSpanIndex>,
}

impl SourceContext<'_> {
    fn span(self, field_path: &str) -> SourceSpan {
        self.spans.map_or_else(
            || span(self.file, field_path),
            |spans| indexed_span(self.file, field_path, spans),
        )
    }

    fn key_span(self, field_path: &str) -> SourceSpan {
        self.spans.map_or_else(
            || span(self.file, field_path),
            |spans| indexed_key_span(self.file, field_path, spans),
        )
    }
}

impl SourceNodeKey<'_> {
    fn inline_service_id(self) -> ServiceId {
        ServiceId::new(format!("inline:s{:08}:{}", self.file.0, self.field_path))
    }

    fn route_id(self) -> RouteId {
        RouteId::new(format!("route:s{:08}:{}", self.file.0, self.field_path))
    }
}

#[derive(Default)]
struct Loader {
    loaded: BTreeSet<PathBuf>,
    stack: Vec<PathBuf>,
    import_chain: Vec<DiagnosticReference>,
    documents: Vec<SourceDocument<GatewaySource>>,
    dependencies: Vec<PathBuf>,
    discovered_dependencies: BTreeSet<PathBuf>,
    source_digests: BTreeMap<PathBuf, ContentDigest>,
}

impl Loader {
    fn load(&mut self, path: &Path) -> Result<(), CompileError> {
        self.discovered_dependencies
            .extend(candidate_dependencies(path));
        if let Some(position) = self.stack.iter().position(|candidate| candidate == path) {
            let chain = self.import_chain[position..].to_vec();
            let primary = chain
                .last()
                .and_then(|reference| reference.span.clone())
                .unwrap_or_else(|| span(path, "imports"));
            return Err(CompileError::one(
                Diagnostic::new(
                    "config.import_cycle",
                    "configuration import cycle detected",
                    primary,
                )
                .with_reference_chain(chain)
                .with_help("remove one import edge from the reported cycle"),
            ));
        }
        if self.loaded.contains(path) {
            return Ok(());
        }
        let source = fs::read_to_string(path).map_err(|error| {
            CompileError::one(Diagnostic::new(
                "config.read",
                format!("cannot read configuration: {error}"),
                span(path, ""),
            ))
        })?;
        let document: SourceDocument<GatewaySource> = parse_yaml_document(path, &source, "")?;

        self.stack.push(path.to_path_buf());
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        for (index, import) in document.value.imports.iter().enumerate() {
            let declared = directory.join(import);
            self.discovered_dependencies
                .extend(candidate_dependencies(&declared));
            let import_span = indexed_span(path, &format!("imports[{index}]"), &document.spans);
            let reference = DiagnosticReference::new(
                format!("`{}` imports `{}`", path.display(), declared.display()),
                import_span.clone(),
            );
            let import = declared.canonicalize().map_err(|error| {
                let mut chain = self.import_chain.clone();
                chain.push(reference.clone());
                CompileError::one(
                    Diagnostic::new(
                        "config.import_missing",
                        format!("cannot resolve import `{}`: {error}", declared.display()),
                        import_span.clone(),
                    )
                    .with_reference_chain(chain),
                )
            })?;
            self.import_chain.push(reference);
            let result = self.load(&import);
            self.import_chain.pop();
            result?;
        }
        self.stack.pop();

        self.source_digests
            .insert(path.to_path_buf(), canonical_yaml_digest(path, &source)?);
        self.dependencies.push(path.to_path_buf());
        self.documents.push(document);
        self.loaded.insert(path.to_path_buf());
        Ok(())
    }

    fn discovered_dependencies(&self) -> Vec<PathBuf> {
        self.discovered_dependencies.iter().cloned().collect()
    }

    fn finish(self, root: PathBuf) -> MergedSource {
        let mut dependencies = self.dependencies;
        dependencies.sort();
        dependencies.dedup();
        let source_files = dependencies
            .iter()
            .enumerate()
            .map(|(index, path)| (path.clone(), SourceFileId(index)))
            .collect();
        let mut identity = ContentDigestBuilder::new("oxidase/config-source/v1");
        identity.field_u64("source_count", dependencies.len() as u64);
        if let Some(root_digest) = self.source_digests.get(&root) {
            identity.field_digest("root", *root_digest);
        }
        for dependency in &dependencies {
            if let Some(digest) = self.source_digests.get(dependency) {
                identity.field_digest("source", *digest);
            }
        }
        let mut merged = MergedSource {
            root,
            dependencies,
            source_files,
            hash: identity.finish(),
            ..MergedSource::default()
        };
        for document in self.documents {
            let file = document.path;
            let spans = Arc::new(document.spans);
            let document = document.value;
            merged.span_indexes.insert(file.clone(), spans.clone());
            merged.api_versions.push(Located {
                value: document.api_version,
                file: file.clone(),
                field_path: "api_version".to_owned(),
                spans: spans.clone(),
            });
            merged.kinds.push(Located {
                value: document.kind,
                file: file.clone(),
                field_path: "kind".to_owned(),
                spans: spans.clone(),
            });
            if let Some(bundle) = document.bundle {
                merge_bundle(&mut merged, bundle, &file, Arc::clone(&spans));
            }
            merge_resources(&mut merged, document.resources, &file, Arc::clone(&spans));
            for (name, service) in document.services {
                insert_located(
                    &mut merged.services,
                    name.clone(),
                    Located {
                        value: service,
                        file: file.clone(),
                        field_path: format!("services.{name}"),
                        spans: spans.clone(),
                    },
                    &mut merged.merge_errors,
                    "service",
                );
            }
            merged
                .listeners
                .extend(
                    document
                        .listeners
                        .into_iter()
                        .enumerate()
                        .map(|(index, listener)| Located {
                            value: listener,
                            file: file.clone(),
                            field_path: format!("listeners[{index}]"),
                            spans: spans.clone(),
                        }),
                );
            merged
                .tests
                .extend(
                    document
                        .tests
                        .into_iter()
                        .enumerate()
                        .map(|(index, test)| Located {
                            value: test,
                            file: file.clone(),
                            field_path: format!("tests[{index}]"),
                            spans: spans.clone(),
                        }),
                );
        }
        for located in merged.certificates.values() {
            let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
            for declared in [&located.value.cert_chain, &located.value.private_key] {
                let resolved = resolve_declared_path(directory, declared);
                merged
                    .dependencies
                    .extend(candidate_dependencies(&resolved));
                merged
                    .dependency_candidates
                    .extend(candidate_dependencies(&resolved));
            }
        }
        for located in merged.secrets.values() {
            let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
            let resolved = resolve_declared_path(directory, &located.value.file);
            merged
                .dependencies
                .extend(candidate_dependencies(&resolved));
            merged
                .dependency_candidates
                .extend(candidate_dependencies(&resolved));
        }
        for located in merged.trust_stores.values() {
            let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
            let resolved = resolve_declared_path(directory, &located.value.ca_bundle);
            merged
                .dependencies
                .extend(candidate_dependencies(&resolved));
            merged
                .dependency_candidates
                .extend(candidate_dependencies(&resolved));
        }
        merged.dependencies.sort();
        merged.dependencies.dedup();
        merged.dependency_candidates.sort();
        merged.dependency_candidates.dedup();
        merged
    }
}

fn resolve_declared_path(directory: &Path, declared: &Path) -> PathBuf {
    if declared.is_absolute() {
        declared.to_path_buf()
    } else {
        directory.join(declared)
    }
}

fn summary_dependencies(merged: &MergedSource) -> Vec<PathBuf> {
    let mut sensitive = BTreeSet::new();
    for located in merged.secrets.values() {
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        sensitive.extend(candidate_dependencies(&resolve_declared_path(
            directory,
            &located.value.file,
        )));
    }
    for located in merged.certificates.values() {
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        sensitive.extend(candidate_dependencies(&resolve_declared_path(
            directory,
            &located.value.private_key,
        )));
    }
    merged
        .dependencies
        .iter()
        .filter(|path| !sensitive.contains(*path))
        .cloned()
        .collect()
}

#[derive(Default)]
struct MergedSource {
    root: PathBuf,
    dependencies: Vec<PathBuf>,
    dependency_candidates: Vec<PathBuf>,
    source_files: BTreeMap<PathBuf, SourceFileId>,
    span_indexes: BTreeMap<PathBuf, Arc<FieldSpanIndex>>,
    hash: ContentDigest,
    api_versions: Vec<Located<String>>,
    kinds: Vec<Located<String>>,
    bundle: Option<Located<BundleSource>>,
    certificates: BTreeMap<String, Located<CertificateSource>>,
    secrets: BTreeMap<String, Located<SecretSource>>,
    trust_stores: BTreeMap<String, Located<TrustStoreSource>>,
    clusters: BTreeMap<String, Located<ClusterSource>>,
    sites: BTreeMap<String, Located<SiteSource>>,
    services: BTreeMap<String, Located<ServiceSource>>,
    listeners: Vec<Located<ListenerSource>>,
    tests: Vec<Located<ConfigTestSource>>,
    merge_errors: Vec<Diagnostic>,
}

fn merge_bundle(
    merged: &mut MergedSource,
    bundle: BundleSource,
    file: &Path,
    spans: Arc<FieldSpanIndex>,
) {
    let located = Located {
        value: bundle,
        file: file.to_path_buf(),
        field_path: "bundle".to_owned(),
        spans,
    };
    if let Some(previous) = &merged.bundle {
        let first = previous.span();
        let duplicate = located.span();
        merged.merge_errors.push(
            Diagnostic::new(
                "bundle.duplicate_settings",
                "the import graph may define only one top-level `bundle` block",
                duplicate.clone(),
            )
            .with_label("first bundle settings", first.clone())
            .with_related("previous bundle settings", first.clone())
            .with_reference_chain([
                DiagnosticReference::new("first bundle settings", first),
                DiagnosticReference::new("duplicate bundle settings", duplicate),
            ]),
        );
    } else {
        merged.bundle = Some(located);
    }
}

impl MergedSource {
    fn node_key<'a>(
        &self,
        file: &Path,
        field_path: &'a str,
    ) -> Result<SourceNodeKey<'a>, CompileError> {
        let context = self.context(file);
        let file = self.source_files.get(file).copied().ok_or_else(|| {
            diagnostic_at(
                "service.source_identity",
                "internal compiler error: source file has no assigned identity",
                context,
                field_path,
            )
        })?;
        Ok(SourceNodeKey { file, field_path })
    }

    fn context<'a>(&'a self, file: &'a Path) -> SourceContext<'a> {
        SourceContext {
            file,
            spans: self.span_indexes.get(file).map(Arc::as_ref),
        }
    }
}

fn merge_resources(
    merged: &mut MergedSource,
    resources: ResourcesSource,
    file: &Path,
    spans: Arc<FieldSpanIndex>,
) {
    for (name, certificate) in resources.certificates {
        let field_path = field_path_child("resources.certificates", &name);
        insert_located(
            &mut merged.certificates,
            name.clone(),
            Located {
                value: certificate,
                file: file.to_path_buf(),
                field_path,
                spans: spans.clone(),
            },
            &mut merged.merge_errors,
            "certificate resource",
        );
    }
    for (name, secret) in resources.secrets {
        let field_path = field_path_child("resources.secrets", &name);
        insert_located(
            &mut merged.secrets,
            name.clone(),
            Located {
                value: secret,
                file: file.to_path_buf(),
                field_path,
                spans: spans.clone(),
            },
            &mut merged.merge_errors,
            "secret resource",
        );
    }
    for (name, trust_store) in resources.trust_stores {
        let field_path = field_path_child("resources.trust_stores", &name);
        insert_located(
            &mut merged.trust_stores,
            name.clone(),
            Located {
                value: trust_store,
                file: file.to_path_buf(),
                field_path,
                spans: spans.clone(),
            },
            &mut merged.merge_errors,
            "trust-store resource",
        );
    }
    for (name, cluster) in resources.clusters {
        insert_located(
            &mut merged.clusters,
            name.clone(),
            Located {
                value: cluster,
                file: file.to_path_buf(),
                field_path: format!("resources.clusters.{name}"),
                spans: spans.clone(),
            },
            &mut merged.merge_errors,
            "cluster resource",
        );
    }
    for (name, site) in resources.sites {
        insert_located(
            &mut merged.sites,
            name.clone(),
            Located {
                value: site,
                file: file.to_path_buf(),
                field_path: format!("resources.sites.{name}"),
                spans: spans.clone(),
            },
            &mut merged.merge_errors,
            "site resource",
        );
    }
}

fn insert_located<T>(
    target: &mut BTreeMap<String, Located<T>>,
    name: String,
    value: Located<T>,
    diagnostics: &mut Vec<Diagnostic>,
    kind: &str,
) {
    if let Some(previous) = target.get(&name) {
        let first = previous.span();
        let duplicate = value.span();
        diagnostics.push(
            Diagnostic::new(
                "config.duplicate_definition",
                format!("duplicate {kind} definition `{name}`"),
                duplicate.clone(),
            )
            .with_label("first definition", first.clone())
            .with_related("previous definition", first.clone())
            .with_reference_chain([
                DiagnosticReference::new("first definition", first),
                DiagnosticReference::new("duplicate definition", duplicate),
            ]),
        );
    } else {
        target.insert(name, value);
    }
}

fn validate_document_identity(merged: &MergedSource) -> Result<(), CompileError> {
    let mut diagnostics = merged.merge_errors.clone();
    for version in &merged.api_versions {
        if version.value != API_VERSION {
            diagnostics.push(
                Diagnostic::new(
                    "config.api_version",
                    format!(
                        "unsupported api_version `{}`; expected `{API_VERSION}`",
                        version.value
                    ),
                    version.span(),
                )
                .with_help("migrate this document to the v0.2 v1alpha1 source schema"),
            );
        }
    }
    for kind in &merged.kinds {
        if kind.value != "gateway" {
            diagnostics.push(Diagnostic::new(
                "config.kind",
                format!("unsupported kind `{}`; expected `gateway`", kind.value),
                kind.span(),
            ));
        }
    }
    if merged.listeners.is_empty() {
        diagnostics.push(Diagnostic::new(
            "config.listeners",
            "at least one listener is required",
            span(&merged.root, "listeners"),
        ));
    }
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(CompileError {
            diagnostics,
            discovered_dependencies: Vec::new(),
        })
    }
}

fn compile_bundle(merged: &MergedSource) -> Result<BundleSpec, CompileError> {
    let Some(located) = &merged.bundle else {
        return Ok(BundleSpec {
            assets: BundleAssetsSpec {
                mode: BundleAssetMode::Embed,
                mode_source: span(&merged.root, "bundle.assets.mode"),
                source: span(&merged.root, "bundle.assets"),
            },
            source: span(&merged.root, "bundle"),
        });
    };

    let assets_path = format!("{}.assets", located.field_path);
    let mode_path = format!("{assets_path}.mode");
    let mode_source = located.span_at(&mode_path);
    let mode = match located.value.assets.mode.as_str() {
        "embed" => BundleAssetMode::Embed,
        "reference" => BundleAssetMode::Reference,
        value => {
            return Err(CompileError::one(
                Diagnostic::new(
                    "bundle.asset_mode",
                    format!("unsupported bundle asset mode `{value}`"),
                    mode_source,
                )
                .with_help("use `embed` or `reference`"),
            ));
        }
    };

    Ok(BundleSpec {
        assets: BundleAssetsSpec {
            mode,
            mode_source,
            source: located.span_at(&assets_path),
        },
        source: located.span(),
    })
}

fn compile_resources(
    merged: &MergedSource,
) -> Result<(CompiledResources, Vec<Diagnostic>), CompileError> {
    let mut resources = CompiledResources::default();
    let mut warnings = Vec::new();
    for (name, located) in &merged.certificates {
        if name.trim().is_empty() {
            return Err(semantic_error_at(
                "resource.certificate_name",
                "certificate resource name cannot be empty",
                located.span(),
            ));
        }
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        let cert_chain_path = format!("{}.cert_chain", located.field_path);
        let private_key_path = format!("{}.private_key", located.field_path);
        if located.value.cert_chain.as_os_str().is_empty() {
            return Err(semantic_error_at(
                "resource.certificate_path",
                "certificate chain path cannot be empty",
                located.span_at(&cert_chain_path),
            ));
        }
        if located.value.private_key.as_os_str().is_empty() {
            return Err(semantic_error_at(
                "resource.certificate_path",
                "private key path cannot be empty",
                located.span_at(&private_key_path),
            ));
        }
        let id = ResourceId::new(format!("certificate:{name}"));
        resources.certificates.insert(
            id.clone(),
            CertificateSpec {
                id,
                cert_chain: resolve_declared_path(directory, &located.value.cert_chain),
                private_key: resolve_declared_path(directory, &located.value.private_key),
                cert_chain_source: located.span_at(&cert_chain_path),
                private_key_source: located.span_at(&private_key_path),
                source: located.span(),
            },
        );
    }
    for (name, located) in &merged.secrets {
        if name.trim().is_empty() {
            return Err(semantic_error_at(
                "resource.secret_name",
                "secret resource name cannot be empty",
                located.span(),
            ));
        }
        let file_path = format!("{}.file", located.field_path);
        let max_bytes_path = format!("{}.max_bytes", located.field_path);
        if located.value.file.as_os_str().is_empty() {
            return Err(semantic_error_at(
                "resource.secret_path",
                "secret file path cannot be empty",
                located.span_at(&file_path),
            ));
        }
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        let id = ResourceId::new(format!("secret:{name}"));
        resources.secrets.insert(
            id.clone(),
            SecretSpec {
                id,
                file: resolve_declared_path(directory, &located.value.file),
                max_bytes: parse_byte_size(
                    &located.value.max_bytes,
                    &located.span_at(&max_bytes_path),
                )?,
                file_source: located.span_at(&file_path),
                max_bytes_source: located.span_at(&max_bytes_path),
                source: located.span(),
            },
        );
    }
    for (name, located) in &merged.trust_stores {
        if name.trim().is_empty() {
            return Err(semantic_error_at(
                "resource.trust_store_name",
                "trust-store resource name cannot be empty",
                located.span(),
            ));
        }
        let ca_bundle_path = format!("{}.ca_bundle", located.field_path);
        if located.value.ca_bundle.as_os_str().is_empty() {
            return Err(semantic_error_at(
                "resource.trust_store_path",
                "CA bundle path cannot be empty",
                located.span_at(&ca_bundle_path),
            ));
        }
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        let id = ResourceId::new(format!("trust_store:{name}"));
        resources.trust_stores.insert(
            id.clone(),
            TrustStoreSpec {
                id,
                ca_bundle: resolve_declared_path(directory, &located.value.ca_bundle),
                ca_bundle_source: located.span_at(&ca_bundle_path),
                source: located.span(),
            },
        );
    }
    for (name, located) in &merged.clusters {
        let protocol_path = format!("{}.protocol", located.field_path);
        let protocol_source = located.span_at(&protocol_path);
        let protocol = parse_cluster_protocol(&located.value.protocol, &protocol_source)?;
        if located.value.endpoints.is_empty() {
            return Err(semantic_error_at(
                "resource.cluster_empty",
                "cluster must contain at least one endpoint",
                located.span_at(&format!("{}.endpoints", located.field_path)),
            ));
        }
        let endpoints = compile_cluster_endpoints(located)?;
        let load_balance_path = format!("{}.load_balance.policy", located.field_path);
        let load_balance = parse_load_balance_policy(
            &located.value.load_balance.policy,
            &located.span_at(&load_balance_path),
        )?;
        if load_balance == LoadBalancePolicy::RoundRobin
            && let Some(endpoint) = endpoints.iter().find(|endpoint| endpoint.weight != 1)
        {
            return Err(CompileError::one(
                Diagnostic::new(
                    "resource.cluster_round_robin_weight",
                    format!(
                        "round_robin requires endpoint `{}` to have weight 1",
                        endpoint.name
                    ),
                    endpoint.weight_source.clone(),
                )
                .with_help("use `weighted_round_robin`, or set every endpoint weight to 1"),
            ));
        }
        let health = compile_cluster_health(located)?;
        let retry = compile_retry(located, &mut warnings)?;
        let limits = compile_cluster_limits(located)?;
        let tls = located
            .value
            .tls
            .as_ref()
            .map(|source| compile_cluster_tls(source, located, &resources, &endpoints))
            .transpose()?;
        let id = ResourceId::new(format!("cluster:{name}"));
        resources.clusters.insert(
            id.clone(),
            ClusterSpec {
                id,
                protocol,
                endpoints,
                load_balance,
                health,
                retry,
                limits,
                tls,
                connect_timeout: parse_duration(
                    &located.value.connect_timeout,
                    &located.span_at(&format!("{}.connect_timeout", located.field_path)),
                )?,
                response_timeout: parse_duration(
                    &located.value.response_timeout,
                    &located.span_at(&format!("{}.response_timeout", located.field_path)),
                )?,
                protocol_source,
                source: located.span(),
            },
        );
    }
    for (name, located) in &merged.sites {
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        let root = directory.join(&located.value.root);
        let manifest = root.join(&located.value.manifest);
        let input_spans: BTreeMap<String, SourceSpan> = located
            .value
            .inputs
            .keys()
            .map(|name| {
                let with_path = field_path_child(&located.field_path, "with");
                (
                    name.clone(),
                    located.span_at(&field_path_child(&with_path, name)),
                )
            })
            .collect();
        let inputs = located
            .value
            .inputs
            .iter()
            .map(|(name, value)| {
                yaml_value(value)
                    .map(|value| (name.clone(), value))
                    .map_err(|message| {
                        semantic_error_at("resource.site_input", message, input_spans[name].clone())
                    })
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let id = ResourceId::new(format!("site:{name}"));
        resources.sites.insert(
            id.clone(),
            SiteSpec {
                id,
                root,
                manifest,
                inputs,
                input_spans,
                source: located.span(),
            },
        );
    }
    Ok((resources, warnings))
}

fn compile_listener_transport(
    source: &ListenerSource,
    resources: &CompiledResources,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<(ListenerProtocol, Option<TlsListenerSpec>, HttpListenerSpec), CompileError> {
    let protocol = match source.protocol {
        ListenerProtocolSource::Http => ListenerProtocol::Http,
        ListenerProtocolSource::Https => ListenerProtocol::Https,
    };
    let tls_path = format!("{field_path}.tls");
    let tls = match (protocol, source.tls.as_ref()) {
        (ListenerProtocol::Http, Some(_)) => {
            return Err(diagnostic_at(
                "listener.tls_forbidden",
                "`tls` is only valid when listener protocol is `https`",
                context,
                &tls_path,
            ));
        }
        (ListenerProtocol::Http, None) => None,
        (ListenerProtocol::Https, None) => {
            return Err(diagnostic_at(
                "listener.tls_required",
                "HTTPS listeners require a `tls` configuration",
                context,
                &format!("{field_path}.protocol"),
            )
            .map_diagnostics(|diagnostic| {
                diagnostic.with_help("set `tls.default_certificate` to a certificate resource")
            }));
        }
        (ListenerProtocol::Https, Some(tls)) => {
            Some(compile_tls_listener(tls, resources, context, &tls_path)?)
        }
    };
    let http = compile_http_listener(
        &source.http,
        protocol,
        context,
        &format!("{field_path}.http"),
    )?;
    Ok((protocol, tls, http))
}

fn compile_tls_listener(
    source: &TlsListenerSource,
    resources: &CompiledResources,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<TlsListenerSpec, CompileError> {
    let default_path = format!("{field_path}.default_certificate");
    let default_certificate = certificate_reference(
        &source.default_certificate,
        resources,
        context,
        &default_path,
    )?;
    let sni_path = format!("{field_path}.sni");
    let mut normalized = BTreeMap::<SniPattern, SourceSpan>::new();
    let mut sni = Vec::with_capacity(source.sni.len());
    for (rule, certificate) in &source.sni {
        let rule_path = field_path_child(&sni_path, rule);
        let rule_span = context.key_span(&rule_path);
        let pattern = parse_sni_pattern(rule).map_err(|message| {
            CompileError::one(
                Diagnostic::new("listener.sni", message, rule_span.clone()).with_help(
                    "use an ASCII DNS name or one left-most wildcard such as `*.example.com`",
                ),
            )
        })?;
        if let Some(previous) = normalized.get(&pattern) {
            return Err(CompileError::one(
                Diagnostic::new(
                    "listener.sni_duplicate",
                    format!(
                        "duplicate normalized SNI rule `{}`",
                        pattern.normalized_rule()
                    ),
                    rule_span.clone(),
                )
                .with_label("first rule", previous.clone())
                .with_related("first rule", previous.clone()),
            ));
        }
        normalized.insert(pattern.clone(), rule_span.clone());
        sni.push(SniCertificateSpec {
            pattern,
            certificate: certificate_reference(certificate, resources, context, &rule_path)?,
            source: rule_span,
            certificate_source: context.span(&rule_path),
        });
    }
    sni.sort_by(|left, right| left.pattern.cmp(&right.pattern));
    Ok(TlsListenerSpec {
        default_certificate,
        default_certificate_source: context.span(&default_path),
        sni,
        handshake_timeout: parse_duration(
            &source.handshake_timeout,
            &context.span(&format!("{field_path}.handshake_timeout")),
        )?,
        client_auth: compile_client_auth(
            &source.client_auth,
            resources,
            context,
            &format!("{field_path}.client_auth"),
        )?,
        source: context.span(field_path),
    })
}

fn compile_client_auth(
    source: &ClientAuthSource,
    resources: &CompiledResources,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<ClientAuthSpec, CompileError> {
    let mode_path = format!("{field_path}.mode");
    let trust_store_path = format!("{field_path}.trust_store");
    let mode = match source.mode.as_str() {
        "none" => ClientAuthMode::None,
        "optional" => ClientAuthMode::Optional,
        "required" => ClientAuthMode::Required,
        mode => {
            return Err(CompileError::one(
                Diagnostic::new(
                    "listener.client_auth_mode",
                    format!("unsupported TLS client-auth mode `{mode}`"),
                    context.span(&mode_path),
                )
                .with_help("use `none`, `optional`, or `required`"),
            ));
        }
    };
    match (mode, source.trust_store.as_deref()) {
        (ClientAuthMode::None, Some(_)) => {
            return Err(CompileError::one(
                Diagnostic::new(
                    "listener.client_auth_trust_forbidden",
                    "client_auth.trust_store is forbidden when mode is `none`",
                    context.span(&trust_store_path),
                )
                .with_help("remove `trust_store`, or use mode `optional` or `required`"),
            ));
        }
        (ClientAuthMode::Optional | ClientAuthMode::Required, None) => {
            return Err(CompileError::one(
                Diagnostic::new(
                    "listener.client_auth_trust_required",
                    format!("client-auth mode `{}` requires a trust_store", source.mode),
                    context.span(field_path),
                )
                .with_help("reference a resource defined under `resources.trust_stores`"),
            ));
        }
        _ => {}
    }
    let trust_store = source
        .trust_store
        .as_deref()
        .map(|name| {
            trust_store_reference(
                name,
                resources,
                context,
                &trust_store_path,
                "listener.trust_store_reference",
            )
        })
        .transpose()?;
    Ok(ClientAuthSpec {
        mode,
        trust_store,
        mode_source: context.span(&mode_path),
        trust_store_source: source
            .trust_store
            .as_ref()
            .map(|_| context.span(&trust_store_path)),
        source: context.span(field_path),
    })
}

fn certificate_reference(
    name: &str,
    resources: &CompiledResources,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<ResourceId, CompileError> {
    let id = ResourceId::new(format!("certificate:{name}"));
    if resources.certificates.contains_key(&id) {
        Ok(id)
    } else {
        Err(diagnostic_at(
            "listener.certificate_reference",
            format!("certificate resource `{name}` does not exist"),
            context,
            field_path,
        )
        .map_diagnostics(|diagnostic| {
            diagnostic.with_help("define it under `resources.certificates`")
        }))
    }
}

fn trust_store_reference(
    name: &str,
    resources: &CompiledResources,
    context: SourceContext<'_>,
    field_path: &str,
    diagnostic_code: &'static str,
) -> Result<ResourceId, CompileError> {
    let id = ResourceId::new(format!("trust_store:{name}"));
    if resources.trust_stores.contains_key(&id) {
        Ok(id)
    } else {
        Err(diagnostic_at(
            diagnostic_code,
            format!("trust-store resource `{name}` does not exist"),
            context,
            field_path,
        )
        .map_diagnostics(|diagnostic| {
            diagnostic.with_help("define it under `resources.trust_stores`")
        }))
    }
}

fn compile_http_listener(
    source: &HttpListenerSource,
    protocol: ListenerProtocol,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<HttpListenerSpec, CompileError> {
    let versions = source.versions.clone().unwrap_or_else(|| match protocol {
        ListenerProtocol::Http => vec![HttpVersionSource::Http1],
        ListenerProtocol::Https => vec![HttpVersionSource::H2, HttpVersionSource::Http1],
    });
    if versions.is_empty() {
        return Err(diagnostic_at(
            "listener.http_versions",
            "at least one HTTP version must be enabled",
            context,
            &format!("{field_path}.versions"),
        ));
    }
    let mut seen = BTreeSet::new();
    let mut compiled_versions = Vec::with_capacity(versions.len());
    for (index, version) in versions.into_iter().enumerate() {
        let version = match version {
            HttpVersionSource::Http1 => HttpVersion::Http1,
            HttpVersionSource::H2 => HttpVersion::H2,
        };
        if protocol == ListenerProtocol::Http && version == HttpVersion::H2 {
            return Err(diagnostic_at(
                "listener.h2c_unsupported",
                "cleartext HTTP/2 (h2c) is not supported",
                context,
                &format!("{field_path}.versions[{index}]"),
            )
            .map_diagnostics(|diagnostic| {
                diagnostic.with_help("use `protocol: https` for HTTP/2 or enable only `http1`")
            }));
        }
        if !seen.insert(version) {
            return Err(diagnostic_at(
                "listener.http_version_duplicate",
                format!(
                    "HTTP version `{}` is configured more than once",
                    http_version_name(version)
                ),
                context,
                &format!("{field_path}.versions[{index}]"),
            ));
        }
        compiled_versions.push(version);
    }
    let http1 = compile_http1_settings(source.http1.as_ref(), &seen, context, field_path)?;
    let http2 = compile_http2_settings(source.http2.as_ref(), &seen, context, field_path)?;
    Ok(HttpListenerSpec {
        versions: compiled_versions,
        http1,
        http2,
        source: context.span(field_path),
    })
}

fn compile_listener_limits(
    source: &ListenerLimitsSource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<ListenerLimits, CompileError> {
    validate_positive(
        source.max_connections,
        "listener.limit.max_connections",
        "max_connections",
        context.span(&format!("{field_path}.max_connections")),
    )?;
    validate_positive(
        source.max_connections_per_ip,
        "listener.limit.max_connections_per_ip",
        "max_connections_per_ip",
        context.span(&format!("{field_path}.max_connections_per_ip")),
    )?;
    validate_positive(
        source.max_headers,
        "listener.limit.max_headers",
        "max_headers",
        context.span(&format!("{field_path}.max_headers")),
    )?;
    validate_positive(
        source.max_requests_per_connection,
        "listener.limit.max_requests_per_connection",
        "max_requests_per_connection",
        context.span(&format!("{field_path}.max_requests_per_connection")),
    )?;
    let max_header_bytes_span = context.span(&format!("{field_path}.max_header_bytes"));
    let max_header_bytes = parse_byte_size(&source.max_header_bytes, &max_header_bytes_span)?;
    if max_header_bytes < 8 * 1_024 {
        return Err(CompileError::one(
            Diagnostic::new(
                "listener.limit.max_header_bytes",
                "max_header_bytes must be at least 8KiB",
                max_header_bytes_span,
            )
            .with_help("use `8KiB` or greater; the HTTP/1 parser requires this minimum"),
        ));
    }
    let max_header_bytes = u32::try_from(max_header_bytes).map_err(|_| {
        CompileError::one(
            Diagnostic::new(
                "listener.limit.max_header_bytes",
                "max_header_bytes cannot exceed 4GiB - 1 byte",
                max_header_bytes_span,
            )
            .with_help("use a smaller positive byte size"),
        )
    })?;
    Ok(ListenerLimits {
        max_connections: source.max_connections,
        max_connections_per_ip: source.max_connections_per_ip,
        idle_timeout: parse_duration(
            &source.idle_timeout,
            &context.span(&format!("{field_path}.idle_timeout")),
        )?,
        request_body_idle_timeout: parse_duration(
            &source.request_body_idle_timeout,
            &context.span(&format!("{field_path}.request_body_idle_timeout")),
        )?,
        response_body_idle_timeout: parse_duration(
            &source.response_body_idle_timeout,
            &context.span(&format!("{field_path}.response_body_idle_timeout")),
        )?,
        max_header_bytes,
        max_headers: source.max_headers,
        max_requests_per_connection: source.max_requests_per_connection,
        source: context.span(field_path),
    })
}

fn compile_http1_settings(
    source: Option<&Http1SettingsSource>,
    versions: &BTreeSet<HttpVersion>,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<Option<Http1Settings>, CompileError> {
    let enabled = versions.contains(&HttpVersion::Http1);
    if !enabled {
        if source.is_some() {
            return Err(diagnostic_at(
                "listener.http1_settings_disabled",
                "`http1` settings require HTTP/1 to be enabled in `versions`",
                context,
                &format!("{field_path}.http1"),
            ));
        }
        return Ok(None);
    }
    let default;
    let source = match source {
        Some(source) => source,
        None => {
            default = Http1SettingsSource::default();
            &default
        }
    };
    Ok(Some(Http1Settings {
        header_read_timeout: parse_duration(
            &source.header_read_timeout,
            &context.span(&format!("{field_path}.http1.header_read_timeout")),
        )?,
        source: context.span(&format!("{field_path}.http1")),
    }))
}

fn compile_http2_settings(
    source: Option<&Http2SettingsSource>,
    versions: &BTreeSet<HttpVersion>,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<Option<Http2Settings>, CompileError> {
    let enabled = versions.contains(&HttpVersion::H2);
    if !enabled {
        if source.is_some() {
            return Err(diagnostic_at(
                "listener.http2_settings_disabled",
                "`http2` settings require `h2` to be enabled in `versions`",
                context,
                &format!("{field_path}.http2"),
            ));
        }
        return Ok(None);
    }
    let default;
    let source = match source {
        Some(source) => source,
        None => {
            default = Http2SettingsSource::default();
            &default
        }
    };
    if source.max_concurrent_streams == 0 {
        return Err(diagnostic_at(
            "listener.http2_max_concurrent_streams",
            "HTTP/2 max_concurrent_streams must be greater than zero",
            context,
            &format!("{field_path}.http2.max_concurrent_streams"),
        ));
    }
    let max_header_list_size = parse_byte_size(
        &source.max_header_list_size,
        &context.span(&format!("{field_path}.http2.max_header_list_size")),
    )?;
    let max_header_list_size = u32::try_from(max_header_list_size).map_err(|_| {
        semantic_error_at(
            "config.byte_size",
            "HTTP/2 max_header_list_size exceeds the supported 32-bit range",
            context.span(&format!("{field_path}.http2.max_header_list_size")),
        )
    })?;
    Ok(Some(Http2Settings {
        max_concurrent_streams: source.max_concurrent_streams,
        max_header_list_size,
        keep_alive_interval: parse_duration(
            &source.keep_alive_interval,
            &context.span(&format!("{field_path}.http2.keep_alive_interval")),
        )?,
        keep_alive_timeout: parse_duration(
            &source.keep_alive_timeout,
            &context.span(&format!("{field_path}.http2.keep_alive_timeout")),
        )?,
        source: context.span(&format!("{field_path}.http2")),
    }))
}

fn http_version_name(version: HttpVersion) -> &'static str {
    match version {
        HttpVersion::Http1 => "http1",
        HttpVersion::H2 => "h2",
    }
}

fn parse_sni_pattern(source: &str) -> Result<SniPattern, String> {
    if !source.is_ascii() {
        return Err(format!(
            "SNI rule `{source}` must contain only ASCII DNS characters"
        ));
    }
    let normalized = source.to_ascii_lowercase();
    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.contains('*') {
            return Err(format!(
                "SNI wildcard `{source}` may contain only one wildcard"
            ));
        }
        validate_dns_name(suffix, true).map(|()| SniPattern::Wildcard(suffix.to_owned()))
    } else {
        if normalized.contains('*') {
            return Err(format!(
                "SNI wildcard in `{source}` must be the complete left-most label"
            ));
        }
        validate_dns_name(&normalized, false).map(|()| SniPattern::Exact(normalized))
    }
}

fn validate_dns_name(name: &str, wildcard_suffix: bool) -> Result<(), String> {
    let max_length = if wildcard_suffix { 251 } else { 253 };
    if name.is_empty() || name.len() > max_length || name.ends_with('.') {
        return Err(format!("invalid SNI DNS name `{name}`"));
    }
    if name.parse::<std::net::IpAddr>().is_ok() {
        let kind = if wildcard_suffix {
            "wildcard suffix"
        } else {
            "name"
        };
        return Err(format!(
            "SNI {kind} `{name}` must be a DNS name, not an IP address"
        ));
    }
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid SNI DNS name `{name}`"));
        }
    }
    if name
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!(
            "SNI DNS name `{name}` must not have an all-numeric final label"
        ));
    }
    Ok(())
}

struct ProgramBuilder<'a> {
    source: &'a MergedSource,
    resources: &'a CompiledResources,
    nodes: BTreeMap<ServiceId, ServiceNode>,
    compiling: BTreeSet<String>,
    listener_names: BTreeSet<String>,
}

impl<'a> ProgramBuilder<'a> {
    fn new(source: &'a MergedSource, resources: &'a CompiledResources) -> Self {
        Self {
            source,
            resources,
            nodes: BTreeMap::new(),
            compiling: BTreeSet::new(),
            listener_names: BTreeSet::new(),
        }
    }

    fn compile_listeners(&mut self) -> Result<Vec<CompiledListener>, CompileError> {
        let mut listeners = Vec::new();
        for located in &self.source.listeners {
            if located.value.name.trim().is_empty() {
                return Err(semantic_error_at(
                    "listener.name",
                    "listener name cannot be empty",
                    located.span_at(&format!("{}.name", located.field_path)),
                ));
            }
            if !self.listener_names.insert(located.value.name.clone()) {
                return Err(semantic_error_at(
                    "listener.duplicate",
                    format!("duplicate listener name `{}`", located.value.name),
                    located.span_at(&format!("{}.name", located.field_path)),
                ));
            }
            let bind = located.value.bind.parse::<SocketAddr>().map_err(|error| {
                semantic_error_at(
                    "listener.bind",
                    format!("invalid listener address `{}`: {error}", located.value.bind),
                    located.span_at(&format!("{}.bind", located.field_path)),
                )
            })?;
            let context = self.source.context(&located.file);
            let (protocol, tls, http) = compile_listener_transport(
                &located.value,
                self.resources,
                context,
                &located.field_path,
            )?;
            let limits = compile_listener_limits(
                &located.value.limits,
                context,
                &format!("{}.limits", located.field_path),
            )?;
            let service = self.compile_service(
                &located.value.service,
                context,
                &format!("{}.service", located.field_path),
            )?;
            listeners.push(CompiledListener {
                id: ListenerId::new(format!("listener:{}", located.value.name)),
                name: located.value.name.clone(),
                bind,
                protocol,
                tls,
                http,
                limits,
                service,
                source: located.span(),
            });
        }
        Ok(listeners)
    }

    fn compile_all_named(&mut self) -> Result<(), CompileError> {
        let names = self.source.services.keys().cloned().collect::<Vec<_>>();
        for name in names {
            self.compile_named(&name)?;
        }
        Ok(())
    }

    fn compile_named(&mut self, name: &str) -> Result<ServiceId, CompileError> {
        let id = ServiceId::new(format!("service:{name}"));
        if self.nodes.contains_key(&id) || self.compiling.contains(name) {
            return Ok(id);
        }
        let located = self.source.services.get(name).ok_or_else(|| {
            CompileError::one(Diagnostic::new(
                "service.reference",
                format!("named service `{name}` does not exist"),
                span(&self.source.root, format!("services.{name}")),
            ))
        })?;
        self.compiling.insert(name.to_owned());
        let context = self.source.context(&located.file);
        self.compile_inline_or_reference_as(
            id.clone(),
            &located.value,
            context,
            &located.field_path,
        )?;
        self.compiling.remove(name);
        Ok(id)
    }

    fn compile_service(
        &mut self,
        source: &ServiceSource,
        context: SourceContext<'_>,
        field_path: &str,
    ) -> Result<ServiceId, CompileError> {
        match source {
            ServiceSource::Reference(reference) => {
                if !self.source.services.contains_key(&reference.reference) {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.reference",
                        format!("named service `{}` does not exist", reference.reference),
                        context.span(&format!("{field_path}.ref")),
                    )));
                }
                self.compile_named(&reference.reference)
            }
            ServiceSource::Inline(_) => {
                let id = self
                    .source
                    .node_key(context.file, field_path)?
                    .inline_service_id();
                self.compile_inline_or_reference_as(id.clone(), source, context, field_path)?;
                Ok(id)
            }
        }
    }

    fn compile_inline_or_reference_as(
        &mut self,
        id: ServiceId,
        source: &ServiceSource,
        context: SourceContext<'_>,
        field_path: &str,
    ) -> Result<(), CompileError> {
        let ServiceSource::Inline(source) = source else {
            let ServiceSource::Reference(reference) = source else {
                unreachable!("ServiceSource has two variants");
            };
            let target = self.compile_named(&reference.reference)?;
            let node = ServiceNode {
                id: id.clone(),
                source: context.span(field_path),
                kind: ServiceKind::Fallback {
                    services: vec![target],
                },
            };
            return self.insert_node(node);
        };
        let kind = self.compile_inline(source, context, field_path)?;
        self.insert_node(ServiceNode {
            id,
            source: context.span(field_path),
            kind,
        })
    }

    fn insert_node(&mut self, node: ServiceNode) -> Result<(), CompileError> {
        use std::collections::btree_map::Entry;

        match self.nodes.entry(node.id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(node);
                Ok(())
            }
            Entry::Occupied(entry) => {
                let first = entry.get().source.clone();
                let duplicate = node.source.clone();
                Err(CompileError::one(
                    Diagnostic::new(
                        "service.duplicate_internal_id",
                        format!("duplicate generated Service ID `{}`", node.id),
                        duplicate.clone(),
                    )
                    .with_label("first generated node", first.clone())
                    .with_related("existing generated node", first.clone())
                    .with_reference_chain([
                        DiagnosticReference::new("first generated node", first),
                        DiagnosticReference::new("duplicate generated node", duplicate),
                    ])
                    .with_help("report this compiler identity collision as an Oxidase bug"),
                ))
            }
        }
    }

    fn compile_inline(
        &mut self,
        source: &InlineServiceSource,
        context: SourceContext<'_>,
        field_path: &str,
    ) -> Result<ServiceKind, CompileError> {
        match source {
            InlineServiceSource::Respond {
                status,
                headers,
                body,
            } => Ok(ServiceKind::Respond {
                status: status_code(*status, context, field_path)?,
                headers: compile_headers(headers, context, &format!("{field_path}.headers"))?,
                body: compile_body(body, context, field_path)?,
            }),
            InlineServiceSource::Redirect {
                status,
                location,
                query,
                headers,
            } => {
                let status = status_code(*status, context, field_path)?;
                if !status.is_redirection() {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.redirect_status",
                        format!("redirect status `{status}` is not 3xx"),
                        context.span(&format!("{field_path}.status")),
                    )));
                }
                Ok(ServiceKind::Redirect {
                    status,
                    location: redirect_template(location, context, field_path)?,
                    preserve_query: matches!(query, RedirectQuerySource::Preserve),
                    headers: compile_headers(headers, context, &format!("{field_path}.headers"))?,
                })
            }
            InlineServiceSource::Site { site } => {
                let resource = ResourceId::new(format!("site:{site}"));
                if !self.resources.sites.contains_key(&resource) {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.site_reference",
                        format!("site resource `{site}` does not exist"),
                        context.span(&format!("{field_path}.site")),
                    )));
                }
                Ok(ServiceKind::Site { resource })
            }
            InlineServiceSource::Proxy { cluster } => {
                let resource = ResourceId::new(format!("cluster:{cluster}"));
                if !self.resources.clusters.contains_key(&resource) {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.cluster_reference",
                        format!("cluster resource `{cluster}` does not exist"),
                        context.span(&format!("{field_path}.cluster")),
                    )));
                }
                Ok(ServiceKind::Proxy { cluster: resource })
            }
            InlineServiceSource::Transform {
                request,
                response,
                service,
            } => Ok(ServiceKind::Transform {
                request: Box::new(compile_request_transform(request, context, field_path)?),
                response: Box::new(compile_response_transform(response, context, field_path)?),
                service: self.compile_service(
                    service,
                    context,
                    &format!("{field_path}.service"),
                )?,
            }),
            InlineServiceSource::Observe { name, service } => {
                validate_policy_name(
                    name,
                    "service.observe.name",
                    context.span(&format!("{field_path}.name")),
                )?;
                Ok(ServiceKind::Observe {
                    name: name.clone(),
                    service: self.compile_service(
                        service,
                        context,
                        &format!("{field_path}.service"),
                    )?,
                })
            }
            InlineServiceSource::Timeout { duration, service } => Ok(ServiceKind::Timeout {
                duration: parse_duration(
                    duration,
                    &context.span(&format!("{field_path}.duration")),
                )?,
                service: self.compile_service(
                    service,
                    context,
                    &format!("{field_path}.service"),
                )?,
            }),
            InlineServiceSource::RequestBodyLimit { max_bytes, service } => {
                Ok(ServiceKind::RequestBodyLimit {
                    max_bytes: parse_byte_size(
                        max_bytes,
                        &context.span(&format!("{field_path}.max_bytes")),
                    )?,
                    service: self.compile_service(
                        service,
                        context,
                        &format!("{field_path}.service"),
                    )?,
                })
            }
            InlineServiceSource::ConcurrencyLimit {
                name,
                max_in_flight,
                queue_timeout,
                on_reject,
                service,
            } => {
                validate_policy_name(
                    name,
                    "service.concurrency_limit.name",
                    context.span(&format!("{field_path}.name")),
                )?;
                validate_positive(
                    *max_in_flight,
                    "service.concurrency_limit.max_in_flight",
                    "max_in_flight",
                    context.span(&format!("{field_path}.max_in_flight")),
                )?;
                let reject_status = status_code(
                    on_reject.status,
                    context,
                    &format!("{field_path}.on_reject"),
                )?;
                if !(reject_status.is_client_error() || reject_status.is_server_error()) {
                    return Err(CompileError::one(
                        Diagnostic::new(
                            "service.concurrency_limit.reject_status",
                            "on_reject.status must be a 4xx or 5xx response status",
                            context.span(&format!("{field_path}.on_reject.status")),
                        )
                        .with_help("use `429` or `503`"),
                    ));
                }
                Ok(ServiceKind::ConcurrencyLimit {
                    name: name.clone(),
                    max_in_flight: *max_in_flight,
                    queue_timeout: parse_nonnegative_duration(
                        queue_timeout,
                        &context.span(&format!("{field_path}.queue_timeout")),
                    )?,
                    reject_status,
                    service: self.compile_service(
                        service,
                        context,
                        &format!("{field_path}.service"),
                    )?,
                })
            }
            InlineServiceSource::RateLimit {
                name,
                key,
                rate,
                burst,
                state,
                service,
            } => {
                validate_policy_name(
                    name,
                    "service.rate_limit.name",
                    context.span(&format!("{field_path}.name")),
                )?;
                if rate.requests == 0 {
                    return Err(semantic_error_at(
                        "service.rate_limit.requests",
                        "rate.requests must be greater than zero",
                        context.span(&format!("{field_path}.rate.requests")),
                    ));
                }
                if *burst == 0 {
                    return Err(semantic_error_at(
                        "service.rate_limit.burst",
                        "burst must be greater than zero",
                        context.span(&format!("{field_path}.burst")),
                    ));
                }
                validate_positive(
                    state.max_keys,
                    "service.rate_limit.max_keys",
                    "state.max_keys",
                    context.span(&format!("{field_path}.state.max_keys")),
                )?;
                let key = match key {
                    RateLimitKeySource::PeerIp => RateLimitKey::PeerIp,
                    RateLimitKeySource::Binding { name } => {
                        validate_binding_name(
                            name,
                            context.span(&format!("{field_path}.key.name")),
                        )?;
                        RateLimitKey::Binding(name.clone())
                    }
                };
                Ok(ServiceKind::RateLimit {
                    name: name.clone(),
                    key,
                    requests: rate.requests,
                    per: parse_duration(
                        &rate.per,
                        &context.span(&format!("{field_path}.rate.per")),
                    )?,
                    burst: *burst,
                    max_keys: state.max_keys,
                    idle_ttl: parse_duration(
                        &state.idle_ttl,
                        &context.span(&format!("{field_path}.state.idle_ttl")),
                    )?,
                    service: self.compile_service(
                        service,
                        context,
                        &format!("{field_path}.service"),
                    )?,
                })
            }
            InlineServiceSource::Recover { service, handlers } => {
                let service =
                    self.compile_service(service, context, &format!("{field_path}.service"))?;
                let handlers = handlers
                    .iter()
                    .enumerate()
                    .map(|(index, handler)| {
                        Ok(RecoverHandler {
                            classes: handler.classes.iter().copied().map(error_class).collect(),
                            service: self.compile_service(
                                &handler.service,
                                context,
                                &format!("{field_path}.handlers[{index}].service"),
                            )?,
                        })
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                Ok(ServiceKind::Recover { service, handlers })
            }
            InlineServiceSource::Route { cases, default }
            | InlineServiceSource::Router {
                rules: cases,
                default,
            } => {
                let cases = cases
                    .iter()
                    .enumerate()
                    .map(|(index, case)| {
                        let case_path = format!("{field_path}.cases[{index}]");
                        Ok(RouteCase {
                            id: self.source.node_key(context.file, &case_path)?.route_id(),
                            predicate: compile_predicate(
                                &case.predicate,
                                context,
                                &format!("{case_path}.when"),
                            )?,
                            service: self.compile_service(
                                &case.service,
                                context,
                                &format!("{case_path}.service"),
                            )?,
                            source: context.span(&case_path),
                        })
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                let default = default
                    .as_ref()
                    .map(|service| {
                        self.compile_service(service, context, &format!("{field_path}.default"))
                    })
                    .transpose()?;
                Ok(ServiceKind::Route { cases, default })
            }
            InlineServiceSource::Fallback { services } => {
                if services.is_empty() {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.fallback_empty",
                        "fallback requires at least one candidate",
                        context.span(&format!("{field_path}.services")),
                    )));
                }
                Ok(ServiceKind::Fallback {
                    services: services
                        .iter()
                        .enumerate()
                        .map(|(index, service)| {
                            self.compile_service(
                                service,
                                context,
                                &format!("{field_path}.services[{index}]"),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            InlineServiceSource::Reenter { target, budget } => {
                if !self.source.services.contains_key(target) {
                    return Err(CompileError::one(Diagnostic::new(
                        "service.reenter_target",
                        format!("Reenter target `{target}` is not a named service"),
                        context.span(&format!("{field_path}.target")),
                    )));
                }
                Ok(ServiceKind::Reenter {
                    target: ServiceId::new(format!("service:{target}")),
                    budget: *budget,
                })
            }
        }
    }
}

fn compile_body(
    source: &BodySource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<RespondBody, CompileError> {
    let selected = usize::from(source.empty)
        + usize::from(source.text.is_some())
        + usize::from(source.json.is_some());
    if selected > 1 {
        return Err(diagnostic_at(
            "service.respond_body",
            "response body must select exactly one of `empty`, `text`, or `json`",
            context,
            field_path,
        ));
    }
    if let Some(text) = &source.text {
        Ok(RespondBody::Text(template(
            text,
            context,
            &format!("{field_path}.body.text"),
        )?))
    } else if let Some(json) = &source.json {
        Ok(RespondBody::Json(yaml_value(json).map_err(|message| {
            diagnostic_at(
                "service.respond_json",
                message,
                context,
                &format!("{field_path}.body.json"),
            )
        })?))
    } else if source.empty || selected == 0 {
        Ok(RespondBody::Empty)
    } else {
        Ok(RespondBody::Bytes(Bytes::new()))
    }
}

fn compile_request_transform(
    source: &RequestTransformSource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<RequestTransform, CompileError> {
    Ok(RequestTransform {
        method: source
            .method
            .as_ref()
            .map(|method| method.parse::<Method>())
            .transpose()
            .map_err(|error| {
                diagnostic_at(
                    "service.transform_method",
                    format!("invalid HTTP method: {error}"),
                    context,
                    &format!("{field_path}.request.method"),
                )
            })?,
        scheme: compile_metadata_template(
            &source.scheme,
            context,
            &format!("{field_path}.request.scheme"),
            "service.transform_scheme",
            parse_transform_scheme,
        )?,
        authority: compile_metadata_template(
            &source.authority,
            context,
            &format!("{field_path}.request.authority"),
            "service.transform_authority",
            parse_transform_authority,
        )?,
        path_and_query: compile_metadata_template(
            &source.path,
            context,
            &format!("{field_path}.request.path"),
            "service.transform_path_and_query",
            parse_transform_path_and_query,
        )?,
        headers: compile_headers(
            &source.headers,
            context,
            &format!("{field_path}.request.headers"),
        )?,
    })
}

fn compile_response_transform(
    source: &ResponseTransformSource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<ResponseTransform, CompileError> {
    Ok(ResponseTransform {
        headers: compile_headers(
            &source.headers,
            context,
            &format!("{field_path}.response.headers"),
        )?,
    })
}

fn compile_headers(
    source: &HeadersSource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<HeaderTransforms, CompileError> {
    Ok(HeaderTransforms {
        set: compile_header_values(&source.set, context, &format!("{field_path}.set"))?,
        add: compile_header_values(&source.add, context, &format!("{field_path}.add"))?,
        remove: source
            .remove
            .iter()
            .enumerate()
            .map(|(index, name)| {
                compile_user_header_name(name, context, &format!("{field_path}.remove[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn compile_header_values(
    source: &BTreeMap<String, String>,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<Vec<HeaderTransform>, CompileError> {
    source
        .iter()
        .map(|(name, value)| {
            let header_path = format!("{field_path}.{name}");
            let name = compile_user_header_name(name, context, &header_path)?;
            let value = template(value, context, &header_path)?;
            if value.is_constant() {
                let rendered = value
                    .render(&oxidase_core::EvalContext::default())
                    .map_err(|error| {
                        diagnostic_at(
                            "service.header_value",
                            error.to_string(),
                            context,
                            &header_path,
                        )
                    })?;
                HeaderValue::from_str(&rendered).map_err(|_| {
                    diagnostic_at(
                        "service.header_value",
                        format!("header `{name}` has an invalid constant value"),
                        context,
                        &header_path,
                    )
                })?;
            }
            Ok(HeaderTransform { name, value })
        })
        .collect()
}

fn compile_user_header_name(
    source: &str,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<HeaderName, CompileError> {
    let name = HeaderName::from_str(source).map_err(|error| {
        diagnostic_at(
            "service.header_name",
            format!("invalid header name `{source}`: {error}"),
            context,
            field_path,
        )
    })?;
    if is_forbidden_user_header(&name) {
        return Err(diagnostic_at(
            "service.forbidden_header",
            format!("header `{name}` is managed by the HTTP response finalizer"),
            context,
            field_path,
        ));
    }
    Ok(name)
}

fn compile_predicate(
    source: &PredicateSource,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<PredicatePlan, CompileError> {
    Ok(PredicatePlan {
        methods: source
            .methods
            .iter()
            .map(|method| method.parse::<Method>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                diagnostic_at(
                    "service.predicate_method",
                    format!("invalid HTTP method: {error}"),
                    context,
                    &format!("{field_path}.methods"),
                )
            })?,
        host: source
            .host
            .as_ref()
            .map(|pattern| CompiledPattern::compile(pattern, PatternContext::Host))
            .transpose()
            .map_err(|error| {
                diagnostic_at(
                    "service.host_pattern",
                    error.to_string(),
                    context,
                    &format!("{field_path}.host"),
                )
            })?,
        path: source
            .path
            .as_ref()
            .map(|pattern| CompiledPattern::compile(pattern, PatternContext::Path))
            .transpose()
            .map_err(|error| {
                diagnostic_at(
                    "service.path_pattern",
                    error.to_string(),
                    context,
                    &format!("{field_path}.path"),
                )
            })?,
        headers: source
            .headers
            .iter()
            .map(|(name, pattern)| {
                Ok(HeaderPredicate {
                    name: HeaderName::from_str(name).map_err(|error| {
                        diagnostic_at(
                            "service.header_name",
                            format!("invalid header name `{name}`: {error}"),
                            context,
                            &format!("{field_path}.headers.{name}"),
                        )
                    })?,
                    pattern: CompiledPattern::compile(pattern, PatternContext::Value).map_err(
                        |error| {
                            diagnostic_at(
                                "service.header_pattern",
                                error.to_string(),
                                context,
                                &format!("{field_path}.headers.{name}"),
                            )
                        },
                    )?,
                    negated: false,
                })
            })
            .collect::<Result<Vec<_>, CompileError>>()?,
        expression: source
            .expression
            .as_ref()
            .map(Expression::compile)
            .transpose()
            .map_err(|error| {
                diagnostic_at(
                    "service.predicate_expression",
                    error.to_string(),
                    context,
                    &format!("{field_path}.expression"),
                )
            })?,
    })
}

fn template(
    source: &str,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<CompiledTemplate, CompileError> {
    CompiledTemplate::compile(source)
        .map_err(|error| diagnostic_at("service.template", error.to_string(), context, field_path))
}

fn redirect_template(
    source: &str,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<CompiledTemplate, CompileError> {
    let template = template(source, context, &format!("{field_path}.location"))?;
    if template.is_constant()
        && (!source.starts_with('/') || source.starts_with("//") || source.contains('\\'))
    {
        return Err(diagnostic_at(
            "service.redirect_location",
            "redirect Location must be a local absolute path",
            context,
            &format!("{field_path}.location"),
        ));
    }
    Ok(template)
}

fn compile_metadata_template<T>(
    source: &Option<String>,
    context: SourceContext<'_>,
    field_path: &str,
    code: &'static str,
    parse: fn(&str) -> Result<T, RequestMetadataError>,
) -> Result<Option<CompiledMetadata<T>>, CompileError> {
    let Some(source) = source else {
        return Ok(None);
    };
    let template = template(source, context, field_path)?;
    if template.is_constant() {
        let rendered = template
            .render(&oxidase_core::EvalContext::default())
            .map_err(|error| diagnostic_at(code, error.to_string(), context, field_path))?;
        parse(&rendered)
            .map(CompiledMetadata::Constant)
            .map(Some)
            .map_err(|error| diagnostic_at(code, error.to_string(), context, field_path))
    } else {
        Ok(Some(CompiledMetadata::Dynamic(template)))
    }
}

fn status_code(
    status: u16,
    context: SourceContext<'_>,
    field_path: &str,
) -> Result<StatusCode, CompileError> {
    StatusCode::from_u16(status).map_err(|error| {
        diagnostic_at(
            "service.status",
            format!("invalid HTTP status `{status}`: {error}"),
            context,
            &format!("{field_path}.status"),
        )
    })
}

fn error_class(source: ErrorClassSource) -> ErrorClass {
    match source {
        ErrorClassSource::Configuration => ErrorClass::Configuration,
        ErrorClassSource::Timeout => ErrorClass::Timeout,
        ErrorClassSource::UpstreamConnect => ErrorClass::UpstreamConnect,
        ErrorClassSource::UpstreamProtocol => ErrorClass::UpstreamProtocol,
        ErrorClassSource::UpstreamUnavailable => ErrorClass::UpstreamUnavailable,
        ErrorClassSource::UpstreamOverloaded => ErrorClass::UpstreamOverloaded,
        ErrorClassSource::SiteIo => ErrorClass::SiteIo,
        ErrorClassSource::TemplateLimit => ErrorClass::TemplateLimit,
        ErrorClassSource::BodyUnavailable => ErrorClass::BodyUnavailable,
        ErrorClassSource::InvalidState => ErrorClass::InvalidState,
        ErrorClassSource::Internal => ErrorClass::Internal,
    }
}

fn parse_duration(source: &str, source_span: &SourceSpan) -> Result<Duration, CompileError> {
    parse_duration_with_zero_policy(source, source_span, false)
}

fn parse_nonnegative_duration(
    source: &str,
    source_span: &SourceSpan,
) -> Result<Duration, CompileError> {
    parse_duration_with_zero_policy(source, source_span, true)
}

fn parse_duration_with_zero_policy(
    source: &str,
    source_span: &SourceSpan,
    allow_zero: bool,
) -> Result<Duration, CompileError> {
    let (number, multiplier) = if let Some(number) = source.strip_suffix("ms") {
        (number, 1u64)
    } else if let Some(number) = source.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = source.strip_suffix('m') {
        (number, 60_000)
    } else {
        return Err(CompileError::one(
            Diagnostic::new(
                "config.duration",
                format!("invalid duration `{source}`"),
                source_span.clone(),
            )
            .with_help("use an integer followed by `ms`, `s`, or `m`"),
        ));
    };
    let number = number.parse::<u64>().map_err(|_| {
        CompileError::one(Diagnostic::new(
            "config.duration",
            format!("invalid duration `{source}`"),
            source_span.clone(),
        ))
    })?;
    let millis = number.checked_mul(multiplier).ok_or_else(|| {
        CompileError::one(Diagnostic::new(
            "config.duration",
            format!("duration `{source}` is too large"),
            source_span.clone(),
        ))
    })?;
    if millis == 0 && !allow_zero {
        return Err(CompileError::one(Diagnostic::new(
            "config.duration",
            "duration must be greater than zero",
            source_span.clone(),
        )));
    }
    Ok(Duration::from_millis(millis))
}

fn parse_cluster_protocol(
    source: &str,
    source_span: &SourceSpan,
) -> Result<ClusterProtocol, CompileError> {
    match source {
        "auto" => Ok(ClusterProtocol::Auto),
        "http1" => Ok(ClusterProtocol::Http1),
        "h2" => Ok(ClusterProtocol::H2),
        _ => Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_protocol",
                format!("unsupported upstream protocol `{source}`"),
                source_span.clone(),
            )
            .with_help("use `auto`, `http1`, or `h2`"),
        )),
    }
}

fn compile_cluster_tls(
    source: &ClusterTlsSource,
    located: &Located<ClusterSource>,
    resources: &CompiledResources,
    endpoints: &[ClusterEndpointSpec],
) -> Result<ClusterTlsSpec, CompileError> {
    let field_path = format!("{}.tls", located.field_path);
    if !endpoints
        .iter()
        .any(|endpoint| endpoint.url.scheme() == "https")
    {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_tls_inert",
                "cluster TLS policy has no effect because every endpoint uses `http`",
                located.span_at(&field_path),
            )
            .with_help("remove `tls`, or configure at least one `https` endpoint"),
        ));
    }

    let context = SourceContext {
        file: &located.file,
        spans: Some(located.spans.as_ref()),
    };
    let server_name_path = format!("{field_path}.server_name");
    let trust_path = format!("{field_path}.trust");
    let system_roots_path = format!("{trust_path}.system_roots");
    let trust_store_path = format!("{trust_path}.trust_store");
    let client_certificate_path = format!("{field_path}.client_certificate");

    let server_name = source
        .server_name
        .as_deref()
        .map(|name| {
            normalize_upstream_server_name(name).map_err(|message| {
                CompileError::one(
                    Diagnostic::new(
                        "resource.cluster_tls_server_name",
                        message,
                        located.span_at(&server_name_path),
                    )
                    .with_help("use an ASCII DNS name or an unbracketed IPv4/IPv6 address"),
                )
            })
        })
        .transpose()?;

    if !source.trust.system_roots && source.trust.trust_store.is_none() {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_tls_trust_empty",
                "upstream TLS must trust system roots, a trust_store, or both",
                located.span_at(&trust_path),
            )
            .with_help("set `system_roots: true` or reference a custom trust_store"),
        ));
    }
    let trust_store = source
        .trust
        .trust_store
        .as_deref()
        .map(|name| {
            trust_store_reference(
                name,
                resources,
                context,
                &trust_store_path,
                "resource.cluster_trust_store_reference",
            )
        })
        .transpose()?;
    let client_certificate = source
        .client_certificate
        .as_deref()
        .map(|name| {
            let id = ResourceId::new(format!("certificate:{name}"));
            if resources.certificates.contains_key(&id) {
                Ok(id)
            } else {
                Err(diagnostic_at(
                    "resource.cluster_client_certificate_reference",
                    format!("certificate resource `{name}` does not exist"),
                    context,
                    &client_certificate_path,
                )
                .map_diagnostics(|diagnostic| {
                    diagnostic.with_help("define it under `resources.certificates`")
                }))
            }
        })
        .transpose()?;

    Ok(ClusterTlsSpec {
        server_name,
        trust: ClusterTlsTrustSpec {
            system_roots: source.trust.system_roots,
            trust_store,
            system_roots_source: located.span_at(&system_roots_path),
            trust_store_source: source
                .trust
                .trust_store
                .as_ref()
                .map(|_| located.span_at(&trust_store_path)),
            source: located.span_at(&trust_path),
        },
        client_certificate,
        server_name_source: source
            .server_name
            .as_ref()
            .map(|_| located.span_at(&server_name_path)),
        client_certificate_source: source
            .client_certificate
            .as_ref()
            .map(|_| located.span_at(&client_certificate_path)),
        source: located.span_at(&field_path),
    })
}

fn normalize_upstream_server_name(source: &str) -> Result<String, String> {
    if source.is_empty() || !source.is_ascii() || source.contains('*') {
        return Err(format!(
            "invalid upstream TLS server name `{source}`; wildcards and non-ASCII names are not supported"
        ));
    }
    if let Ok(address) = source.parse::<std::net::IpAddr>() {
        return Ok(address.to_string());
    }
    let normalized = source.to_ascii_lowercase();
    if normalized.len() > 253 || normalized.ends_with('.') {
        return Err(format!("invalid upstream TLS server name `{source}`"));
    }
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!("invalid upstream TLS server name `{source}`"));
        }
    }
    if normalized
        .rsplit('.')
        .next()
        .is_some_and(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(format!(
            "upstream TLS server name `{source}` must not have an all-numeric final DNS label"
        ));
    }
    Ok(normalized)
}

fn compile_cluster_endpoints(
    located: &Located<ClusterSource>,
) -> Result<Vec<ClusterEndpointSpec>, CompileError> {
    let mut endpoints = Vec::with_capacity(located.value.endpoints.len());
    let mut names = BTreeMap::<String, SourceSpan>::new();
    for (index, endpoint) in located.value.endpoints.iter().enumerate() {
        let base_path = format!("{}.endpoints[{index}]", located.field_path);
        let base_span = located.span_at(&base_path);
        let (name, url_source, weight, name_span, url_span, weight_span) = match endpoint {
            ClusterEndpointSource::Shorthand(url) => (
                format!("endpoint-{index}"),
                url.as_str(),
                1_u64,
                base_span.clone(),
                base_span.clone(),
                base_span.clone(),
            ),
            ClusterEndpointSource::Structured(endpoint) => (
                endpoint.name.clone(),
                endpoint.url.as_str(),
                endpoint.weight,
                located.span_at(&format!("{base_path}.name")),
                located.span_at(&format!("{base_path}.url")),
                located.span_at(&format!("{base_path}.weight")),
            ),
        };
        validate_endpoint_name(&name, &name_span)?;
        if let Some(first) = names.insert(name.clone(), name_span.clone()) {
            return Err(CompileError::one(
                Diagnostic::new(
                    "resource.endpoint_duplicate",
                    format!("duplicate endpoint name `{name}`"),
                    name_span,
                )
                .with_label("first endpoint with this name", first.clone())
                .with_related("first endpoint definition", first),
            ));
        }
        let weight = u16::try_from(weight)
            .ok()
            .filter(|weight| (1..=1_000).contains(weight))
            .ok_or_else(|| {
                CompileError::one(
                    Diagnostic::new(
                        "resource.endpoint_weight",
                        format!("endpoint `{name}` weight must be in 1..=1000"),
                        weight_span.clone(),
                    )
                    .with_help("choose an integer weight from 1 through 1000"),
                )
            })?;
        let url = parse_endpoint_url(url_source, &url_span)?;
        endpoints.push(ClusterEndpointSpec {
            name,
            url,
            weight,
            name_source: name_span,
            url_source: url_span,
            weight_source: weight_span,
            source: base_span,
        });
    }
    Ok(endpoints)
}

fn validate_endpoint_name(name: &str, source: &SourceSpan) -> Result<(), CompileError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.endpoint_name",
                format!("invalid endpoint name `{name}`"),
                source.clone(),
            )
            .with_help("use 1 to 128 ASCII letters, digits, dots, underscores, or hyphens"),
        ));
    }
    Ok(())
}

fn parse_endpoint_url(source: &str, source_span: &SourceSpan) -> Result<Url, CompileError> {
    let url = Url::parse(source).map_err(|error| {
        semantic_error_at(
            "resource.endpoint",
            format!("invalid endpoint `{source}`: {error}"),
            source_span.clone(),
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(semantic_error_at(
            "resource.endpoint",
            format!(
                "endpoint `{source}` must be an http(s) origin/path without credentials, query, or fragment"
            ),
            source_span.clone(),
        ));
    }
    Ok(url)
}

fn parse_load_balance_policy(
    source: &str,
    source_span: &SourceSpan,
) -> Result<LoadBalancePolicy, CompileError> {
    match source {
        "round_robin" => Ok(LoadBalancePolicy::RoundRobin),
        "weighted_round_robin" => Ok(LoadBalancePolicy::WeightedRoundRobin),
        "least_requests" => Ok(LoadBalancePolicy::LeastRequests),
        _ => Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_load_balance",
                format!("unsupported load-balancing policy `{source}`"),
                source_span.clone(),
            )
            .with_help("use `round_robin`, `weighted_round_robin`, or `least_requests`"),
        )),
    }
}

fn compile_cluster_health(
    located: &Located<ClusterSource>,
) -> Result<ClusterHealthSpec, CompileError> {
    let health_path = format!("{}.health", located.field_path);
    let active = located
        .value
        .health
        .active
        .as_ref()
        .map(|source| compile_active_health(source, located, &format!("{health_path}.active")))
        .transpose()?;
    let passive = located
        .value
        .health
        .passive
        .as_ref()
        .map(|source| compile_passive_health(source, located, &format!("{health_path}.passive")))
        .transpose()?;
    Ok(ClusterHealthSpec { active, passive })
}

fn compile_active_health(
    source: &ActiveHealthSource,
    located: &Located<ClusterSource>,
    field_path: &str,
) -> Result<ActiveHealthSpec, CompileError> {
    let path_span = located.span_at(&format!("{field_path}.path"));
    if !source.path.starts_with('/')
        || source.path.starts_with("//")
        || PathAndQuery::from_str(&source.path).is_err()
    {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_health_path",
                format!(
                    "health-check path `{}` is not valid origin-form",
                    source.path
                ),
                path_span,
            )
            .with_help("use an absolute path such as `/healthz`, optionally with a query"),
        ));
    }
    if source.healthy_statuses.is_empty() {
        return Err(semantic_error_at(
            "resource.cluster_health_status",
            "active health checks require at least one healthy status range",
            located.span_at(&format!("{field_path}.healthy_statuses")),
        ));
    }
    let healthy_statuses = compile_status_ranges(
        &source.healthy_statuses,
        located,
        &format!("{field_path}.healthy_statuses"),
        "resource.cluster_health_status",
    )?;
    validate_positive(
        source.healthy_threshold,
        "resource.cluster_health_threshold",
        "healthy_threshold",
        located.span_at(&format!("{field_path}.healthy_threshold")),
    )?;
    validate_positive(
        source.unhealthy_threshold,
        "resource.cluster_health_threshold",
        "unhealthy_threshold",
        located.span_at(&format!("{field_path}.unhealthy_threshold")),
    )?;
    Ok(ActiveHealthSpec {
        path: source.path.clone(),
        interval: parse_duration(
            &source.interval,
            &located.span_at(&format!("{field_path}.interval")),
        )?,
        timeout: parse_duration(
            &source.timeout,
            &located.span_at(&format!("{field_path}.timeout")),
        )?,
        healthy_statuses,
        healthy_threshold: source.healthy_threshold,
        unhealthy_threshold: source.unhealthy_threshold,
        source: located.span_at(field_path),
    })
}

fn compile_passive_health(
    source: &PassiveHealthSource,
    located: &Located<ClusterSource>,
    field_path: &str,
) -> Result<PassiveHealthSpec, CompileError> {
    validate_positive(
        source.consecutive_failures,
        "resource.cluster_passive_threshold",
        "consecutive_failures",
        located.span_at(&format!("{field_path}.consecutive_failures")),
    )?;
    Ok(PassiveHealthSpec {
        consecutive_failures: source.consecutive_failures,
        eject_for: parse_duration(
            &source.eject_for,
            &located.span_at(&format!("{field_path}.eject_for")),
        )?,
        source: located.span_at(field_path),
    })
}

fn compile_retry(
    located: &Located<ClusterSource>,
    warnings: &mut Vec<Diagnostic>,
) -> Result<RetrySpec, CompileError> {
    let source: &RetrySource = &located.value.retry;
    let field_path = format!("{}.retry", located.field_path);
    validate_positive(
        source.max_attempts,
        "resource.cluster_retry_attempts",
        "max_attempts",
        located.span_at(&format!("{field_path}.max_attempts")),
    )?;
    validate_positive(
        source.max_concurrent_retries,
        "resource.cluster_retry_concurrency",
        "max_concurrent_retries",
        located.span_at(&format!("{field_path}.max_concurrent_retries")),
    )?;

    let mut methods = Vec::with_capacity(source.methods.len());
    let mut method_names = BTreeSet::new();
    for (index, method) in source.methods.iter().enumerate() {
        let method_span = located.span_at(&format!("{field_path}.methods[{index}]"));
        let parsed = Method::from_bytes(method.as_bytes()).map_err(|error| {
            CompileError::one(Diagnostic::new(
                "resource.cluster_retry_method",
                format!("invalid retry method `{method}`: {error}"),
                method_span.clone(),
            ))
        })?;
        if !method_names.insert(parsed.as_str().to_owned()) {
            return Err(semantic_error_at(
                "resource.cluster_retry_method",
                format!("duplicate retry method `{method}`"),
                method_span,
            ));
        }
        if parsed == Method::POST {
            warnings.push(
                Diagnostic::warning(
                    "resource.cluster_retry_post",
                    "retrying POST requires the operator to guarantee request idempotency",
                    method_span,
                )
                .with_help("remove POST unless the upstream operation is safe to repeat"),
            );
        }
        methods.push(parsed);
    }

    let mut retry_on = Vec::with_capacity(source.retry_on.len());
    let mut causes = BTreeSet::new();
    for (index, cause) in source.retry_on.iter().enumerate() {
        let cause_span = located.span_at(&format!("{field_path}.retry_on[{index}]"));
        let cause = parse_retry_cause(cause, &cause_span)?;
        if !causes.insert(cause) {
            return Err(semantic_error_at(
                "resource.cluster_retry_cause",
                format!("duplicate retry cause `{}`", cause.as_str()),
                cause_span,
            ));
        }
        retry_on.push(cause);
    }
    let statuses = compile_status_ranges(
        &source.statuses,
        located,
        &format!("{field_path}.statuses"),
        "resource.cluster_retry_status",
    )?;
    if source.max_attempts > 1 && methods.is_empty() {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_retry_methods",
                "retry max_attempts greater than 1 requires at least one explicit method",
                located.span_at(&format!("{field_path}.methods")),
            )
            .with_help("list only methods whose upstream operations are safe to repeat"),
        ));
    }
    if source.max_attempts > 1 && retry_on.is_empty() && statuses.is_empty() {
        return Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_retry_trigger",
                "retry max_attempts greater than 1 requires a retry_on cause or status",
                located.span_at(field_path.as_str()),
            )
            .with_help("configure explicit pre-response-head failures or response statuses"),
        ));
    }
    Ok(RetrySpec {
        max_attempts: source.max_attempts,
        methods,
        retry_on,
        statuses,
        request_body: compile_retry_body(&source.request_body, located, &field_path)?,
        max_concurrent_retries: source.max_concurrent_retries,
        source: located.span_at(&field_path),
    })
}

fn parse_retry_cause(source: &str, source_span: &SourceSpan) -> Result<RetryCause, CompileError> {
    match source {
        "connect_failure" => Ok(RetryCause::ConnectFailure),
        "response_header_timeout" => Ok(RetryCause::ResponseHeaderTimeout),
        "refused_stream" => Ok(RetryCause::RefusedStream),
        "reset" => Ok(RetryCause::Reset),
        _ => Err(CompileError::one(
            Diagnostic::new(
                "resource.cluster_retry_cause",
                format!("unsupported retry cause `{source}`"),
                source_span.clone(),
            )
            .with_help(
                "use `connect_failure`, `response_header_timeout`, `refused_stream`, or `reset`",
            ),
        )),
    }
}

fn compile_retry_body(
    source: &RetryRequestBodySource,
    located: &Located<ClusterSource>,
    retry_path: &str,
) -> Result<RetryRequestBodySpec, CompileError> {
    let field_path = format!("{retry_path}.request_body");
    let mode_span = located.span_at(&format!("{field_path}.mode"));
    let mode = match source.mode.as_str() {
        "none" => RetryBodyMode::None,
        "buffer" => RetryBodyMode::Buffer,
        _ => {
            return Err(CompileError::one(
                Diagnostic::new(
                    "resource.cluster_retry_body_mode",
                    format!("unsupported retry request-body mode `{}`", source.mode),
                    mode_span,
                )
                .with_help("use `none` or `buffer`"),
            ));
        }
    };
    Ok(RetryRequestBodySpec {
        mode,
        max_bytes: parse_byte_size(
            &source.max_bytes,
            &located.span_at(&format!("{field_path}.max_bytes")),
        )?,
        source: located.span_at(&field_path),
    })
}

fn compile_cluster_limits(located: &Located<ClusterSource>) -> Result<ClusterLimits, CompileError> {
    let source = &located.value.limits;
    let field_path = format!("{}.limits", located.field_path);
    validate_positive(
        source.max_in_flight,
        "resource.cluster_limit",
        "max_in_flight",
        located.span_at(&format!("{field_path}.max_in_flight")),
    )?;
    validate_positive(
        source.max_in_flight_per_endpoint,
        "resource.cluster_limit",
        "max_in_flight_per_endpoint",
        located.span_at(&format!("{field_path}.max_in_flight_per_endpoint")),
    )?;
    Ok(ClusterLimits {
        max_in_flight: source.max_in_flight,
        max_in_flight_per_endpoint: source.max_in_flight_per_endpoint,
        queue_timeout: parse_nonnegative_duration(
            &source.queue_timeout,
            &located.span_at(&format!("{field_path}.queue_timeout")),
        )?,
        source: located.span_at(&field_path),
    })
}

fn compile_status_ranges(
    sources: &[StatusRangeSource],
    located: &Located<ClusterSource>,
    field_path: &str,
    code: &'static str,
) -> Result<Vec<StatusRange>, CompileError> {
    let mut ranges = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        ranges.push(parse_status_range(
            source,
            code,
            &located.span_at(&format!("{field_path}[{index}]")),
        )?);
    }
    Ok(ranges)
}

fn parse_status_range(
    source: &StatusRangeSource,
    code: &'static str,
    source_span: &SourceSpan,
) -> Result<StatusRange, CompileError> {
    let source = match source {
        StatusRangeSource::Code(code) => code.to_string(),
        StatusRangeSource::Text(source) => source.clone(),
    };
    let (start, end) = source
        .split_once('-')
        .map_or((source.as_str(), source.as_str()), |(start, end)| {
            (start, end)
        });
    let parse = |value: &str| {
        value
            .parse::<u16>()
            .ok()
            .filter(|value| StatusCode::from_u16(*value).is_ok())
    };
    let Some(start) = parse(start) else {
        return Err(invalid_status_range(code, &source, source_span));
    };
    let Some(end) = parse(end) else {
        return Err(invalid_status_range(code, &source, source_span));
    };
    if start > end {
        return Err(invalid_status_range(code, &source, source_span));
    }
    Ok(StatusRange { start, end })
}

fn invalid_status_range(code: &'static str, source: &str, span: &SourceSpan) -> CompileError {
    CompileError::one(
        Diagnostic::new(
            code,
            format!("invalid HTTP status or closed range `{source}`"),
            span.clone(),
        )
        .with_help("use a status such as `503` or an inclusive range such as `200-299`"),
    )
}

fn validate_positive(
    value: u32,
    code: &'static str,
    name: &str,
    source: SourceSpan,
) -> Result<(), CompileError> {
    if value == 0 {
        return Err(semantic_error_at(
            code,
            format!("{name} must be greater than zero"),
            source,
        ));
    }
    Ok(())
}

fn validate_policy_name(
    value: &str,
    code: &'static str,
    source: SourceSpan,
) -> Result<(), CompileError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(CompileError::one(
            Diagnostic::new(
                code,
                "policy name must be 1-128 ASCII letters, digits, `_`, `-`, `.`, or `:`",
                source,
            )
            .with_help("use a short static configuration name suitable for bounded metrics"),
        ))
    }
}

fn validate_binding_name(value: &str, source: SourceSpan) -> Result<(), CompileError> {
    let mut bytes = value.bytes();
    let valid_start = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
    let valid_tail = bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if valid_start && valid_tail {
        Ok(())
    } else {
        Err(CompileError::one(
            Diagnostic::new(
                "service.rate_limit.binding",
                format!("invalid lexical binding name `{value}`"),
                source,
            )
            .with_help("use an identifier such as `tenant_id`"),
        ))
    }
}

fn parse_byte_size(source: &str, source_span: &SourceSpan) -> Result<u64, CompileError> {
    let (number, multiplier) = if let Some(number) = source.strip_suffix("KiB") {
        (number, 1_024u64)
    } else if let Some(number) = source.strip_suffix("MiB") {
        (number, 1_024u64 * 1_024)
    } else if let Some(number) = source.strip_suffix("GiB") {
        (number, 1_024u64 * 1_024 * 1_024)
    } else if let Some(number) = source.strip_suffix('B') {
        (number, 1u64)
    } else {
        return Err(CompileError::one(
            Diagnostic::new(
                "config.byte_size",
                format!("invalid byte size `{source}`"),
                source_span.clone(),
            )
            .with_help("use an integer followed by `B`, `KiB`, `MiB`, or `GiB`"),
        ));
    };
    let number = number.parse::<u64>().map_err(|_| {
        CompileError::one(Diagnostic::new(
            "config.byte_size",
            format!("invalid byte size `{source}`"),
            source_span.clone(),
        ))
    })?;
    let bytes = number.checked_mul(multiplier).ok_or_else(|| {
        CompileError::one(Diagnostic::new(
            "config.byte_size",
            format!("byte size `{source}` is too large"),
            source_span.clone(),
        ))
    })?;
    if bytes == 0 {
        return Err(CompileError::one(Diagnostic::new(
            "config.byte_size",
            "byte size must be greater than zero",
            source_span.clone(),
        )));
    }
    Ok(bytes)
}

fn yaml_value(source: &serde_yaml_ng::Value) -> Result<Value, String> {
    match source {
        serde_yaml_ng::Value::Null => Ok(Value::Null),
        serde_yaml_ng::Value::Bool(value) => Ok(Value::Bool(*value)),
        serde_yaml_ng::Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Ok(Value::Integer(value))
            } else if let Some(value) = value.as_f64() {
                Ok(Value::Float(value))
            } else {
                Err("numeric value is outside the supported range".to_owned())
            }
        }
        serde_yaml_ng::Value::String(value) => Ok(Value::String(value.clone())),
        serde_yaml_ng::Value::Sequence(values) => values
            .iter()
            .map(yaml_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        serde_yaml_ng::Value::Mapping(values) => values
            .iter()
            .map(|(key, value)| {
                let serde_yaml_ng::Value::String(key) = key else {
                    return Err("map keys must be strings".to_owned());
                };
                Ok((key.clone(), yaml_value(value)?))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()
            .map(Value::Map),
        serde_yaml_ng::Value::Tagged(_) => {
            Err("YAML tags are not supported in typed values".to_owned())
        }
    }
}

fn semantic_error_at(
    code: &'static str,
    message: impl Into<String>,
    source: SourceSpan,
) -> CompileError {
    CompileError::one(Diagnostic::new(code, message, source))
}

fn diagnostic_at(
    code: &'static str,
    message: impl Into<String>,
    context: SourceContext<'_>,
    field_path: &str,
) -> CompileError {
    CompileError::one(Diagnostic::new(code, message, context.span(field_path)))
}

fn span(path: &Path, field_path: impl Into<String>) -> SourceSpan {
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: 0,
        end_byte: 0,
        line: 1,
        column: 1,
        end_line: 1,
        end_column: 1,
        field_path: field_path.into(),
    }
}

fn indexed_span(path: &Path, field_path: &str, spans: &FieldSpanIndex) -> SourceSpan {
    let Some(source) = spans.nearest(field_path) else {
        return span(path, field_path);
    };
    let source = &source.value;
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: source.start_byte,
        end_byte: source.end_byte,
        line: source.start_line,
        column: source.start_column,
        end_line: source.end_line,
        end_column: source.end_column,
        field_path: field_path.to_owned(),
    }
}

fn indexed_key_span(path: &Path, field_path: &str, spans: &FieldSpanIndex) -> SourceSpan {
    let Some(source) = spans.nearest(field_path) else {
        return span(path, field_path);
    };
    let source = &source.key;
    SourceSpan {
        file: path.to_path_buf(),
        start_byte: source.start_byte,
        end_byte: source.end_byte,
        line: source.start_line,
        column: source.start_column,
        end_line: source.end_line,
        end_column: source.end_column,
        field_path: field_path.to_owned(),
    }
}

fn parse_yaml<T: serde::de::DeserializeOwned>(
    path: &Path,
    source: &str,
    field_path: &str,
) -> Result<T, CompileError> {
    parse_yaml_document(path, source, field_path).map(|document| document.value)
}

fn parse_yaml_document<T: serde::de::DeserializeOwned>(
    path: &Path,
    source: &str,
    field_path: &str,
) -> Result<SourceDocument<T>, CompileError> {
    oxidase_source::parse_document(path, source).map_err(|error| {
        let mut diagnostic = Diagnostic::new(
            error.code,
            error.message,
            SourceSpan {
                file: error.path,
                start_byte: 0,
                end_byte: 0,
                line: error.line,
                column: error.column,
                end_line: error.line,
                end_column: error.column,
                field_path: field_path.to_owned(),
            },
        );
        if let Some(help) = error.help {
            diagnostic = diagnostic.with_help(help);
        }
        CompileError::one(diagnostic)
    })
}

fn canonical_yaml_digest(path: &Path, source: &str) -> Result<ContentDigest, CompileError> {
    let value: serde_yaml_ng::Value = serde_yaml_ng::from_str(source).map_err(|error| {
        CompileError::one(Diagnostic::new(
            "yaml.deserialize",
            error.to_string(),
            span(path, ""),
        ))
    })?;
    let value = serde_json::to_value(value).map_err(|error| {
        CompileError::one(Diagnostic::new(
            "yaml.canonicalize",
            format!("cannot canonicalize configuration: {error}"),
            span(path, ""),
        ))
    })?;
    let bytes = serde_json::to_vec(&value).map_err(|error| {
        CompileError::one(Diagnostic::new(
            "yaml.canonicalize",
            format!("cannot encode canonical configuration: {error}"),
            span(path, ""),
        ))
    })?;
    Ok(ContentDigest::of_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use http::StatusCode;
    use oxidase_core::{
        ErrorClass, HeaderTransforms, RateLimitKey, RespondBody, ServiceId, ServiceKind,
        ServiceNode, SourceSpan,
    };
    use tempfile::tempdir;

    use super::{CompiledResources, Compiler, MergedSource, ProgramBuilder};

    fn write_config(source: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("oxidase.yaml");
        fs::write(&path, source).expect("fixture config can be written");
        (directory, path)
    }

    fn write_file(directory: &std::path::Path, name: &str, source: &str) {
        fs::write(directory.join(name), source).expect("fixture config can be written");
    }

    fn response_text<'a>(gateway: &'a super::CompiledGateway, listener: &str) -> &'a str {
        let listener = gateway
            .listeners
            .iter()
            .find(|candidate| candidate.name == listener)
            .expect("listener exists");
        match &gateway
            .graph
            .get(&listener.service)
            .expect("listener entry exists")
            .kind
        {
            ServiceKind::Respond {
                body: RespondBody::Text(body),
                ..
            } => body.source(),
            other => panic!("expected Respond, got {other:?}"),
        }
    }

    #[test]
    fn bundle_assets_default_to_embed_and_are_inspectable() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let gateway = Compiler::compile_path(path).expect("default bundle policy compiles");
        assert_eq!(gateway.bundle.assets.mode, super::BundleAssetMode::Embed);
        assert_eq!(gateway.bundle.source.field_path, "bundle");
        assert_eq!(gateway.bundle.assets.source.field_path, "bundle.assets");
        assert_eq!(
            gateway.bundle.assets.mode_source.field_path,
            "bundle.assets.mode"
        );
        assert_eq!(
            serde_json::to_value(gateway.summary()).expect("summary serializes")["bundle"]["assets"]
                ["mode"],
            "embed"
        );
    }

    #[test]
    fn compiles_reference_bundle_assets_with_exact_source_spans() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: reference
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let gateway = Compiler::compile_path(path).expect("reference policy compiles");
        assert_eq!(
            gateway.bundle.assets.mode,
            super::BundleAssetMode::Reference
        );
        assert_eq!(gateway.bundle.source.line, 3);
        assert_eq!(gateway.bundle.assets.source.line, 4);
        assert_eq!(gateway.bundle.assets.mode_source.line, 5);
        assert_eq!(
            gateway.bundle.assets.mode_source.field_path,
            "bundle.assets.mode"
        );
        assert!(
            gateway.bundle.assets.mode_source.end_byte
                > gateway.bundle.assets.mode_source.start_byte
        );
        assert_eq!(
            serde_json::to_value(gateway.summary()).expect("summary serializes")["bundle"]["assets"]
                ["mode"],
            "reference"
        );
    }

    #[test]
    fn rejects_unknown_bundle_asset_mode_at_exact_value() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: magical
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let error = Compiler::compile_path(path).expect_err("unknown mode must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "bundle.asset_mode");
        assert_eq!(diagnostic.primary.field_path, "bundle.assets.mode");
        assert_eq!(diagnostic.primary.line, 5);
        assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
        assert_eq!(
            diagnostic.help.as_deref(),
            Some("use `embed` or `reference`")
        );
    }

    #[test]
    fn rejects_unknown_bundle_fields_instead_of_accepting_inert_policy() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: embed
    compression: magical
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let error = Compiler::compile_path(path).expect_err("unknown field must fail");
        assert_eq!(error.diagnostics[0].code, "source.parse");
        assert!(error.diagnostics[0].message.contains("compression"));
    }

    #[test]
    fn rejects_multiple_bundle_blocks_across_imports_with_both_spans() {
        let directory = tempdir().expect("temporary directory is available");
        write_file(
            directory.path(),
            "a.yaml",
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: embed
"#,
        );
        write_file(
            directory.path(),
            "b.yaml",
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
bundle:
  assets:
    mode: reference
"#,
        );
        write_file(
            directory.path(),
            "root.yaml",
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [a.yaml, b.yaml]
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let error = Compiler::compile_path(directory.path().join("root.yaml"))
            .expect_err("only one bundle block is allowed");
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "bundle.duplicate_settings")
            .expect("duplicate settings diagnostic exists");
        assert_eq!(diagnostic.primary.field_path, "bundle");
        assert_eq!(diagnostic.primary.line, 3);
        assert!(diagnostic.primary.file.ends_with("b.yaml"));
        assert_eq!(diagnostic.labels.len(), 1);
        assert!(diagnostic.labels[0].span.file.ends_with("a.yaml"));
        assert_eq!(diagnostic.reference_chain.len(), 2);
    }

    #[test]
    fn compiles_named_and_inline_services_to_one_ir() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  public:
    type: transform
    response:
      headers:
        set:
          X-Frame: outer
    service:
      type: respond
      body:
        text: "hello {{ request.path }}"
listeners:
  - name: public
    bind: 127.0.0.1:7589
    service:
      ref: public
"#,
        );
        let gateway = Compiler::compile_path(path).expect("valid gateway compiles");
        let program = gateway
            .program_for("public")
            .expect("listener program exists");
        assert!(matches!(
            program
                .graph
                .get(&program.entry)
                .expect("entry node exists")
                .kind,
            ServiceKind::Transform { .. }
        ));
        assert_eq!(gateway.listeners.len(), 1);
    }

    #[test]
    fn compiles_listener_limits_and_all_ingress_governance_services() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  governed:
    type: rate_limit
    name: tenant-rate
    key:
      source: binding
      name: tenant_id
    rate:
      requests: 100
      per: 1s
    burst: 200
    state:
      max_keys: 100000
      idle_ttl: 10m
    service:
      type: concurrency_limit
      name: upstream-admission
      max_in_flight: 100
      queue_timeout: 50ms
      on_reject:
        status: 429
      service:
        type: request_body_limit
        max_bytes: 16MiB
        service:
          type: respond
listeners:
  - name: public
    bind: 127.0.0.1:0
    limits:
      max_connections: 8000
      max_connections_per_ip: 80
      idle_timeout: 90s
      request_body_idle_timeout: 20s
      response_body_idle_timeout: 25s
      max_header_bytes: 32KiB
      max_headers: 64
      max_requests_per_connection: 500
    service:
      ref: governed
"#,
        );

        let gateway = Compiler::compile_path(path).expect("governance source compiles");
        let limits = &gateway.listeners[0].limits;
        assert_eq!(limits.max_connections, 8_000);
        assert_eq!(limits.max_connections_per_ip, 80);
        assert_eq!(limits.idle_timeout, std::time::Duration::from_secs(90));
        assert_eq!(
            limits.request_body_idle_timeout,
            std::time::Duration::from_secs(20)
        );
        assert_eq!(
            limits.response_body_idle_timeout,
            std::time::Duration::from_secs(25)
        );
        assert_eq!(limits.max_header_bytes, 32 * 1_024);
        assert_eq!(limits.max_headers, 64);
        assert_eq!(limits.max_requests_per_connection, 500);
        assert_eq!(limits.source.field_path, "listeners[0].limits");

        let rate = gateway
            .graph
            .get(&ServiceId::new("service:governed"))
            .expect("rate node");
        let ServiceKind::RateLimit {
            name,
            key,
            requests,
            per,
            burst,
            max_keys,
            idle_ttl,
            service: concurrency,
        } = &rate.kind
        else {
            panic!("expected RateLimit, got {:?}", rate.kind);
        };
        assert_eq!(name, "tenant-rate");
        assert_eq!(key, &RateLimitKey::Binding("tenant_id".to_owned()));
        assert_eq!((*requests, *burst, *max_keys), (100, 200, 100_000));
        assert_eq!(*per, std::time::Duration::from_secs(1));
        assert_eq!(*idle_ttl, std::time::Duration::from_secs(600));

        let ServiceKind::ConcurrencyLimit {
            name,
            max_in_flight,
            queue_timeout,
            reject_status,
            service: body_limit,
        } = &gateway
            .graph
            .get(concurrency)
            .expect("concurrency node")
            .kind
        else {
            panic!("expected ConcurrencyLimit");
        };
        assert_eq!(name, "upstream-admission");
        assert_eq!(*max_in_flight, 100);
        assert_eq!(*queue_timeout, std::time::Duration::from_millis(50));
        assert_eq!(*reject_status, StatusCode::TOO_MANY_REQUESTS);
        assert!(matches!(
            gateway.graph.get(body_limit).expect("body limit node").kind,
            ServiceKind::RequestBodyLimit {
                max_bytes: 16_777_216,
                ..
            }
        ));
    }

    #[test]
    fn listener_governance_defaults_are_safe_and_backwards_compatible() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: concurrency_limit
      name: default-reject
      max_in_flight: 1
      service:
        type: respond
"#,
        );
        let gateway = Compiler::compile_path(path).expect("defaults compile");
        let limits = &gateway.listeners[0].limits;
        assert_eq!(limits.max_connections, 10_000);
        assert_eq!(limits.max_connections_per_ip, 100);
        assert_eq!(limits.idle_timeout, std::time::Duration::from_secs(120));
        assert_eq!(limits.max_header_bytes, 65_536);
        assert_eq!(limits.max_headers, 100);
        assert_eq!(limits.max_requests_per_connection, 1_000);
        let entry = gateway
            .graph
            .get(&gateway.listeners[0].service)
            .expect("entry node");
        assert!(matches!(
            entry.kind,
            ServiceKind::ConcurrencyLimit {
                queue_timeout: std::time::Duration::ZERO,
                reject_status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
    }

    #[test]
    fn governance_validation_reports_the_exact_semantic_field() {
        let fixtures = [
            (
                "limits:\n      max_connections: 0",
                "type: respond",
                "listener.limit.max_connections",
                "listeners[0].limits.max_connections",
            ),
            (
                "limits:\n      max_header_bytes: 4KiB",
                "type: respond",
                "listener.limit.max_header_bytes",
                "listeners[0].limits.max_header_bytes",
            ),
            (
                "",
                "type: request_body_limit\n      max_bytes: 0B\n      service:\n        type: respond",
                "config.byte_size",
                "listeners[0].service.max_bytes",
            ),
            (
                "",
                "type: concurrency_limit\n      name: bad/name\n      max_in_flight: 1\n      service:\n        type: respond",
                "service.concurrency_limit.name",
                "listeners[0].service.name",
            ),
            (
                "",
                "type: concurrency_limit\n      name: good\n      max_in_flight: 0\n      service:\n        type: respond",
                "service.concurrency_limit.max_in_flight",
                "listeners[0].service.max_in_flight",
            ),
            (
                "",
                "type: concurrency_limit\n      name: good\n      max_in_flight: 1\n      on_reject:\n        status: 200\n      service:\n        type: respond",
                "service.concurrency_limit.reject_status",
                "listeners[0].service.on_reject.status",
            ),
            (
                "",
                "type: rate_limit\n      name: rate\n      key:\n        source: binding\n        name: bad-name\n      rate:\n        requests: 1\n        per: 1s\n      burst: 1\n      state:\n        max_keys: 10\n        idle_ttl: 1m\n      service:\n        type: respond",
                "service.rate_limit.binding",
                "listeners[0].service.key.name",
            ),
            (
                "",
                "type: rate_limit\n      name: rate\n      key:\n        source: peer_ip\n      rate:\n        requests: 0\n        per: 1s\n      burst: 1\n      state:\n        max_keys: 10\n        idle_ttl: 1m\n      service:\n        type: respond",
                "service.rate_limit.requests",
                "listeners[0].service.rate.requests",
            ),
            (
                "",
                "type: rate_limit\n      name: rate\n      key:\n        source: peer_ip\n      rate:\n        requests: 1\n        per: 1s\n      burst: 0\n      state:\n        max_keys: 10\n        idle_ttl: 1m\n      service:\n        type: respond",
                "service.rate_limit.burst",
                "listeners[0].service.burst",
            ),
            (
                "",
                "type: rate_limit\n      name: rate\n      key:\n        source: peer_ip\n      rate:\n        requests: 1\n        per: 1s\n      burst: 1\n      state:\n        max_keys: 0\n        idle_ttl: 1m\n      service:\n        type: respond",
                "service.rate_limit.max_keys",
                "listeners[0].service.state.max_keys",
            ),
        ];

        for (listener_limits, service, code, field_path) in fixtures {
            let (_directory, path) = write_config(&format!(
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    {listener_limits}\n    service:\n      {service}\n"
            ));
            let error = Compiler::compile_path(path).expect_err("invalid governance field fails");
            assert_eq!(error.diagnostics[0].code, code);
            assert_eq!(error.diagnostics[0].primary.field_path, field_path);
            assert!(
                error.diagnostics[0].primary.end_byte > error.diagnostics[0].primary.start_byte
            );
        }
    }

    #[test]
    fn governance_sources_reject_unknown_inert_fields() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: public
    bind: 127.0.0.1:0
    limits:
      max_connections: 100
      magic_overflow_policy: ignore
    service:
      type: respond
"#,
        );
        let error = Compiler::compile_path(path).expect_err("unknown limit must fail");
        assert_eq!(error.diagnostics[0].code, "source.parse");
        assert!(error.to_string().contains("magic_overflow_policy"));
    }

    #[test]
    fn recover_compiles_cluster_availability_error_classes() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: recover
    service:
      type: respond
      body:
        text: primary
    handlers:
      - classes: [upstream_unavailable, upstream_overloaded]
        service:
          type: respond
          body:
            text: recovered
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        );

        let gateway = Compiler::compile_path(path).expect("Recover classes compile");
        let program = gateway
            .program_for("public")
            .expect("listener program exists");
        let ServiceKind::Recover { handlers, .. } = &program
            .graph
            .get(&program.entry)
            .expect("Recover entry exists")
            .kind
        else {
            panic!("listener entry must be Recover");
        };

        assert_eq!(handlers.len(), 1);
        assert_eq!(
            handlers[0].classes,
            [
                ErrorClass::UpstreamUnavailable,
                ErrorClass::UpstreamOverloaded,
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn cluster_protocol_defaults_to_auto_for_legacy_endpoint_shorthand() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://127.0.0.1:3000
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let gateway = Compiler::compile_path(path).expect("legacy cluster shorthand compiles");
        let cluster = gateway
            .resources
            .clusters
            .get(&oxidase_core::ResourceId::new("cluster:api"))
            .expect("cluster is compiled");
        assert_eq!(cluster.protocol, super::ClusterProtocol::Auto);
        assert_eq!(cluster.endpoints[0].name, "endpoint-0");
        assert_eq!(cluster.endpoints[0].weight, 1);
        assert_eq!(cluster.endpoints[0].url.as_str(), "http://127.0.0.1:3000/");
        assert_eq!(gateway.summary().clusters.len(), 1);
        assert_eq!(
            gateway.summary().clusters[0].protocol,
            super::ClusterProtocol::Auto
        );
    }

    #[test]
    fn compiles_each_upstream_cluster_protocol_into_ir_and_summary() {
        for (source, expected) in [
            ("auto", super::ClusterProtocol::Auto),
            ("http1", super::ClusterProtocol::Http1),
            ("h2", super::ClusterProtocol::H2),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: {source}
      endpoints: [https://example.test]
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#
            ));

            let gateway = Compiler::compile_path(path).expect("cluster protocol compiles");
            let cluster =
                &gateway.resources.clusters[&oxidase_core::ResourceId::new("cluster:api")];
            assert_eq!(cluster.protocol, expected);
            assert_eq!(
                cluster.protocol_source.field_path,
                "resources.clusters.api.protocol"
            );
            assert_eq!(gateway.summary().clusters[0].protocol, expected);
        }
    }

    #[test]
    fn rejects_unknown_cluster_protocol_at_the_protocol_value_span() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: http3
      endpoints: [https://example.test]
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let error = Compiler::compile_path(path).expect_err("unknown protocol must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "resource.cluster_protocol");
        assert_eq!(
            diagnostic.primary.field_path,
            "resources.clusters.api.protocol"
        );
        assert_eq!(diagnostic.primary.line, 6);
        assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
        assert_eq!(
            diagnostic.help.as_deref(),
            Some("use `auto`, `http1`, or `h2`")
        );
    }

    #[test]
    fn rejects_unknown_cluster_fields_instead_of_accepting_inert_policy() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: auto
      upstream_protocol: h2
      endpoints: [https://example.test]
"#,
        );

        let error = Compiler::compile_path(path).expect_err("unknown cluster field must fail");
        assert_eq!(error.diagnostics[0].code, "source.parse");
        assert!(
            error
                .to_string()
                .contains("unknown field `upstream_protocol`")
        );
    }

    #[test]
    fn compiles_structured_resilient_cluster_policy_and_post_warning() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: https://127.0.0.1:8443/base
          weight: 2
        - name: api-b
          url: https://127.0.0.1:9443
          weight: 1
      load_balance:
        policy: weighted_round_robin
      health:
        active:
          path: /healthz?ready=1
          interval: 5s
          timeout: 1s
          healthy_statuses: ["200-299", 304]
          healthy_threshold: 2
          unhealthy_threshold: 3
        passive:
          consecutive_failures: 4
          eject_for: 30s
      retry:
        max_attempts: 3
        methods: [GET, POST]
        retry_on: [connect_failure, response_header_timeout, refused_stream, reset]
        statuses: [502, "503-504"]
        request_body:
          mode: buffer
          max_bytes: 64KiB
        max_concurrent_retries: 16
      limits:
        max_in_flight: 512
        max_in_flight_per_endpoint: 128
        queue_timeout: 0ms
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let gateway = Compiler::compile_path(path).expect("resilient cluster compiles");
        let cluster = &gateway.resources.clusters[&oxidase_core::ResourceId::new("cluster:api")];
        assert_eq!(cluster.endpoints.len(), 2);
        assert_eq!(cluster.endpoints[0].name, "api-a");
        assert_eq!(cluster.endpoints[0].weight, 2);
        assert_eq!(
            cluster.load_balance,
            super::LoadBalancePolicy::WeightedRoundRobin
        );
        let active = cluster.health.active.as_ref().expect("active health plan");
        assert_eq!(active.path, "/healthz?ready=1");
        assert!(active.healthy_statuses[0].contains(250));
        assert!(active.healthy_statuses[1].contains(304));
        assert_eq!(
            cluster
                .health
                .passive
                .as_ref()
                .expect("passive health plan")
                .consecutive_failures,
            4
        );
        assert_eq!(cluster.retry.max_attempts, 3);
        assert_eq!(
            cluster.retry.methods,
            [http::Method::GET, http::Method::POST]
        );
        assert_eq!(cluster.retry.retry_on.len(), 4);
        assert_eq!(
            cluster.retry.request_body.mode,
            super::RetryBodyMode::Buffer
        );
        assert_eq!(cluster.retry.request_body.max_bytes, 65_536);
        assert_eq!(cluster.limits.max_in_flight, 512);
        assert_eq!(cluster.limits.queue_timeout, std::time::Duration::ZERO);
        assert_eq!(gateway.warnings.len(), 1);
        assert_eq!(gateway.warnings[0].code, "resource.cluster_retry_post");
        assert_eq!(
            gateway.warnings[0].primary.field_path,
            "resources.clusters.api.retry.methods[1]"
        );
        let summary = &gateway.summary().clusters[0];
        assert_eq!(
            summary.load_balance,
            super::LoadBalancePolicy::WeightedRoundRobin
        );
        assert_eq!(summary.endpoint_count, 2);
        assert!(summary.active_health);
        assert!(summary.passive_health);
        assert_eq!(summary.retry_max_attempts, 3);
    }

    #[test]
    fn rejects_duplicate_endpoint_names_with_both_definition_spans() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - name: duplicate
          url: https://one.example
        - name: duplicate
          url: https://two.example
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        );

        let error = Compiler::compile_path(path).expect_err("duplicate endpoint must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "resource.endpoint_duplicate");
        assert_eq!(
            diagnostic.primary.field_path,
            "resources.clusters.api.endpoints[1].name"
        );
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(
            diagnostic.labels[0].span.field_path,
            "resources.clusters.api.endpoints[0].name"
        );
    }

    #[test]
    fn validates_endpoint_weight_and_round_robin_weight_semantics() {
        for (weight, expected_code) in [
            ("0", "resource.endpoint_weight"),
            ("1001", "resource.endpoint_weight"),
            ("2", "resource.cluster_round_robin_weight"),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - name: api-a
          url: https://one.example
          weight: {weight}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid weight policy fails");
            assert_eq!(error.diagnostics[0].code, expected_code);
            assert_eq!(
                error.diagnostics[0].primary.field_path,
                "resources.clusters.api.endpoints[0].weight"
            );
        }
    }

    #[test]
    fn validates_health_path_status_range_and_threshold_spans() {
        for (fragment, code, field_path) in [
            (
                "path: https://example.test/health",
                "resource.cluster_health_path",
                "resources.clusters.api.health.active.path",
            ),
            (
                "healthy_statuses: [\"299-200\"]",
                "resource.cluster_health_status",
                "resources.clusters.api.health.active.healthy_statuses[0]",
            ),
            (
                "healthy_threshold: 0",
                "resource.cluster_health_threshold",
                "resources.clusters.api.health.active.healthy_threshold",
            ),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints: [https://one.example]
      health:
        active:
          {fragment}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid health policy fails");
            assert_eq!(error.diagnostics[0].code, code);
            assert_eq!(error.diagnostics[0].primary.field_path, field_path);
        }
    }

    #[test]
    fn rejects_incomplete_or_unknown_retry_policy_at_exact_fields() {
        for (retry, code, field_path) in [
            (
                "max_attempts: 0",
                "resource.cluster_retry_attempts",
                "resources.clusters.api.retry.max_attempts",
            ),
            (
                "max_attempts: 2\n        methods: [GET]\n        retry_on: [socket_magic]",
                "resource.cluster_retry_cause",
                "resources.clusters.api.retry.retry_on[0]",
            ),
            (
                "max_attempts: 2\n        retry_on: [connect_failure]",
                "resource.cluster_retry_methods",
                "resources.clusters.api.retry.methods",
            ),
            (
                "request_body:\n          mode: unlimited\n          max_bytes: 1KiB",
                "resource.cluster_retry_body_mode",
                "resources.clusters.api.retry.request_body.mode",
            ),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints: [https://one.example]
      retry:
        {retry}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid retry policy fails");
            assert_eq!(error.diagnostics[0].code, code);
            assert_eq!(error.diagnostics[0].primary.field_path, field_path);
        }
    }

    #[test]
    fn rejects_zero_concurrency_limits_but_accepts_zero_queue_timeout() {
        for field in ["max_in_flight", "max_in_flight_per_endpoint"] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints: [https://one.example]
      limits:
        {field}: 0
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("zero limit fails");
            assert_eq!(error.diagnostics[0].code, "resource.cluster_limit");
            assert_eq!(
                error.diagnostics[0].primary.field_path,
                format!("resources.clusters.api.limits.{field}")
            );
        }
    }

    #[test]
    fn router_is_lowered_to_route() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  public:
    type: router
    rules:
      - when:
          path: /old
        service:
          type: redirect
          location: /new
listeners:
  - name: public
    bind: 127.0.0.1:7589
    service:
      ref: public
"#,
        );
        let gateway = Compiler::compile_path(path).expect("valid router compiles");
        let program = gateway
            .program_for("public")
            .expect("listener program exists");
        assert!(matches!(
            program
                .graph
                .get(&program.entry)
                .expect("entry node exists")
                .kind,
            ServiceKind::Route { .. }
        ));
    }

    #[test]
    fn check_compiles_templates_and_resource_references() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  public:
    type: site
    site: missing
listeners:
  - name: public
    bind: 127.0.0.1:7589
    service:
      ref: public
"#,
        );
        let error = Compiler::compile_path(path).expect_err("missing resource must fail");
        assert!(error.to_string().contains("site resource `missing`"));
    }

    #[test]
    fn rejects_implicit_service_reference_cycle() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  one:
    type: observe
    name: one
    service:
      ref: two
  two:
    type: observe
    name: two
    service:
      ref: one
listeners:
  - name: public
    bind: 127.0.0.1:7589
    service:
      ref: one
"#,
        );
        let error = Compiler::compile_path(path).expect_err("reference cycle must fail");
        assert!(error.to_string().contains("reference cycle"));
    }

    #[test]
    fn resolves_imports_relative_to_the_importing_file() {
        let directory = tempdir().expect("temporary directory is available");
        let service_path = directory.path().join("service.yaml");
        fs::write(
            &service_path,
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  imported:
    type: respond
    body:
      text: imported
"#,
        )
        .expect("import can be written");
        let root = directory.path().join("oxidase.yaml");
        fs::write(
            &root,
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
imports:
  - service.yaml
listeners:
  - name: public
    bind: 127.0.0.1:7589
    service:
      ref: imported
"#,
        )
        .expect("root can be written");
        let gateway = Compiler::compile_path(root).expect("import graph compiles");
        assert_eq!(gateway.dependencies.len(), 2);
    }

    #[test]
    fn imported_listener_inline_services_have_distinct_source_identities() {
        let directory = tempdir().expect("temporary directory is available");
        write_file(
            directory.path(),
            "a.yaml",
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: a
    bind: 127.0.0.1:7589
    service:
      type: respond
      body:
        text: A
"#,
        );
        write_file(
            directory.path(),
            "b.yaml",
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: b
    bind: 127.0.0.1:7590
    service:
      type: respond
      body:
        text: B
"#,
        );
        write_file(
            directory.path(),
            "root.yaml",
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
imports:
  - a.yaml
  - b.yaml
"#,
        );

        let gateway = Compiler::compile_path(directory.path().join("root.yaml"))
            .expect("import graph compiles");
        assert_ne!(gateway.listeners[0].service, gateway.listeners[1].service);
        assert_eq!(gateway.graph.len(), 2);
        assert_eq!(response_text(&gateway, "a"), "A");
        assert_eq!(response_text(&gateway, "b"), "B");
    }

    #[test]
    fn imported_nested_routes_and_children_have_distinct_source_identities() {
        let directory = tempdir().expect("temporary directory is available");
        for (file, listener, bind, body) in [
            ("a.yaml", "a", "127.0.0.1:7589", "A"),
            ("b.yaml", "b", "127.0.0.1:7590", "B"),
        ] {
            write_file(
                directory.path(),
                file,
                &format!(
                    r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: {listener}
    bind: {bind}
    service:
      type: route
      cases:
        - when:
            path: /matched
          service:
            type: respond
            body:
              text: {body}
"#
                ),
            );
        }
        write_file(
            directory.path(),
            "root.yaml",
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [a.yaml, b.yaml]
"#,
        );

        let root = directory.path().join("root.yaml");
        let first = Compiler::compile_path(&root).expect("import graph compiles");
        let second = Compiler::compile_path(&root).expect("repeat compile succeeds");

        let route = |gateway: &super::CompiledGateway, index: usize| {
            let entry = &gateway.listeners[index].service;
            let ServiceKind::Route { cases, .. } = &gateway
                .graph
                .get(entry)
                .expect("listener entry exists")
                .kind
            else {
                panic!("listener entry must be a Route");
            };
            (entry.clone(), cases[0].id.clone(), cases[0].service.clone())
        };
        let first_a = route(&first, 0);
        let first_b = route(&first, 1);
        assert_ne!(first_a.0, first_b.0);
        assert_ne!(first_a.1, first_b.1);
        assert_ne!(first_a.2, first_b.2);
        assert_eq!(first.graph.len(), 4);

        assert_eq!(first_a, route(&second, 0));
        assert_eq!(first_b, route(&second, 1));
        assert_eq!(
            first.graph.keys().collect::<Vec<_>>(),
            second.graph.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_value(first.summary()).expect("summary serializes"),
            serde_json::to_value(second.summary()).expect("summary serializes")
        );
    }

    #[test]
    fn duplicate_generated_service_id_is_an_error() {
        let source = MergedSource::default();
        let resources = CompiledResources::default();
        let mut builder = ProgramBuilder::new(&source, &resources);
        let node = |field_path: &str| ServiceNode {
            id: ServiceId::new("inline:s00000000:collision"),
            source: SourceSpan::synthetic(field_path),
            kind: ServiceKind::Respond {
                status: StatusCode::OK,
                headers: HeaderTransforms::default(),
                body: RespondBody::Empty,
            },
        };

        builder
            .insert_node(node("first"))
            .expect("first insertion succeeds");
        let error = builder
            .insert_node(node("second"))
            .expect_err("duplicate generated ID must fail");
        assert_eq!(error.diagnostics[0].code, "service.duplicate_internal_id");
        assert!(error.to_string().contains("first"));
        assert!(error.to_string().contains("second"));
    }

    #[test]
    fn rejects_user_controlled_response_framing_headers() {
        for name in ["Content-Length", "Connection", "Transfer-Encoding"] {
            let (_directory, path) = write_config(&format!(
                r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    headers:
      set:
        {name}: value
    body:
      text: body
listeners:
  - name: test
    bind: 127.0.0.1:7589
    service:
      ref: root
"#
            ));
            let error = Compiler::compile_path(path).expect_err("framing header must fail");
            assert_eq!(error.diagnostics[0].code, "service.forbidden_header");
            assert!(error.to_string().contains(name));
            assert!(error.to_string().contains("services.root.headers.set"));
        }
    }

    #[test]
    fn rejects_response_transform_of_managed_header() {
        let (_directory, path) = write_config(
            r#"
api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: transform
    response:
      headers:
        add:
          Trailer: X-Checksum
    service:
      type: respond
      body:
        text: body
listeners:
  - name: test
    bind: 127.0.0.1:7589
    service:
      ref: root
"#,
        );
        let error = Compiler::compile_path(path).expect_err("managed transform header must fail");
        assert_eq!(error.diagnostics[0].code, "service.forbidden_header");
        assert!(
            error
                .to_string()
                .contains("services.root.response.headers.add.Trailer")
        );
    }

    #[test]
    fn gateway_uses_shared_strict_yaml_subset() {
        let (_directory, path) =
            write_config("api_version: oxidase.dev/v1alpha1\nkind: gateway\nkind: gateway\n");
        let error = Compiler::compile_path(path).expect_err("duplicate Gateway key must fail");
        assert_eq!(error.diagnostics[0].code, "source.duplicate_key");
        assert_eq!(error.diagnostics[0].primary.line, 3);
    }

    #[test]
    fn compile_failures_report_discovered_and_missing_import_candidates() {
        let directory = tempdir().expect("temporary directory is available");
        let canonical_directory = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        let root = directory.path().join("root.yaml");
        let imported = directory.path().join("candidate.yaml");
        fs::write(
            &imported,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices: invalid\n",
        )
        .expect("invalid import can be written");
        fs::write(
            &root,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [candidate.yaml]\n",
        )
        .expect("root can be written");
        let error = Compiler::compile_path(&root).expect_err("invalid import must fail");
        assert!(
            error
                .discovered_dependencies
                .contains(&imported.canonicalize().expect("import canonicalizes"))
        );
        assert!(error.discovered_dependencies.contains(&canonical_directory));

        fs::write(
            &root,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [missing.yaml]\n",
        )
        .expect("root can be updated");
        let error = Compiler::compile_path(&root).expect_err("missing import must fail");
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical_directory.join("missing.yaml"))
        );
        assert!(error.discovered_dependencies.contains(&canonical_directory));
    }

    #[test]
    fn validates_constant_transformed_request_metadata() {
        for (field, value, code) in [
            ("scheme", "ftp", "service.transform_scheme"),
            (
                "authority",
                "user@example.com",
                "service.transform_authority",
            ),
            (
                "authority",
                "example.com:99999",
                "service.transform_authority",
            ),
            (
                "path",
                "https://evil.test/path",
                "service.transform_path_and_query",
            ),
            (
                "path",
                "\"/safe\\r\\nX-Evil: yes\"",
                "service.transform_path_and_query",
            ),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: transform
    request:
      {field}: {value}
    service:
      type: respond
      body:
        text: ok
listeners:
  - name: test
    bind: 127.0.0.1:7589
    service:
      ref: root
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid metadata must fail");
            assert_eq!(error.diagnostics[0].code, code);
            assert!(
                error.diagnostics[0]
                    .primary
                    .field_path
                    .contains(&format!("request.{field}"))
            );
        }

        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: transform
    request:
      scheme: https
      authority: "[::1]:8443"
      path: /rewritten?b=2&a=1&a=3
    service:
      type: respond
      body:
        text: ok
listeners:
  - name: test
    bind: 127.0.0.1:7589
    service:
      ref: root
"#,
        );
        Compiler::compile_path(path).expect("valid typed metadata compiles");
    }

    #[test]
    fn config_digest_is_stable_across_mapping_order_and_repeated_compilation() {
        let first = r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: respond
    status: 201
    body:
      text: stable
listeners:
  - name: test
    bind: 127.0.0.1:7589
    service:
      ref: root
"#;
        let second = r#"listeners:
  - service:
      ref: root
    bind: 127.0.0.1:7589
    name: test
services:
  root:
    body:
      text: stable
    status: 201
    type: respond
kind: gateway
api_version: oxidase.dev/v1alpha1
"#;
        let (_first_directory, first_path) = write_config(first);
        let (_second_directory, second_path) = write_config(second);
        let first = Compiler::compile_path(&first_path).expect("first config compiles");
        let repeated = Compiler::compile_path(&first_path).expect("repeat config compiles");
        let second = Compiler::compile_path(&second_path).expect("reordered config compiles");
        assert_eq!(first.config_version, repeated.config_version);
        assert_eq!(first.config_version, second.config_version);
        assert!(first.config_version.as_str().starts_with("v2-sha256-"));
        assert_eq!(first.config_version.as_str().len(), "v2-sha256-".len() + 64);
    }

    #[test]
    fn semantic_diagnostics_use_exact_field_spans_after_crlf_block_scalars() {
        let (_directory, path) = write_config(concat!(
            "api_version: oxidase.dev/v1alpha1\r\n",
            "kind: gateway\r\n",
            "services:\r\n",
            "  root:\r\n",
            "    type: respond\r\n",
            "    body:\r\n",
            "      text: |-\r\n",
            "        雪: remains template text\r\n",
            "        duplicate: remains text\r\n",
            "listeners:\r\n",
            "  - name: public\r\n",
            "    bind: not-an-address\r\n",
            "    service:\r\n",
            "      ref: root\r\n",
        ));
        let error = Compiler::compile_path(path).expect_err("invalid bind must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "listener.bind");
        assert_eq!(
            (diagnostic.primary.line, diagnostic.primary.column),
            (12, 11)
        );
        assert_eq!(diagnostic.primary.field_path, "listeners[0].bind");
        assert!(diagnostic.primary.end_byte > diagnostic.primary.start_byte);
    }

    #[test]
    fn missing_service_reference_points_to_the_reference_value() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: public
    bind: 127.0.0.1:8080
    service:
      ref: missing
"#,
        );
        let error = Compiler::compile_path(path).expect_err("missing service must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "service.reference");
        assert_eq!(
            (diagnostic.primary.line, diagnostic.primary.column),
            (7, 12)
        );
        assert_eq!(diagnostic.primary.field_path, "listeners[0].service.ref");
    }

    #[test]
    fn duplicate_imported_definitions_report_both_exact_spans() {
        let directory = tempdir().expect("temporary directory is available");
        for name in ["a.yaml", "b.yaml"] {
            fs::write(
                directory.path().join(name),
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  duplicate:\n    type: respond\n",
            )
            .expect("import can be written");
        }
        let root = directory.path().join("oxidase.yaml");
        fs::write(
            &root,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [a.yaml, b.yaml]\n",
        )
        .expect("root config can be written");
        let error = Compiler::compile_path(root).expect_err("duplicate service must fail");
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.duplicate_definition")
            .expect("duplicate diagnostic is present");
        assert_eq!((diagnostic.primary.line, diagnostic.primary.column), (4, 3));
        assert!(diagnostic.primary.file.ends_with("b.yaml"));
        assert_eq!(diagnostic.labels.len(), 1);
        assert!(diagnostic.labels[0].span.file.ends_with("a.yaml"));
        assert_eq!(diagnostic.reference_chain.len(), 2);
        assert!(
            diagnostic.reference_chain[0]
                .span
                .as_ref()
                .expect("first definition has a span")
                .file
                .ends_with("a.yaml")
        );
        assert!(
            diagnostic.reference_chain[1]
                .span
                .as_ref()
                .expect("duplicate definition has a span")
                .file
                .ends_with("b.yaml")
        );
    }

    #[test]
    fn import_cycles_retain_every_exact_edge_span() {
        let directory = tempdir().expect("temporary directory is available");
        let root = directory.path().join("oxidase.yaml");
        let imported = directory.path().join("a.yaml");
        fs::write(
            &root,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [a.yaml]\n",
        )
        .expect("root config can be written");
        fs::write(
            &imported,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [oxidase.yaml]\n",
        )
        .expect("import can be written");

        let error = Compiler::compile_path(&root).expect_err("import cycle must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "config.import_cycle");
        assert_eq!(diagnostic.reference_chain.len(), 2);
        let spans = diagnostic
            .reference_chain
            .iter()
            .map(|reference| {
                reference
                    .span
                    .as_ref()
                    .expect("every import edge has an exact span")
            })
            .collect::<Vec<_>>();
        assert!(spans[0].file.ends_with("oxidase.yaml"));
        assert!(spans[1].file.ends_with("a.yaml"));
        assert!(spans.iter().all(|span| span.field_path == "imports[0]"));
        assert_eq!(diagnostic.primary, *spans[1]);
    }

    #[test]
    fn legacy_http_listener_defaults_to_http1() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: public
    bind: 127.0.0.1:8080
    service:
      type: respond
"#,
        );
        let gateway = Compiler::compile_path(path).expect("legacy listener compiles");
        let listener = &gateway.listeners[0];
        assert_eq!(listener.protocol, super::ListenerProtocol::Http);
        assert!(listener.tls.is_none());
        assert_eq!(listener.http.versions, vec![super::HttpVersion::Http1]);
        assert_eq!(
            listener
                .http
                .http1
                .as_ref()
                .expect("HTTP/1 settings exist")
                .header_read_timeout,
            std::time::Duration::from_secs(30)
        );
        assert!(listener.http.http2.is_none());
    }

    #[test]
    fn https_defaults_to_h2_then_http1_and_resolves_certificate_paths() {
        let directory = tempdir().expect("temporary directory is available");
        fs::create_dir_all(directory.path().join("config/certs"))
            .expect("certificate directory can be created");
        let cert = directory.path().join("config/certs/public.pem");
        let key = directory.path().join("config/certs/public-key.pem");
        fs::write(&cert, "test certificate bytes").expect("certificate can be written");
        fs::write(&key, "TEST-ONLY PRIVATE KEY CONTENT").expect("private key can be written");
        write_file(
            directory.path(),
            "config/resources.yaml",
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: certs/public.pem
      private_key: certs/public-key.pem
"#,
        );
        write_file(
            directory.path(),
            "oxidase.yaml",
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [config/resources.yaml]
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
    service:
      type: respond
"#,
        );

        let gateway = Compiler::compile_path(directory.path().join("oxidase.yaml"))
            .expect("HTTPS listener compiles");
        let listener = &gateway.listeners[0];
        assert_eq!(listener.protocol, super::ListenerProtocol::Https);
        assert_eq!(
            listener.http.versions,
            vec![super::HttpVersion::H2, super::HttpVersion::Http1]
        );
        assert!(listener.http.http1.is_some());
        let http2 = listener.http.http2.as_ref().expect("HTTP/2 settings exist");
        assert_eq!(http2.max_concurrent_streams, 256);
        assert_eq!(http2.max_header_list_size, 64 * 1024);
        assert_eq!(
            http2.keep_alive_interval,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(http2.keep_alive_timeout, std::time::Duration::from_secs(10));
        assert_eq!(
            listener
                .tls
                .as_ref()
                .expect("TLS settings exist")
                .handshake_timeout,
            std::time::Duration::from_secs(5)
        );

        let certificate = gateway
            .resources
            .certificates
            .get(&oxidase_core::ResourceId::new("certificate:public"))
            .expect("certificate exists");
        assert_eq!(
            certificate.cert_chain,
            cert.canonicalize().expect("cert canonicalizes")
        );
        assert_eq!(
            certificate.private_key,
            key.canonicalize().expect("key canonicalizes")
        );
        assert!(gateway.dependencies.contains(&certificate.cert_chain));
        assert!(gateway.dependencies.contains(&certificate.private_key));

        let summary = serde_json::to_string(&gateway.summary()).expect("summary serializes");
        assert!(summary.contains("certificate:public"));
        assert!(!summary.contains("TEST-ONLY PRIVATE KEY CONTENT"));
    }

    #[test]
    fn compiles_normalized_exact_and_single_label_wildcard_sni_rules() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    default:
      cert_chain: default.pem
      private_key: default-key.pem
    api:
      cert_chain: api.pem
      private_key: api-key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: default
      sni:
        API.Example.COM: api
        "*.internal.example.com": api
    service:
      type: respond
"#,
        );
        let gateway = Compiler::compile_path(path).expect("SNI rules compile");
        let tls = gateway.listeners[0]
            .tls
            .as_ref()
            .expect("TLS settings exist");
        let sni = &tls.sni;
        assert_eq!(sni.len(), 2);
        assert!(sni.iter().any(|rule| {
            rule.pattern == super::SniPattern::Exact("api.example.com".to_owned())
                && rule.pattern.matches("API.EXAMPLE.COM")
        }));
        let wildcard = sni
            .iter()
            .find(|rule| matches!(rule.pattern, super::SniPattern::Wildcard(_)))
            .expect("wildcard exists");
        assert!(wildcard.pattern.matches("one.internal.example.com"));
        assert!(!wildcard.pattern.matches("a.b.internal.example.com"));
        assert!(!wildcard.pattern.matches("internal.example.com"));
        assert_eq!(
            tls.select_certificate(Some("api.example.com")).as_str(),
            "certificate:api"
        );
        assert_eq!(
            tls.select_certificate(Some("one.internal.example.com"))
                .as_str(),
            "certificate:api"
        );
        assert_eq!(
            tls.select_certificate(Some("unknown.example.com")).as_str(),
            "certificate:default"
        );
        assert_eq!(tls.select_certificate(None).as_str(), "certificate:default");
    }

    #[test]
    fn rejects_duplicate_normalized_sni_rules_with_both_spans() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
      sni:
        API.Example.COM: public
        api.example.com: public
    service:
      type: respond
"#,
        );
        let error = Compiler::compile_path(path).expect_err("duplicate SNI must fail");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "listener.sni_duplicate");
        assert_eq!(diagnostic.primary.line, 16);
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(diagnostic.labels[0].span.line, 15);
    }

    #[test]
    fn rejects_invalid_sni_rule_forms() {
        for rule in [
            "",
            "127.0.0.1",
            "*.127.0.0.1",
            "foo.*.example.com",
            "*.*.example.com",
            "foo..example.com",
            "foo_example.com",
            "example.123",
            "*.example.com.",
            "雪.example.com",
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
      sni:
        "{rule}": public
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid SNI must fail");
            assert_eq!(error.diagnostics[0].code, "listener.sni", "rule: {rule}");
            assert_eq!(error.diagnostics[0].primary.line, 15, "rule: {rule}");
        }
    }

    #[test]
    fn enforces_protocol_tls_and_http_version_boundaries() {
        let cases = [
            (
                r#"protocol: http
    tls:
      default_certificate: public"#,
                "listener.tls_forbidden",
                "listeners[0].tls",
            ),
            (
                "protocol: https",
                "listener.tls_required",
                "listeners[0].protocol",
            ),
            (
                r#"protocol: http
    http:
      versions: [http1, h2]"#,
                "listener.h2c_unsupported",
                "listeners[0].http.versions[1]",
            ),
            (
                r#"protocol: https
    tls:
      default_certificate: public
    http:
      versions: []"#,
                "listener.http_versions",
                "listeners[0].http.versions",
            ),
            (
                r#"protocol: https
    tls:
      default_certificate: public
    http:
      versions: [h2, h2]"#,
                "listener.http_version_duplicate",
                "listeners[0].http.versions[1]",
            ),
            (
                r#"protocol: https
    tls:
      default_certificate: public
    http:
      versions: [h2]
      http1:
        header_read_timeout: 1s"#,
                "listener.http1_settings_disabled",
                "listeners[0].http.http1",
            ),
            (
                r#"protocol: https
    tls:
      default_certificate: public
    http:
      versions: [http1]
      http2:
        max_concurrent_streams: 1"#,
                "listener.http2_settings_disabled",
                "listeners[0].http.http2",
            ),
        ];
        for (listener_fields, code, field_path) in cases {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: public
    bind: 127.0.0.1:8443
    {listener_fields}
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid transport must fail");
            assert_eq!(error.diagnostics[0].code, code);
            assert_eq!(error.diagnostics[0].primary.field_path, field_path);
            assert!(
                error.diagnostics[0].primary.end_byte > error.diagnostics[0].primary.start_byte
            );
        }
    }

    #[test]
    fn validates_certificate_references_with_exact_spans() {
        for (tls, line, field_path) in [
            (
                "default_certificate: missing",
                13,
                "listeners[0].tls.default_certificate",
            ),
            (
                "default_certificate: public\n      sni:\n        api.example.com: missing",
                15,
                "listeners[0].tls.sni[\"api.example.com\"]",
            ),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      {tls}
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("unknown certificate must fail");
            let diagnostic = &error.diagnostics[0];
            assert_eq!(diagnostic.code, "listener.certificate_reference");
            assert_eq!(diagnostic.primary.line, line);
            assert_eq!(diagnostic.primary.field_path, field_path);
        }
    }

    #[test]
    fn validates_http_timeouts_stream_limits_and_header_sizes() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
      handshake_timeout: 2500ms
    http:
      versions: [h2, http1]
      http1:
        header_read_timeout: 45s
      http2:
        max_concurrent_streams: 128
        max_header_list_size: 1MiB
        keep_alive_interval: 1m
        keep_alive_timeout: 7s
    service:
      type: respond
"#,
        );
        let gateway = Compiler::compile_path(path).expect("custom transport settings compile");
        let listener = &gateway.listeners[0];
        assert_eq!(
            listener.tls.as_ref().expect("TLS exists").handshake_timeout,
            std::time::Duration::from_millis(2500)
        );
        assert_eq!(
            listener
                .http
                .http1
                .as_ref()
                .expect("HTTP/1 exists")
                .header_read_timeout,
            std::time::Duration::from_secs(45)
        );
        let http2 = listener.http.http2.as_ref().expect("HTTP/2 exists");
        assert_eq!(http2.max_concurrent_streams, 128);
        assert_eq!(http2.max_header_list_size, 1024 * 1024);
        assert_eq!(
            http2.keep_alive_interval,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(http2.keep_alive_timeout, std::time::Duration::from_secs(7));

        for (field, value, code) in [
            (
                "max_concurrent_streams",
                "0",
                "listener.http2_max_concurrent_streams",
            ),
            ("max_header_list_size", "0B", "config.byte_size"),
            ("max_header_list_size", "64KB", "config.byte_size"),
            ("keep_alive_interval", "0s", "config.duration"),
            ("keep_alive_timeout", "forever", "config.duration"),
        ] {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
    http:
      versions: [h2]
      http2:
        {field}: {value}
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("invalid setting must fail");
            assert_eq!(error.diagnostics[0].code, code, "field: {field}");
            assert!(
                error.diagnostics[0].primary.field_path.ends_with(field),
                "field: {field}"
            );
        }
    }

    #[test]
    fn rejects_empty_certificate_paths_at_the_declared_field() {
        for (field, field_path) in [
            ("cert_chain", "resources.certificates.public.cert_chain"),
            ("private_key", "resources.certificates.public.private_key"),
        ] {
            let cert_chain = if field == "cert_chain" {
                "\"\""
            } else {
                "cert.pem"
            };
            let private_key = if field == "private_key" {
                "\"\""
            } else {
                "key.pem"
            };
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: {cert_chain}
      private_key: {private_key}
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("empty path must fail");
            assert_eq!(error.diagnostics[0].code, "resource.certificate_path");
            assert_eq!(error.diagnostics[0].primary.field_path, field_path);
            assert_eq!(
                error.diagnostics[0].primary.line,
                6 + usize::from(field == "private_key")
            );
        }
    }

    #[test]
    fn certificate_dependencies_survive_later_semantic_failure() {
        let directory = tempdir().expect("temporary directory is available");
        let root = directory.path().join("oxidase.yaml");
        let canonical_directory = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        let cert = canonical_directory.join("missing/cert.pem");
        let key = canonical_directory.join("missing/key.pem");
        fs::write(
            &root,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: missing/cert.pem
      private_key: missing/key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: unknown
    service:
      type: respond
"#,
        )
        .expect("config can be written");
        let error = Compiler::compile_path(root).expect_err("unknown reference must fail");
        assert!(error.discovered_dependencies.contains(&cert));
        assert!(error.discovered_dependencies.contains(&key));
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical_directory.join("missing"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn certificate_dependency_preserves_declared_symlink_path() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory is available");
        let canonical_directory = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        fs::write(canonical_directory.join("cert-v1.pem"), "certificate")
            .expect("certificate can be written");
        fs::write(canonical_directory.join("key.pem"), "key").expect("key can be written");
        symlink("cert-v1.pem", canonical_directory.join("cert.pem"))
            .expect("certificate symlink can be created");
        fs::write(
            canonical_directory.join("oxidase.yaml"),
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    public:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: public
    service:
      type: respond
"#,
        )
        .expect("config can be written");
        let gateway = Compiler::compile_path(canonical_directory.join("oxidase.yaml"))
            .expect("config compiles");
        let certificate = gateway
            .resources
            .certificates
            .get(&oxidase_core::ResourceId::new("certificate:public"))
            .expect("certificate exists");
        let declared = canonical_directory.join("cert.pem");
        assert_eq!(certificate.cert_chain, declared);
        assert_ne!(
            certificate.cert_chain,
            canonical_directory.join("cert-v1.pem")
        );
        assert!(gateway.dependencies.contains(&declared));
        assert!(gateway.dependencies.contains(&canonical_directory));
    }

    #[test]
    fn duplicate_imported_certificate_definitions_report_both_spans() {
        let directory = tempdir().expect("temporary directory is available");
        for name in ["a.yaml", "b.yaml"] {
            fs::write(
                directory.path().join(name),
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  certificates:\n    duplicate:\n      cert_chain: cert.pem\n      private_key: key.pem\n",
            )
            .expect("import can be written");
        }
        let root = directory.path().join("oxidase.yaml");
        fs::write(
            &root,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nimports: [a.yaml, b.yaml]\nlisteners:\n  - name: public\n    bind: 127.0.0.1:8080\n    service:\n      type: respond\n",
        )
        .expect("root config can be written");
        let error = Compiler::compile_path(root).expect_err("duplicate certificate must fail");
        let diagnostic = error
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "config.duplicate_definition")
            .expect("duplicate diagnostic exists");
        assert!(diagnostic.message.contains("certificate resource"));
        assert_eq!(diagnostic.primary.line, 5);
        assert_eq!(diagnostic.labels.len(), 1);
        assert_eq!(diagnostic.labels[0].span.line, 5);
        assert!(diagnostic.primary.file.ends_with("b.yaml"));
        assert!(diagnostic.labels[0].span.file.ends_with("a.yaml"));
    }

    #[test]
    fn compiles_secret_trust_and_mutual_tls_policies_with_exact_spans() {
        let (directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    admin-token:
      file: secrets/admin-token
      max_bytes: 8KiB
  trust_stores:
    internal-ca:
      ca_bundle: pki/internal-ca.pem
  certificates:
    gateway:
      cert_chain: pki/gateway.pem
      private_key: pki/gateway-key.pem
    upstream-client:
      cert_chain: pki/client.pem
      private_key: pki/client-key.pem
  clusters:
    api:
      endpoints:
        - https://127.0.0.1:8443
      tls:
        server_name: API.Internal.Example
        trust:
          system_roots: false
          trust_store: internal-ca
        client_certificate: upstream-client
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: gateway
      client_auth:
        mode: required
        trust_store: internal-ca
    service:
      type: proxy
      cluster: api
"#,
        );

        let gateway = Compiler::compile_path(path).expect("mutual TLS source compiles");
        let canonical_directory = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        let secret = gateway
            .resources
            .secrets
            .get(&oxidase_core::ResourceId::new("secret:admin-token"))
            .expect("secret exists");
        assert_eq!(secret.file, canonical_directory.join("secrets/admin-token"));
        assert_eq!(secret.max_bytes, 8 * 1_024);
        assert_eq!(
            secret.file_source.field_path,
            "resources.secrets[\"admin-token\"].file"
        );
        assert_eq!(
            secret.max_bytes_source.field_path,
            "resources.secrets[\"admin-token\"].max_bytes"
        );
        assert!(gateway.dependencies.contains(&secret.file));
        assert!(!gateway.summary_dependencies.contains(&secret.file));

        let trust = gateway
            .resources
            .trust_stores
            .get(&oxidase_core::ResourceId::new("trust_store:internal-ca"))
            .expect("trust store exists");
        assert_eq!(
            trust.ca_bundle,
            canonical_directory.join("pki/internal-ca.pem")
        );
        assert_eq!(
            trust.ca_bundle_source.field_path,
            "resources.trust_stores[\"internal-ca\"].ca_bundle"
        );
        assert!(gateway.dependencies.contains(&trust.ca_bundle));
        assert!(gateway.summary_dependencies.contains(&trust.ca_bundle));
        let private_key = canonical_directory.join("pki/gateway-key.pem");
        assert!(gateway.dependencies.contains(&private_key));
        assert!(!gateway.summary_dependencies.contains(&private_key));
        let summary = serde_json::to_string(&gateway.summary()).expect("summary serializes");
        assert!(!summary.contains("secrets/admin-token"));
        assert!(!summary.contains("gateway-key.pem"));
        let resources_debug = format!("{:?}", gateway.resources);
        assert!(resources_debug.contains("<redacted path>"));
        assert!(!resources_debug.contains("secrets/admin-token"));
        assert!(!resources_debug.contains("gateway-key.pem"));
        let gateway_debug = format!("{gateway:?}");
        assert!(!gateway_debug.contains("secrets/admin-token"));
        assert!(!gateway_debug.contains("gateway-key.pem"));

        let tls = gateway
            .resources
            .clusters
            .get(&oxidase_core::ResourceId::new("cluster:api"))
            .and_then(|cluster| cluster.tls.as_ref())
            .expect("cluster TLS exists");
        assert_eq!(tls.server_name.as_deref(), Some("api.internal.example"));
        assert!(!tls.trust.system_roots);
        assert_eq!(
            tls.trust.trust_store.as_ref().map(|id| id.as_str()),
            Some("trust_store:internal-ca")
        );
        assert_eq!(
            tls.client_certificate.as_ref().map(|id| id.as_str()),
            Some("certificate:upstream-client")
        );
        assert_eq!(
            tls.server_name_source
                .as_ref()
                .expect("server-name span")
                .field_path,
            "resources.clusters.api.tls.server_name"
        );
        assert_eq!(
            tls.trust
                .trust_store_source
                .as_ref()
                .expect("trust-store span")
                .field_path,
            "resources.clusters.api.tls.trust.trust_store"
        );
        assert_eq!(
            tls.client_certificate_source
                .as_ref()
                .expect("client-certificate span")
                .field_path,
            "resources.clusters.api.tls.client_certificate"
        );

        let client_auth = &gateway.listeners[0]
            .tls
            .as_ref()
            .expect("listener TLS exists")
            .client_auth;
        assert_eq!(client_auth.mode, super::ClientAuthMode::Required);
        assert_eq!(
            client_auth.trust_store.as_ref().map(|id| id.as_str()),
            Some("trust_store:internal-ca")
        );
        assert_eq!(
            client_auth.mode_source.field_path,
            "listeners[0].tls.client_auth.mode"
        );
        assert_eq!(
            client_auth
                .trust_store_source
                .as_ref()
                .expect("client-auth trust span")
                .field_path,
            "listeners[0].tls.client_auth.trust_store"
        );
    }

    #[test]
    fn preserves_secret_and_client_auth_defaults() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    token:
      file: token.txt
  certificates:
    gateway:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: gateway
    service:
      type: respond
"#,
        );
        let gateway = Compiler::compile_path(path).expect("defaults compile");
        assert_eq!(
            gateway
                .resources
                .secrets
                .get(&oxidase_core::ResourceId::new("secret:token"))
                .expect("secret exists")
                .max_bytes,
            64 * 1_024
        );
        let auth = &gateway.listeners[0]
            .tls
            .as_ref()
            .expect("TLS exists")
            .client_auth;
        assert_eq!(auth.mode, super::ClientAuthMode::None);
        assert!(auth.trust_store.is_none());
    }

    #[test]
    fn validates_listener_client_auth_contract_at_the_declared_field() {
        let cases = [
            (
                "mode: sometimes",
                "listener.client_auth_mode",
                "listeners[0].tls.client_auth.mode",
            ),
            (
                "mode: none\n        trust_store: internal-ca",
                "listener.client_auth_trust_forbidden",
                "listeners[0].tls.client_auth.trust_store",
            ),
            (
                "mode: required",
                "listener.client_auth_trust_required",
                "listeners[0].tls.client_auth",
            ),
            (
                "mode: optional\n        trust_store: missing",
                "listener.trust_store_reference",
                "listeners[0].tls.client_auth.trust_store",
            ),
        ];
        for (client_auth, code, field_path) in cases {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  trust_stores:
    internal-ca:
      ca_bundle: ca.pem
  certificates:
    gateway:
      cert_chain: cert.pem
      private_key: key.pem
listeners:
  - name: secure
    bind: 127.0.0.1:8443
    protocol: https
    tls:
      default_certificate: gateway
      client_auth:
        {client_auth}
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("client-auth source must fail");
            assert_eq!(error.diagnostics[0].code, code, "source: {client_auth}");
            assert_eq!(
                error.diagnostics[0].primary.field_path, field_path,
                "source: {client_auth}"
            );
        }
    }

    #[test]
    fn validates_cluster_tls_policy_and_references() {
        let cases = [
            (
                "http://127.0.0.1:8080",
                "server_name: api.internal.example".to_owned(),
                "resource.cluster_tls_inert",
                "resources.clusters.api.tls",
            ),
            (
                "https://127.0.0.1:8443",
                "trust:\n          system_roots: false".to_owned(),
                "resource.cluster_tls_trust_empty",
                "resources.clusters.api.tls.trust",
            ),
            (
                "https://127.0.0.1:8443",
                "server_name: \"bad name\"".to_owned(),
                "resource.cluster_tls_server_name",
                "resources.clusters.api.tls.server_name",
            ),
            (
                "https://127.0.0.1:8443",
                "trust:\n          trust_store: missing".to_owned(),
                "resource.cluster_trust_store_reference",
                "resources.clusters.api.tls.trust.trust_store",
            ),
            (
                "https://127.0.0.1:8443",
                "client_certificate: missing".to_owned(),
                "resource.cluster_client_certificate_reference",
                "resources.clusters.api.tls.client_certificate",
            ),
        ];
        for (endpoint, tls, code, field_path) in cases {
            let (_directory, path) = write_config(&format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints: [{endpoint}]
      tls:
        {tls}
listeners:
  - name: public
    bind: 127.0.0.1:8080
    service:
      type: respond
"#
            ));
            let error = Compiler::compile_path(path).expect_err("cluster TLS source must fail");
            assert_eq!(error.diagnostics[0].code, code, "TLS: {tls}");
            assert_eq!(
                error.diagnostics[0].primary.field_path, field_path,
                "TLS: {tls}"
            );
        }
    }

    #[test]
    fn rejects_empty_resource_paths_and_zero_secret_limit() {
        let cases = [
            (
                "secrets:\n    value:\n      file: \"\"",
                "resource.secret_path",
                "resources.secrets.value.file",
            ),
            (
                "secrets:\n    value:\n      file: value\n      max_bytes: 0B",
                "config.byte_size",
                "resources.secrets.value.max_bytes",
            ),
            (
                "trust_stores:\n    roots:\n      ca_bundle: \"\"",
                "resource.trust_store_path",
                "resources.trust_stores.roots.ca_bundle",
            ),
        ];
        for (resources, code, field_path) in cases {
            let (_directory, path) = write_config(&format!(
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  {resources}\nlisteners:\n  - name: public\n    bind: 127.0.0.1:8080\n    service:\n      type: respond\n"
            ));
            let error = Compiler::compile_path(path).expect_err("invalid resource must fail");
            assert_eq!(error.diagnostics[0].code, code, "resource: {resources}");
            assert_eq!(
                error.diagnostics[0].primary.field_path, field_path,
                "resource: {resources}"
            );
        }
    }

    #[test]
    fn secret_and_trust_dependencies_survive_semantic_failure() {
        let directory = tempdir().expect("temporary directory is available");
        let root = directory.path().join("oxidase.yaml");
        fs::write(
            &root,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    gateway:
      cert_chain: missing/public.pem
      private_key: missing/distinctive-private-key.pem
  secrets:
    token:
      file: missing/token
  trust_stores:
    roots:
      ca_bundle: missing/ca.pem
listeners:
  - name: public
    bind: not-an-address
    service:
      type: respond
"#,
        )
        .expect("config can be written");
        let error = Compiler::compile_path(root).expect_err("listener bind must fail");
        let canonical = directory
            .path()
            .canonicalize()
            .expect("temporary directory canonicalizes");
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical.join("missing/token"))
        );
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical.join("missing/ca.pem"))
        );
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical.join("missing"))
        );
        assert!(
            error
                .discovered_dependencies
                .contains(&canonical.join("missing/distinctive-private-key.pem"))
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains("missing/token"));
        assert!(!debug.contains("distinctive-private-key.pem"));
    }

    #[test]
    fn strict_yaml_rejects_unknown_nested_trust_fields() {
        let (_directory, path) = write_config(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  trust_stores:
    roots:
      ca_bundle: ca.pem
      accepted_but_inert: true
listeners:
  - name: public
    bind: 127.0.0.1:8080
    service:
      type: respond
"#,
        );
        let error = Compiler::compile_path(path).expect_err("unknown field must fail");
        assert_eq!(error.diagnostics[0].code, "source.parse");
        assert!(error.diagnostics[0].message.contains("accepted_but_inert"));
    }
}
