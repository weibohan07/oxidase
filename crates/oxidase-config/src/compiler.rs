use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use oxidase_core::{
    CompiledMetadata, CompiledPattern, CompiledTemplate, ConfigVersion, ContentDigest,
    ContentDigestBuilder, DiagnosticReference, ErrorClass, Expression, HeaderPredicate,
    HeaderTransform, HeaderTransforms, ListenerId, PatternContext, PredicatePlan, RecoverHandler,
    RequestMetadataError, RequestTransform, ResourceId, RespondBody, ResponseTransform, RouteCase,
    RouteId, ServiceGraph, ServiceId, ServiceKind, ServiceNode, ServiceProgram, SourceSpan, Value,
    is_forbidden_user_header, parse_transform_authority, parse_transform_path_and_query,
    parse_transform_scheme,
};
use serde::Serialize;
use url::Url;

use oxidase_source::{FieldSpanIndex, SourceDocument, field_path_child};

use crate::API_VERSION;
use crate::diagnostic::{CompileError, Diagnostic};
use crate::source::{
    BodySource, CertificateSource, ClusterSource, ConfigTestSource, ErrorClassSource,
    GatewaySource, HeadersSource, Http1SettingsSource, Http2SettingsSource, HttpListenerSource,
    HttpVersionSource, InlineServiceSource, ListenerProtocolSource, ListenerSource,
    PredicateSource, RedirectQuerySource, RequestTransformSource, ResourcesSource,
    ResponseTransformSource, ServiceSource, SiteSource, TlsListenerSource,
};

#[derive(Debug, Clone)]
pub struct CompiledGateway {
    pub source: PathBuf,
    pub config_version: ConfigVersion,
    pub dependencies: Vec<PathBuf>,
    pub graph: Arc<ServiceGraph>,
    pub resources: CompiledResources,
    pub listeners: Vec<CompiledListener>,
    pub tests: Vec<ConfigTestSource>,
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
            dependencies: self
                .dependencies
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
                .keys()
                .map(ToString::to_string)
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

#[derive(Debug, Clone, Default)]
pub struct CompiledResources {
    pub certificates: BTreeMap<ResourceId, CertificateSpec>,
    pub clusters: BTreeMap<ResourceId, ClusterSpec>,
    pub sites: BTreeMap<ResourceId, SiteSpec>,
}

/// Paths and source locations for one inbound TLS certificate resource.
///
/// Certificate and private-key bytes are deliberately not part of the
/// compiled configuration. The server preparation boundary reads and validates
/// them without making secret material inspectable through this IR.
#[derive(Debug, Clone)]
pub struct CertificateSpec {
    pub id: ResourceId,
    pub cert_chain: PathBuf,
    pub private_key: PathBuf,
    pub cert_chain_source: SourceSpan,
    pub private_key_source: SourceSpan,
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct ClusterSpec {
    pub id: ResourceId,
    pub endpoints: Vec<Url>,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
    pub source: SourceSpan,
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
    pub service: ServiceId,
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
    pub source: SourceSpan,
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
    pub dependencies: Vec<String>,
    pub listeners: Vec<ListenerSummary>,
    pub services: Vec<String>,
    pub certificates: Vec<String>,
    pub clusters: Vec<String>,
    pub sites: Vec<String>,
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
            let resources = compile_resources(&merged)?;

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
                dependencies: merged.dependencies,
                graph,
                resources,
                listeners,
                tests: merged
                    .tests
                    .into_iter()
                    .map(|located| located.value)
                    .collect(),
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
    certificates: BTreeMap<String, Located<CertificateSource>>,
    clusters: BTreeMap<String, Located<ClusterSource>>,
    sites: BTreeMap<String, Located<SiteSource>>,
    services: BTreeMap<String, Located<ServiceSource>>,
    listeners: Vec<Located<ListenerSource>>,
    tests: Vec<Located<ConfigTestSource>>,
    merge_errors: Vec<Diagnostic>,
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

fn compile_resources(merged: &MergedSource) -> Result<CompiledResources, CompileError> {
    let mut resources = CompiledResources::default();
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
    for (name, located) in &merged.clusters {
        if located.value.endpoints.is_empty() {
            return Err(semantic_error_at(
                "resource.cluster_empty",
                "cluster must contain at least one endpoint",
                located.span_at(&format!("{}.endpoints", located.field_path)),
            ));
        }
        let mut endpoints = Vec::new();
        for (index, endpoint) in located.value.endpoints.iter().enumerate() {
            let endpoint_span =
                located.span_at(&format!("{}.endpoints[{index}]", located.field_path));
            let url = Url::parse(endpoint).map_err(|error| {
                semantic_error_at(
                    "resource.endpoint",
                    format!("invalid endpoint `{endpoint}`: {error}"),
                    endpoint_span.clone(),
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
                        "endpoint `{endpoint}` must be an http(s) origin/path without credentials, query, or fragment"
                    ),
                    endpoint_span,
                ));
            }
            endpoints.push(url);
        }
        let id = ResourceId::new(format!("cluster:{name}"));
        resources.clusters.insert(
            id.clone(),
            ClusterSpec {
                id,
                endpoints,
                connect_timeout: parse_duration(
                    &located.value.connect_timeout,
                    &located.span_at(&format!("{}.connect_timeout", located.field_path)),
                )?,
                response_timeout: parse_duration(
                    &located.value.response_timeout,
                    &located.span_at(&format!("{}.response_timeout", located.field_path)),
                )?,
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
    Ok(resources)
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
            InlineServiceSource::Observe { name, service } => Ok(ServiceKind::Observe {
                name: name.clone(),
                service: self.compile_service(
                    service,
                    context,
                    &format!("{field_path}.service"),
                )?,
            }),
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
        ErrorClassSource::SiteIo => ErrorClass::SiteIo,
        ErrorClassSource::TemplateLimit => ErrorClass::TemplateLimit,
        ErrorClassSource::BodyUnavailable => ErrorClass::BodyUnavailable,
        ErrorClassSource::InvalidState => ErrorClass::InvalidState,
        ErrorClassSource::Internal => ErrorClass::Internal,
    }
}

fn parse_duration(source: &str, source_span: &SourceSpan) -> Result<Duration, CompileError> {
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
    if millis == 0 {
        return Err(CompileError::one(Diagnostic::new(
            "config.duration",
            "duration must be greater than zero",
            source_span.clone(),
        )));
    }
    Ok(Duration::from_millis(millis))
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
        HeaderTransforms, RespondBody, ServiceId, ServiceKind, ServiceNode, SourceSpan,
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
}
