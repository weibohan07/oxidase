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
    CompiledPattern, CompiledTemplate, ConfigVersion, ErrorClass, Expression, HeaderPredicate,
    HeaderTransform, HeaderTransforms, ListenerId, PatternContext, PredicatePlan, RecoverHandler,
    RequestTransform, ResourceId, RespondBody, ResponseTransform, RouteCase, RouteId, ServiceGraph,
    ServiceId, ServiceKind, ServiceNode, ServiceProgram, SourceSpan, Value,
    is_forbidden_user_header,
};
use serde::Serialize;
use url::Url;

use crate::diagnostic::{CompileError, Diagnostic};
use crate::source::{
    BodySource, ClusterSource, ConfigTestSource, ErrorClassSource, GatewaySource, HeadersSource,
    InlineServiceSource, ListenerProtocolSource, ListenerSource, PredicateSource,
    RedirectQuerySource, RequestTransformSource, ResourcesSource, ResponseTransformSource,
    ServiceSource, SiteSource,
};
use crate::{API_VERSION, strict_yaml};

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
    pub clusters: BTreeMap<ResourceId, ClusterSpec>,
    pub sites: BTreeMap<ResourceId, SiteSpec>,
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
    pub source: SourceSpan,
}

#[derive(Debug, Clone)]
pub struct CompiledListener {
    pub id: ListenerId,
    pub name: String,
    pub bind: SocketAddr,
    pub service: ServiceId,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewaySummary {
    pub config_version: String,
    pub source: String,
    pub dependencies: Vec<String>,
    pub listeners: Vec<ListenerSummary>,
    pub services: Vec<String>,
    pub clusters: Vec<String>,
    pub sites: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListenerSummary {
    pub name: String,
    pub bind: String,
    pub service: String,
}

#[derive(Debug, Default)]
pub struct Compiler;

impl Compiler {
    pub fn compile_path(path: impl AsRef<Path>) -> Result<CompiledGateway, CompileError> {
        let path = canonical_input(path.as_ref())?;
        let mut loader = Loader::default();
        loader.load(&path)?;
        let merged = loader.finish(path.clone());
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
            config_version: ConfigVersion::new(format!("v2-{:016x}", merged.hash)),
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
        strict_yaml::parse(path, &source, "request")
            .map_err(|diagnostic| CompileError::one(*diagnostic))
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

#[derive(Debug, Clone)]
struct Located<T> {
    value: T,
    file: PathBuf,
    field_path: String,
}

impl<T> Located<T> {
    fn span(&self) -> SourceSpan {
        span(&self.file, &self.field_path)
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
    documents: Vec<Located<GatewaySource>>,
    dependencies: Vec<PathBuf>,
    hash: u64,
}

impl Loader {
    fn load(&mut self, path: &Path) -> Result<(), CompileError> {
        if let Some(position) = self.stack.iter().position(|candidate| candidate == path) {
            let mut chain = self.stack[position..]
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>();
            chain.push(path.display().to_string());
            return Err(CompileError::one(
                Diagnostic::new(
                    "config.import_cycle",
                    "configuration import cycle detected",
                    span(path, "imports"),
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
        let document: GatewaySource = strict_yaml::parse(path, &source, "")
            .map_err(|diagnostic| CompileError::one(*diagnostic))?;

        self.stack.push(path.to_path_buf());
        let directory = path.parent().unwrap_or_else(|| Path::new("."));
        for import in &document.imports {
            let import = directory.join(import).canonicalize().map_err(|error| {
                CompileError::one(
                    Diagnostic::new(
                        "config.import_missing",
                        format!("cannot resolve import `{}`: {error}", import.display()),
                        span(path, "imports"),
                    )
                    .with_reference_chain(
                        self.stack
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect(),
                    ),
                )
            })?;
            self.load(&import)?;
        }
        self.stack.pop();

        hash_bytes(&mut self.hash, path.to_string_lossy().as_bytes());
        hash_bytes(&mut self.hash, source.as_bytes());
        self.dependencies.push(path.to_path_buf());
        self.documents.push(Located {
            value: document,
            file: path.to_path_buf(),
            field_path: String::new(),
        });
        self.loaded.insert(path.to_path_buf());
        Ok(())
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
        let mut merged = MergedSource {
            root,
            dependencies,
            source_files,
            hash: self.hash,
            ..MergedSource::default()
        };
        for document in self.documents {
            merged.api_versions.push(Located {
                value: document.value.api_version,
                file: document.file.clone(),
                field_path: "api_version".to_owned(),
            });
            merged.kinds.push(Located {
                value: document.value.kind,
                file: document.file.clone(),
                field_path: "kind".to_owned(),
            });
            merge_resources(&mut merged, document.value.resources, &document.file);
            for (name, service) in document.value.services {
                insert_located(
                    &mut merged.services,
                    name.clone(),
                    Located {
                        value: service,
                        file: document.file.clone(),
                        field_path: format!("services.{name}"),
                    },
                    &mut merged.merge_errors,
                    "service",
                );
            }
            merged
                .listeners
                .extend(document.value.listeners.into_iter().enumerate().map(
                    |(index, listener)| Located {
                        value: listener,
                        file: document.file.clone(),
                        field_path: format!("listeners[{index}]"),
                    },
                ));
            merged
                .tests
                .extend(
                    document
                        .value
                        .tests
                        .into_iter()
                        .enumerate()
                        .map(|(index, test)| Located {
                            value: test,
                            file: document.file.clone(),
                            field_path: format!("tests[{index}]"),
                        }),
                );
        }
        merged
    }
}

#[derive(Default)]
struct MergedSource {
    root: PathBuf,
    dependencies: Vec<PathBuf>,
    source_files: BTreeMap<PathBuf, SourceFileId>,
    hash: u64,
    api_versions: Vec<Located<String>>,
    kinds: Vec<Located<String>>,
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
        let file = self.source_files.get(file).copied().ok_or_else(|| {
            diagnostic_at(
                "service.source_identity",
                "internal compiler error: source file has no assigned identity",
                file,
                field_path,
            )
        })?;
        Ok(SourceNodeKey { file, field_path })
    }
}

fn merge_resources(merged: &mut MergedSource, resources: ResourcesSource, file: &Path) {
    for (name, cluster) in resources.clusters {
        insert_located(
            &mut merged.clusters,
            name.clone(),
            Located {
                value: cluster,
                file: file.to_path_buf(),
                field_path: format!("resources.clusters.{name}"),
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
        diagnostics.push(
            Diagnostic::new(
                "config.duplicate_definition",
                format!("duplicate {kind} definition `{name}`"),
                value.span(),
            )
            .with_reference_chain(vec![
                previous.file.display().to_string(),
                value.file.display().to_string(),
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
        Err(CompileError { diagnostics })
    }
}

fn compile_resources(merged: &MergedSource) -> Result<CompiledResources, CompileError> {
    let mut resources = CompiledResources::default();
    for (name, located) in &merged.clusters {
        if located.value.endpoints.is_empty() {
            return Err(semantic_error(
                "resource.cluster_empty",
                "cluster must contain at least one endpoint",
                located,
            ));
        }
        let mut endpoints = Vec::new();
        for endpoint in &located.value.endpoints {
            let url = Url::parse(endpoint).map_err(|error| {
                semantic_error(
                    "resource.endpoint",
                    format!("invalid endpoint `{endpoint}`: {error}"),
                    located,
                )
            })?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(semantic_error(
                    "resource.endpoint",
                    format!(
                        "endpoint `{endpoint}` must be an http(s) origin/path without credentials, query, or fragment"
                    ),
                    located,
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
                connect_timeout: parse_duration(&located.value.connect_timeout, &located.span())?,
                response_timeout: parse_duration(&located.value.response_timeout, &located.span())?,
                source: located.span(),
            },
        );
    }
    for (name, located) in &merged.sites {
        let directory = located.file.parent().unwrap_or_else(|| Path::new("."));
        let root = directory.join(&located.value.root);
        let manifest = root.join(&located.value.manifest);
        let inputs = located
            .value
            .inputs
            .iter()
            .map(|(name, value)| {
                yaml_value(value)
                    .map(|value| (name.clone(), value))
                    .map_err(|message| semantic_error("resource.site_input", message, located))
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
                source: located.span(),
            },
        );
    }
    Ok(resources)
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
                return Err(semantic_error(
                    "listener.name",
                    "listener name cannot be empty",
                    located,
                ));
            }
            if !self.listener_names.insert(located.value.name.clone()) {
                return Err(semantic_error(
                    "listener.duplicate",
                    format!("duplicate listener name `{}`", located.value.name),
                    located,
                ));
            }
            let bind = located.value.bind.parse::<SocketAddr>().map_err(|error| {
                semantic_error(
                    "listener.bind",
                    format!("invalid listener address `{}`: {error}", located.value.bind),
                    located,
                )
            })?;
            match located.value.protocol {
                ListenerProtocolSource::Http => {}
            }
            let service = self.compile_service(
                &located.value.service,
                &located.file,
                &format!("{}.service", located.field_path),
            )?;
            listeners.push(CompiledListener {
                id: ListenerId::new(format!("listener:{}", located.value.name)),
                name: located.value.name.clone(),
                bind,
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
        self.compile_inline_or_reference_as(
            id.clone(),
            &located.value,
            &located.file,
            &located.field_path,
        )?;
        self.compiling.remove(name);
        Ok(id)
    }

    fn compile_service(
        &mut self,
        source: &ServiceSource,
        file: &Path,
        field_path: &str,
    ) -> Result<ServiceId, CompileError> {
        match source {
            ServiceSource::Reference(reference) => self.compile_named(&reference.reference),
            ServiceSource::Inline(_) => {
                let id = self.source.node_key(file, field_path)?.inline_service_id();
                self.compile_inline_or_reference_as(id.clone(), source, file, field_path)?;
                Ok(id)
            }
        }
    }

    fn compile_inline_or_reference_as(
        &mut self,
        id: ServiceId,
        source: &ServiceSource,
        file: &Path,
        field_path: &str,
    ) -> Result<(), CompileError> {
        let ServiceSource::Inline(source) = source else {
            let ServiceSource::Reference(reference) = source else {
                unreachable!("ServiceSource has two variants");
            };
            let target = self.compile_named(&reference.reference)?;
            let node = ServiceNode {
                id: id.clone(),
                source: span(file, field_path),
                kind: ServiceKind::Fallback {
                    services: vec![target],
                },
            };
            return self.insert_node(node);
        };
        let kind = self.compile_inline(source, file, field_path)?;
        self.insert_node(ServiceNode {
            id,
            source: span(file, field_path),
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
            Entry::Occupied(entry) => Err(CompileError::one(
                Diagnostic::new(
                    "service.duplicate_internal_id",
                    format!("duplicate generated Service ID `{}`", node.id),
                    node.source.clone(),
                )
                .with_reference_chain(vec![
                    entry.get().source.to_string(),
                    node.source.to_string(),
                ])
                .with_help("report this compiler identity collision as an Oxidase bug"),
            )),
        }
    }

    fn compile_inline(
        &mut self,
        source: &InlineServiceSource,
        file: &Path,
        field_path: &str,
    ) -> Result<ServiceKind, CompileError> {
        match source {
            InlineServiceSource::Respond {
                status,
                headers,
                body,
            } => Ok(ServiceKind::Respond {
                status: status_code(*status, file, field_path)?,
                headers: compile_headers(headers, file, &format!("{field_path}.headers"))?,
                body: compile_body(body, file, field_path)?,
            }),
            InlineServiceSource::Redirect {
                status,
                location,
                query,
                headers,
            } => {
                let status = status_code(*status, file, field_path)?;
                if !status.is_redirection() {
                    return Err(diagnostic_at(
                        "service.redirect_status",
                        format!("redirect status `{status}` is not 3xx"),
                        file,
                        field_path,
                    ));
                }
                Ok(ServiceKind::Redirect {
                    status,
                    location: redirect_template(location, file, field_path)?,
                    preserve_query: matches!(query, RedirectQuerySource::Preserve),
                    headers: compile_headers(headers, file, &format!("{field_path}.headers"))?,
                })
            }
            InlineServiceSource::Site { site } => {
                let resource = ResourceId::new(format!("site:{site}"));
                if !self.resources.sites.contains_key(&resource) {
                    return Err(diagnostic_at(
                        "service.site_reference",
                        format!("site resource `{site}` does not exist"),
                        file,
                        field_path,
                    ));
                }
                Ok(ServiceKind::Site { resource })
            }
            InlineServiceSource::Proxy { cluster } => {
                let resource = ResourceId::new(format!("cluster:{cluster}"));
                if !self.resources.clusters.contains_key(&resource) {
                    return Err(diagnostic_at(
                        "service.cluster_reference",
                        format!("cluster resource `{cluster}` does not exist"),
                        file,
                        field_path,
                    ));
                }
                Ok(ServiceKind::Proxy { cluster: resource })
            }
            InlineServiceSource::Transform {
                request,
                response,
                service,
            } => Ok(ServiceKind::Transform {
                request: Box::new(compile_request_transform(request, file, field_path)?),
                response: Box::new(compile_response_transform(response, file, field_path)?),
                service: self.compile_service(service, file, &format!("{field_path}.service"))?,
            }),
            InlineServiceSource::Observe { name, service } => Ok(ServiceKind::Observe {
                name: name.clone(),
                service: self.compile_service(service, file, &format!("{field_path}.service"))?,
            }),
            InlineServiceSource::Timeout { duration, service } => Ok(ServiceKind::Timeout {
                duration: parse_duration(duration, &span(file, field_path))?,
                service: self.compile_service(service, file, &format!("{field_path}.service"))?,
            }),
            InlineServiceSource::Recover { service, handlers } => {
                let service =
                    self.compile_service(service, file, &format!("{field_path}.service"))?;
                let handlers = handlers
                    .iter()
                    .enumerate()
                    .map(|(index, handler)| {
                        Ok(RecoverHandler {
                            classes: handler.classes.iter().copied().map(error_class).collect(),
                            service: self.compile_service(
                                &handler.service,
                                file,
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
                            id: self.source.node_key(file, &case_path)?.route_id(),
                            predicate: compile_predicate(
                                &case.predicate,
                                file,
                                &format!("{case_path}.when"),
                            )?,
                            service: self.compile_service(
                                &case.service,
                                file,
                                &format!("{case_path}.service"),
                            )?,
                            source: span(file, case_path),
                        })
                    })
                    .collect::<Result<Vec<_>, CompileError>>()?;
                let default = default
                    .as_ref()
                    .map(|service| {
                        self.compile_service(service, file, &format!("{field_path}.default"))
                    })
                    .transpose()?;
                Ok(ServiceKind::Route { cases, default })
            }
            InlineServiceSource::Fallback { services } => {
                if services.is_empty() {
                    return Err(diagnostic_at(
                        "service.fallback_empty",
                        "fallback requires at least one candidate",
                        file,
                        field_path,
                    ));
                }
                Ok(ServiceKind::Fallback {
                    services: services
                        .iter()
                        .enumerate()
                        .map(|(index, service)| {
                            self.compile_service(
                                service,
                                file,
                                &format!("{field_path}.services[{index}]"),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                })
            }
            InlineServiceSource::Reenter { target, budget } => {
                if !self.source.services.contains_key(target) {
                    return Err(diagnostic_at(
                        "service.reenter_target",
                        format!("Reenter target `{target}` is not a named service"),
                        file,
                        field_path,
                    ));
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
    file: &Path,
    field_path: &str,
) -> Result<RespondBody, CompileError> {
    let selected = usize::from(source.empty)
        + usize::from(source.text.is_some())
        + usize::from(source.json.is_some());
    if selected > 1 {
        return Err(diagnostic_at(
            "service.respond_body",
            "response body must select exactly one of `empty`, `text`, or `json`",
            file,
            field_path,
        ));
    }
    if let Some(text) = &source.text {
        Ok(RespondBody::Text(template(text, file, field_path)?))
    } else if let Some(json) = &source.json {
        Ok(RespondBody::Json(yaml_value(json).map_err(|message| {
            diagnostic_at("service.respond_json", message, file, field_path)
        })?))
    } else if source.empty || selected == 0 {
        Ok(RespondBody::Empty)
    } else {
        Ok(RespondBody::Bytes(Bytes::new()))
    }
}

fn compile_request_transform(
    source: &RequestTransformSource,
    file: &Path,
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
                    file,
                    field_path,
                )
            })?,
        scheme: optional_template(&source.scheme, file, field_path)?,
        authority: optional_template(&source.authority, file, field_path)?,
        path_and_query: optional_template(&source.path, file, field_path)?,
        headers: compile_headers(
            &source.headers,
            file,
            &format!("{field_path}.request.headers"),
        )?,
    })
}

fn compile_response_transform(
    source: &ResponseTransformSource,
    file: &Path,
    field_path: &str,
) -> Result<ResponseTransform, CompileError> {
    Ok(ResponseTransform {
        headers: compile_headers(
            &source.headers,
            file,
            &format!("{field_path}.response.headers"),
        )?,
    })
}

fn compile_headers(
    source: &HeadersSource,
    file: &Path,
    field_path: &str,
) -> Result<HeaderTransforms, CompileError> {
    Ok(HeaderTransforms {
        set: compile_header_values(&source.set, file, &format!("{field_path}.set"))?,
        add: compile_header_values(&source.add, file, &format!("{field_path}.add"))?,
        remove: source
            .remove
            .iter()
            .enumerate()
            .map(|(index, name)| {
                compile_user_header_name(name, file, &format!("{field_path}.remove[{index}]"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn compile_header_values(
    source: &BTreeMap<String, String>,
    file: &Path,
    field_path: &str,
) -> Result<Vec<HeaderTransform>, CompileError> {
    source
        .iter()
        .map(|(name, value)| {
            let header_path = format!("{field_path}.{name}");
            let name = compile_user_header_name(name, file, &header_path)?;
            let value = template(value, file, &header_path)?;
            if value.is_constant() {
                let rendered = value
                    .render(&oxidase_core::EvalContext::default())
                    .map_err(|error| {
                        diagnostic_at("service.header_value", error.to_string(), file, field_path)
                    })?;
                HeaderValue::from_str(&rendered).map_err(|_| {
                    diagnostic_at(
                        "service.header_value",
                        format!("header `{name}` has an invalid constant value"),
                        file,
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
    file: &Path,
    field_path: &str,
) -> Result<HeaderName, CompileError> {
    let name = HeaderName::from_str(source).map_err(|error| {
        diagnostic_at(
            "service.header_name",
            format!("invalid header name `{source}`: {error}"),
            file,
            field_path,
        )
    })?;
    if is_forbidden_user_header(&name) {
        return Err(diagnostic_at(
            "service.forbidden_header",
            format!("header `{name}` is managed by the HTTP response finalizer"),
            file,
            field_path,
        ));
    }
    Ok(name)
}

fn compile_predicate(
    source: &PredicateSource,
    file: &Path,
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
                    file,
                    field_path,
                )
            })?,
        host: source
            .host
            .as_ref()
            .map(|pattern| CompiledPattern::compile(pattern, PatternContext::Host))
            .transpose()
            .map_err(|error| {
                diagnostic_at("service.host_pattern", error.to_string(), file, field_path)
            })?,
        path: source
            .path
            .as_ref()
            .map(|pattern| CompiledPattern::compile(pattern, PatternContext::Path))
            .transpose()
            .map_err(|error| {
                diagnostic_at("service.path_pattern", error.to_string(), file, field_path)
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
                            file,
                            field_path,
                        )
                    })?,
                    pattern: CompiledPattern::compile(pattern, PatternContext::Value).map_err(
                        |error| {
                            diagnostic_at(
                                "service.header_pattern",
                                error.to_string(),
                                file,
                                field_path,
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
                    file,
                    field_path,
                )
            })?,
    })
}

fn template(source: &str, file: &Path, field_path: &str) -> Result<CompiledTemplate, CompileError> {
    CompiledTemplate::compile(source)
        .map_err(|error| diagnostic_at("service.template", error.to_string(), file, field_path))
}

fn redirect_template(
    source: &str,
    file: &Path,
    field_path: &str,
) -> Result<CompiledTemplate, CompileError> {
    let template = template(source, file, field_path)?;
    if template.is_constant()
        && (!source.starts_with('/') || source.starts_with("//") || source.contains('\\'))
    {
        return Err(diagnostic_at(
            "service.redirect_location",
            "redirect Location must be a local absolute path",
            file,
            field_path,
        ));
    }
    Ok(template)
}

fn optional_template(
    source: &Option<String>,
    file: &Path,
    field_path: &str,
) -> Result<Option<CompiledTemplate>, CompileError> {
    source
        .as_ref()
        .map(|source| template(source, file, field_path))
        .transpose()
}

fn status_code(status: u16, file: &Path, field_path: &str) -> Result<StatusCode, CompileError> {
    StatusCode::from_u16(status).map_err(|error| {
        diagnostic_at(
            "service.status",
            format!("invalid HTTP status `{status}`: {error}"),
            file,
            field_path,
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

fn semantic_error<T>(
    code: &'static str,
    message: impl Into<String>,
    located: &Located<T>,
) -> CompileError {
    CompileError::one(Diagnostic::new(code, message, located.span()))
}

fn diagnostic_at(
    code: &'static str,
    message: impl Into<String>,
    file: &Path,
    field_path: &str,
) -> CompileError {
    CompileError::one(Diagnostic::new(code, message, span(file, field_path)))
}

fn span(path: &Path, field_path: impl Into<String>) -> SourceSpan {
    SourceSpan {
        file: path.to_path_buf(),
        line: 1,
        column: 1,
        field_path: field_path.into(),
    }
}

fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    if *hash == 0 {
        *hash = 0xcbf2_9ce4_8422_2325;
    }
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
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
}
