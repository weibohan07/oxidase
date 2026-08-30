//! Stable, runtime-independent Service graph representation for portable bundles.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr as _;
use std::time::Duration;

use bytes::Bytes;
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderName, Method, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CompiledMetadata, CompiledPattern, CompiledTemplate, ErrorClass, Expression, HeaderPredicate,
    HeaderTransform, HeaderTransforms, PatternContext, PredicatePlan, RateLimitKey, RecoverHandler,
    RequestTransform, RespondBody, ResponseTransform, RouteCase, RouteId, ServiceGraph, ServiceId,
    ServiceKind, ServiceNode, SourceSpan, Value,
};

pub const PORTABLE_SERVICE_GRAPH_SCHEMA_V1: &str = "oxidase.service-program/v1";
const MAX_PORTABLE_SERVICE_NODES: usize = 1_000_000;

/// Canonical Service graph DTO. All maps become deterministically ordered
/// vectors and compiled implementation objects are represented by their stable
/// source language.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableServiceGraphV1 {
    pub schema_version: String,
    pub nodes: Vec<PortableServiceNodeV1>,
}

impl PortableServiceGraphV1 {
    #[must_use]
    pub fn from_graph(graph: &ServiceGraph) -> Self {
        Self {
            schema_version: PORTABLE_SERVICE_GRAPH_SCHEMA_V1.to_owned(),
            nodes: graph
                .iter()
                .map(|(_, node)| PortableServiceNodeV1::from_node(node))
                .collect(),
        }
    }

    pub fn compile(&self) -> Result<ServiceGraph, PortableIrError> {
        if self.schema_version != PORTABLE_SERVICE_GRAPH_SCHEMA_V1 {
            return Err(PortableIrError::SchemaVersion(self.schema_version.clone()));
        }
        if self.nodes.len() > MAX_PORTABLE_SERVICE_NODES {
            return Err(PortableIrError::Limit {
                field: "nodes",
                limit: MAX_PORTABLE_SERVICE_NODES,
                actual: self.nodes.len(),
            });
        }
        let mut nodes = BTreeMap::new();
        for node in &self.nodes {
            let compiled = node.compile()?;
            let id = compiled.id.clone();
            if nodes.insert(id.clone(), compiled).is_some() {
                return Err(PortableIrError::DuplicateService(id));
            }
        }
        Ok(ServiceGraph::new(nodes))
    }

    /// Rewrites every physical source file retained by this graph.
    ///
    /// Bundle builders use this to replace compiler-machine absolute paths
    /// with deterministic logical source names. Field paths and byte/line
    /// coordinates remain unchanged.
    pub fn map_source_files(&mut self, mut map: impl FnMut(&Path) -> PathBuf) {
        for node in &mut self.nodes {
            node.source.file = map(&node.source.file);
            if let PortableServiceKindV1::Route { cases, .. } = &mut node.kind {
                for case in cases {
                    case.source.file = map(&case.source.file);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableServiceNodeV1 {
    pub id: ServiceId,
    pub source: SourceSpan,
    pub kind: PortableServiceKindV1,
}

impl PortableServiceNodeV1 {
    fn from_node(node: &ServiceNode) -> Self {
        Self {
            id: node.id.clone(),
            source: node.source.clone(),
            kind: PortableServiceKindV1::from_kind(&node.kind),
        }
    }

    fn compile(&self) -> Result<ServiceNode, PortableIrError> {
        self.source
            .validate_portable()
            .map_err(|message| PortableIrError::Invalid {
                field: "service.source",
                message,
            })?;
        Ok(ServiceNode {
            id: self.id.clone(),
            source: self.source.clone(),
            kind: self.kind.compile()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableServiceKindV1 {
    Respond {
        status: u16,
        headers: PortableHeaderTransformsV1,
        body: PortableRespondBodyV1,
    },
    Redirect {
        status: u16,
        location: String,
        preserve_query: bool,
        headers: PortableHeaderTransformsV1,
    },
    Site {
        resource: crate::ResourceId,
    },
    Proxy {
        cluster: crate::ResourceId,
    },
    Transform {
        request: Box<PortableRequestTransformV1>,
        response: Box<PortableResponseTransformV1>,
        service: ServiceId,
    },
    Observe {
        name: String,
        service: ServiceId,
    },
    Timeout {
        duration: PortableDurationV1,
        service: ServiceId,
    },
    RequestBodyLimit {
        max_bytes: u64,
        service: ServiceId,
    },
    ConcurrencyLimit {
        name: String,
        max_in_flight: u32,
        queue_timeout: PortableDurationV1,
        reject_status: u16,
        service: ServiceId,
    },
    RateLimit {
        name: String,
        key: PortableRateLimitKeyV1,
        requests: u64,
        per: PortableDurationV1,
        burst: u64,
        max_keys: u32,
        idle_ttl: PortableDurationV1,
        service: ServiceId,
    },
    Recover {
        service: ServiceId,
        handlers: Vec<PortableRecoverHandlerV1>,
    },
    Route {
        cases: Vec<PortableRouteCaseV1>,
        default: Option<ServiceId>,
    },
    Fallback {
        services: Vec<ServiceId>,
    },
    Reenter {
        target: ServiceId,
        budget: u32,
    },
}

impl PortableServiceKindV1 {
    fn from_kind(kind: &ServiceKind) -> Self {
        match kind {
            ServiceKind::Respond {
                status,
                headers,
                body,
            } => Self::Respond {
                status: status.as_u16(),
                headers: PortableHeaderTransformsV1::from_headers(headers),
                body: PortableRespondBodyV1::from_body(body),
            },
            ServiceKind::Redirect {
                status,
                location,
                preserve_query,
                headers,
            } => Self::Redirect {
                status: status.as_u16(),
                location: location.source().to_owned(),
                preserve_query: *preserve_query,
                headers: PortableHeaderTransformsV1::from_headers(headers),
            },
            ServiceKind::Site { resource } => Self::Site {
                resource: resource.clone(),
            },
            ServiceKind::Proxy { cluster } => Self::Proxy {
                cluster: cluster.clone(),
            },
            ServiceKind::Transform {
                request,
                response,
                service,
            } => Self::Transform {
                request: Box::new(PortableRequestTransformV1::from_transform(request)),
                response: Box::new(PortableResponseTransformV1::from_transform(response)),
                service: service.clone(),
            },
            ServiceKind::Observe { name, service } => Self::Observe {
                name: name.clone(),
                service: service.clone(),
            },
            ServiceKind::Timeout { duration, service } => Self::Timeout {
                duration: PortableDurationV1::from_duration(*duration),
                service: service.clone(),
            },
            ServiceKind::RequestBodyLimit { max_bytes, service } => Self::RequestBodyLimit {
                max_bytes: *max_bytes,
                service: service.clone(),
            },
            ServiceKind::ConcurrencyLimit {
                name,
                max_in_flight,
                queue_timeout,
                reject_status,
                service,
            } => Self::ConcurrencyLimit {
                name: name.clone(),
                max_in_flight: *max_in_flight,
                queue_timeout: PortableDurationV1::from_duration(*queue_timeout),
                reject_status: reject_status.as_u16(),
                service: service.clone(),
            },
            ServiceKind::RateLimit {
                name,
                key,
                requests,
                per,
                burst,
                max_keys,
                idle_ttl,
                service,
            } => Self::RateLimit {
                name: name.clone(),
                key: PortableRateLimitKeyV1::from_key(key),
                requests: *requests,
                per: PortableDurationV1::from_duration(*per),
                burst: *burst,
                max_keys: *max_keys,
                idle_ttl: PortableDurationV1::from_duration(*idle_ttl),
                service: service.clone(),
            },
            ServiceKind::Recover { service, handlers } => Self::Recover {
                service: service.clone(),
                handlers: handlers
                    .iter()
                    .map(PortableRecoverHandlerV1::from_handler)
                    .collect(),
            },
            ServiceKind::Route { cases, default } => Self::Route {
                cases: cases.iter().map(PortableRouteCaseV1::from_case).collect(),
                default: default.clone(),
            },
            ServiceKind::Fallback { services } => Self::Fallback {
                services: services.clone(),
            },
            ServiceKind::Reenter { target, budget } => Self::Reenter {
                target: target.clone(),
                budget: *budget,
            },
        }
    }

    fn compile(&self) -> Result<ServiceKind, PortableIrError> {
        Ok(match self {
            Self::Respond {
                status,
                headers,
                body,
            } => ServiceKind::Respond {
                status: parse_status(*status, "respond.status")?,
                headers: headers.compile()?,
                body: body.compile()?,
            },
            Self::Redirect {
                status,
                location,
                preserve_query,
                headers,
            } => ServiceKind::Redirect {
                status: parse_status(*status, "redirect.status")?,
                location: compile_template(location, "redirect.location")?,
                preserve_query: *preserve_query,
                headers: headers.compile()?,
            },
            Self::Site { resource } => ServiceKind::Site {
                resource: resource.clone(),
            },
            Self::Proxy { cluster } => ServiceKind::Proxy {
                cluster: cluster.clone(),
            },
            Self::Transform {
                request,
                response,
                service,
            } => ServiceKind::Transform {
                request: Box::new(request.compile()?),
                response: Box::new(response.compile()?),
                service: service.clone(),
            },
            Self::Observe { name, service } => ServiceKind::Observe {
                name: name.clone(),
                service: service.clone(),
            },
            Self::Timeout { duration, service } => ServiceKind::Timeout {
                duration: duration.compile("timeout.duration")?,
                service: service.clone(),
            },
            Self::RequestBodyLimit { max_bytes, service } => ServiceKind::RequestBodyLimit {
                max_bytes: *max_bytes,
                service: service.clone(),
            },
            Self::ConcurrencyLimit {
                name,
                max_in_flight,
                queue_timeout,
                reject_status,
                service,
            } => ServiceKind::ConcurrencyLimit {
                name: name.clone(),
                max_in_flight: *max_in_flight,
                queue_timeout: queue_timeout.compile("concurrency_limit.queue_timeout")?,
                reject_status: parse_status(*reject_status, "concurrency_limit.reject_status")?,
                service: service.clone(),
            },
            Self::RateLimit {
                name,
                key,
                requests,
                per,
                burst,
                max_keys,
                idle_ttl,
                service,
            } => ServiceKind::RateLimit {
                name: name.clone(),
                key: key.compile(),
                requests: *requests,
                per: per.compile("rate_limit.per")?,
                burst: *burst,
                max_keys: *max_keys,
                idle_ttl: idle_ttl.compile("rate_limit.idle_ttl")?,
                service: service.clone(),
            },
            Self::Recover { service, handlers } => ServiceKind::Recover {
                service: service.clone(),
                handlers: handlers
                    .iter()
                    .map(PortableRecoverHandlerV1::compile)
                    .collect(),
            },
            Self::Route { cases, default } => ServiceKind::Route {
                cases: cases
                    .iter()
                    .map(PortableRouteCaseV1::compile)
                    .collect::<Result<Vec<_>, _>>()?,
                default: default.clone(),
            },
            Self::Fallback { services } => ServiceKind::Fallback {
                services: services.clone(),
            },
            Self::Reenter { target, budget } => ServiceKind::Reenter {
                target: target.clone(),
                budget: *budget,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableDurationV1 {
    pub seconds: u64,
    pub nanoseconds: u32,
}

impl PortableDurationV1 {
    fn from_duration(duration: Duration) -> Self {
        Self {
            seconds: duration.as_secs(),
            nanoseconds: duration.subsec_nanos(),
        }
    }

    fn compile(self, field: &'static str) -> Result<Duration, PortableIrError> {
        if self.nanoseconds >= 1_000_000_000 {
            return Err(PortableIrError::Invalid {
                field,
                message: "nanoseconds must be below one billion".to_owned(),
            });
        }
        Ok(Duration::new(self.seconds, self.nanoseconds))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableRateLimitKeyV1 {
    PeerIp,
    Binding { name: String },
}

impl PortableRateLimitKeyV1 {
    fn from_key(key: &RateLimitKey) -> Self {
        match key {
            RateLimitKey::PeerIp => Self::PeerIp,
            RateLimitKey::Binding(name) => Self::Binding { name: name.clone() },
        }
    }

    fn compile(&self) -> RateLimitKey {
        match self {
            Self::PeerIp => RateLimitKey::PeerIp,
            Self::Binding { name } => RateLimitKey::Binding(name.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableRespondBodyV1 {
    Empty,
    Bytes { value: Vec<u8> },
    Text { template: String },
    Json { value: PortableValueV1 },
}

impl PortableRespondBodyV1 {
    fn from_body(body: &RespondBody) -> Self {
        match body {
            RespondBody::Empty => Self::Empty,
            RespondBody::Bytes(value) => Self::Bytes {
                value: value.to_vec(),
            },
            RespondBody::Text(template) => Self::Text {
                template: template.source().to_owned(),
            },
            RespondBody::Json(value) => Self::Json {
                value: PortableValueV1::from_value(value),
            },
        }
    }

    fn compile(&self) -> Result<RespondBody, PortableIrError> {
        Ok(match self {
            Self::Empty => RespondBody::Empty,
            Self::Bytes { value } => RespondBody::Bytes(Bytes::copy_from_slice(value)),
            Self::Text { template } => {
                RespondBody::Text(compile_template(template, "respond.body.text")?)
            }
            Self::Json { value } => RespondBody::Json(value.compile()),
        })
    }
}

/// Exact, JSON-safe representation of the shared runtime Value model.
///
/// Floats use IEEE-754 bits so NaN payloads, infinities, and signed zero never
/// depend on a JSON number formatter. Bytes remain an explicit integer array
/// instead of relying on an implicit binary-text codec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PortableValueV1 {
    Null,
    Bool(bool),
    Integer(i64),
    FloatBits(u64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<PortableValueV1>),
    Map(BTreeMap<String, PortableValueV1>),
}

impl PortableValueV1 {
    #[must_use]
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Bool(*value),
            Value::Integer(value) => Self::Integer(*value),
            Value::Float(value) => Self::FloatBits(value.to_bits()),
            Value::String(value) => Self::String(value.clone()),
            Value::Bytes(value) => Self::Bytes(value.clone()),
            Value::List(values) => Self::List(values.iter().map(Self::from_value).collect()),
            Value::Map(values) => Self::Map(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_value(value)))
                    .collect(),
            ),
        }
    }

    #[must_use]
    pub fn compile(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(value) => Value::Bool(*value),
            Self::Integer(value) => Value::Integer(*value),
            Self::FloatBits(bits) => Value::Float(f64::from_bits(*bits)),
            Self::String(value) => Value::String(value.clone()),
            Self::Bytes(value) => Value::Bytes(value.clone()),
            Self::List(values) => Value::List(values.iter().map(Self::compile).collect()),
            Self::Map(values) => Value::Map(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.compile()))
                    .collect(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderTransformsV1 {
    pub set: Vec<PortableHeaderTransformV1>,
    pub add: Vec<PortableHeaderTransformV1>,
    pub remove: Vec<String>,
}

impl PortableHeaderTransformsV1 {
    fn from_headers(headers: &HeaderTransforms) -> Self {
        Self {
            set: headers
                .set
                .iter()
                .map(PortableHeaderTransformV1::from_header)
                .collect(),
            add: headers
                .add
                .iter()
                .map(PortableHeaderTransformV1::from_header)
                .collect(),
            remove: headers.remove.iter().map(ToString::to_string).collect(),
        }
    }

    fn compile(&self) -> Result<HeaderTransforms, PortableIrError> {
        Ok(HeaderTransforms {
            set: self
                .set
                .iter()
                .map(PortableHeaderTransformV1::compile)
                .collect::<Result<Vec<_>, _>>()?,
            add: self
                .add
                .iter()
                .map(PortableHeaderTransformV1::compile)
                .collect::<Result<Vec<_>, _>>()?,
            remove: self
                .remove
                .iter()
                .map(|name| parse_header_name(name, "headers.remove"))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderTransformV1 {
    pub name: String,
    pub value: String,
}

impl PortableHeaderTransformV1 {
    fn from_header(header: &HeaderTransform) -> Self {
        Self {
            name: header.name.to_string(),
            value: header.value.source().to_owned(),
        }
    }

    fn compile(&self) -> Result<HeaderTransform, PortableIrError> {
        Ok(HeaderTransform {
            name: parse_header_name(&self.name, "headers.name")?,
            value: compile_template(&self.value, "headers.value")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortableMetadataV1 {
    Constant { value: String },
    Dynamic { template: String },
}

impl PortableMetadataV1 {
    fn from_scheme(value: &CompiledMetadata<Scheme>) -> Self {
        match value {
            CompiledMetadata::Constant(value) => Self::Constant {
                value: value.to_string(),
            },
            CompiledMetadata::Dynamic(template) => Self::Dynamic {
                template: template.source().to_owned(),
            },
        }
    }

    fn from_authority(value: &CompiledMetadata<Authority>) -> Self {
        match value {
            CompiledMetadata::Constant(value) => Self::Constant {
                value: value.to_string(),
            },
            CompiledMetadata::Dynamic(template) => Self::Dynamic {
                template: template.source().to_owned(),
            },
        }
    }

    fn from_path_and_query(value: &CompiledMetadata<PathAndQuery>) -> Self {
        match value {
            CompiledMetadata::Constant(value) => Self::Constant {
                value: value.to_string(),
            },
            CompiledMetadata::Dynamic(template) => Self::Dynamic {
                template: template.source().to_owned(),
            },
        }
    }

    fn compile_scheme(&self) -> Result<CompiledMetadata<Scheme>, PortableIrError> {
        self.compile_with("transform.request.scheme", Scheme::from_str)
    }

    fn compile_authority(&self) -> Result<CompiledMetadata<Authority>, PortableIrError> {
        self.compile_with("transform.request.authority", Authority::from_str)
    }

    fn compile_path_and_query(&self) -> Result<CompiledMetadata<PathAndQuery>, PortableIrError> {
        self.compile_with("transform.request.path_and_query", PathAndQuery::from_str)
    }

    fn compile_with<T, Error>(
        &self,
        field: &'static str,
        parse: impl FnOnce(&str) -> Result<T, Error>,
    ) -> Result<CompiledMetadata<T>, PortableIrError>
    where
        Error: std::fmt::Display,
    {
        match self {
            Self::Constant { value } => {
                parse(value)
                    .map(CompiledMetadata::Constant)
                    .map_err(|error| PortableIrError::Invalid {
                        field,
                        message: error.to_string(),
                    })
            }
            Self::Dynamic { template } => {
                compile_template(template, field).map(CompiledMetadata::Dynamic)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRequestTransformV1 {
    pub method: Option<String>,
    pub scheme: Option<PortableMetadataV1>,
    pub authority: Option<PortableMetadataV1>,
    pub path_and_query: Option<PortableMetadataV1>,
    pub headers: PortableHeaderTransformsV1,
}

impl PortableRequestTransformV1 {
    fn from_transform(transform: &RequestTransform) -> Self {
        Self {
            method: transform.method.as_ref().map(ToString::to_string),
            scheme: transform
                .scheme
                .as_ref()
                .map(PortableMetadataV1::from_scheme),
            authority: transform
                .authority
                .as_ref()
                .map(PortableMetadataV1::from_authority),
            path_and_query: transform
                .path_and_query
                .as_ref()
                .map(PortableMetadataV1::from_path_and_query),
            headers: PortableHeaderTransformsV1::from_headers(&transform.headers),
        }
    }

    fn compile(&self) -> Result<RequestTransform, PortableIrError> {
        Ok(RequestTransform {
            method: self
                .method
                .as_deref()
                .map(|method| parse_method(method, "transform.request.method"))
                .transpose()?,
            scheme: self
                .scheme
                .as_ref()
                .map(PortableMetadataV1::compile_scheme)
                .transpose()?,
            authority: self
                .authority
                .as_ref()
                .map(PortableMetadataV1::compile_authority)
                .transpose()?,
            path_and_query: self
                .path_and_query
                .as_ref()
                .map(PortableMetadataV1::compile_path_and_query)
                .transpose()?,
            headers: self.headers.compile()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableResponseTransformV1 {
    pub headers: PortableHeaderTransformsV1,
}

impl PortableResponseTransformV1 {
    fn from_transform(transform: &ResponseTransform) -> Self {
        Self {
            headers: PortableHeaderTransformsV1::from_headers(&transform.headers),
        }
    }

    fn compile(&self) -> Result<ResponseTransform, PortableIrError> {
        Ok(ResponseTransform {
            headers: self.headers.compile()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRecoverHandlerV1 {
    pub classes: BTreeSet<ErrorClass>,
    pub service: ServiceId,
}

impl PortableRecoverHandlerV1 {
    fn from_handler(handler: &RecoverHandler) -> Self {
        Self {
            classes: handler.classes.clone(),
            service: handler.service.clone(),
        }
    }

    fn compile(&self) -> RecoverHandler {
        RecoverHandler {
            classes: self.classes.clone(),
            service: self.service.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableRouteCaseV1 {
    pub id: RouteId,
    pub predicate: PortablePredicateV1,
    pub service: ServiceId,
    pub source: SourceSpan,
}

impl PortableRouteCaseV1 {
    fn from_case(case: &RouteCase) -> Self {
        Self {
            id: case.id.clone(),
            predicate: PortablePredicateV1::from_predicate(&case.predicate),
            service: case.service.clone(),
            source: case.source.clone(),
        }
    }

    fn compile(&self) -> Result<RouteCase, PortableIrError> {
        self.source
            .validate_portable()
            .map_err(|message| PortableIrError::Invalid {
                field: "route.source",
                message,
            })?;
        Ok(RouteCase {
            id: self.id.clone(),
            predicate: self.predicate.compile()?,
            service: self.service.clone(),
            source: self.source.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePredicateV1 {
    pub methods: Vec<String>,
    pub host: Option<PortablePatternV1>,
    pub path: Option<PortablePatternV1>,
    pub headers: Vec<PortableHeaderPredicateV1>,
    pub expression: Option<String>,
}

impl PortablePredicateV1 {
    fn from_predicate(predicate: &PredicatePlan) -> Self {
        Self {
            methods: predicate.methods.iter().map(ToString::to_string).collect(),
            host: predicate.host.as_ref().map(PortablePatternV1::from_pattern),
            path: predicate.path.as_ref().map(PortablePatternV1::from_pattern),
            headers: predicate
                .headers
                .iter()
                .map(PortableHeaderPredicateV1::from_predicate)
                .collect(),
            expression: predicate
                .expression
                .as_ref()
                .map(|expression| expression.source().to_owned()),
        }
    }

    fn compile(&self) -> Result<PredicatePlan, PortableIrError> {
        Ok(PredicatePlan {
            methods: self
                .methods
                .iter()
                .map(|method| parse_method(method, "route.methods"))
                .collect::<Result<Vec<_>, _>>()?,
            host: self
                .host
                .as_ref()
                .map(PortablePatternV1::compile)
                .transpose()?,
            path: self
                .path
                .as_ref()
                .map(PortablePatternV1::compile)
                .transpose()?,
            headers: self
                .headers
                .iter()
                .map(PortableHeaderPredicateV1::compile)
                .collect::<Result<Vec<_>, _>>()?,
            expression: self
                .expression
                .as_deref()
                .map(|source| compile_expression(source, "route.expression"))
                .transpose()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortablePatternContextV1 {
    Host,
    Path,
    Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortablePatternV1 {
    pub source: String,
    pub context: PortablePatternContextV1,
}

impl PortablePatternV1 {
    fn from_pattern(pattern: &CompiledPattern) -> Self {
        Self {
            source: pattern.raw().to_owned(),
            context: match pattern.context() {
                PatternContext::Host => PortablePatternContextV1::Host,
                PatternContext::Path => PortablePatternContextV1::Path,
                PatternContext::Value => PortablePatternContextV1::Value,
            },
        }
    }

    fn compile(&self) -> Result<CompiledPattern, PortableIrError> {
        let context = match self.context {
            PortablePatternContextV1::Host => PatternContext::Host,
            PortablePatternContextV1::Path => PatternContext::Path,
            PortablePatternContextV1::Value => PatternContext::Value,
        };
        CompiledPattern::compile(&self.source, context).map_err(|error| PortableIrError::Invalid {
            field: "pattern",
            message: error.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableHeaderPredicateV1 {
    pub name: String,
    pub pattern: PortablePatternV1,
    pub negated: bool,
}

impl PortableHeaderPredicateV1 {
    fn from_predicate(predicate: &HeaderPredicate) -> Self {
        Self {
            name: predicate.name.to_string(),
            pattern: PortablePatternV1::from_pattern(&predicate.pattern),
            negated: predicate.negated,
        }
    }

    fn compile(&self) -> Result<HeaderPredicate, PortableIrError> {
        Ok(HeaderPredicate {
            name: parse_header_name(&self.name, "route.headers.name")?,
            pattern: self.pattern.compile()?,
            negated: self.negated,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PortableIrError {
    #[error("unsupported portable Service graph schema `{0}`")]
    SchemaVersion(String),
    #[error("portable Service graph contains duplicate service `{0}`")]
    DuplicateService(ServiceId),
    #[error("portable Service graph field `{field}` exceeds limit {limit}: {actual}")]
    Limit {
        field: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("portable Service graph field `{field}` is invalid: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
}

fn parse_status(status: u16, field: &'static str) -> Result<StatusCode, PortableIrError> {
    StatusCode::from_u16(status).map_err(|error| PortableIrError::Invalid {
        field,
        message: error.to_string(),
    })
}

fn parse_method(method: &str, field: &'static str) -> Result<Method, PortableIrError> {
    Method::from_bytes(method.as_bytes()).map_err(|error| PortableIrError::Invalid {
        field,
        message: error.to_string(),
    })
}

fn parse_header_name(name: &str, field: &'static str) -> Result<HeaderName, PortableIrError> {
    HeaderName::from_bytes(name.as_bytes()).map_err(|error| PortableIrError::Invalid {
        field,
        message: error.to_string(),
    })
}

fn compile_template(
    source: &str,
    field: &'static str,
) -> Result<CompiledTemplate, PortableIrError> {
    CompiledTemplate::compile(source).map_err(|error| PortableIrError::Invalid {
        field,
        message: error.to_string(),
    })
}

fn compile_expression(source: &str, field: &'static str) -> Result<Expression, PortableIrError> {
    Expression::compile(source).map_err(|error| PortableIrError::Invalid {
        field,
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use http::StatusCode;

    use super::{
        PORTABLE_SERVICE_GRAPH_SCHEMA_V1, PortableIrError, PortableServiceGraphV1, PortableValueV1,
    };
    use crate::{
        HeaderTransforms, RespondBody, ServiceGraph, ServiceId, ServiceKind, ServiceNode,
        ServiceProgram, SourceSpan, Value,
    };

    fn graph() -> ServiceGraph {
        ServiceGraph::new(BTreeMap::from([
            (
                ServiceId::new("service:root"),
                ServiceNode {
                    id: ServiceId::new("service:root"),
                    source: SourceSpan::synthetic("services.root"),
                    kind: ServiceKind::Fallback {
                        services: vec![
                            ServiceId::new("service:missing"),
                            ServiceId::new("service:ok"),
                        ],
                    },
                },
            ),
            (
                ServiceId::new("service:missing"),
                ServiceNode {
                    id: ServiceId::new("service:missing"),
                    source: SourceSpan::synthetic("services.missing"),
                    kind: ServiceKind::Respond {
                        status: StatusCode::NO_CONTENT,
                        headers: HeaderTransforms::default(),
                        body: RespondBody::Empty,
                    },
                },
            ),
            (
                ServiceId::new("service:ok"),
                ServiceNode {
                    id: ServiceId::new("service:ok"),
                    source: SourceSpan::synthetic("services.ok"),
                    kind: ServiceKind::Respond {
                        status: StatusCode::OK,
                        headers: HeaderTransforms::default(),
                        body: RespondBody::Text(
                            crate::CompiledTemplate::compile("ok {{ request.path }}")
                                .expect("fixture template compiles"),
                        ),
                    },
                },
            ),
        ]))
    }

    #[test]
    fn round_trip_is_deterministic_and_revalidates_the_program() {
        let portable = PortableServiceGraphV1::from_graph(&graph());
        assert_eq!(portable.schema_version, PORTABLE_SERVICE_GRAPH_SCHEMA_V1);
        let first = serde_json::to_vec(&portable).expect("portable graph serializes");
        let repeated = serde_json::to_vec(&PortableServiceGraphV1::from_graph(&graph()))
            .expect("repeated graph serializes");
        assert_eq!(first, repeated);

        let decoded: PortableServiceGraphV1 =
            serde_json::from_slice(&first).expect("portable graph parses");
        let compiled = Arc::new(decoded.compile().expect("portable graph recompiles"));
        ServiceProgram::new(ServiceId::new("service:root"), compiled)
            .validate()
            .expect("portable graph retains Service invariants");
    }

    #[test]
    fn rejects_unknown_schema_and_duplicate_nodes() {
        let mut portable = PortableServiceGraphV1::from_graph(&graph());
        portable.schema_version = "oxidase.service-program/v999".to_owned();
        assert!(portable.compile().is_err());

        let mut duplicate = PortableServiceGraphV1::from_graph(&graph());
        duplicate.nodes.push(duplicate.nodes[0].clone());
        assert!(duplicate.compile().is_err());

        let mut unsafe_span = PortableServiceGraphV1::from_graph(&graph());
        unsafe_span.nodes[0].source.file = std::path::PathBuf::from("/absolute/source.yaml");
        assert!(matches!(
            unsafe_span.compile(),
            Err(PortableIrError::Invalid {
                field: "service.source",
                ..
            })
        ));
    }

    #[test]
    fn source_path_mapping_preserves_semantic_coordinates() {
        let mut portable = PortableServiceGraphV1::from_graph(&graph());
        portable.map_source_files(|path| {
            std::path::PathBuf::from("sources").join(
                path.file_name()
                    .unwrap_or_else(|| std::ffi::OsStr::new("generated")),
            )
        });
        for node in portable.nodes {
            assert!(node.source.file.starts_with("sources"));
            assert_eq!(node.source.line, 1);
            assert!(!node.source.field_path.is_empty());
        }
    }

    #[test]
    fn portable_values_preserve_float_bits_bytes_and_strict_shape() {
        let value = Value::List(vec![
            Value::Float(f64::from_bits(0x7ff8_0000_0000_0042)),
            Value::Float(-0.0),
            Value::Bytes(vec![0, 255]),
        ]);
        let portable = PortableValueV1::from_value(&value);
        let encoded = serde_json::to_vec(&portable).expect("portable value serializes");
        let decoded: PortableValueV1 =
            serde_json::from_slice(&encoded).expect("portable value parses");
        let Value::List(values) = decoded.compile() else {
            panic!("fixture remains a list");
        };
        let Value::Float(nan) = values[0] else {
            panic!("first value remains a float");
        };
        let Value::Float(negative_zero) = values[1] else {
            panic!("second value remains a float");
        };
        assert_eq!(nan.to_bits(), 0x7ff8_0000_0000_0042);
        assert_eq!(negative_zero.to_bits(), (-0.0_f64).to_bits());
        assert_eq!(values[2], Value::Bytes(vec![0, 255]));

        assert!(
            serde_json::from_str::<PortableValueV1>(r#"{"type":"null","future":true}"#).is_err()
        );
    }
}
