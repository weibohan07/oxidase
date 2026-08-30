use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderName, Method, StatusCode};
use thiserror::Error;

use crate::{
    CompiledPattern, CompiledTemplate, ErrorClass, Expression, ExpressionError, PatternContext,
    ResourceId, RouteId, ServiceId, SourceSpan, Value,
};
use crate::{RequestFrame, pattern::PatternError};

#[derive(Debug)]
pub struct ServiceGraph {
    nodes: BTreeMap<ServiceId, ServiceNode>,
}

impl ServiceGraph {
    #[must_use]
    pub fn new(nodes: BTreeMap<ServiceId, ServiceNode>) -> Self {
        Self { nodes }
    }

    #[must_use]
    pub fn get(&self, id: &ServiceId) -> Option<&ServiceNode> {
        self.nodes.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&ServiceId, &ServiceNode)> {
        self.nodes.iter()
    }

    pub fn keys(&self) -> impl Iterator<Item = &ServiceId> {
        self.nodes.keys()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct ServiceProgram {
    pub entry: ServiceId,
    pub graph: Arc<ServiceGraph>,
}

impl ServiceProgram {
    #[must_use]
    pub fn new(entry: ServiceId, graph: Arc<ServiceGraph>) -> Self {
        Self { entry, graph }
    }

    #[must_use]
    pub fn from_nodes(entry: ServiceId, nodes: BTreeMap<ServiceId, ServiceNode>) -> Self {
        Self::new(entry, Arc::new(ServiceGraph::new(nodes)))
    }

    pub fn validate(&self) -> Result<(), ServiceProgramError> {
        if self.graph.get(&self.entry).is_none() {
            return Err(ServiceProgramError::MissingService(self.entry.clone()));
        }
        for (id, node) in self.graph.iter() {
            for referenced in node.kind.references() {
                if self.graph.get(referenced).is_none() {
                    return Err(ServiceProgramError::MissingReference {
                        owner: id.clone(),
                        target: referenced.clone(),
                    });
                }
            }
            if let ServiceKind::Reenter { budget, .. } = node.kind
                && budget == 0
            {
                return Err(ServiceProgramError::ZeroReenterBudget(id.clone()));
            }
            match &node.kind {
                ServiceKind::RequestBodyLimit { max_bytes, .. } if *max_bytes == 0 => {
                    return Err(ServiceProgramError::InvalidLimit {
                        service: id.clone(),
                        field: "max_bytes",
                    });
                }
                ServiceKind::ConcurrencyLimit {
                    name,
                    max_in_flight,
                    ..
                } if name.is_empty() || *max_in_flight == 0 => {
                    return Err(ServiceProgramError::InvalidLimit {
                        service: id.clone(),
                        field: if name.is_empty() {
                            "name"
                        } else {
                            "max_in_flight"
                        },
                    });
                }
                ServiceKind::RateLimit {
                    name,
                    key,
                    requests,
                    per,
                    burst,
                    max_keys,
                    idle_ttl,
                    ..
                } if name.is_empty()
                    || matches!(key, RateLimitKey::Binding(name) if name.is_empty())
                    || *requests == 0
                    || per.is_zero()
                    || *burst == 0
                    || *max_keys == 0
                    || idle_ttl.is_zero() =>
                {
                    let field = if name.is_empty() {
                        "name"
                    } else if matches!(key, RateLimitKey::Binding(name) if name.is_empty()) {
                        "key.name"
                    } else if *requests == 0 {
                        "rate.requests"
                    } else if per.is_zero() {
                        "rate.per"
                    } else if *burst == 0 {
                        "burst"
                    } else if *max_keys == 0 {
                        "state.max_keys"
                    } else {
                        "state.idle_ttl"
                    };
                    return Err(ServiceProgramError::InvalidLimit {
                        service: id.clone(),
                        field,
                    });
                }
                _ => {}
            }
            if let ServiceKind::Fallback { services } = &node.kind {
                for service in services.iter().take(services.len().saturating_sub(1)) {
                    if self.may_consume_body(service, &mut BTreeSet::new())? {
                        return Err(ServiceProgramError::UnsafeFallbackBody {
                            fallback: id.clone(),
                            candidate: service.clone(),
                        });
                    }
                }
            }
        }

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for id in self.graph.keys() {
            self.visit_acyclic(id, &mut visiting, &mut visited)?;
        }
        Ok(())
    }

    fn visit_acyclic(
        &self,
        id: &ServiceId,
        visiting: &mut BTreeSet<ServiceId>,
        visited: &mut BTreeSet<ServiceId>,
    ) -> Result<(), ServiceProgramError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !visiting.insert(id.clone()) {
            return Err(ServiceProgramError::ReferenceCycle(id.clone()));
        }
        let node = self
            .graph
            .get(id)
            .ok_or_else(|| ServiceProgramError::MissingService(id.clone()))?;
        for child in node.kind.non_reenter_references() {
            self.visit_acyclic(child, visiting, visited)?;
        }
        visiting.remove(id);
        visited.insert(id.clone());
        Ok(())
    }

    fn may_consume_body(
        &self,
        id: &ServiceId,
        visiting: &mut BTreeSet<ServiceId>,
    ) -> Result<bool, ServiceProgramError> {
        if !visiting.insert(id.clone()) {
            // Cycles are diagnosed separately. Conservatively reject a cyclic body
            // analysis path if it can only be reached through malformed IR.
            return Ok(true);
        }
        let node = self
            .graph
            .get(id)
            .ok_or_else(|| ServiceProgramError::MissingService(id.clone()))?;
        let consumes = match &node.kind {
            ServiceKind::Proxy { .. } => true,
            ServiceKind::Route { cases, default } => {
                let case_consumes = cases.iter().try_fold(false, |consumes, case| {
                    self.may_consume_body(&case.service, visiting)
                        .map(|value| consumes || value)
                })?;
                if case_consumes {
                    true
                } else if let Some(default) = default {
                    self.may_consume_body(default, visiting)?
                } else {
                    false
                }
            }
            ServiceKind::Fallback { services } => {
                let mut consumes = false;
                for service in services {
                    consumes |= self.may_consume_body(service, visiting)?;
                }
                consumes
            }
            ServiceKind::Transform { service, .. }
            | ServiceKind::Observe { service, .. }
            | ServiceKind::Timeout { service, .. }
            | ServiceKind::RequestBodyLimit { service, .. }
            | ServiceKind::ConcurrencyLimit { service, .. }
            | ServiceKind::RateLimit { service, .. } => self.may_consume_body(service, visiting)?,
            ServiceKind::Recover { service, handlers } => {
                let mut consumes = self.may_consume_body(service, visiting)?;
                for handler in handlers {
                    consumes |= self.may_consume_body(&handler.service, visiting)?;
                }
                consumes
            }
            ServiceKind::Reenter { .. } => true,
            ServiceKind::Respond { .. }
            | ServiceKind::Redirect { .. }
            | ServiceKind::Site { .. } => false,
        };
        visiting.remove(id);
        Ok(consumes)
    }
}

#[derive(Debug, Clone)]
pub struct ServiceNode {
    pub id: ServiceId,
    pub source: SourceSpan,
    pub kind: ServiceKind,
}

#[derive(Debug, Clone)]
pub enum ServiceKind {
    Respond {
        status: StatusCode,
        headers: HeaderTransforms,
        body: RespondBody,
    },
    Redirect {
        status: StatusCode,
        location: CompiledTemplate,
        preserve_query: bool,
        headers: HeaderTransforms,
    },
    Site {
        resource: ResourceId,
    },
    Proxy {
        cluster: ResourceId,
    },
    Transform {
        request: Box<RequestTransform>,
        response: Box<ResponseTransform>,
        service: ServiceId,
    },
    Observe {
        name: String,
        service: ServiceId,
    },
    Timeout {
        duration: Duration,
        service: ServiceId,
    },
    /// Enforces a streaming request-body byte ceiling around `service`.
    RequestBodyLimit {
        max_bytes: u64,
        service: ServiceId,
    },
    /// Admits at most `max_in_flight` executions into `service`.
    ConcurrencyLimit {
        name: String,
        max_in_flight: u32,
        queue_timeout: Duration,
        reject_status: StatusCode,
        service: ServiceId,
    },
    /// Applies a bounded token-bucket admission policy before executing `service`.
    RateLimit {
        name: String,
        key: RateLimitKey,
        requests: u64,
        per: Duration,
        burst: u64,
        max_keys: u32,
        idle_ttl: Duration,
        service: ServiceId,
    },
    Recover {
        service: ServiceId,
        handlers: Vec<RecoverHandler>,
    },
    Route {
        cases: Vec<RouteCase>,
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

impl ServiceKind {
    fn references(&self) -> Vec<&ServiceId> {
        match self {
            Self::Transform { service, .. }
            | Self::Observe { service, .. }
            | Self::Timeout { service, .. }
            | Self::RequestBodyLimit { service, .. }
            | Self::ConcurrencyLimit { service, .. }
            | Self::RateLimit { service, .. } => vec![service],
            Self::Recover { service, handlers } => std::iter::once(service)
                .chain(handlers.iter().map(|handler| &handler.service))
                .collect(),
            Self::Route { cases, default } => cases
                .iter()
                .map(|case| &case.service)
                .chain(default.iter())
                .collect(),
            Self::Fallback { services } => services.iter().collect(),
            Self::Reenter { target, .. } => vec![target],
            Self::Respond { .. }
            | Self::Redirect { .. }
            | Self::Site { .. }
            | Self::Proxy { .. } => Vec::new(),
        }
    }

    fn non_reenter_references(&self) -> Vec<&ServiceId> {
        if matches!(self, Self::Reenter { .. }) {
            Vec::new()
        } else {
            self.references()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitKey {
    /// The transport peer address, never a forwarded client header.
    PeerIp,
    /// A lexical route binding compiled from a static configuration name.
    Binding(String),
}

#[derive(Debug, Clone)]
pub enum RespondBody {
    Empty,
    Bytes(Bytes),
    Text(CompiledTemplate),
    Json(Value),
}

#[derive(Debug, Clone, Default)]
pub struct RequestTransform {
    pub method: Option<Method>,
    pub scheme: Option<CompiledMetadata<Scheme>>,
    pub authority: Option<CompiledMetadata<Authority>>,
    pub path_and_query: Option<CompiledMetadata<PathAndQuery>>,
    pub headers: HeaderTransforms,
}

#[derive(Debug, Clone)]
pub enum CompiledMetadata<T> {
    Constant(T),
    Dynamic(CompiledTemplate),
}

#[derive(Debug, Clone, Default)]
pub struct ResponseTransform {
    pub headers: HeaderTransforms,
}

#[derive(Debug, Clone, Default)]
pub struct HeaderTransforms {
    pub set: Vec<HeaderTransform>,
    pub add: Vec<HeaderTransform>,
    pub remove: Vec<HeaderName>,
}

#[derive(Debug, Clone)]
pub struct HeaderTransform {
    pub name: HeaderName,
    pub value: CompiledTemplate,
}

#[derive(Debug, Clone)]
pub struct RecoverHandler {
    pub classes: BTreeSet<ErrorClass>,
    pub service: ServiceId,
}

#[derive(Debug, Clone)]
pub struct RouteCase {
    pub id: RouteId,
    pub predicate: PredicatePlan,
    pub service: ServiceId,
    pub source: SourceSpan,
}

#[derive(Debug, Clone, Default)]
pub struct PredicatePlan {
    pub methods: Vec<Method>,
    pub host: Option<CompiledPattern>,
    pub path: Option<CompiledPattern>,
    pub headers: Vec<HeaderPredicate>,
    pub expression: Option<Expression>,
}

impl PredicatePlan {
    pub fn evaluate(
        &self,
        request: &RequestFrame,
    ) -> Result<Option<BTreeMap<String, Value>>, ExpressionError> {
        if !self.methods.is_empty() && !self.methods.iter().any(|method| method == request.method())
        {
            return Ok(None);
        }

        let mut captures = BTreeMap::new();
        if let Some(pattern) = &self.host {
            let Some(values) = pattern.captures(request.host()) else {
                return Ok(None);
            };
            captures.extend(
                values
                    .into_iter()
                    .map(|(name, value)| (name, Value::String(value))),
            );
        }
        if let Some(pattern) = &self.path {
            let Some(values) = pattern.captures(request.path()) else {
                return Ok(None);
            };
            captures.extend(
                values
                    .into_iter()
                    .map(|(name, value)| (name, Value::String(value))),
            );
        }
        let headers = request.effective_headers();
        for predicate in &self.headers {
            let value = headers
                .get_all(&predicate.name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find_map(|value| predicate.pattern.captures(value));
            let matched = value.is_some();
            if matched == predicate.negated {
                return Ok(None);
            }
            if !predicate.negated {
                captures.extend(
                    value
                        .into_iter()
                        .flatten()
                        .map(|(name, value)| (name, Value::String(value))),
                );
            }
        }
        if let Some(expression) = &self.expression {
            let request = request.with_bindings(captures.clone());
            let value = expression.evaluate(&request.evaluation_context())?;
            if value.as_bool() != Some(true) {
                return Ok(None);
            }
        }
        Ok(Some(captures))
    }

    pub fn path(source: &str) -> Result<Self, PatternError> {
        Ok(Self {
            path: Some(CompiledPattern::compile(source, PatternContext::Path)?),
            ..Self::default()
        })
    }
}

#[derive(Debug, Clone)]
pub struct HeaderPredicate {
    pub name: HeaderName,
    pub pattern: CompiledPattern,
    pub negated: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ServiceProgramError {
    #[error("entry service `{0}` does not exist")]
    MissingService(ServiceId),
    #[error("service `{owner}` references missing service `{target}`")]
    MissingReference { owner: ServiceId, target: ServiceId },
    #[error("service reference cycle reaches `{0}` without an explicit Reenter node")]
    ReferenceCycle(ServiceId),
    #[error("Reenter service `{0}` has a zero execution budget")]
    ZeroReenterBudget(ServiceId),
    #[error("service `{service}` has an invalid `{field}` limit field")]
    InvalidLimit {
        service: ServiceId,
        field: &'static str,
    },
    #[error(
        "fallback `{fallback}` places body-consuming service `{candidate}` before another candidate"
    )]
    UnsafeFallbackBody {
        fallback: ServiceId,
        candidate: ServiceId,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use http::StatusCode;

    use super::{
        HeaderTransforms, RateLimitKey, RespondBody, ServiceKind, ServiceNode, ServiceProgram,
    };
    use crate::{ServiceId, SourceSpan};

    fn node(id: &str, kind: ServiceKind) -> ServiceNode {
        ServiceNode {
            id: ServiceId::new(id),
            source: SourceSpan::synthetic(id),
            kind,
        }
    }

    #[test]
    fn rejects_implicit_reference_cycles() {
        let first = node(
            "first",
            ServiceKind::Fallback {
                services: vec![ServiceId::new("second")],
            },
        );
        let second = node(
            "second",
            ServiceKind::Fallback {
                services: vec![ServiceId::new("first")],
            },
        );
        let program = ServiceProgram::from_nodes(
            ServiceId::new("first"),
            BTreeMap::from([(first.id.clone(), first), (second.id.clone(), second)]),
        );
        assert!(program.validate().is_err());
    }

    #[test]
    fn accepts_explicit_budgeted_reentry() {
        let respond = node(
            "root",
            ServiceKind::Respond {
                status: StatusCode::OK,
                headers: HeaderTransforms::default(),
                body: RespondBody::Empty,
            },
        );
        let reenter = node(
            "again",
            ServiceKind::Reenter {
                target: ServiceId::new("root"),
                budget: 2,
            },
        );
        let program = ServiceProgram::from_nodes(
            ServiceId::new("again"),
            BTreeMap::from([(respond.id.clone(), respond), (reenter.id.clone(), reenter)]),
        );
        assert!(program.validate().is_ok());
    }

    #[test]
    fn rejects_proxy_before_later_fallback_candidate() {
        let proxy = node(
            "proxy",
            ServiceKind::Proxy {
                cluster: "api".into(),
            },
        );
        let respond = node(
            "respond",
            ServiceKind::Respond {
                status: StatusCode::OK,
                headers: HeaderTransforms::default(),
                body: RespondBody::Empty,
            },
        );
        let fallback = node(
            "fallback",
            ServiceKind::Fallback {
                services: vec![proxy.id.clone(), respond.id.clone()],
            },
        );
        let program = ServiceProgram::from_nodes(
            fallback.id.clone(),
            BTreeMap::from([
                (proxy.id.clone(), proxy),
                (respond.id.clone(), respond),
                (fallback.id.clone(), fallback),
            ]),
        );
        assert!(program.validate().is_err());
    }

    #[test]
    fn governance_wrappers_preserve_fallback_body_consumption_analysis() {
        let proxy = node(
            "proxy",
            ServiceKind::Proxy {
                cluster: "api".into(),
            },
        );
        let body_limit = node(
            "body-limit",
            ServiceKind::RequestBodyLimit {
                max_bytes: 1024,
                service: proxy.id.clone(),
            },
        );
        let concurrency = node(
            "concurrency",
            ServiceKind::ConcurrencyLimit {
                name: "public".to_owned(),
                max_in_flight: 10,
                queue_timeout: std::time::Duration::ZERO,
                reject_status: StatusCode::SERVICE_UNAVAILABLE,
                service: body_limit.id.clone(),
            },
        );
        let rate = node(
            "rate",
            ServiceKind::RateLimit {
                name: "public".to_owned(),
                key: RateLimitKey::PeerIp,
                requests: 100,
                per: std::time::Duration::from_secs(1),
                burst: 200,
                max_keys: 1_000,
                idle_ttl: std::time::Duration::from_secs(60),
                service: concurrency.id.clone(),
            },
        );
        let respond = node(
            "respond",
            ServiceKind::Respond {
                status: StatusCode::OK,
                headers: HeaderTransforms::default(),
                body: RespondBody::Empty,
            },
        );
        let fallback = node(
            "fallback",
            ServiceKind::Fallback {
                services: vec![rate.id.clone(), respond.id.clone()],
            },
        );
        let program = ServiceProgram::from_nodes(
            fallback.id.clone(),
            BTreeMap::from([
                (proxy.id.clone(), proxy),
                (body_limit.id.clone(), body_limit),
                (concurrency.id.clone(), concurrency),
                (rate.id.clone(), rate),
                (respond.id.clone(), respond),
                (fallback.id.clone(), fallback),
            ]),
        );
        assert!(matches!(
            program.validate(),
            Err(super::ServiceProgramError::UnsafeFallbackBody { .. })
        ));
    }

    #[test]
    fn rejects_invalid_governance_ir_before_execution() {
        let respond = node(
            "respond",
            ServiceKind::Respond {
                status: StatusCode::OK,
                headers: HeaderTransforms::default(),
                body: RespondBody::Empty,
            },
        );
        let invalid = node(
            "invalid",
            ServiceKind::RateLimit {
                name: "public".to_owned(),
                key: RateLimitKey::PeerIp,
                requests: 0,
                per: std::time::Duration::from_secs(1),
                burst: 1,
                max_keys: 1,
                idle_ttl: std::time::Duration::from_secs(1),
                service: respond.id.clone(),
            },
        );
        let program = ServiceProgram::from_nodes(
            invalid.id.clone(),
            BTreeMap::from([(respond.id.clone(), respond), (invalid.id.clone(), invalid)]),
        );
        assert!(matches!(
            program.validate(),
            Err(super::ServiceProgramError::InvalidLimit {
                field: "rate.requests",
                ..
            })
        ));
    }
}
