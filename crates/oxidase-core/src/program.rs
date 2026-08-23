use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, Method, StatusCode};
use thiserror::Error;

use crate::{
    CompiledPattern, CompiledTemplate, ErrorClass, Expression, ExpressionError, PatternContext,
    ResourceId, RouteId, ServiceId, SourceSpan, Value,
};
use crate::{RequestFrame, pattern::PatternError};

#[derive(Debug, Clone)]
pub struct ServiceProgram {
    pub entry: ServiceId,
    pub nodes: BTreeMap<ServiceId, ServiceNode>,
}

impl ServiceProgram {
    pub fn validate(&self) -> Result<(), ServiceProgramError> {
        if !self.nodes.contains_key(&self.entry) {
            return Err(ServiceProgramError::MissingService(self.entry.clone()));
        }
        for (id, node) in &self.nodes {
            for referenced in node.kind.references() {
                if !self.nodes.contains_key(referenced) {
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
        for id in self.nodes.keys() {
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
            .nodes
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
            .nodes
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
            | ServiceKind::Timeout { service, .. } => self.may_consume_body(service, visiting)?,
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
            | Self::Timeout { service, .. } => vec![service],
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
    pub scheme: Option<CompiledTemplate>,
    pub authority: Option<CompiledTemplate>,
    pub path_and_query: Option<CompiledTemplate>,
    pub headers: HeaderTransforms,
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
        let headers = request.headers();
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

    use super::{HeaderTransforms, RespondBody, ServiceKind, ServiceNode, ServiceProgram};
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
        let program = ServiceProgram {
            entry: ServiceId::new("first"),
            nodes: BTreeMap::from([(first.id.clone(), first), (second.id.clone(), second)]),
        };
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
        let program = ServiceProgram {
            entry: ServiceId::new("again"),
            nodes: BTreeMap::from([(respond.id.clone(), respond), (reenter.id.clone(), reenter)]),
        };
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
        let program = ServiceProgram {
            entry: fallback.id.clone(),
            nodes: BTreeMap::from([
                (proxy.id.clone(), proxy),
                (respond.id.clone(), respond),
                (fallback.id.clone(), fallback),
            ]),
        };
        assert!(program.validate().is_err());
    }
}
