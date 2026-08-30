use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use oxidase_core::{
    BodyState, CompiledMetadata, ErrorClass, HeaderTransforms, RateLimitKey, RequestFrame,
    RequestMetadataError, RequestTransform, ResourceId, RespondBody, ResponseHead,
    ResponseTransform, RouteId, ServiceError, ServiceId, ServiceKind, ServiceOutcome,
    ServiceProgram, SourceSpan, Value, parse_transform_authority, parse_transform_path_and_query,
    parse_transform_scheme,
};

use crate::governance::{
    ConcurrencyPermit, ConcurrencyRejection, GovernanceRegistry, RateLimitDecision,
    RateLimitRejection,
};

pub type BoxLeafFuture<'a, B> = Pin<Box<dyn Future<Output = ServiceOutcome<B>> + Send + 'a>>;

/// The boundary between protocol-independent Service execution and concrete
/// request/response body implementations. Production and in-memory explain/test
/// execution are both consumers of this boundary.
pub trait LeafExecutor<RequestBody, ResponseBody>: Send + Sync {
    fn body_from_bytes(&self, bytes: Bytes) -> ResponseBody;

    fn execute_site<'a>(
        &'a self,
        resource: &'a ResourceId,
        request: &'a RequestFrame,
    ) -> BoxLeafFuture<'a, ResponseBody>;

    fn execute_proxy<'a>(
        &'a self,
        cluster: &'a ResourceId,
        request: &'a RequestFrame,
        body: &'a mut Option<RequestBody>,
        max_request_body_bytes: Option<u64>,
    ) -> BoxLeafFuture<'a, ResponseBody>;

    fn governance(&self) -> Option<&GovernanceRegistry> {
        None
    }

    fn retain_concurrency_permit(
        &self,
        body: ResponseBody,
        _permit: ConcurrencyPermit,
    ) -> ResponseBody {
        body
    }

    fn record_governance_result(&self, _kind: &'static str, _name: &str, _result: &'static str) {}
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionTrace {
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub service: ServiceId,
    pub route: Option<RouteId>,
    pub event: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Copy)]
pub enum TraceDetail<'a> {
    Source(&'a SourceSpan),
    Text(&'a str),
    Bindings(usize),
    Service(&'a ServiceId),
    Recovery {
        class: ErrorClass,
        service: &'a ServiceId,
    },
    Reentry {
        target: &'a ServiceId,
        count: u32,
        budget: u32,
    },
    RequestBodyLimit {
        max_bytes: u64,
    },
    ConcurrencyLimit {
        name: &'a str,
        max_in_flight: u32,
        queue_timeout: Duration,
        reject_status: StatusCode,
    },
    RateLimit {
        name: &'a str,
        key: &'a RateLimitKey,
        requests: u64,
        per: Duration,
        burst: u64,
        max_keys: u32,
        idle_ttl: Duration,
    },
}

impl fmt::Display for TraceDetail<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(source) => source.fmt(formatter),
            Self::Text(text) => formatter.write_str(text),
            Self::Bindings(count) => write!(formatter, "{count} binding(s)"),
            Self::Service(service) => service.fmt(formatter),
            Self::Recovery { class, service } => write!(formatter, "{class:?} -> {service}"),
            Self::Reentry {
                target,
                count,
                budget,
            } => write!(formatter, "{target} ({count}/{budget})"),
            Self::RequestBodyLimit { max_bytes } => {
                write!(formatter, "max_bytes={max_bytes}")
            }
            Self::ConcurrencyLimit {
                name,
                max_in_flight,
                queue_timeout,
                reject_status,
            } => write!(
                formatter,
                "name={name} max_in_flight={max_in_flight} queue_timeout={queue_timeout:?} reject_status={}",
                reject_status.as_u16()
            ),
            Self::RateLimit {
                name,
                key,
                requests,
                per,
                burst,
                max_keys,
                idle_ttl,
            } => {
                let key = match key {
                    RateLimitKey::PeerIp => "peer_ip".to_owned(),
                    RateLimitKey::Binding(binding) => format!("binding:{binding}"),
                };
                write!(
                    formatter,
                    "name={name} key={key} requests={requests} per={per:?} burst={burst} max_keys={max_keys} idle_ttl={idle_ttl:?}"
                )
            }
        }
    }
}

pub trait TraceSink: Send {
    fn record(
        &mut self,
        service: &ServiceId,
        route: Option<&RouteId>,
        event: &'static str,
        detail: TraceDetail<'_>,
    );
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceObservationContext<'a> {
    pub observe_name: &'a str,
    pub service_id: &'a ServiceId,
    pub depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceObservationOutcome {
    Handled(StatusCode),
    Declined,
    Failed(ErrorClass),
}

impl ServiceObservationOutcome {
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Handled(_) => "handled",
            Self::Declined => "declined",
            Self::Failed(_) => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceObservationResult {
    pub outcome: ServiceObservationOutcome,
}

pub trait ExecutionObserver: Send + Sync {
    type Scope: Send;

    fn service_started(&self, context: ServiceObservationContext<'_>) -> Self::Scope;

    fn service_finished(&self, scope: Self::Scope, result: ServiceObservationResult);

    fn service_cancelled(&self, scope: Self::Scope);
}

#[derive(Debug, Default)]
pub struct NoopExecutionObserver;

impl ExecutionObserver for NoopExecutionObserver {
    type Scope = ();

    fn service_started(&self, _context: ServiceObservationContext<'_>) {}

    fn service_finished(&self, _scope: Self::Scope, _result: ServiceObservationResult) {}

    fn service_cancelled(&self, _scope: Self::Scope) {}
}

struct ActiveObservation<'a, Observer: ExecutionObserver> {
    observer: &'a Observer,
    scope: Option<Observer::Scope>,
}

struct ExecutionContext<'a, RequestBody, Sink, Observer> {
    body: Option<RequestBody>,
    state: ExecutionState,
    trace: &'a mut Sink,
    observer: &'a Observer,
}

impl<'a, Observer: ExecutionObserver> ActiveObservation<'a, Observer> {
    fn new(observer: &'a Observer, scope: Observer::Scope) -> Self {
        Self {
            observer,
            scope: Some(scope),
        }
    }

    fn finish(mut self, result: ServiceObservationResult) {
        let scope = self.scope.take().expect("observation scope is active");
        self.observer.service_finished(scope, result);
    }
}

impl<Observer: ExecutionObserver> Drop for ActiveObservation<'_, Observer> {
    fn drop(&mut self) {
        if let Some(scope) = self.scope.take() {
            self.observer.service_cancelled(scope);
        }
    }
}

#[derive(Debug, Default)]
pub struct NoopTraceSink;

impl TraceSink for NoopTraceSink {
    fn record(
        &mut self,
        _service: &ServiceId,
        _route: Option<&RouteId>,
        _event: &'static str,
        _detail: TraceDetail<'_>,
    ) {
    }
}

#[derive(Debug, Default)]
pub struct ExplainTraceCollector {
    trace: ExecutionTrace,
}

impl ExplainTraceCollector {
    #[must_use]
    pub fn into_trace(self) -> ExecutionTrace {
        self.trace
    }
}

impl TraceSink for ExplainTraceCollector {
    fn record(
        &mut self,
        service: &ServiceId,
        route: Option<&RouteId>,
        event: &'static str,
        detail: TraceDetail<'_>,
    ) {
        self.trace.events.push(TraceEvent {
            service: service.clone(),
            route: route.cloned(),
            event,
            detail: detail.to_string(),
        });
    }
}

#[derive(Debug)]
pub struct ExecutionReport<ResponseBody> {
    pub outcome: ServiceOutcome<ResponseBody>,
    pub trace: ExecutionTrace,
    pub body_state: BodyState,
}

pub struct Executor<'a, RequestBody, ResponseBody, Leaves> {
    program: &'a ServiceProgram,
    leaves: &'a Leaves,
    marker: std::marker::PhantomData<fn(RequestBody) -> ResponseBody>,
}

impl<'a, RequestBody, ResponseBody, Leaves> Executor<'a, RequestBody, ResponseBody, Leaves>
where
    RequestBody: Send,
    ResponseBody: Send,
    Leaves: LeafExecutor<RequestBody, ResponseBody>,
{
    #[must_use]
    pub fn new(program: &'a ServiceProgram, leaves: &'a Leaves) -> Self {
        Self {
            program,
            leaves,
            marker: std::marker::PhantomData,
        }
    }

    pub async fn execute(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
    ) -> ExecutionReport<ResponseBody> {
        let mut trace = NoopTraceSink;
        let observer = NoopExecutionObserver;
        self.execute_instrumented(request, body, &mut trace, &observer)
            .await
    }

    pub async fn execute_traced(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
    ) -> ExecutionReport<ResponseBody> {
        let mut trace = ExplainTraceCollector::default();
        let observer = NoopExecutionObserver;
        let mut report = self
            .execute_instrumented(request, body, &mut trace, &observer)
            .await;
        report.trace = trace.into_trace();
        report
    }

    pub async fn execute_with_sink<Sink>(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
        trace: &mut Sink,
    ) -> ExecutionReport<ResponseBody>
    where
        Sink: TraceSink,
    {
        let observer = NoopExecutionObserver;
        self.execute_instrumented(request, body, trace, &observer)
            .await
    }

    pub async fn execute_observed<Observer>(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
        observer: &Observer,
    ) -> ExecutionReport<ResponseBody>
    where
        Observer: ExecutionObserver,
    {
        let mut trace = NoopTraceSink;
        self.execute_instrumented(request, body, &mut trace, observer)
            .await
    }

    pub async fn execute_with_sink_and_observer<Sink, Observer>(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
        trace: &mut Sink,
        observer: &Observer,
    ) -> ExecutionReport<ResponseBody>
    where
        Sink: TraceSink,
        Observer: ExecutionObserver,
    {
        self.execute_instrumented(request, body, trace, observer)
            .await
    }

    async fn execute_instrumented<Sink, Observer>(
        &self,
        request: RequestFrame,
        body: Option<RequestBody>,
        trace: &mut Sink,
        observer: &Observer,
    ) -> ExecutionReport<ResponseBody>
    where
        Sink: TraceSink,
        Observer: ExecutionObserver,
    {
        let mut execution = ExecutionContext {
            body,
            state: ExecutionState::default(),
            trace,
            observer,
        };
        let outcome = self
            .execute_node(&self.program.entry, request, &mut execution, 0, None)
            .await;
        ExecutionReport {
            outcome,
            trace: ExecutionTrace::default(),
            body_state: execution.state.body_state,
        }
    }

    fn execute_node<'b, Sink, Observer>(
        &'b self,
        id: &'b ServiceId,
        request: RequestFrame,
        execution: &'b mut ExecutionContext<'_, RequestBody, Sink, Observer>,
        observation_depth: usize,
        request_body_limit: Option<u64>,
    ) -> BoxLeafFuture<'b, ResponseBody>
    where
        Sink: TraceSink + 'b,
        Observer: ExecutionObserver + 'b,
    {
        Box::pin(async move {
            let Some(node) = self.program.graph.get(id) else {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("runtime plan references missing service `{id}`"),
                ));
            };
            execution
                .trace
                .record(id, None, "enter", TraceDetail::Source(&node.source));

            let outcome = match &node.kind {
                ServiceKind::Respond {
                    status,
                    headers,
                    body: response_body,
                } => self.execute_respond(*status, headers, response_body, &request),
                ServiceKind::Redirect {
                    status,
                    location,
                    preserve_query,
                    headers,
                } => {
                    let context = request.evaluation_context();
                    match location.render(&context).and_then(|location| {
                        let location = append_query(location, *preserve_query, &request);
                        validate_redirect_location(&location)
                            .map(|value| (location, value))
                            .map_err(|_| oxidase_core::TemplateError::Render("invalid Location"))
                    }) {
                        Ok((_, location)) => {
                            let mut response = ResponseHead::new(
                                *status,
                                self.leaves.body_from_bytes(Bytes::new()),
                            );
                            response.headers.insert(header::LOCATION, location);
                            match apply_response_headers(headers, &request, &mut response.headers) {
                                Ok(()) => ServiceOutcome::Handled(response),
                                Err(error) => ServiceOutcome::Failed(error),
                            }
                        }
                        Err(error) => ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::InvalidState,
                            format!("redirect template failed: {error}"),
                        )),
                    }
                }
                ServiceKind::Site { resource } => {
                    self.leaves.execute_site(resource, &request).await
                }
                ServiceKind::Proxy { cluster } => {
                    if execution.state.body_state == BodyState::Consumed {
                        ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::BodyUnavailable,
                            "request body was already consumed before Proxy",
                        ))
                    } else {
                        // Mark before the first await so cancellation cannot make a
                        // partially consumed stream appear replayable.
                        execution.state.body_state = BodyState::Consumed;
                        self.leaves
                            .execute_proxy(
                                cluster,
                                &request,
                                &mut execution.body,
                                request_body_limit,
                            )
                            .await
                    }
                }
                ServiceKind::Transform {
                    request: request_transform,
                    response: response_transform,
                    service,
                } => {
                    let mut child_request = request.clone();
                    match apply_request_transform(request_transform, &mut child_request) {
                        Ok(()) => {
                            let outcome = self
                                .execute_node(
                                    service,
                                    child_request,
                                    execution,
                                    observation_depth,
                                    request_body_limit,
                                )
                                .await;
                            apply_response_transform(outcome, response_transform, &request)
                        }
                        Err(error) => ServiceOutcome::Failed(error),
                    }
                }
                ServiceKind::Observe { name, service } => {
                    execution
                        .trace
                        .record(id, None, "observe_start", TraceDetail::Text(name));
                    let observation = ActiveObservation::new(
                        execution.observer,
                        execution
                            .observer
                            .service_started(ServiceObservationContext {
                                observe_name: name,
                                service_id: id,
                                depth: observation_depth,
                            }),
                    );
                    let outcome = self
                        .execute_node(
                            service,
                            request,
                            execution,
                            observation_depth + 1,
                            request_body_limit,
                        )
                        .await;
                    observation.finish(ServiceObservationResult {
                        outcome: observation_outcome(&outcome),
                    });
                    execution.trace.record(
                        id,
                        None,
                        "observe_finish",
                        TraceDetail::Text(outcome.kind()),
                    );
                    outcome
                }
                ServiceKind::Timeout { duration, service } => {
                    match tokio::time::timeout(
                        *duration,
                        self.execute_node(
                            service,
                            request,
                            execution,
                            observation_depth,
                            request_body_limit,
                        ),
                    )
                    .await
                    {
                        Ok(outcome) => outcome,
                        Err(_) => ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::Timeout,
                            format!("service `{service}` exceeded {duration:?}"),
                        )),
                    }
                }
                ServiceKind::RequestBodyLimit { max_bytes, service } => {
                    execution.trace.record(
                        id,
                        None,
                        "policy",
                        TraceDetail::RequestBodyLimit {
                            max_bytes: *max_bytes,
                        },
                    );
                    let effective_limit =
                        request_body_limit.map_or(*max_bytes, |current| current.min(*max_bytes));
                    if request_content_length(&request)
                        .is_some_and(|length| length > effective_limit)
                    {
                        self.leaves.record_governance_result(
                            "request_body_limit",
                            id.as_str(),
                            "rejected",
                        );
                        rejection_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            self.leaves
                                .body_from_bytes(Bytes::from_static(b"Payload Too Large")),
                        )
                    } else {
                        self.leaves.record_governance_result(
                            "request_body_limit",
                            id.as_str(),
                            "evaluated",
                        );
                        self.execute_node(
                            service,
                            request,
                            execution,
                            observation_depth,
                            Some(effective_limit),
                        )
                        .await
                    }
                }
                ServiceKind::ConcurrencyLimit {
                    name,
                    max_in_flight,
                    queue_timeout,
                    reject_status,
                    service,
                } => {
                    execution.trace.record(
                        id,
                        None,
                        "policy",
                        TraceDetail::ConcurrencyLimit {
                            name,
                            max_in_flight: *max_in_flight,
                            queue_timeout: *queue_timeout,
                            reject_status: *reject_status,
                        },
                    );
                    let admission = if let Some(governance) = self.leaves.governance() {
                        governance
                            .acquire_concurrency(id, *max_in_flight, *queue_timeout)
                            .await
                    } else {
                        Ok(ConcurrencyPermit::untracked())
                    };
                    match admission {
                        Ok(permit) => {
                            self.leaves.record_governance_result(
                                "concurrency_limit",
                                name,
                                "admitted",
                            );
                            let outcome = self
                                .execute_node(
                                    service,
                                    request,
                                    execution,
                                    observation_depth,
                                    request_body_limit,
                                )
                                .await;
                            match outcome {
                                ServiceOutcome::Handled(mut response) => {
                                    response.body = self
                                        .leaves
                                        .retain_concurrency_permit(response.body, permit);
                                    ServiceOutcome::Handled(response)
                                }
                                ServiceOutcome::Declined => ServiceOutcome::Declined,
                                ServiceOutcome::Failed(error) => ServiceOutcome::Failed(error),
                            }
                        }
                        Err(ConcurrencyRejection::MissingState) => {
                            ServiceOutcome::Failed(ServiceError::new(
                                ErrorClass::InvalidState,
                                format!("concurrency state for `{id}` is missing"),
                            ))
                        }
                        Err(rejection) => {
                            self.leaves.record_governance_result(
                                "concurrency_limit",
                                name,
                                rejection.as_str(),
                            );
                            rejection_response(
                                *reject_status,
                                self.leaves.body_from_bytes(Bytes::copy_from_slice(
                                    reject_status
                                        .canonical_reason()
                                        .unwrap_or("Request Rejected")
                                        .as_bytes(),
                                )),
                            )
                        }
                    }
                }
                ServiceKind::RateLimit {
                    name,
                    key,
                    requests,
                    per,
                    burst,
                    max_keys,
                    idle_ttl,
                    service,
                } => {
                    execution.trace.record(
                        id,
                        None,
                        "policy",
                        TraceDetail::RateLimit {
                            name,
                            key,
                            requests: *requests,
                            per: *per,
                            burst: *burst,
                            max_keys: *max_keys,
                            idle_ttl: *idle_ttl,
                        },
                    );
                    let decision =
                        self.leaves
                            .governance()
                            .map_or(RateLimitDecision::Allowed, |governance| {
                                governance.check_rate_limit(id, &request, std::time::Instant::now())
                            });
                    match decision {
                        RateLimitDecision::Allowed => {
                            self.leaves
                                .record_governance_result("rate_limit", name, "admitted");
                            self.execute_node(
                                service,
                                request,
                                execution,
                                observation_depth,
                                request_body_limit,
                            )
                            .await
                        }
                        RateLimitDecision::Rejected {
                            reason: RateLimitRejection::MissingState,
                            ..
                        } => ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::InvalidState,
                            format!("rate-limit state for `{id}` is missing"),
                        )),
                        RateLimitDecision::Rejected {
                            retry_after,
                            reason,
                        } => {
                            self.leaves.record_governance_result(
                                "rate_limit",
                                name,
                                reason.as_str(),
                            );
                            let mut response = ResponseHead::new(
                                StatusCode::TOO_MANY_REQUESTS,
                                self.leaves
                                    .body_from_bytes(Bytes::from_static(b"Too Many Requests")),
                            );
                            let seconds = retry_after
                                .as_secs()
                                .saturating_add(u64::from(retry_after.subsec_nanos() != 0))
                                .max(1);
                            response.headers.insert(
                                header::RETRY_AFTER,
                                HeaderValue::from_str(&seconds.to_string())
                                    .expect("u64 seconds form a valid Retry-After value"),
                            );
                            ServiceOutcome::Handled(response)
                        }
                    }
                }
                ServiceKind::Recover { service, handlers } => {
                    let outcome = self
                        .execute_node(
                            service,
                            request.clone(),
                            execution,
                            observation_depth,
                            request_body_limit,
                        )
                        .await;
                    if let ServiceOutcome::Failed(error) = outcome {
                        if let Some(handler) = handlers
                            .iter()
                            .find(|handler| handler.classes.contains(&error.class))
                        {
                            execution.trace.record(
                                id,
                                None,
                                "recover",
                                TraceDetail::Recovery {
                                    class: error.class,
                                    service: &handler.service,
                                },
                            );
                            let mut bindings = BTreeMap::new();
                            bindings.insert(
                                "error_class".to_owned(),
                                Value::from(format!("{:?}", error.class).to_lowercase()),
                            );
                            bindings.insert(
                                "error_status".to_owned(),
                                Value::Integer(i64::from(error.public_status.as_u16())),
                            );
                            self.execute_node(
                                &handler.service,
                                request.with_bindings(bindings),
                                execution,
                                observation_depth,
                                request_body_limit,
                            )
                            .await
                        } else {
                            ServiceOutcome::Failed(error)
                        }
                    } else {
                        outcome
                    }
                }
                ServiceKind::Route { cases, default } => {
                    let mut selected = None;
                    for case in cases {
                        match case.predicate.evaluate(&request) {
                            Ok(Some(bindings)) => {
                                execution.trace.record(
                                    id,
                                    Some(&case.id),
                                    "route_match",
                                    TraceDetail::Bindings(bindings.len()),
                                );
                                selected = Some((case.service.clone(), bindings));
                                break;
                            }
                            Ok(None) => execution.trace.record(
                                id,
                                Some(&case.id),
                                "route_miss",
                                TraceDetail::Text("predicate did not match"),
                            ),
                            Err(error) => {
                                return ServiceOutcome::Failed(ServiceError::new(
                                    ErrorClass::InvalidState,
                                    format!("route predicate failed: {error}"),
                                ));
                            }
                        }
                    }
                    if let Some((service, bindings)) = selected {
                        self.execute_node(
                            &service,
                            request.with_bindings(bindings),
                            execution,
                            observation_depth,
                            request_body_limit,
                        )
                        .await
                    } else if let Some(default) = default {
                        execution.trace.record(
                            id,
                            None,
                            "route_default",
                            TraceDetail::Service(default),
                        );
                        self.execute_node(
                            default,
                            request,
                            execution,
                            observation_depth,
                            request_body_limit,
                        )
                        .await
                    } else {
                        ServiceOutcome::Declined
                    }
                }
                ServiceKind::Fallback { services } => {
                    let mut outcome = ServiceOutcome::Declined;
                    for service in services {
                        let body_before = execution.state.body_state;
                        outcome = self
                            .execute_node(
                                service,
                                request.clone(),
                                execution,
                                observation_depth,
                                request_body_limit,
                            )
                            .await;
                        if matches!(outcome, ServiceOutcome::Declined) {
                            if execution.state.body_state != body_before {
                                return ServiceOutcome::Failed(ServiceError::new(
                                    ErrorClass::BodyUnavailable,
                                    format!(
                                        "fallback candidate `{service}` declined after consuming the body"
                                    ),
                                ));
                            }
                            execution.trace.record(
                                id,
                                None,
                                "fallback_next",
                                TraceDetail::Service(service),
                            );
                        } else {
                            break;
                        }
                    }
                    outcome
                }
                ServiceKind::Reenter { target, budget } => {
                    let count = execution.state.reentries.entry(id.clone()).or_default();
                    if *count >= *budget {
                        ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::InvalidState,
                            format!("Reenter `{id}` exhausted its budget of {budget}"),
                        ))
                    } else {
                        *count += 1;
                        execution.trace.record(
                            id,
                            None,
                            "reenter",
                            TraceDetail::Reentry {
                                target,
                                count: *count,
                                budget: *budget,
                            },
                        );
                        self.execute_node(
                            target,
                            request,
                            execution,
                            observation_depth,
                            request_body_limit,
                        )
                        .await
                    }
                }
            };

            execution
                .trace
                .record(id, None, "outcome", TraceDetail::Text(outcome.kind()));
            outcome
        })
    }

    fn execute_respond(
        &self,
        status: StatusCode,
        headers: &HeaderTransforms,
        body: &RespondBody,
        request: &RequestFrame,
    ) -> ServiceOutcome<ResponseBody> {
        let context = request.evaluation_context();
        let bytes = match body {
            RespondBody::Empty => Bytes::new(),
            RespondBody::Bytes(bytes) => bytes.clone(),
            RespondBody::Text(template) => match template.render(&context) {
                Ok(value) => Bytes::from(value),
                Err(error) => {
                    return ServiceOutcome::Failed(ServiceError::new(
                        ErrorClass::InvalidState,
                        format!("response template failed: {error}"),
                    ));
                }
            },
            RespondBody::Json(value) => match serde_json::to_vec(value) {
                Ok(value) => Bytes::from(value),
                Err(error) => {
                    return ServiceOutcome::Failed(ServiceError::new(
                        ErrorClass::InvalidState,
                        format!("JSON response serialization failed: {error}"),
                    ));
                }
            },
        };
        let mut response = ResponseHead::new(status, self.leaves.body_from_bytes(bytes));
        if matches!(body, RespondBody::Json(_)) {
            response.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        match apply_response_headers(headers, request, &mut response.headers) {
            Ok(()) => ServiceOutcome::Handled(response),
            Err(error) => ServiceOutcome::Failed(error),
        }
    }
}

fn request_content_length(request: &RequestFrame) -> Option<u64> {
    request
        .effective_headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

fn rejection_response<ResponseBody>(
    status: StatusCode,
    body: ResponseBody,
) -> ServiceOutcome<ResponseBody> {
    ServiceOutcome::Handled(ResponseHead::new(status, body))
}

fn observation_outcome<ResponseBody>(
    outcome: &ServiceOutcome<ResponseBody>,
) -> ServiceObservationOutcome {
    match outcome {
        ServiceOutcome::Handled(response) => ServiceObservationOutcome::Handled(response.status),
        ServiceOutcome::Declined => ServiceObservationOutcome::Declined,
        ServiceOutcome::Failed(error) => ServiceObservationOutcome::Failed(error.class),
    }
}

fn append_query(mut location: String, preserve_query: bool, request: &RequestFrame) -> String {
    if preserve_query
        && !location.contains('?')
        && let Some(query) = request.raw_query()
        && !query.is_empty()
    {
        location.push('?');
        location.push_str(query);
    }
    location
}

fn validate_redirect_location(location: &str) -> Result<HeaderValue, ()> {
    if !location.starts_with('/') || location.starts_with("//") || location.contains('\\') {
        return Err(());
    }
    location.parse::<http::Uri>().map_err(|_| ())?;
    HeaderValue::from_str(location).map_err(|_| ())
}

fn apply_request_transform(
    transform: &RequestTransform,
    request: &mut RequestFrame,
) -> Result<(), ServiceError> {
    let context = request.evaluation_context();
    let scheme = render_metadata(
        &transform.scheme,
        &context,
        "scheme",
        parse_transform_scheme,
    )?;
    let authority = render_metadata(
        &transform.authority,
        &context,
        "authority",
        parse_transform_authority,
    )?;
    let path_and_query = render_metadata(
        &transform.path_and_query,
        &context,
        "path_and_query",
        parse_transform_path_and_query,
    )?;
    let set_headers = transform
        .headers
        .set
        .iter()
        .map(|header| {
            render_header(&header.value, &context).map(|value| (header.name.clone(), value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let add_headers = transform
        .headers
        .add
        .iter()
        .map(|header| {
            render_header(&header.value, &context).map(|value| (header.name.clone(), value))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let overlay = request.overlay_mut();
    overlay.method.clone_from(&transform.method);
    overlay.scheme = scheme;
    overlay.authority = authority;
    overlay.path_and_query = path_and_query;
    for name in &transform.headers.remove {
        overlay.remove_header(name.clone());
    }
    for (name, value) in set_headers {
        overlay.set_header(name, value);
    }
    for (name, value) in add_headers {
        overlay.add_header(name, value);
    }
    Ok(())
}

fn apply_response_transform<ResponseBody>(
    outcome: ServiceOutcome<ResponseBody>,
    transform: &ResponseTransform,
    request: &RequestFrame,
) -> ServiceOutcome<ResponseBody> {
    match outcome {
        ServiceOutcome::Handled(mut response) => {
            match apply_response_headers(&transform.headers, request, &mut response.headers) {
                Ok(()) => ServiceOutcome::Handled(response),
                Err(error) => ServiceOutcome::Failed(error),
            }
        }
        ServiceOutcome::Declined => ServiceOutcome::Declined,
        ServiceOutcome::Failed(error) => ServiceOutcome::Failed(error),
    }
}

fn apply_response_headers(
    transforms: &HeaderTransforms,
    request: &RequestFrame,
    headers: &mut HeaderMap,
) -> Result<(), ServiceError> {
    let context = request.evaluation_context();
    for name in &transforms.remove {
        headers.remove(name);
    }
    for header in &transforms.set {
        headers.insert(header.name.clone(), render_header(&header.value, &context)?);
    }
    for header in &transforms.add {
        headers.append(header.name.clone(), render_header(&header.value, &context)?);
    }
    Ok(())
}

fn render_metadata<T: Clone>(
    template: &Option<CompiledMetadata<T>>,
    context: &oxidase_core::EvalContext,
    kind: &'static str,
    parse: fn(&str) -> Result<T, RequestMetadataError>,
) -> Result<Option<T>, ServiceError> {
    let Some(template) = template else {
        return Ok(None);
    };
    match template {
        CompiledMetadata::Constant(value) => Ok(Some(value.clone())),
        CompiledMetadata::Dynamic(template) => {
            let rendered = template.render(context).map_err(|error| {
                ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("request transform `{kind}` rendering failed: {error}"),
                )
            })?;
            parse(&rendered).map(Some).map_err(|error| {
                ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("request transform produced invalid `{kind}`: {error}"),
                )
            })
        }
    }
}

fn render_header(
    template: &oxidase_core::CompiledTemplate,
    context: &oxidase_core::EvalContext,
) -> Result<HeaderValue, ServiceError> {
    let value = template.render(context).map_err(|error| {
        ServiceError::new(
            ErrorClass::InvalidState,
            format!("header transform failed: {error}"),
        )
    })?;
    HeaderValue::from_str(&value).map_err(|_| {
        ServiceError::new(
            ErrorClass::InvalidState,
            "header transform produced an invalid value",
        )
    })
}

#[derive(Default)]
struct ExecutionState {
    body_state: BodyState,
    reentries: BTreeMap<ServiceId, u32>,
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;
    use std::fs;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, Method, StatusCode};
    use oxidase_config::Compiler;
    use oxidase_core::{
        CompiledMetadata, CompiledTemplate, ErrorClass, HeaderTransform, HeaderTransforms,
        PredicatePlan, RateLimitKey, RecoverHandler, RequestFrame, RequestMetadata,
        RequestTransform, RespondBody, ResponseHead, ResponseTransform, RouteCase, RouteId,
        ServiceId, ServiceKind, ServiceNode, ServiceOutcome, ServiceProgram, SourceSpan, Value,
        parse_transform_path_and_query,
    };
    use tempfile::tempdir;

    use super::{
        BoxLeafFuture, ExecutionObserver, Executor, LeafExecutor, ServiceObservationContext,
        ServiceObservationOutcome, ServiceObservationResult,
    };
    use crate::{GovernanceRegistry, RuntimeSnapshot};

    #[derive(Default)]
    struct MemoryLeaves {
        calls: Mutex<Vec<String>>,
        proxy_limits: Mutex<Vec<Option<u64>>>,
        governance: Option<GovernanceRegistry>,
    }

    impl LeafExecutor<(), Bytes> for MemoryLeaves {
        fn body_from_bytes(&self, bytes: Bytes) -> Bytes {
            bytes
        }

        fn execute_site<'a>(
            &'a self,
            resource: &'a oxidase_core::ResourceId,
            request: &'a RequestFrame,
        ) -> BoxLeafFuture<'a, Bytes> {
            self.calls
                .lock()
                .expect("call log mutex is not poisoned")
                .push(resource.to_string());
            Box::pin(async move {
                match resource.as_str() {
                    "decline" => ServiceOutcome::Declined,
                    "fail" => ServiceOutcome::Failed(oxidase_core::ServiceError::new(
                        ErrorClass::SiteIo,
                        "fixture failure",
                    )),
                    "slow" => {
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        ServiceOutcome::Handled(ResponseHead::new(
                            StatusCode::OK,
                            Bytes::from_static(b"slow"),
                        ))
                    }
                    "path" => ServiceOutcome::Handled(ResponseHead::new(
                        StatusCode::OK,
                        Bytes::copy_from_slice(request.path().as_bytes()),
                    )),
                    _ => ServiceOutcome::Handled(ResponseHead::new(
                        StatusCode::OK,
                        Bytes::from_static(b"site"),
                    )),
                }
            })
        }

        fn execute_proxy<'a>(
            &'a self,
            cluster: &'a oxidase_core::ResourceId,
            _request: &'a RequestFrame,
            _body: &'a mut Option<()>,
            max_request_body_bytes: Option<u64>,
        ) -> BoxLeafFuture<'a, Bytes> {
            self.calls
                .lock()
                .expect("call log mutex is not poisoned")
                .push(cluster.to_string());
            self.proxy_limits
                .lock()
                .expect("proxy limit log mutex is not poisoned")
                .push(max_request_body_bytes);
            Box::pin(async {
                ServiceOutcome::Handled(ResponseHead::new(
                    StatusCode::OK,
                    Bytes::from_static(b"proxy"),
                ))
            })
        }

        fn governance(&self) -> Option<&GovernanceRegistry> {
            self.governance.as_ref()
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum ObservationEvent {
        Started {
            name: String,
            depth: usize,
        },
        Finished {
            name: String,
            outcome: ServiceObservationOutcome,
        },
        Cancelled {
            name: String,
        },
    }

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<ObservationEvent>>,
    }

    impl RecordingObserver {
        fn events(&self) -> Vec<ObservationEvent> {
            self.events
                .lock()
                .expect("observer mutex is not poisoned")
                .clone()
        }
    }

    impl ExecutionObserver for RecordingObserver {
        type Scope = String;

        fn service_started(&self, context: ServiceObservationContext<'_>) -> Self::Scope {
            self.events
                .lock()
                .expect("observer mutex is not poisoned")
                .push(ObservationEvent::Started {
                    name: context.observe_name.to_owned(),
                    depth: context.depth,
                });
            context.observe_name.to_owned()
        }

        fn service_finished(&self, scope: Self::Scope, result: ServiceObservationResult) {
            self.events
                .lock()
                .expect("observer mutex is not poisoned")
                .push(ObservationEvent::Finished {
                    name: scope,
                    outcome: result.outcome,
                });
        }

        fn service_cancelled(&self, scope: Self::Scope) {
            self.events
                .lock()
                .expect("observer mutex is not poisoned")
                .push(ObservationEvent::Cancelled { name: scope });
        }
    }

    fn request(path: &str) -> RequestFrame {
        RequestFrame::new(
            RequestMetadata::try_new(Method::GET, "http", "example.com", path, HeaderMap::new())
                .expect("valid fixture request metadata"),
        )
    }

    fn node(id: &str, kind: ServiceKind) -> ServiceNode {
        ServiceNode {
            id: ServiceId::new(id),
            source: SourceSpan::synthetic(id),
            kind,
        }
    }

    fn program(entry: &str, nodes: Vec<ServiceNode>) -> ServiceProgram {
        ServiceProgram::from_nodes(
            ServiceId::new(entry),
            nodes
                .into_iter()
                .map(|node| (node.id.clone(), node))
                .collect(),
        )
    }

    fn text_response(id: &str, status: StatusCode, text: &str) -> ServiceNode {
        node(
            id,
            ServiceKind::Respond {
                status,
                headers: HeaderTransforms::default(),
                body: RespondBody::Text(
                    CompiledTemplate::compile(text).expect("valid response template"),
                ),
            },
        )
    }

    #[tokio::test]
    async fn handled_404_is_not_declined() {
        let program = program(
            "not-found",
            vec![text_response("not-found", StatusCode::NOT_FOUND, "missing")],
        );
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("404 response must be handled");
        };
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn fallback_advances_only_on_declined() {
        let site = node(
            "site",
            ServiceKind::Site {
                resource: "fail".into(),
            },
        );
        let response = text_response("response", StatusCode::OK, "second");
        let fallback = node(
            "fallback",
            ServiceKind::Fallback {
                services: vec![site.id.clone(), response.id.clone()],
            },
        );
        let program = program("fallback", vec![site, response, fallback]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        let ServiceOutcome::Failed(error) = report.outcome else {
            panic!("failure must not be swallowed by fallback");
        };
        assert_eq!(error.class, ErrorClass::SiteIo);
    }

    #[tokio::test]
    async fn recover_handles_only_selected_error_classes() {
        let site = node(
            "site",
            ServiceKind::Site {
                resource: "fail".into(),
            },
        );
        let response = text_response(
            "recovery",
            StatusCode::SERVICE_UNAVAILABLE,
            "{{ bindings.error_class }}",
        );
        let recover = node(
            "recover",
            ServiceKind::Recover {
                service: site.id.clone(),
                handlers: vec![RecoverHandler {
                    classes: BTreeSet::from([ErrorClass::SiteIo]),
                    service: response.id.clone(),
                }],
            },
        );
        let program = program("recover", vec![site, response, recover]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("matching failure must be recovered");
        };
        assert_eq!(response.body, Bytes::from_static(b"siteio"));
    }

    #[tokio::test]
    async fn route_commits_captures_only_after_complete_match() {
        let matched = text_response("matched", StatusCode::OK, "{{ bindings.id }}");
        let default = text_response("default", StatusCode::OK, "{{ bindings.id ?? \"none\" }}");
        let mut predicate = PredicatePlan::path("/users/<id:uint>").expect("valid pattern");
        predicate.methods = vec![Method::POST];
        let route = node(
            "route",
            ServiceKind::Route {
                cases: vec![RouteCase {
                    id: RouteId::new("users"),
                    predicate,
                    service: matched.id.clone(),
                    source: SourceSpan::synthetic("route.cases[0]"),
                }],
                default: Some(default.id.clone()),
            },
        );
        let program = program("route", vec![matched, default, route]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/users/42"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("default must handle request");
        };
        assert_eq!(response.body, Bytes::from_static(b"none"));
    }

    #[tokio::test]
    async fn fallback_request_overlay_is_transactional() {
        let site = node(
            "site",
            ServiceKind::Site {
                resource: "decline".into(),
            },
        );
        let transform = node(
            "transform",
            ServiceKind::Transform {
                request: Box::new(RequestTransform {
                    path_and_query: Some(CompiledMetadata::Constant(
                        parse_transform_path_and_query("/changed").expect("valid transformed path"),
                    )),
                    ..RequestTransform::default()
                }),
                response: Box::new(ResponseTransform::default()),
                service: site.id.clone(),
            },
        );
        let response = text_response("response", StatusCode::OK, "{{ request.path }}");
        let fallback = node(
            "fallback",
            ServiceKind::Fallback {
                services: vec![transform.id.clone(), response.id.clone()],
            },
        );
        let program = program("fallback", vec![site, transform, response, fallback]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/original?order=kept"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("second fallback candidate must handle");
        };
        assert_eq!(response.body, Bytes::from_static(b"/original"));
    }

    #[tokio::test]
    async fn validates_dynamic_transformed_request_metadata() {
        let transforms = [
            RequestTransform {
                scheme: Some(CompiledMetadata::Dynamic(
                    CompiledTemplate::compile("{{ request.path }}")
                        .expect("valid dynamic template"),
                )),
                ..RequestTransform::default()
            },
            RequestTransform {
                authority: Some(CompiledMetadata::Dynamic(
                    CompiledTemplate::compile("user@{{ request.host }}")
                        .expect("valid dynamic template"),
                )),
                ..RequestTransform::default()
            },
            RequestTransform {
                authority: Some(CompiledMetadata::Dynamic(
                    CompiledTemplate::compile("example.com:{{ request.path }}")
                        .expect("valid dynamic template"),
                )),
                ..RequestTransform::default()
            },
            RequestTransform {
                authority: Some(CompiledMetadata::Dynamic(
                    CompiledTemplate::compile("example.com{{ request.path }}\r\ninvalid")
                        .expect("valid dynamic template"),
                )),
                ..RequestTransform::default()
            },
            RequestTransform {
                path_and_query: Some(CompiledMetadata::Dynamic(
                    CompiledTemplate::compile("https://evil.test{{ request.path }}")
                        .expect("valid dynamic template"),
                )),
                ..RequestTransform::default()
            },
        ];
        let leaves = MemoryLeaves::default();
        for transform in transforms {
            let response = text_response("response", StatusCode::OK, "unreachable");
            let transformed = node(
                "transform",
                ServiceKind::Transform {
                    request: Box::new(transform),
                    response: Box::new(ResponseTransform::default()),
                    service: response.id.clone(),
                },
            );
            let program = program("transform", vec![response, transformed]);
            let report = Executor::new(&program, &leaves)
                .execute(request("/original"), None)
                .await;
            let ServiceOutcome::Failed(error) = report.outcome else {
                panic!("invalid dynamic metadata must fail");
            };
            assert_eq!(error.class, ErrorClass::InvalidState);
            assert!(error.internal_detail.contains("request transform"));
        }
    }

    #[tokio::test]
    async fn transformed_origin_form_preserves_query_wire_order() {
        let response = text_response("response", StatusCode::OK, "{{ request.path_and_query }}");
        let transform = node(
            "transform",
            ServiceKind::Transform {
                request: Box::new(RequestTransform {
                    path_and_query: Some(CompiledMetadata::Dynamic(
                        CompiledTemplate::compile(
                            "/rewritten?b=2&a=1&a=3&from={{ request.path | url_encode }}",
                        )
                        .expect("valid dynamic path template"),
                    )),
                    ..RequestTransform::default()
                }),
                response: Box::new(ResponseTransform::default()),
                service: response.id.clone(),
            },
        );
        let program = program("transform", vec![response, transform]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/original?untouched=1"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("valid transformed path must handle");
        };
        assert_eq!(
            response.body,
            Bytes::from_static(b"/rewritten?b=2&a=1&a=3&from=%2Foriginal")
        );
    }

    #[tokio::test]
    async fn outer_transform_wraps_child_response() {
        let response = text_response("response", StatusCode::OK, "ok");
        let transform = node(
            "transform",
            ServiceKind::Transform {
                request: Box::new(RequestTransform::default()),
                response: Box::new(ResponseTransform {
                    headers: HeaderTransforms {
                        set: vec![HeaderTransform {
                            name: HeaderName::from_static("x-frame"),
                            value: CompiledTemplate::compile("outer")
                                .expect("valid header template"),
                        }],
                        ..HeaderTransforms::default()
                    },
                }),
                service: response.id.clone(),
            },
        );
        let program = program("transform", vec![response, transform]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        let ServiceOutcome::Handled(response) = report.outcome else {
            panic!("response must be handled");
        };
        assert_eq!(response.headers["x-frame"], "outer");
    }

    #[tokio::test]
    async fn reenter_has_a_hard_budget() {
        let reenter = node(
            "loop",
            ServiceKind::Reenter {
                target: ServiceId::new("loop"),
                budget: 2,
            },
        );
        let program = program("loop", vec![reenter]);
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        let ServiceOutcome::Failed(error) = report.outcome else {
            panic!("reentry budget must stop the loop");
        };
        assert_eq!(error.class, ErrorClass::InvalidState);
    }

    #[tokio::test]
    async fn redirect_rejects_network_path_and_header_injection() {
        for location in ["//evil.example/path", "/safe\r\nX-Evil: yes"] {
            let redirect = node(
                "redirect",
                ServiceKind::Redirect {
                    status: StatusCode::TEMPORARY_REDIRECT,
                    location: CompiledTemplate::compile(location)
                        .expect("template syntax is valid"),
                    preserve_query: false,
                    headers: HeaderTransforms::default(),
                },
            );
            let program = program("redirect", vec![redirect]);
            let leaves = MemoryLeaves::default();
            let report = Executor::new(&program, &leaves)
                .execute(request("/"), None)
                .await;
            assert!(matches!(report.outcome, ServiceOutcome::Failed(_)));
        }
    }

    #[tokio::test]
    async fn imported_listener_inline_services_execute_distinct_nodes() {
        let directory = tempdir().expect("temporary directory is available");
        for (file, listener, bind, body) in [
            ("a.yaml", "a", "127.0.0.1:7589", "A"),
            ("b.yaml", "b", "127.0.0.1:7590", "B"),
        ] {
            fs::write(
                directory.path().join(file),
                format!(
                    r#"api_version: oxidase.dev/v1alpha1
kind: gateway
listeners:
  - name: {listener}
    bind: {bind}
    service:
      type: respond
      body:
        text: {body}
"#
                ),
            )
            .expect("import can be written");
        }
        let root = directory.path().join("root.yaml");
        fs::write(
            &root,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
imports: [a.yaml, b.yaml]
"#,
        )
        .expect("root can be written");
        let gateway = Compiler::compile_path(root).expect("import graph compiles");
        let leaves = MemoryLeaves::default();

        for (listener, expected) in [("a", b"A".as_slice()), ("b", b"B".as_slice())] {
            let program = gateway
                .program_for(listener)
                .expect("listener program exists");
            let report = Executor::new(&program, &leaves)
                .execute(request("/"), None)
                .await;
            let ServiceOutcome::Handled(response) = report.outcome else {
                panic!("listener must handle request");
            };
            assert_eq!(response.body.as_ref(), expected);
        }
    }

    #[tokio::test]
    async fn default_execution_skips_explain_trace_collection() {
        let response = text_response("response", StatusCode::OK, "ok");
        let observe = node(
            "observe",
            ServiceKind::Observe {
                name: "request".to_owned(),
                service: response.id.clone(),
            },
        );
        let program = program("observe", vec![response, observe]);
        let leaves = MemoryLeaves::default();

        let report = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        assert!(report.trace.events.is_empty());

        let report = Executor::new(&program, &leaves)
            .execute_traced(request("/"), None)
            .await;
        assert!(report.trace.events.len() >= 6);
        assert!(
            report
                .trace
                .events
                .iter()
                .any(|event| event.event == "observe_start" && event.detail == "request")
        );
    }

    #[tokio::test]
    async fn production_observer_tracks_nested_and_terminal_outcomes() {
        let response = text_response("response", StatusCode::CREATED, "ok");
        let inner = node(
            "inner",
            ServiceKind::Observe {
                name: "inner".to_owned(),
                service: response.id.clone(),
            },
        );
        let outer = node(
            "outer",
            ServiceKind::Observe {
                name: "outer".to_owned(),
                service: inner.id.clone(),
            },
        );
        let nested_program = program("outer", vec![response, inner, outer]);
        let leaves = MemoryLeaves::default();
        let observer = RecordingObserver::default();
        let report = Executor::new(&nested_program, &leaves)
            .execute_observed(request("/private?token=secret"), None, &observer)
            .await;
        assert!(matches!(report.outcome, ServiceOutcome::Handled(_)));
        assert_eq!(
            observer.events(),
            [
                ObservationEvent::Started {
                    name: "outer".to_owned(),
                    depth: 0,
                },
                ObservationEvent::Started {
                    name: "inner".to_owned(),
                    depth: 1,
                },
                ObservationEvent::Finished {
                    name: "inner".to_owned(),
                    outcome: ServiceObservationOutcome::Handled(StatusCode::CREATED),
                },
                ObservationEvent::Finished {
                    name: "outer".to_owned(),
                    outcome: ServiceObservationOutcome::Handled(StatusCode::CREATED),
                },
            ]
        );

        for (resource, expected) in [
            ("decline", ServiceObservationOutcome::Declined),
            (
                "fail",
                ServiceObservationOutcome::Failed(ErrorClass::SiteIo),
            ),
        ] {
            let site = node(
                "site",
                ServiceKind::Site {
                    resource: resource.into(),
                },
            );
            let observe = node(
                "observe",
                ServiceKind::Observe {
                    name: resource.to_owned(),
                    service: site.id.clone(),
                },
            );
            let outcome_program = program("observe", vec![site, observe]);
            let observer = RecordingObserver::default();
            Executor::new(&outcome_program, &leaves)
                .execute_observed(request("/"), None, &observer)
                .await;
            assert_eq!(
                observer.events().last(),
                Some(&ObservationEvent::Finished {
                    name: resource.to_owned(),
                    outcome: expected,
                })
            );
        }
    }

    #[tokio::test]
    async fn production_observer_finishes_after_recover_and_cancels_on_timeout() {
        let failed = node(
            "failed",
            ServiceKind::Site {
                resource: "fail".into(),
            },
        );
        let recovered = text_response("recovered", StatusCode::OK, "recovered");
        let recover = node(
            "recover",
            ServiceKind::Recover {
                service: failed.id.clone(),
                handlers: vec![RecoverHandler {
                    classes: BTreeSet::from([ErrorClass::SiteIo]),
                    service: recovered.id.clone(),
                }],
            },
        );
        let observe = node(
            "observe",
            ServiceKind::Observe {
                name: "recovered".to_owned(),
                service: recover.id.clone(),
            },
        );
        let recover_program = program("observe", vec![failed, recovered, recover, observe]);
        let leaves = MemoryLeaves::default();
        let observer = RecordingObserver::default();
        Executor::new(&recover_program, &leaves)
            .execute_observed(request("/"), None, &observer)
            .await;
        assert_eq!(
            observer.events().last(),
            Some(&ObservationEvent::Finished {
                name: "recovered".to_owned(),
                outcome: ServiceObservationOutcome::Handled(StatusCode::OK),
            })
        );

        let slow = node(
            "slow",
            ServiceKind::Site {
                resource: "slow".into(),
            },
        );
        let observe = node(
            "observe",
            ServiceKind::Observe {
                name: "timed".to_owned(),
                service: slow.id.clone(),
            },
        );
        let timeout = node(
            "timeout",
            ServiceKind::Timeout {
                duration: std::time::Duration::from_millis(1),
                service: observe.id.clone(),
            },
        );
        let timeout_program = program("timeout", vec![slow, observe, timeout]);
        let observer = RecordingObserver::default();
        let report = Executor::new(&timeout_program, &leaves)
            .execute_observed(request("/"), None, &observer)
            .await;
        assert!(matches!(
            report.outcome,
            ServiceOutcome::Failed(ref error) if error.class == ErrorClass::Timeout
        ));
        assert_eq!(
            observer.events(),
            [
                ObservationEvent::Started {
                    name: "timed".to_owned(),
                    depth: 0,
                },
                ObservationEvent::Cancelled {
                    name: "timed".to_owned(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn large_snapshot_program_views_share_one_graph() {
        let directory = tempdir().expect("temporary directory is available");
        let path = directory.path().join("oxidase.yaml");
        let mut source = String::from(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  entry:
    type: respond
    body:
      text: short
"#,
        );
        for index in 0..1_024 {
            writeln!(
                source,
                "  unused_{index}:\n    type: respond\n    body:\n      text: unused"
            )
            .expect("writing to a String cannot fail");
        }
        source.push_str(
            r#"listeners:
  - name: hot
    bind: 127.0.0.1:7589
    service:
      ref: entry
"#,
        );
        fs::write(&path, source).expect("large fixture can be written");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("large graph compiles"))
                .expect("large snapshot prepares");
        let first = snapshot.program_for("hot").expect("program view exists");
        assert_eq!(first.graph.len(), 1_025);
        assert!(Arc::ptr_eq(&snapshot.graph, &first.graph));
        let leaves = MemoryLeaves::default();

        for _ in 0..32 {
            let view = snapshot.program_for("hot").expect("program view exists");
            assert!(Arc::ptr_eq(&first.graph, &view.graph));
            let report = Executor::new(&view, &leaves)
                .execute(request("/"), None)
                .await;
            let ServiceOutcome::Handled(response) = report.outcome else {
                panic!("entry service must handle the request");
            };
            assert_eq!(response.body, Bytes::from_static(b"short"));
            assert!(report.trace.events.is_empty());
        }
    }

    #[tokio::test]
    async fn request_body_limit_rejects_known_length_and_is_lexical_across_fallback() {
        let proxy = node(
            "proxy",
            ServiceKind::Proxy {
                cluster: "cluster:test".into(),
            },
        );
        let limited = node(
            "limited",
            ServiceKind::RequestBodyLimit {
                max_bytes: 4,
                service: proxy.id.clone(),
            },
        );
        let limited_program = program("limited", vec![proxy.clone(), limited]);
        let leaves = MemoryLeaves::default();
        let mut oversized = request("/");
        oversized.overlay_mut().set_header(
            http::header::CONTENT_LENGTH,
            "5".parse().expect("fixture Content-Length is valid"),
        );
        let report = Executor::new(&limited_program, &leaves)
            .execute(oversized, Some(()))
            .await;
        assert!(matches!(
            report.outcome,
            ServiceOutcome::Handled(ref response)
                if response.status == StatusCode::PAYLOAD_TOO_LARGE
        ));
        assert!(
            leaves
                .proxy_limits
                .lock()
                .expect("proxy limit log mutex is not poisoned")
                .is_empty()
        );

        let decline = node(
            "decline",
            ServiceKind::Site {
                resource: "decline".into(),
            },
        );
        let limited_decline = node(
            "limited-decline",
            ServiceKind::RequestBodyLimit {
                max_bytes: 1,
                service: decline.id.clone(),
            },
        );
        let fallback = node(
            "fallback",
            ServiceKind::Fallback {
                services: vec![limited_decline.id.clone(), proxy.id.clone()],
            },
        );
        let fallback_program = program("fallback", vec![proxy, decline, limited_decline, fallback]);
        fallback_program
            .validate()
            .expect("a non-consuming limited candidate is safe in Fallback");
        let leaves = MemoryLeaves::default();
        let report = Executor::new(&fallback_program, &leaves)
            .execute(request("/"), Some(()))
            .await;
        assert!(matches!(report.outcome, ServiceOutcome::Handled(_)));
        assert_eq!(
            *leaves
                .proxy_limits
                .lock()
                .expect("proxy limit log mutex is not poisoned"),
            [None],
            "a declined wrapper must not leak its lexical body limit to its sibling"
        );
    }

    #[tokio::test]
    async fn concurrency_limit_rejects_overlap_and_releases_after_child_completion() {
        let slow = node(
            "slow",
            ServiceKind::Site {
                resource: "slow".into(),
            },
        );
        let limit = node(
            "limit",
            ServiceKind::ConcurrencyLimit {
                name: "tests".to_owned(),
                max_in_flight: 1,
                queue_timeout: Duration::ZERO,
                reject_status: StatusCode::SERVICE_UNAVAILABLE,
                service: slow.id.clone(),
            },
        );
        let program = program("limit", vec![slow, limit]);
        let leaves = MemoryLeaves {
            governance: Some(GovernanceRegistry::prepare(&program.graph, None).0),
            ..MemoryLeaves::default()
        };
        let first_executor = Executor::new(&program, &leaves);
        let first = first_executor.execute(request("/"), None);
        let second = async {
            tokio::task::yield_now().await;
            Executor::new(&program, &leaves)
                .execute(request("/"), None)
                .await
        };
        let (first, second) = tokio::join!(first, second);
        assert!(matches!(first.outcome, ServiceOutcome::Handled(_)));
        assert!(matches!(
            second.outcome,
            ServiceOutcome::Handled(ref response)
                if response.status == StatusCode::SERVICE_UNAVAILABLE
        ));
        let third = Executor::new(&program, &leaves)
            .execute(request("/"), None)
            .await;
        assert!(matches!(third.outcome, ServiceOutcome::Handled(_)));
    }

    #[tokio::test]
    async fn concurrency_permits_release_on_decline_failure_and_timeout() {
        for (resource, expected) in [
            ("decline", None),
            ("fail", Some(ErrorClass::SiteIo)),
            ("slow", Some(ErrorClass::Timeout)),
        ] {
            let leaf = node(
                "leaf",
                ServiceKind::Site {
                    resource: resource.into(),
                },
            );
            let child = if resource == "slow" {
                node(
                    "child",
                    ServiceKind::Timeout {
                        duration: Duration::from_millis(1),
                        service: leaf.id.clone(),
                    },
                )
            } else {
                node(
                    "child",
                    ServiceKind::Observe {
                        name: "transparent".to_owned(),
                        service: leaf.id.clone(),
                    },
                )
            };
            let limit = node(
                "limit",
                ServiceKind::ConcurrencyLimit {
                    name: "tests".to_owned(),
                    max_in_flight: 1,
                    queue_timeout: Duration::ZERO,
                    reject_status: StatusCode::SERVICE_UNAVAILABLE,
                    service: child.id.clone(),
                },
            );
            let program = program("limit", vec![leaf, child, limit]);
            let leaves = MemoryLeaves {
                governance: Some(GovernanceRegistry::prepare(&program.graph, None).0),
                ..MemoryLeaves::default()
            };

            for _ in 0..2 {
                let report = Executor::new(&program, &leaves)
                    .execute(request("/"), None)
                    .await;
                match expected {
                    None => assert!(matches!(report.outcome, ServiceOutcome::Declined)),
                    Some(class) => assert!(matches!(
                        report.outcome,
                        ServiceOutcome::Failed(ref error) if error.class == class
                    )),
                }
            }
        }
    }

    #[tokio::test]
    async fn rate_limit_uses_lexical_binding_and_returns_retry_after() {
        let child = text_response("child", StatusCode::OK, "allowed");
        let limit = node(
            "limit",
            ServiceKind::RateLimit {
                name: "tests".to_owned(),
                key: RateLimitKey::Binding("tenant".to_owned()),
                requests: 1,
                per: Duration::from_secs(60),
                burst: 1,
                max_keys: 8,
                idle_ttl: Duration::from_secs(120),
                service: child.id.clone(),
            },
        );
        let program = program("limit", vec![child, limit]);
        let leaves = MemoryLeaves {
            governance: Some(GovernanceRegistry::prepare(&program.graph, None).0),
            ..MemoryLeaves::default()
        };
        let request = request("/").with_bindings(BTreeMap::from([(
            "tenant".to_owned(),
            Value::String("alpha".to_owned()),
        )]));
        let first = Executor::new(&program, &leaves)
            .execute(request.clone(), None)
            .await;
        assert!(matches!(
            first.outcome,
            ServiceOutcome::Handled(ref response) if response.status == StatusCode::OK
        ));
        let second = Executor::new(&program, &leaves)
            .execute(request, None)
            .await;
        let ServiceOutcome::Handled(response) = second.outcome else {
            panic!("rate-limit rejection is a handled response");
        };
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers[http::header::RETRY_AFTER], "60");
    }
}
