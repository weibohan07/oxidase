use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use oxidase_core::{
    BodyState, ErrorClass, HeaderTransforms, RequestFrame, RequestTransform, ResourceId,
    RespondBody, ResponseHead, ResponseTransform, RouteId, ServiceError, ServiceId, ServiceKind,
    ServiceOutcome, ServiceProgram, Value,
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
    ) -> BoxLeafFuture<'a, ResponseBody>;
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

impl ExecutionTrace {
    fn push(
        &mut self,
        service: &ServiceId,
        route: Option<&RouteId>,
        event: &'static str,
        detail: impl Into<String>,
    ) {
        self.events.push(TraceEvent {
            service: service.clone(),
            route: route.cloned(),
            event,
            detail: detail.into(),
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
        mut body: Option<RequestBody>,
    ) -> ExecutionReport<ResponseBody> {
        let mut state = ExecutionState::default();
        let mut trace = ExecutionTrace::default();
        let outcome = self
            .execute_node(
                &self.program.entry,
                request,
                &mut body,
                &mut state,
                &mut trace,
            )
            .await;
        ExecutionReport {
            outcome,
            trace,
            body_state: state.body_state,
        }
    }

    fn execute_node<'b>(
        &'b self,
        id: &'b ServiceId,
        request: RequestFrame,
        body: &'b mut Option<RequestBody>,
        state: &'b mut ExecutionState,
        trace: &'b mut ExecutionTrace,
    ) -> BoxLeafFuture<'b, ResponseBody> {
        Box::pin(async move {
            let Some(node) = self.program.nodes.get(id) else {
                return ServiceOutcome::Failed(ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("runtime plan references missing service `{id}`"),
                ));
            };
            trace.push(id, None, "enter", node.source.to_string());

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
                    if state.body_state == BodyState::Consumed {
                        ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::BodyUnavailable,
                            "request body was already consumed before Proxy",
                        ))
                    } else {
                        // Mark before the first await so cancellation cannot make a
                        // partially consumed stream appear replayable.
                        state.body_state = BodyState::Consumed;
                        self.leaves.execute_proxy(cluster, &request, body).await
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
                                .execute_node(service, child_request, body, state, trace)
                                .await;
                            apply_response_transform(outcome, response_transform, &request)
                        }
                        Err(error) => ServiceOutcome::Failed(error),
                    }
                }
                ServiceKind::Observe { name, service } => {
                    trace.push(id, None, "observe_start", name);
                    let outcome = self
                        .execute_node(service, request, body, state, trace)
                        .await;
                    trace.push(id, None, "observe_finish", outcome.kind());
                    outcome
                }
                ServiceKind::Timeout { duration, service } => {
                    match tokio::time::timeout(
                        *duration,
                        self.execute_node(service, request, body, state, trace),
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
                ServiceKind::Recover { service, handlers } => {
                    let outcome = self
                        .execute_node(service, request.clone(), body, state, trace)
                        .await;
                    if let ServiceOutcome::Failed(error) = outcome {
                        if let Some(handler) = handlers
                            .iter()
                            .find(|handler| handler.classes.contains(&error.class))
                        {
                            trace.push(
                                id,
                                None,
                                "recover",
                                format!("{:?} -> {}", error.class, handler.service),
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
                                body,
                                state,
                                trace,
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
                                trace.push(
                                    id,
                                    Some(&case.id),
                                    "route_match",
                                    format!("{} binding(s)", bindings.len()),
                                );
                                selected = Some((case.service.clone(), bindings));
                                break;
                            }
                            Ok(None) => trace.push(
                                id,
                                Some(&case.id),
                                "route_miss",
                                "predicate did not match",
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
                            body,
                            state,
                            trace,
                        )
                        .await
                    } else if let Some(default) = default {
                        trace.push(id, None, "route_default", default.to_string());
                        self.execute_node(default, request, body, state, trace)
                            .await
                    } else {
                        ServiceOutcome::Declined
                    }
                }
                ServiceKind::Fallback { services } => {
                    let mut outcome = ServiceOutcome::Declined;
                    for service in services {
                        let body_before = state.body_state;
                        outcome = self
                            .execute_node(service, request.clone(), body, state, trace)
                            .await;
                        if matches!(outcome, ServiceOutcome::Declined) {
                            if state.body_state != body_before {
                                return ServiceOutcome::Failed(ServiceError::new(
                                    ErrorClass::BodyUnavailable,
                                    format!(
                                        "fallback candidate `{service}` declined after consuming the body"
                                    ),
                                ));
                            }
                            trace.push(id, None, "fallback_next", service.to_string());
                        } else {
                            break;
                        }
                    }
                    outcome
                }
                ServiceKind::Reenter { target, budget } => {
                    let count = state.reentries.entry(id.clone()).or_default();
                    if *count >= *budget {
                        ServiceOutcome::Failed(ServiceError::new(
                            ErrorClass::InvalidState,
                            format!("Reenter `{id}` exhausted its budget of {budget}"),
                        ))
                    } else {
                        *count += 1;
                        trace.push(id, None, "reenter", format!("{target} ({count}/{budget})"));
                        self.execute_node(target, request, body, state, trace).await
                    }
                }
            };

            trace.push(id, None, "outcome", outcome.kind());
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
    request.overlay.method.clone_from(&transform.method);
    request.overlay.scheme = render_optional(&transform.scheme, &context)?;
    request.overlay.authority = render_optional(&transform.authority, &context)?;
    request.overlay.path_and_query = render_optional(&transform.path_and_query, &context)?;
    for name in &transform.headers.remove {
        request.overlay.remove_header(name.clone());
    }
    for header in &transform.headers.set {
        let value = render_header(&header.value, &context)?;
        request.overlay.set_header(header.name.clone(), value);
    }
    for header in &transform.headers.add {
        let value = render_header(&header.value, &context)?;
        request.overlay.add_header(header.name.clone(), value);
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

fn render_optional(
    template: &Option<oxidase_core::CompiledTemplate>,
    context: &oxidase_core::EvalContext,
) -> Result<Option<String>, ServiceError> {
    template
        .as_ref()
        .map(|template| {
            template.render(context).map_err(|error| {
                ServiceError::new(
                    ErrorClass::InvalidState,
                    format!("request transform failed: {error}"),
                )
            })
        })
        .transpose()
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
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::Mutex;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, Method, StatusCode};
    use oxidase_config::Compiler;
    use oxidase_core::{
        CompiledTemplate, ErrorClass, HeaderTransform, HeaderTransforms, PredicatePlan,
        RecoverHandler, RequestFrame, RequestMetadata, RequestTransform, RespondBody, ResponseHead,
        ResponseTransform, RouteCase, RouteId, ServiceId, ServiceKind, ServiceNode, ServiceOutcome,
        ServiceProgram, SourceSpan,
    };
    use tempfile::tempdir;

    use super::{BoxLeafFuture, Executor, LeafExecutor};

    #[derive(Default)]
    struct MemoryLeaves {
        calls: Mutex<Vec<String>>,
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
        ) -> BoxLeafFuture<'a, Bytes> {
            self.calls
                .lock()
                .expect("call log mutex is not poisoned")
                .push(cluster.to_string());
            Box::pin(async {
                ServiceOutcome::Handled(ResponseHead::new(
                    StatusCode::OK,
                    Bytes::from_static(b"proxy"),
                ))
            })
        }
    }

    fn request(path: &str) -> RequestFrame {
        RequestFrame::new(RequestMetadata::new(
            Method::GET,
            "http",
            "example.com",
            path,
            HeaderMap::new(),
        ))
    }

    fn node(id: &str, kind: ServiceKind) -> ServiceNode {
        ServiceNode {
            id: ServiceId::new(id),
            source: SourceSpan::synthetic(id),
            kind,
        }
    }

    fn program(entry: &str, nodes: Vec<ServiceNode>) -> ServiceProgram {
        ServiceProgram {
            entry: ServiceId::new(entry),
            nodes: nodes
                .into_iter()
                .map(|node| (node.id.clone(), node))
                .collect(),
        }
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
                    path_and_query: Some(
                        CompiledTemplate::compile("/changed").expect("valid template"),
                    ),
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
}
