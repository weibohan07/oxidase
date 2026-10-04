use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use oxidase_bundle::BundleVerificationKey;
use oxidase_config::{
    AdminListenSpec, Http1Settings, Http2Settings, HttpVersion, ListenerLimits, ListenerProtocol,
};
use oxidase_core::{
    Diagnostic, RequestFrame, RequestMetadata, ServiceOutcome, SourceSpan, TlsConnectionMetadata,
};
use oxidase_runtime::{
    CandidateSignaturePolicy, CandidateStore, CandidateStoreLimits, CandidateWorkControl,
    ClusterRuntimeStatus, Executor, OperationReceipt, PreparedListenerPlan, PreparedTlsListener,
    PublishedRuntime, ResourceReuse, RuntimeOrigin, RuntimeSnapshot, ServingState, SnapshotStore,
    verified_client_metadata,
};
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::admin::{
    AdminPeerIdentity, AdminSecurityPolicy, DEFAULT_ADMIN_REQUEST_BODY_BYTES,
    allowed_admin_methods, classify_admin_route, validate_mutation_header_shape,
};
use crate::admin_audit::{AdminAuditEvent, AdminAuditSink};
use crate::body::{
    DownstreamTimeoutSignal, GatewayBody, GatewayBodyPlan, UnconsumedH2Body,
    instrument_response_body_with_snapshot_timeout, retain_unconsumed_h2_body,
    timeout_request_body,
};
use crate::cluster_health::ClusterHealthManager;
use crate::connection::TrackedExecutor;
use crate::discovery_manager::{DiscoveryManager, PreparedDiscoveryOwners};
use crate::ingress::{ConnectionRequestBudget, IdleIo, ListenerIngressState, RequestAdmission};
use crate::leaves::{HyperLeaves, ProxyClient};
use crate::metrics::{
    ConnectionProtocol, H2Shutdown, ListenerTransportMetrics, Metrics, ProductionObserver, TlsAlpn,
    TlsHandshakeOutcome, TunnelTermination as TunnelMetricTermination,
};
use crate::protocol::{RequestTrailerGuard, WireProtocol, http1_accepts_trailers};
use crate::response::{
    FinalizedResponse, ResponseFinalizationContext, ResponseFinalizationError, ResponseFinalizer,
};
use crate::upgrade::{
    GatewayRequestPayload, TunnelPlan, TunnelTermination as TunnelIoTermination,
    validate_upgrade_request,
};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const DEFAULT_HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_HTTP1_MAX_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_HTTP1_MAX_HEADERS: usize = 100;
const DEFAULT_HTTP1_MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;
const HTTP1_REQUEST_LINE_AND_FRAMING_ALLOWANCE: usize = 1024;
const MAX_CONCURRENT_TLS_HANDSHAKES_PER_LISTENER: usize = 128;
const MAX_CONCURRENT_ADMIN_CONNECTIONS: usize = 256;
const ADMIN_MUTATION_TIMEOUT: Duration = Duration::from_secs(60);

fn http1_builder(header_read_timeout: Duration) -> http1::Builder {
    http1_builder_with_limits(
        header_read_timeout,
        DEFAULT_HTTP1_MAX_HEADERS,
        DEFAULT_HTTP1_MAX_HEADER_BYTES,
    )
}

fn http1_builder_with_limits(
    header_read_timeout: Duration,
    max_headers: usize,
    max_header_bytes: usize,
) -> http1::Builder {
    // Hyper's read buffer includes the request line and delimiter bytes, while
    // `max_header_bytes` is the decoded Header name/value budget enforced
    // after parsing. Reserve independent bounded space so a valid long target
    // cannot silently consume the configured Header allowance.
    let read_buffer = max_header_bytes
        .saturating_add(DEFAULT_HTTP1_MAX_REQUEST_TARGET_BYTES)
        .saturating_add(max_headers.saturating_mul(4))
        .saturating_add(HTTP1_REQUEST_LINE_AND_FRAMING_ALLOWANCE);
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .max_headers(max_headers)
        .max_buf_size(read_buffer)
        .header_read_timeout(header_read_timeout);
    builder
}

pub struct GatewayServer {
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    health: ClusterHealthManager,
    discovery: DiscoveryManager,
    prepared_discovery: PreparedDiscoveryOwners,
    metrics: Arc<Metrics>,
    listeners: Vec<BoundListener>,
    admin: Option<BoundAdmin>,
    drain_timeout: Duration,
}

struct BoundAdmin {
    transport: BoundAdminTransport,
    endpoint: AdminEndpoint,
    security: Arc<AdminSecurityPolicy>,
    tls: Option<PreparedTlsListener>,
    candidates: Option<Arc<CandidateStore>>,
    candidate_upload_directory: Option<PathBuf>,
    candidate_deployment_root: Option<PathBuf>,
    max_candidate_bytes: u64,
    audit: Option<AdminAuditSink>,
}

#[derive(Clone)]
struct AdminControlPlane {
    candidates: Arc<CandidateStore>,
    reload: ReloadHandle,
    deployment_root: PathBuf,
    max_candidate_bytes: u64,
    mutation_gate: Arc<Semaphore>,
    audit: Option<AdminAuditSink>,
    operation_tasks: Arc<tokio::sync::Mutex<JoinSet<()>>>,
}

#[derive(Clone)]
struct ManagedAdminOperation {
    context: oxidase_runtime::CandidateOperationContext,
    work: CandidateWorkControl,
    deadline: std::time::Instant,
    observed_id: Arc<Mutex<Option<String>>>,
    audit: SharedOperationAudit,
}

type SharedOperationAudit = Arc<
    Mutex<
        Option<(
            crate::admin_audit::AdminAuditPermit,
            AdminAuditEvent,
            AdminAuditSink,
        )>,
    >,
>;

async fn begin_managed_operation(
    control: &AdminControlPlane,
    managed: &ManagedAdminOperation,
    action: oxidase_runtime::AuditAction,
    target: Option<oxidase_bundle::BundleDigest>,
    body_digest: Option<oxidase_bundle::BundleDigest>,
) -> Result<oxidase_runtime::OperationBegin, oxidase_runtime::CandidateStoreError> {
    let (response, received) = oneshot::channel();
    let required_audit = managed
        .audit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some();
    control
        .reload
        .control
        .send(Control::BeginOperation {
            store: Arc::clone(&control.candidates),
            context: managed.context.clone(),
            action,
            target,
            body_digest,
            required_audit,
            work: managed.work.clone(),
            response,
        })
        .await
        .map_err(|_| {
            oxidase_runtime::CandidateStoreError::new(
                "candidate.manager_closed",
                "publication manager is closed",
            )
        })?;
    let begin = received.await.map_err(|_| {
        oxidase_runtime::CandidateStoreError::new(
            "candidate.manager_closed",
            "publication manager is closed",
        )
    })??;
    *managed
        .observed_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(begin.receipt.operation_id.clone());
    Ok(begin)
}

fn operation_receipt_response(
    receipt: &OperationReceipt,
    published: &PublishedRuntime,
    replayed: bool,
    method: &Method,
) -> Response<GatewayBody> {
    operation_receipt_diagnostics_response(receipt, published, replayed, &[], method)
}

fn operation_receipt_diagnostics_response(
    receipt: &OperationReceipt,
    published: &PublishedRuntime,
    replayed: bool,
    diagnostics: &[Diagnostic],
    method: &Method,
) -> Response<GatewayBody> {
    use oxidase_runtime::OperationPhase;
    let status = match receipt.phase {
        OperationPhase::Committed => StatusCode::OK,
        OperationPhase::RecoveryRequired | OperationPhase::Accepted | OperationPhase::Preparing => {
            StatusCode::ACCEPTED
        }
        OperationPhase::Cancelled => StatusCode::REQUEST_TIMEOUT,
        OperationPhase::Failed
            if receipt.error_code.as_deref().is_some_and(|code| {
                matches!(code, "admin.precondition_failed" | "candidate.precondition")
            }) =>
        {
            StatusCode::PRECONDITION_FAILED
        }
        OperationPhase::Failed
            if receipt.error_code.as_deref() == Some("admin.source_unavailable") =>
        {
            StatusCode::CONFLICT
        }
        OperationPhase::Failed
            if receipt.error_code.as_deref().is_some_and(|code| {
                matches!(code, "candidate.capacity" | "admin.preparation_busy")
            }) =>
        {
            StatusCode::SERVICE_UNAVAILABLE
        }
        OperationPhase::Failed => StatusCode::UNPROCESSABLE_ENTITY,
    };
    let mut response = admin_json_value_response(
        status,
        &serde_json::json!({
            "schema_version":"oxidase.admin/v1", "operation_id":receipt.operation_id,
            "phase":receipt.phase, "digest":receipt.target_digest, "operation":receipt,
            "current_revision":published.runtime_revision, "current_etag":published.etag(),
            "current_config_version":published.snapshot.config_version.as_str(),
            "code":receipt.error_code, "idempotent_replay":replayed,
            "diagnostics":safe_admin_diagnostics(diagnostics)
        }),
        method,
    );
    response.extensions_mut().insert(AdminReplay(replayed));
    response
}

#[derive(Clone, Copy)]
struct AdminReplay(bool);

fn safe_admin_span(span: &SourceSpan) -> serde_json::Value {
    serde_json::json!({"file":"<source>","field_path":safe_admin_field_path(&span.field_path),"start":{"byte":span.start_byte,"line":span.line,"column":span.column},"end":{"byte":span.end_byte,"line":span.end_line,"column":span.end_column}})
}

fn safe_admin_field_path(path: &str) -> String {
    let root = path.split(['.', '[']).next().unwrap_or_default();
    if path.len() > 512
        || !path.is_ascii()
        || !matches!(
            root,
            "resources"
                | "services"
                | "listeners"
                | "defaults"
                | "profiles"
                | "response"
                | "templates"
                | "errors"
                | "visibility"
                | "inputs"
                | "params"
                | "admin"
                | "bundle"
                | "request"
                | "site"
                | "asset"
        )
    {
        return "<field>".to_owned();
    }
    let mut result = String::new();
    let mut quoted = None;
    for character in path.chars() {
        if let Some(quote) = quoted {
            if character == quote {
                result.push_str("<key>\"");
                quoted = None;
            }
        } else if matches!(character, '\'' | '"') {
            result.push('"');
            quoted = Some(character);
        } else if character.is_ascii_alphanumeric()
            || matches!(character, '.' | '[' | ']' | '_' | '-')
        {
            result.push(character);
        } else {
            return "<field>".to_owned();
        }
    }
    if quoted.is_some() {
        "<field>".to_owned()
    } else {
        result
    }
}

fn safe_admin_diagnostics(diagnostics: &[Diagnostic]) -> Vec<serde_json::Value> {
    diagnostics.iter().take(64).map(|diagnostic| serde_json::json!({
        "code":diagnostic.code,"severity":diagnostic.severity.to_string(),"message":"candidate validation failed",
        "primary":safe_admin_span(&diagnostic.primary),
        "labels":diagnostic.labels.iter().take(16).map(|label| serde_json::json!({"message":"related location","span":safe_admin_span(&label.span)})).collect::<Vec<_>>(),
        "related":diagnostic.related.iter().take(16).map(|label| serde_json::json!({"message":"related location","span":safe_admin_span(&label.span)})).collect::<Vec<_>>(),
        "notes":[],"help":null,
        "reference_chain":diagnostic.reference_chain.iter().take(16).map(|reference| serde_json::json!({"message":"reference","span":reference.span.as_ref().map(safe_admin_span)})).collect::<Vec<_>>()
    })).collect()
}

fn candidate_preparation_error(
    error: oxidase_runtime::BundleActivationError,
) -> oxidase_runtime::CandidateStoreError {
    let diagnostics = error.structured_diagnostics().unwrap_or_default();
    oxidase_runtime::CandidateStoreError::new(error.code(), "candidate validation failed")
        .with_diagnostics(diagnostics)
}

async fn finish_operation_error(
    control: &AdminControlPlane,
    operation_id: String,
    error: oxidase_runtime::CandidateStoreError,
) -> Option<OperationReceipt> {
    let store = Arc::clone(&control.candidates);
    tokio::task::spawn_blocking(move || {
        let result = if matches!(
            error.code(),
            "candidate.cancelled" | "candidate.deadline" | "admin.operation_cancelled"
        ) {
            store.finish_cancelled(&operation_id, error.code())
        } else {
            store.finish_failed(&operation_id, error.code())
        };
        result.unwrap_or_else(|failure| {
            store.force_uncommitted_recovery_receipt(&operation_id, failure.code())
        })
    })
    .await
    .ok()
}

enum BoundAdminTransport {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(crate::admin::unix_socket::BoundUnixAdmin),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminEndpoint {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(PathBuf),
}

trait AdminIo: AsyncRead + AsyncWrite {}
impl<T> AdminIo for T where T: AsyncRead + AsyncWrite {}
type BoxAdminIo = Box<dyn AdminIo + Unpin + Send + 'static>;

struct ActiveListener {
    configured_address: SocketAddr,
    local_address: SocketAddr,
    generation: u64,
    shutdown: watch::Sender<bool>,
    accept_stopped: Option<oneshot::Receiver<()>>,
    task: JoinHandle<()>,
}

struct ActiveAdmin {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

struct ListenerCompletion {
    name: String,
    generation: u64,
    result: Result<(), ServerError>,
}

enum Control {
    BeginOperation {
        store: Arc<CandidateStore>,
        context: oxidase_runtime::CandidateOperationContext,
        action: oxidase_runtime::AuditAction,
        target: Option<oxidase_bundle::BundleDigest>,
        body_digest: Option<oxidase_bundle::BundleDigest>,
        required_audit: bool,
        work: CandidateWorkControl,
        response: oneshot::Sender<
            Result<oxidase_runtime::OperationBegin, oxidase_runtime::CandidateStoreError>,
        >,
    },
    Reload {
        snapshot: Box<RuntimeSnapshot>,
        reuse: ResourceReuse,
        expected_version: String,
        origin: RuntimeOrigin,
        watched_source: bool,
        deadline: std::time::Instant,
        operation: Option<CommitOperation>,
        response: oneshot::Sender<Result<ReloadReport, ServerError>>,
    },
    Drain {
        expected_version: String,
        deadline: std::time::Instant,
        operation: Option<CommitOperation>,
        response: oneshot::Sender<Result<(), ServerError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
struct CommitOperation {
    store: Arc<CandidateStore>,
    operation_id: String,
    work: CandidateWorkControl,
    audit: SharedOperationAudit,
}

struct BoundListener {
    name: String,
    configured_address: SocketAddr,
    source_span: SourceSpan,
    listener: TcpListener,
    local_address: SocketAddr,
}

impl GatewayServer {
    pub async fn bind(snapshot: RuntimeSnapshot) -> Result<Self, ServerError> {
        Self::bind_with_origin(snapshot, RuntimeOrigin::Source).await
    }

    pub async fn bind_with_origin(
        snapshot: RuntimeSnapshot,
        origin: RuntimeOrigin,
    ) -> Result<Self, ServerError> {
        let census = snapshot.resource_census();
        let discovery = DiscoveryManager::new_with_census(Arc::clone(&census));
        let preparation = discovery.preparation_for(&snapshot);
        let prepared_discovery = tokio::task::spawn_blocking(move || preparation.prepare())
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?
            .map_err(|diagnostics| ServerError::Reload(ReloadError::new(diagnostics)))?;
        let mut listeners = Vec::new();
        for configured in &snapshot.listeners {
            let listener =
                TcpListener::bind(configured.bind)
                    .await
                    .map_err(|source| ServerError::Bind {
                        listener: configured.name.clone(),
                        address: configured.bind,
                        source_span: Box::new(configured.source.clone()),
                        source,
                    })?;
            let local_address =
                listener
                    .local_addr()
                    .map_err(|source| ServerError::LocalAddress {
                        listener: configured.name.clone(),
                        source_span: Box::new(configured.source.clone()),
                        source,
                    })?;
            listeners.push(BoundListener {
                name: configured.name.clone(),
                configured_address: configured.bind,
                source_span: configured.source.clone(),
                listener,
                local_address,
            });
        }
        let admin = bind_configured_admin(&snapshot).await?;
        let proxy = Arc::new(
            ProxyClient::with_census(Arc::clone(&census)).map_err(ServerError::DataPlane)?,
        );
        proxy.reconcile_snapshot(&snapshot);
        let health = ClusterHealthManager::with_census(census).map_err(ServerError::DataPlane)?;
        Ok(Self {
            store: Arc::new(SnapshotStore::new_with_origin(snapshot, origin)),
            proxy,
            health,
            discovery,
            prepared_discovery,
            metrics: Arc::new(Metrics::default()),
            listeners,
            admin,
            drain_timeout: Duration::from_secs(10),
        })
    }

    pub async fn with_admin_listener(mut self, bind: SocketAddr) -> Result<Self, ServerError> {
        if self.admin.is_some() {
            return Err(ServerError::AdminConfiguration(
                "the snapshot already defines an administration listener".to_owned(),
            ));
        }
        if !bind.ip().is_loopback() {
            return Err(ServerError::AdminConfiguration(
                "the legacy unauthenticated administration listener is restricted to loopback"
                    .to_owned(),
            ));
        }
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| ServerError::Bind {
                listener: "@admin".to_owned(),
                address: bind,
                source_span: Box::new(SourceSpan::synthetic("serve.admin_bind")),
                source,
            })?;
        let local_address = listener
            .local_addr()
            .map_err(|source| ServerError::LocalAddress {
                listener: "@admin".to_owned(),
                source_span: Box::new(SourceSpan::synthetic("serve.admin_bind")),
                source,
            })?;
        self.admin = Some(BoundAdmin {
            transport: BoundAdminTransport::Tcp(listener),
            endpoint: AdminEndpoint::Tcp(local_address),
            security: Arc::new(AdminSecurityPolicy::legacy_loopback_read_only()),
            tls: None,
            candidates: None,
            candidate_upload_directory: None,
            candidate_deployment_root: None,
            max_candidate_bytes: DEFAULT_ADMIN_REQUEST_BODY_BYTES,
            audit: None,
        });
        Ok(self)
    }

    /// Enables the explicit development-only Unix administration transport.
    /// Production configuration should use the top-level authenticated
    /// `admin` block, which is prepared automatically with the snapshot.
    #[cfg(unix)]
    pub async fn with_admin_unix_listener(
        mut self,
        path: impl AsRef<std::path::Path>,
        mode: u32,
    ) -> Result<Self, ServerError> {
        if self.admin.is_some() {
            return Err(ServerError::AdminConfiguration(
                "the snapshot already defines an administration listener".to_owned(),
            ));
        }
        let listener = crate::admin::unix_socket::BoundUnixAdmin::bind(path.as_ref(), mode)
            .await
            .map_err(|source| ServerError::AdminUnixBind {
                path: path.as_ref().to_path_buf(),
                source_span: Box::new(SourceSpan::synthetic("serve.admin_unix")),
                source,
            })?;
        let endpoint = AdminEndpoint::Unix(listener.path().to_path_buf());
        self.admin = Some(BoundAdmin {
            transport: BoundAdminTransport::Unix(listener),
            endpoint,
            security: Arc::new(AdminSecurityPolicy::legacy_loopback_read_only()),
            tls: None,
            candidates: None,
            candidate_upload_directory: None,
            candidate_deployment_root: None,
            max_candidate_bytes: DEFAULT_ADMIN_REQUEST_BODY_BYTES,
            audit: None,
        });
        Ok(self)
    }

    #[must_use]
    pub fn admin_address(&self) -> Option<SocketAddr> {
        self.admin.as_ref().and_then(|admin| match admin.endpoint {
            AdminEndpoint::Tcp(address) => Some(address),
            #[cfg(unix)]
            AdminEndpoint::Unix(_) => None,
        })
    }

    #[must_use]
    pub fn admin_endpoint(&self) -> Option<&AdminEndpoint> {
        self.admin.as_ref().map(|admin| &admin.endpoint)
    }

    #[must_use]
    pub fn local_addresses(&self) -> Vec<(String, SocketAddr)> {
        self.listeners
            .iter()
            .map(|listener| (listener.name.clone(), listener.local_address))
            .collect()
    }

    #[must_use]
    pub fn snapshot_store(&self) -> Arc<SnapshotStore> {
        self.store.clone()
    }

    pub fn spawn(self) -> RunningServer {
        let addresses = self.local_addresses();
        let admin_address = self.admin_address();
        let admin_endpoint = self.admin_endpoint().cloned();
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let reload_dependencies = Arc::new(Mutex::new(ReloadDependencyState::new(
            store.pin().dependencies.clone(),
        )));
        let compile_gate = Arc::new(Semaphore::new(1));
        let (control, receiver) = mpsc::channel(8);
        let reload = ReloadHandle {
            store,
            metrics,
            control: control.clone(),
            dependencies: reload_dependencies,
            compile_gate,
            #[cfg(test)]
            preparation_delay: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            preparation_started: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            preparation_pause: Arc::new(Mutex::new(None)),
        };
        let task = tokio::spawn(self.run(receiver, reload.clone()));
        RunningServer {
            addresses,
            reload,
            admin_address,
            admin_endpoint,
            control,
            task,
        }
    }

    pub async fn run_until<F>(self, signal: F) -> Result<(), ServerError>
    where
        F: Future<Output = ()>,
    {
        let running = self.spawn();
        signal.await;
        running.shutdown().await
    }

    async fn run(
        mut self,
        mut control: mpsc::Receiver<Control>,
        reload: ReloadHandle,
    ) -> Result<(), ServerError> {
        let bootstrap = self.admin.as_ref().map(|admin| Arc::clone(&admin.security));
        let journal = self
            .admin
            .as_ref()
            .and_then(|admin| admin.candidates.clone());
        let audit = self.admin.as_ref().and_then(|admin| admin.audit.clone());
        let preparation_gate = Arc::clone(&reload.compile_gate);
        self.discovery
            .activate_snapshot(
                &self.store.pin(),
                &self.proxy,
                &self.metrics,
                self.prepared_discovery,
            )
            .await;
        self.health.activate_snapshot(&self.store.pin());
        let (completion_sender, mut completions) = mpsc::unbounded_channel();
        let mut listeners = BTreeMap::new();
        let mut generation = 1u64;
        for listener in self.listeners.drain(..) {
            let name = listener.name.clone();
            listeners.insert(
                name,
                start_listener(
                    listener,
                    generation,
                    self.store.clone(),
                    self.proxy.clone(),
                    self.metrics.clone(),
                    self.drain_timeout,
                    completion_sender.clone(),
                ),
            );
            generation = generation.saturating_add(1);
        }
        let mut admin = self.admin.take().map(|admin| {
            start_admin_listener(
                admin,
                self.store.clone(),
                self.metrics.clone(),
                self.drain_timeout,
                reload,
            )
        });

        loop {
            tokio::select! {
                command = control.recv() => {
                    match command {
                        Some(Control::BeginOperation { store, context, action, target, body_digest, required_audit, work, response }) => {
                            let expected = context.if_match.clone();
                            let actual = self.store.published().etag();
                            let worker_store = Arc::clone(&store);
                            let result = if response.is_closed() { Err(oxidase_runtime::CandidateStoreError::new("candidate.cancelled", "operation caller was cancelled")) } else if let Err(error) = work.checkpoint() { Err(error) } else {
                                match store.replay_operation(&context, action, target, body_digest) {
                                    Ok(Some(receipt)) => Ok(oxidase_runtime::OperationBegin { receipt, replayed:true }),
                                    Ok(None) if expected.as_deref() != Some(actual.as_str()) => Err(oxidase_runtime::CandidateStoreError::new("candidate.precondition", "current runtime condition is stale")),
                                    Ok(None) => tokio::task::spawn_blocking(move || if required_audit { worker_store.begin_operation_audited(&context,action,target,body_digest) } else { worker_store.begin_operation(&context, action, target, body_digest) }).await.map_err(|_| oxidase_runtime::CandidateStoreError::new("candidate.operation_worker", "operation journal worker failed")).and_then(|result| result),
                                    Err(error) => Err(error),
                                }
                            };
                            let _ = response.send(result);
                        }
                        Some(Control::Reload { snapshot, reuse, expected_version, origin, watched_source, deadline, operation, response }) => {
                            let mut operation = operation;
                            let initial = self.store.published();
                            let automatic = if operation.is_none() && origin == RuntimeOrigin::Source && expected_version == initial.etag() && !response.is_closed() && std::time::Instant::now() < deadline && (!watched_source || (initial.origin == RuntimeOrigin::Source && initial.serving_state == ServingState::Running)) {
                                if let Some(journal) = &journal {
                                    match prepare_source_commit_operation(journal, audit.as_ref(), &initial, deadline).await {
                                        Ok(created) => { operation = Some(created); Ok(()) },
                                        Err(error) => Err(error),
                                    }
                                } else { Ok(()) }
                            } else { Ok(()) };
                            let environment = ReloadEnvironment {
                                store: &self.store,
                                proxy: &self.proxy,
                                metrics: &self.metrics,
                                health: &mut self.health,
                                discovery: &mut self.discovery,
                                drain_timeout: self.drain_timeout,
                                completion: &completion_sender,
                                expected_etag: &expected_version,
                                deadline,
                                operation: operation.as_ref(),
                                response: &response,
                                #[cfg(test)]
                                after_publish: None,
                            };
                            let published = self.store.published();
                            let result = if let Err(error) = automatic { Err(error) } else if expected_version != published.etag() {
                                Err(ServerError::PreconditionFailed)
                            } else if response.is_closed() || std::time::Instant::now() >= deadline {
                                Err(ServerError::OperationCancelled)
                            } else if watched_source && (published.origin != RuntimeOrigin::Source || published.serving_state != ServingState::Running) {
                                Err(ServerError::SourceAuthorityLost)
                            } else {
                                let compatibility = if let Some(security) = &bootstrap {
                                    let security = Arc::clone(security);
                                    let candidate = (*snapshot).clone();
                                    let admission = Arc::clone(&preparation_gate).try_acquire_owned();
                                    if let Ok(admission) = admission { tokio::task::spawn_blocking(move || {
                                        let _admission = admission;
                                        security.check_candidate(&candidate)
                                    })
                                        .await.map_err(|error| ServerError::Task(error.to_string()))
                                        .and_then(|result| result.map_err(ServerError::AdminPreparation)) } else { Err(ServerError::PreparationBusy) }
                                } else { Ok(()) };
                                if let Err(error) = compatibility { Err(error) } else { apply_reload(
                                    *snapshot,
                                    reuse,
                                    origin,
                                    &mut listeners,
                                    &mut generation,
                                    environment,
                                ).await }
                            };
                            if let (Some(operation), Err(error)) = (&operation, &result) {
                                let store = Arc::clone(&operation.store);
                                let id = operation.operation_id.clone();
                                let code = error.diagnostics().first().map(|diagnostic| diagnostic.code).unwrap_or("admin.commit_failed");
                                let cancelled = matches!(error, ServerError::OperationCancelled);
                                let _ = tokio::task::spawn_blocking(move || {
                                    let result = if cancelled { store.finish_cancelled(&id, code) } else { store.finish_failed(&id, code) };
                                    result.unwrap_or_else(|error| store.force_uncommitted_recovery_receipt(&id,error.code()))
                                }).await;
                                let receipt = operation.store.operation(&operation.operation_id);
                                finish_operation_audit(&operation.audit, &operation.store, receipt, &self.store.published()).await;
                            }
                            let _ = response.send(result);
                        }
                        Some(Control::Shutdown { response }) => {
                            control.close();
                            reject_pending_admin_commands(&mut control, &self.store).await;
                            stop_all_listeners(&mut listeners).await;
                            stop_admin_listener(&mut admin).await;
                            self.health.shutdown().await;
                            self.discovery.shutdown().await;
                            let _ = response.send(());
                            return Ok(());
                        }
                        Some(Control::Drain { expected_version, deadline, operation, response }) => {
                            let published = self.store.published();
                            let result = if expected_version != published.etag() {
                                Err(ServerError::PreconditionFailed)
                            } else if response.is_closed() || std::time::Instant::now() >= deadline {
                                Err(ServerError::OperationCancelled)
                            } else if published.serving_state == ServingState::Drained {
                                if let Some(operation) = &operation {
                                    let worker = operation.clone();
                                    let version = published.snapshot.config_version.to_string();
                                    let revision = published.runtime_revision;
                                    match tokio::task::spawn_blocking(move || worker.store.complete_unchanged(&worker.operation_id, revision, &version)).await {
                                        Ok(Ok(receipt)) => { finish_operation_audit(&operation.audit, &operation.store, Some(receipt), &published).await; Ok(()) },
                                        _ => Err(ServerError::AdminStore("candidate.completion_worker")),
                                    }
                                } else { Ok(()) }
                            } else {
                                let intent = async {
                                    if let Some(operation) = &operation {
                                        operation.work.checkpoint().map_err(|_| ServerError::OperationCancelled)?;
                                        let operation = operation.clone();
                                        let published = Arc::clone(&published);
                                        tokio::task::spawn_blocking(move || operation.store.begin_intent(&operation.operation_id, published.runtime_revision, published.snapshot.config_version.as_str()))
                                            .await.map_err(|error| ServerError::Task(error.to_string()))?
                                            .map_err(|error| ServerError::AdminStore(error.code()))?;
                                    }
                                    if response.is_closed() || std::time::Instant::now() >= deadline || operation.as_ref().is_some_and(|operation| operation.work.checkpoint().is_err()) {
                                        return Err(ServerError::OperationCancelled);
                                    }
                                    Ok(())
                                }.await;
                                if let Err(error) = intent { Err(error) } else {
                                    self.store.set_serving_state(ServingState::Draining);
                                    stop_all_listeners(&mut listeners).await;
                                    self.health.shutdown().await;
                                    self.discovery.shutdown().await;
                                    self.store.set_serving_state(ServingState::Drained);
                                    if let Some(operation) = &operation {
                                        finish_runtime_commit(operation, &self.store.published()).await;
                                    }
                                    Ok(())
                                }
                            };
                            if let (Some(operation), Err(error)) = (&operation, &result) {
                                let store = Arc::clone(&operation.store);
                                let id = operation.operation_id.clone();
                                let code = error.diagnostics().first().map_or("admin.drain_failed", |diagnostic| diagnostic.code);
                                let cancelled = matches!(error, ServerError::OperationCancelled);
                                let _ = tokio::task::spawn_blocking(move || {
                                    let result = if cancelled { store.finish_cancelled(&id, code) } else { store.finish_failed(&id, code) };
                                    result.unwrap_or_else(|error| store.force_uncommitted_recovery_receipt(&id,error.code()))
                                }).await;
                                finish_operation_audit(&operation.audit, &operation.store, operation.store.operation(&operation.operation_id), &self.store.published()).await;
                            }
                            let _ = response.send(result);
                        }
                        None => {
                            stop_all_listeners(&mut listeners).await;
                            stop_admin_listener(&mut admin).await;
                            self.health.shutdown().await;
                            self.discovery.shutdown().await;
                            return Ok(());
                        }
                    }
                }
                completion = completions.recv() => {
                    if let Some(completion) = completion {
                        let is_active = listeners
                            .get(&completion.name)
                            .is_some_and(|listener| listener.generation == completion.generation);
                        if is_active {
                            listeners.remove(&completion.name);
                            completion.result?;
                            return Err(ServerError::Task(format!(
                                "listener `{}` stopped unexpectedly",
                                completion.name
                            )));
                        } else if let Err(error) = completion.result {
                            tracing::warn!(listener = completion.name, error = %error, "retired listener failed while draining");
                        }
                    }
                }
            }
        }
    }
}

async fn bind_configured_admin(
    snapshot: &RuntimeSnapshot,
) -> Result<Option<BoundAdmin>, ServerError> {
    let Some(admin) = snapshot.admin.as_ref() else {
        return Ok(None);
    };
    let bootstrap_snapshot = snapshot.clone();
    let (security, candidates, audit) = tokio::task::spawn_blocking(move || {
        let spec = bootstrap_snapshot
            .admin
            .as_ref()
            .expect("compiled Admin exists");
        let security = Arc::new(
            AdminSecurityPolicy::prepare(&bootstrap_snapshot)
                .map_err(ServerError::AdminPreparation)?,
        );
        let candidates = prepare_candidate_store(spec)?;
        let audit = AdminAuditSink::start(&spec.audit).map_err(|_| {
            ServerError::AdminPreparation(Box::new(Diagnostic::new(
                "admin.audit_prepare",
                "cannot prepare the configured audit destination",
                spec.source.clone(),
            )))
        })?;
        Ok::<_, ServerError>((security, candidates, Some(audit)))
    })
    .await
    .map_err(|error| ServerError::Task(error.to_string()))??;
    match &admin.listen {
        AdminListenSpec::Https(https) => {
            let tls = PreparedTlsListener::prepare_admin(
                https,
                &snapshot.resources.certificates,
                &snapshot.resources.trust_stores,
            )
            .map_err(ServerError::AdminPreparation)?;
            let listener =
                TcpListener::bind(https.bind)
                    .await
                    .map_err(|source| ServerError::Bind {
                        listener: "@admin".to_owned(),
                        address: https.bind,
                        source_span: Box::new(https.bind_source.clone()),
                        source,
                    })?;
            let local_address =
                listener
                    .local_addr()
                    .map_err(|source| ServerError::LocalAddress {
                        listener: "@admin".to_owned(),
                        source_span: Box::new(https.bind_source.clone()),
                        source,
                    })?;
            Ok(Some(BoundAdmin {
                transport: BoundAdminTransport::Tcp(listener),
                endpoint: AdminEndpoint::Tcp(local_address),
                security,
                tls: Some(tls),
                candidates,
                candidate_upload_directory: Some(admin.storage.directory.clone()),
                candidate_deployment_root: Some(admin.bundle_trust.deployment_root.clone()),
                max_candidate_bytes: admin.candidates.max_candidate_bytes,
                audit,
            }))
        }
        AdminListenSpec::Unix(unix) => {
            #[cfg(unix)]
            {
                let listener =
                    crate::admin::unix_socket::BoundUnixAdmin::bind(&unix.path, unix.mode)
                        .await
                        .map_err(|source| ServerError::AdminUnixBind {
                            path: unix.path.clone(),
                            source_span: Box::new(unix.source.clone()),
                            source,
                        })?;
                let endpoint = AdminEndpoint::Unix(listener.path().to_path_buf());
                Ok(Some(BoundAdmin {
                    transport: BoundAdminTransport::Unix(listener),
                    endpoint,
                    security,
                    tls: None,
                    candidates,
                    candidate_upload_directory: Some(admin.storage.directory.clone()),
                    candidate_deployment_root: Some(admin.bundle_trust.deployment_root.clone()),
                    max_candidate_bytes: admin.candidates.max_candidate_bytes,
                    audit,
                }))
            }
            #[cfg(not(unix))]
            {
                let _ = unix;
                Err(ServerError::AdminConfiguration(
                    "Unix administration sockets are unavailable on this platform".to_owned(),
                ))
            }
        }
    }
}

fn prepare_candidate_store(
    admin: &oxidase_config::AdminSpec,
) -> Result<Option<Arc<CandidateStore>>, ServerError> {
    let trusted_keys = admin
        .bundle_trust
        .verification_keys
        .iter()
        .zip(&admin.bundle_trust.verification_key_sources)
        .map(|(path, source)| {
            BundleVerificationKey::read_file(path).map_err(|error| {
                ServerError::AdminPreparation(Box::new(Diagnostic::new(
                    error.code(),
                    "cannot load an admin Bundle verification key",
                    source.clone(),
                )))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let limits = CandidateStoreLimits {
        max_candidates: usize::try_from(admin.candidates.max_count).map_err(|_| {
            ServerError::AdminConfiguration(
                "admin candidate count exceeds this platform's address space".to_owned(),
            )
        })?,
        max_total_bytes: admin.candidates.max_bytes,
        max_candidate_bytes: admin.candidates.max_candidate_bytes,
        max_history_snapshots: usize::try_from(admin.history.max_snapshots).map_err(|_| {
            ServerError::AdminConfiguration(
                "admin history count exceeds this platform's address space".to_owned(),
            )
        })?,
        max_history_bytes: admin.history.max_bytes,
        ..CandidateStoreLimits::default()
    };
    let capabilities = oxidase_runtime::bundle_runtime_capabilities();
    CandidateStore::open(
        admin.storage.directory.clone(),
        limits,
        CandidateSignaturePolicy::require_trusted(trusted_keys),
        capabilities,
    )
    .map(Some)
    .map_err(|error| {
        ServerError::AdminPreparation(Box::new(Diagnostic::new(
            error.code(),
            "cannot prepare the bounded admin candidate store",
            admin.storage.source.clone(),
        )))
    })
}

pub struct RunningServer {
    addresses: Vec<(String, SocketAddr)>,
    admin_address: Option<SocketAddr>,
    admin_endpoint: Option<AdminEndpoint>,
    reload: ReloadHandle,
    control: mpsc::Sender<Control>,
    task: JoinHandle<Result<(), ServerError>>,
}

impl RunningServer {
    #[must_use]
    pub fn local_addresses(&self) -> &[(String, SocketAddr)] {
        &self.addresses
    }

    #[must_use]
    pub const fn admin_address(&self) -> Option<SocketAddr> {
        self.admin_address
    }

    #[must_use]
    pub fn admin_endpoint(&self) -> Option<&AdminEndpoint> {
        self.admin_endpoint.as_ref()
    }

    #[must_use]
    pub fn reload_handle(&self) -> ReloadHandle {
        self.reload.clone()
    }

    pub async fn reload_path(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<ReloadReport, ServerError> {
        self.reload.reload_path(path).await
    }

    pub async fn shutdown(self) -> Result<(), ServerError> {
        let (response, received) = oneshot::channel();
        self.control
            .send(Control::Shutdown { response })
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        let _ = received.await;
        self.task
            .await
            .map_err(|error| ServerError::Task(error.to_string()))?
    }
}

#[derive(Clone)]
pub struct ReloadHandle {
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    control: mpsc::Sender<Control>,
    dependencies: Arc<Mutex<ReloadDependencyState>>,
    compile_gate: Arc<Semaphore>,
    #[cfg(test)]
    preparation_delay: Arc<Mutex<Option<Duration>>>,
    #[cfg(test)]
    preparation_started: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    preparation_pause: Arc<Mutex<Option<Arc<std::sync::Barrier>>>>,
}

impl ReloadHandle {
    pub async fn reload_path(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<ReloadReport, ServerError> {
        let result = self.reload_path_inner(path.as_ref(), false, None).await;
        self.metrics.record_reload(result.is_ok());
        result
    }

    pub async fn reload_watched_path(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<ReloadReport, ServerError> {
        let result = self.reload_path_inner(path.as_ref(), true, None).await;
        self.metrics.record_reload(result.is_ok());
        result
    }

    #[cfg(test)]
    async fn drain_data_plane(&self, expected_version: String) -> Result<(), ServerError> {
        self.drain_operation(
            expected_version,
            None,
            std::time::Instant::now() + ADMIN_MUTATION_TIMEOUT,
        )
        .await
    }

    async fn drain_operation(
        &self,
        expected_version: String,
        operation: Option<CommitOperation>,
        deadline: std::time::Instant,
    ) -> Result<(), ServerError> {
        let (response, received) = oneshot::channel();
        self.control
            .send(Control::Drain {
                expected_version,
                deadline,
                operation,
                response,
            })
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        received.await.map_err(|_| ServerError::ControlClosed)?
    }

    #[cfg(test)]
    async fn activate_prepared(
        &self,
        snapshot: RuntimeSnapshot,
        reuse: ResourceReuse,
        expected_version: String,
        origin: RuntimeOrigin,
    ) -> Result<ReloadReport, ServerError> {
        self.publish_prepared(
            snapshot,
            reuse,
            expected_version,
            origin,
            None,
            std::time::Instant::now() + ADMIN_MUTATION_TIMEOUT,
        )
        .await
    }

    async fn publish_prepared(
        &self,
        snapshot: RuntimeSnapshot,
        reuse: ResourceReuse,
        expected_version: String,
        origin: RuntimeOrigin,
        operation: Option<CommitOperation>,
        deadline: std::time::Instant,
    ) -> Result<ReloadReport, ServerError> {
        let published_dependencies = snapshot.dependencies.clone();
        let (response, received) = oneshot::channel();
        self.control
            .send(Control::Reload {
                snapshot: Box::new(snapshot),
                reuse,
                expected_version,
                origin,
                watched_source: false,
                deadline,
                operation,
                response,
            })
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        let report = received.await.map_err(|_| ServerError::ControlClosed)??;
        self.record_published_dependencies(published_dependencies);
        Ok(report)
    }

    async fn reload_path_inner(
        &self,
        path: &std::path::Path,
        watched_source: bool,
        expected: Option<String>,
    ) -> Result<ReloadReport, ServerError> {
        self.reload_path_with_operation(
            path,
            watched_source,
            expected,
            None,
            std::time::Instant::now() + ADMIN_MUTATION_TIMEOUT,
        )
        .await
    }

    async fn reload_path_with_operation(
        &self,
        path: &std::path::Path,
        watched_source: bool,
        expected: Option<String>,
        operation: Option<CommitOperation>,
        deadline: std::time::Instant,
    ) -> Result<ReloadReport, ServerError> {
        let published = self.store.published();
        if watched_source
            && (published.origin != RuntimeOrigin::Source
                || published.serving_state != ServingState::Running)
        {
            return Err(ServerError::SourceAuthorityLost);
        }
        let expected_version = expected.unwrap_or_else(|| published.etag());
        if expected_version != published.etag() {
            return Err(ServerError::PreconditionFailed);
        }
        let permit = Arc::clone(&self.compile_gate)
            .try_acquire_owned()
            .map_err(|_| ServerError::PreparationBusy)?;
        let current = Arc::clone(&published.snapshot);
        let path = path.to_path_buf();
        let checked_work = operation
            .as_ref()
            .map(|operation| operation.work.clone())
            .unwrap_or_else(|| CandidateWorkControl::with_deadline(deadline));
        let preparation_delay = self.test_preparation_delay();
        #[cfg(test)]
        let preparation_started = Some(self.preparation_started.clone());
        #[cfg(not(test))]
        let preparation_started: Option<Arc<tokio::sync::Notify>> = None;
        #[cfg(test)]
        let preparation_pause = self
            .preparation_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        #[cfg(not(test))]
        let preparation_pause: Option<Arc<std::sync::Barrier>> = None;
        let prepared = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            checked_work
                .checkpoint()
                .map_err(|_| (ServerError::OperationCancelled, Vec::new()))?;
            if let Some(started) = preparation_started {
                started.notify_one();
            }
            if let Some(pause) = preparation_pause {
                pause.wait();
            }
            if let Some(delay) = preparation_delay {
                std::thread::sleep(delay);
            }
            let mut gateway = match oxidase_config::Compiler::compile_path_controlled(path, || {
                checked_work.checkpoint().map_err(|error| {
                    oxidase_config::CompileError::one(Diagnostic::new(
                        error.code(),
                        "source preparation interrupted",
                        SourceSpan::synthetic("source"),
                    ))
                })
            }) {
                Ok(gateway) => gateway,
                Err(error) => {
                    let dependencies = error.discovered_dependencies;
                    return Err((
                        ServerError::Reload(ReloadError::new(error.diagnostics)),
                        dependencies,
                    ));
                }
            };
            let attempt_dependencies = candidate_gateway_dependencies(&gateway);
            checked_work.checkpoint().map_err(|_| {
                (
                    ServerError::OperationCancelled,
                    attempt_dependencies.clone(),
                )
            })?;
            let mut warnings = std::mem::take(&mut gateway.warnings);
            match RuntimeSnapshot::prepare_reusing_controlled(
                gateway,
                Some(&current),
                &checked_work,
            ) {
                Ok((snapshot, reuse)) => {
                    checked_work.checkpoint().map_err(|_| {
                        (
                            ServerError::OperationCancelled,
                            snapshot.dependencies.clone(),
                        )
                    })?;
                    warnings.extend(snapshot.preparation_warnings().iter().cloned());
                    Ok((snapshot, reuse, attempt_dependencies, warnings))
                }
                Err(error) => {
                    let mut dependencies = attempt_dependencies;
                    dependencies.extend(error.candidate_dependencies.iter().cloned());
                    dependencies.sort();
                    dependencies.dedup();
                    let mut diagnostics = warnings;
                    diagnostics.extend(error.into_diagnostics());
                    Err((
                        ServerError::Reload(ReloadError::new(diagnostics)),
                        dependencies,
                    ))
                }
            }
        })
        .await
        .map_err(|error| ServerError::Task(format!("reload compiler worker failed: {error}")))?;
        let (snapshot, reuse, attempt_dependencies, warnings) = match prepared {
            Ok(prepared) => prepared,
            Err((error, dependencies)) => {
                self.record_attempt_dependencies(dependencies);
                return Err(error);
            }
        };
        self.record_attempt_dependencies(attempt_dependencies);
        let published_dependencies = snapshot.dependencies.clone();
        let (response, received) = oneshot::channel();
        self.control
            .send(Control::Reload {
                snapshot: Box::new(snapshot),
                reuse,
                expected_version,
                origin: RuntimeOrigin::Source,
                watched_source,
                deadline,
                operation,
                response,
            })
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        let mut report = received.await.map_err(|_| ServerError::ControlClosed)??;
        report.warnings = warnings;
        self.record_published_dependencies(published_dependencies);
        Ok(report)
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.store.pin()
    }

    #[must_use]
    pub fn published_runtime(&self) -> Arc<PublishedRuntime> {
        self.store.published()
    }

    #[must_use]
    pub fn watched_dependencies(&self) -> Vec<PathBuf> {
        self.dependencies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .watched()
    }

    fn record_attempt_dependencies(&self, dependencies: Vec<PathBuf>) {
        self.dependencies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_attempt(dependencies);
    }

    fn record_published_dependencies(&self, dependencies: Vec<PathBuf>) {
        self.dependencies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record_published(dependencies);
    }

    fn test_preparation_delay(&self) -> Option<Duration> {
        #[cfg(test)]
        {
            *self
                .preparation_delay
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        #[cfg(not(test))]
        {
            None
        }
    }

    #[cfg(test)]
    fn set_test_preparation_delay(&self, delay: Duration) {
        *self
            .preparation_delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(delay);
    }

    #[cfg(test)]
    async fn wait_test_preparation_started(&self) {
        self.preparation_started.notified().await;
    }

    #[cfg(test)]
    fn pause_test_preparation(&self) -> Arc<std::sync::Barrier> {
        let pause = Arc::new(std::sync::Barrier::new(2));
        *self
            .preparation_pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&pause));
        pause
    }
}

#[derive(Debug, Default)]
struct ReloadDependencyState {
    published: BTreeSet<PathBuf>,
    last_attempt: BTreeSet<PathBuf>,
}

impl ReloadDependencyState {
    fn new(published: Vec<PathBuf>) -> Self {
        let published = published.into_iter().collect::<BTreeSet<_>>();
        Self {
            last_attempt: published.clone(),
            published,
        }
    }

    fn record_attempt(&mut self, dependencies: Vec<PathBuf>) {
        self.last_attempt = dependencies.into_iter().collect();
    }

    fn record_published(&mut self, dependencies: Vec<PathBuf>) {
        self.published = dependencies.into_iter().collect();
        self.last_attempt = self.published.clone();
    }

    fn watched(&self) -> Vec<PathBuf> {
        self.published.union(&self.last_attempt).cloned().collect()
    }
}

fn candidate_gateway_dependencies(gateway: &oxidase_config::CompiledGateway) -> Vec<PathBuf> {
    let mut dependencies = gateway
        .dependencies
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for site in gateway.resources.sites.values() {
        dependencies.insert(site.root.clone());
        dependencies.insert(site.manifest.clone());
        if let Some(parent) = site.manifest.parent() {
            dependencies.insert(parent.to_path_buf());
        }
    }
    dependencies.into_iter().collect()
}

#[derive(Debug, Clone)]
pub struct ReloadReport {
    pub previous_version: String,
    pub current_version: String,
    pub reused_sites: usize,
    pub reused_clusters: usize,
    pub reused_cluster_endpoints: usize,
    pub reused_certificates: usize,
    pub listeners_added: Vec<String>,
    pub listeners_removed: Vec<String>,
    pub listeners_retained: Vec<String>,
    pub local_addresses: Vec<(String, SocketAddr)>,
    /// Non-fatal diagnostics emitted while compiling this committed candidate.
    pub warnings: Vec<Diagnostic>,
    pub operation: Option<OperationReceipt>,
}

fn start_listener(
    listener: BoundListener,
    generation: u64,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    drain_timeout: Duration,
    completion: mpsc::UnboundedSender<ListenerCompletion>,
) -> ActiveListener {
    let name = listener.name.clone();
    let configured_address = listener.configured_address;
    let local_address = listener.local_address;
    let (shutdown, receiver) = watch::channel(false);
    let (accept_stopped, stopped) = oneshot::channel();
    let completion_name = name.clone();
    let task = tokio::spawn(async move {
        let result = run_listener(
            listener,
            store,
            proxy,
            metrics,
            receiver,
            drain_timeout,
            accept_stopped,
        )
        .await;
        let _ = completion.send(ListenerCompletion {
            name: completion_name,
            generation,
            result,
        });
    });
    ActiveListener {
        configured_address,
        local_address,
        generation,
        shutdown,
        accept_stopped: Some(stopped),
        task,
    }
}

async fn apply_reload(
    snapshot: RuntimeSnapshot,
    reuse: ResourceReuse,
    origin: RuntimeOrigin,
    active: &mut BTreeMap<String, ActiveListener>,
    generation: &mut u64,
    environment: ReloadEnvironment<'_>,
) -> Result<ReloadReport, ServerError> {
    let preparation = environment.discovery.preparation_for(&snapshot);
    let prepared_discovery = tokio::task::spawn_blocking(move || preparation.prepare())
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
        .map_err(|diagnostics| ServerError::Reload(ReloadError::new(diagnostics)))?;
    let retained = snapshot
        .listeners
        .iter()
        .filter(|listener| {
            active
                .get(&listener.name)
                .is_some_and(|active| active.configured_address == listener.bind)
        })
        .map(|listener| listener.name.clone())
        .collect::<BTreeSet<_>>();

    // Every new socket is prepared before accept state or the published snapshot is
    // changed. Dropping this vector rolls the whole preparation back on any error.
    let mut prepared = Vec::new();
    for configured in snapshot
        .listeners
        .iter()
        .filter(|listener| !retained.contains(&listener.name))
    {
        let listener =
            TcpListener::bind(configured.bind)
                .await
                .map_err(|source| ServerError::Bind {
                    listener: configured.name.clone(),
                    address: configured.bind,
                    source_span: Box::new(configured.source.clone()),
                    source,
                })?;
        let local_address = listener
            .local_addr()
            .map_err(|source| ServerError::LocalAddress {
                listener: configured.name.clone(),
                source_span: Box::new(configured.source.clone()),
                source,
            })?;
        prepared.push(BoundListener {
            name: configured.name.clone(),
            configured_address: configured.bind,
            source_span: configured.source.clone(),
            listener,
            local_address,
        });
    }

    // Final conditions are checked after every socket has been prebound. Intent
    // records describe only a prepared publication, never a failed bind.
    let before = environment.store.published();
    if before.etag() != environment.expected_etag {
        return Err(ServerError::PreconditionFailed);
    }
    if environment.response.is_closed() || std::time::Instant::now() >= environment.deadline {
        return Err(ServerError::OperationCancelled);
    }
    if let Some(operation) = environment.operation {
        operation
            .work
            .checkpoint()
            .map_err(|_| ServerError::OperationCancelled)?;
        let operation = operation.clone();
        let before_revision = before.runtime_revision;
        let version = snapshot.config_version.to_string();
        tokio::task::spawn_blocking(move || {
            operation
                .store
                .begin_intent(&operation.operation_id, before_revision, &version)
        })
        .await
        .map_err(|error| ServerError::Task(error.to_string()))?
        .map_err(|error| ServerError::AdminStore(error.code()))?;
        if environment.response.is_closed()
            || std::time::Instant::now() >= environment.deadline
            || environment
                .operation
                .is_some_and(|operation| operation.work.checkpoint().is_err())
        {
            return Err(ServerError::OperationCancelled);
        }
    }

    let to_stop = active
        .keys()
        .filter(|name| !retained.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    let mut retired = Vec::new();
    for name in &to_stop {
        if let Some(mut listener) = active.remove(name) {
            let _ = listener.shutdown.send(true);
            if let Some(stopped) = listener.accept_stopped.take() {
                let _ = tokio::time::timeout(Duration::from_secs(2), stopped).await;
            }
            retired.push(listener);
        }
    }

    let previous_version = environment.store.pin().config_version.to_string();
    let current_version = snapshot.config_version.to_string();
    environment.store.publish_as(snapshot, origin);
    #[cfg(test)]
    if let Some(hook) = environment.after_publish {
        hook();
    }
    environment
        .proxy
        .reconcile_snapshot(&environment.store.pin());
    environment
        .discovery
        .activate_snapshot(
            &environment.store.pin(),
            environment.proxy,
            environment.metrics,
            prepared_discovery,
        )
        .await;
    environment
        .health
        .activate_snapshot(&environment.store.pin());
    let listeners_added = prepared
        .iter()
        .map(|listener| listener.name.clone())
        .collect::<Vec<_>>();
    for listener in prepared {
        let name = listener.name.clone();
        active.insert(
            name,
            start_listener(
                listener,
                *generation,
                environment.store.clone(),
                environment.proxy.clone(),
                environment.metrics.clone(),
                environment.drain_timeout,
                environment.completion.clone(),
            ),
        );
        *generation = generation.saturating_add(1);
    }
    // Dropping JoinHandle detaches retired tasks; they continue to drain and report
    // completion through the manager's completion channel.
    drop(retired);

    // Runtime availability does not wait for fsync or audit delivery. The
    // manager still owns and completes that post-publication bookkeeping.
    let operation = if let Some(operation) = environment.operation {
        Some(finish_runtime_commit(operation, &environment.store.published()).await)
    } else {
        None
    };

    Ok(ReloadReport {
        previous_version,
        current_version,
        reused_sites: reuse.sites,
        reused_clusters: reuse.clusters,
        reused_cluster_endpoints: reuse.cluster_endpoints,
        reused_certificates: reuse.certificates,
        listeners_added,
        listeners_removed: to_stop,
        listeners_retained: retained.into_iter().collect(),
        local_addresses: active
            .iter()
            .map(|(name, listener)| (name.clone(), listener.local_address))
            .collect(),
        warnings: Vec::new(),
        operation,
    })
}

struct ReloadEnvironment<'a> {
    store: &'a Arc<SnapshotStore>,
    proxy: &'a Arc<ProxyClient>,
    metrics: &'a Arc<Metrics>,
    health: &'a mut ClusterHealthManager,
    discovery: &'a mut DiscoveryManager,
    drain_timeout: Duration,
    completion: &'a mpsc::UnboundedSender<ListenerCompletion>,
    expected_etag: &'a str,
    deadline: std::time::Instant,
    operation: Option<&'a CommitOperation>,
    response: &'a oneshot::Sender<Result<ReloadReport, ServerError>>,
    #[cfg(test)]
    after_publish: Option<Box<dyn FnOnce() + Send>>,
}

async fn reject_pending_admin_commands(
    control: &mut mpsc::Receiver<Control>,
    published: &Arc<SnapshotStore>,
) {
    while let Ok(command) = control.try_recv() {
        match command {
            Control::BeginOperation { response, .. } => {
                let _ = response.send(Err(oxidase_runtime::CandidateStoreError::new(
                    "candidate.cancelled",
                    "server is shutting down",
                )));
            }
            Control::Reload {
                operation,
                response,
                ..
            } => {
                cancel_queued_operation(operation, published).await;
                let _ = response.send(Err(ServerError::OperationCancelled));
            }
            Control::Drain {
                operation,
                response,
                ..
            } => {
                cancel_queued_operation(operation, published).await;
                let _ = response.send(Err(ServerError::OperationCancelled));
            }
            Control::Shutdown { response } => {
                let _ = response.send(());
            }
        }
    }
}

async fn cancel_queued_operation(
    operation: Option<CommitOperation>,
    published: &Arc<SnapshotStore>,
) {
    if let Some(operation) = operation {
        operation.work.cancel();
        let worker = operation.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            worker
                .store
                .finish_cancelled(&worker.operation_id, "candidate.cancelled")
                .unwrap_or_else(|error| {
                    worker
                        .store
                        .force_uncommitted_recovery_receipt(&worker.operation_id, error.code())
                })
        })
        .await
        .ok();
        finish_operation_audit(
            &operation.audit,
            &operation.store,
            receipt,
            &published.published(),
        )
        .await;
    }
}

async fn finish_runtime_commit(
    operation: &CommitOperation,
    published: &PublishedRuntime,
) -> OperationReceipt {
    let store = Arc::clone(&operation.store);
    let operation_id = operation.operation_id.clone();
    let revision = published.runtime_revision;
    let version = published.snapshot.config_version.to_string();
    let receipt = match tokio::task::spawn_blocking(move || {
        store.complete_committed(&operation_id, revision, &version)
    })
    .await
    {
        Ok(receipt) => receipt,
        Err(_) => {
            force_operation_recovery(
                operation.store.clone(),
                operation.operation_id.clone(),
                revision,
                published.snapshot.config_version.to_string(),
                "candidate.completion_worker",
            )
            .await
        }
    };
    finish_operation_audit(&operation.audit, &operation.store, Some(receipt), published)
        .await
        .expect("runtime commit has a receipt")
}

async fn prepare_source_commit_operation(
    store: &Arc<CandidateStore>,
    sink: Option<&AdminAuditSink>,
    published: &PublishedRuntime,
    deadline: std::time::Instant,
) -> Result<CommitOperation, ServerError> {
    let request_id = format!(
        "source-{}-{}",
        published.runtime_revision,
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let mut event =
        AdminAuditEvent::new(&request_id, "unauthenticated", "internal", "reload_source");
    event.previous_revision = Some(published.runtime_revision.to_string());
    let permit = if let Some(sink) = sink {
        let permit = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            sink.prepare_mutation(event.clone()),
        )
        .await
        .map_err(|_| ServerError::AdminStore("admin.audit_deadline"))?
        .map_err(|error| ServerError::AdminStore(error.code()))?;
        Some((permit, event, sink.clone()))
    } else {
        None
    };
    let context = oxidase_runtime::CandidateOperationContext {
        request_id,
        principal: "internal:source".to_owned(),
        if_match: Some(published.etag()),
        idempotency_key: None,
    };
    let worker = Arc::clone(store);
    let required_audit = permit.is_some();
    let begin = tokio::task::spawn_blocking(move || {
        if required_audit {
            worker.begin_operation_audited(
                &context,
                oxidase_runtime::AuditAction::ReloadSource,
                None,
                None,
            )
        } else {
            worker.begin_operation(
                &context,
                oxidase_runtime::AuditAction::ReloadSource,
                None,
                None,
            )
        }
    })
    .await
    .map_err(|_| ServerError::AdminStore("candidate.operation_worker"))?
    .map_err(|error| ServerError::AdminStore(error.code()))?;
    Ok(CommitOperation {
        store: Arc::clone(store),
        operation_id: begin.receipt.operation_id,
        work: CandidateWorkControl::with_deadline(deadline),
        audit: Arc::new(Mutex::new(permit)),
    })
}

async fn force_operation_recovery(
    store: Arc<CandidateStore>,
    id: String,
    revision: u64,
    version: String,
    code: &'static str,
) -> OperationReceipt {
    // This path performs durable I/O too; it must not run on a Tokio worker.
    tokio::task::spawn_blocking(move || store.force_recovery_receipt(&id, revision, &version, code))
        .await
        .expect("recovery marker worker must not panic")
}

async fn finish_operation_audit(
    audit: &SharedOperationAudit,
    store: &Arc<CandidateStore>,
    receipt: Option<OperationReceipt>,
    published: &PublishedRuntime,
) -> Option<OperationReceipt> {
    let owned = audit
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    let Some((permit, mut event, sink)) = owned else {
        return receipt;
    };
    event.operation_id = receipt.as_ref().map(|receipt| receipt.operation_id.clone());
    event.new_revision = Some(published.runtime_revision.to_string());
    if let Some(receipt) = &receipt {
        event.result = if event.result == "replayed" {
            "replayed"
        } else {
            match receipt.phase {
                oxidase_runtime::OperationPhase::Committed => "committed",
                oxidase_runtime::OperationPhase::RecoveryRequired => "recovery_required",
                oxidase_runtime::OperationPhase::Cancelled => "cancelled",
                _ => "failed",
            }
        }
        .to_owned();
        event.target_digest = receipt.target_digest.map(|digest| digest.to_string());
        event.diagnostic_code.clone_from(&receipt.error_code);
    }
    let delivered = tokio::time::timeout(Duration::from_secs(5), permit.finish(event)).await;
    if !matches!(delivered, Ok(Ok(Ok(())))) {
        sink.fail_closed();
        if let Some(receipt) = receipt
            .as_ref()
            .filter(|receipt| receipt.committed_revision.is_some())
        {
            return Some(
                force_operation_recovery(
                    Arc::clone(store),
                    receipt.operation_id.clone(),
                    receipt.committed_revision.unwrap_or_default(),
                    receipt
                        .config_version
                        .clone()
                        .unwrap_or_else(|| "unknown".to_owned()),
                    "admin.audit_completion",
                )
                .await,
            );
        }
        if let Some(receipt) = receipt.as_ref().filter(|receipt| {
            receipt.audit_pending || receipt.phase == oxidase_runtime::OperationPhase::Committed
        }) {
            let worker = Arc::clone(store);
            let id = receipt.operation_id.clone();
            return tokio::task::spawn_blocking(move || {
                worker.force_uncommitted_recovery_receipt(&id, "admin.audit_completion")
            })
            .await
            .ok();
        }
        return receipt;
    }
    if let Some(receipt) = receipt.as_ref().filter(|receipt| receipt.audit_pending) {
        let worker = Arc::clone(store);
        let id = receipt.operation_id.clone();
        match tokio::task::spawn_blocking(move || worker.complete_audit(&id)).await {
            Ok(Ok(completed)) => return Some(completed),
            _ if receipt.committed_revision.is_some() => {
                return Some(
                    force_operation_recovery(
                        Arc::clone(store),
                        receipt.operation_id.clone(),
                        receipt.committed_revision.unwrap_or_default(),
                        receipt
                            .config_version
                            .clone()
                            .unwrap_or_else(|| "unknown".to_owned()),
                        "admin.audit_record_failed",
                    )
                    .await,
                );
            }
            _ => {
                let worker = Arc::clone(store);
                let id = receipt.operation_id.clone();
                return tokio::task::spawn_blocking(move || {
                    worker.force_uncommitted_recovery_receipt(&id, "admin.audit_record_failed")
                })
                .await
                .ok();
            }
        }
    }
    receipt
}

async fn stop_all_listeners(active: &mut BTreeMap<String, ActiveListener>) {
    let mut listeners = std::mem::take(active).into_values().collect::<Vec<_>>();
    for listener in &listeners {
        let _ = listener.shutdown.send(true);
    }
    for listener in &mut listeners {
        if let Some(stopped) = listener.accept_stopped.take() {
            let _ = stopped.await;
        }
    }
    for listener in listeners {
        let _ = listener.task.await;
    }
}

fn start_admin_listener(
    admin: BoundAdmin,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    drain_timeout: Duration,
    reload: ReloadHandle,
) -> ActiveAdmin {
    let control_plane = admin
        .candidates
        .as_ref()
        .zip(admin.candidate_upload_directory.as_ref())
        .zip(admin.candidate_deployment_root.as_ref())
        .map(
            |((candidates, _upload_directory), deployment_root)| AdminControlPlane {
                candidates: candidates.clone(),
                reload,
                deployment_root: deployment_root.clone(),
                max_candidate_bytes: admin.max_candidate_bytes,
                mutation_gate: Arc::new(Semaphore::new(1)),
                audit: admin.audit.clone(),
                operation_tasks: Arc::new(tokio::sync::Mutex::new(JoinSet::new())),
            },
        );
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(run_admin_listener(
        admin,
        control_plane,
        store,
        metrics,
        receiver,
        drain_timeout,
    ));
    ActiveAdmin { shutdown, task }
}

async fn stop_admin_listener(admin: &mut Option<ActiveAdmin>) {
    if let Some(admin) = admin.take() {
        let _ = admin.shutdown.send(true);
        let _ = admin.task.await;
    }
}

async fn run_admin_listener(
    admin: BoundAdmin,
    control_plane: Option<AdminControlPlane>,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) {
    let mut connections = JoinSet::new();
    let admission = Arc::new(Semaphore::new(MAX_CONCURRENT_ADMIN_CONNECTIONS));
    loop {
        reap_finished_connections(&mut connections, "admin");
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = admin.accept() => {
                let Ok(stream) = accepted else {
                    tracing::error!("admin listener failed while accepting a connection");
                    break;
                };
                let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
                    tracing::debug!(
                        limit = MAX_CONCURRENT_ADMIN_CONNECTIONS,
                        "admin connection admission rejected"
                    );
                    drop(stream);
                    continue;
                };
                let store = store.clone();
                let metrics = metrics.clone();
                let security = admin.security.clone();
                let tls = admin.tls.clone();
                let control_plane = control_plane.clone();
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    serve_admin_connection(
                        stream,
                        store,
                        metrics,
                        security,
                        tls,
                        control_plane,
                        connection_shutdown,
                    ).await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(error = %error, "admin connection task failed");
                }
            }
        }
    }
    if tokio::time::timeout(drain_timeout, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if let Some(control) = &control_plane {
        let mut tasks = control.operation_tasks.lock().await;
        if tokio::time::timeout(drain_timeout, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        if let Some(audit) = &control.audit {
            let _ = tokio::time::timeout(drain_timeout, audit.flush()).await;
        }
    }
}

impl BoundAdmin {
    async fn accept(&self) -> std::io::Result<BoxAdminIo> {
        match &self.transport {
            BoundAdminTransport::Tcp(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(Box::new(stream))
            }
            #[cfg(unix)]
            BoundAdminTransport::Unix(listener) => {
                let (stream, _) = listener.listener().accept().await?;
                Ok(Box::new(stream))
            }
        }
    }
}

async fn serve_admin_connection(
    stream: BoxAdminIo,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    security: Arc<AdminSecurityPolicy>,
    tls: Option<PreparedTlsListener>,
    control_plane: Option<AdminControlPlane>,
    shutdown: watch::Receiver<bool>,
) {
    if let Some(tls) = tls {
        let acceptor = TlsAcceptor::from(tls.server_config);
        let accepted = tokio::time::timeout(tls.handshake_timeout, acceptor.accept(stream)).await;
        let stream = match accepted {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                tracing::debug!(error = %error, "admin TLS handshake failed");
                return;
            }
            Err(_) => {
                tracing::debug!("admin TLS handshake timed out");
                return;
            }
        };
        let client = match verified_client_metadata(stream.get_ref().1.peer_certificates()) {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(error = %error, "verified admin client metadata is invalid");
                return;
            }
        };
        let peer = AdminPeerIdentity {
            verified_client_sha256: client.verified.then_some(client.sha256).flatten(),
        };
        serve_admin_http(
            Box::new(stream),
            store,
            metrics,
            security,
            peer,
            control_plane,
            shutdown,
        )
        .await;
        return;
    }
    serve_admin_http(
        stream,
        store,
        metrics,
        security,
        AdminPeerIdentity::default(),
        control_plane,
        shutdown,
    )
    .await;
}

async fn serve_admin_http(
    stream: BoxAdminIo,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    security: Arc<AdminSecurityPolicy>,
    peer: AdminPeerIdentity,
    control_plane: Option<AdminControlPlane>,
    mut shutdown: watch::Receiver<bool>,
) {
    let service = service_fn(move |request| {
        handle_admin_request(
            request,
            store.clone(),
            metrics.clone(),
            security.clone(),
            peer.clone(),
            control_plane.clone(),
        )
    });
    let connection = http1_builder(DEFAULT_HTTP1_HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let result = tokio::select! {
        result = &mut connection => result,
        () = wait_for_shutdown(&mut shutdown) => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::debug!(error = %error, "admin HTTP connection ended with an error");
    }
}

async fn handle_admin_request(
    request: Request<Incoming>,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    security: Arc<AdminSecurityPolicy>,
    peer: AdminPeerIdentity,
    control_plane: Option<AdminControlPlane>,
) -> Result<Response<GatewayBody>, Infallible> {
    let request_id = format!("admin-{}", REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed));
    let method = request.method().clone();
    let Some(route) = classify_admin_route(request.method(), request.uri().path()) else {
        if request.uri().path().starts_with("/api/v1/") {
            let allowed = allowed_admin_methods(request.uri().path());
            let mut response = admin_code_response(
                if allowed.is_some() {
                    StatusCode::METHOD_NOT_ALLOWED
                } else {
                    StatusCode::NOT_FOUND
                },
                if allowed.is_some() {
                    "admin.method_not_allowed"
                } else {
                    "admin.not_found"
                },
                &method,
            );
            if let Some(allowed) = allowed {
                response
                    .headers_mut()
                    .insert(header::ALLOW, HeaderValue::from_static(allowed));
            }
            return Ok(response);
        }
        let known_read_path = matches!(
            request.uri().path(),
            "/health/live"
                | "/health/ready"
                | "/metrics"
                | "/api/v1/clusters"
                | "/api/v1/resources"
                | "/api/v1/runtime"
                | "/api/v1/snapshots/current"
                | "/api/v1/snapshots"
        );
        return Ok(admin_response(
            if known_read_path {
                StatusCode::METHOD_NOT_ALLOWED
            } else {
                StatusCode::NOT_FOUND
            },
            "text/plain; charset=utf-8",
            Bytes::from_static(if known_read_path {
                b"Method Not Allowed"
            } else {
                b"Not Found"
            }),
            &method,
        ));
    };
    let published = store.published();
    let snapshot = Arc::clone(&published.snapshot);
    let principal = match security.authorize(request.headers(), &peer, route.permission) {
        Ok(principal) => principal,
        Err(error) => {
            if let Some(audit) = control_plane
                .as_ref()
                .and_then(|control| control.audit.as_ref())
            {
                let authenticated = security
                    .authenticated_principal(request.headers(), &peer)
                    .ok();
                let mut event = AdminAuditEvent::new(
                    &request_id,
                    authenticated
                        .as_ref()
                        .map_or("unauthenticated", |principal| {
                            principal.authentication_kind()
                        }),
                    authenticated
                        .as_ref()
                        .map_or("unauthenticated", |principal| principal.audit_id()),
                    route.permission.as_str(),
                );
                event.result = "rejected".to_owned();
                event.diagnostic_code = Some(error.code().to_owned());
                audit.try_record(event);
            }
            return Ok(admin_security_response(error, &method));
        }
    };
    tracing::debug!(
        admin_authentication = principal.authentication_kind(),
        admin_principal = principal.audit_id(),
        admin_permission = route.permission.as_str(),
        "administration request authorized"
    );
    if route.mutation {
        let max_body_bytes = security.max_body_bytes;
        if let Some(content_type) = route.content_type
            && let Err(error) =
                validate_mutation_header_shape(request.headers(), content_type, max_body_bytes)
        {
            if let Some(audit) = control_plane
                .as_ref()
                .and_then(|control| control.audit.as_ref())
            {
                let mut event = AdminAuditEvent::new(
                    &request_id,
                    principal.authentication_kind(),
                    principal.audit_id(),
                    route.permission.as_str(),
                );
                event.result = "rejected".to_owned();
                event.diagnostic_code = Some(error.code().to_owned());
                audit.try_record(event);
            }
            return Ok(admin_security_response(error, &method));
        }
        let Some(control_plane) = control_plane else {
            return Ok(admin_code_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin.control_unavailable",
                &method,
            ));
        };
        return Ok(dispatch_admin_mutation(request, principal, control_plane, request_id).await);
    }
    let response = match request.uri().path() {
        "/health/live" => admin_response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"live\n"),
            &method,
        ),
        "/health/ready" => {
            let ready = store.published().ready();
            admin_response(
                if ready {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                "text/plain; charset=utf-8",
                Bytes::from_static(if ready { b"ready\n" } else { b"not ready\n" }),
                &method,
            )
        }
        "/metrics" => {
            let mut text = metrics.render_prometheus_for(&store.pin());
            if let Some(audit) = control_plane
                .as_ref()
                .and_then(|control| control.audit.as_ref())
            {
                text.push_str(&format!("oxidase_admin_audit_dropped_total {}\noxidase_admin_audit_failed_total {}\noxidase_admin_audit_delivered_total {}\noxidase_admin_audit_healthy {}\n", audit.dropped(), audit.failed(), audit.delivered(), u8::from(audit.is_healthy())));
            }
            admin_response(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                Bytes::from(text),
                &method,
            )
        }
        "/api/v1/clusters" => cluster_admin_response(&snapshot, &method),
        "/api/v1/resources" => admin_response(
            StatusCode::OK,
            "application/json",
            Bytes::from(
                serde_json::to_vec(&snapshot.resource_census().sample())
                    .expect("fixed scalar resource sample serializes"),
            ),
            &method,
        ),
        "/api/v1/runtime" | "/api/v1/snapshots/current" => {
            current_runtime_admin_response(&published, &method)
        }
        "/api/v1/snapshots" => snapshot_list_admin_response(
            &published,
            control_plane.as_ref().map(|control| &control.candidates),
            &method,
        ),
        path if path.starts_with("/api/v1/operations/") => {
            let receipt = control_plane.as_ref().and_then(|control| {
                control
                    .candidates
                    .operation(path.trim_start_matches("/api/v1/operations/"))
            });
            match receipt {
                Some(receipt) => operation_receipt_response(&receipt, &published, false, &method),
                None => {
                    admin_code_response(StatusCode::NOT_FOUND, "admin.operation_not_found", &method)
                }
            }
        }
        _ => admin_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Not Found"),
            &method,
        ),
    };
    Ok(response)
}

struct AdminCancellationGuard(CandidateWorkControl);

impl Drop for AdminCancellationGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct AdminTaskGuard {
    store: Arc<CandidateStore>,
    observed_id: Arc<Mutex<Option<String>>>,
    work: CandidateWorkControl,
    audit: SharedOperationAudit,
    published: Arc<SnapshotStore>,
}

impl Drop for AdminTaskGuard {
    fn drop(&mut self) {
        self.work.cancel();
        let id = self
            .observed_id
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(id) = id else {
            return;
        };
        let Some(receipt) = self.store.operation(&id) else {
            return;
        };
        // After intent, only the manager can decide publication and completion.
        if receipt.phase.is_finished() || receipt.commit_intent {
            return;
        }
        let store = Arc::clone(&self.store);
        let audit = Arc::clone(&self.audit);
        let published = Arc::clone(&self.published);
        tokio::spawn(async move {
            let worker = Arc::clone(&store);
            let receipt = tokio::task::spawn_blocking(move || {
                worker
                    .finish_cancelled(&id, "candidate.cancelled")
                    .unwrap_or_else(|error| {
                        worker.force_uncommitted_recovery_receipt(&id, error.code())
                    })
            })
            .await
            .ok();
            finish_operation_audit(&audit, &store, receipt, &published.published()).await;
        });
    }
}

async fn dispatch_admin_mutation(
    request: Request<Incoming>,
    principal: crate::admin::AdminPrincipal,
    control: AdminControlPlane,
    request_id: String,
) -> Response<GatewayBody> {
    let method = request.method().clone();
    let Ok(admission) = Arc::clone(&control.mutation_gate).try_acquire_owned() else {
        if let Some(audit) = &control.audit {
            let mut event = AdminAuditEvent::new(
                &request_id,
                principal.authentication_kind(),
                principal.audit_id(),
                "unknown",
            );
            event.result = "rejected".to_owned();
            event.diagnostic_code = Some("admin.mutation_busy".to_owned());
            audit.try_record(event);
        }
        return admin_code_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin.mutation_busy",
            &method,
        );
    };
    let deadline = std::time::Instant::now() + ADMIN_MUTATION_TIMEOUT;
    let work = CandidateWorkControl::with_deadline(deadline);
    let guard = AdminCancellationGuard(work.clone());
    let operation_id = Arc::new(Mutex::new(None::<String>));
    let observed_operation = Arc::clone(&operation_id);
    let published = control.reload.published_runtime();
    let (response, received) = oneshot::channel();
    let tasks = Arc::clone(&control.operation_tasks);
    {
        let mut tasks = tasks.lock().await;
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let _admission = admission;
            let path = request.uri().path();
            let action = if path == "/api/v1/candidates" {
                "stage"
            } else if path.ends_with("/validate") {
                "validate"
            } else if path.ends_with("/activate") {
                "activate"
            } else if path.ends_with("/rollback") {
                "rollback"
            } else if path.ends_with("/drain") {
                "drain"
            } else {
                "reload_source"
            };
            let mut event = AdminAuditEvent::new(
                &request_id,
                principal.authentication_kind(),
                principal.audit_id(),
                action,
            );
            event.previous_revision = Some(published.runtime_revision.to_string());
            let audit_permit = if let Some(sink) = &control.audit {
                match tokio::time::timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    sink.prepare_mutation(event.clone()),
                )
                .await
                {
                    Ok(Ok(permit)) => Some((permit, event.clone(), sink.clone())),
                    Ok(Err(error)) => {
                        let _ = response.send(admin_code_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            error.code(),
                            request.method(),
                        ));
                        return;
                    }
                    Err(_) => {
                        let _ = response.send(admin_code_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "admin.audit_deadline",
                            request.method(),
                        ));
                        return;
                    }
                }
            } else {
                None
            };
            let audit = Arc::new(Mutex::new(audit_permit));
            let _bookkeeping = AdminTaskGuard {
                store: Arc::clone(&control.candidates),
                observed_id: Arc::clone(&operation_id),
                work: work.clone(),
                audit: Arc::clone(&audit),
                published: Arc::clone(&control.reload.store),
            };
            let method = request.method().clone();
            let managed = ManagedAdminOperation {
                context: oxidase_runtime::CandidateOperationContext {
                    request_id,
                    principal: format!(
                        "{}:{}",
                        principal.authentication_kind(),
                        principal.audit_id()
                    ),
                    if_match: request
                        .headers()
                        .get(header::IF_MATCH)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    idempotency_key: request
                        .headers()
                        .get("idempotency-key")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                },
                work,
                deadline,
                observed_id: Arc::clone(&operation_id),
                audit: Arc::clone(&audit),
            };
            let mut result = handle_admin_mutation(request, control.clone(), managed).await;
            let id = operation_id
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let receipt = id
                .as_deref()
                .and_then(|id| control.candidates.operation(id));
            if let Some((_, event, _)) = audit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                event.result = if result
                    .extensions()
                    .get::<AdminReplay>()
                    .is_some_and(|replay| replay.0)
                {
                    "replayed"
                } else if result.status().is_success() {
                    "committed"
                } else {
                    "failed"
                }
                .to_owned();
                event.diagnostic_code = result
                    .extensions()
                    .get::<AdminResponseCode>()
                    .map(|code| code.0.to_owned());
            }
            if let Some(receipt) = finish_operation_audit(
                &audit,
                &control.candidates,
                receipt,
                &control.reload.published_runtime(),
            )
            .await
                && receipt.phase == oxidase_runtime::OperationPhase::RecoveryRequired
            {
                result = operation_receipt_response(
                    &receipt,
                    &control.reload.published_runtime(),
                    false,
                    &method,
                );
            }
            let _ = response.send(result);
        });
    }
    let result = match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), received)
        .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => admin_code_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin.operation_worker",
            &method,
        ),
        Err(_) => {
            let id = observed_operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            admin_json_value_response(
                if id.is_some() {
                    StatusCode::ACCEPTED
                } else {
                    StatusCode::REQUEST_TIMEOUT
                },
                &serde_json::json!({"schema_version":"oxidase.admin/v1","code":"admin.operation_deadline","operation_id":id}),
                &method,
            )
        }
    };
    drop(guard);
    result
}

async fn handle_admin_mutation(
    request: Request<Incoming>,
    control: AdminControlPlane,
    managed: ManagedAdminOperation,
) -> Response<GatewayBody> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let deadline = managed.deadline;
    if managed.context.idempotency_key.is_none()
        && managed.context.if_match.as_deref()
            != Some(control.reload.published_runtime().etag().as_str())
    {
        return admin_code_response(
            StatusCode::PRECONDITION_FAILED,
            "admin.precondition_failed",
            &method,
        );
    }
    if path == "/api/v1/candidates" {
        stage_admin_candidate(request.into_body(), &control, &managed, &method).await
    } else if let Some(digest) = admin_action_digest(&path, "/api/v1/candidates/", "validate") {
        if let Err(error) = consume_admin_json_body(request.into_body(), deadline).await {
            admin_code_response(error.status, error.code, &method)
        } else {
            validate_admin_candidate(digest, &control, &managed, &method).await
        }
    } else if let Some(digest) = admin_action_digest(&path, "/api/v1/candidates/", "activate") {
        if let Err(error) = consume_admin_json_body(request.into_body(), deadline).await {
            admin_code_response(error.status, error.code, &method)
        } else {
            activate_admin_candidate(digest, &control, &managed, false, &method).await
        }
    } else if let Some(digest) = admin_action_digest(&path, "/api/v1/snapshots/", "rollback") {
        if let Err(error) = consume_admin_json_body(request.into_body(), deadline).await {
            admin_code_response(error.status, error.code, &method)
        } else {
            activate_admin_candidate(digest, &control, &managed, true, &method).await
        }
    } else if path == "/api/v1/drain" {
        if let Err(error) = consume_admin_json_body(request.into_body(), deadline).await {
            admin_code_response(error.status, error.code, &method)
        } else {
            execute_runtime_action(
                &control,
                &managed,
                oxidase_runtime::AuditAction::Drain,
                &method,
            )
            .await
        }
    } else if path == "/api/v1/reload-source" {
        if let Err(error) = consume_admin_json_body(request.into_body(), deadline).await {
            admin_code_response(error.status, error.code, &method)
        } else {
            execute_runtime_action(
                &control,
                &managed,
                oxidase_runtime::AuditAction::ReloadSource,
                &method,
            )
            .await
        }
    } else {
        admin_code_response(
            StatusCode::NOT_IMPLEMENTED,
            "admin.bundle_activation_unavailable",
            &method,
        )
    }
}

async fn execute_runtime_action(
    control: &AdminControlPlane,
    managed: &ManagedAdminOperation,
    action: oxidase_runtime::AuditAction,
    method: &Method,
) -> Response<GatewayBody> {
    let begin = match begin_managed_operation(
        control,
        managed,
        action,
        None,
        Some(oxidase_bundle::BundleDigest::of_bytes(b"{}")),
    )
    .await
    {
        Ok(begin) => begin,
        Err(error) => return admin_candidate_error_response(&error, method),
    };
    if begin.replayed || begin.receipt.phase.is_finished() {
        return operation_receipt_response(
            &begin.receipt,
            &control.reload.published_runtime(),
            begin.replayed,
            method,
        );
    }
    let id = begin.receipt.operation_id;
    let operation = CommitOperation {
        store: Arc::clone(&control.candidates),
        operation_id: id.clone(),
        work: managed.work.clone(),
        audit: Arc::clone(&managed.audit),
    };
    let expected = managed.context.if_match.clone().unwrap_or_default();
    let result = if action == oxidase_runtime::AuditAction::Drain {
        control
            .reload
            .drain_operation(expected, Some(operation), managed.deadline)
            .await
    } else if let Some(source) = control.reload.published_runtime().source_origin.clone() {
        control
            .reload
            .reload_path_with_operation(
                &source,
                false,
                Some(expected),
                Some(operation),
                managed.deadline,
            )
            .await
            .map(|_| ())
    } else {
        Err(ServerError::AdminStore("admin.source_unavailable"))
    };
    let diagnostics = result
        .as_ref()
        .err()
        .map(ServerError::diagnostics)
        .unwrap_or_default();
    if let Err(error) = result
        && control
            .candidates
            .operation(&id)
            .is_some_and(|receipt| !receipt.phase.is_finished())
    {
        let code = error
            .diagnostics()
            .first()
            .map_or("admin.operation_failed", |diagnostic| diagnostic.code);
        let _ = finish_operation_error(
            control,
            id.clone(),
            oxidase_runtime::CandidateStoreError::new(code, "runtime operation failed"),
        )
        .await;
    }
    match control.candidates.operation(&id) {
        Some(receipt) => operation_receipt_diagnostics_response(
            &receipt,
            &control.reload.published_runtime(),
            false,
            &diagnostics,
            method,
        ),
        None => admin_code_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin.receipt_missing",
            method,
        ),
    }
}

fn admin_action_digest(
    path: &str,
    prefix: &str,
    action: &str,
) -> Option<oxidase_bundle::BundleDigest> {
    let rest = path.strip_prefix(prefix)?;
    let (digest, actual_action) = rest.split_once('/')?;
    if actual_action != action {
        return None;
    }
    serde_json::from_value(serde_json::Value::String(digest.to_owned())).ok()
}

async fn consume_admin_json_body(
    mut body: Incoming,
    deadline: std::time::Instant,
) -> Result<(), AdminUploadError> {
    const MAX_JSON_BODY_BYTES: u64 = 64 * 1024;
    let mut received = 0_u64;
    let mut bytes = Vec::new();
    let receive = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| AdminUploadError {
                status: StatusCode::BAD_REQUEST,
                code: "admin.request_body",
            })?;
            if let Some(data) = frame.data_ref() {
                received = received
                    .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
                    .ok_or(AdminUploadError {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        code: "admin.payload_too_large",
                    })?;
                if received > MAX_JSON_BODY_BYTES {
                    return Err(AdminUploadError {
                        status: StatusCode::PAYLOAD_TOO_LARGE,
                        code: "admin.payload_too_large",
                    });
                }
                bytes.extend_from_slice(data);
            } else if frame.trailers_ref().is_some() {
                return Err(AdminUploadError {
                    status: StatusCode::BAD_REQUEST,
                    code: "admin.request_trailers",
                });
            }
        }
        Ok::<(), AdminUploadError>(())
    };
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), receive)
        .await
        .map_err(|_| AdminUploadError {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "admin.request_timeout",
        })??;
    if bytes.is_empty() {
        return Ok(());
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| AdminUploadError {
            status: StatusCode::BAD_REQUEST,
            code: "admin.invalid_json",
        })?;
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        Ok(())
    } else {
        Err(AdminUploadError {
            status: StatusCode::BAD_REQUEST,
            code: "admin.unexpected_body",
        })
    }
}

async fn validate_admin_candidate(
    digest: oxidase_bundle::BundleDigest,
    control: &AdminControlPlane,
    managed: &ManagedAdminOperation,
    method: &Method,
) -> Response<GatewayBody> {
    let begin = match begin_managed_operation(
        control,
        managed,
        oxidase_runtime::AuditAction::Validate,
        Some(digest),
        None,
    )
    .await
    {
        Ok(begin) => begin,
        Err(error) => return admin_candidate_error_response(&error, method),
    };
    if begin.replayed || begin.receipt.phase.is_finished() {
        return operation_receipt_response(
            &begin.receipt,
            &control.reload.published_runtime(),
            begin.replayed,
            method,
        );
    }
    let id = begin.receipt.operation_id;
    let bundle_path = control.candidates.candidate_path(digest);
    let deployment_root = control.deployment_root.clone();
    let previous = control.reload.current_snapshot();
    let work = managed.work.clone();
    let result = async {
        work.checkpoint()?;
        if managed.context.if_match.as_deref()
            != Some(control.reload.published_runtime().etag().as_str())
        {
            return Err(oxidase_runtime::CandidateStoreError::new(
                "candidate.precondition",
                "current runtime condition is stale",
            ));
        }
        let store = Arc::clone(&control.candidates);
        let preparing_id = id.clone();
        tokio::task::spawn_blocking(move || store.mark_preparing(&preparing_id))
            .await
            .map_err(|_| {
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.validation_worker",
                    "preparation journal worker failed",
                )
            })??;
        let permit = Arc::clone(&control.reload.compile_gate)
            .try_acquire_owned()
            .map_err(|_| {
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.busy",
                    "preparation worker is occupied",
                )
            })?;
        let (archive, permit) = control
            .candidates
            .verified_archive_admitted(digest, work.clone(), permit)
            .await?;
        let checked_work = work.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            checked_work.checkpoint()?;
            let prepared = oxidase_runtime::prepare_bundle_archive_controlled(
                &archive,
                &bundle_path,
                &deployment_root,
                Some(&previous),
                &checked_work,
            )
            .map_err(candidate_preparation_error)?;
            crate::validate_discovery_bootstrap(&prepared.snapshot).map_err(|diagnostics| {
                oxidase_runtime::CandidateStoreError::new(
                    "discovery.resolver_prepare",
                    "cannot prepare the local DNS resolver inputs",
                )
                .with_diagnostics(diagnostics)
            })?;
            checked_work.checkpoint()
        })
        .await
        .map_err(|_| {
            oxidase_runtime::CandidateStoreError::new(
                "candidate.validation_worker",
                "validation worker failed",
            )
        })??;
        let store = Arc::clone(&control.candidates);
        let completion_id = id.clone();
        tokio::task::spawn_blocking(move || store.complete_validation(&completion_id, digest))
            .await
            .map_err(|_| {
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.validation_worker",
                    "validation completion worker failed",
                )
            })??;
        Ok::<_, oxidase_runtime::CandidateStoreError>(())
    }
    .await;
    let diagnostics = result
        .as_ref()
        .err()
        .map(|error| error.diagnostics().to_vec())
        .unwrap_or_default();
    if let Err(error) = result {
        let _ = finish_operation_error(control, id.clone(), error).await;
    }
    match control.candidates.operation(&id) {
        Some(receipt) => operation_receipt_diagnostics_response(
            &receipt,
            &control.reload.published_runtime(),
            false,
            &diagnostics,
            method,
        ),
        None => admin_code_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin.receipt_missing",
            method,
        ),
    }
}

async fn activate_admin_candidate(
    digest: oxidase_bundle::BundleDigest,
    control: &AdminControlPlane,
    managed: &ManagedAdminOperation,
    rollback: bool,
    method: &Method,
) -> Response<GatewayBody> {
    let begin = match begin_managed_operation(
        control,
        managed,
        if rollback {
            oxidase_runtime::AuditAction::Rollback
        } else {
            oxidase_runtime::AuditAction::Activate
        },
        Some(digest),
        None,
    )
    .await
    {
        Ok(begin) => begin,
        Err(error) => return admin_candidate_error_response(&error, method),
    };
    if begin.replayed || begin.receipt.phase.is_finished() {
        return operation_receipt_response(
            &begin.receipt,
            &control.reload.published_runtime(),
            begin.replayed,
            method,
        );
    }
    let id = begin.receipt.operation_id;
    let bundle_path = control.candidates.candidate_path(digest);
    let deployment_root = control.deployment_root.clone();
    let reload = control.reload.clone();
    let expected_version = managed.context.if_match.clone().unwrap_or_default();
    let work = managed.work.clone();
    let result = async {
        work.checkpoint()?;
        control
            .candidates
            .ensure_candidate_activatable(digest, rollback)?;
        let previous = reload.current_snapshot();
        if reload.published_runtime().etag() != expected_version {
            return Err(oxidase_runtime::CandidateStoreError::new(
                "candidate.precondition",
                "current snapshot changed before candidate preparation",
            ));
        }
        let store = Arc::clone(&control.candidates);
        let preparing_id = id.clone();
        tokio::task::spawn_blocking(move || store.mark_preparing(&preparing_id))
            .await
            .map_err(|_| {
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.activation_worker",
                    "preparation journal worker failed",
                )
            })??;
        let permit = Arc::clone(&reload.compile_gate)
            .try_acquire_owned()
            .map_err(|_| {
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.busy",
                    "preparation worker is occupied",
                )
            })?;
        let (archive, permit) = control
            .candidates
            .verified_archive_admitted(digest, work.clone(), permit)
            .await?;
        let checked_work = work.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            checked_work.checkpoint()?;
            oxidase_runtime::prepare_bundle_archive_controlled(
                &archive,
                &bundle_path,
                &deployment_root,
                Some(&previous),
                &checked_work,
            )
            .map_err(candidate_preparation_error)
        })
        .await
        .map_err(|error| {
            oxidase_runtime::CandidateStoreError::new(
                "candidate.activation_worker",
                format!("candidate activation worker failed: {error}"),
            )
        })??;
        work.checkpoint()?;
        let operation = CommitOperation {
            store: Arc::clone(&control.candidates),
            operation_id: id.clone(),
            work: work.clone(),
            audit: Arc::clone(&managed.audit),
        };
        let report = reload
            .publish_prepared(
                prepared.snapshot,
                prepared.reuse,
                expected_version,
                RuntimeOrigin::Bundle {
                    digest: digest.into(),
                },
                Some(operation),
                managed.deadline,
            )
            .await
            .map_err(|error| {
                let diagnostics = error.diagnostics();
                oxidase_runtime::CandidateStoreError::new(
                    diagnostics
                        .first()
                        .map_or("candidate.activation", |diagnostic| diagnostic.code),
                    "candidate publication failed",
                )
                .with_diagnostics(diagnostics)
            })?;
        Ok(report.current_version)
    }
    .await;
    let diagnostics = result
        .as_ref()
        .err()
        .map(|error| error.diagnostics().to_vec())
        .unwrap_or_default();
    if let Err(error) = result
        && control
            .candidates
            .operation(&id)
            .is_some_and(|receipt| !receipt.phase.is_finished())
    {
        let _ = finish_operation_error(control, id.clone(), error).await;
    }
    match control.candidates.operation(&id) {
        Some(receipt) => operation_receipt_diagnostics_response(
            &receipt,
            &control.reload.published_runtime(),
            false,
            &diagnostics,
            method,
        ),
        None => admin_code_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "admin.receipt_missing",
            method,
        ),
    }
}

async fn stage_admin_candidate(
    body: Incoming,
    control: &AdminControlPlane,
    managed: &ManagedAdminOperation,
    method: &Method,
) -> Response<GatewayBody> {
    let spool = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(managed.deadline),
        spool_admin_upload(
            body,
            Arc::clone(&control.candidates),
            control.max_candidate_bytes,
            managed.work.clone(),
            managed.deadline,
        ),
    )
    .await
    {
        Ok(Ok(spool)) => spool,
        Ok(Err(error)) => return admin_code_response(error.status, error.code, method),
        Err(_) => {
            return admin_code_response(
                StatusCode::REQUEST_TIMEOUT,
                "admin.request_timeout",
                method,
            );
        }
    };
    let begin = match begin_managed_operation(
        control,
        managed,
        oxidase_runtime::AuditAction::Stage,
        None,
        Some(spool.body_digest),
    )
    .await
    {
        Ok(begin) => begin,
        Err(error) => return admin_candidate_error_response(&error, method),
    };
    if begin.replayed || begin.receipt.phase.is_finished() {
        return operation_receipt_response(
            &begin.receipt,
            &control.reload.published_runtime(),
            begin.replayed,
            method,
        );
    }
    let id = begin.receipt.operation_id;
    let permit = match Arc::clone(&control.reload.compile_gate).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            if let Some(receipt) = finish_operation_error(
                control,
                id,
                oxidase_runtime::CandidateStoreError::new(
                    "candidate.busy",
                    "preparation worker is occupied",
                ),
            )
            .await
            {
                return operation_receipt_response(
                    &receipt,
                    &control.reload.published_runtime(),
                    false,
                    method,
                );
            }
            return admin_code_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "admin.preparation_busy",
                method,
            );
        }
    };
    let outcome = control
        .candidates
        .stage_spool_for_operation(
            spool.file,
            managed.context.clone(),
            managed.work.clone(),
            id.clone(),
            Some(permit),
        )
        .await;
    // The detached operation cannot relinquish shared preparation admission
    // while the blocking staging worker still owns its spool and work permit.
    match outcome {
        Ok(outcome) => {
            let store = Arc::clone(&control.candidates);
            let completion_id = id.clone();
            let digest = outcome.candidate.digest;
            match tokio::task::spawn_blocking(move || store.finish_staged(&completion_id, digest))
                .await
            {
                Ok(Ok(receipt)) => operation_receipt_response(
                    &receipt,
                    &control.reload.published_runtime(),
                    false,
                    method,
                ),
                _ => {
                    let published = control.reload.published_runtime();
                    let worker = Arc::clone(&control.candidates);
                    let receipt = tokio::task::spawn_blocking(move || {
                        worker.force_uncommitted_recovery_receipt(&id, "admin.stage_record_failed")
                    })
                    .await
                    .expect("recovery marker worker");
                    operation_receipt_response(&receipt, &published, false, method)
                }
            }
        }
        Err(error) => match finish_operation_error(control, id, error.clone()).await {
            Some(receipt) => operation_receipt_response(
                &receipt,
                &control.reload.published_runtime(),
                false,
                method,
            ),
            None => admin_candidate_error_response(&error, method),
        },
    }
}

struct AdminUploadError {
    status: StatusCode,
    code: &'static str,
}

struct AdminUploadSpool {
    file: tempfile::NamedTempFile,
    body_digest: oxidase_bundle::BundleDigest,
}

async fn spool_admin_upload(
    mut body: Incoming,
    store: Arc<CandidateStore>,
    max_bytes: u64,
    work: CandidateWorkControl,
    deadline: std::time::Instant,
) -> Result<AdminUploadSpool, AdminUploadError> {
    let worker_store = Arc::clone(&store);
    let temporary = tokio::task::spawn_blocking(move || worker_store.create_upload_spool())
        .await
        .map_err(|_| AdminUploadError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "admin.upload_worker",
        })?
        .map_err(|_| AdminUploadError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "admin.upload_io",
        })?;
    let file = temporary
        .as_file()
        .try_clone()
        .map_err(|_| AdminUploadError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "admin.upload_io",
        })?;
    let mut file = tokio::fs::File::from_std(file);
    let mut received = 0_u64;
    let mut hasher = oxidase_core::ContentHasher::new();
    while let Some(frame) =
        tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), body.frame())
            .await
            .map_err(|_| AdminUploadError {
                status: StatusCode::REQUEST_TIMEOUT,
                code: "admin.request_timeout",
            })?
    {
        work.checkpoint().map_err(|_| AdminUploadError {
            status: StatusCode::REQUEST_TIMEOUT,
            code: "admin.operation_cancelled",
        })?;
        let frame = frame.map_err(|_| AdminUploadError {
            status: StatusCode::BAD_REQUEST,
            code: "admin.request_body",
        })?;
        if let Some(data) = frame.data_ref() {
            received = received
                .checked_add(u64::try_from(data.len()).unwrap_or(u64::MAX))
                .ok_or(AdminUploadError {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    code: "admin.payload_too_large",
                })?;
            if received > max_bytes {
                return Err(AdminUploadError {
                    status: StatusCode::PAYLOAD_TOO_LARGE,
                    code: "admin.payload_too_large",
                });
            }
            let worker_store = Arc::clone(&store);
            tokio::task::spawn_blocking(move || worker_store.reserve_upload_capacity(received))
                .await
                .map_err(|_| AdminUploadError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "admin.upload_worker",
                })?
                .map_err(|_| AdminUploadError {
                    status: StatusCode::INSUFFICIENT_STORAGE,
                    code: "admin.upload_capacity",
                })?;
            hasher.update(data);
            file.write_all(data).await.map_err(|_| AdminUploadError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "admin.upload_io",
            })?;
        } else if frame.trailers_ref().is_some() {
            return Err(AdminUploadError {
                status: StatusCode::BAD_REQUEST,
                code: "admin.request_trailers",
            });
        }
    }
    file.flush().await.map_err(|_| AdminUploadError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "admin.upload_io",
    })?;
    file.sync_all().await.map_err(|_| AdminUploadError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "admin.upload_io",
    })?;
    drop(file);
    Ok(AdminUploadSpool {
        file: temporary,
        body_digest: hasher.finish().into(),
    })
}

fn admin_candidate_error_response(
    error: &oxidase_runtime::CandidateStoreError,
    method: &Method,
) -> Response<GatewayBody> {
    let status = match error.code() {
        "candidate.not_found" => StatusCode::NOT_FOUND,
        "candidate.precondition" => StatusCode::PRECONDITION_FAILED,
        "candidate.capacity" => StatusCode::SERVICE_UNAVAILABLE,
        "candidate.limit" => StatusCode::PAYLOAD_TOO_LARGE,
        "candidate.idempotency_conflict" => StatusCode::CONFLICT,
        code if code.starts_with("bundle.") => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    tracing::warn!(code = error.code(), "admin candidate operation failed");
    admin_code_response(status, error.code(), method)
}

fn admin_code_response(
    status: StatusCode,
    code: &'static str,
    method: &Method,
) -> Response<GatewayBody> {
    let mut response = admin_json_value_response(
        status,
        &serde_json::json!({
            "schema_version": "oxidase.admin/v1",
            "code": code,
            "diagnostics": [{"code":code,"severity":"error","message":"administration operation rejected","primary":null,"labels":[],"notes":[],"help":null,"reference_chain":[]}]
        }),
        method,
    );
    response.extensions_mut().insert(AdminResponseCode(code));
    response
}

#[derive(Clone, Copy)]
struct AdminResponseCode(&'static str);

fn admin_json_value_response(
    status: StatusCode,
    value: &serde_json::Value,
    method: &Method,
) -> Response<GatewayBody> {
    let mut envelope = value.clone();
    if let Some(object) = envelope.as_object_mut()
        && object.get("code").is_some_and(|code| !code.is_null())
        && !object.contains_key("diagnostics")
    {
        object.insert("diagnostics".to_owned(), serde_json::json!([{"code":object["code"],"severity":"error","message":"administration operation rejected","primary":null,"labels":[],"related":[],"notes":[],"help":null,"reference_chain":[]}]));
    }
    match serde_json::to_vec(&envelope) {
        Ok(body) => admin_response(
            status,
            "application/json; charset=utf-8",
            Bytes::from(body),
            method,
        ),
        Err(_) => admin_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json; charset=utf-8",
            Bytes::from_static(b"{\"code\":\"admin.serialization_failed\"}\n"),
            method,
        ),
    }
}

fn admin_security_response(
    error: crate::admin::AdminSecurityError,
    method: &Method,
) -> Response<GatewayBody> {
    let mut response = admin_code_response(error.status(), error.code(), method);
    if error.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"oxidase-admin\""),
        );
    }
    response
}

#[derive(Serialize)]
struct RuntimeAdminResponse<'a> {
    schema_version: &'static str,
    config_version: &'a str,
    runtime_revision: u64,
    etag: String,
    origin: &'a RuntimeOrigin,
    serving_state: ServingState,
    bundle_digest: Option<String>,
    listener_count: usize,
    cluster_count: usize,
    site_count: usize,
}

fn current_runtime_admin_response(
    published: &PublishedRuntime,
    method: &Method,
) -> Response<GatewayBody> {
    let snapshot = &published.snapshot;
    let response = RuntimeAdminResponse {
        schema_version: "oxidase.admin/v1",
        config_version: snapshot.config_version.as_str(),
        runtime_revision: published.runtime_revision,
        etag: published.etag(),
        origin: &published.origin,
        serving_state: published.serving_state,
        bundle_digest: published.bundle_digest().map(|digest| digest.to_string()),
        listener_count: snapshot.listeners.len(),
        cluster_count: snapshot.resources.clusters.len(),
        site_count: snapshot.resources.sites.len(),
    };
    let mut response = json_admin_response(&response, method);
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&published.etag()).expect("runtime ETag is ASCII"),
    );
    response
}

fn snapshot_list_admin_response(
    published: &PublishedRuntime,
    candidates: Option<&Arc<CandidateStore>>,
    method: &Method,
) -> Response<GatewayBody> {
    let history = candidates.map_or_else(Vec::new, |store| store.history());
    let digest = published.bundle_digest().map(|digest| digest.to_string());
    let rollbackable = digest.as_ref().is_some_and(|digest| {
        history
            .iter()
            .any(|record| record.digest.to_string() == *digest)
    });
    admin_json_value_response(
        StatusCode::OK,
        &serde_json::json!({
            "schema_version":"oxidase.admin/v1", "current":{
                "config_version":published.snapshot.config_version.as_str(),
                "runtime_revision":published.runtime_revision, "etag":published.etag(),
                "origin":published.origin, "bundle_digest":digest,
                "serving_state":published.serving_state, "rollbackable":rollbackable
            }, "history":history
        }),
        method,
    )
}

fn json_admin_response(value: &impl Serialize, method: &Method) -> Response<GatewayBody> {
    match serde_json::to_vec(value) {
        Ok(body) => admin_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            Bytes::from(body),
            method,
        ),
        Err(_) => admin_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json; charset=utf-8",
            Bytes::from_static(b"{\"error\":{\"code\":\"admin.serialization_failed\"}}\n"),
            method,
        ),
    }
}

#[derive(Serialize)]
struct ClusterAdminResponse {
    clusters: Vec<ClusterRuntimeStatus>,
}

fn cluster_admin_response(snapshot: &RuntimeSnapshot, method: &Method) -> Response<GatewayBody> {
    let now = std::time::Instant::now();
    let mut clusters = snapshot
        .resources
        .clusters
        .values()
        .map(|cluster| cluster.observed_status(now))
        .collect::<Vec<_>>();
    clusters.sort_by(|left, right| left.cluster.cmp(&right.cluster));
    for cluster in &mut clusters {
        cluster
            .endpoints
            .sort_by(|left, right| left.name.cmp(&right.name));
    }
    match serde_json::to_vec(&ClusterAdminResponse { clusters }) {
        Ok(body) => admin_response(
            StatusCode::OK,
            "application/json; charset=utf-8",
            Bytes::from(body),
            method,
        ),
        Err(_) => admin_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json; charset=utf-8",
            Bytes::from_static(b"{\"error\":\"serialization_failed\"}\n"),
            method,
        ),
    }
}

fn admin_response(
    status: StatusCode,
    content_type: &'static str,
    body: Bytes,
    method: &Method,
) -> Response<GatewayBody> {
    let mut response = oxidase_core::ResponseHead::new(status, GatewayBodyPlan::Bytes(body));
    response
        .headers
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    ResponseFinalizer::new(method).finalize(response)
}

async fn run_listener(
    listener: BoundListener,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
    accept_stopped: oneshot::Sender<()>,
) -> Result<(), ServerError> {
    let mut connections = JoinSet::new();
    let mut accept_error = None;
    let transport_metrics = metrics.listener_transport(&listener.name);
    let tls_handshake_gate = Arc::new(Semaphore::new(MAX_CONCURRENT_TLS_HANDSHAKES_PER_LISTENER));
    let ingress = ListenerIngressState::default();
    loop {
        reap_finished_connections(&mut connections, "data-plane");
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.listener.accept() => {
                let (stream, peer_address) = match accepted {
                    Ok(accepted) => accepted,
                    Err(source) => {
                        accept_error = Some(ServerError::Accept {
                            listener: listener.name.clone(),
                            source_span: Box::new(listener.source_span.clone()),
                            source,
                        });
                        break;
                    }
                };
                let plan = store
                    .pin()
                    .prepared_listener_for(&listener.name)
                    .cloned();
                let Some(plan) = plan else {
                    accept_error = Some(ServerError::Task(format!(
                        "listener `{}` has no prepared transport plan",
                        listener.name
                    )));
                    break;
                };
                let connection_admission = match ingress.try_admit(peer_address, &plan.limits) {
                    Ok(admission) => admission,
                    Err(reason) => {
                        tracing::debug!(
                            listener = listener.name,
                            reason = ?reason,
                            "listener connection admission rejected"
                        );
                        drop(stream);
                        continue;
                    }
                };
                let tls_handshake_permit = match reserve_tls_handshake(
                    plan.protocol,
                    &tls_handshake_gate,
                    &transport_metrics,
                ) {
                    Ok(permit) => permit,
                    Err(()) => {
                        tracing::debug!(
                            listener = listener.name,
                            limit = MAX_CONCURRENT_TLS_HANDSHAKES_PER_LISTENER,
                            "TLS handshake concurrency limit reached"
                        );
                        drop(stream);
                        continue;
                    }
                };
                let listener_name = listener.name.clone();
                let store = store.clone();
                let proxy = proxy.clone();
                let metrics = metrics.clone();
                let connection_shutdown = shutdown.clone();
                let context = GatewayConnectionContext {
                    peer_address,
                    listener_name,
                    store,
                    proxy,
                    metrics,
                    transport_metrics: transport_metrics.clone(),
                    scheme: "http",
                    tls: TlsConnectionMetadata::default(),
                    tunnel_sender: None,
                    limits: plan.limits.clone(),
                    downstream_timeout: DownstreamTimeoutSignal::default(),
                };
                connections.spawn(async move {
                    let _connection_admission = connection_admission;
                    serve_connection(
                        stream,
                        plan,
                        context,
                        connection_shutdown,
                        tls_handshake_permit,
                    )
                    .await;
                });
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(error = %error, "connection task failed");
                }
            }
        }
    }

    let _ = accept_stopped.send(());

    let drained = tokio::time::timeout(drain_timeout, async {
        while let Some(result) = connections.join_next().await {
            if let Err(error) = result {
                tracing::warn!(error = %error, "connection task failed during drain");
            }
        }
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if let Some(error) = accept_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn reap_finished_connections(connections: &mut JoinSet<()>, boundary: &'static str) {
    while let Some(result) = connections.try_join_next() {
        if let Err(error) = result {
            tracing::warn!(error = %error, boundary, "connection task failed");
        }
    }
}

fn reserve_tls_handshake(
    protocol: ListenerProtocol,
    gate: &Arc<Semaphore>,
    metrics: &ListenerTransportMetrics,
) -> Result<Option<OwnedSemaphorePermit>, ()> {
    if protocol == ListenerProtocol::Http {
        return Ok(None);
    }
    gate.clone().try_acquire_owned().map(Some).map_err(|_| {
        metrics.record_tls_handshake(TlsHandshakeOutcome::Overloaded, Duration::ZERO);
    })
}

async fn serve_connection(
    stream: TcpStream,
    plan: PreparedListenerPlan,
    mut context: GatewayConnectionContext,
    mut shutdown: watch::Receiver<bool>,
    tls_handshake_permit: Option<OwnedSemaphorePermit>,
) {
    let listener_name = context.listener_name.clone();
    match plan.protocol {
        ListenerProtocol::Http => {
            let Some(settings) = plan.http.http1.clone() else {
                tracing::error!(
                    listener = listener_name,
                    "HTTP listener has no HTTP/1 settings"
                );
                return;
            };
            let idle_timeout = context.limits.idle_timeout;
            let response_body_idle_timeout = context.limits.response_body_idle_timeout;
            let downstream_timeout = context.downstream_timeout.clone();
            serve_http1_connection(
                IdleIo::with_timeout_signal(
                    stream,
                    idle_timeout,
                    response_body_idle_timeout,
                    downstream_timeout,
                ),
                context,
                settings,
                shutdown,
            )
            .await;
        }
        ListenerProtocol::Https => {
            let Some(tls_handshake_permit) = tls_handshake_permit else {
                tracing::error!(
                    listener = listener_name,
                    "HTTPS connection has no handshake permit"
                );
                return;
            };
            let Some(tls) = plan.tls.clone() else {
                tracing::error!(listener = listener_name, "HTTPS listener has no TLS plan");
                return;
            };
            let handshake_started = std::time::Instant::now();
            let acceptor = TlsAcceptor::from(tls.server_config.clone());
            let tls_stream = tokio::select! {
                result = tokio::time::timeout(tls.handshake_timeout, acceptor.accept(stream)) => {
                    match result {
                        Ok(Ok(stream)) => {
                            stream
                        }
                        Ok(Err(error)) => {
                            let outcome = tls_accept_error_outcome(
                                &error,
                                http_versions_require_h2_alpn(&plan.http.versions),
                            );
                            context.transport_metrics.record_tls_handshake(
                                outcome,
                                handshake_started.elapsed(),
                            );
                            tracing::debug!(listener = listener_name, error = %error, "TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            context.transport_metrics.record_tls_handshake(
                                TlsHandshakeOutcome::Timeout,
                                handshake_started.elapsed(),
                            );
                            tracing::debug!(listener = listener_name, "TLS handshake timed out");
                            return;
                        }
                    }
                }
                () = wait_for_shutdown(&mut shutdown) => {
                    context.transport_metrics.record_tls_handshake(
                        TlsHandshakeOutcome::Failure,
                        handshake_started.elapsed(),
                    );
                    return;
                }
            };
            drop(tls_handshake_permit);
            let connection = tls_stream.get_ref().1;
            let client_metadata = match verified_client_metadata(connection.peer_certificates()) {
                Ok(metadata) => metadata,
                Err(error) => {
                    context.transport_metrics.record_tls_handshake(
                        TlsHandshakeOutcome::Protocol,
                        handshake_started.elapsed(),
                    );
                    tracing::debug!(
                        listener = listener_name,
                        error = %error,
                        "verified TLS client metadata could not be represented safely"
                    );
                    return;
                }
            };
            let server_name = connection.server_name().map(str::to_owned);
            let negotiated_alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
            context
                .transport_metrics
                .record_tls_alpn(TlsAlpn::from_negotiated(negotiated_alpn.as_deref()));
            let tls_metadata = TlsConnectionMetadata {
                enabled: true,
                server_name: server_name.clone(),
                alpn: negotiated_alpn
                    .as_deref()
                    .and_then(|protocol| std::str::from_utf8(protocol).ok())
                    .map(str::to_owned),
                version: connection.protocol_version().map(tls_version_name),
                client: client_metadata,
            };
            tracing::debug!(
                listener = listener_name,
                server_name,
                alpn = ?tls_metadata.alpn,
                tls_version = ?tls_metadata.version,
                "TLS handshake completed"
            );
            context.scheme = "https";
            context.tls = tls_metadata;
            let negotiated_protocol =
                match select_https_protocol(&plan.http.versions, negotiated_alpn.as_deref()) {
                    Ok(protocol) => {
                        context.transport_metrics.record_tls_handshake(
                            TlsHandshakeOutcome::Success,
                            handshake_started.elapsed(),
                        );
                        protocol
                    }
                    Err(error) => {
                        context.transport_metrics.record_tls_handshake(
                            error.handshake_outcome(),
                            handshake_started.elapsed(),
                        );
                        tracing::debug!(
                            listener = context.listener_name,
                            alpn = ?negotiated_alpn,
                            result = error.as_str(),
                            "TLS ALPN did not select an enabled HTTP protocol"
                        );
                        return;
                    }
                };
            match negotiated_protocol {
                NegotiatedHttpProtocol::H2 => {
                    let Some(settings) = plan.http.http2.clone() else {
                        tracing::error!(
                            listener = context.listener_name,
                            "H2 listener has no HTTP/2 settings"
                        );
                        return;
                    };
                    let idle_timeout = context.limits.idle_timeout;
                    let response_body_idle_timeout = context.limits.response_body_idle_timeout;
                    let downstream_timeout = context.downstream_timeout.clone();
                    serve_http2_connection(
                        IdleIo::with_timeout_signal(
                            tls_stream,
                            idle_timeout,
                            response_body_idle_timeout,
                            downstream_timeout,
                        ),
                        context,
                        settings,
                        shutdown,
                    )
                    .await;
                }
                NegotiatedHttpProtocol::Http1 => {
                    let Some(settings) = plan.http.http1.clone() else {
                        tracing::error!(
                            listener = context.listener_name,
                            "HTTP/1 listener has no HTTP/1 settings"
                        );
                        return;
                    };
                    let idle_timeout = context.limits.idle_timeout;
                    let response_body_idle_timeout = context.limits.response_body_idle_timeout;
                    let downstream_timeout = context.downstream_timeout.clone();
                    serve_http1_connection(
                        IdleIo::with_timeout_signal(
                            tls_stream,
                            idle_timeout,
                            response_body_idle_timeout,
                            downstream_timeout,
                        ),
                        context,
                        settings,
                        shutdown,
                    )
                    .await;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NegotiatedHttpProtocol {
    Http1,
    H2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlpnSelectionError {
    Required,
    Mismatch,
}

impl AlpnSelectionError {
    const fn handshake_outcome(self) -> TlsHandshakeOutcome {
        match self {
            Self::Required => TlsHandshakeOutcome::AlpnRequired,
            Self::Mismatch => TlsHandshakeOutcome::AlpnMismatch,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "alpn_required",
            Self::Mismatch => "alpn_mismatch",
        }
    }
}

fn select_https_protocol(
    versions: &[HttpVersion],
    negotiated_alpn: Option<&[u8]>,
) -> Result<NegotiatedHttpProtocol, AlpnSelectionError> {
    match negotiated_alpn {
        Some(b"h2") if versions.contains(&HttpVersion::H2) => Ok(NegotiatedHttpProtocol::H2),
        Some(b"http/1.1") if versions.contains(&HttpVersion::Http1) => {
            Ok(NegotiatedHttpProtocol::Http1)
        }
        None if versions.contains(&HttpVersion::Http1) => Ok(NegotiatedHttpProtocol::Http1),
        None => Err(AlpnSelectionError::Required),
        Some(_) => Err(AlpnSelectionError::Mismatch),
    }
}

fn http_versions_require_h2_alpn(versions: &[HttpVersion]) -> bool {
    versions.contains(&HttpVersion::H2) && !versions.contains(&HttpVersion::Http1)
}

fn tls_accept_error_outcome(error: &std::io::Error, h2_alpn_required: bool) -> TlsHandshakeOutcome {
    if h2_alpn_required
        && error
            .get_ref()
            .and_then(|source| source.downcast_ref::<tokio_rustls::rustls::Error>())
            .is_some_and(|error| {
                matches!(error, tokio_rustls::rustls::Error::NoApplicationProtocol)
            })
    {
        TlsHandshakeOutcome::AlpnMismatch
    } else if error.kind() == std::io::ErrorKind::InvalidData {
        TlsHandshakeOutcome::Protocol
    } else {
        TlsHandshakeOutcome::Io
    }
}

#[derive(Clone)]
struct GatewayConnectionContext {
    peer_address: SocketAddr,
    listener_name: String,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    transport_metrics: ListenerTransportMetrics,
    scheme: &'static str,
    tls: TlsConnectionMetadata,
    tunnel_sender: Option<mpsc::Sender<TunnelPlan>>,
    limits: ListenerLimits,
    downstream_timeout: DownstreamTimeoutSignal,
}

async fn serve_http1_connection<Io>(
    io: Io,
    context: GatewayConnectionContext,
    settings: Http1Settings,
    mut shutdown: watch::Receiver<bool>,
) where
    Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _active_connection = context
        .transport_metrics
        .connection_accepted(ConnectionProtocol::Http1);
    let (tunnel_sender, mut tunnel_receiver) = mpsc::channel(1);
    let mut service_context = context.clone();
    service_context.tunnel_sender = Some(tunnel_sender);
    let request_budget = Arc::new(ConnectionRequestBudget::new(
        context.limits.max_requests_per_connection,
    ));
    let service = service_fn(move |request| {
        serve_bounded_request(
            request,
            service_context.clone(),
            request_budget.try_begin(),
            WireProtocol::Http1,
        )
    });
    let connection = http1_builder_with_limits(
        settings.header_read_timeout,
        context.limits.max_headers as usize,
        context.limits.max_header_bytes as usize,
    )
    .serve_connection(TokioIo::new(io), service)
    .with_upgrades();
    tokio::pin!(connection);
    let result = tokio::select! {
        result = &mut connection => result,
        () = wait_for_shutdown(&mut shutdown) => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::debug!(error = %error, "HTTP/1 connection ended with an error");
    }
    if let Ok(tunnel) = tunnel_receiver.try_recv() {
        let observation = context.transport_metrics.tunnel_started();
        match tunnel.run().await {
            Ok(report) => {
                observation.finish(
                    report.downstream_to_upstream_bytes,
                    report.upstream_to_downstream_bytes,
                    match report.termination {
                        TunnelIoTermination::DownstreamClosed => {
                            TunnelMetricTermination::DownstreamClosed
                        }
                        TunnelIoTermination::UpstreamClosed => {
                            TunnelMetricTermination::UpstreamClosed
                        }
                        TunnelIoTermination::DownstreamReadError(_)
                        | TunnelIoTermination::DownstreamWriteError(_)
                        | TunnelIoTermination::UpstreamReadError(_)
                        | TunnelIoTermination::UpstreamWriteError(_) => {
                            TunnelMetricTermination::Error
                        }
                    },
                );
                tracing::debug!(
                    downstream_to_upstream_bytes = report.downstream_to_upstream_bytes,
                    upstream_to_downstream_bytes = report.upstream_to_downstream_bytes,
                    termination = ?report.termination,
                    "HTTP/1 upgrade tunnel finished"
                );
            }
            Err(error) => {
                observation.finish(0, 0, TunnelMetricTermination::Error);
                tracing::debug!(error = %error, "HTTP/1 upgrade tunnel could not be established");
            }
        }
    }
}

async fn serve_http2_connection<Io>(
    io: Io,
    context: GatewayConnectionContext,
    settings: Http2Settings,
    mut shutdown: watch::Receiver<bool>,
) where
    Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _active_connection = context
        .transport_metrics
        .connection_accepted(ConnectionProtocol::Http2);
    let executor = TrackedExecutor::new(context.transport_metrics.clone());
    let mut builder = http2::Builder::new(executor);
    let max_header_list_size = settings
        .max_header_list_size
        .min(context.limits.max_header_bytes);
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(Some(settings.max_concurrent_streams))
        .max_header_list_size(max_header_list_size)
        .keep_alive_interval(Some(settings.keep_alive_interval))
        .keep_alive_timeout(settings.keep_alive_timeout);
    let service_context = context.clone();
    let request_budget = Arc::new(ConnectionRequestBudget::new(
        context.limits.max_requests_per_connection,
    ));
    let (request_limit, mut request_limit_reached) = watch::channel(false);
    let service = service_fn(move |request| {
        let admission = request_budget.try_begin();
        if admission == RequestAdmission::LastAllowed {
            let _ = request_limit.send(true);
        }
        serve_bounded_request(
            request,
            service_context.clone(),
            admission,
            WireProtocol::Http2,
        )
    });
    let connection = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(connection);
    let mut drain = H2DrainObservation::new(context.transport_metrics.clone());
    let result = tokio::select! {
        result = &mut connection => result,
        () = wait_for_shutdown(&mut shutdown) => {
            drain.started = true;
            connection.as_mut().graceful_shutdown();
            let result = connection.await;
            if result.is_ok() {
                drain.completed = true;
                context
                    .transport_metrics
                    .record_h2_shutdown(H2Shutdown::Graceful);
            }
            result
        }
        () = wait_for_shutdown(&mut request_limit_reached) => {
            drain.started = true;
            connection.as_mut().graceful_shutdown();
            let result = connection.await;
            if result.is_ok() {
                drain.completed = true;
                context
                    .transport_metrics
                    .record_h2_shutdown(H2Shutdown::Graceful);
            }
            result
        }
    };
    if let Err(error) = result {
        tracing::debug!(error = %error, "HTTP/2 connection ended with an error");
    }
}

struct H2DrainObservation {
    metrics: ListenerTransportMetrics,
    started: bool,
    completed: bool,
}

impl H2DrainObservation {
    fn new(metrics: ListenerTransportMetrics) -> Self {
        Self {
            metrics,
            started: false,
            completed: false,
        }
    }
}

impl Drop for H2DrainObservation {
    fn drop(&mut self) {
        if self.started && !self.completed {
            self.metrics.record_h2_shutdown(H2Shutdown::Forced);
        }
    }
}

fn tls_version_name(version: tokio_rustls::rustls::ProtocolVersion) -> String {
    match version {
        tokio_rustls::rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".to_owned(),
        tokio_rustls::rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".to_owned(),
        version => format!("{version:?}"),
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn serve_bounded_request(
    request: Request<Incoming>,
    context: GatewayConnectionContext,
    admission: RequestAdmission,
    protocol: WireProtocol,
) -> Result<Response<GatewayBody>, Infallible> {
    if admission == RequestAdmission::Rejected {
        let method = request.method().clone();
        drop(request);
        let mut response = safe_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Connection Request Limit Reached",
            &method,
        );
        if protocol == WireProtocol::Http1 {
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
        }
        return Ok(response);
    }

    let mut response = handle_request(request, context).await?;
    if admission == RequestAdmission::LastAllowed
        && protocol == WireProtocol::Http1
        && response.status() != StatusCode::SWITCHING_PROTOCOLS
    {
        // This is server-owned connection control applied after the root
        // ResponseFinalizer. It cannot be constructed by Gateway or Oxista
        // source and causes Hyper to retire the connection after this response.
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    Ok(response)
}

async fn handle_request(
    mut request: Request<Incoming>,
    context: GatewayConnectionContext,
) -> Result<Response<GatewayBody>, Infallible> {
    let GatewayConnectionContext {
        peer_address,
        listener_name,
        store,
        proxy,
        metrics,
        transport_metrics: _,
        scheme,
        tls,
        tunnel_sender,
        limits,
        downstream_timeout,
    } = context;
    let active_request = metrics.request_started();
    let request_id = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let started = std::time::Instant::now();
    let snapshot = store.pin();
    let config_version = snapshot.config_version.to_string();
    let Some(program) = snapshot.program_for(&listener_name) else {
        tracing::error!(
            request_id,
            config_version,
            listener = listener_name,
            error_class = "invalid_state",
            "listener root is missing from pinned snapshot"
        );
        metrics.record_request(
            "failed",
            StatusCode::INTERNAL_SERVER_ERROR,
            started.elapsed(),
        );
        let response = safe_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            request.method(),
        );
        return Ok(instrument_response_body_with_snapshot_timeout(
            response,
            metrics,
            active_request,
            Some(snapshot),
            Some(limits.response_body_idle_timeout),
            Some(downstream_timeout.clone()),
        ));
    };

    let request_method = request.method().clone();
    let wire_protocol = wire_protocol(request.version());
    let accepts_http1_trailers =
        wire_protocol == WireProtocol::Http1 && http1_accepts_trailers(request.headers());
    let request_trailer_guard = match RequestTrailerGuard::from_request_headers(
        wire_protocol,
        request.headers(),
    ) {
        Ok(guard) => guard,
        Err(error) => {
            tracing::debug!(request_id, error = %error, "request trailer declaration is invalid");
            metrics.record_request("failed", StatusCode::BAD_REQUEST, started.elapsed());
            let response = safe_response(StatusCode::BAD_REQUEST, "Bad Request", &request_method);
            return Ok(instrument_response_body_with_snapshot_timeout(
                response,
                metrics,
                active_request,
                Some(snapshot),
                Some(limits.response_body_idle_timeout),
                Some(downstream_timeout.clone()),
            ));
        }
    };
    let pending_upgrade = match validate_upgrade_request(&request) {
        Ok(Some(candidate)) => Some(candidate.pending(hyper::upgrade::on(&mut request))),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(request_id, error = %error, "HTTP Upgrade request is invalid");
            metrics.record_request("failed", StatusCode::BAD_REQUEST, started.elapsed());
            let response = safe_response(StatusCode::BAD_REQUEST, "Bad Request", &request_method);
            return Ok(instrument_response_body_with_snapshot_timeout(
                response,
                metrics,
                active_request,
                Some(snapshot),
                Some(limits.response_body_idle_timeout),
                Some(downstream_timeout.clone()),
            ));
        }
    };
    let (mut parts, body) = request.into_parts();
    if parts.headers.iter().count() > limits.max_headers as usize
        || decoded_header_bytes(&parts.headers) > limits.max_header_bytes as usize
    {
        metrics.record_request(
            "failed",
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            started.elapsed(),
        );
        let response = safe_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "Request Header Fields Too Large",
            &request_method,
        );
        return Ok(instrument_response_body_with_snapshot_timeout(
            response,
            metrics,
            active_request,
            Some(snapshot),
            Some(limits.response_body_idle_timeout),
            Some(downstream_timeout.clone()),
        ));
    }
    if wire_protocol == WireProtocol::Http1
        && request_target_length(&parts.uri) > DEFAULT_HTTP1_MAX_REQUEST_TARGET_BYTES
    {
        metrics.record_request("failed", StatusCode::URI_TOO_LONG, started.elapsed());
        let response = safe_response(StatusCode::URI_TOO_LONG, "URI Too Long", &request_method);
        return Ok(instrument_response_body_with_snapshot_timeout(
            response,
            metrics,
            active_request,
            Some(snapshot),
            Some(limits.response_body_idle_timeout),
            Some(downstream_timeout.clone()),
        ));
    }
    let authority = match normalize_ingress_authority(&mut parts) {
        Ok(authority) => authority,
        Err(error) => {
            tracing::warn!(request_id, error, "request authority is invalid");
            metrics.record_request("failed", StatusCode::BAD_REQUEST, started.elapsed());
            let response = safe_response(StatusCode::BAD_REQUEST, "Bad Request", &request_method);
            return Ok(instrument_response_body_with_snapshot_timeout(
                response,
                metrics,
                active_request,
                Some(snapshot),
                Some(limits.response_body_idle_timeout),
                Some(downstream_timeout.clone()),
            ));
        }
    };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_owned(), |value| value.as_str().to_owned());
    let mut metadata = match RequestMetadata::try_new(
        parts.method,
        scheme,
        authority,
        path_and_query,
        parts.headers,
    ) {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::warn!(request_id, error = %error, "request metadata is invalid");
            metrics.record_request("failed", StatusCode::BAD_REQUEST, started.elapsed());
            let response = safe_response(StatusCode::BAD_REQUEST, "Bad Request", &request_method);
            return Ok(instrument_response_body_with_snapshot_timeout(
                response,
                metrics,
                active_request,
                Some(snapshot),
                Some(limits.response_body_idle_timeout),
                Some(downstream_timeout.clone()),
            ));
        }
    };
    metadata.peer_address = Some(peer_address);
    metadata.http_version = parts.version;
    metadata.tls = tls;
    let leaves = HyperLeaves::new(snapshot.clone(), proxy, Arc::clone(&metrics));
    let observer = ProductionObserver::new(&metrics, &config_version, &listener_name, request_id);
    let incoming = timeout_request_body(body, limits.request_body_idle_timeout);
    let unconsumed_h2 = (wire_protocol == WireProtocol::Http2
        && !http_body::Body::is_end_stream(&incoming))
    .then(UnconsumedH2Body::default);
    let mut payload = GatewayRequestPayload::new(incoming, pending_upgrade, request_trailer_guard);
    if let Some(slot) = &unconsumed_h2 {
        payload = payload.with_unconsumed_h2(slot.clone());
    }
    let report = Executor::new(&program, &leaves)
        .execute_observed(RequestFrame::new(metadata), Some(payload), &observer)
        .await;

    let (outcome, status, response, tunnel) = match report.outcome {
        ServiceOutcome::Handled(response) => match response_from_head(
            response,
            &request_method,
            ResponseFinalizationContext::new(wire_protocol, accepts_http1_trailers),
        ) {
            Ok(FinalizedResponse { response, tunnel }) => {
                let status = response.status();
                ("handled", status, response, tunnel)
            }
            Err(error) => {
                tracing::error!(
                    request_id,
                    error = ?error,
                    "trusted response finalization failed"
                );
                (
                    "failed",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        &request_method,
                    ),
                    None,
                )
            }
        },
        ServiceOutcome::Declined => (
            "declined",
            StatusCode::NOT_FOUND,
            safe_response(StatusCode::NOT_FOUND, "Not Found", &request_method),
            None,
        ),
        ServiceOutcome::Failed(error) => {
            tracing::error!(
                request_id,
                config_version,
                listener = listener_name,
                error_class = ?error.class,
                internal_detail = %error.internal_detail,
                "Service execution failed"
            );
            (
                "failed",
                error.public_status,
                safe_response(
                    error.public_status,
                    safe_error_body(error.public_status),
                    &request_method,
                ),
                None,
            )
        }
    };
    let (outcome, status, response) = if let Some(tunnel) = tunnel {
        match tunnel_sender.and_then(|sender| sender.try_send(tunnel).ok()) {
            Some(()) => (outcome, status, response),
            None => {
                tracing::error!(
                    request_id,
                    "trusted Upgrade tunnel has no live HTTP/1 connection owner"
                );
                (
                    "failed",
                    StatusCode::INTERNAL_SERVER_ERROR,
                    safe_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        &request_method,
                    ),
                )
            }
        }
    } else {
        (outcome, status, response)
    };
    tracing::info!(
        request_id,
        config_version,
        listener = listener_name,
        outcome,
        status = status.as_u16(),
        latency_micros = started.elapsed().as_micros(),
        "request complete"
    );
    metrics.record_request(outcome, status, started.elapsed());
    let response = if let Some(slot) = unconsumed_h2 {
        retain_unconsumed_h2_body(response, slot, limits.request_body_idle_timeout)
    } else {
        response
    };
    Ok(instrument_response_body_with_snapshot_timeout(
        response,
        metrics,
        active_request,
        Some(snapshot),
        Some(limits.response_body_idle_timeout),
        Some(downstream_timeout),
    ))
}

fn decoded_header_bytes(headers: &http::HeaderMap) -> usize {
    headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(": ".len())
            .saturating_add(value.as_bytes().len())
            .saturating_add("\r\n".len())
    })
}

fn request_target_length(uri: &http::Uri) -> usize {
    if let (Some(scheme), Some(authority)) = (uri.scheme(), uri.authority()) {
        scheme.as_str().len()
            + "://".len()
            + authority.as_str().len()
            + uri
                .path_and_query()
                .map_or(0, |path_and_query| path_and_query.as_str().len())
    } else if let Some(authority) = uri.authority() {
        authority.as_str().len()
    } else {
        uri.path_and_query()
            .map_or(0, |path_and_query| path_and_query.as_str().len())
    }
}

fn normalize_ingress_authority(parts: &mut http::request::Parts) -> Result<String, &'static str> {
    let mut host_values = parts.headers.get_all(header::HOST).iter();
    let host = host_values.next();
    if host_values.next().is_some() {
        return Err("request contains multiple Host fields");
    }
    if parts.version == Version::HTTP_11 {
        let Some(host) = host else {
            return Err("HTTP/1.1 requires exactly one Host field");
        };
        if host.as_bytes().is_empty() {
            return Err("HTTP/1.1 Host field is empty");
        }
    }

    if parts.version != Version::HTTP_2
        && parts.uri.authority().is_some()
        && parts.uri.scheme().is_none()
    {
        return Err("authority-form is only valid for CONNECT");
    }

    // For absolute-form requests, RFC 9112 requires recipients to use the
    // request-target authority instead of a potentially conflicting Host
    // field. H2 also carries its trusted `:authority` value in the URI.
    let authority = parts
        .uri
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            host.and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .ok_or("request has no valid authority")?;
    let canonical_host = HeaderValue::try_from(authority.as_str())
        .map_err(|_| "request authority is not a valid Host field value")?;
    parts.headers.remove(header::HOST);
    parts.headers.insert(header::HOST, canonical_host);
    Ok(authority)
}

fn response_from_head(
    response: oxidase_core::ResponseHead<GatewayBodyPlan>,
    method: &Method,
    context: ResponseFinalizationContext,
) -> Result<FinalizedResponse, ResponseFinalizationError> {
    ResponseFinalizer::with_context(method, context).finalize_handled(response)
}

fn wire_protocol(version: Version) -> WireProtocol {
    if version == Version::HTTP_2 {
        WireProtocol::Http2
    } else {
        WireProtocol::Http1
    }
}

fn safe_error_body(status: StatusCode) -> &'static str {
    if status == StatusCode::GATEWAY_TIMEOUT {
        "Gateway Timeout"
    } else if status == StatusCode::BAD_GATEWAY {
        "Bad Gateway"
    } else if status == StatusCode::SERVICE_UNAVAILABLE {
        "Service Unavailable"
    } else {
        "Internal Server Error"
    }
}

fn safe_response(
    status: StatusCode,
    message: &'static str,
    method: &Method,
) -> Response<GatewayBody> {
    let bytes = Bytes::from_static(message.as_bytes());
    let mut response = oxidase_core::ResponseHead::new(status, GatewayBodyPlan::Bytes(bytes));
    response.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    ResponseFinalizer::new(method).finalize(response)
}

#[derive(Debug, Clone)]
pub struct ReloadError {
    diagnostics: Vec<Diagnostic>,
}

impl ReloadError {
    fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self { diagnostics }
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        self.diagnostics
    }
}

impl fmt::Display for ReloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, diagnostic) in self.diagnostics.iter().enumerate() {
            if index > 0 {
                writeln!(formatter)?;
            }
            write!(formatter, "{diagnostic}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ReloadError {}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("invalid administration listener configuration: {0}")]
    AdminConfiguration(String),
    #[error("cannot prepare administration transport: {0}")]
    AdminPreparation(Box<Diagnostic>),
    #[error("snapshot activation precondition failed")]
    PreconditionFailed,
    #[error("operation was cancelled or expired before publication")]
    OperationCancelled,
    #[error("automatic source reload no longer owns the active deployment")]
    SourceAuthorityLost,
    #[error("the bounded preparation worker is already in use")]
    PreparationBusy,
    #[error("control-plane durable operation failed ({0})")]
    AdminStore(&'static str),
    #[cfg(unix)]
    #[error("cannot bind administration Unix socket `{path}`: {source}")]
    AdminUnixBind {
        path: PathBuf,
        source_span: Box<SourceSpan>,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot bind listener `{listener}` to {address}: {source}")]
    Bind {
        listener: String,
        address: SocketAddr,
        source_span: Box<SourceSpan>,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read local address for listener `{listener}`: {source}")]
    LocalAddress {
        listener: String,
        source_span: Box<SourceSpan>,
        #[source]
        source: std::io::Error,
    },
    #[error("listener `{listener}` failed while accepting a connection: {source}")]
    Accept {
        listener: String,
        source_span: Box<SourceSpan>,
        #[source]
        source: std::io::Error,
    },
    #[error("server task failed: {0}")]
    Task(String),
    #[error("cannot initialize HTTP data plane: {0}")]
    DataPlane(String),
    #[error("reload failed: {0}")]
    Reload(#[source] ReloadError),
    #[error("server control channel is closed")]
    ControlClosed,
}

impl ServerError {
    /// Produces renderer-neutral diagnostics for command-line and management
    /// boundaries without flattening reload compiler errors into one string.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<Diagnostic> {
        match self {
            Self::AdminConfiguration(message) => vec![Diagnostic::new(
                "admin.listener_configuration",
                message.clone(),
                SourceSpan::synthetic("admin.listen"),
            )],
            Self::AdminPreparation(diagnostic) => vec![diagnostic.as_ref().clone()],
            Self::PreconditionFailed => vec![Diagnostic::new(
                "admin.precondition_failed",
                "snapshot activation precondition failed",
                SourceSpan::synthetic("admin.if_match"),
            )],
            Self::OperationCancelled => vec![Diagnostic::new(
                "admin.operation_cancelled",
                "operation was cancelled or expired before publication",
                SourceSpan::synthetic("admin.operation"),
            )],
            Self::SourceAuthorityLost => vec![Diagnostic::new(
                "reload.source_authority_lost",
                "automatic source reload cannot replace a Bundle deployment or reopen a drained runtime",
                SourceSpan::synthetic("serve.watch"),
            )],
            Self::PreparationBusy => vec![Diagnostic::new(
                "admin.preparation_busy",
                "the bounded preparation worker is already in use",
                SourceSpan::synthetic("admin.operation"),
            )],
            Self::AdminStore(code) => vec![Diagnostic::new(
                code,
                "durable operation could not be completed",
                SourceSpan::synthetic("admin.operation"),
            )],
            #[cfg(unix)]
            Self::AdminUnixBind {
                path,
                source_span,
                source,
            } => vec![Diagnostic::new(
                "admin.unix_bind",
                format!(
                    "cannot bind administration Unix socket `{}`: {source}",
                    path.display()
                ),
                source_span.as_ref().clone(),
            )],
            Self::Bind {
                listener,
                address,
                source_span,
                source,
            } => vec![Diagnostic::new(
                "server.listener_bind",
                format!("cannot bind listener `{listener}` to {address}: {source}"),
                source_span.as_ref().clone(),
            )],
            Self::LocalAddress {
                listener,
                source_span,
                source,
            } => vec![Diagnostic::new(
                "server.listener_local_address",
                format!("cannot read local address for listener `{listener}`: {source}"),
                source_span.as_ref().clone(),
            )],
            Self::Accept {
                listener,
                source_span,
                source,
            } => vec![Diagnostic::new(
                "server.listener_accept",
                format!("listener `{listener}` failed while accepting a connection: {source}"),
                source_span.as_ref().clone(),
            )],
            Self::Task(message) => vec![Diagnostic::new(
                "server.task",
                message.clone(),
                SourceSpan::synthetic("server.task"),
            )],
            Self::DataPlane(message) => vec![Diagnostic::new(
                "server.data_plane",
                message.clone(),
                SourceSpan::synthetic("server.data_plane"),
            )],
            Self::Reload(error) => error.diagnostics().to_vec(),
            Self::ControlClosed => vec![Diagnostic::new(
                "server.control_closed",
                "server control channel is closed",
                SourceSpan::synthetic("server.control"),
            )],
        }
    }

    #[must_use]
    pub fn into_diagnostics(self) -> Vec<Diagnostic> {
        match self {
            Self::Reload(error) => error.into_diagnostics(),
            error => error.diagnostics(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Version, header};
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::client::conn::http2 as client_http2;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use oxidase_config::{Compiler, Http2Settings, HttpVersion, ListenerProtocol};
    use oxidase_core::{SourceSpan, TlsConnectionMetadata};
    use oxidase_runtime::{RuntimeSnapshot, SnapshotStore};
    use rcgen::{CertifiedKey as GeneratedCertificate, generate_simple_self_signed};
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{Notify, Semaphore, oneshot, watch};

    use super::{
        AlpnSelectionError, DEFAULT_HTTP1_HEADER_READ_TIMEOUT, DownstreamTimeoutSignal,
        GatewayConnectionContext, GatewayServer, H2DrainObservation, NegotiatedHttpProtocol,
        ProxyClient, ServerError, http1_builder, reap_finished_connections, reserve_tls_handshake,
        safe_error_body, select_https_protocol, serve_http2_connection, tls_accept_error_outcome,
    };
    use crate::metrics::{Metrics, TlsHandshakeOutcome};

    #[test]
    fn listener_errors_expose_stable_structured_diagnostics() {
        let error = ServerError::Bind {
            listener: "public".to_owned(),
            address: "127.0.0.1:8443".parse().expect("fixture address is valid"),
            source_span: Box::new(SourceSpan::synthetic("listeners[0].bind")),
            source: std::io::Error::new(std::io::ErrorKind::AddrInUse, "already in use"),
        };

        let diagnostics = error.into_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "server.listener_bind");
        assert_eq!(diagnostics[0].primary.field_path, "listeners[0].bind");
        assert!(diagnostics[0].message.contains("public"));
    }

    #[test]
    fn admin_diagnostics_preserve_locations_without_replaying_sensitive_strings() {
        let mut span = SourceSpan::synthetic("resources.certificates.public.private_key");
        span.file = "/run/secrets/operator.key".into();
        span.line = 12;
        let diagnostic = oxidase_core::Diagnostic::new(
            "tls.private_key_missing",
            "secret details /run/secrets/operator.key",
            span.clone(),
        )
        .with_label("raw token and path", span.clone())
        .with_note("private content")
        .with_help("/run/secrets/operator.key");
        let value = serde_json::to_string(&super::safe_admin_diagnostics(&[diagnostic]))
            .expect("JSON projection");
        assert!(value.contains("resources.certificates.public.private_key"));
        assert!(value.contains("\"line\":12"));
        assert!(!value.contains("operator.key"));
        assert!(!value.contains("raw token"));
        assert_eq!(super::safe_admin_field_path("/run/secrets/key"), "<field>");
        assert_eq!(
            super::safe_admin_field_path("defaults.by_extension[\"/secret/key\"]"),
            "defaults.by_extension[\"<key>\"]"
        );
    }

    #[test]
    fn root_error_bodies_are_safe_and_status_specific() {
        assert_eq!(safe_error_body(StatusCode::BAD_GATEWAY), "Bad Gateway");
        assert_eq!(
            safe_error_body(StatusCode::SERVICE_UNAVAILABLE),
            "Service Unavailable"
        );
        assert_eq!(
            safe_error_body(StatusCode::GATEWAY_TIMEOUT),
            "Gateway Timeout"
        );
        assert_eq!(
            safe_error_body(StatusCode::INTERNAL_SERVER_ERROR),
            "Internal Server Error"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_connection_tasks_are_reaped_during_sustained_churn() {
        let mut connections = tokio::task::JoinSet::new();
        for _ in 0..2_000 {
            connections.spawn(async {});
            tokio::task::yield_now().await;
            reap_finished_connections(&mut connections, "test");
            assert!(
                connections.len() <= 1,
                "completed connection tasks must not accumulate behind a ready accept loop"
            );
        }
        while connections.join_next().await.is_some() {}
    }

    async fn request(address: std::net::SocketAddr, path: &str, extra: &str) -> String {
        raw_request(
            address,
            &format!(
                "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n{extra}\r\n"
            ),
        )
        .await
    }

    async fn raw_request(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("test server accepts connections");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("request can be written");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("response can be read");
        String::from_utf8(response).expect("test response is UTF-8")
    }

    async fn raw_request_allow_disconnect(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("test server accepts connections");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("request can be written");
        let mut response = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => response.extend_from_slice(&buffer[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::UnexpectedEof
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("response read failed: {error}"),
            }
        }
        String::from_utf8_lossy(&response).into_owned()
    }

    fn write_proxy_gateway(
        path: &std::path::Path,
        upstream: std::net::SocketAddr,
        response_timeout: &str,
    ) {
        fs::write(
            path,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: {response_timeout}
services:
  root:
    type: proxy
    cluster: upstream
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("proxy gateway config can be written");
    }

    fn write_blocked_proxy_gateway(path: &std::path::Path, upstream: std::net::SocketAddr) {
        fs::write(
            path,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 5s
services:
  root:
    type: route
    cases:
      - when:
          path: /blocked
        service:
          type: proxy
          cluster: upstream
    default:
      type: respond
      body:
        text: probe
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("blocked proxy gateway config can be written");
    }

    fn raw_response_parts(response: &str) -> (&str, &str) {
        response
            .split_once("\r\n\r\n")
            .expect("wire response contains a header terminator")
    }

    fn raw_header_values(response: &str, name: &str) -> Vec<String> {
        let (headers, _) = raw_response_parts(response);
        headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(candidate, _)| candidate.trim().eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim().to_owned())
            .collect()
    }

    fn raw_header(response: &str, name: &str) -> String {
        raw_header_values(response, name)
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("wire response is missing `{name}`"))
    }

    async fn read_until_contains(stream: &mut tokio::net::TcpStream, needle: &str) -> String {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut response = Vec::new();
            let mut buffer = [0u8; 512];
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .expect("response is readable");
                assert!(read > 0, "connection closed before complete response");
                response.extend_from_slice(&buffer[..read]);
                let response_text = String::from_utf8_lossy(&response);
                if response_text.contains(needle) {
                    return String::from_utf8(response).expect("response is UTF-8");
                }
            }
        })
        .await
        .expect("response arrives before timeout")
    }

    async fn read_http1_response(stream: &mut tokio::net::TcpStream) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut response = Vec::new();
            let mut buffer = [0u8; 4096];
            let mut expected_length = None;
            let mut chunked = false;
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .expect("response is readable");
                assert!(read > 0, "connection closed before complete response");
                response.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = response.windows(4).position(|value| value == b"\r\n\r\n")
                {
                    let body_start = header_end + 4;
                    if expected_length.is_none() && !chunked {
                        let headers = String::from_utf8_lossy(&response[..header_end]);
                        expected_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        chunked = headers.lines().any(|line| {
                            line.split_once(':').is_some_and(|(name, value)| {
                                name.eq_ignore_ascii_case("transfer-encoding")
                                    && value.trim().eq_ignore_ascii_case("chunked")
                            })
                        });
                    }
                    if expected_length.is_some_and(|length| response.len() >= body_start + length)
                        || chunked && response[body_start..].ends_with(b"0\r\n\r\n")
                    {
                        return String::from_utf8(response).expect("response is UTF-8");
                    }
                }
            }
        })
        .await
        .expect("complete HTTP/1 response arrives before timeout")
    }

    fn available_address() -> std::net::SocketAddr {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("temporary port can be reserved");
        listener.local_addr().expect("reserved address is known")
    }

    async fn spawn_upstream() -> (
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("upstream binds");
        let address = listener.local_addr().expect("upstream address is known");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_for_task = accepts.clone();
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed = receiver.changed() => {
                        if changed.is_err() || *receiver.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        accepts_for_task.fetch_add(1, Ordering::Relaxed);
                        connections.spawn(async move {
                            let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
                                let path = request
                                    .uri()
                                    .path_and_query()
                                    .map_or("/", http::uri::PathAndQuery::as_str)
                                    .to_owned();
                                let host = request
                                    .headers()
                                    .get(header::HOST)
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                let forwarded = request
                                    .headers()
                                    .get("x-forwarded-for")
                                    .and_then(|value| value.to_str().ok())
                                    .unwrap_or("")
                                    .to_owned();
                                let standardized_forwarded = request
                                    .headers()
                                    .get("forwarded")
                                    .cloned();
                                let has_hop_header = request.headers().contains_key("x-hop");
                                if path.starts_with("/slow") {
                                    tokio::time::sleep(Duration::from_millis(150)).await;
                                }
                                let body = request
                                    .into_body()
                                    .collect()
                                    .await
                                    .expect("fixture request body is readable")
                                    .to_bytes();
                                let message = format!(
                                    "{path}|{}|{host}|{forwarded}|{has_hop_header}",
                                    String::from_utf8_lossy(&body)
                                );
                                let mut response = Response::new(Full::new(Bytes::from(message)));
                                response.headers_mut().insert(
                                    header::CONNECTION,
                                    HeaderValue::from_static("x-remove"),
                                );
                                response.headers_mut().insert(
                                    HeaderName::from_static("x-remove"),
                                    HeaderValue::from_static("secret"),
                                );
                                response.headers_mut().insert(
                                    HeaderName::from_static("x-keep"),
                                    HeaderValue::from_static("kept"),
                                );
                                if let Some(forwarded) = standardized_forwarded {
                                    response.headers_mut().insert(
                                        HeaderName::from_static("x-seen-forwarded"),
                                        forwarded,
                                    );
                                }
                                Ok::<_, Infallible>(response)
                            });
                            let _ = http1::Builder::new()
                                .keep_alive(true)
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        (address, accepts, shutdown, task)
    }

    async fn spawn_blocked_upstream() -> (
        std::net::SocketAddr,
        Arc<Notify>,
        Arc<Notify>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("blocked upstream binds");
        let address = listener
            .local_addr()
            .expect("blocked upstream address is known");
        let request_started = Arc::new(Notify::new());
        let release_response = Arc::new(Notify::new());
        let request_started_for_task = request_started.clone();
        let release_response_for_task = release_response.clone();
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    changed = receiver.changed() => {
                        if changed.is_err() || *receiver.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let request_started = request_started_for_task.clone();
                        let release_response = release_response_for_task.clone();
                        connections.spawn(async move {
                            let service = service_fn(move |_| {
                                let request_started = request_started.clone();
                                let release_response = release_response.clone();
                                async move {
                                    request_started.notify_one();
                                    release_response.notified().await;
                                    Ok::<_, Infallible>(Response::new(Full::new(
                                        Bytes::from_static(b"released"),
                                    )))
                                }
                            });
                            let _ = http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .await;
                        });
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        });
        (address, request_started, release_response, shutdown, task)
    }

    fn write_respond_gateway(path: &std::path::Path, body: &str, extra_listener: Option<&str>) {
        write_respond_gateway_at(path, body, "127.0.0.1:0", extra_listener);
    }

    fn write_limited_respond_gateway(path: &std::path::Path, limits: &str) {
        fs::write(
            path,
            format!(
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  root:\n    type: respond\n    body:\n      text: ok\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    limits:\n{limits}\n    service:\n      ref: root\n"
            ),
        )
        .expect("limited gateway config can be written");
    }

    fn write_respond_gateway_at(
        path: &std::path::Path,
        body: &str,
        bind: &str,
        extra_listener: Option<&str>,
    ) {
        let extra_listener = extra_listener.map_or(String::new(), |bind| {
            format!("  - name: extra\n    bind: {bind}\n    service:\n      ref: root\n")
        });
        fs::write(
            path,
            format!(
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  root:\n    type: respond\n    body:\n      text: {body}\nlisteners:\n  - name: test\n    bind: {bind}\n    service:\n      ref: root\n{extra_listener}"
            ),
        )
        .expect("gateway config can be written");
    }

    fn write_https_respond_gateway(path: &std::path::Path, body: &str, handshake_timeout: &str) {
        let GeneratedCertificate { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_owned(), "example.test".to_owned()])
                .expect("test-only certificate can be generated");
        let directory = path.parent().expect("config has a parent directory");
        fs::write(directory.join("test-cert.pem"), cert.pem())
            .expect("test-only certificate can be written");
        fs::write(directory.join("test-key.pem"), signing_key.serialize_pem())
            .expect("test-only private key can be written");
        fs::write(
            path,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  certificates:
    test:
      cert_chain: ./test-cert.pem
      private_key: ./test-key.pem
services:
  root:
    type: respond
    body:
      text: {body}
listeners:
  - name: test
    bind: 127.0.0.1:0
    protocol: https
    tls:
      default_certificate: test
      handshake_timeout: {handshake_timeout}
    http:
      versions: [http1]
    service:
      ref: root
"#
            ),
        )
        .expect("HTTPS gateway config can be written");
    }

    fn h2_settings() -> Http2Settings {
        Http2Settings {
            max_concurrent_streams: 32,
            max_header_list_size: 16 * 1024,
            keep_alive_interval: Duration::from_secs(60),
            keep_alive_timeout: Duration::from_secs(5),
            source: SourceSpan::synthetic("listeners[0].http.http2"),
        }
    }

    fn h2_connection_context(
        snapshot: RuntimeSnapshot,
        metrics: Arc<Metrics>,
    ) -> GatewayConnectionContext {
        let transport_metrics = metrics.listener_transport("test");
        let limits = snapshot
            .prepared_listener_for("test")
            .expect("test listener has a prepared plan")
            .limits
            .clone();
        GatewayConnectionContext {
            peer_address: "127.0.0.1:43123"
                .parse()
                .expect("test peer address is valid"),
            listener_name: "test".to_owned(),
            store: Arc::new(SnapshotStore::new(snapshot)),
            proxy: Arc::new(ProxyClient::new().expect("proxy client can be initialized")),
            metrics,
            transport_metrics,
            scheme: "https",
            tls: TlsConnectionMetadata {
                enabled: true,
                server_name: Some("example.test".to_owned()),
                alpn: Some("h2".to_owned()),
                version: Some("TLS1.3".to_owned()),
                client: oxidase_core::TlsClientMetadata::default(),
            },
            tunnel_sender: None,
            limits,
            downstream_timeout: DownstreamTimeoutSignal::default(),
        }
    }

    fn h2_request(path: &str) -> Request<Empty<Bytes>> {
        Request::builder()
            .version(Version::HTTP_2)
            .uri(format!("https://example.test{path}"))
            .body(Empty::new())
            .expect("test HTTP/2 request is valid")
    }

    async fn wait_for_h2_goaway(sender: &mut client_http2::SendRequest<Empty<Bytes>>) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Ok(response) = sender.send_request(h2_request("/probe")).await {
                response
                    .into_body()
                    .collect()
                    .await
                    .expect("pre-GOAWAY probe body is readable");
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("HTTP/2 GOAWAY rejects new streams");
    }

    #[tokio::test]
    async fn serves_route_redirect_fallback_and_graceful_shutdown() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: route
    cases:
      - when:
          path: /hello
        service:
          type: respond
          body:
            text: hello
      - when:
          path: /old
        service:
          type: redirect
          location: /new
    default:
      type: respond
      status: 404
      body:
        text: missing
  observed:
    type: observe
    name: public
    service:
      ref: root
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: observed
"#,
        )
        .expect("config can be written");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("server binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("valid admin bind"))
            .await
            .expect("admin server binds");
        let running = server.spawn();
        let address = running.local_addresses()[0].1;
        let admin_address = running.admin_address().expect("admin address is available");

        let hello = request(address, "/hello", "").await;
        assert!(hello.starts_with("HTTP/1.1 200 OK"));
        assert!(hello.ends_with("hello"));
        let redirect = request(address, "/old", "").await;
        assert!(redirect.starts_with("HTTP/1.1 308 Permanent Redirect"));
        assert!(redirect.to_ascii_lowercase().contains("location: /new"));
        let missing = request(address, "/missing", "").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
        assert!(missing.ends_with("missing"));
        let live = request(admin_address, "/health/live", "").await;
        assert!(live.starts_with("HTTP/1.1 200 OK"));
        assert!(live.ends_with("live\n"));
        let metrics = request(admin_address, "/metrics", "").await;
        assert!(metrics.contains("oxidase_requests_total 3"));
        assert!(metrics.contains("oxidase_request_outcomes_total{outcome=\"handled\"} 3"));
        assert!(
            metrics.contains("oxidase_observe_total{observe=\"public\",outcome=\"handled\"} 3")
        );
        assert!(metrics.contains(
            "oxidase_observe_response_head_duration_seconds_bucket{observe=\"public\",le=\"+Inf\"} 3"
        ));
        assert!(
            metrics.contains("oxidase_response_body_terminations_total{reason=\"completed\"} 3"),
            "{metrics}"
        );
        running.shutdown().await.expect("server shuts down cleanly");
    }

    #[tokio::test]
    async fn listener_connection_limit_rejects_excess_and_releases_on_disconnect() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_limited_respond_gateway(
            &config,
            "      max_connections: 1\n      max_connections_per_ip: 1\n      idle_timeout: 5s",
        );
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("limited config compiles"),
        )
        .expect("limited snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("limited gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let first = tokio::net::TcpStream::connect(address)
            .await
            .expect("first socket connects");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let excess = raw_request_allow_disconnect(
            address,
            "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            !excess.contains("200 OK"),
            "an excess socket must not execute the Service graph: {excess}"
        );

        drop(first);
        let recovered = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let response = request(address, "/", "").await;
                if response.starts_with("HTTP/1.1 200 OK") {
                    break response;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("disconnect releases listener and peer accounting");
        assert!(recovered.ends_with("ok"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn listener_idle_timeout_closes_a_quiet_keep_alive_socket() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_limited_respond_gateway(
            &config,
            "      max_connections: 4\n      max_connections_per_ip: 4\n      idle_timeout: 40ms",
        );
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("idle timeout config compiles"),
        )
        .expect("idle timeout snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("idle timeout gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let mut socket = tokio::net::TcpStream::connect(address)
            .await
            .expect("quiet socket connects");
        let mut bytes = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(1), socket.read_to_end(&mut bytes))
            .await
            .expect("idle timeout closes the socket");
        if let Err(error) = result {
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::BrokenPipe
                ),
                "unexpected idle close error: {error}"
            );
        }
        assert!(bytes.is_empty());
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn slow_downstream_write_is_reported_as_a_body_timeout() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir_all(&site).expect("site directory can be created");
        fs::write(site.join("site.oxsite"), "oxista: site/v1\n")
            .expect("site manifest can be written");
        fs::File::create(site.join("large.bin"))
            .expect("large sparse asset can be created")
            .set_len(32 * 1024 * 1024)
            .expect("large sparse asset length can be set");
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
    limits:
      idle_timeout: 5s
      response_body_idle_timeout: 40ms
    service:
      ref: root
"#,
        )
        .expect("slow-client gateway config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("slow-client config compiles"),
        )
        .expect("slow-client snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("slow-client gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");

        let socket = tokio::net::TcpSocket::new_v4().expect("client socket is available");
        socket
            .set_recv_buffer_size(1_024)
            .expect("client receive buffer can be bounded");
        let mut client = socket.connect(address).await.expect("slow client connects");
        client
            .write_all(
                b"GET /large.bin HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("slow-client request can be written");

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let metrics = request(admin, "/metrics", "").await;
                if metrics
                    .contains("oxidase_response_body_terminations_total{reason=\"timeout\"} 1")
                {
                    assert!(metrics.contains("oxidase_active_requests 0"));
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("write backpressure reaches the configured body timeout");

        drop(client);
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn http1_request_count_and_header_limits_prevent_extra_service_execution() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_limited_respond_gateway(
            &config,
            "      max_headers: 3\n      max_header_bytes: 8KiB\n      max_requests_per_connection: 2",
        );
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("HTTP/1 limits config compiles"),
        )
        .expect("HTTP/1 limits snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("HTTP/1 limits gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let pipelined = raw_request(
            address,
            concat!(
                "GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n",
                "GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n",
                "GET /three HTTP/1.1\r\nHost: example.test\r\n\r\n"
            ),
        )
        .await;
        assert_eq!(
            pipelined.matches("HTTP/1.1 200 OK").count(),
            2,
            "{pipelined}"
        );
        assert!(
            pipelined.to_ascii_lowercase().contains("connection: close"),
            "{pipelined}"
        );

        let too_many_headers = raw_request_allow_disconnect(
            address,
            "GET / HTTP/1.1\r\nHost: example.test\r\nX-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            !too_many_headers.contains("200 OK"),
            "header-count overflow must not execute the Service graph: {too_many_headers}"
        );

        let oversized_value = "a".repeat(9 * 1024);
        let oversized = raw_request_allow_disconnect(
            address,
            &format!("GET / HTTP/1.1\r\nHost: example.test\r\nX-Large: {oversized_value}\r\n\r\n"),
        )
        .await;
        assert!(
            !oversized.contains("200 OK"),
            "header-byte overflow must not execute the Service graph: {oversized}"
        );

        let long_target = format!("/{}", "p".repeat(7_000));
        let large_but_valid_header = "a".repeat(7_000);
        let independent_budgets = raw_request(
            address,
            &format!(
                "GET {long_target} HTTP/1.1\r\nHost: example.test\r\nX-Large: {large_but_valid_header}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(
            independent_budgets.contains("HTTP/1.1 200 OK"),
            "request-target bytes must not consume the decoded Header budget: {independent_budgets}"
        );

        let target_over_limit = format!("/{}", "p".repeat(8 * 1_024));
        let target_rejection = raw_request(
            address,
            &format!(
                "GET {target_over_limit} HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(
            target_rejection.contains("HTTP/1.1 414 URI Too Long"),
            "the independent request-target limit remains explicit: {target_rejection}"
        );

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn admin_clusters_are_deterministic_snapshot_scoped_and_omit_origins() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    zeta:
      endpoints:
        - name: zeta-a
          url: http://127.0.0.1:43125
    alpha:
      protocol: h2
      endpoints:
        - name: alpha-b
          url: http://127.0.0.1:43124
        - name: alpha-a
          url: http://127.0.0.1:43123
      load_balance:
        policy: least_requests
services:
  root:
    type: respond
    body:
      text: ok
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("fixture config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("fixture config compiles"),
        )
        .expect("fixture snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("server binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("valid admin bind"))
            .await
            .expect("admin server binds");
        let running = server.spawn();
        let admin = running.admin_address().expect("admin address is available");

        let first = request(admin, "/api/v1/clusters", "").await;
        let second = request(admin, "/api/v1/clusters", "").await;
        assert!(first.starts_with("HTTP/1.1 200 OK"), "{first}");
        assert!(
            first
                .to_ascii_lowercase()
                .contains("content-type: application/json; charset=utf-8"),
            "{first}"
        );
        let first_body = first
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("admin response has a body");
        let second_body = second
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("second admin response has a body");
        assert_eq!(first_body, second_body);
        assert!(!first_body.contains("127.0.0.1"));
        assert!(!first_body.contains("url"));

        let document: serde_json::Value =
            serde_json::from_str(first_body).expect("admin body is valid JSON");
        let clusters = document["clusters"]
            .as_array()
            .expect("clusters is an array");
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0]["cluster"], "alpha");
        assert_eq!(clusters[0]["policy"], "least_requests");
        assert_eq!(clusters[0]["protocol"], "h2");
        assert_eq!(clusters[0]["endpoints"][0]["name"], "alpha-a");
        assert_eq!(clusters[0]["endpoints"][1]["name"], "alpha-b");
        assert_eq!(clusters[1]["cluster"], "zeta");
        for field in [
            "active_requests",
            "active_retries",
            "retry_attempts",
            "retry_exhausted",
            "overload_rejections",
            "unavailable_rejections",
        ] {
            assert_eq!(clusters[0][field], 0, "missing or nonzero field {field}");
        }
        for field in [
            "health",
            "active_requests",
            "selections",
            "successes",
            "failures",
            "active_health_successes",
            "active_health_failures",
            "passive_ejections",
            "health_transitions",
            "last_transition_unix_ms",
            "ejection_remaining_ms",
        ] {
            assert!(
                clusters[0]["endpoints"][0].get(field).is_some(),
                "missing endpoint field {field}"
            );
        }

        let metrics = request(admin, "/metrics", "").await;
        let alpha = metrics
            .find("oxidase_cluster_info{cluster=\"alpha\"")
            .expect("alpha metrics are rendered");
        let zeta = metrics
            .find("oxidase_cluster_info{cluster=\"zeta\"")
            .expect("zeta metrics are rendered");
        assert!(alpha < zeta);
        assert!(!metrics.contains("127.0.0.1"));

        running.shutdown().await.expect("server shuts down cleanly");
    }

    #[tokio::test]
    async fn http1_header_timeout_closes_stalled_clients_without_rejecting_progress() {
        assert_eq!(DEFAULT_HTTP1_HEADER_READ_TIMEOUT, Duration::from_secs(30));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("header timeout listener binds");
        let address = listener.local_addr().expect("listener address is known");
        let stalled = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("stalled client connects");
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            let _ = http1_builder(Duration::from_millis(40))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("stalled client connects");
        client
            .write_all(b"GET / HTTP/1.1\r\nHost:")
            .await
            .expect("partial header can be written");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
            .await
            .expect("stalled connection closes before test timeout")
            .expect("stalled connection reaches EOF");
        assert!(!String::from_utf8_lossy(&response).contains("200 OK"));
        stalled.await.expect("stalled fixture task completes");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("progressing listener binds");
        let address = listener.local_addr().expect("listener address is known");
        let progressing = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("progressing client connects");
            let service = service_fn(|_| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
            });
            let _ = http1_builder(Duration::from_millis(200))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("progressing client connects");
        client
            .write_all(b"GET / HTTP/1.1\r\n")
            .await
            .expect("request line can be written");
        tokio::time::sleep(Duration::from_millis(25)).await;
        client
            .write_all(b"Host: example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("remaining headers can be written");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("normal response is readable");
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
        progressing
            .await
            .expect("progressing fixture task completes");
    }

    #[tokio::test]
    async fn tls_handshake_timeout_closes_stalled_clients_and_records_timeout() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_https_respond_gateway(&config, "secure", "40ms");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("HTTPS config compiles"),
        )
        .expect("HTTPS snapshot prepares");
        let server = GatewayServer::bind(snapshot)
            .await
            .expect("HTTPS gateway binds");
        let metrics = server.metrics.clone();
        let running = server.spawn();
        let address = running.local_addresses()[0].1;
        let mut stalled = tokio::net::TcpStream::connect(address)
            .await
            .expect("stalled TLS client connects");

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stalled.read_to_end(&mut response))
            .await
            .expect("TLS handshake timeout closes the socket")
            .expect("stalled TLS client reaches EOF");
        assert!(response.is_empty(), "TLS timeout must not emit HTTP bytes");

        let rendered = metrics.render_prometheus();
        assert!(
            rendered
                .contains("oxidase_tls_handshakes_total{listener=\"test\",result=\"timeout\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("oxidase_active_connections{listener=\"test\",protocol=\"http1\"} 0"),
            "{rendered}"
        );
        assert!(
            rendered.contains("oxidase_active_connections{listener=\"test\",protocol=\"h2\"} 0"),
            "{rendered}"
        );

        running.shutdown().await.expect("gateway shuts down");
    }

    #[test]
    fn tls_handshake_gate_rejects_excess_work_without_waiting() {
        let metrics = Metrics::default();
        let transport = metrics.listener_transport("secure");
        let gate = Arc::new(Semaphore::new(1));

        let first = reserve_tls_handshake(ListenerProtocol::Https, &gate, &transport)
            .expect("the first TLS handshake receives the only permit")
            .expect("HTTPS reserves a handshake permit");
        assert_eq!(gate.available_permits(), 0);
        assert!(
            reserve_tls_handshake(ListenerProtocol::Https, &gate, &transport).is_err(),
            "an excess handshake must fail immediately instead of joining a queue"
        );

        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                "oxidase_tls_handshakes_total{listener=\"secure\",result=\"overloaded\"} 1"
            ),
            "{rendered}"
        );

        drop(first);
        assert_eq!(gate.available_permits(), 1);
        let plain = reserve_tls_handshake(ListenerProtocol::Http, &gate, &transport)
            .expect("plain HTTP never consumes the TLS gate");
        assert!(plain.is_none());
        assert_eq!(gate.available_permits(), 1);
    }

    #[test]
    fn h2_only_listener_requires_matching_alpn() {
        let h2_only = [HttpVersion::H2];
        assert_eq!(
            select_https_protocol(&h2_only, Some(b"h2")),
            Ok(NegotiatedHttpProtocol::H2)
        );
        assert_eq!(
            select_https_protocol(&h2_only, None),
            Err(AlpnSelectionError::Required)
        );
        assert_eq!(
            select_https_protocol(&h2_only, Some(b"http/1.1")),
            Err(AlpnSelectionError::Mismatch)
        );
        assert_eq!(
            select_https_protocol(&[HttpVersion::Http1], None),
            Ok(NegotiatedHttpProtocol::Http1)
        );
    }

    #[test]
    fn rustls_no_application_protocol_is_a_distinct_h2_only_result() {
        let error = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            tokio_rustls::rustls::Error::NoApplicationProtocol,
        );
        assert_eq!(
            tls_accept_error_outcome(&error, true),
            TlsHandshakeOutcome::AlpnMismatch
        );
        assert_eq!(
            tls_accept_error_outcome(&error, false),
            TlsHandshakeOutcome::Protocol
        );
    }

    #[tokio::test]
    async fn http2_request_and_header_limits_apply_before_service_execution() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "ok", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("fixture config compiles"),
        )
        .expect("fixture snapshot prepares");
        let metrics = Arc::new(Metrics::default());
        let mut context = h2_connection_context(snapshot, metrics);
        context.limits.max_requests_per_connection = 2;
        context.limits.max_headers = 1;
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(serve_http2_connection(
            server_io,
            context,
            h2_settings(),
            receiver,
        ));
        let (mut sender, client_connection) =
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("HTTP/2 client handshake succeeds");
        let client_task = tokio::spawn(client_connection);

        let too_many_headers = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.test/headers")
            .header("x-one", "1")
            .header("x-two", "2")
            .body(Empty::new())
            .expect("header overflow request is valid");
        let response = sender
            .send_request(too_many_headers)
            .await
            .expect("header overflow receives a response");
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        response
            .into_body()
            .collect()
            .await
            .expect("header overflow response body is readable");

        let response = sender
            .send_request(h2_request("/allowed"))
            .await
            .expect("last allowed stream receives a response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .expect("last allowed response body is readable")
                .to_bytes(),
            Bytes::from_static(b"ok")
        );
        wait_for_h2_goaway(&mut sender).await;

        drop(sender);
        let _ = shutdown.send(true);
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("limited HTTP/2 server finishes")
            .expect("limited HTTP/2 server task joins");
        tokio::time::timeout(Duration::from_secs(1), client_task)
            .await
            .expect("limited HTTP/2 client finishes")
            .expect("limited HTTP/2 client task joins")
            .expect("limited HTTP/2 client connection closes cleanly");
    }

    #[tokio::test]
    async fn http2_graceful_shutdown_allows_an_active_stream_to_finish() {
        let (upstream, request_started, release_response, upstream_shutdown, upstream_task) =
            spawn_blocked_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_blocked_proxy_gateway(&config, upstream);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let metrics = Arc::new(Metrics::default());
        let context = h2_connection_context(snapshot, metrics.clone());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(serve_http2_connection(
            server_io,
            context,
            h2_settings(),
            receiver,
        ));
        let (mut sender, client_connection) =
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("HTTP/2 client handshake succeeds");
        let client_task = tokio::spawn(client_connection);
        let mut shutdown_probe = sender.clone();
        let response_task = tokio::spawn(async move {
            let response = sender
                .send_request(h2_request("/blocked"))
                .await
                .expect("active stream receives a response head");
            response
                .into_body()
                .collect()
                .await
                .expect("active stream body is readable")
                .to_bytes()
        });

        tokio::time::timeout(Duration::from_secs(1), request_started.notified())
            .await
            .expect("active stream reaches the blocked upstream");
        shutdown
            .send(true)
            .expect("connection shutdown can be signaled");
        wait_for_h2_goaway(&mut shutdown_probe).await;
        release_response.notify_one();

        let body = tokio::time::timeout(Duration::from_secs(1), response_task)
            .await
            .expect("active stream finishes inside the drain window")
            .expect("active stream task joins");
        assert_eq!(body, Bytes::from_static(b"released"));
        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("HTTP/2 server finishes graceful shutdown")
            .expect("HTTP/2 server task joins");
        tokio::time::timeout(Duration::from_secs(1), client_task)
            .await
            .expect("HTTP/2 client observes graceful connection completion")
            .expect("HTTP/2 client task joins")
            .expect("HTTP/2 client connection closes cleanly");

        let rendered = metrics.render_prometheus();
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"graceful\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"forced\"} 0"),
            "{rendered}"
        );
        assert!(
            rendered.contains("oxidase_http2_active_streams{listener=\"test\"} 0"),
            "{rendered}"
        );

        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("blocked upstream shuts down");
    }

    #[tokio::test]
    async fn aborting_an_http2_drain_cancels_streams_and_records_forced_shutdown() {
        let (upstream, request_started, _release_response, upstream_shutdown, upstream_task) =
            spawn_blocked_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_blocked_proxy_gateway(&config, upstream);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let metrics = Arc::new(Metrics::default());
        let context = h2_connection_context(snapshot, metrics.clone());
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (shutdown, receiver) = watch::channel(false);
        let server_task = tokio::spawn(serve_http2_connection(
            server_io,
            context,
            h2_settings(),
            receiver,
        ));
        let (mut sender, client_connection) =
            client_http2::handshake(TokioExecutor::new(), TokioIo::new(client_io))
                .await
                .expect("HTTP/2 client handshake succeeds");
        let client_task = tokio::spawn(client_connection);
        let mut shutdown_probe = sender.clone();
        let response_task = tokio::spawn(async move {
            let response = sender
                .send_request(h2_request("/blocked"))
                .await
                .map_err(|error| error.to_string())?;
            response
                .into_body()
                .collect()
                .await
                .map(|body| body.to_bytes())
                .map_err(|error| error.to_string())
        });

        tokio::time::timeout(Duration::from_secs(1), request_started.notified())
            .await
            .expect("active stream reaches the blocked upstream");
        shutdown
            .send(true)
            .expect("connection shutdown can be signaled");
        wait_for_h2_goaway(&mut shutdown_probe).await;
        server_task.abort();
        let join_error = server_task
            .await
            .expect_err("drain timeout aborts the HTTP/2 connection task");
        assert!(join_error.is_cancelled());

        let response = tokio::time::timeout(Duration::from_secs(1), response_task)
            .await
            .expect("forced drain terminates the active stream")
            .expect("active stream task joins");
        assert!(
            response.is_err(),
            "forced stream must not complete normally"
        );
        let _ = tokio::time::timeout(Duration::from_secs(1), client_task)
            .await
            .expect("HTTP/2 client connection exits after forced drain")
            .expect("HTTP/2 client task joins");

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let rendered = metrics.render_prometheus();
                if rendered.contains("oxidase_http2_active_streams{listener=\"test\"} 0") {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("forced drain releases every HTTP/2 stream guard");
        let rendered = metrics.render_prometheus();
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"graceful\"} 0"),
            "{rendered}"
        );
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"forced\"} 1"),
            "{rendered}"
        );

        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("blocked upstream shuts down");
    }

    #[test]
    fn dropping_an_incomplete_h2_drain_records_a_forced_shutdown() {
        let metrics = Arc::new(Metrics::default());
        let mut drain = H2DrainObservation::new(metrics.listener_transport("test"));
        drain.started = true;
        drop(drain);

        let rendered = metrics.render_prometheus();
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"forced\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered
                .contains("oxidase_http2_shutdown_total{listener=\"test\",result=\"graceful\"} 0"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn finalizes_status_and_head_framing_on_the_wire() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  root:
    type: route
    cases:
      - when:
          path: /informational
        service:
          type: respond
          status: 101
          body:
            text: forbidden-101
      - when:
          path: /no-content
        service:
          type: respond
          status: 204
          body:
            text: forbidden-204
      - when:
          path: /not-modified
        service:
          type: respond
          status: 304
          body:
            text: forbidden-304
      - when:
          path: /reset-content
        service:
          type: respond
          status: 205
          body:
            text: forbidden-205
    default:
      type: respond
      body:
        text: hello
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("gateway config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway config compiles"),
        )
        .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        for (path, status) in [
            ("/informational", "101 Switching Protocols"),
            ("/no-content", "204 No Content"),
            ("/not-modified", "304 Not Modified"),
        ] {
            let response = tokio::time::timeout(Duration::from_secs(1), request(address, path, ""))
                .await
                .expect("wire response completes");
            let (headers, body) = raw_response_parts(&response);
            assert!(headers.starts_with(&format!("HTTP/1.1 {status}")));
            let headers = headers.to_ascii_lowercase();
            assert!(!headers.contains("content-length:"));
            assert!(!headers.contains("transfer-encoding:"));
            assert!(body.is_empty());
        }

        let reset = request(address, "/reset-content", "").await;
        let (headers, body) = raw_response_parts(&reset);
        assert!(headers.starts_with("HTTP/1.1 205 Reset Content"));
        assert!(
            raw_header_values(&reset, "content-length")
                .iter()
                .all(|value| value == "0")
        );
        assert!(!headers.to_ascii_lowercase().contains("transfer-encoding:"));
        assert!(body.is_empty());

        let response = raw_request(
            address,
            "HEAD /head HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (headers, body) = raw_response_parts(&response);
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        assert!(headers.to_ascii_lowercase().contains("content-length: 5"));
        assert!(body.is_empty());

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn custom_site_404_preserves_template_metadata_for_head() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir_all(site.join("_templates")).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            r#"oxista: site/v1
paths:
  missing: respond
templates:
  roots: [_templates]
  default_output: text
defaults:
  response:
    headers:
      set:
        X-Error-Policy: applied
errors:
  404:
    template: _templates/404.oxt
"#,
        )
        .expect("manifest can be written");
        fs::write(
            site.join("_templates/404.oxt"),
            "---\noxista: template/v1\n---\nnot-found\n",
        )
        .expect("404 template can be written");
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
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway config compiles"),
        )
        .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let get = request(address, "/missing", "").await;
        assert!(get.starts_with("HTTP/1.1 404 Not Found"));
        assert_eq!(
            raw_header(&get, "content-type"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(raw_header(&get, "x-error-policy"), "applied");
        assert!(get.ends_with("not-found\n"));

        let head = raw_request(
            address,
            "HEAD /missing HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (headers, body) = raw_response_parts(&head);
        assert!(headers.starts_with("HTTP/1.1 404 Not Found"));
        assert!(headers.to_ascii_lowercase().contains("content-length: 10"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("x-error-policy: applied")
        );
        assert!(body.is_empty());

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn streams_asset_and_honors_single_range() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\npaths:\n  missing: decline\n",
        )
        .expect("manifest can be written");
        fs::write(site.join("large.bin"), b"abcdefghij").expect("asset can be written");
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
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("config compiles"))
                .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("server binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let response = request(address, "/large.bin", "Range: bytes=2-5\r\n").await;
        assert!(response.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(
            response
                .to_ascii_lowercase()
                .contains("content-range: bytes 2-5/10")
        );
        assert!(response.ends_with("cdef"));
        let head = raw_request(
            address,
            "HEAD /large.bin HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (headers, body) = raw_response_parts(&head);
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        assert!(headers.to_ascii_lowercase().contains("content-length: 10"));
        assert!(body.is_empty());
        running.shutdown().await.expect("server shuts down cleanly");
    }

    #[tokio::test]
    async fn negotiates_asset_representations_validators_and_if_range() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(
            site.join("site.oxsite"),
            r#"oxista: site/v1
assets:
  precompressed:
    brotli: .br
    gzip: .gz
defaults:
  response:
    headers:
      set:
        Vary: Origin
        Cache-Control: "public, max-age=60"
  by_extension:
    ".css":
      headers:
        set:
          X-Logical-Extension: css
"#,
        )
        .expect("manifest can be written");
        fs::write(site.join("asset.txt"), "identity-v1").expect("identity can be written");
        fs::write(site.join("copy.txt"), "identity-v1").expect("copy can be written");
        fs::write(site.join("asset.txt.br"), "brotli-v1").expect("Brotli can be written");
        fs::write(site.join("asset.txt.gz"), "gzip-v1").expect("gzip can be written");
        fs::write(site.join("style.css"), "style-identity").expect("CSS can be written");
        fs::write(site.join("style.css.br"), "style-brotli")
            .expect("compressed CSS can be written");
        fs::write(
            site.join("asset.txt.oxr"),
            r#"---
oxista: response/v1
response:
  content_type: application/x-asset
  body:
    asset: sibling
---
"#,
        )
        .expect("OXR can be written");
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
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway config compiles"),
        )
        .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let compressed_css = request(address, "/style.css", "Accept-Encoding: br\r\n").await;
        assert!(compressed_css.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(raw_header(&compressed_css, "content-encoding"), "br");
        assert_eq!(raw_header(&compressed_css, "x-logical-extension"), "css");
        assert!(compressed_css.ends_with("style-brotli"));

        let identity = request(address, "/asset.txt", "").await;
        assert!(identity.starts_with("HTTP/1.1 200 OK"));
        assert!(identity.ends_with("identity-v1"));
        assert_eq!(raw_header(&identity, "content-type"), "application/x-asset");
        let identity_etag = raw_header(&identity, "etag");
        assert!(identity_etag.starts_with("\"sha256-"));
        assert_eq!(identity_etag.len(), "\"sha256-\"".len() + 64);
        let copy = request(address, "/copy.txt", "").await;
        assert_eq!(raw_header(&copy, "etag"), identity_etag);
        let identity_modified = raw_header(&identity, "last-modified");

        let brotli = request(address, "/asset.txt", "Accept-Encoding: br\r\n").await;
        assert!(brotli.ends_with("brotli-v1"));
        assert_eq!(raw_header(&brotli, "content-encoding"), "br");
        let brotli_etag = raw_header(&brotli, "etag");

        let gzip = request(address, "/asset.txt", "Accept-Encoding: gzip\r\n").await;
        assert!(gzip.ends_with("gzip-v1"));
        assert_eq!(raw_header(&gzip, "content-encoding"), "gzip");
        let gzip_etag = raw_header(&gzip, "etag");
        assert_ne!(identity_etag, brotli_etag);
        assert_ne!(identity_etag, gzip_etag);
        assert_ne!(brotli_etag, gzip_etag);

        let vary = raw_header_values(&brotli, "vary").join(",");
        assert!(vary.to_ascii_lowercase().contains("origin"));
        assert_eq!(
            vary.split(',')
                .filter(|value| value.trim().eq_ignore_ascii_case("accept-encoding"))
                .count(),
            1
        );

        let preferred = request(
            address,
            "/asset.txt",
            "Accept-Encoding: br;q=0.2, gzip;q=1\r\n",
        )
        .await;
        assert_eq!(raw_header(&preferred, "content-encoding"), "gzip");
        assert!(preferred.ends_with("gzip-v1"));
        let excluded = request(
            address,
            "/asset.txt",
            "Accept-Encoding: br;q=0, gzip;q=0, identity;q=0\r\n",
        )
        .await;
        assert!(excluded.starts_with("HTTP/1.1 406 Not Acceptable"));
        let malformed = request(
            address,
            "/asset.txt",
            "Accept-Encoding: br;level=9;q=1, gzip;q=0, identity;q=0\r\n",
        )
        .await;
        assert!(malformed.starts_with("HTTP/1.1 406 Not Acceptable"));

        let not_modified = request(
            address,
            "/asset.txt",
            &format!("Accept-Encoding: br\r\nIf-None-Match: {brotli_etag}\r\n"),
        )
        .await;
        let (headers, body) = raw_response_parts(&not_modified);
        assert!(headers.starts_with("HTTP/1.1 304 Not Modified"));
        assert!(body.is_empty());
        assert_eq!(raw_header(&not_modified, "etag"), brotli_etag);
        assert_eq!(raw_header(&not_modified, "content-encoding"), "br");
        assert_eq!(
            raw_header(&not_modified, "cache-control"),
            "public, max-age=60"
        );
        assert!(!raw_header_values(&not_modified, "last-modified").is_empty());
        assert!(!raw_header_values(&not_modified, "vary").is_empty());

        let weak_candidate = format!("W/{identity_etag}");
        let weak_match = request(
            address,
            "/asset.txt",
            &format!("If-None-Match: {weak_candidate}\r\n"),
        )
        .await;
        assert!(weak_match.starts_with("HTTP/1.1 304 Not Modified"));

        let precedence = request(
            address,
            "/asset.txt",
            &format!("If-None-Match: \"different\"\r\nIf-Modified-Since: {identity_modified}\r\n"),
        )
        .await;
        assert!(precedence.starts_with("HTTP/1.1 200 OK"));
        assert!(precedence.ends_with("identity-v1"));

        let matching_range = request(
            address,
            "/asset.txt",
            &format!("Range: bytes=2-5\r\nIf-Range: {identity_etag}\r\n"),
        )
        .await;
        assert!(matching_range.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(matching_range.ends_with("enti"));
        let mismatching_range = request(
            address,
            "/asset.txt",
            "Range: bytes=2-5\r\nIf-Range: \"different\"\r\n",
        )
        .await;
        assert!(mismatching_range.starts_with("HTTP/1.1 200 OK"));
        assert!(mismatching_range.ends_with("identity-v1"));
        let matching_date = request(
            address,
            "/asset.txt",
            &format!("Range: bytes=-3\r\nIf-Range: {identity_modified}\r\n"),
        )
        .await;
        assert!(matching_date.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(matching_date.ends_with("-v1"));
        let stale_date = request(
            address,
            "/asset.txt",
            "Range: bytes=-3\r\nIf-Range: Sun, 06 Nov 1994 08:49:37 GMT\r\n",
        )
        .await;
        assert!(stale_date.starts_with("HTTP/1.1 200 OK"));

        let range_ignores_compression = request(
            address,
            "/asset.txt",
            "Accept-Encoding: br\r\nRange: bytes=0-2\r\n",
        )
        .await;
        assert!(range_ignores_compression.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(raw_header_values(&range_ignores_compression, "content-encoding").is_empty());
        assert!(range_ignores_compression.ends_with("ide"));

        let head_range = raw_request(
            address,
            &format!(
                "HEAD /asset.txt HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\nRange: bytes=2-5\r\nIf-Range: {identity_etag}\r\n\r\n"
            ),
        )
        .await;
        let (headers, body) = raw_response_parts(&head_range);
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        assert!(headers.to_ascii_lowercase().contains("content-length: 11"));
        assert!(!headers.to_ascii_lowercase().contains("content-range:"));
        assert!(body.is_empty());

        let compressed_head_range = raw_request(
            address,
            &format!(
                "HEAD /asset.txt HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\nAccept-Encoding: br\r\nRange: bytes=2-5\r\nIf-Range: {identity_etag}\r\n\r\n"
            ),
        )
        .await;
        let (headers, body) = raw_response_parts(&compressed_head_range);
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        assert!(
            headers
                .to_ascii_lowercase()
                .contains("content-encoding: br")
        );
        assert!(headers.to_ascii_lowercase().contains("content-length: 9"));
        assert!(!headers.to_ascii_lowercase().contains("content-range:"));
        assert!(body.is_empty());

        for value in ["items=0-10", "bytes=abc", "bytes=-", "bytes=0-1,4-5"] {
            let ignored = request(
                address,
                "/asset.txt",
                &format!("Accept-Encoding: br\r\nRange: {value}\r\n"),
            )
            .await;
            assert!(ignored.starts_with("HTTP/1.1 200 OK"), "{value}: {ignored}");
            assert_eq!(raw_header(&ignored, "content-encoding"), "br");
            assert!(raw_header_values(&ignored, "content-range").is_empty());
            assert!(ignored.ends_with("brotli-v1"));
        }

        let unsatisfiable = request(address, "/asset.txt", "Range: bytes=99-100\r\n").await;
        assert!(unsatisfiable.starts_with("HTTP/1.1 416 Range Not Satisfiable"));
        assert_eq!(raw_header(&unsatisfiable, "content-range"), "bytes */11");

        let compressed_range = request(
            address,
            "/asset.txt",
            "Accept-Encoding: br, identity;q=0\r\nRange: bytes=0-2\r\n",
        )
        .await;
        assert!(compressed_range.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(raw_header(&compressed_range, "content-encoding"), "br");
        assert!(raw_header_values(&compressed_range, "content-range").is_empty());
        assert!(compressed_range.ends_with("brotli-v1"));

        fs::write(site.join("asset.txt.br"), "brotli-v2-changed")
            .expect("Brotli representation can change");
        running
            .reload_path(&config)
            .await
            .expect("changed representation reloads");
        let changed = request(address, "/asset.txt", "Accept-Encoding: br\r\n").await;
        assert_ne!(raw_header(&changed, "etag"), brotli_etag);
        assert!(changed.ends_with("brotli-v2-changed"));

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn hides_dynamic_template_type_errors_behind_safe_500() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir_all(site.join("_templates")).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            "oxista: site/v1\ntemplates:\n  roots: [_templates]\n",
        )
        .expect("manifest can be written");
        fs::write(
            site.join("_templates/value.oxt"),
            r#"---
oxista: template/v1
params:
  count: int
---
{{ count }}
"#,
        )
        .expect("typed child template can be written");
        fs::write(
            site.join("_templates/card.oxt"),
            r#"---
oxista: template/v1
---
{% include "_templates/value.oxt" with count=page.count only %}
"#,
        )
        .expect("include caller template can be written");
        fs::write(
            site.join("index.oxr"),
            r#"---
oxista: response/v1
page:
  count: wrong
response:
  body:
    template:
      source: _templates/card.oxt
---
"#,
        )
        .expect("OXR can be written");
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
    type: recover
    service:
      type: site
      site: web
    handlers:
      - classes: [template_limit]
        service:
          type: respond
          body:
            text: unexpected-limit-recovery
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("gateway config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway config compiles"),
        )
        .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let response = request(address, "/index", "").await;
        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(response.ends_with("Internal Server Error"));
        assert!(!response.contains("unexpected-limit-recovery"));
        assert!(!response.contains("parameter `count`"));
        assert!(!response.contains("expects int"));

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn recover_catches_only_structured_template_limits() {
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir_all(site.join("_templates")).expect("template directory can be created");
        fs::write(
            site.join("site.oxsite"),
            r#"oxista: site/v1
templates:
  roots: [_templates]
  limits:
    output_size: 16B
    loop_iterations: 1
"#,
        )
        .expect("manifest can be written");
        fs::write(
            site.join("_templates/output.oxt"),
            "---\noxista: template/v1\noutput: text\n---\nthis-output-is-longer-than-sixteen-bytes\n",
        )
        .expect("output template can be written");
        fs::write(
            site.join("_templates/loop.oxt"),
            r#"---
oxista: template/v1
output: text
---
{% for item in page.items %}x{% endfor %}
"#,
        )
        .expect("loop template can be written");
        fs::write(
            site.join("output.oxr"),
            r#"---
oxista: response/v1
response:
  body:
    template:
      source: _templates/output.oxt
---
"#,
        )
        .expect("output OXR can be written");
        fs::write(
            site.join("loop.oxr"),
            r#"---
oxista: response/v1
page:
  items: [one, two]
response:
  body:
    template:
      source: _templates/loop.oxt
---
"#,
        )
        .expect("loop OXR can be written");
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
    type: recover
    service:
      type: site
      site: web
    handlers:
      - classes: [template_limit]
        service:
          type: respond
          status: 503
          body:
            text: recovered-template-limit
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("gateway config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("gateway config compiles"),
        )
        .expect("snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        for path in ["/output", "/loop"] {
            let response = request(address, path, "").await;
            assert!(
                response.starts_with("HTTP/1.1 503 Service Unavailable"),
                "{path}: {response}"
            );
            assert!(response.ends_with("recovered-template-limit"));
            assert!(!response.contains("_templates/"));
        }

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn upstream_mid_body_disconnect_is_streamed_as_body_error_and_pool_recovers() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("raw upstream binds");
        let upstream_address = upstream.local_addr().expect("upstream address is known");
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_for_task = accepts.clone();
        let upstream_task = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = upstream.accept().await.expect("gateway connects upstream");
                accepts_for_task.fetch_add(1, Ordering::Relaxed);
                let _ = read_until_contains(&mut stream, "\r\n\r\n").await;
                if attempt == 0 {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: keep-alive\r\n\r\nabc",
                        )
                        .await
                        .expect("partial upstream body can be written");
                    // Drop before the declared Content-Length is complete.
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await
                        .expect("healthy upstream response can be written");
                }
            }
        });

        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_proxy_gateway(&config, upstream_address, "1s");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");

        let truncated = raw_request_allow_disconnect(
            address,
            "GET /broken HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(truncated.starts_with("HTTP/1.1 200 OK"), "{truncated}");
        assert!(truncated.contains("abc"), "{truncated}");
        assert!(!truncated.contains("502 Bad Gateway"));

        let healthy = request(address, "/healthy", "").await;
        assert!(healthy.starts_with("HTTP/1.1 200 OK"), "{healthy}");
        assert!(healthy.ends_with("ok"), "{healthy}");
        upstream_task.await.expect("raw upstream task completes");
        assert_eq!(accepts.load(Ordering::Relaxed), 2);

        let metrics = request(admin, "/metrics", "").await;
        assert!(metrics.contains("oxidase_response_body_terminations_total{reason=\"error\"} 1"));
        assert!(metrics.contains("oxidase_active_requests 0"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn upstream_body_timeout_is_idle_between_frames_not_response_head_timeout() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("raw upstream binds");
        let upstream_address = upstream.local_addr().expect("upstream address is known");
        let upstream_task = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = upstream.accept().await.expect("gateway connects upstream");
                let request = read_until_contains(&mut stream, "\r\n\r\n").await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("upstream response head can be written");
                stream
                    .write_all(b"3\r\none\r\n")
                    .await
                    .expect("first body frame can be written");
                if attempt == 0 {
                    assert!(request.starts_with("GET /paced "));
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    stream
                        .write_all(b"3\r\ntwo\r\n0\r\n\r\n")
                        .await
                        .expect("paced body completes");
                } else {
                    assert!(request.starts_with("GET /stalled "));
                    tokio::time::sleep(Duration::from_millis(180)).await;
                    let _ = stream.write_all(b"0\r\n\r\n").await;
                }
            }
        });

        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_proxy_gateway(&config, upstream_address, "80ms");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");

        let paced = request(address, "/paced", "").await;
        assert!(paced.starts_with("HTTP/1.1 200 OK"), "{paced}");
        assert!(paced.contains("one"), "{paced}");
        assert!(paced.contains("two"), "{paced}");

        let stalled = raw_request_allow_disconnect(
            address,
            "GET /stalled HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(stalled.starts_with("HTTP/1.1 200 OK"), "{stalled}");
        assert!(stalled.contains("one"), "{stalled}");
        upstream_task.await.expect("upstream fixture completes");
        let metrics = request(admin, "/metrics", "").await;
        assert!(metrics.contains("oxidase_response_body_terminations_total{reason=\"timeout\"} 1"));
        assert!(metrics.contains("oxidase_active_requests 0"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn client_download_disconnect_cancels_upstream_body_and_releases_request() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("raw upstream binds");
        let upstream_address = upstream.local_addr().expect("upstream address is known");
        let (cancelled_sender, cancelled_receiver) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("gateway connects upstream");
            let _ = read_until_contains(&mut stream, "\r\n\r\n").await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .expect("upstream response head can be written");
            let chunk = vec![b'a'; 64 * 1024];
            for _ in 0..256 {
                if stream.write_all(b"10000\r\n").await.is_err()
                    || stream.write_all(&chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                {
                    let _ = cancelled_sender.send(true);
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            let _ = cancelled_sender.send(false);
        });

        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_proxy_gateway(&config, upstream_address, "1s");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");

        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("download client connects");
        client
            .write_all(
                b"GET /download HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n",
            )
            .await
            .expect("download request can be written");
        let partial = read_until_contains(&mut client, "aaaa").await;
        assert!(partial.starts_with("HTTP/1.1 200 OK"), "{partial}");
        drop(client);

        assert!(
            tokio::time::timeout(Duration::from_secs(3), cancelled_receiver)
                .await
                .expect("upstream cancellation is observed")
                .expect("cancellation fixture reports")
        );
        upstream_task.await.expect("upstream fixture completes");
        let metrics = request(admin, "/metrics", "").await;
        assert!(
            metrics.contains("oxidase_response_body_terminations_total{reason=\"cancelled\"} 1")
        );
        assert!(metrics.contains("oxidase_active_requests 0"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn client_upload_disconnect_cancels_upstream_request_and_pool_remains_usable() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("raw upstream binds");
        let upstream_address = upstream.local_addr().expect("upstream address is known");
        let (upload_sender, upload_receiver) = oneshot::channel();
        let upstream_task = tokio::spawn(async move {
            let (mut first, _) = upstream.accept().await.expect("first upstream connects");
            let initial = read_until_contains(&mut first, "\r\n\r\n").await;
            let mut received = initial
                .split_once("\r\n\r\n")
                .map_or(0, |(_, body)| body.len());
            let mut buffer = [0u8; 4096];
            loop {
                match first.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => received += read,
                }
            }
            let _ = upload_sender.send(received);

            let (mut second, _) = upstream.accept().await.expect("second upstream connects");
            let _ = read_until_contains(&mut second, "\r\n\r\n").await;
            second
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("healthy upstream response can be written");
        });

        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_proxy_gateway(&config, upstream_address, "1s");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");

        let mut client = tokio::net::TcpStream::connect(address)
            .await
            .expect("upload client connects");
        client
            .write_all(
                b"POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1048576\r\nConnection: keep-alive\r\n\r\npartial-upload",
            )
            .await
            .expect("partial upload can be written");
        tokio::time::sleep(Duration::from_millis(30)).await;
        drop(client);

        let received = tokio::time::timeout(Duration::from_secs(3), upload_receiver)
            .await
            .expect("upstream observes upload cancellation")
            .expect("upload fixture reports byte count");
        assert!(received < 1_048_576);

        let healthy = request(address, "/after-upload", "").await;
        assert!(healthy.starts_with("HTTP/1.1 200 OK"), "{healthy}");
        assert!(healthy.ends_with("ok"), "{healthy}");
        upstream_task.await.expect("upstream fixture completes");
        let metrics = request(admin, "/metrics", "").await;
        assert!(metrics.contains("oxidase_active_requests 0"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    #[ignore = "manual proxy/reload/fd soak; set OXIDASE_SOAK_ITERATIONS and use --nocapture"]
    async fn manual_proxy_reload_keepalive_and_cancellation_soak() {
        let iterations = std::env::var("OXIDASE_SOAK_ITERATIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(100);
        let (upstream, _, upstream_shutdown, upstream_task) = spawn_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let site = directory.path().join("site");
        fs::create_dir(&site).expect("site directory can be created");
        fs::write(site.join("site.oxsite"), "oxista: site/v1\n")
            .expect("site manifest can be written");
        fs::write(site.join("large.bin"), vec![b'a'; 8 * 1024 * 1024])
            .expect("large soak asset can be written");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    upstream:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
  sites:
    files:
      root: site
services:
  root:
    type: route
    cases:
      - when:
          path: /large.bin
        service:
          type: site
          site: files
    default:
      type: proxy
      cluster: upstream
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("soak gateway config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("soak config compiles"),
        )
        .expect("soak snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("soak gateway binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind is valid"))
            .await
            .expect("admin listener binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin address is available");
        let mut keep_alive = tokio::net::TcpStream::connect(address)
            .await
            .expect("keep-alive client connects");

        for iteration in 0..iterations {
            keep_alive
                .write_all(
                    format!(
                        "GET /soak/{iteration} HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .expect("keep-alive request can be written");
            let response = read_http1_response(&mut keep_alive).await;
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");

            if iteration % 10 == 9 {
                running
                    .reload_path(&config)
                    .await
                    .expect("unchanged soak reload succeeds");
            }
            if iteration % 20 == 19 {
                let mut cancelled = tokio::net::TcpStream::connect(address)
                    .await
                    .expect("cancel client connects");
                cancelled
                    .write_all(
                        b"GET /slow HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await
                    .expect("cancel request can be written");
                drop(cancelled);

                let mut asset_client = tokio::net::TcpStream::connect(address)
                    .await
                    .expect("asset client connects");
                asset_client
                    .write_all(
                        b"GET /large.bin HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n",
                    )
                    .await
                    .expect("asset request can be written");
                let _ = read_until_contains(&mut asset_client, "aaaa").await;
                drop(asset_client);
            }
        }
        drop(keep_alive);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let metrics = request(admin, "/metrics", "").await;
        assert!(metrics.contains("oxidase_active_requests 0"), "{metrics}");
        eprintln!("completed {iterations} keep-alive proxy iterations with periodic reload/cancel");
        running.shutdown().await.expect("soak gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("soak upstream shuts down");
    }

    #[tokio::test]
    async fn proxies_streaming_bodies_with_pooling_headers_and_timeout() {
        let (upstream, accepts, upstream_shutdown, upstream_task) = spawn_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://{upstream}
      connect_timeout: 25ms
      response_timeout: 25ms
services:
  root:
    type: transform
    request:
      scheme: https
      authority: "[::1]:8443"
    service:
      type: proxy
      cluster: api
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("proxy config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("proxy config compiles"),
        )
        .expect("proxy snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        let first = raw_request(
            address,
            "POST /upload?b=2&a=1 HTTP/1.1\r\nHost: incoming.test\r\nConnection: close, x-hop\r\nX-Hop: remove-me\r\nContent-Length: 6\r\n\r\nstream",
        )
        .await;
        assert!(first.starts_with("HTTP/1.1 200 OK"));
        assert!(first.ends_with(&format!(
            "/upload?b=2&a=1|stream|{upstream}|127.0.0.1|false"
        )));
        let first_lower = first.to_ascii_lowercase();
        assert!(first_lower.contains("x-keep: kept"));
        assert!(!first_lower.contains("x-remove: secret"));
        assert!(
            first_lower
                .contains("x-seen-forwarded: for=\"127.0.0.1\";proto=http;host=\"incoming.test\"")
        );

        let second = request(address, "/second", "").await;
        assert!(second.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

        let head = raw_request(
            address,
            "HEAD /second HTTP/1.1\r\nHost: incoming.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let (headers, body) = raw_response_parts(&head);
        assert!(headers.starts_with("HTTP/1.1 200 OK"));
        assert!(!headers.to_ascii_lowercase().contains("content-length:"));
        assert!(body.is_empty());

        let timeout = request(address, "/slow", "").await;
        assert!(timeout.starts_with("HTTP/1.1 504 Gateway Timeout"));
        assert!(timeout.ends_with("Gateway Timeout"));

        running.shutdown().await.expect("gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream task shuts down");
    }

    #[tokio::test]
    async fn reload_is_atomic_and_manages_listener_lifecycle() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "one", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        assert!(request(address, "/", "").await.ends_with("one"));

        write_respond_gateway(&config, "two", None);
        let report = running.reload_path(&config).await.expect("reload commits");
        assert_eq!(report.listeners_retained, vec!["test"]);
        assert!(request(address, "/", "").await.ends_with("two"));
        let last_good = report.current_version;

        fs::write(
            &config,
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nunknown: true\n",
        )
        .expect("invalid config can be written");
        let error = running
            .reload_path(&config)
            .await
            .expect_err("invalid reload must be rejected");
        let diagnostics = error.diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "source.parse");
        assert_eq!(diagnostics[0].primary.line, 3);
        assert_eq!(
            running
                .reload_handle()
                .current_snapshot()
                .config_version
                .as_str(),
            last_good
        );
        assert!(request(address, "/", "").await.ends_with("two"));

        write_respond_gateway(&config, "two", Some(&address.to_string()));
        assert!(running.reload_path(&config).await.is_err());
        assert!(request(address, "/", "").await.ends_with("two"));

        write_respond_gateway(&config, "three", Some("127.0.0.1:0"));
        let added = running
            .reload_path(&config)
            .await
            .expect("new listener is prepared and committed");
        assert_eq!(added.listeners_added, vec!["extra"]);
        assert_eq!(added.local_addresses.len(), 2);
        assert!(request(address, "/", "").await.ends_with("three"));

        write_respond_gateway(&config, "four", None);
        let removed = running
            .reload_path(&config)
            .await
            .expect("removed listener drains");
        assert_eq!(removed.listeners_removed, vec!["extra"]);
        assert!(request(address, "/", "").await.ends_with("four"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn successful_reload_reports_non_fatal_compiler_warnings() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "old", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;

        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - name: primary
          url: http://127.0.0.1:3000
      retry:
        max_attempts: 2
        methods: [POST]
        retry_on: [connect_failure]
services:
  root:
    type: respond
    body:
      text: warning-committed
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#,
        )
        .expect("warning candidate can be written");

        let report = running
            .reload_path(&config)
            .await
            .expect("warning does not reject reload");
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "resource.cluster_retry_post");
        assert_eq!(
            report.warnings[0].primary.field_path,
            "resources.clusters.api.retry.methods[0]"
        );
        assert!(
            request(address, "/", "")
                .await
                .ends_with("warning-committed")
        );

        running.shutdown().await.expect("gateway shuts down");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reload_reports_resource_warnings_and_keeps_sensitive_watcher_dependencies() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "old", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();

        let secret = directory.path().join("distinctive-reload-token.secret");
        fs::write(&secret, b"do-not-render-this-reload-token").expect("secret can be written");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o644))
            .expect("secret permissions can be set");
        fs::write(
            &config,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  secrets:
    admin-token:
      file: distinctive-reload-token.secret
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      type: respond
      body:
        text: committed
"#,
        )
        .expect("warning candidate can be written");

        let report = running
            .reload_path(&config)
            .await
            .expect("warning does not reject reload");
        assert_eq!(report.warnings.len(), 1);
        assert_eq!(report.warnings[0].code, "secret.file_permissions");
        let rendered = report
            .warnings
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!rendered.contains("do-not-render-this-reload-token"));
        assert!(!rendered.contains("distinctive-reload-token.secret"));
        let canonical_secret = secret.canonicalize().expect("secret path canonicalizes");
        assert!(
            running
                .reload_handle()
                .watched_dependencies()
                .contains(&canonical_secret)
        );
        assert!(
            running
                .reload_handle()
                .current_snapshot()
                .summary()
                .dependencies
                .iter()
                .all(|dependency| !dependency.contains("distinctive-reload-token.secret"))
        );

        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn stale_source_preparation_cannot_overwrite_a_bundle_publication() {
        let directory = tempdir().expect("temporary directory");
        let config = directory.path().join("source.yaml");
        let bundle_config = directory.path().join("bundle-fixture.yaml");
        write_respond_gateway(&config, "initial", None);
        write_respond_gateway(&bundle_config, "bundle", None);
        let prepare = |path: &std::path::Path| {
            RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("fixture compiles"))
                .expect("fixture prepares")
        };
        let running = GatewayServer::bind(prepare(&config))
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let reload = running.reload_handle();
        let initial_etag = reload.published_runtime().etag();
        let pause = reload.pause_test_preparation();
        write_respond_gateway(&config, "stale-source", None);
        let task = tokio::spawn({
            let reload = reload.clone();
            let config = config.clone();
            async move { reload.reload_watched_path(config).await }
        });
        reload.wait_test_preparation_started().await;
        reload
            .activate_prepared(
                prepare(&bundle_config),
                oxidase_runtime::ResourceReuse::default(),
                initial_etag.clone(),
                oxidase_runtime::RuntimeOrigin::Bundle {
                    digest: oxidase_core::ContentDigest::of_bytes(b"bundle"),
                },
            )
            .await
            .expect("Bundle publishes while source preparation is paused");
        assert!(request(address, "/", "").await.ends_with("bundle"));
        tokio::task::spawn_blocking(move || pause.wait())
            .await
            .expect("release preparation");
        assert!(matches!(
            task.await.expect("preparation task joins"),
            Err(super::ServerError::PreconditionFailed)
        ));
        assert!(request(address, "/", "").await.ends_with("bundle"));
        assert!(matches!(
            reload.reload_watched_path(&config).await,
            Err(super::ServerError::SourceAuthorityLost)
        ));
        assert!(matches!(
            reload.drain_data_plane(initial_etag).await,
            Err(super::ServerError::PreconditionFailed)
        ));
        running.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn drain_changes_readiness_and_watcher_cannot_reopen_listeners() {
        let directory = tempdir().expect("temporary directory");
        let config = directory.path().join("source.yaml");
        write_respond_gateway(&config, "active", None);
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("fixture compiles"))
                .expect("prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("binds")
            .with_admin_listener("127.0.0.1:0".parse().expect("admin bind"))
            .await
            .expect("admin binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let admin = running.admin_address().expect("admin available");
        let reload = running.reload_handle();
        reload
            .drain_data_plane(reload.published_runtime().etag())
            .await
            .expect("drain completes");
        assert_eq!(
            reload.published_runtime().serving_state,
            oxidase_runtime::ServingState::Drained
        );
        assert!(
            request(admin, "/health/live", "")
                .await
                .starts_with("HTTP/1.1 200")
        );
        assert!(
            request(admin, "/health/ready", "")
                .await
                .starts_with("HTTP/1.1 503")
        );
        assert!(tokio::net::TcpStream::connect(address).await.is_err());
        assert!(matches!(
            reload.reload_watched_path(&config).await,
            Err(super::ServerError::SourceAuthorityLost)
        ));
        reload
            .drain_data_plane(reload.published_runtime().etag())
            .await
            .expect("repeated drain");
        running.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn published_runtime_survives_caller_cancellation_and_completion_storage_failure() {
        let directory = tempdir().expect("temporary directory");
        let config = directory.path().join("source.yaml");
        write_respond_gateway(&config, "old", None);
        let prepare = || {
            RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("compiles"))
                .expect("prepares")
        };
        let store = std::sync::Arc::new(SnapshotStore::new(prepare()));
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical test root")
            .join("journal");
        let candidates = oxidase_runtime::CandidateStore::open(
            path.clone(),
            oxidase_runtime::CandidateStoreLimits::default(),
            oxidase_runtime::CandidateSignaturePolicy::require_trusted(Vec::new()),
            oxidase_bundle::BundleCapabilities::default(),
        )
        .expect("journal opens");
        let begin = candidates
            .begin_operation(
                &oxidase_runtime::CandidateOperationContext {
                    request_id: "fault-test".to_owned(),
                    principal: "internal:test".to_owned(),
                    if_match: Some(store.published().etag()),
                    idempotency_key: Some("fault".to_owned()),
                },
                oxidase_runtime::AuditAction::ReloadSource,
                None,
                None,
            )
            .expect("accepted");
        let operation = super::CommitOperation {
            store: candidates.clone(),
            operation_id: begin.receipt.operation_id.clone(),
            work: oxidase_runtime::CandidateWorkControl::with_deadline(
                std::time::Instant::now() + Duration::from_secs(30),
            ),
            audit: std::sync::Arc::new(std::sync::Mutex::new(None)),
        };
        write_respond_gateway(&config, "published", None);
        let dns_mode = Arc::new(AtomicUsize::new(0));
        let fixture_mode = Arc::clone(&dns_mode);
        let dns = crate::dns_test_fixture::DnsFixture::start(move |question, _| {
            use hickory_resolver::proto::op::ResponseCode;
            use hickory_resolver::proto::rr::{RData, Record, RecordType, rdata::A};
            if question.query_type() != RecordType::A {
                return crate::dns_test_fixture::FixtureReply::code(ResponseCode::NoError);
            }
            let last = if fixture_mode.load(Ordering::Acquire) == 0 {
                1
            } else {
                2
            };
            crate::dns_test_fixture::FixtureReply::answers(vec![Record::from_rdata(
                question.name().clone(),
                2,
                RData::A(A(std::net::Ipv4Addr::new(127, 0, 0, last))),
            )])
        })
        .await;
        let source = fs::read_to_string(&config).expect("published source");
        fs::write(&config, format!("{source}resources:\n  clusters:\n    api:\n      discovery:\n        dns:\n          name: recovery.example.invalid\n          port: 9\n          origin: http://fixed.example.invalid/base\n          resolver:\n            nameservers: [\"{}\"]\n            query_timeout: 500ms\n          refresh:\n            min_interval: 10ms\n            max_interval: 50ms\n            jitter_percent: 0\n          address_policy:\n            allow_loopback: true\n", dns.address)).expect("dynamic candidate source");
        let prepared = prepare();
        let metrics = std::sync::Arc::new(Metrics::default());
        let proxy = std::sync::Arc::new(ProxyClient::new().expect("proxy prepares"));
        let mut health =
            crate::cluster_health::ClusterHealthManager::new().expect("health manager prepares");
        let mut discovery = crate::discovery_manager::DiscoveryManager::new();
        let (completion, _) = tokio::sync::mpsc::unbounded_channel();
        let (response, received) = oneshot::channel();
        let cancelled_receiver = std::sync::Arc::new(std::sync::Mutex::new(Some(received)));
        let before = store.published().etag();
        let mut listeners = std::collections::BTreeMap::new();
        let mut generation = 1;
        let report = super::apply_reload(
            prepared,
            oxidase_runtime::ResourceReuse::default(),
            oxidase_runtime::RuntimeOrigin::Source,
            &mut listeners,
            &mut generation,
            super::ReloadEnvironment {
                store: &store,
                proxy: &proxy,
                metrics: &metrics,
                health: &mut health,
                discovery: &mut discovery,
                drain_timeout: Duration::from_millis(100),
                completion: &completion,
                expected_etag: &before,
                deadline: std::time::Instant::now() + Duration::from_secs(30),
                operation: Some(&operation),
                response: &response,
                after_publish: Some(Box::new(move || {
                    // Fault is injected only after the atomic runtime publication.
                    cancelled_receiver.lock().expect("test lock").take();
                    std::fs::rename(path.join("state.json"), path.join("saved-state.json"))
                        .expect("preserve intent");
                    std::fs::create_dir(path.join("state.json"))
                        .expect("force completion rename failure");
                })),
            },
        )
        .await
        .expect("publication is not misreported as failed");
        assert_ne!(store.published().etag(), before);
        let receipt = report.operation.expect("receipt is queryable");
        assert_eq!(
            receipt.phase,
            oxidase_runtime::OperationPhase::RecoveryRequired
        );
        assert_eq!(
            receipt.committed_revision,
            Some(store.published().runtime_revision)
        );
        assert!(candidates.ensure_mutations_allowed().is_err());
        let recovery_publication = store.published();
        let cluster = Arc::clone(
            recovery_publication
                .snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("discovery cluster"),
        );
        for expected in [1, 2] {
            if expected == 2 {
                dns_mode.store(1, Ordering::Release);
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if cluster.endpoints().first().is_some_and(|endpoint| {
                        endpoint.dial_target().is_some_and(|target| {
                            target.ip()
                                == std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                    127, 0, 0, expected,
                                ))
                        })
                    }) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect(
                "authorized LKG operational refresh continues despite durable recovery fencing",
            );
        }
        assert!(
            Arc::ptr_eq(&recovery_publication, &store.published()),
            "DNS cannot publish a new revision to clear recovery"
        );
        assert_eq!(
            recovery_publication.origin,
            oxidase_runtime::RuntimeOrigin::Source
        );
        assert_eq!(
            recovery_publication.serving_state,
            oxidase_runtime::ServingState::Running
        );
        assert!(
            candidates.ensure_mutations_allowed().is_err(),
            "refresh cannot restore publication authority"
        );
        assert_eq!(
            candidates
                .operation(&receipt.operation_id)
                .expect("durable operation")
                .phase,
            oxidase_runtime::OperationPhase::RecoveryRequired
        );
        assert!(
            dns.counts.udp.load(Ordering::Relaxed) >= 4,
            "both real DNS observations occurred"
        );
        assert_eq!(dns.counts.tcp.load(Ordering::Relaxed), 0);
        assert!(dns.counts.responses_for("recovery.example.invalid.") >= 4);
        assert!(
            dns.counts.responses_for_type(
                "recovery.example.invalid.",
                hickory_resolver::proto::rr::RecordType::A
            ) >= 2
        );
        assert!(
            request(report.local_addresses[0].1, "/", "")
                .await
                .ends_with("published")
        );
        super::stop_all_listeners(&mut listeners).await;
        health.shutdown().await;
        discovery.shutdown().await;
        assert!(
            cluster.endpoints().is_empty(),
            "shutdown retires operational membership even while old publication is pinned"
        );
        assert!(
            metrics
                .render_prometheus_for(&store.pin())
                .contains("oxidase_discovery_active_supervisors 0\n")
        );
    }

    #[tokio::test]
    async fn required_stage_audit_failure_is_durable_recovery_without_a_runtime_revision() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().canonicalize().expect("canonical fixture");
        let config = root.join("source.yaml");
        write_respond_gateway(&config, "unchanged", None);
        let snapshot = RuntimeSnapshot::prepare(Compiler::compile_path(&config).expect("compiles"))
            .expect("prepares");
        let published = SnapshotStore::new(snapshot).published();
        let path = root.join("journal");
        let candidates = oxidase_runtime::CandidateStore::open(
            path.clone(),
            oxidase_runtime::CandidateStoreLimits::default(),
            oxidase_runtime::CandidateSignaturePolicy::allow_unsigned_for_development(),
            oxidase_bundle::BundleCapabilities::default(),
        )
        .expect("test-only unsigned journal");
        let bundle = oxidase_bundle::BundleBuilder::new(oxidase_bundle::BundleManifest::new(
            oxidase_bundle::BuildMetadata {
                tool_version: "test".to_owned(),
                source_commit: None,
                gateway_api: "oxidase.dev/v1alpha1".to_owned(),
                oxista_api: "v1".to_owned(),
            },
            "0.3.0-alpha.1",
        ))
        .build()
        .expect("test Bundle");
        let context = oxidase_runtime::CandidateOperationContext {
            request_id: "audit-fault".to_owned(),
            principal: "bearer:test".to_owned(),
            if_match: Some(published.etag()),
            idempotency_key: None,
        };
        let staged = candidates
            .stage_bytes(&bundle, &context)
            .await
            .expect("fixture artifact");
        let begin = candidates
            .begin_operation_audited(
                &context,
                oxidase_runtime::AuditAction::Stage,
                Some(staged.candidate.digest),
                Some(oxidase_bundle::BundleDigest::of_bytes(&bundle)),
            )
            .expect("audited receipt");
        let id = begin.receipt.operation_id;
        let completed = candidates
            .finish_staged(&id, staged.candidate.digest)
            .expect("artifact registered");
        assert!(completed.audit_pending);
        let sink = crate::admin_audit::AdminAuditSink::test_completion_failure();
        let event =
            crate::admin_audit::AdminAuditEvent::new("audit-fault", "bearer", "bearer", "stage");
        let permit = sink
            .prepare_mutation(event.clone())
            .await
            .expect("start acknowledged");
        let audit = std::sync::Arc::new(std::sync::Mutex::new(Some((permit, event, sink))));
        let receipt =
            super::finish_operation_audit(&audit, &candidates, Some(completed), &published)
                .await
                .expect("queryable outcome");
        assert_eq!(
            receipt.phase,
            oxidase_runtime::OperationPhase::RecoveryRequired
        );
        assert_eq!(receipt.committed_revision, None);
        assert!(candidates.ensure_mutations_allowed().is_err());
        drop(candidates);
        let reopened = oxidase_runtime::CandidateStore::open(
            path,
            oxidase_runtime::CandidateStoreLimits::default(),
            oxidase_runtime::CandidateSignaturePolicy::allow_unsigned_for_development(),
            oxidase_bundle::BundleCapabilities::default(),
        )
        .expect("recovery opens for inspection");
        assert_eq!(
            reopened.operation(&id).expect("receipt survives").phase,
            oxidase_runtime::OperationPhase::RecoveryRequired
        );
        assert!(reopened.ensure_mutations_allowed().is_err());
    }

    #[tokio::test]
    async fn slow_blocking_preparation_does_not_stall_existing_requests() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "old", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let reload = running.reload_handle();
        reload.set_test_preparation_delay(Duration::from_millis(300));
        write_respond_gateway(&config, "new", None);

        let reload_task = tokio::spawn({
            let reload = reload.clone();
            let config = config.clone();
            async move { reload.reload_path(config).await }
        });
        tokio::time::timeout(
            Duration::from_secs(1),
            reload.wait_test_preparation_started(),
        )
        .await
        .expect("blocking preparation starts");

        let response = tokio::time::timeout(Duration::from_millis(100), request(address, "/", ""))
            .await
            .expect("existing request is not blocked by preparation");
        assert!(response.ends_with("old"));

        reload_task
            .await
            .expect("reload task joins")
            .expect("reload commits");
        assert!(request(address, "/", "").await.ends_with("new"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn retired_listener_closes_idle_keep_alive_and_starts_replacement() {
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        write_respond_gateway(&config, "old", None);
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let old_address = running.local_addresses()[0].1;
        let mut idle = tokio::net::TcpStream::connect(old_address)
            .await
            .expect("idle keep-alive connects");
        idle.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("request can be written");
        let response = read_until_contains(&mut idle, "\r\n\r\nold").await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));

        let replacement = available_address();
        write_respond_gateway_at(&config, "new", &replacement.to_string(), None);
        let report = running
            .reload_path(&config)
            .await
            .expect("replacement listener commits");
        assert_eq!(report.listeners_removed, vec!["test"]);
        assert_eq!(report.listeners_added, vec!["test"]);
        assert!(
            report
                .local_addresses
                .contains(&("test".to_owned(), replacement))
        );

        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(200), idle.read(&mut byte))
            .await
            .expect("idle keep-alive closes promptly")
            .expect("idle connection closes cleanly");
        assert_eq!(read, 0);
        assert!(request(replacement, "/", "").await.ends_with("new"));
        running.shutdown().await.expect("gateway shuts down");
    }

    #[tokio::test]
    async fn retired_listener_aborts_requests_after_drain_timeout() {
        let (upstream, accepts, upstream_shutdown, upstream_task) = spawn_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: proxy
    cluster: api
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("initial config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let mut server = GatewayServer::bind(snapshot).await.expect("gateway binds");
        server.drain_timeout = Duration::from_millis(30);
        let running = server.spawn();
        let old_address = running.local_addresses()[0].1;
        let old_request = tokio::spawn(request(old_address, "/slow-timeout", ""));
        tokio::time::timeout(Duration::from_secs(1), async {
            while accepts.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old request reaches upstream");

        let replacement = available_address();
        write_respond_gateway_at(&config, "replacement", &replacement.to_string(), None);
        running
            .reload_path(&config)
            .await
            .expect("replacement listener commits");
        assert!(request(replacement, "/", "").await.ends_with("replacement"));

        match tokio::time::timeout(Duration::from_secs(1), old_request).await {
            Ok(Ok(response)) => {
                assert!(
                    !response.contains("/slow-timeout||"),
                    "timed-out request must not complete: {response}"
                );
            }
            Ok(Err(_aborted_or_panicked)) => {}
            Err(_) => panic!("timed-out request connection must be aborted"),
        }

        running.shutdown().await.expect("gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream task shuts down");
    }

    #[tokio::test]
    async fn long_request_keeps_old_snapshot_while_new_requests_switch() {
        let (upstream, accepts, upstream_shutdown, upstream_task) = spawn_upstream().await;
        let directory = tempdir().expect("temporary directory is available");
        let config = directory.path().join("oxidase.yaml");
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: proxy
    cluster: api
listeners:
  - name: test
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("initial config can be written");
        let snapshot = RuntimeSnapshot::prepare(
            Compiler::compile_path(&config).expect("initial config compiles"),
        )
        .expect("initial snapshot prepares");
        let running = GatewayServer::bind(snapshot)
            .await
            .expect("gateway binds")
            .spawn();
        let address = running.local_addresses()[0].1;
        let old_request = tokio::spawn(request(address, "/slow", ""));
        tokio::time::timeout(Duration::from_secs(1), async {
            while accepts.load(Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("old request reaches upstream");

        let replacement = available_address();
        fs::write(
            &config,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      endpoints:
        - http://{upstream}
      connect_timeout: 1s
      response_timeout: 1s
services:
  root:
    type: respond
    body:
      text: new-version
listeners:
  - name: test
    bind: {replacement}
    service:
      ref: root
"#
            ),
        )
        .expect("new config can be written");
        let report = running.reload_path(&config).await.expect("reload commits");
        assert_eq!(report.reused_clusters, 1);
        assert_eq!(report.listeners_removed, vec!["test"]);
        assert_eq!(report.listeners_added, vec!["test"]);
        assert!(request(replacement, "/", "").await.ends_with("new-version"));
        let old_response = old_request.await.expect("old request task completes");
        assert!(old_response.starts_with("HTTP/1.1 200 OK"));
        assert!(old_response.contains("/slow||"));

        running.shutdown().await.expect("gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream task shuts down");
    }
}
