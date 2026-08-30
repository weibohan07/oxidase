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
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use oxidase_config::{Http1Settings, Http2Settings, HttpVersion, ListenerProtocol};
use oxidase_core::{
    Diagnostic, RequestFrame, RequestMetadata, ServiceOutcome, SourceSpan, TlsConnectionMetadata,
};
use oxidase_runtime::{
    Executor, PreparedListenerPlan, ResourceReuse, RuntimeSnapshot, SnapshotStore,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::body::{GatewayBody, GatewayBodyPlan, instrument_response_body_with_snapshot};
use crate::connection::TrackedExecutor;
use crate::leaves::{HyperLeaves, ProxyClient};
use crate::metrics::{
    ConnectionProtocol, H2Shutdown, ListenerTransportMetrics, Metrics, ProductionObserver, TlsAlpn,
    TlsHandshakeOutcome, TunnelTermination as TunnelMetricTermination,
};
use crate::protocol::{WireProtocol, http1_accepts_trailers};
use crate::response::{
    FinalizedResponse, ResponseFinalizationContext, ResponseFinalizationError, ResponseFinalizer,
};
use crate::upgrade::{
    GatewayRequestPayload, TunnelPlan, TunnelTermination as TunnelIoTermination,
    validate_upgrade_request,
};

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const DEFAULT_HTTP1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_TLS_HANDSHAKES_PER_LISTENER: usize = 128;

fn http1_builder(header_read_timeout: Duration) -> http1::Builder {
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    builder
}

pub struct GatewayServer {
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    listeners: Vec<BoundListener>,
    admin: Option<BoundAdmin>,
    drain_timeout: Duration,
}

struct BoundAdmin {
    listener: TcpListener,
    local_address: SocketAddr,
}

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
    Reload {
        snapshot: Box<RuntimeSnapshot>,
        reuse: ResourceReuse,
        response: oneshot::Sender<Result<ReloadReport, ServerError>>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
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
        Ok(Self {
            store: Arc::new(SnapshotStore::new(snapshot)),
            proxy: Arc::new(ProxyClient::new().map_err(ServerError::DataPlane)?),
            metrics: Arc::new(Metrics::default()),
            listeners,
            admin: None,
            drain_timeout: Duration::from_secs(10),
        })
    }

    pub async fn with_admin_listener(mut self, bind: SocketAddr) -> Result<Self, ServerError> {
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
            listener,
            local_address,
        });
        Ok(self)
    }

    #[must_use]
    pub fn admin_address(&self) -> Option<SocketAddr> {
        self.admin.as_ref().map(|admin| admin.local_address)
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
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let reload_dependencies = Arc::new(Mutex::new(ReloadDependencyState::new(
            store.pin().dependencies.clone(),
        )));
        let compile_gate = Arc::new(Semaphore::new(1));
        let (control, receiver) = mpsc::channel(8);
        let task = tokio::spawn(self.run(receiver));
        RunningServer {
            addresses,
            reload: ReloadHandle {
                store,
                metrics,
                control: control.clone(),
                dependencies: reload_dependencies,
                compile_gate,
                #[cfg(test)]
                preparation_delay: Arc::new(Mutex::new(None)),
                #[cfg(test)]
                preparation_started: Arc::new(tokio::sync::Notify::new()),
            },
            admin_address,
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

    async fn run(mut self, mut control: mpsc::Receiver<Control>) -> Result<(), ServerError> {
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
            )
        });

        loop {
            tokio::select! {
                command = control.recv() => {
                    match command {
                        Some(Control::Reload { snapshot, reuse, response }) => {
                            let environment = ReloadEnvironment {
                                store: &self.store,
                                proxy: &self.proxy,
                                metrics: &self.metrics,
                                drain_timeout: self.drain_timeout,
                                completion: &completion_sender,
                            };
                            let result = apply_reload(
                                *snapshot,
                                reuse,
                                &mut listeners,
                                &mut generation,
                                environment,
                            ).await;
                            let _ = response.send(result);
                        }
                        Some(Control::Shutdown { response }) => {
                            stop_all_listeners(&mut listeners).await;
                            stop_admin_listener(&mut admin).await;
                            let _ = response.send(());
                            return Ok(());
                        }
                        None => {
                            stop_all_listeners(&mut listeners).await;
                            stop_admin_listener(&mut admin).await;
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

pub struct RunningServer {
    addresses: Vec<(String, SocketAddr)>,
    admin_address: Option<SocketAddr>,
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
}

impl ReloadHandle {
    pub async fn reload_path(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<ReloadReport, ServerError> {
        let result = self.reload_path_inner(path.as_ref()).await;
        self.metrics.record_reload(result.is_ok());
        result
    }

    async fn reload_path_inner(&self, path: &std::path::Path) -> Result<ReloadReport, ServerError> {
        let _permit = self
            .compile_gate
            .acquire()
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        let current = self.store.pin();
        let path = path.to_path_buf();
        let preparation_delay = self.test_preparation_delay();
        #[cfg(test)]
        let preparation_started = Some(self.preparation_started.clone());
        #[cfg(not(test))]
        let preparation_started: Option<Arc<tokio::sync::Notify>> = None;
        let prepared = tokio::task::spawn_blocking(move || {
            if let Some(started) = preparation_started {
                started.notify_one();
            }
            if let Some(delay) = preparation_delay {
                std::thread::sleep(delay);
            }
            let gateway = match oxidase_config::Compiler::compile_path(path) {
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
            match RuntimeSnapshot::prepare_reusing(gateway, Some(&current)) {
                Ok((snapshot, reuse)) => Ok((snapshot, reuse, attempt_dependencies)),
                Err(error) => {
                    let mut dependencies = attempt_dependencies;
                    dependencies.extend(error.candidate_dependencies.iter().cloned());
                    dependencies.sort();
                    dependencies.dedup();
                    Err((
                        ServerError::Reload(ReloadError::new(error.into_diagnostics())),
                        dependencies,
                    ))
                }
            }
        })
        .await
        .map_err(|error| ServerError::Task(format!("reload compiler worker failed: {error}")))?;
        let (snapshot, reuse, attempt_dependencies) = match prepared {
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
                response,
            })
            .await
            .map_err(|_| ServerError::ControlClosed)?;
        let report = received.await.map_err(|_| ServerError::ControlClosed)??;
        self.record_published_dependencies(published_dependencies);
        Ok(report)
    }

    #[must_use]
    pub fn current_snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.store.pin()
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
    pub reused_certificates: usize,
    pub listeners_added: Vec<String>,
    pub listeners_removed: Vec<String>,
    pub listeners_retained: Vec<String>,
    pub local_addresses: Vec<(String, SocketAddr)>,
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
    active: &mut BTreeMap<String, ActiveListener>,
    generation: &mut u64,
    environment: ReloadEnvironment<'_>,
) -> Result<ReloadReport, ServerError> {
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
    environment.store.publish(snapshot);

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

    Ok(ReloadReport {
        previous_version,
        current_version,
        reused_sites: reuse.sites,
        reused_clusters: reuse.clusters,
        reused_certificates: reuse.certificates,
        listeners_added,
        listeners_removed: to_stop,
        listeners_retained: retained.into_iter().collect(),
        local_addresses: active
            .iter()
            .map(|(name, listener)| (name.clone(), listener.local_address))
            .collect(),
    })
}

struct ReloadEnvironment<'a> {
    store: &'a Arc<SnapshotStore>,
    proxy: &'a Arc<ProxyClient>,
    metrics: &'a Arc<Metrics>,
    drain_timeout: Duration,
    completion: &'a mpsc::UnboundedSender<ListenerCompletion>,
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
) -> ActiveAdmin {
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(run_admin_listener(
        admin,
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
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = admin.listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tracing::error!("admin listener failed while accepting a connection");
                    break;
                };
                let store = store.clone();
                let metrics = metrics.clone();
                let connection_shutdown = shutdown.clone();
                connections.spawn(async move {
                    serve_admin_connection(
                        stream,
                        store,
                        metrics,
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
}

async fn serve_admin_connection(
    stream: TcpStream,
    store: Arc<SnapshotStore>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
) {
    let service =
        service_fn(move |request| handle_admin_request(request, store.clone(), metrics.clone()));
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
) -> Result<Response<GatewayBody>, Infallible> {
    let method = request.method().clone();
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Ok(admin_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Method Not Allowed"),
            &method,
        ));
    }
    let response = match request.uri().path() {
        "/health/live" => admin_response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"live\n"),
            &method,
        ),
        "/health/ready" => {
            let ready = !store.pin().listeners.is_empty();
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
        "/metrics" => admin_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            Bytes::from(metrics.render_prometheus()),
            &method,
        ),
        _ => admin_response(
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Not Found"),
            &method,
        ),
    };
    Ok(response)
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
    loop {
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
                };
                connections.spawn(async move {
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
            serve_http1_connection(stream, context, settings, shutdown).await;
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
                    serve_http2_connection(tls_stream, context, settings, shutdown).await;
                }
                NegotiatedHttpProtocol::Http1 => {
                    let Some(settings) = plan.http.http1.clone() else {
                        tracing::error!(
                            listener = context.listener_name,
                            "HTTP/1 listener has no HTTP/1 settings"
                        );
                        return;
                    };
                    serve_http1_connection(tls_stream, context, settings, shutdown).await;
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
    let service = service_fn(move |request| handle_request(request, service_context.clone()));
    let connection = http1_builder(settings.header_read_timeout)
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
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(Some(settings.max_concurrent_streams))
        .max_header_list_size(settings.max_header_list_size)
        .keep_alive_interval(Some(settings.keep_alive_interval))
        .keep_alive_timeout(settings.keep_alive_timeout);
    let service_context = context.clone();
    let service = service_fn(move |request| handle_request(request, service_context.clone()));
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
        return Ok(instrument_response_body_with_snapshot(
            response,
            metrics,
            active_request,
            Some(snapshot),
        ));
    };

    let request_method = request.method().clone();
    let wire_protocol = wire_protocol(request.version());
    let accepts_http1_trailers =
        wire_protocol == WireProtocol::Http1 && http1_accepts_trailers(request.headers());
    let pending_upgrade = match validate_upgrade_request(&request) {
        Ok(Some(candidate)) => Some(candidate.pending(hyper::upgrade::on(&mut request))),
        Ok(None) => None,
        Err(error) => {
            tracing::debug!(request_id, error = %error, "HTTP Upgrade request is invalid");
            metrics.record_request("failed", StatusCode::BAD_REQUEST, started.elapsed());
            let response = safe_response(StatusCode::BAD_REQUEST, "Bad Request", &request_method);
            return Ok(instrument_response_body_with_snapshot(
                response,
                metrics,
                active_request,
                Some(snapshot),
            ));
        }
    };
    let (parts, body) = request.into_parts();
    let authority = parts
        .headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| parts.uri.authority().map(ToString::to_string))
        .unwrap_or_default();
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
            return Ok(instrument_response_body_with_snapshot(
                response,
                metrics,
                active_request,
                Some(snapshot),
            ));
        }
    };
    metadata.peer_address = Some(peer_address);
    metadata.http_version = parts.version;
    metadata.tls = tls;
    let leaves = HyperLeaves::new(snapshot.clone(), proxy);
    let observer = ProductionObserver::new(&metrics, &config_version, &listener_name, request_id);
    let report = Executor::new(&program, &leaves)
        .execute_observed(
            RequestFrame::new(metadata),
            Some(GatewayRequestPayload::new(body, pending_upgrade)),
            &observer,
        )
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
    Ok(instrument_response_body_with_snapshot(
        response,
        metrics,
        active_request,
        Some(snapshot),
    ))
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
        AlpnSelectionError, DEFAULT_HTTP1_HEADER_READ_TIMEOUT, GatewayConnectionContext,
        GatewayServer, H2DrainObservation, NegotiatedHttpProtocol, ProxyClient, ServerError,
        http1_builder, reserve_tls_handshake, safe_error_body, select_https_protocol,
        serve_http2_connection, tls_accept_error_outcome,
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
            },
            tunnel_sender: None,
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
