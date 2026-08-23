use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use oxidase_core::{RequestFrame, RequestMetadata, ServiceOutcome};
use oxidase_runtime::{Executor, ResourceReuse, RuntimeSnapshot, SnapshotStore};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::body::{GatewayBody, GatewayBodyPlan};
use crate::leaves::{HyperLeaves, ProxyClient};
use crate::metrics::Metrics;
use crate::response::ResponseFinalizer;

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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
                        source,
                    })?;
            let local_address =
                listener
                    .local_addr()
                    .map_err(|source| ServerError::LocalAddress {
                        listener: configured.name.clone(),
                        source,
                    })?;
            listeners.push(BoundListener {
                name: configured.name.clone(),
                configured_address: configured.bind,
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
                source,
            })?;
        let local_address = listener
            .local_addr()
            .map_err(|source| ServerError::LocalAddress {
                listener: "@admin".to_owned(),
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
        let (control, receiver) = mpsc::channel(8);
        let task = tokio::spawn(self.run(receiver));
        RunningServer {
            addresses,
            reload: ReloadHandle {
                store,
                metrics,
                control: control.clone(),
                dependencies: reload_dependencies,
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
        let current = self.store.pin();
        let gateway = match oxidase_config::Compiler::compile_path(path) {
            Ok(gateway) => gateway,
            Err(error) => {
                self.record_attempt_dependencies(error.discovered_dependencies.clone());
                return Err(ServerError::Reload(error.to_string()));
            }
        };
        self.record_attempt_dependencies(candidate_gateway_dependencies(&gateway));
        let (snapshot, reuse) = RuntimeSnapshot::prepare_reusing(gateway, Some(&current))
            .map_err(|error| ServerError::Reload(error.to_string()))?;
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
                    source,
                })?;
        let local_address = listener
            .local_addr()
            .map_err(|source| ServerError::LocalAddress {
                listener: configured.name.clone(),
                source,
            })?;
        prepared.push(BoundListener {
            name: configured.name.clone(),
            configured_address: configured.bind,
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
                connections.spawn(async move {
                    let service = service_fn(move |request| {
                        handle_admin_request(request, store.clone(), metrics.clone())
                    });
                    if let Err(error) = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::debug!(error = %error, "admin HTTP connection ended with an error");
                    }
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
                            source,
                        });
                        break;
                    }
                };
                let listener_name = listener.name.clone();
                let store = store.clone();
                let proxy = proxy.clone();
                let metrics = metrics.clone();
                connections.spawn(async move {
                    serve_connection(
                        stream,
                        peer_address,
                        listener_name,
                        store,
                        proxy,
                        metrics,
                    ).await;
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

async fn serve_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    listener_name: String,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
) {
    let service = service_fn(move |request| {
        handle_request(
            request,
            peer_address,
            listener_name.clone(),
            store.clone(),
            proxy.clone(),
            metrics.clone(),
        )
    });
    if let Err(error) = http1::Builder::new()
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(error = %error, "HTTP connection ended with an error");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    peer_address: SocketAddr,
    listener_name: String,
    store: Arc<SnapshotStore>,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
) -> Result<Response<GatewayBody>, Infallible> {
    let _active_request = metrics.request_started();
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
        return Ok(safe_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            request.method(),
        ));
    };

    let (parts, body) = request.into_parts();
    let request_method = parts.method.clone();
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
    let mut metadata = RequestMetadata::new(
        parts.method,
        "http",
        authority,
        path_and_query,
        parts.headers,
    );
    metadata.peer_address = Some(peer_address.to_string());
    let leaves = HyperLeaves::new(snapshot.clone(), proxy);
    let report = Executor::new(&program, &leaves)
        .execute(RequestFrame::new(metadata), Some(body))
        .await;

    let (outcome, status, response) = match report.outcome {
        ServiceOutcome::Handled(response) => {
            let status = response.status;
            (
                "handled",
                status,
                response_from_head(response, &request_method),
            )
        }
        ServiceOutcome::Declined => (
            "declined",
            StatusCode::NOT_FOUND,
            safe_response(StatusCode::NOT_FOUND, "Not Found", &request_method),
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
            )
        }
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
    Ok(response)
}

fn response_from_head(
    response: oxidase_core::ResponseHead<GatewayBodyPlan>,
    method: &Method,
) -> Response<GatewayBody> {
    ResponseFinalizer::new(method).finalize(response)
}

fn safe_error_body(status: StatusCode) -> &'static str {
    if status == StatusCode::GATEWAY_TIMEOUT {
        "Gateway Timeout"
    } else if status == StatusCode::BAD_GATEWAY {
        "Bad Gateway"
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

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("cannot bind listener `{listener}` to {address}: {source}")]
    Bind {
        listener: String,
        address: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot read local address for listener `{listener}`: {source}")]
    LocalAddress {
        listener: String,
        #[source]
        source: std::io::Error,
    },
    #[error("listener `{listener}` failed while accepting a connection: {source}")]
    Accept {
        listener: String,
        #[source]
        source: std::io::Error,
    },
    #[error("server task failed: {0}")]
    Task(String),
    #[error("cannot initialize HTTP data plane: {0}")]
    DataPlane(String),
    #[error("reload failed: {0}")]
    Reload(String),
    #[error("server control channel is closed")]
    ControlClosed,
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::fs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use http::{HeaderName, HeaderValue, Response, header};
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use oxidase_config::Compiler;
    use oxidase_runtime::RuntimeSnapshot;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::watch;

    use super::GatewayServer;

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

    fn write_respond_gateway(path: &std::path::Path, body: &str, extra_listener: Option<&str>) {
        let extra_listener = extra_listener.map_or(String::new(), |bind| {
            format!("  - name: extra\n    bind: {bind}\n    service:\n      ref: root\n")
        });
        fs::write(
            path,
            format!(
                "api_version: oxidase.dev/v1alpha1\nkind: gateway\nservices:\n  root:\n    type: respond\n    body:\n      text: {body}\nlisteners:\n  - name: test\n    bind: 127.0.0.1:0\n    service:\n      ref: root\n{extra_listener}"
            ),
        )
        .expect("gateway config can be written");
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
        running.shutdown().await.expect("server shuts down cleanly");
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
"#,
        )
        .expect("manifest can be written");
        fs::write(site.join("asset.txt"), "identity-v1").expect("identity can be written");
        fs::write(site.join("asset.txt.br"), "brotli-v1").expect("Brotli can be written");
        fs::write(site.join("asset.txt.gz"), "gzip-v1").expect("gzip can be written");
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

        let identity = request(address, "/asset.txt", "").await;
        assert!(identity.starts_with("HTTP/1.1 200 OK"));
        assert!(identity.ends_with("identity-v1"));
        assert_eq!(raw_header(&identity, "content-type"), "application/x-asset");
        let identity_etag = raw_header(&identity, "etag");
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
        assert!(headers.starts_with("HTTP/1.1 206 Partial Content"));
        assert!(headers.to_ascii_lowercase().contains("content-length: 4"));
        assert!(body.is_empty());

        for value in ["bytes=99-100", "bytes=0-1,4-5"] {
            let invalid = request(address, "/asset.txt", &format!("Range: {value}\r\n")).await;
            assert!(invalid.starts_with("HTTP/1.1 416 Range Not Satisfiable"));
            assert_eq!(raw_header(&invalid, "content-range"), "bytes */11");
        }

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
            site.join("_templates/card.oxt"),
            r#"---
oxista: template/v1
params:
  count: int
---
{{ count }}
"#,
        )
        .expect("template can be written");
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
      with:
        count:
          $expr: page.count
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

        let response = request(address, "/index", "").await;
        assert!(response.starts_with("HTTP/1.1 500 Internal Server Error"));
        assert!(response.ends_with("Internal Server Error"));
        assert!(!response.contains("parameter `count`"));
        assert!(!response.contains("expects int"));

        running.shutdown().await.expect("gateway shuts down");
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

        let second = request(address, "/second", "").await;
        assert!(second.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(accepts.load(Ordering::Relaxed), 1);

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
        assert!(running.reload_path(&config).await.is_err());
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
    bind: 127.0.0.1:0
    service:
      ref: root
"#
            ),
        )
        .expect("new config can be written");
        let report = running.reload_path(&config).await.expect("reload commits");
        assert_eq!(report.reused_clusters, 1);
        assert!(request(address, "/", "").await.ends_with("new-version"));
        let old_response = old_request.await.expect("old request task completes");
        assert!(old_response.starts_with("HTTP/1.1 200 OK"));
        assert!(old_response.contains("/slow||"));

        running.shutdown().await.expect("gateway shuts down");
        let _ = upstream_shutdown.send(true);
        upstream_task.await.expect("upstream task shuts down");
    }
}
