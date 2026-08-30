//! Commit-activated active health checking for prepared Clusters.
//!
//! Runtime preparation remains side-effect free. The server manager calls
//! [`ClusterHealthManager::activate_snapshot`] only after publishing a snapshot;
//! failed candidates therefore cannot leak health-check tasks.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Buf, Bytes};
use futures_util::future::join_all;
use http::{Method, Request, Uri};
use http_body::Body;
use http_body_util::{BodyExt, Empty};
use hyper_rustls::{FixedServerNameResolver, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use oxidase_config::{ActiveHealthSpec, ClusterProtocol};
use oxidase_core::ContentDigest;
use oxidase_runtime::{PreparedCluster, PreparedEndpoint, RuntimeSnapshot};
use tokio::sync::watch;
use tokio::task::JoinSet;

const MAX_HEALTH_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const HEALTH_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const HEALTH_POOL_MAX_IDLE_PER_HOST: usize = 8;

type HealthPool = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

/// Owns the long-lived health-check pools and all committed supervisor tasks.
///
/// A manager is scoped to one running server. Dropping it aborts any remaining
/// tasks; normal shutdown first asks tasks to stop cooperatively.
pub(crate) struct ClusterHealthManager {
    client: Arc<HealthClient>,
    shutdown: watch::Sender<bool>,
    tasks: JoinSet<()>,
    #[cfg(test)]
    counters: Arc<SupervisorTaskCounters>,
}

impl ClusterHealthManager {
    pub(crate) fn new() -> Result<Self, String> {
        let client = Arc::new(HealthClient::new()?);
        let (shutdown, _) = watch::channel(false);
        Ok(Self {
            client,
            shutdown,
            tasks: JoinSet::new(),
            #[cfg(test)]
            counters: Arc::new(SupervisorTaskCounters::default()),
        })
    }

    /// Activates active-health supervisors for one committed snapshot.
    ///
    /// Unchanged Clusters retain the same `Arc<PreparedCluster>` and its
    /// activation latch, so publishing the same prepared resource never starts
    /// a duplicate supervisor.
    pub(crate) fn activate_snapshot(&mut self, snapshot: &RuntimeSnapshot) -> usize {
        self.reap_finished();
        self.client.reconcile_snapshot(snapshot);
        let mut activated = 0;
        for cluster in snapshot.resources.clusters.values() {
            if cluster.spec().health.active.is_none() || !cluster.try_activate_supervisor() {
                continue;
            }
            activated += 1;
            let task = run_cluster_supervisor(
                Arc::downgrade(cluster),
                Arc::clone(&self.client),
                self.shutdown.subscribe(),
                #[cfg(test)]
                Arc::clone(&self.counters),
            );
            self.tasks.spawn(task);
        }
        activated
    }

    /// Stops all health work and waits for task termination.
    pub(crate) async fn shutdown(&mut self) {
        let _ = self.shutdown.send(true);
        while self.tasks.join_next().await.is_some() {}
    }

    fn reap_finished(&mut self) {
        while self.tasks.try_join_next().is_some() {}
    }

    #[cfg(test)]
    fn counters(&self) -> Arc<SupervisorTaskCounters> {
        Arc::clone(&self.counters)
    }
}

impl Drop for ClusterHealthManager {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.tasks.abort_all();
    }
}

struct HealthClient {
    default_tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    pool_registry: Mutex<HealthPoolRegistry>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HealthPoolKey {
    connect_timeout: Duration,
    tls_digest: Option<ContentDigest>,
}

#[derive(Default)]
struct HealthPoolRegistry {
    active: BTreeMap<HealthPoolKey, Arc<HealthPools>>,
    cached: BTreeMap<HealthPoolKey, Weak<HealthPools>>,
}

struct HealthPools {
    auto: HealthPool,
    http1: HealthPool,
    h2: HealthPool,
}

impl HealthClient {
    fn new() -> Result<Self, String> {
        Ok(Self {
            default_tls_config: Arc::new(cleartext_health_connector_tls_config()?),
            pool_registry: Mutex::new(HealthPoolRegistry::default()),
        })
    }

    fn reconcile_snapshot(&self, snapshot: &RuntimeSnapshot) {
        let active = snapshot
            .resources
            .clusters
            .values()
            .filter(|cluster| cluster.spec().health.active.is_some())
            .map(|cluster| (Self::pool_key(cluster), Arc::clone(cluster)))
            .collect::<BTreeMap<_, _>>();
        let mut registry = self
            .pool_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.active.retain(|key, _| active.contains_key(key));
        for (key, cluster) in active {
            if registry.active.contains_key(&key) {
                continue;
            }
            let pools = registry
                .cached
                .get(&key)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| self.build_pools(&cluster));
            registry.cached.insert(key, Arc::downgrade(&pools));
            registry.active.insert(key, pools);
        }
        let active_keys = registry.active.keys().copied().collect::<BTreeSet<_>>();
        registry
            .cached
            .retain(|key, pools| active_keys.contains(key) || pools.strong_count() > 0);
    }

    fn pools(&self, cluster: &PreparedCluster) -> Arc<HealthPools> {
        let key = Self::pool_key(cluster);
        let mut registry = self
            .pool_registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pools) = registry.active.get(&key) {
            return Arc::clone(pools);
        }
        if let Some(pools) = registry.cached.get(&key).and_then(Weak::upgrade) {
            return pools;
        }
        let pools = self.build_pools(cluster);
        registry.cached.insert(key, Arc::downgrade(&pools));
        pools
    }

    fn pool_key(cluster: &PreparedCluster) -> HealthPoolKey {
        HealthPoolKey {
            connect_timeout: cluster.spec().connect_timeout,
            tls_digest: cluster.upstream_tls().map(|tls| tls.digest()),
        }
    }

    fn build_pools(&self, cluster: &PreparedCluster) -> Arc<HealthPools> {
        let (tls_config, server_name) = cluster.upstream_tls().map_or_else(
            || (Arc::clone(&self.default_tls_config), None),
            |tls| (tls.client_config(), tls.server_name()),
        );
        Arc::new(HealthPools::new(
            cluster.spec().connect_timeout,
            tls_config.as_ref(),
            server_name,
        ))
    }

    async fn probe(
        &self,
        cluster: &PreparedCluster,
        endpoint: &PreparedEndpoint,
        plan: &ActiveHealthSpec,
    ) -> bool {
        let Some(uri) = health_uri(endpoint, &plan.path) else {
            return false;
        };
        let Ok(request) = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::new())
        else {
            return false;
        };
        tokio::time::timeout(plan.timeout, async {
            let pools = self.pools(cluster);
            let response = pools.pool(cluster.protocol()).request(request).await.ok()?;
            let status = response.status().as_u16();
            let body_complete = discard_bounded_body(response.into_body()).await;
            if !body_complete {
                return None;
            }
            Some(
                plan.healthy_statuses
                    .iter()
                    .any(|range| range.contains(status)),
            )
        })
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
    }
}

impl HealthPools {
    fn new(
        connect_timeout: Duration,
        tls_config: &tokio_rustls::rustls::ClientConfig,
        server_name: Option<tokio_rustls::rustls::pki_types::ServerName<'static>>,
    ) -> Self {
        let auto = build_health_connector(
            connect_timeout,
            tls_config,
            server_name.clone(),
            ClusterProtocol::Auto,
        );
        let http1 = build_health_connector(
            connect_timeout,
            tls_config,
            server_name.clone(),
            ClusterProtocol::Http1,
        );
        let h2 = build_health_connector(
            connect_timeout,
            tls_config,
            server_name,
            ClusterProtocol::H2,
        );
        Self {
            auto: build_health_pool(auto, false),
            http1: build_health_pool(http1, false),
            h2: build_health_pool(h2, true),
        }
    }

    fn pool(&self, protocol: ClusterProtocol) -> &HealthPool {
        match protocol {
            ClusterProtocol::Auto => &self.auto,
            ClusterProtocol::Http1 => &self.http1,
            ClusterProtocol::H2 => &self.h2,
        }
    }
}

fn cleartext_health_connector_tls_config() -> Result<tokio_rustls::rustls::ClientConfig, String> {
    use tokio_rustls::rustls::RootCertStore;
    use tokio_rustls::rustls::crypto::ring::default_provider;

    // Used only by HTTP-only clusters. HTTPS health checks always use the
    // same prepared trust/client-identity policy as ordinary Proxy traffic.
    let roots = RootCertStore::empty();
    tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("cannot enable safe health-check TLS versions: {error}"))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}

fn build_health_connector(
    connect_timeout: Duration,
    tls_config: &tokio_rustls::rustls::ClientConfig,
    server_name: Option<tokio_rustls::rustls::pki_types::ServerName<'static>>,
    protocol: ClusterProtocol,
) -> HttpsConnector<HttpConnector> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(connect_timeout));
    let builder = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config.clone())
        .https_or_http();
    let builder = if let Some(server_name) = server_name {
        builder.with_server_name_resolver(FixedServerNameResolver::new(server_name))
    } else {
        builder
    };
    match protocol {
        ClusterProtocol::Auto => builder.enable_http1().enable_http2().wrap_connector(http),
        ClusterProtocol::Http1 => builder.enable_http1().wrap_connector(http),
        ClusterProtocol::H2 => builder.enable_http2().wrap_connector(http),
    }
}

fn build_health_pool(connector: HttpsConnector<HttpConnector>, http2_only: bool) -> HealthPool {
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(TokioTimer::new())
        .pool_idle_timeout(HEALTH_POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(HEALTH_POOL_MAX_IDLE_PER_HOST)
        .http2_only(http2_only);
    builder.build(connector)
}

fn health_uri(endpoint: &PreparedEndpoint, path_and_query: &str) -> Option<Uri> {
    let mut target = endpoint.url().clone();
    let parsed = path_and_query.parse::<http::uri::PathAndQuery>().ok()?;
    target.set_path(parsed.path());
    target.set_query(parsed.query());
    target.set_fragment(None);
    target.as_str().parse::<Uri>().ok()
}

/// Drains enough of a health response to make ordinary small responses
/// reusable without allowing an endpoint to force unbounded consumption.
/// Oversized bodies are intentionally dropped once the fixed cap is crossed;
/// framing errors before that point make the probe fail.
async fn discard_bounded_body<B>(mut body: B) -> bool
where
    B: Body + Unpin,
    B::Data: Buf,
{
    let mut consumed = 0usize;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return false;
        };
        if let Some(data) = frame.data_ref() {
            consumed = consumed.saturating_add(data.remaining());
            if consumed >= MAX_HEALTH_RESPONSE_BODY_BYTES {
                break;
            }
        }
    }
    true
}

async fn run_cluster_supervisor(
    cluster: std::sync::Weak<PreparedCluster>,
    client: Arc<HealthClient>,
    mut shutdown: watch::Receiver<bool>,
    #[cfg(test)] counters: Arc<SupervisorTaskCounters>,
) {
    #[cfg(test)]
    let _task = SupervisorTaskGuard::new(counters);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let Some(cluster) = cluster.upgrade() else {
            break;
        };
        let Some(plan) = cluster.spec().health.active.clone() else {
            break;
        };
        let interval = plan.interval;
        let probes = cluster
            .endpoints()
            .iter()
            .map(|endpoint| client.probe(&cluster, endpoint, &plan));
        let round = join_all(probes);
        let outcomes = tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            outcomes = round => outcomes,
        };
        let observed_at = Instant::now();
        for (endpoint, succeeded) in cluster.endpoints().iter().zip(outcomes) {
            cluster.record_active_health(endpoint.name(), succeeded, observed_at);
        }
        drop(cluster);

        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = tokio::time::sleep(interval) => {}
        }
    }
}

#[cfg(test)]
#[derive(Default)]
struct SupervisorTaskCounters {
    started: AtomicU64,
    active: AtomicU64,
    finished: AtomicU64,
}

#[cfg(test)]
struct SupervisorTaskGuard {
    counters: Arc<SupervisorTaskCounters>,
}

#[cfg(test)]
impl SupervisorTaskGuard {
    fn new(counters: Arc<SupervisorTaskCounters>) -> Self {
        counters.started.fetch_add(1, Ordering::Relaxed);
        counters.active.fetch_add(1, Ordering::Relaxed);
        Self { counters }
    }
}

#[cfg(test)]
impl Drop for SupervisorTaskGuard {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        self.counters.finished.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use http_body::{Body, Frame, SizeHint};
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use oxidase_config::Compiler;
    use oxidase_runtime::{EndpointHealthState, RuntimeSnapshot};
    use tempfile::TempDir;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio::task::{JoinHandle, JoinSet};

    use super::{ClusterHealthManager, MAX_HEALTH_RESPONSE_BODY_BYTES, discard_bounded_body};

    struct HealthFixture {
        address: std::net::SocketAddr,
        status: Arc<AtomicU16>,
        delay_ms: Arc<AtomicU64>,
        requests: Arc<AtomicU64>,
        accepts: Arc<AtomicU64>,
        request_targets: Arc<Mutex<Vec<String>>>,
        shutdown: watch::Sender<bool>,
        task: JoinHandle<()>,
    }

    impl HealthFixture {
        async fn spawn(status: StatusCode) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("fixture listener binds");
            let address = listener.local_addr().expect("fixture address is available");
            let status = Arc::new(AtomicU16::new(status.as_u16()));
            let delay_ms = Arc::new(AtomicU64::new(0));
            let requests = Arc::new(AtomicU64::new(0));
            let accepts = Arc::new(AtomicU64::new(0));
            let request_targets = Arc::new(Mutex::new(Vec::new()));
            let (shutdown, mut shutdown_receiver) = watch::channel(false);
            let task_status = Arc::clone(&status);
            let task_delay_ms = Arc::clone(&delay_ms);
            let task_requests = Arc::clone(&requests);
            let task_accepts = Arc::clone(&accepts);
            let task_targets = Arc::clone(&request_targets);
            let task = tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        biased;
                        changed = shutdown_receiver.changed() => {
                            if changed.is_err() || *shutdown_receiver.borrow() {
                                break;
                            }
                        }
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else {
                                break;
                            };
                            task_accepts.fetch_add(1, Ordering::Relaxed);
                            connections.spawn(serve_fixture_connection(
                                stream,
                                Arc::clone(&task_status),
                                Arc::clone(&task_delay_ms),
                                Arc::clone(&task_requests),
                                Arc::clone(&task_targets),
                            ));
                        }
                        completed = connections.join_next(), if !connections.is_empty() => {
                            let _ = completed;
                        }
                    }
                }
                connections.shutdown().await;
            });
            Self {
                address,
                status,
                delay_ms,
                requests,
                accepts,
                request_targets,
                shutdown,
                task,
            }
        }

        fn set_status(&self, status: StatusCode) {
            self.status.store(status.as_u16(), Ordering::Relaxed);
        }

        fn set_delay(&self, delay: Duration) {
            self.delay_ms.store(
                u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }

        async fn shutdown(self) {
            let _ = self.shutdown.send(true);
            self.task.await.expect("fixture task joins");
        }
    }

    async fn serve_fixture_connection(
        stream: TcpStream,
        status: Arc<AtomicU16>,
        delay_ms: Arc<AtomicU64>,
        requests: Arc<AtomicU64>,
        request_targets: Arc<Mutex<Vec<String>>>,
    ) {
        let service = service_fn(move |request: Request<Incoming>| {
            let status = Arc::clone(&status);
            let delay_ms = Arc::clone(&delay_ms);
            let requests = Arc::clone(&requests);
            let request_targets = Arc::clone(&request_targets);
            async move {
                requests.fetch_add(1, Ordering::Relaxed);
                request_targets
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(request.uri().to_string());
                let delay = Duration::from_millis(delay_ms.load(Ordering::Relaxed));
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let status = StatusCode::from_u16(status.load(Ordering::Relaxed))
                    .expect("fixture status is valid");
                let mut response = Response::new(Full::new(Bytes::new()));
                *response.status_mut() = status;
                Ok::<_, Infallible>(response)
            }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    fn compile_gateway(
        fixture: &HealthFixture,
        interval: Duration,
        timeout: Duration,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
    ) -> oxidase_config::CompiledGateway {
        let directory = TempDir::new().expect("temporary configuration directory");
        let path = directory.path().join("oxidase.yaml");
        std::fs::write(
            &path,
            format!(
                r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    api:
      protocol: auto
      endpoints:
        - name: origin
          url: http://{}/base
          weight: 1
      health:
        active:
          path: /healthz?ready=1
          interval: {}ms
          timeout: {}ms
          healthy_statuses: ["200-299"]
          healthy_threshold: {}
          unhealthy_threshold: {}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
                fixture.address,
                interval.as_millis(),
                timeout.as_millis(),
                healthy_threshold,
                unhealthy_threshold,
            ),
        )
        .expect("fixture configuration is written");
        Compiler::compile_path(path).expect("health fixture configuration compiles")
    }

    fn prepare_snapshot(
        fixture: &HealthFixture,
        interval: Duration,
        timeout: Duration,
        healthy_threshold: u32,
        unhealthy_threshold: u32,
    ) -> RuntimeSnapshot {
        RuntimeSnapshot::prepare(compile_gateway(
            fixture,
            interval,
            timeout,
            healthy_threshold,
            unhealthy_threshold,
        ))
        .expect("health fixture snapshot prepares")
    }

    async fn wait_until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition becomes true before timeout");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn committed_supervisor_applies_thresholds_recovers_and_reuses_connection() {
        let fixture = HealthFixture::spawn(StatusCode::SERVICE_UNAVAILABLE).await;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(200),
            2,
            2,
        );
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("prepared Cluster exists"),
        );
        let mut manager = ClusterHealthManager::new().expect("health pools initialize");
        assert_eq!(manager.activate_snapshot(&snapshot), 1);
        wait_until(|| {
            cluster.endpoints()[0].health_state(Instant::now()) == EndpointHealthState::Unhealthy
        })
        .await;

        fixture.set_status(StatusCode::NO_CONTENT);
        wait_until(|| {
            cluster.endpoints()[0].health_state(Instant::now()) == EndpointHealthState::Healthy
        })
        .await;
        wait_until(|| fixture.requests.load(Ordering::Relaxed) >= 4).await;
        assert_eq!(fixture.accepts.load(Ordering::Relaxed), 1);
        assert_eq!(
            fixture
                .request_targets
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .first()
                .map(String::as_str),
            Some("/healthz?ready=1")
        );

        manager.shutdown().await;
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unchanged_reload_does_not_duplicate_and_last_arc_stops_task() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(100),
            1,
            1,
        );
        let weak_cluster = Arc::downgrade(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("prepared Cluster exists"),
        );
        let gateway = compile_gateway(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(100),
            1,
            1,
        );
        let (reloaded, reuse) = RuntimeSnapshot::prepare_reusing(gateway, Some(&snapshot))
            .expect("unchanged snapshot prepares");
        assert_eq!(reuse.clusters, 1);
        assert!(Arc::ptr_eq(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("old Cluster exists"),
            reloaded
                .resources
                .clusters
                .values()
                .next()
                .expect("reused Cluster exists"),
        ));

        let mut manager = ClusterHealthManager::new().expect("health pools initialize");
        let counters = manager.counters();
        assert_eq!(manager.activate_snapshot(&snapshot), 1);
        assert_eq!(manager.activate_snapshot(&reloaded), 0);
        wait_until(|| counters.active.load(Ordering::Relaxed) == 1).await;

        drop(snapshot);
        assert!(weak_cluster.upgrade().is_some());
        assert_eq!(counters.active.load(Ordering::Relaxed), 1);
        drop(reloaded);
        wait_until(|| weak_cluster.upgrade().is_none()).await;
        wait_until(|| counters.active.load(Ordering::Relaxed) == 0).await;
        assert_eq!(counters.started.load(Ordering::Relaxed), 1);
        assert_eq!(counters.finished.load(Ordering::Relaxed), 1);

        manager.shutdown().await;
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_timeout_is_independent_and_records_failure() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        fixture.set_delay(Duration::from_millis(100));
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(20),
            1,
            1,
        );
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("prepared Cluster exists"),
        );
        let mut manager = ClusterHealthManager::new().expect("health pools initialize");
        assert_eq!(manager.activate_snapshot(&snapshot), 1);
        wait_until(|| {
            cluster.endpoints()[0].health_state(Instant::now()) == EndpointHealthState::Unhealthy
        })
        .await;
        assert!(fixture.requests.load(Ordering::Relaxed) >= 1);

        manager.shutdown().await;
        fixture.shutdown().await;
    }

    #[test]
    fn failed_candidate_never_claims_or_starts_a_supervisor() {
        let directory = TempDir::new().expect("temporary configuration directory");
        let path = directory.path().join("oxidase.yaml");
        std::fs::write(
            &path,
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
resources:
  clusters:
    broken:
      endpoints: [http://127.0.0.1:9]
      health:
        active:
          path: https://not-origin-form.test/healthz
          interval: 10ms
          timeout: 10ms
          healthy_statuses: [200]
          healthy_threshold: 1
          unhealthy_threshold: 1
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      type: respond
"#,
        )
        .expect("failed candidate source is written");
        let error = Compiler::compile_path(path).expect_err("candidate compilation must fail");
        assert_eq!(error.diagnostics[0].code, "resource.cluster_health_path");
    }

    struct CountingBody {
        frames: VecDeque<Result<Frame<Bytes>, Infallible>>,
        polls: Arc<AtomicU64>,
    }

    impl Body for CountingBody {
        type Data = Bytes;
        type Error = Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(self.frames.pop_front())
        }

        fn is_end_stream(&self) -> bool {
            self.frames.is_empty()
        }

        fn size_hint(&self) -> SizeHint {
            SizeHint::default()
        }
    }

    #[tokio::test]
    async fn response_body_discard_stops_at_the_fixed_cap() {
        let polls = Arc::new(AtomicU64::new(0));
        let chunk = Bytes::from(vec![0; MAX_HEALTH_RESPONSE_BODY_BYTES / 2]);
        let body = CountingBody {
            frames: VecDeque::from([
                Ok(Frame::data(chunk.clone())),
                Ok(Frame::data(chunk.clone())),
                Ok(Frame::data(chunk)),
            ]),
            polls: Arc::clone(&polls),
        };
        assert!(discard_bounded_body(body).await);
        assert_eq!(polls.load(Ordering::Relaxed), 2);
    }
}
