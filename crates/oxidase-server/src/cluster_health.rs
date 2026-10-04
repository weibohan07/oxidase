//! Commit-activated active health checking for prepared Clusters.
//!
//! Runtime preparation remains side-effect free. The server manager calls
//! [`ClusterHealthManager::activate_snapshot`] only after publishing a snapshot;
//! failed candidates therefore cannot leak health-check tasks.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

#[cfg(test)]
use std::sync::atomic::AtomicU64;

use bytes::{Buf, Bytes};
use futures_util::stream::{self, StreamExt as _};
use http::{Method, Request, Uri};
use http_body::Body;
use http_body_util::{BodyExt, Empty};
use oxidase_config::ActiveHealthSpec;
use oxidase_core::ResourceId;
use oxidase_runtime::{
    PreparedCluster, PreparedEndpoint, ResourceCancellationHandle, ResourceCensus, ResourceKind,
    ResourceState, RuntimeSnapshot,
};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::static_targets::{StaticTargetCache, static_upstream_pool_observed};
use crate::upstream_pool::{BoundedPoolRegistry, PoolPurpose};
use crate::upstream_transport::{TransportError, TransportErrorKind, TransportPhase};

const MAX_HEALTH_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const HEALTH_POOL_MAX_IDLE_PER_HOST: usize = 8;
const MAX_CONCURRENT_HEALTH_PROBES: usize = 64;
const MAX_CONCURRENT_CLUSTER_PROBES: usize = 32;

/// Owns the long-lived health-check pools and all committed supervisor tasks.
///
/// A manager is scoped to one running server. Dropping it aborts any remaining
/// tasks; normal shutdown first asks tasks to stop cooperatively.
pub(crate) struct ClusterHealthManager {
    client: Arc<HealthClient>,
    census: Arc<ResourceCensus>,
    supervisors: BTreeMap<ResourceId, HealthSupervisor>,
    tasks: JoinSet<()>,
    #[cfg(test)]
    counters: Arc<SupervisorTaskCounters>,
}

struct HealthSupervisor {
    owner: Weak<PreparedCluster>,
    cancel: watch::Sender<bool>,
    task: tokio::task::AbortHandle,
    observation: ResourceCancellationHandle,
}

impl HealthSupervisor {
    fn stop(&self) {
        self.observation.cancel_requested();
        let _ = self.cancel.send(true);
        self.task.abort();
    }
}

impl ClusterHealthManager {
    #[cfg(test)]
    pub(crate) fn new() -> Result<Self, String> {
        Self::with_census(ResourceCensus::process())
    }

    pub(crate) fn with_census(census: Arc<ResourceCensus>) -> Result<Self, String> {
        let client = Arc::new(HealthClient::with_census(Arc::clone(&census))?);
        Ok(Self {
            client,
            census,
            supervisors: BTreeMap::new(),
            tasks: JoinSet::new(),
            #[cfg(test)]
            counters: Arc::new(SupervisorTaskCounters::default()),
        })
    }

    /// Activates active-health supervisors for one committed snapshot.
    ///
    /// Unchanged resources retain exactly one manager-owned supervisor. Removed
    /// or replaced resources stop immediately even when an old request still
    /// pins their snapshot; a resource latch cannot prevent explicit resume.
    pub(crate) fn activate_snapshot(&mut self, snapshot: &RuntimeSnapshot) -> usize {
        self.reap_finished();
        self.client.reconcile_snapshot(snapshot);
        self.supervisors.retain(|id, supervisor| {
            let keep = snapshot.resources.clusters.get(id).is_some_and(|cluster| {
                cluster.spec().health.active.is_some()
                    && supervisor
                        .owner
                        .upgrade()
                        .is_some_and(|owner| Arc::ptr_eq(&owner, cluster))
                    && !supervisor.task.is_finished()
            });
            if !keep {
                supervisor.stop();
            }
            keep
        });
        let mut activated = 0;
        for cluster in snapshot.resources.clusters.values() {
            if cluster.spec().health.active.is_none() || self.supervisors.contains_key(cluster.id())
            {
                continue;
            }
            activated += 1;
            let (cancel, receiver) = watch::channel(false);
            let lifetime = self
                .census
                .token(ResourceKind::HealthSupervisor, ResourceState::Scheduled);
            let observation = lifetime.cancellation_handle();
            let weak = Arc::downgrade(cluster);
            let client = Arc::clone(&self.client);
            #[cfg(test)]
            let counters = Arc::clone(&self.counters);
            let task = self.tasks.spawn(async move {
                lifetime.transition(ResourceState::Running);
                run_cluster_supervisor(
                    weak,
                    client,
                    receiver,
                    #[cfg(test)]
                    counters,
                )
                .await;
                drop(lifetime);
            });
            self.supervisors.insert(
                cluster.id().clone(),
                HealthSupervisor {
                    owner: Arc::downgrade(cluster),
                    cancel,
                    task,
                    observation,
                },
            );
        }
        activated
    }

    /// Stops all health work and waits for task termination.
    pub(crate) async fn shutdown(&mut self) {
        for supervisor in self.supervisors.values() {
            supervisor.observation.cancel_requested();
            let _ = supervisor.cancel.send(true);
        }
        while self.tasks.join_next().await.is_some() {}
        self.supervisors.clear();
    }

    fn reap_finished(&mut self) {
        while self.tasks.try_join_next().is_some() {}
        self.supervisors
            .retain(|_, supervisor| !supervisor.task.is_finished());
    }

    #[cfg(test)]
    fn counters(&self) -> Arc<SupervisorTaskCounters> {
        Arc::clone(&self.counters)
    }
}

impl Drop for ClusterHealthManager {
    fn drop(&mut self) {
        for supervisor in self.supervisors.values() {
            supervisor.stop();
        }
        self.client.admission.close();
        self.tasks.abort_all();
    }
}

struct HealthClient {
    pool_registry: BoundedPoolRegistry<Empty<Bytes>>,
    targets: StaticTargetCache,
    admission: Semaphore,
    census: Arc<ResourceCensus>,
    #[cfg(test)]
    peak_concurrency: AtomicU64,
}

impl HealthClient {
    #[cfg(test)]
    fn new() -> Result<Self, String> {
        Self::with_census(ResourceCensus::process())
    }

    fn with_census(census: Arc<ResourceCensus>) -> Result<Self, String> {
        Ok(Self {
            pool_registry: BoundedPoolRegistry::with_census(
                1024,
                PoolPurpose::Health,
                Arc::clone(&census),
            ),
            targets: StaticTargetCache::new(1024),
            admission: Semaphore::new(MAX_CONCURRENT_HEALTH_PROBES),
            census,
            #[cfg(test)]
            peak_concurrency: AtomicU64::new(0),
        })
    }

    fn reconcile_snapshot(&self, snapshot: &RuntimeSnapshot) {
        self.pool_registry.reconcile_snapshot(snapshot);
        self.targets.reconcile_snapshot(snapshot);
    }

    async fn probe(
        &self,
        cluster: &Arc<PreparedCluster>,
        endpoint: &Arc<PreparedEndpoint>,
        plan: &ActiveHealthSpec,
    ) -> Option<bool> {
        // This is an entered logical probe future, not a separately spawned
        // Tokio task or proof that a Hyper connection has closed.
        let observation = self
            .census
            .token(ResourceKind::HealthProbe, ResourceState::Waiting);
        // Fair local health admission is independent of business permits. Its
        // queue does not consume an endpoint's network deadline or count as a
        // failed endpoint observation. A cancelled round drops these waits and
        // all acquired permits without leaving per-endpoint tasks behind.
        let Ok(_permit) = self.admission.acquire().await else {
            return None;
        };
        // The endpoint may have been withdrawn while waiting for fair local
        // quota. Never issue a new physical probe for an unleased old member.
        if !cluster.contains_endpoint(endpoint) {
            return None;
        }
        observation.transition(ResourceState::Running);
        #[cfg(test)]
        self.peak_concurrency.fetch_max(
            (MAX_CONCURRENT_HEALTH_PROBES - self.admission.available_permits()) as u64,
            Ordering::Relaxed,
        );
        let Some(deadline) = tokio::time::Instant::now().checked_add(plan.timeout) else {
            return Some(false);
        };
        let physical_ready = AtomicBool::new(false);
        match tokio::time::timeout_at(deadline, async {
            let pool = match static_upstream_pool_observed(
                &self.pool_registry,
                &self.targets,
                cluster,
                endpoint,
                cluster.protocol(),
                HEALTH_POOL_MAX_IDLE_PER_HOST,
                &physical_ready,
            )
            .await
            {
                Ok(pool) => pool,
                Err(error)
                    if error.phase() == TransportPhase::Resolve
                        || error.kind() == TransportErrorKind::ConnectionCapacity =>
                {
                    return None;
                }
                Err(_) => return Some(false),
            };
            let request = Request::builder()
                .method(Method::GET)
                .uri(health_uri(endpoint, &plan.path)?)
                .body(Empty::new())
                .ok()?;
            // The probe has one independent total budget including resolution,
            // transport, response head and bounded body discard. It never uses
            // business retries or consumes business admission permits.
            let response = match pool.request(request).await {
                Ok(response) => response,
                Err(error) => {
                    if let Some(transport) = find_transport_error(&error) {
                        if transport.phase() == TransportPhase::Resolve
                            || matches!(
                                transport.kind(),
                                TransportErrorKind::ConnectionCapacity
                                    | TransportErrorKind::ResolutionCapacity
                                    | TransportErrorKind::DeadlineOutOfRange
                            )
                        {
                            return None;
                        }
                        if transport.phase() == TransportPhase::Connect
                            && matches!(
                                transport.kind(),
                                TransportErrorKind::Io | TransportErrorKind::Timeout
                            )
                        {
                            // A later probe may reselect among the same bounded
                            // validated native answers, never retarget this
                            // already-issued Client or retry this probe.
                            self.pool_registry.retire_failed_pool(&pool);
                        }
                    }
                    return Some(false);
                }
            };
            let status = response.status().as_u16();
            if !discard_bounded_body(response.into_body()).await {
                return Some(false);
            }
            Some(
                plan.healthy_statuses
                    .iter()
                    .any(|range| range.contains(status)),
            )
        })
        .await
        {
            Ok(outcome) => outcome,
            Err(_) if physical_ready.load(Ordering::Acquire) => Some(false),
            Err(_) => None,
        }
    }
}

fn find_transport_error<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a TransportError> {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(transport) = error.downcast_ref::<TransportError>() {
            return Some(transport);
        }
        source = error.source();
    }
    None
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
        // Construct at most 32 futures for this resource instead of starting
        // every endpoint at once. Completion advances the finite endpoint
        // iterator, so a large set cannot starve behind a fixed first batch.
        let round = async {
            let endpoints = cluster.endpoints();
            let mut probes = stream::iter(endpoints.iter().cloned())
                .map(|endpoint| {
                    let cluster = &cluster;
                    let client = &client;
                    let plan = &plan;
                    async move {
                        let outcome = client.probe(cluster, &endpoint, plan).await;
                        (endpoint, outcome)
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_CLUSTER_PROBES);
            while let Some((endpoint, outcome)) = probes.next().await {
                if let Some(succeeded) = outcome {
                    cluster.record_active_health_for(&endpoint, succeeded, Instant::now());
                }
            }
        };
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            () = round => {},
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

    use super::{
        ClusterHealthManager, MAX_CONCURRENT_CLUSTER_PROBES, MAX_CONCURRENT_HEALTH_PROBES,
        MAX_HEALTH_RESPONSE_BODY_BYTES, discard_bounded_body,
    };

    struct HealthFixture {
        address: std::net::SocketAddr,
        status: Arc<AtomicU16>,
        delay_ms: Arc<AtomicU64>,
        requests: Arc<AtomicU64>,
        accepts: Arc<AtomicU64>,
        active_requests: Arc<AtomicU64>,
        peak_requests: Arc<AtomicU64>,
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
            let active_requests = Arc::new(AtomicU64::new(0));
            let peak_requests = Arc::new(AtomicU64::new(0));
            let request_targets = Arc::new(Mutex::new(Vec::new()));
            let (shutdown, mut shutdown_receiver) = watch::channel(false);
            let task_status = Arc::clone(&status);
            let task_delay_ms = Arc::clone(&delay_ms);
            let task_requests = Arc::clone(&requests);
            let task_accepts = Arc::clone(&accepts);
            let task_active_requests = Arc::clone(&active_requests);
            let task_peak_requests = Arc::clone(&peak_requests);
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
                                Arc::clone(&task_active_requests),
                                Arc::clone(&task_peak_requests),
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
                active_requests,
                peak_requests,
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
        active_requests: Arc<AtomicU64>,
        peak_requests: Arc<AtomicU64>,
        request_targets: Arc<Mutex<Vec<String>>>,
    ) {
        let service = service_fn(move |request: Request<Incoming>| {
            let status = Arc::clone(&status);
            let delay_ms = Arc::clone(&delay_ms);
            let requests = Arc::clone(&requests);
            let active_requests = Arc::clone(&active_requests);
            let peak_requests = Arc::clone(&peak_requests);
            let request_targets = Arc::clone(&request_targets);
            async move {
                requests.fetch_add(1, Ordering::Relaxed);
                let active = active_requests.fetch_add(1, Ordering::Relaxed) + 1;
                peak_requests.fetch_max(active, Ordering::Relaxed);
                let _request_guard = FixtureRequestGuard(active_requests);
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

    struct FixtureRequestGuard(Arc<AtomicU64>);

    impl Drop for FixtureRequestGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
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
    async fn removed_cluster_stops_supervisor_even_when_an_old_snapshot_is_pinned() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let old = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(100),
            1,
            1,
        );
        let mut manager = ClusterHealthManager::new().expect("manager");
        assert_eq!(manager.activate_snapshot(&old), 1);
        wait_until(|| fixture.requests.load(Ordering::Relaxed) > 0).await;
        let mut removed = old.clone();
        removed.resources.clusters.clear();
        assert_eq!(manager.activate_snapshot(&removed), 0);
        wait_until(|| manager.counters().active.load(Ordering::Relaxed) == 0).await;
        assert!(
            old.resources.clusters.values().next().is_some(),
            "held old snapshot remains valid"
        );
        let before = fixture.requests.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(
            fixture.requests.load(Ordering::Relaxed),
            before,
            "old pinned owner cannot keep probing after removal"
        );
        assert!(manager.supervisors.is_empty());
        assert_eq!(
            manager.client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
        manager.shutdown().await;
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replaced_health_policy_cancels_old_owner_and_same_arc_resume_restarts_once() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let old = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(100),
            1,
            1,
        );
        let old_cluster = old.resources.clusters.values().next().expect("old cluster");
        let mut manager = ClusterHealthManager::new().expect("manager");
        assert_eq!(manager.activate_snapshot(&old), 1);
        wait_until(|| {
            old_cluster.status(Instant::now()).endpoints[0]
                .runtime
                .active_health_successes
                > 0
        })
        .await;
        let (replacement, _) = RuntimeSnapshot::prepare_reusing(
            compile_gateway(
                &fixture,
                Duration::from_millis(20),
                Duration::from_millis(100),
                1,
                1,
            ),
            Some(&old),
        )
        .expect("replacement policy");
        let current_cluster = replacement
            .resources
            .clusters
            .values()
            .next()
            .expect("new cluster");
        assert!(!Arc::ptr_eq(old_cluster, current_cluster));
        assert_eq!(manager.activate_snapshot(&replacement), 1);
        assert_eq!(manager.activate_snapshot(&replacement), 0);
        wait_until(|| {
            manager.counters().finished.load(Ordering::Relaxed) == 1
                && current_cluster.status(Instant::now()).endpoints[0]
                    .runtime
                    .active_health_successes
                    > 0
        })
        .await;
        let old_success = old_cluster.status(Instant::now()).endpoints[0]
            .runtime
            .active_health_successes;
        tokio::time::sleep(Duration::from_millis(45)).await;
        assert_eq!(
            old_cluster.status(Instant::now()).endpoints[0]
                .runtime
                .active_health_successes,
            old_success
        );
        assert_eq!(manager.counters().active.load(Ordering::Relaxed), 1);
        manager.shutdown().await;
        assert_eq!(manager.counters().active.load(Ordering::Relaxed), 0);
        assert_eq!(
            manager.client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
        let current_success = current_cluster.status(Instant::now()).endpoints[0]
            .runtime
            .active_health_successes;
        assert_eq!(
            manager.activate_snapshot(&replacement),
            1,
            "explicit resume must not be blocked by a one-shot resource latch"
        );
        assert_eq!(manager.activate_snapshot(&replacement), 0);
        wait_until(|| {
            current_cluster.status(Instant::now()).endpoints[0]
                .runtime
                .active_health_successes
                > current_success
        })
        .await;
        assert_eq!(manager.counters().started.load(Ordering::Relaxed), 3);
        manager.shutdown().await;
        assert_eq!(manager.counters().finished.load(Ordering::Relaxed), 3);
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retired_endpoint_is_rechecked_after_local_health_admission_wait() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let old = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(100),
            1,
            1,
        );
        let old_endpoint = Arc::clone(
            &old.resources
                .clusters
                .values()
                .next()
                .expect("old")
                .endpoints()[0],
        );
        let (replacement, _) = RuntimeSnapshot::prepare_reusing(
            compile_gateway(
                &fixture,
                Duration::from_millis(20),
                Duration::from_millis(100),
                1,
                1,
            ),
            Some(&old),
        )
        .expect("changed policy");
        let cluster = Arc::clone(
            replacement
                .resources
                .clusters
                .values()
                .next()
                .expect("current"),
        );
        assert!(!cluster.contains_endpoint(&old_endpoint));
        let client = Arc::new(super::HealthClient::new().expect("client"));
        client.reconcile_snapshot(&replacement);
        let quota = client
            .admission
            .acquire_many(MAX_CONCURRENT_HEALTH_PROBES as u32)
            .await
            .expect("hold global health quota");
        let caller = Arc::clone(&client);
        let plan = cluster.spec().health.active.clone().expect("health");
        let probe = tokio::spawn(async move { caller.probe(&cluster, &old_endpoint, &plan).await });
        tokio::task::yield_now().await;
        assert!(
            !probe.is_finished(),
            "health wait is outside endpoint timeout"
        );
        drop(quota);
        assert_eq!(
            probe.await.expect("probe cancelled at membership boundary"),
            None
        );
        assert_eq!(
            fixture.requests.load(Ordering::Relaxed),
            0,
            "no new probe may issue for the removed Arc after quota admission"
        );
        assert_eq!(
            client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
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

    fn prepare_many_clusters(
        fixture: &HealthFixture,
        clusters: usize,
        endpoints: usize,
    ) -> RuntimeSnapshot {
        use std::fmt::Write as _;

        let directory = TempDir::new().expect("temporary quota fixture");
        let path = directory.path().join("gateway.yaml");
        let mut text =
            "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n"
                .to_owned();
        for cluster in 0..clusters {
            writeln!(text, "    api-{cluster}:\n      endpoints:").expect("String write");
            for endpoint in 0..endpoints {
                writeln!(
                    text,
                    "        - name: endpoint-{endpoint}\n          url: http://{}/base-{cluster}",
                    fixture.address
                )
                .expect("String write");
            }
            text.push_str("      health:\n        active:\n          path: /healthz\n          interval: 10s\n          timeout: 5s\n          healthy_statuses: [200]\n          healthy_threshold: 1\n          unhealthy_threshold: 1\n");
        }
        text.push_str("listeners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      type: respond\n");
        std::fs::write(&path, text).expect("quota fixture written");
        RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("quota fixture compiles"))
            .expect("quota fixture prepares")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_rounds_enforce_global_and_per_cluster_quotas_without_starving_late_endpoints() {
        for clusters in [1, 3] {
            let fixture = HealthFixture::spawn(StatusCode::OK).await;
            fixture.set_delay(Duration::from_millis(30));
            let snapshot =
                prepare_many_clusters(&fixture, clusters, MAX_CONCURRENT_CLUSTER_PROBES + 1);
            let mut manager = ClusterHealthManager::new().expect("health manager");
            assert_eq!(manager.activate_snapshot(&snapshot), clusters);
            tokio::time::timeout(Duration::from_secs(10), async {
                while !snapshot.resources.clusters.values().all(|cluster| {
                    cluster.endpoints().iter().all(|endpoint| {
                        endpoint.health_state(Instant::now()) == EndpointHealthState::Healthy
                    })
                }) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("all endpoints, including after the first 32, get a healthy observation");
            let cap = if clusters == 1 {
                MAX_CONCURRENT_CLUSTER_PROBES
            } else {
                MAX_CONCURRENT_HEALTH_PROBES
            } as u64;
            let observed_peak = fixture.peak_requests.load(Ordering::Relaxed);
            assert!(
                observed_peak > 0 && observed_peak <= cap,
                "actual HTTP probe concurrency {observed_peak} exceeds {cap}"
            );
            assert!(manager.client.peak_concurrency.load(Ordering::Relaxed) <= cap);
            assert_eq!(
                fixture.requests.load(Ordering::Relaxed),
                (clusters * (MAX_CONCURRENT_CLUSTER_PROBES + 1)) as u64
            );
            assert_eq!(
                manager.client.admission.available_permits(),
                MAX_CONCURRENT_HEALTH_PROBES
            );
            manager.shutdown().await;
            assert_eq!(manager.counters().active.load(Ordering::Relaxed), 0);
            assert_eq!(fixture.active_requests.load(Ordering::Relaxed), 0);
            fixture.shutdown().await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn local_health_admission_wait_is_not_an_endpoint_failure_and_shutdown_cancels_it() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(5),
            1,
            1,
        );
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let mut manager = ClusterHealthManager::new().expect("health manager");
        let client = Arc::clone(&manager.client);
        let held = client
            .admission
            .acquire_many(MAX_CONCURRENT_HEALTH_PROBES as u32)
            .await
            .expect("hold all local health quota");
        manager.activate_snapshot(&snapshot);
        wait_until(|| manager.counters().started.load(Ordering::Relaxed) == 1).await;
        // Deliberately longer than the endpoint's network timeout. Local quota
        // waiting cannot falsely eject a healthy endpoint.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            cluster.endpoints()[0].health_state(Instant::now()),
            EndpointHealthState::UnknownEligible
        );
        assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);
        tokio::time::timeout(Duration::from_secs(1), manager.shutdown())
            .await
            .expect("shutdown drops queued health futures cooperatively");
        assert_eq!(manager.counters().active.load(Ordering::Relaxed), 0);
        assert_eq!(
            cluster.endpoints()[0].health_state(Instant::now()),
            EndpointHealthState::UnknownEligible
        );
        drop(held);
        assert_eq!(
            client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_resolution_failure_does_not_eject_a_previously_healthy_physical_endpoint() {
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let mut gateway = compile_gateway(
            &fixture,
            Duration::from_millis(10),
            Duration::from_millis(50),
            1,
            1,
        );
        gateway
            .resources
            .clusters
            .values_mut()
            .next()
            .expect("cluster source")
            .endpoints[0]
            .url = "http://unresolved.oxidase.invalid/"
            .parse()
            .expect("logical origin");
        let snapshot =
            RuntimeSnapshot::prepare(gateway).expect("native name policy prepares without DNS");
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let endpoints = cluster.endpoints();
        let endpoint = endpoints[0].name();
        cluster.record_active_health(endpoint, true, Instant::now());
        let calls = Arc::new(AtomicU64::new(0));
        let lookup_calls = Arc::clone(&calls);
        let mut manager = ClusterHealthManager::new().expect("manager");
        Arc::get_mut(&mut manager.client)
            .expect("sole bootstrap client owner")
            .targets = crate::static_targets::StaticTargetCache::with_lookup(1024, move |_| {
            lookup_calls.fetch_add(1, Ordering::Relaxed);
            Err(crate::upstream_transport::TransportError::new(
                crate::upstream_transport::TransportPhase::Resolve,
                crate::upstream_transport::TransportErrorKind::Io,
                Some(Box::new(std::io::Error::other("fixture DNS outage"))),
            ))
        });
        manager.activate_snapshot(&snapshot);
        wait_until(|| calls.load(Ordering::Relaxed) > 0).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            cluster.endpoints()[0].health_state(Instant::now()),
            EndpointHealthState::Healthy
        );
        assert_eq!(
            cluster.status(Instant::now()).endpoints[0]
                .runtime
                .active_health_failures,
            0
        );
        assert_eq!(fixture.requests.load(Ordering::Relaxed), 0);
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

    fn resource_count(
        census: &oxidase_runtime::ResourceCensus,
        kind: oxidase_runtime::ResourceKind,
    ) -> oxidase_runtime::ResourceCount {
        census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == kind)
            .expect("fixed census kind")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn health_census_tracks_abort_before_first_poll_until_actual_future_drop_without_scrape()
    {
        use oxidase_runtime::{ResourceCensus, ResourceKind, ResourceState};
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_secs(30),
            Duration::from_secs(30),
            1,
            1,
        );
        let census = Arc::new(ResourceCensus::default());
        let mut manager = ClusterHealthManager::with_census(Arc::clone(&census))
            .expect("isolated health manager");
        assert_eq!(manager.activate_snapshot(&snapshot), 1);
        let before = resource_count(&census, ResourceKind::HealthSupervisor);
        assert_eq!((before.created, before.destroyed, before.live), (1, 0, 1));
        assert_eq!(
            before
                .states
                .iter()
                .find(|row| row.state == ResourceState::Scheduled)
                .expect("scheduled state")
                .live,
            1
        );
        let mut removed = snapshot.clone();
        removed.resources.clusters.clear();
        assert_eq!(manager.activate_snapshot(&removed), 0);
        let cancelling = resource_count(&census, ResourceKind::HealthSupervisor);
        assert_eq!(
            cancelling.live, 1,
            "abort is a request, not completion; current-thread task has not run"
        );
        assert_eq!(
            cancelling
                .states
                .iter()
                .find(|row| row.state == ResourceState::Exiting)
                .expect("exiting state")
                .live,
            1
        );
        assert!(
            manager
                .tasks
                .join_next()
                .await
                .expect("scheduled task exists")
                .expect_err("task was aborted")
                .is_cancelled()
        );
        let completed = resource_count(&census, ResourceKind::HealthSupervisor);
        assert_eq!(
            (completed.created, completed.destroyed, completed.live),
            (1, 1, 0)
        );
        assert_eq!(
            resource_count(&census, ResourceKind::HealthProbe).created,
            0
        );
        assert_eq!(fixture.requests.load(Ordering::Acquire), 0);
        assert_eq!(census.sample().invariant_failures, 0);
        manager.shutdown().await;
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn health_probe_census_distinguishes_admission_wait_and_cancellation_without_scrape() {
        use oxidase_runtime::{ResourceCensus, ResourceKind, ResourceState};
        let fixture = HealthFixture::spawn(StatusCode::OK).await;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_secs(30),
            Duration::from_secs(30),
            1,
            1,
        );
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let endpoints = cluster.endpoints();
        let endpoint = &endpoints[0];
        let plan = cluster
            .spec()
            .health
            .active
            .as_ref()
            .expect("active health policy");
        let census = Arc::new(ResourceCensus::default());
        let client =
            super::HealthClient::with_census(Arc::clone(&census)).expect("isolated health client");
        let quota = client
            .admission
            .acquire_many(MAX_CONCURRENT_HEALTH_PROBES as u32)
            .await
            .expect("hold global quota");
        let mut probe = Box::pin(client.probe(cluster, endpoint, plan));
        assert!(futures_util::poll!(probe.as_mut()).is_pending());
        let waiting = resource_count(&census, ResourceKind::HealthProbe);
        assert_eq!(
            (waiting.created, waiting.destroyed, waiting.live),
            (1, 0, 1)
        );
        assert_eq!(
            waiting
                .states
                .iter()
                .find(|row| row.state == ResourceState::Waiting)
                .expect("waiting state")
                .live,
            1
        );
        assert_eq!(
            waiting
                .states
                .iter()
                .find(|row| row.state == ResourceState::Running)
                .expect("running state")
                .live,
            0
        );
        drop(probe);
        let cancelled = resource_count(&census, ResourceKind::HealthProbe);
        assert_eq!(
            (cancelled.created, cancelled.destroyed, cancelled.live),
            (1, 1, 0)
        );
        assert_eq!(
            client.admission.available_permits(),
            0,
            "only test-held quota remains"
        );
        drop(quota);
        assert_eq!(
            client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
        assert_eq!(fixture.requests.load(Ordering::Acquire), 0);
        assert_eq!(census.sample().invariant_failures, 0);
        fixture.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_health_probe_retirement_counts_future_exit_not_abort_or_manager_entry() {
        use oxidase_runtime::{ResourceCensus, ResourceKind, ResourceState};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::sync::oneshot;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("controlled health socket");
        let address = listener.local_addr().expect("health address");
        let (arrived, request_arrived) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let fixture_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("real probe connected");
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.expect("probe header byte"), 1);
                headers.push(byte[0]);
                assert!(headers.len() <= 8192, "test health head is bounded");
            }
            arrived.send(()).expect("probe reception acknowledged");
            released.await.expect("controlled server release");
            // A cancelled probe may already have closed its socket. This test
            // deliberately proves logical future lifetime, not that all Hyper
            // drivers or physical sockets exit when its token exits.
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        let mut fixture = HealthFixture::spawn(StatusCode::OK).await;
        fixture.address = address;
        let snapshot = prepare_snapshot(
            &fixture,
            Duration::from_secs(30),
            Duration::from_secs(30),
            1,
            1,
        );
        let census = Arc::new(ResourceCensus::default());
        let mut manager = ClusterHealthManager::with_census(Arc::clone(&census))
            .expect("isolated health manager");
        assert_eq!(manager.activate_snapshot(&snapshot), 1);
        tokio::time::timeout(Duration::from_secs(3), request_arrived)
            .await
            .expect("actual probe reached fixture")
            .expect("probe acknowledgement");
        assert_eq!(resource_count(&census, ResourceKind::HealthProbe).live, 1);
        let mut removed = snapshot.clone();
        removed.resources.clusters.clear();
        assert_eq!(manager.activate_snapshot(&removed), 0);
        assert!(manager.supervisors.is_empty());
        let requested = resource_count(&census, ResourceKind::HealthSupervisor);
        assert_eq!(
            requested.live, 1,
            "manager entry removal is not task destruction"
        );
        assert_eq!(
            requested
                .states
                .iter()
                .find(|row| row.state == ResourceState::Exiting)
                .expect("exiting state")
                .live,
            1
        );
        assert_eq!(resource_count(&census, ResourceKind::HealthProbe).live, 1);
        assert!(
            manager
                .tasks
                .join_next()
                .await
                .expect("retired task")
                .expect_err("supervisor cancelled")
                .is_cancelled()
        );
        for kind in [ResourceKind::HealthSupervisor, ResourceKind::HealthProbe] {
            let row = resource_count(&census, kind);
            assert_eq!((row.created, row.destroyed, row.live), (1, 1, 0));
        }
        assert_eq!(
            manager.client.admission.available_permits(),
            MAX_CONCURRENT_HEALTH_PROBES
        );
        release
            .send(())
            .expect("release blocked fixture explicitly");
        fixture_task.await.expect("actual fixture task finished");
        assert_eq!(census.sample().invariant_failures, 0);
        manager.shutdown().await;
        fixture.shutdown().await;
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
