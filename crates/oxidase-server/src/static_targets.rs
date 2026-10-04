//! Bounded native-name cache for configured static endpoints only.
//!
//! This is not dynamic DNS discovery and carries no DNS TTL claim. A successful
//! native answer is cached for 90 seconds. Native temporary failures may retain
//! that selected, validated answer for another fixed 90 seconds, with 5-second
//! failure suppression. Neither bound slides on errors. Dynamic discovery must
//! instead use its separately observed record expirations and result classes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use futures_util::FutureExt as _;
use futures_util::future::{BoxFuture, Shared};
use http_body::Body;
use hyper_util::client::legacy::Client;
use oxidase_config::ClusterProtocol;
use oxidase_core::{ContentDigest, ContentDigestBuilder, ResourceId};
use oxidase_runtime::{PreparedCluster, PreparedEndpoint, RuntimeSnapshot};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::body::BoxError;
use crate::upstream_pool::BoundedPoolRegistry;
use crate::upstream_transport::{
    DialTarget, DirectConnector, LogicalOrigin, MAX_STATIC_ADDRESSES, TransportError,
    TransportErrorKind, TransportPhase, TransportTimeouts,
};

const FRESH: Duration = Duration::from_secs(90);
const STALE: Duration = Duration::from_secs(90);
const RETRY_AFTER: Duration = Duration::from_secs(5);
const MAX_NATIVE_JOBS: usize = 32;
const MAX_PRECONNECTS: usize = 1024;

struct ColdConnectBudget {
    deadline: Instant,
}

impl ColdConnectBudget {
    fn new(limit: Duration) -> Result<Self, TransportError> {
        Instant::now()
            .checked_add(limit)
            .map(|deadline| Self { deadline })
            .ok_or_else(|| {
                TransportError::new(
                    TransportPhase::Connect,
                    TransportErrorKind::DeadlineOutOfRange,
                    None,
                )
            })
    }

    fn remaining(&self) -> Result<Duration, TransportError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(TransportError::new(
                TransportPhase::Connect,
                TransportErrorKind::Timeout,
                None,
            ))
        } else {
            Ok(remaining)
        }
    }
}
type Flight = Shared<BoxFuture<'static, Arc<Result<Vec<DialTarget>, TransportError>>>>;
#[cfg(test)]
type TestLookup = dyn Fn(LogicalOrigin) -> Result<Vec<DialTarget>, TransportError> + Send + Sync;

pub(crate) struct StaticTargetCache {
    capacity: usize,
    inner: Mutex<CacheIndex>,
    admission: Arc<Semaphore>,
    connect_admission: Arc<Semaphore>,
    #[cfg(test)]
    lookup: Option<Arc<TestLookup>>,
}

struct CacheIndex {
    current: BTreeMap<ResourceId, Weak<PreparedCluster>>,
    reconciled: bool,
    clock: u64,
    entries: BTreeMap<ContentDigest, CacheEntry>,
}

struct CacheEntry {
    owner: Weak<PreparedCluster>,
    cluster: ResourceId,
    endpoint: String,
    state: Arc<Mutex<CachedAnswer>>,
    last_used: u64,
}

#[derive(Default)]
struct CachedAnswer {
    targets: Vec<DialTarget>,
    fresh_until: Option<Instant>,
    stale_until: Option<Instant>,
    retry_at: Option<Instant>,
    last_error: Option<TransportError>,
    flight: Option<(u64, Flight)>,
    sequence: u64,
}

impl StaticTargetCache {
    #[cfg(test)]
    pub(crate) fn with_lookup<F>(capacity: usize, lookup: F) -> Self
    where
        F: Fn(LogicalOrigin) -> Result<Vec<DialTarget>, TransportError> + Send + Sync + 'static,
    {
        let mut cache = Self::new(capacity);
        cache.lookup = Some(Arc::new(lookup));
        cache
    }

    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(CacheIndex {
                current: BTreeMap::new(),
                reconciled: false,
                clock: 0,
                entries: BTreeMap::new(),
            }),
            admission: Arc::new(Semaphore::new(MAX_NATIVE_JOBS)),
            connect_admission: Arc::new(Semaphore::new(MAX_PRECONNECTS)),
            #[cfg(test)]
            lookup: None,
        }
    }

    pub(crate) fn reconcile_snapshot(&self, snapshot: &RuntimeSnapshot) {
        let mut index = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        index.current = snapshot
            .resources
            .clusters
            .iter()
            .map(|(id, cluster)| (id.clone(), Arc::downgrade(cluster)))
            .collect();
        index.reconciled = true;
        index.entries.retain(|key, entry| {
            let Some(owner) = snapshot.resources.clusters.get(&entry.cluster) else {
                return false;
            };
            let endpoints = owner.endpoints();
            let Some(endpoint) = endpoints
                .iter()
                .find(|endpoint| endpoint.name() == entry.endpoint)
            else {
                return false;
            };
            if static_key(owner, endpoint) != *key {
                return false;
            }
            entry.owner = Arc::downgrade(owner);
            true
        });
    }

    fn entry(
        &self,
        cluster: &Arc<PreparedCluster>,
        endpoint: &PreparedEndpoint,
    ) -> Arc<Mutex<CachedAnswer>> {
        let key = static_key(cluster, endpoint);
        let mut index = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        index
            .entries
            .retain(|_, entry| entry.owner.strong_count() > 0);
        index.clock = index.clock.saturating_add(1);
        let now = index.clock;
        if let Some(entry) = index.entries.get_mut(&key) {
            entry.last_used = now;
            return Arc::clone(&entry.state);
        }
        let state = Arc::new(Mutex::new(CachedAnswer::default()));
        let is_current = !index.reconciled
            || index
                .current
                .get(cluster.id())
                .and_then(Weak::upgrade)
                .is_some_and(|owner| Arc::ptr_eq(&owner, cluster));
        if !is_current {
            return state;
        }
        if index.entries.len() >= self.capacity
            && let Some(key) = index
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| *key)
        {
            index.entries.remove(&key);
        }
        index.entries.insert(
            key,
            CacheEntry {
                owner: Arc::downgrade(cluster),
                cluster: cluster.id().clone(),
                endpoint: endpoint.name().to_owned(),
                state: Arc::clone(&state),
                last_used: now,
            },
        );
        state
    }

    pub(crate) async fn resolve(
        &self,
        cluster: &Arc<PreparedCluster>,
        endpoint: &PreparedEndpoint,
    ) -> Result<Vec<DialTarget>, TransportError> {
        let origin = LogicalOrigin::from_url(endpoint.url())?;
        if let Ok(ip) = origin.host().parse::<IpAddr>() {
            return DialTarget::new(SocketAddr::new(ip, origin.port())).map(|target| vec![target]);
        }
        let state = self.entry(cluster, endpoint);
        let now = Instant::now();
        let (flight_id, flight) = {
            let mut answer = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if answer.fresh_until.is_some_and(|expiry| now < expiry) {
                return Ok(answer.targets.clone());
            }
            if answer.retry_at.is_some_and(|retry| now < retry) {
                if answer.stale_until.is_some_and(|expiry| now < expiry)
                    && !answer.targets.is_empty()
                {
                    return Ok(answer.targets.clone());
                }
                if let Some(error) = &answer.last_error {
                    return Err(error.clone());
                }
            }
            if let Some((id, flight)) = &answer.flight {
                (*id, flight.clone())
            } else {
                let id = answer.sequence.checked_add(1).ok_or_else(|| {
                    TransportError::new(
                        TransportPhase::Resolve,
                        TransportErrorKind::ResolutionCapacity,
                        None,
                    )
                })?;
                answer.sequence = id;
                let permit = Arc::clone(&self.admission)
                    .try_acquire_owned()
                    .map_err(|_| {
                        TransportError::new(
                            TransportPhase::Resolve,
                            TransportErrorKind::ResolutionCapacity,
                            None,
                        )
                    })?;
                #[cfg(test)]
                let injected = self.lookup.clone();
                let job = tokio::task::spawn_blocking(move || {
                    // The native call itself owns admission. Cancelling an HTTP
                    // waiter cannot release the permit while libc still runs.
                    let _permit = permit;
                    #[cfg(test)]
                    if let Some(lookup) = injected {
                        return lookup(origin);
                    }
                    native_lookup(origin)
                });
                let flight = async move {
                    Arc::new(job.await.unwrap_or_else(|error| {
                        Err(TransportError::new(
                            TransportPhase::Resolve,
                            TransportErrorKind::Io,
                            Some(Box::new(error)),
                        ))
                    }))
                }
                .boxed()
                .shared();
                answer.flight = Some((id, flight.clone()));
                (id, flight)
            }
        };
        let result = flight.await;
        let mut answer = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // All coalesced callers receive the same completed immutable result.
        // Only the first consumes this flight and establishes observation time.
        if answer
            .flight
            .as_ref()
            .is_some_and(|(id, _)| *id == flight_id)
        {
            answer.flight = None;
            let observed = Instant::now();
            match result.as_ref() {
                Ok(targets) => {
                    answer.targets = targets.clone();
                    answer.fresh_until = observed.checked_add(FRESH);
                    answer.stale_until = answer
                        .fresh_until
                        .and_then(|expiry| expiry.checked_add(STALE));
                    answer.retry_at = None;
                    answer.last_error = None;
                }
                Err(error) => {
                    if !matches!(
                        error.kind(),
                        TransportErrorKind::Io | TransportErrorKind::NoAddresses
                    ) {
                        answer.targets.clear();
                        answer.fresh_until = None;
                        answer.stale_until = None;
                    }
                    answer.retry_at = observed.checked_add(RETRY_AFTER);
                    answer.last_error = Some(error.clone());
                }
            }
        }
        match result.as_ref() {
            Ok(targets) => Ok(targets.clone()),
            Err(_)
                if answer
                    .stale_until
                    .is_some_and(|expiry| Instant::now() < expiry)
                    && !answer.targets.is_empty() =>
            {
                Ok(answer.targets.clone())
            }
            Err(error) => Err(error.clone()),
        }
    }
}

fn static_key(cluster: &PreparedCluster, endpoint: &PreparedEndpoint) -> ContentDigest {
    let timing = TransportTimeouts::for_cluster(cluster);
    let mut digest = ContentDigestBuilder::new("oxidase/static-resolution/v1");
    let protocol = match cluster.protocol() {
        ClusterProtocol::Auto => "auto",
        ClusterProtocol::Http1 => "http1",
        ClusterProtocol::H2 => "h2",
    };
    digest
        .field_bytes("cluster", cluster.id().as_str())
        .field_bytes("endpoint", endpoint.name())
        .field_bytes("origin", endpoint.url().as_str())
        .field_bytes("protocol", protocol)
        .field_u128("connect_ns", timing.connect.as_nanos())
        .field_u128("tls_ns", timing.tls_handshake.as_nanos());
    if let Some(tls) = cluster.upstream_tls() {
        digest.field_digest("security_policy", tls.digest());
    }
    digest.finish()
}

fn native_lookup(origin: LogicalOrigin) -> Result<Vec<DialTarget>, TransportError> {
    let resolved = (origin.host(), origin.port())
        .to_socket_addrs()
        .map_err(|error| {
            TransportError::new(
                TransportPhase::Resolve,
                TransportErrorKind::Io,
                Some(Box::new(error)),
            )
        })?;
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for address in resolved {
        let target = DialTarget::new(address)?;
        if seen.insert(target) {
            targets.push(target);
        }
        if targets.len() > MAX_STATIC_ADDRESSES {
            return Err(TransportError::new(
                TransportPhase::Resolve,
                TransportErrorKind::AddressLimit,
                None,
            ));
        }
    }
    if targets.is_empty() {
        return Err(TransportError::new(
            TransportPhase::Resolve,
            TransportErrorKind::NoAddresses,
            None,
        ));
    }
    Ok(targets)
}

/// Reuses a pool for any still validated answer before opening a new socket.
/// Cold TCP-only fallback tries each bounded address once before body dispatch;
/// TLS authentication/ALPN failures stop immediately. The caller's one absolute
/// logical budget encloses this entire function, so address fallback cannot
/// refresh it or create another business retry/response-head opportunity.
pub(crate) async fn static_upstream_pool<B>(
    registry: &BoundedPoolRegistry<B>,
    targets: &StaticTargetCache,
    cluster: &Arc<PreparedCluster>,
    endpoint: &PreparedEndpoint,
    protocol: ClusterProtocol,
    max_idle: usize,
) -> Result<Arc<Client<DirectConnector, B>>, TransportError>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    static_upstream_pool_observed(
        registry,
        targets,
        cluster,
        endpoint,
        protocol,
        max_idle,
        &AtomicBool::new(false),
    )
    .await
}

pub(crate) async fn static_upstream_pool_observed<B>(
    registry: &BoundedPoolRegistry<B>,
    targets_cache: &StaticTargetCache,
    cluster: &Arc<PreparedCluster>,
    endpoint: &PreparedEndpoint,
    protocol: ClusterProtocol,
    max_idle: usize,
    physical_ready: &AtomicBool,
) -> Result<Arc<Client<DirectConnector, B>>, TransportError>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    let origin = LogicalOrigin::from_url(endpoint.url())?;
    // Dynamic membership already approved a concrete physical address. Never
    // hand its logical origin back to libc or a default Hyper connector.
    let targets = if let Some(target) = endpoint.dial_target() {
        let plan = cluster.spec().discovery.as_ref().ok_or_else(|| {
            TransportError::new(
                TransportPhase::Resolve,
                TransportErrorKind::AddressRejected,
                None,
            )
        })?;
        let approved = oxidase_runtime::validate_discovery_address(
            target.ip(),
            target.port(),
            &plan.address_policy,
        )
        .map_err(|_| {
            TransportError::new(
                TransportPhase::Resolve,
                TransportErrorKind::AddressRejected,
                None,
            )
        })?;
        vec![DialTarget::new(approved)?]
    } else {
        targets_cache.resolve(cluster, endpoint).await?
    };
    physical_ready.store(true, Ordering::Release);
    let connectors = targets
        .into_iter()
        .map(|target| {
            let connector = DirectConnector::new(
                origin.clone(),
                target,
                protocol,
                cluster.upstream_tls().map(Arc::as_ref),
                TransportTimeouts::for_cluster(cluster),
            )?
            .with_census(registry.census())
            .with_connection_admission(Arc::clone(&targets_cache.connect_admission))
            .with_endpoint_incarnation(endpoint.incarnation());
            Ok(
                if protocol == ClusterProtocol::Http1
                    && cluster.protocol() != ClusterProtocol::Http1
                {
                    connector.for_http1_upgrade()
                } else {
                    connector
                },
            )
        })
        .collect::<Result<Vec<_>, TransportError>>()?;
    for connector in &connectors {
        if let Some(pool) =
            registry.get_existing(connector.pool_identity(cluster.id(), endpoint.name()))
        {
            return Ok(pool);
        }
    }
    // All cold address attempts share one TCP limit. No request payload has
    // been dispatched, and neither address fallback nor pool reconnect may
    // refresh a logical request's separate absolute deadline.
    let connect_budget = ColdConnectBudget::new(TransportTimeouts::for_cluster(cluster).connect)?;
    let _connect_permit = Arc::clone(&targets_cache.connect_admission)
        .try_acquire_owned()
        .map_err(|_| {
            TransportError::new(
                TransportPhase::Connect,
                TransportErrorKind::ConnectionCapacity,
                None,
            )
        })?;
    let mut last_error = None;
    for connector in connectors {
        let key = connector.pool_identity(cluster.id(), endpoint.name());
        match connector
            .preconnect_admitted_with_connect_timeout(&_connect_permit, connect_budget.remaining()?)
            .await
        {
            Ok(connector) => {
                return Ok(registry.get_or_build(key, cluster, connector, protocol, max_idle));
            }
            Err(error)
                if error.phase() == TransportPhase::Connect
                    && matches!(
                        error.kind(),
                        TransportErrorKind::Io | TransportErrorKind::Timeout
                    ) =>
            {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        TransportError::new(
            TransportPhase::Resolve,
            TransportErrorKind::NoAddresses,
            None,
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Request, Response, header};
    use http_body_util::{BodyExt as _, Empty, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::client::legacy::connect::HttpInfo;
    use hyper_util::rt::TokioIo;
    use oxidase_config::Compiler;
    use std::convert::Infallible;
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};

    fn snapshot(host: &str) -> (RuntimeSnapshot, Arc<PreparedCluster>) {
        let directory = TempDir::new().expect("fixture directory");
        let path = directory.path().join("gateway.yaml");
        std::fs::write(&path, format!("api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      endpoints:\n        - name: origin\n          url: http://{host}/base\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      type: respond\n")).expect("source fixture");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("fixture compiles"))
                .expect("fixture prepares");
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        (snapshot, cluster)
    }

    fn answer() -> Vec<DialTarget> {
        vec![DialTarget::new("127.0.0.1:1234".parse().expect("address")).expect("target")]
    }
    fn failure() -> TransportError {
        TransportError::new(
            TransportPhase::Resolve,
            TransportErrorKind::Io,
            Some(Box::new(std::io::Error::other(
                "fixture resolution failure",
            ))),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn cold_address_fallback_uses_one_exact_tcp_deadline_not_one_per_address() {
        let budget = ColdConnectBudget::new(Duration::from_secs(5)).expect("bounded policy");
        let started = Instant::now();
        let mut attempted = 0;
        for delay in [
            Duration::from_secs(2),
            Duration::from_secs(20),
            Duration::from_secs(20),
        ] {
            let Ok(remaining) = budget.remaining() else {
                break;
            };
            attempted += 1;
            let _ = tokio::time::timeout(remaining, tokio::time::sleep(delay)).await;
        }
        assert_eq!(
            attempted, 2,
            "third blackhole must not execute after exhausted aggregate budget"
        );
        assert_eq!(
            Instant::now().duration_since(started),
            Duration::from_secs(5)
        );
        assert_eq!(
            budget
                .remaining()
                .expect_err("first excess attempt fails before dial")
                .kind(),
            TransportErrorKind::Timeout
        );
        assert_eq!(
            ColdConnectBudget::new(Duration::MAX)
                .err()
                .expect("legacy unrepresentable deadline")
                .kind(),
            TransportErrorKind::DeadlineOutOfRange
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cache_hits_skip_resolution_and_error_stale_deadline_never_slides() {
        let (snapshot, cluster) = snapshot("logical.oxidase.invalid");
        let calls = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicBool::new(false));
        let job_calls = Arc::clone(&calls);
        let job_failed = Arc::clone(&failed);
        let cache = StaticTargetCache::with_lookup(2, move |_| {
            job_calls.fetch_add(1, Ordering::Relaxed);
            if job_failed.load(Ordering::Relaxed) {
                Err(failure())
            } else {
                Ok(answer())
            }
        });
        cache.reconcile_snapshot(&snapshot);
        let endpoint = &cluster.endpoints()[0];
        let initial = Instant::now();
        assert_eq!(
            cache
                .resolve(&cluster, endpoint)
                .await
                .expect("first answer"),
            answer()
        );
        failed.store(true, Ordering::Relaxed);
        assert_eq!(
            cache
                .resolve(&cluster, endpoint)
                .await
                .expect("cached answer during outage"),
            answer()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        tokio::time::advance(FRESH).await;
        assert_eq!(
            cache
                .resolve(&cluster, endpoint)
                .await
                .expect("bounded stale fallback"),
            answer()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(cache.resolve(&cluster, endpoint).await.is_ok());
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        tokio::time::advance(RETRY_AFTER).await;
        assert!(cache.resolve(&cluster, endpoint).await.is_ok());
        tokio::time::advance(STALE - RETRY_AFTER).await;
        assert!(
            cache.resolve(&cluster, endpoint).await.is_err(),
            "failed refresh cannot extend the fixed bound"
        );
        assert_eq!(
            cache
                .entry(&cluster, endpoint)
                .lock()
                .expect("answer state")
                .stale_until,
            initial.checked_add(FRESH + STALE)
        );
    }

    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        wake: Condvar,
    }
    impl Gate {
        fn release(&self) {
            *self.open.lock().expect("gate") = true;
            self.wake.notify_all();
        }
        fn wait(&self) {
            let mut open = self.open.lock().expect("gate");
            while !*open {
                open = self.wake.wait(open).expect("gate wait");
            }
        }
    }
    struct ReleaseOnDrop(Arc<Gate>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    #[tokio::test]
    async fn coalesced_native_job_keeps_admission_after_its_first_waiter_is_cancelled() {
        let (snapshot, cluster) = snapshot("logical.oxidase.invalid");
        let gate = Arc::new(Gate::default());
        let _release = ReleaseOnDrop(Arc::clone(&gate));
        let calls = Arc::new(AtomicU64::new(0));
        let (started, receiver) = oneshot::channel();
        let started = Mutex::new(Some(started));
        let job_calls = Arc::clone(&calls);
        let job_gate = Arc::clone(&gate);
        let cache = Arc::new(StaticTargetCache::with_lookup(2, move |_| {
            job_calls.fetch_add(1, Ordering::Relaxed);
            if let Some(started) = started.lock().expect("rendezvous").take() {
                let _ = started.send(());
            }
            job_gate.wait();
            Ok(answer())
        }));
        cache.reconcile_snapshot(&snapshot);
        let first_cache = Arc::clone(&cache);
        let first_cluster = Arc::clone(&cluster);
        let first = tokio::spawn(async move {
            first_cache
                .resolve(&first_cluster, &first_cluster.endpoints()[0])
                .await
        });
        receiver.await.expect("native job actually holds admission");
        first.abort();
        let _ = first.await;
        assert_eq!(cache.admission.available_permits(), MAX_NATIVE_JOBS - 1);
        let second_cache = Arc::clone(&cache);
        let second_cluster = Arc::clone(&cluster);
        let second = tokio::spawn(async move {
            second_cache
                .resolve(&second_cluster, &second_cluster.endpoints()[0])
                .await
        });
        tokio::task::yield_now().await;
        gate.release();
        assert_eq!(
            second
                .await
                .expect("second waiter")
                .expect("coalesced answer"),
            answer()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(cache.admission.available_permits(), MAX_NATIVE_JOBS);
    }

    #[tokio::test]
    async fn retirement_removes_static_answers_and_a_late_pinned_request_cannot_reinsert_them() {
        let (snapshot, cluster) = snapshot("logical.oxidase.invalid");
        let cache = StaticTargetCache::with_lookup(2, |_| Ok(answer()));
        cache.reconcile_snapshot(&snapshot);
        cache
            .resolve(&cluster, &cluster.endpoints()[0])
            .await
            .expect("cached answer");
        assert_eq!(cache.inner.lock().expect("cache").entries.len(), 1);
        let mut removed = snapshot.clone();
        removed.resources.clusters.clear();
        cache.reconcile_snapshot(&removed);
        assert_eq!(cache.inner.lock().expect("cache").entries.len(), 0);
        cache
            .resolve(&cluster, &cluster.endpoints()[0])
            .await
            .expect("pinned request finishes privately");
        assert_eq!(cache.inner.lock().expect("cache").entries.len(), 0);
    }

    #[tokio::test]
    async fn cold_ipv4_failure_falls_back_to_verified_ipv6_once_and_pooled_hits_reuse_it() {
        let listener = TcpListener::bind("[::1]:0")
            .await
            .expect("ephemeral IPv6 fixture");
        let address = listener.local_addr().expect("IPv6 address");
        let (snapshot, cluster) = snapshot(&format!(
            "not-resolvable.oxidase.invalid:{}",
            address.port()
        ));
        let good = DialTarget::new(address).expect("IPv6 target");
        let bad = DialTarget::new(SocketAddr::new(
            "127.0.0.1".parse().expect("IPv4"),
            address.port(),
        ))
        .expect("unbound IPv4 target");
        let mut cache = StaticTargetCache::with_lookup(2, move |_| Ok(vec![bad, good]));
        cache.connect_admission = Arc::new(Semaphore::new(1));
        cache.reconcile_snapshot(&snapshot);
        let registry = BoundedPoolRegistry::<Empty<Bytes>>::new(2);
        registry.reconcile_snapshot(&snapshot);
        let accepts = Arc::new(AtomicU64::new(0));
        let fixture_accepts = Arc::clone(&accepts);
        let (observed, mut observations) = mpsc::channel(2);
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("selected IPv6 socket");
            fixture_accepts.fetch_add(1, Ordering::Relaxed);
            http1::Builder::new()
                .serve_connection(
                    TokioIo::new(socket),
                    service_fn(move |request: Request<hyper::body::Incoming>| {
                        let observed = observed.clone();
                        async move {
                            observed
                                .send((
                                    request.headers()[header::HOST]
                                        .to_str()
                                        .expect("Host")
                                        .to_owned(),
                                    request.uri().to_string(),
                                ))
                                .await
                                .expect("observation");
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                        }
                    }),
                )
                .await
                .expect("fixture HTTP connection");
        });
        let origin = LogicalOrigin::from_url(cluster.endpoints()[0].url()).expect("logical origin");
        let mut previous = None;
        for path in ["/one?x=a%2f&x=2", "/two"] {
            let _blocked_cold_quota = if previous.is_some() {
                Some(
                    Arc::clone(&cache.connect_admission)
                        .try_acquire_owned()
                        .expect("one free cold connect slot"),
                )
            } else {
                None
            };
            let pool = static_upstream_pool(
                &registry,
                &cache,
                &cluster,
                &cluster.endpoints()[0],
                cluster.protocol(),
                2,
            )
            .await
            .expect("bounded address fallback / pooled hit");
            if let Some(old) = &previous {
                assert!(Arc::ptr_eq(old, &pool));
            }
            let response = pool
                .request(
                    Request::builder()
                        .uri(origin.request_uri(path).expect("URI"))
                        .body(Empty::new())
                        .expect("request"),
                )
                .await
                .expect("direct request");
            assert_eq!(
                response
                    .extensions()
                    .get::<HttpInfo>()
                    .expect("actual peer")
                    .remote_addr(),
                address
            );
            response.into_body().collect().await.expect("body");
            previous = Some(pool);
        }
        assert_eq!(accepts.load(Ordering::Relaxed), 1);
        assert_eq!(
            observations.recv().await.expect("first").1,
            "/base/one?x=a%2f&x=2"
        );
        assert_eq!(
            observations.recv().await.expect("second").0,
            format!("not-resolvable.oxidase.invalid:{}", address.port())
        );
        fixture.abort();
        let _ = fixture.await;
    }
}
