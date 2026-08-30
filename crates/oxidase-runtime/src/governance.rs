//! Snapshot-scoped, bounded state for protective Service wrappers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use oxidase_core::{RateLimitKey, RequestFrame, ServiceGraph, ServiceId, ServiceKind, Value};
use tokio::sync::Notify;

const MAX_BINDING_KEY_BYTES: usize = 256;

/// Prepared mutable state for protective Services in one immutable graph.
#[derive(Clone, Debug, Default)]
pub struct GovernanceRegistry {
    concurrency: BTreeMap<ServiceId, Arc<ConcurrencyState>>,
    rate_limits: BTreeMap<ServiceId, RateLimitEntry>,
}

impl GovernanceRegistry {
    /// Builds bounded state for `graph`, reusing only policy-compatible state.
    #[must_use]
    pub fn prepare(graph: &ServiceGraph, previous: Option<&Self>) -> (Self, GovernanceReuse) {
        let mut registry = Self::default();
        let mut reuse = GovernanceReuse::default();
        for (id, node) in graph.iter() {
            match &node.kind {
                ServiceKind::ConcurrencyLimit { .. } => {
                    let state = previous
                        .and_then(|previous| previous.concurrency.get(id))
                        .cloned()
                        .unwrap_or_else(|| Arc::new(ConcurrencyState::default()));
                    if previous.is_some_and(|previous| previous.concurrency.contains_key(id)) {
                        reuse.concurrency += 1;
                    }
                    registry.concurrency.insert(id.clone(), state);
                }
                ServiceKind::RateLimit {
                    key,
                    requests,
                    per,
                    burst,
                    max_keys,
                    idle_ttl,
                    ..
                } => {
                    let policy = RateLimitPolicy {
                        key: key.clone(),
                        requests: *requests,
                        per: *per,
                        burst: *burst,
                        max_keys: *max_keys,
                        idle_ttl: *idle_ttl,
                    };
                    let state = previous
                        .and_then(|previous| previous.rate_limits.get(id))
                        .filter(|previous| previous.policy == policy)
                        .map(|previous| Arc::clone(&previous.state));
                    let state = if let Some(state) = state {
                        reuse.rate_limits += 1;
                        state
                    } else {
                        Arc::new(RateLimitState::default())
                    };
                    registry
                        .rate_limits
                        .insert(id.clone(), RateLimitEntry { policy, state });
                }
                _ => {}
            }
        }
        (registry, reuse)
    }

    /// Acquires one cancellation-safe Service concurrency permit.
    pub async fn acquire_concurrency(
        &self,
        service: &ServiceId,
        max_in_flight: u32,
        queue_timeout: Duration,
    ) -> Result<ConcurrencyPermit, ConcurrencyRejection> {
        let state = self
            .concurrency
            .get(service)
            .cloned()
            .ok_or(ConcurrencyRejection::MissingState)?;
        state.acquire(max_in_flight, queue_timeout).await
    }

    /// Evaluates one rate-limit decision at a caller-supplied monotonic time.
    #[must_use]
    pub fn check_rate_limit(
        &self,
        service: &ServiceId,
        request: &RequestFrame,
        now: Instant,
    ) -> RateLimitDecision {
        let Some(entry) = self.rate_limits.get(service) else {
            return RateLimitDecision::Rejected {
                retry_after: Duration::from_secs(1),
                reason: RateLimitRejection::MissingState,
            };
        };
        let key = match rate_limit_key(&entry.policy.key, request) {
            Ok(key) => key,
            Err(reason) => {
                return RateLimitDecision::Rejected {
                    retry_after: Duration::from_secs(1),
                    reason,
                };
            }
        };
        entry.state.check(&entry.policy, key, now)
    }

    #[cfg(test)]
    fn rate_limit_key_count(&self, service: &ServiceId) -> usize {
        self.rate_limits
            .get(service)
            .map_or(0, |entry| entry.state.key_count())
    }

    #[cfg(test)]
    fn rate_limit_index_count(&self, service: &ServiceId) -> usize {
        self.rate_limits
            .get(service)
            .map_or(0, |entry| entry.state.index_count())
    }

    #[cfg(test)]
    fn concurrency_counts(&self, service: &ServiceId) -> (u64, u64) {
        self.concurrency.get(service).map_or((0, 0), |state| {
            (
                state.active.load(Ordering::Acquire),
                state.waiters.load(Ordering::Acquire),
            )
        })
    }
}

/// Number of mutable state objects reused while preparing a new snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GovernanceReuse {
    pub concurrency: usize,
    pub rate_limits: usize,
}

#[derive(Debug, Default)]
struct ConcurrencyState {
    active: AtomicU64,
    waiters: AtomicU64,
    released: Notify,
}

impl ConcurrencyState {
    async fn acquire(
        self: Arc<Self>,
        max_in_flight: u32,
        queue_timeout: Duration,
    ) -> Result<ConcurrencyPermit, ConcurrencyRejection> {
        if let Some(permit) = self.try_acquire(max_in_flight) {
            return Ok(permit);
        }
        if queue_timeout.is_zero() {
            return Err(ConcurrencyRejection::Saturated);
        }
        let waiter = ConcurrencyWaiter::try_new(Arc::clone(&self), max_in_flight)?;
        let deadline = tokio::time::Instant::now() + queue_timeout;
        let notified = self.released.notified();
        tokio::pin!(notified);
        loop {
            // Register before checking `active`. Otherwise a release between
            // the state check and the first poll can be coalesced by `Notify`,
            // leaving a free slot while a waiter sleeps until timeout.
            notified.as_mut().enable();
            if let Some(permit) = self.try_acquire(max_in_flight) {
                drop(waiter);
                return Ok(permit);
            }
            match tokio::time::timeout_at(deadline, notified.as_mut()).await {
                Ok(()) => notified.set(self.released.notified()),
                Err(_) => return Err(ConcurrencyRejection::Timeout),
            }
        }
    }

    fn try_acquire(self: &Arc<Self>, max_in_flight: u32) -> Option<ConcurrencyPermit> {
        let limit = u64::from(max_in_flight);
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConcurrencyPermit {
                        state: Some(Arc::clone(self)),
                    });
                }
                Err(observed) => active = observed,
            }
        }
    }
}

struct ConcurrencyWaiter {
    state: Arc<ConcurrencyState>,
}

impl ConcurrencyWaiter {
    fn try_new(
        state: Arc<ConcurrencyState>,
        max_waiters: u32,
    ) -> Result<Self, ConcurrencyRejection> {
        let limit = u64::from(max_waiters);
        let mut waiters = state.waiters.load(Ordering::Acquire);
        loop {
            if waiters >= limit {
                return Err(ConcurrencyRejection::QueueFull);
            }
            match state.waiters.compare_exchange_weak(
                waiters,
                waiters + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Self { state }),
                Err(observed) => waiters = observed,
            }
        }
    }
}

impl Drop for ConcurrencyWaiter {
    fn drop(&mut self) {
        self.state.waiters.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Permit retained through a handled response or trusted tunnel lifecycle.
pub struct ConcurrencyPermit {
    state: Option<Arc<ConcurrencyState>>,
}

impl ConcurrencyPermit {
    /// A no-op permit used only by non-production symbolic executors.
    #[must_use]
    pub fn untracked() -> Self {
        Self { state: None }
    }
}

impl fmt::Debug for ConcurrencyPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConcurrencyPermit")
            .field("tracked", &self.state.is_some())
            .finish()
    }
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            state.active.fetch_sub(1, Ordering::AcqRel);
            state.released.notify_one();
        }
    }
}

/// Fixed reasons why concurrency admission was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConcurrencyRejection {
    MissingState,
    Saturated,
    QueueFull,
    Timeout,
}

impl ConcurrencyRejection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingState => "missing_state",
            Self::Saturated => "saturated",
            Self::QueueFull => "queue_full",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Debug)]
struct RateLimitEntry {
    policy: RateLimitPolicy,
    state: Arc<RateLimitState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RateLimitPolicy {
    key: RateLimitKey,
    requests: u64,
    per: Duration,
    burst: u64,
    max_keys: u32,
    idle_ttl: Duration,
}

#[derive(Debug, Default)]
struct RateLimitState {
    buckets: Mutex<RateBuckets>,
}

#[derive(Debug, Default)]
struct RateBuckets {
    by_key: BTreeMap<String, RateBucket>,
    idle_order: BTreeSet<(Instant, String)>,
}

impl RateLimitState {
    fn check(&self, policy: &RateLimitPolicy, key: String, now: Instant) -> RateLimitDecision {
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        buckets.evict_expired(now, policy.idle_ttl);
        let period_nanos = policy.per.as_nanos().max(1);
        let capacity = period_nanos.saturating_mul(u128::from(policy.burst));
        let mut bucket = if let Some(bucket) = buckets.by_key.remove(&key) {
            buckets.idle_order.remove(&(bucket.last_seen, key.clone()));
            bucket
        } else {
            if buckets.by_key.len() >= policy.max_keys as usize {
                return RateLimitDecision::Rejected {
                    retry_after: Duration::from_secs(1),
                    reason: RateLimitRejection::Capacity,
                };
            }
            RateBucket {
                credit: capacity,
                refilled_at: now,
                last_seen: now,
            }
        };
        let decision = consume_rate_bucket(policy, &mut bucket, now, period_nanos, capacity);
        bucket.last_seen = now;
        buckets.idle_order.insert((now, key.clone()));
        buckets.by_key.insert(key, bucket);
        decision
    }

    #[cfg(test)]
    fn key_count(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .by_key
            .len()
    }

    #[cfg(test)]
    fn index_count(&self) -> usize {
        self.buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .idle_order
            .len()
    }
}

impl RateBuckets {
    fn evict_expired(&mut self, now: Instant, idle_ttl: Duration) {
        loop {
            let Some((last_seen, key)) = self.idle_order.first().cloned() else {
                return;
            };
            if now.saturating_duration_since(last_seen) < idle_ttl {
                return;
            }
            self.idle_order.remove(&(last_seen, key.clone()));
            if self
                .by_key
                .get(&key)
                .is_some_and(|bucket| bucket.last_seen == last_seen)
            {
                self.by_key.remove(&key);
            }
        }
    }
}

fn consume_rate_bucket(
    policy: &RateLimitPolicy,
    bucket: &mut RateBucket,
    now: Instant,
    period_nanos: u128,
    capacity: u128,
) -> RateLimitDecision {
    let elapsed = now.saturating_duration_since(bucket.refilled_at).as_nanos();
    bucket.credit = bucket
        .credit
        .saturating_add(elapsed.saturating_mul(u128::from(policy.requests)))
        .min(capacity);
    bucket.refilled_at = now;
    if bucket.credit >= period_nanos {
        bucket.credit -= period_nanos;
        return RateLimitDecision::Allowed;
    }
    let missing = period_nanos - bucket.credit;
    let requests = u128::from(policy.requests);
    let wait_nanos = missing.saturating_add(requests - 1) / requests;
    RateLimitDecision::Rejected {
        retry_after: duration_from_nanos(wait_nanos),
        reason: RateLimitRejection::Rate,
    }
}

#[derive(Debug)]
struct RateBucket {
    credit: u128,
    refilled_at: Instant,
    last_seen: Instant,
}

/// One token-bucket decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitDecision {
    Allowed,
    Rejected {
        retry_after: Duration,
        reason: RateLimitRejection,
    },
}

/// Fixed, bounded result labels for rate-limit rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitRejection {
    MissingState,
    InvalidKey,
    Capacity,
    Rate,
}

impl RateLimitRejection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingState => "missing_state",
            Self::InvalidKey => "invalid_key",
            Self::Capacity => "capacity",
            Self::Rate => "rate",
        }
    }
}

fn rate_limit_key(
    key: &RateLimitKey,
    request: &RequestFrame,
) -> Result<String, RateLimitRejection> {
    let rendered = match key {
        RateLimitKey::PeerIp => request
            .original()
            .peer_address
            .map(|address| normalized_ip(address.ip()).to_string())
            .ok_or(RateLimitRejection::InvalidKey)?,
        RateLimitKey::Binding(name) => match request.bindings().resolve(name) {
            Some(Value::Bool(value)) => value.to_string(),
            Some(Value::Integer(value)) => value.to_string(),
            Some(Value::String(value)) => value.clone(),
            _ => return Err(RateLimitRejection::InvalidKey),
        },
    };
    if rendered.is_empty() || rendered.len() > MAX_BINDING_KEY_BYTES {
        return Err(RateLimitRejection::InvalidKey);
    }
    Ok(rendered)
}

fn normalized_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn duration_from_nanos(nanos: u128) -> Duration {
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use http::{HeaderMap, Method, StatusCode};
    use oxidase_core::{
        RateLimitKey, RequestFrame, RequestMetadata, ServiceGraph, ServiceId, ServiceKind,
        ServiceNode, SourceSpan, Value,
    };

    use super::{ConcurrencyRejection, GovernanceRegistry, RateLimitDecision, RateLimitRejection};

    fn request(peer: &str) -> RequestFrame {
        let mut metadata =
            RequestMetadata::try_new(Method::GET, "http", "example.test", "/", HeaderMap::new())
                .expect("request metadata is valid");
        metadata.peer_address = Some(peer.parse::<SocketAddr>().expect("peer is valid"));
        RequestFrame::new(metadata)
    }

    fn graph(kind: ServiceKind) -> ServiceGraph {
        let node = ServiceNode {
            id: ServiceId::new("limit"),
            source: SourceSpan::synthetic("limit"),
            kind,
        };
        ServiceGraph::new(BTreeMap::from([(node.id.clone(), node)]))
    }

    fn concurrency_graph(max_in_flight: u32) -> ServiceGraph {
        graph(ServiceKind::ConcurrencyLimit {
            name: "test".to_owned(),
            max_in_flight,
            queue_timeout: Duration::from_secs(1),
            reject_status: StatusCode::SERVICE_UNAVAILABLE,
            service: ServiceId::new("child"),
        })
    }

    fn rate_graph(key: RateLimitKey, max_keys: u32, idle_ttl: Duration) -> ServiceGraph {
        graph(ServiceKind::RateLimit {
            name: "test".to_owned(),
            key,
            requests: 2,
            per: Duration::from_secs(1),
            burst: 2,
            max_keys,
            idle_ttl,
            service: ServiceId::new("child"),
        })
    }

    #[tokio::test]
    async fn concurrency_is_bounded_queued_and_cancellation_safe() {
        let registry = Arc::new(GovernanceRegistry::prepare(&concurrency_graph(1), None).0);
        let id = ServiceId::new("limit");
        let first = registry
            .acquire_concurrency(&id, 1, Duration::ZERO)
            .await
            .expect("first execution is admitted");
        assert!(matches!(
            registry.acquire_concurrency(&id, 1, Duration::ZERO).await,
            Err(ConcurrencyRejection::Saturated)
        ));
        let waiter = {
            let registry = Arc::clone(&registry);
            let id = id.clone();
            tokio::spawn(async move {
                registry
                    .acquire_concurrency(&id, 1, Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        drop(first);
        let second = waiter
            .await
            .expect("waiter task does not panic")
            .expect("released permit wakes one waiter");
        drop(second);
    }

    #[tokio::test]
    async fn multiple_releases_wake_multiple_registered_waiters() {
        let registry = Arc::new(GovernanceRegistry::prepare(&concurrency_graph(2), None).0);
        let id = ServiceId::new("limit");
        let first = registry
            .acquire_concurrency(&id, 2, Duration::ZERO)
            .await
            .expect("first execution is admitted");
        let second = registry
            .acquire_concurrency(&id, 2, Duration::ZERO)
            .await
            .expect("second execution is admitted");
        let waiters = (0..2)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let id = id.clone();
                tokio::spawn(async move {
                    registry
                        .acquire_concurrency(&id, 2, Duration::from_secs(1))
                        .await
                })
            })
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(1), async {
            while registry.concurrency_counts(&id).1 != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both waiters register before release");

        drop(first);
        drop(second);
        for waiter in waiters {
            let permit = tokio::time::timeout(Duration::from_millis(100), waiter)
                .await
                .expect("a distinct release wakes each waiter")
                .expect("waiter task does not panic")
                .expect("waiter acquires a released slot");
            drop(permit);
        }
    }

    #[test]
    fn token_bucket_has_exact_boundaries_and_bounded_keys() {
        let id = ServiceId::new("limit");
        let registry = GovernanceRegistry::prepare(
            &rate_graph(RateLimitKey::PeerIp, 1, Duration::from_secs(10)),
            None,
        )
        .0;
        let now = Instant::now();
        let first = request("127.0.0.1:1000");
        assert_eq!(
            registry.check_rate_limit(&id, &first, now),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            registry.check_rate_limit(&id, &first, now),
            RateLimitDecision::Allowed
        );
        assert!(matches!(
            registry.check_rate_limit(&id, &first, now),
            RateLimitDecision::Rejected {
                reason: RateLimitRejection::Rate,
                ..
            }
        ));
        assert_eq!(
            registry.check_rate_limit(&id, &first, now + Duration::from_millis(500)),
            RateLimitDecision::Allowed
        );

        let second = request("127.0.0.2:1000");
        assert!(matches!(
            registry.check_rate_limit(&id, &second, now),
            RateLimitDecision::Rejected {
                reason: RateLimitRejection::Capacity,
                ..
            }
        ));
        assert_eq!(registry.rate_limit_key_count(&id), 1);
        assert_eq!(
            registry.check_rate_limit(&id, &second, now + Duration::from_secs(11)),
            RateLimitDecision::Allowed
        );
        assert_eq!(registry.rate_limit_key_count(&id), 1);
    }

    #[test]
    fn concurrent_token_bucket_admits_exactly_the_configured_burst() {
        const WORKERS: usize = 64;
        const BURST: u64 = 17;

        let id = ServiceId::new("limit");
        let graph = graph(ServiceKind::RateLimit {
            name: "test".to_owned(),
            key: RateLimitKey::PeerIp,
            requests: 1,
            per: Duration::from_secs(60),
            burst: BURST,
            max_keys: 4,
            idle_ttl: Duration::from_secs(120),
            service: ServiceId::new("child"),
        });
        let registry = Arc::new(GovernanceRegistry::prepare(&graph, None).0);
        let barrier = Arc::new(Barrier::new(WORKERS));
        let now = Instant::now();
        let workers = (0..WORKERS)
            .map(|_| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                let id = id.clone();
                std::thread::spawn(move || {
                    let request = request("127.0.0.1:1000");
                    barrier.wait();
                    registry.check_rate_limit(&id, &request, now)
                })
            })
            .collect::<Vec<_>>();
        let allowed = workers
            .into_iter()
            .map(|worker| worker.join().expect("rate-limit worker does not panic"))
            .filter(|decision| *decision == RateLimitDecision::Allowed)
            .count();
        assert_eq!(allowed, BURST as usize);
    }

    #[test]
    fn rotating_capacity_rejections_keep_the_bucket_and_expiry_indexes_bounded() {
        let id = ServiceId::new("limit");
        let registry = GovernanceRegistry::prepare(
            &rate_graph(RateLimitKey::PeerIp, 4, Duration::from_secs(60)),
            None,
        )
        .0;
        let now = Instant::now();
        for host in 1..=4 {
            let request = request(&format!("192.0.2.{host}:1000"));
            assert_eq!(
                registry.check_rate_limit(&id, &request, now),
                RateLimitDecision::Allowed
            );
        }
        for host in 1..=1_000 {
            let third = (host / 250) + 3;
            let fourth = (host % 250) + 1;
            let request = request(&format!("198.51.{third}.{fourth}:1000"));
            assert!(matches!(
                registry.check_rate_limit(&id, &request, now),
                RateLimitDecision::Rejected {
                    reason: RateLimitRejection::Capacity,
                    ..
                }
            ));
        }
        assert_eq!(registry.rate_limit_key_count(&id), 4);
        assert_eq!(registry.rate_limit_index_count(&id), 4);
    }

    #[test]
    fn compatible_state_reuses_and_policy_changes_reset_rate_buckets() {
        let first_graph = rate_graph(RateLimitKey::PeerIp, 4, Duration::from_secs(10));
        let first = GovernanceRegistry::prepare(&first_graph, None).0;
        let same_graph = rate_graph(RateLimitKey::PeerIp, 4, Duration::from_secs(10));
        let (_, reuse) = GovernanceRegistry::prepare(&same_graph, Some(&first));
        assert_eq!(reuse.rate_limits, 1);

        let changed_graph = rate_graph(RateLimitKey::PeerIp, 5, Duration::from_secs(10));
        let (_, reuse) = GovernanceRegistry::prepare(&changed_graph, Some(&first));
        assert_eq!(reuse.rate_limits, 0);

        let concurrency = GovernanceRegistry::prepare(&concurrency_graph(1), None).0;
        let (_, reuse) = GovernanceRegistry::prepare(&concurrency_graph(2), Some(&concurrency));
        assert_eq!(reuse.concurrency, 1);
    }

    #[test]
    fn scalar_binding_keys_are_lexical_and_bounded() {
        let id = ServiceId::new("limit");
        let registry = GovernanceRegistry::prepare(
            &rate_graph(
                RateLimitKey::Binding("tenant".to_owned()),
                4,
                Duration::from_secs(10),
            ),
            None,
        )
        .0;
        let now = Instant::now();
        let request = request("127.0.0.1:1000").with_bindings(BTreeMap::from([(
            "tenant".to_owned(),
            Value::String("alpha".to_owned()),
        )]));
        assert_eq!(
            registry.check_rate_limit(&id, &request, now),
            RateLimitDecision::Allowed
        );

        let oversized = request.with_bindings(BTreeMap::from([(
            "tenant".to_owned(),
            Value::String("x".repeat(257)),
        )]));
        assert!(matches!(
            registry.check_rate_limit(&id, &oversized, now),
            RateLimitDecision::Rejected {
                reason: RateLimitRejection::InvalidKey,
                ..
            }
        ));
    }
}
