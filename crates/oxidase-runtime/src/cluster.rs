//! Prepared upstream Cluster plans and their reload-stable runtime state.
//!
//! This module deliberately owns no connection pool and starts no background
//! tasks. Preparation is therefore side-effect free: the server may activate a
//! health supervisor only after the containing snapshot has committed.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oxidase_config::{
    ActiveHealthSpec, ClusterEndpointSpec, ClusterHealthSpec, ClusterProtocol, ClusterSpec,
    LoadBalancePolicy, PassiveHealthSpec,
};
use oxidase_core::ResourceId;
use serde::Serialize;
use tokio::sync::Notify;

const HEALTH_UNKNOWN_ELIGIBLE: u8 = 0;
const HEALTH_HEALTHY: u8 = 1;
const HEALTH_UNHEALTHY: u8 = 2;
const HEALTH_PASSIVELY_EJECTED: u8 = 3;

/// Runtime eligibility of an upstream endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointHealthState {
    /// No active-health threshold has completed yet. The endpoint is eligible.
    UnknownEligible,
    Healthy,
    Unhealthy,
    PassivelyEjected,
}

impl EndpointHealthState {
    const fn encode(self) -> u8 {
        match self {
            Self::UnknownEligible => HEALTH_UNKNOWN_ELIGIBLE,
            Self::Healthy => HEALTH_HEALTHY,
            Self::Unhealthy => HEALTH_UNHEALTHY,
            Self::PassivelyEjected => HEALTH_PASSIVELY_EJECTED,
        }
    }

    const fn decode(value: u8) -> Self {
        match value {
            HEALTH_HEALTHY => Self::Healthy,
            HEALTH_UNHEALTHY => Self::Unhealthy,
            HEALTH_PASSIVELY_EJECTED => Self::PassivelyEjected,
            _ => Self::UnknownEligible,
        }
    }

    #[must_use]
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::UnknownEligible | Self::Healthy)
    }
}

/// Reload-stable, concurrency-safe state for one endpoint identity.
///
/// Identity is supplied by [`PreparedCluster`]: Cluster resource ID, endpoint
/// name, canonical URL, upstream protocol, and health policy. Reloads that
/// change the health state machine create a fresh object so an old pinned
/// supervisor cannot mutate the new policy's state.
pub struct EndpointRuntimeState {
    health_transition_lock: Mutex<()>,
    health: AtomicU8,
    consecutive_active_health_successes: AtomicU64,
    consecutive_active_health_failures: AtomicU64,
    active_health_successes: AtomicU64,
    active_health_failures: AtomicU64,
    passive_failures: AtomicU64,
    passive_ejections: AtomicU64,
    health_transitions: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    selections: AtomicU64,
    ejection_deadline_tick: AtomicU64,
    last_transition_unix_ms: AtomicU64,
    clock_origin: Instant,
    admission: Arc<AdmissionCounter>,
}

impl fmt::Debug for EndpointRuntimeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointRuntimeState")
            .field("health", &self.health_state(Instant::now()))
            .field("active_requests", &self.active_requests())
            .field("successes", &self.successes.load(Ordering::Relaxed))
            .field("failures", &self.failures.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for EndpointRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointRuntimeState {
    #[must_use]
    pub fn new() -> Self {
        Self::new_at(Instant::now())
    }

    fn new_at(now: Instant) -> Self {
        Self::new_at_with_admission(now, Arc::new(AdmissionCounter::default()))
    }

    fn new_at_with_admission(now: Instant, admission: Arc<AdmissionCounter>) -> Self {
        Self {
            health_transition_lock: Mutex::new(()),
            health: AtomicU8::new(HEALTH_UNKNOWN_ELIGIBLE),
            consecutive_active_health_successes: AtomicU64::new(0),
            consecutive_active_health_failures: AtomicU64::new(0),
            active_health_successes: AtomicU64::new(0),
            active_health_failures: AtomicU64::new(0),
            passive_failures: AtomicU64::new(0),
            passive_ejections: AtomicU64::new(0),
            health_transitions: AtomicU64::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            selections: AtomicU64::new(0),
            ejection_deadline_tick: AtomicU64::new(0),
            last_transition_unix_ms: AtomicU64::new(unix_time_millis()),
            clock_origin: now,
            admission,
        }
    }

    /// Returns current health, lazily expiring passive ejection.
    #[must_use]
    pub fn health_state(&self, now: Instant) -> EndpointHealthState {
        self.recover_expired_ejection(now);
        EndpointHealthState::decode(self.health.load(Ordering::Acquire))
    }

    #[must_use]
    pub fn is_eligible(&self, now: Instant) -> bool {
        self.health_state(now).is_eligible()
    }

    #[must_use]
    pub fn active_requests(&self) -> u64 {
        self.admission.active()
    }

    #[must_use]
    pub fn selections(&self) -> u64 {
        self.selections.load(Ordering::Relaxed)
    }

    fn selected(&self) {
        self.selections.fetch_add(1, Ordering::Relaxed);
    }

    fn record_active_health(&self, succeeded: bool, plan: &ActiveHealthSpec, now: Instant) {
        let _transition_guard = self
            .health_transition_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if succeeded {
            self.active_health_successes.fetch_add(1, Ordering::Relaxed);
            self.consecutive_active_health_failures
                .store(0, Ordering::Release);
            let successes = self
                .consecutive_active_health_successes
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            if successes >= u64::from(plan.healthy_threshold) {
                self.passive_failures.store(0, Ordering::Release);
                self.ejection_deadline_tick.store(0, Ordering::Release);
                self.transition_to(EndpointHealthState::Healthy);
            }
        } else {
            self.active_health_failures.fetch_add(1, Ordering::Relaxed);
            self.consecutive_active_health_successes
                .store(0, Ordering::Release);
            let failures = self
                .consecutive_active_health_failures
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            if failures >= u64::from(plan.unhealthy_threshold) {
                // Passive ejection has precedence over an active-health
                // failure. The conditional transition must be one atomic
                // operation: a preceding read followed by an unconditional
                // swap could overwrite an ejection that won between them.
                self.recover_expired_ejection_locked(now);
                let observed = self.health.load(Ordering::Acquire);
                self.transition_to_unhealthy_from(observed);
            }
        }
    }

    fn record_passive_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        let _transition_guard = self
            .health_transition_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.passive_failures.store(0, Ordering::Release);
    }

    fn record_passive_failure(&self, plan: Option<&PassiveHealthSpec>, now: Instant) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        let Some(plan) = plan else {
            return;
        };
        let _transition_guard = self
            .health_transition_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let failures = self
            .passive_failures
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        if failures >= u64::from(plan.consecutive_failures) {
            let deadline = self
                .tick(now)
                .saturating_add(duration_tick(plan.eject_for))
                .max(1);
            self.ejection_deadline_tick
                .store(deadline, Ordering::Release);
            self.transition_to(EndpointHealthState::PassivelyEjected);
        }
    }

    fn recover_expired_ejection(&self, now: Instant) {
        if self.health.load(Ordering::Acquire) != HEALTH_PASSIVELY_EJECTED {
            return;
        }
        let deadline = self.ejection_deadline_tick.load(Ordering::Acquire);
        if deadline == 0 || self.tick(now) < deadline {
            return;
        }
        let _transition_guard = self
            .health_transition_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.recover_expired_ejection_locked(now);
    }

    fn recover_expired_ejection_locked(&self, now: Instant) {
        if self.health.load(Ordering::Acquire) != HEALTH_PASSIVELY_EJECTED {
            return;
        }
        let deadline = self.ejection_deadline_tick.load(Ordering::Acquire);
        if deadline == 0 || self.tick(now) < deadline {
            return;
        }
        if self
            .health
            .compare_exchange(
                HEALTH_PASSIVELY_EJECTED,
                HEALTH_UNKNOWN_ELIGIBLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.ejection_deadline_tick.store(0, Ordering::Release);
            self.passive_failures.store(0, Ordering::Release);
            self.consecutive_active_health_successes
                .store(0, Ordering::Release);
            self.consecutive_active_health_failures
                .store(0, Ordering::Release);
            self.health_transitions.fetch_add(1, Ordering::Relaxed);
            self.last_transition_unix_ms
                .store(unix_time_millis(), Ordering::Release);
        }
    }

    fn transition_to(&self, state: EndpointHealthState) {
        let previous = self.health.swap(state.encode(), Ordering::AcqRel);
        self.record_transition(previous, state);
    }

    fn transition_to_unhealthy_from(&self, mut observed: u8) {
        loop {
            if matches!(observed, HEALTH_UNHEALTHY | HEALTH_PASSIVELY_EJECTED) {
                return;
            }
            match self.health.compare_exchange_weak(
                observed,
                HEALTH_UNHEALTHY,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(previous) => {
                    self.record_transition(previous, EndpointHealthState::Unhealthy);
                    return;
                }
                Err(current) => observed = current,
            }
        }
    }

    fn record_transition(&self, previous: u8, state: EndpointHealthState) {
        if previous != state.encode() {
            self.health_transitions.fetch_add(1, Ordering::Relaxed);
            if state == EndpointHealthState::PassivelyEjected {
                self.passive_ejections.fetch_add(1, Ordering::Relaxed);
            }
            self.last_transition_unix_ms
                .store(unix_time_millis(), Ordering::Release);
        }
    }

    fn tick(&self, now: Instant) -> u64 {
        duration_tick(now.saturating_duration_since(self.clock_origin))
    }

    fn status(&self, now: Instant) -> EndpointRuntimeStatus {
        let health = self.health_state(now);
        let deadline = self.ejection_deadline_tick.load(Ordering::Acquire);
        let current = self.tick(now);
        EndpointRuntimeStatus {
            health,
            active_requests: self.active_requests(),
            selections: self.selections(),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            active_health_successes: self.active_health_successes.load(Ordering::Relaxed),
            active_health_failures: self.active_health_failures.load(Ordering::Relaxed),
            passive_ejections: self.passive_ejections.load(Ordering::Relaxed),
            health_transitions: self.health_transitions.load(Ordering::Relaxed),
            last_transition_unix_ms: self.last_transition_unix_ms.load(Ordering::Acquire),
            ejection_remaining_ms: (health == EndpointHealthState::PassivelyEjected)
                .then(|| deadline.saturating_sub(current) / 1_000_000),
        }
    }
}

/// An immutable endpoint plan paired with reload-stable state.
#[derive(Debug)]
pub struct PreparedEndpoint {
    spec: ClusterEndpointSpec,
    state: Arc<EndpointRuntimeState>,
}

impl PreparedEndpoint {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.spec.name
    }

    #[must_use]
    pub fn url(&self) -> &url::Url {
        &self.spec.url
    }

    #[must_use]
    pub const fn weight(&self) -> u16 {
        self.spec.weight
    }

    #[must_use]
    pub fn source(&self) -> &oxidase_core::SourceSpan {
        &self.spec.source
    }

    #[must_use]
    pub fn runtime_state(&self) -> &Arc<EndpointRuntimeState> {
        &self.state
    }

    #[must_use]
    pub fn health_state(&self, now: Instant) -> EndpointHealthState {
        self.state.health_state(now)
    }

    #[must_use]
    pub fn active_requests(&self) -> u64 {
        self.state.active_requests()
    }
}

/// Side-effect-free prepared Cluster resource.
///
/// Health supervisors and connection pools live at the server boundary. This
/// object provides immutable policy, deterministic selection, reload-stable
/// endpoint state, and cancellation-safe admission permits.
pub struct PreparedCluster {
    spec: ClusterSpec,
    endpoints: Vec<Arc<PreparedEndpoint>>,
    runtime: Arc<ClusterRuntimeState>,
    round_robin_sequence: AtomicU64,
    weighted_state: Mutex<Vec<i64>>,
    supervisor_activated: AtomicBool,
}

impl fmt::Debug for PreparedCluster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCluster")
            .field("id", &self.spec.id)
            .field("protocol", &self.spec.protocol)
            .field("load_balance", &self.spec.load_balance)
            .field("endpoints", &self.endpoints)
            .finish_non_exhaustive()
    }
}

impl PreparedCluster {
    /// Prepares a new immutable policy and reuses compatible runtime state.
    ///
    /// The return value counts endpoint states reused from `previous`.
    #[must_use]
    pub fn prepare(spec: ClusterSpec, previous: Option<&Self>) -> (Self, usize) {
        let same_cluster = previous.filter(|previous| previous.spec.id == spec.id);
        let same_protocol = same_cluster.filter(|previous| previous.spec.protocol == spec.protocol);
        let same_health_policy = same_protocol
            .filter(|previous| health_policy_compatible(&previous.spec.health, &spec.health));
        let runtime = same_cluster.map_or_else(
            || Arc::new(ClusterRuntimeState::default()),
            |previous| Arc::clone(&previous.runtime),
        );
        let mut reused = 0;
        let endpoints = spec
            .endpoints
            .iter()
            .cloned()
            .map(|endpoint| {
                let previous_endpoint = same_protocol.and_then(|previous| {
                    previous.endpoints.iter().find(|candidate| {
                        candidate.name() == endpoint.name && candidate.url() == &endpoint.url
                    })
                });
                let state = match (previous_endpoint, same_health_policy.is_some()) {
                    (Some(endpoint), true) => {
                        reused += 1;
                        Arc::clone(endpoint.runtime_state())
                    }
                    (Some(endpoint), false) => {
                        Arc::new(EndpointRuntimeState::new_at_with_admission(
                            Instant::now(),
                            Arc::clone(&endpoint.runtime_state().admission),
                        ))
                    }
                    (None, _) => Arc::new(EndpointRuntimeState::new()),
                };
                Arc::new(PreparedEndpoint {
                    spec: endpoint,
                    state,
                })
            })
            .collect::<Vec<_>>();
        let weighted_state = Mutex::new(vec![0; endpoints.len()]);
        (
            Self {
                spec,
                endpoints,
                runtime,
                round_robin_sequence: AtomicU64::new(0),
                weighted_state,
                supervisor_activated: AtomicBool::new(false),
            },
            reused,
        )
    }

    #[must_use]
    pub fn id(&self) -> &ResourceId {
        &self.spec.id
    }

    /// Configuration name without the compiler-owned `cluster:` namespace.
    #[must_use]
    pub fn name(&self) -> &str {
        self.spec
            .id
            .as_str()
            .strip_prefix("cluster:")
            .unwrap_or_else(|| self.spec.id.as_str())
    }

    #[must_use]
    pub const fn protocol(&self) -> ClusterProtocol {
        self.spec.protocol
    }

    #[must_use]
    pub const fn load_balance(&self) -> LoadBalancePolicy {
        self.spec.load_balance
    }

    #[must_use]
    pub fn spec(&self) -> &ClusterSpec {
        &self.spec
    }

    #[must_use]
    pub fn endpoints(&self) -> &[Arc<PreparedEndpoint>] {
        &self.endpoints
    }

    #[must_use]
    pub fn active_requests(&self) -> u64 {
        self.runtime.admission.active()
    }

    #[must_use]
    pub fn active_retries(&self) -> u64 {
        self.runtime.retries.active()
    }

    /// Claims activation of this exact prepared Cluster once.
    ///
    /// Snapshot reuse preserves the same `Arc<PreparedCluster>`, so a commit
    /// manager can avoid starting a duplicate health supervisor. A changed
    /// immutable policy creates a new prepared object and therefore a new latch.
    #[must_use]
    pub fn try_activate_supervisor(&self) -> bool {
        self.supervisor_activated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    #[must_use]
    pub fn supervisor_is_activated(&self) -> bool {
        self.supervisor_activated.load(Ordering::Acquire)
    }

    /// Selects one currently eligible endpoint according to the compiled policy.
    #[must_use]
    pub fn select_endpoint(&self, now: Instant) -> Option<Arc<PreparedEndpoint>> {
        self.select_endpoint_excluding(now, &BTreeSet::new())
    }

    /// Selects an eligible endpoint not present in `excluded`.
    ///
    /// Retry callers use endpoint names from earlier attempts. If every
    /// eligible endpoint has already been tried, this returns `None` instead of
    /// silently repeating one.
    #[must_use]
    pub fn select_endpoint_excluding(
        &self,
        now: Instant,
        excluded: &BTreeSet<String>,
    ) -> Option<Arc<PreparedEndpoint>> {
        let eligible = self
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, endpoint)| {
                endpoint.state.is_eligible(now) && !excluded.contains(endpoint.name())
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return None;
        }
        let selected = match self.spec.load_balance {
            LoadBalancePolicy::RoundRobin => {
                let sequence = self.round_robin_sequence.fetch_add(1, Ordering::Relaxed);
                eligible[sequence as usize % eligible.len()]
            }
            LoadBalancePolicy::WeightedRoundRobin => self.select_weighted(&eligible),
            LoadBalancePolicy::LeastRequests => self.select_least_requests(&eligible),
        };
        Some(Arc::clone(&self.endpoints[selected]))
    }

    /// Acquires Cluster and endpoint concurrency permits without consuming a
    /// request body. Dropping the returned permit releases both counts.
    pub async fn acquire(&self) -> Result<ClusterRequestPermit, ClusterAdmissionError> {
        self.acquire_excluding(&BTreeSet::new()).await
    }

    /// Acquires admission while preferring an endpoint not used by an earlier
    /// attempt. A saturated selected endpoint never hides capacity on another
    /// eligible endpoint.
    pub async fn acquire_excluding(
        &self,
        excluded: &BTreeSet<String>,
    ) -> Result<ClusterRequestPermit, ClusterAdmissionError> {
        let queue_timeout = self.spec.limits.queue_timeout;
        let deadline =
            (!queue_timeout.is_zero()).then(|| tokio::time::Instant::now() + queue_timeout);
        let cluster = acquire_counter(
            Arc::clone(&self.runtime.admission),
            self.spec.limits.max_in_flight,
            deadline,
        )
        .await
        .map_err(|()| ClusterAdmissionError::Overloaded)?;

        loop {
            // Register before scanning all endpoints so a release racing the
            // scan leaves a Notify permit instead of being lost.
            let released = self.runtime.endpoint_released.notified();
            match self.try_acquire_endpoint(excluded, Instant::now()) {
                EndpointAcquire::Acquired(endpoint, endpoint_permit) => {
                    return Ok(ClusterRequestPermit {
                        endpoint,
                        _cluster: cluster,
                        _endpoint: endpoint_permit,
                    });
                }
                EndpointAcquire::Unavailable => {
                    return Err(ClusterAdmissionError::Unavailable);
                }
                EndpointAcquire::Saturated => {}
            }
            let Some(deadline) = deadline else {
                return Err(ClusterAdmissionError::Overloaded);
            };
            if tokio::time::timeout_at(deadline, released).await.is_err() {
                return Err(ClusterAdmissionError::Overloaded);
            }
        }
    }

    /// Attempts to move an admitted request to an untried endpoint while
    /// retaining its Cluster permit and current endpoint lease until success.
    ///
    /// This is the status-retry handoff boundary. Returning `false` leaves
    /// `current` byte-for-byte usable by the caller, so it can return the
    /// original upstream response if no replacement endpoint is available. The
    /// borrowed permit also remains owned by the caller if this future is
    /// cancelled while waiting.
    pub async fn retarget_excluding(
        &self,
        current: &mut ClusterRequestPermit,
        excluded: &BTreeSet<String>,
    ) -> bool {
        if !Arc::ptr_eq(&current._cluster.counter, &self.runtime.admission) {
            return false;
        }
        let mut excluded = excluded.clone();
        excluded.insert(current.endpoint.name().to_owned());
        let queue_timeout = self.spec.limits.queue_timeout;
        let deadline =
            (!queue_timeout.is_zero()).then(|| tokio::time::Instant::now() + queue_timeout);

        loop {
            let released = self.runtime.endpoint_released.notified();
            match self.try_acquire_endpoint(&excluded, Instant::now()) {
                EndpointAcquire::Acquired(endpoint, endpoint_permit) => {
                    let old_endpoint = std::mem::replace(&mut current._endpoint, endpoint_permit);
                    current.endpoint = endpoint;
                    drop(old_endpoint);
                    return true;
                }
                EndpointAcquire::Unavailable => return false,
                EndpointAcquire::Saturated => {}
            }
            let Some(deadline) = deadline else {
                return false;
            };
            if tokio::time::timeout_at(deadline, released).await.is_err() {
                return false;
            }
        }
    }

    /// Attempts to enter the retry storm-protection budget without waiting.
    #[must_use]
    pub fn try_acquire_retry(&self) -> Option<ClusterRetryPermit> {
        let permit = self
            .runtime
            .retries
            .try_acquire(u64::from(self.spec.retry.max_concurrent_retries), None)?;
        Some(ClusterRetryPermit { _permit: permit })
    }

    /// Applies one active-health observation. Unknown endpoint names are ignored
    /// so a retiring supervisor cannot mutate a replacement endpoint by index.
    pub fn record_active_health(&self, endpoint_name: &str, succeeded: bool, now: Instant) {
        let Some(plan) = &self.spec.health.active else {
            return;
        };
        if let Some(endpoint) = self.endpoint(endpoint_name) {
            endpoint.state.record_active_health(succeeded, plan, now);
        }
    }

    pub fn record_passive_success(&self, endpoint_name: &str) {
        if let Some(endpoint) = self.endpoint(endpoint_name) {
            endpoint.state.record_passive_success();
        }
    }

    pub fn record_passive_failure(&self, endpoint_name: &str, now: Instant) {
        if let Some(endpoint) = self.endpoint(endpoint_name) {
            endpoint
                .state
                .record_passive_failure(self.spec.health.passive.as_ref(), now);
        }
    }

    /// Records a retry attempt after the retry budget and replacement endpoint
    /// have both been acquired. First attempts must not call this method.
    pub fn record_retry_attempt(&self) {
        self.runtime.retry_attempts.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that policy, attempt, endpoint, or storm-protection limits ended
    /// retry processing before another attempt could start.
    pub fn record_retry_exhausted(&self) {
        self.runtime.retry_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a bounded admission rejection without retaining dynamic error
    /// strings or endpoint URLs.
    pub fn record_admission_failure(&self, error: ClusterAdmissionError) {
        match error {
            ClusterAdmissionError::Unavailable => {
                self.runtime
                    .unavailable_rejections
                    .fetch_add(1, Ordering::Relaxed);
            }
            ClusterAdmissionError::Overloaded => {
                self.runtime
                    .overload_rejections
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[must_use]
    pub fn status(&self, now: Instant) -> ClusterRuntimeStatus {
        ClusterRuntimeStatus {
            cluster: self.name().to_owned(),
            protocol: self.spec.protocol.as_str().to_owned(),
            policy: self.spec.load_balance.as_str().to_owned(),
            active_requests: self.active_requests(),
            active_retries: self.active_retries(),
            retry_attempts: self.runtime.retry_attempts.load(Ordering::Relaxed),
            retry_exhausted: self.runtime.retry_exhausted.load(Ordering::Relaxed),
            overload_rejections: self.runtime.overload_rejections.load(Ordering::Relaxed),
            unavailable_rejections: self.runtime.unavailable_rejections.load(Ordering::Relaxed),
            endpoints: self
                .endpoints
                .iter()
                .map(|endpoint| EndpointStatusSnapshot {
                    name: endpoint.name().to_owned(),
                    runtime: endpoint.state.status(now),
                })
                .collect(),
        }
    }

    fn endpoint(&self, name: &str) -> Option<&Arc<PreparedEndpoint>> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.name() == name)
    }

    fn select_weighted(&self, eligible: &[usize]) -> usize {
        let mut current = self
            .weighted_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (index, value) in current.iter_mut().enumerate() {
            if !eligible.contains(&index) {
                *value = 0;
            }
        }
        let total = eligible.iter().fold(0_i64, |total, index| {
            total + i64::from(self.endpoints[*index].weight())
        });
        let mut selected = eligible[0];
        for index in eligible {
            current[*index] += i64::from(self.endpoints[*index].weight());
            if current[*index] > current[selected] {
                selected = *index;
            }
        }
        current[selected] -= total;
        selected
    }

    fn eligible_indices(&self, excluded: &BTreeSet<String>, now: Instant) -> Vec<usize> {
        self.endpoints
            .iter()
            .enumerate()
            .filter(|(_, endpoint)| {
                endpoint.state.is_eligible(now) && !excluded.contains(endpoint.name())
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn try_acquire_endpoint(&self, excluded: &BTreeSet<String>, now: Instant) -> EndpointAcquire {
        let eligible = self.eligible_indices(excluded, now);
        if eligible.is_empty() {
            return EndpointAcquire::Unavailable;
        }
        match self.spec.load_balance {
            LoadBalancePolicy::RoundRobin => self.try_acquire_round_robin(&eligible),
            LoadBalancePolicy::WeightedRoundRobin => self.try_acquire_weighted(&eligible),
            LoadBalancePolicy::LeastRequests => self.try_acquire_least_requests(&eligible),
        }
    }

    fn try_endpoint_permit(&self, index: usize) -> Option<AdmissionPermit> {
        let permit = self.endpoints[index].state.admission.try_acquire(
            u64::from(self.spec.limits.max_in_flight_per_endpoint),
            Some(Arc::clone(&self.runtime.endpoint_released)),
        )?;
        if self.endpoints[index].state.is_eligible(Instant::now()) {
            Some(permit)
        } else {
            drop(permit);
            None
        }
    }

    fn acquired_endpoint(&self, index: usize, permit: AdmissionPermit) -> EndpointAcquire {
        self.endpoints[index].state.selected();
        EndpointAcquire::Acquired(Arc::clone(&self.endpoints[index]), permit)
    }

    fn try_acquire_round_robin(&self, eligible: &[usize]) -> EndpointAcquire {
        // Reserve a unique starting slot before probing. Concurrent requests do
        // not all observe the same cursor even when endpoint capacity is > 1.
        let sequence = self.round_robin_sequence.fetch_add(1, Ordering::Relaxed);
        let start = sequence as usize % eligible.len();
        for offset in 0..eligible.len() {
            let index = eligible[(start + offset) % eligible.len()];
            if let Some(permit) = self.try_endpoint_permit(index) {
                return self.acquired_endpoint(index, permit);
            }
        }
        EndpointAcquire::Saturated
    }

    fn try_acquire_weighted(&self, eligible: &[usize]) -> EndpointAcquire {
        let mut current = self
            .weighted_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (index, value) in current.iter_mut().enumerate() {
            if !eligible.contains(&index) {
                *value = 0;
            }
        }
        let mut candidates = eligible.to_vec();
        candidates.sort_by(|left, right| {
            let left_score = current[*left] + i64::from(self.endpoints[*left].weight());
            let right_score = current[*right] + i64::from(self.endpoints[*right].weight());
            right_score.cmp(&left_score).then_with(|| left.cmp(right))
        });
        for index in candidates {
            let Some(permit) = self.try_endpoint_permit(index) else {
                continue;
            };
            let total = eligible.iter().fold(0_i64, |total, endpoint| {
                total + i64::from(self.endpoints[*endpoint].weight())
            });
            for endpoint in eligible {
                current[*endpoint] += i64::from(self.endpoints[*endpoint].weight());
            }
            current[index] -= total;
            return self.acquired_endpoint(index, permit);
        }
        EndpointAcquire::Saturated
    }

    fn try_acquire_least_requests(&self, eligible: &[usize]) -> EndpointAcquire {
        let mut candidates = eligible.to_vec();
        candidates.sort_by(|left, right| {
            let left_active = self.endpoints[*left].active_requests().saturating_add(1);
            let right_active = self.endpoints[*right].active_requests().saturating_add(1);
            let left_score = u128::from(left_active) * u128::from(self.endpoints[*right].weight());
            let right_score = u128::from(right_active) * u128::from(self.endpoints[*left].weight());
            left_score.cmp(&right_score).then_with(|| left.cmp(right))
        });
        for index in candidates {
            if let Some(permit) = self.try_endpoint_permit(index) {
                return self.acquired_endpoint(index, permit);
            }
        }
        EndpointAcquire::Saturated
    }

    fn select_least_requests(&self, eligible: &[usize]) -> usize {
        let mut selected = eligible[0];
        for index in eligible.iter().copied().skip(1) {
            let candidate = self.endpoints[index].active_requests().saturating_add(1);
            let incumbent = self.endpoints[selected].active_requests().saturating_add(1);
            let candidate_score =
                u128::from(candidate) * u128::from(self.endpoints[selected].weight());
            let incumbent_score =
                u128::from(incumbent) * u128::from(self.endpoints[index].weight());
            if candidate_score < incumbent_score {
                selected = index;
            }
        }
        selected
    }
}

fn health_policy_compatible(previous: &ClusterHealthSpec, next: &ClusterHealthSpec) -> bool {
    let active_matches = match (&previous.active, &next.active) {
        (None, None) => true,
        (Some(previous), Some(next)) => {
            previous.path == next.path
                && previous.interval == next.interval
                && previous.timeout == next.timeout
                && previous.healthy_statuses == next.healthy_statuses
                && previous.healthy_threshold == next.healthy_threshold
                && previous.unhealthy_threshold == next.unhealthy_threshold
        }
        _ => false,
    };
    let passive_matches = match (&previous.passive, &next.passive) {
        (None, None) => true,
        (Some(previous), Some(next)) => {
            previous.consecutive_failures == next.consecutive_failures
                && previous.eject_for == next.eject_for
        }
        _ => false,
    };
    active_matches && passive_matches
}

/// Admission failure before request-body consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterAdmissionError {
    Unavailable,
    Overloaded,
}

impl fmt::Display for ClusterAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("no eligible upstream endpoint"),
            Self::Overloaded => formatter.write_str("upstream Cluster concurrency limit reached"),
        }
    }
}

impl std::error::Error for ClusterAdmissionError {}

enum EndpointAcquire {
    Acquired(Arc<PreparedEndpoint>, AdmissionPermit),
    Unavailable,
    Saturated,
}

/// RAII request admission. It must live through the complete upstream body
/// lifecycle so success, failure, cancellation, and timeout all release counts.
pub struct ClusterRequestPermit {
    endpoint: Arc<PreparedEndpoint>,
    _cluster: AdmissionPermit,
    _endpoint: AdmissionPermit,
}

impl fmt::Debug for ClusterRequestPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterRequestPermit")
            .field("endpoint", &self.endpoint.name())
            .finish_non_exhaustive()
    }
}

impl ClusterRequestPermit {
    #[must_use]
    pub fn endpoint(&self) -> &Arc<PreparedEndpoint> {
        &self.endpoint
    }
}

/// RAII retry permit. First attempts do not acquire this budget.
#[derive(Debug)]
pub struct ClusterRetryPermit {
    _permit: AdmissionPermit,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterRuntimeStatus {
    pub cluster: String,
    pub protocol: String,
    pub policy: String,
    pub active_requests: u64,
    pub active_retries: u64,
    pub retry_attempts: u64,
    pub retry_exhausted: u64,
    pub overload_rejections: u64,
    pub unavailable_rejections: u64,
    pub endpoints: Vec<EndpointStatusSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointStatusSnapshot {
    pub name: String,
    #[serde(flatten)]
    pub runtime: EndpointRuntimeStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointRuntimeStatus {
    pub health: EndpointHealthState,
    pub active_requests: u64,
    pub selections: u64,
    pub successes: u64,
    pub failures: u64,
    pub active_health_successes: u64,
    pub active_health_failures: u64,
    pub passive_ejections: u64,
    pub health_transitions: u64,
    pub last_transition_unix_ms: u64,
    pub ejection_remaining_ms: Option<u64>,
}

#[derive(Default)]
struct ClusterRuntimeState {
    admission: Arc<AdmissionCounter>,
    retries: Arc<AdmissionCounter>,
    endpoint_released: Arc<Notify>,
    retry_attempts: AtomicU64,
    retry_exhausted: AtomicU64,
    overload_rejections: AtomicU64,
    unavailable_rejections: AtomicU64,
}

#[derive(Debug, Default)]
struct AdmissionCounter {
    active: AtomicU64,
    released: Notify,
}

impl AdmissionCounter {
    fn active(&self) -> u64 {
        self.active.load(Ordering::Acquire)
    }

    fn try_acquire(
        self: &Arc<Self>,
        limit: u64,
        additional_notify: Option<Arc<Notify>>,
    ) -> Option<AdmissionPermit> {
        if limit == 0 {
            return None;
        }
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= limit {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(AdmissionPermit {
                        counter: Arc::clone(self),
                        additional_notify,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct AdmissionPermit {
    counter: Arc<AdmissionCounter>,
    additional_notify: Option<Arc<Notify>>,
}

impl fmt::Debug for AdmissionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmissionPermit")
            .finish_non_exhaustive()
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        self.counter.active.fetch_sub(1, Ordering::AcqRel);
        self.counter.released.notify_one();
        if let Some(notify) = &self.additional_notify {
            notify.notify_one();
        }
    }
}

async fn acquire_counter(
    counter: Arc<AdmissionCounter>,
    limit: u32,
    deadline: Option<tokio::time::Instant>,
) -> Result<AdmissionPermit, ()> {
    loop {
        let notified = counter.released.notified();
        if let Some(permit) = counter.try_acquire(u64::from(limit), None) {
            return Ok(permit);
        }
        let Some(deadline) = deadline else {
            return Err(());
        };
        if tokio::time::timeout_at(deadline, notified).await.is_err() {
            return Err(());
        }
    }
}

fn duration_tick(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use http::Method;
    use oxidase_config::{
        ActiveHealthSpec, ClusterEndpointSpec, ClusterHealthSpec, ClusterLimits, ClusterProtocol,
        ClusterSpec, LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryRequestBodySpec,
        RetrySpec, StatusRange,
    };
    use oxidase_core::{ResourceId, SourceSpan};
    use url::Url;

    use super::{
        ClusterAdmissionError, EndpointHealthState, EndpointRuntimeState, HEALTH_UNKNOWN_ELIGIBLE,
        PreparedCluster,
    };

    fn endpoint(name: &str, url: &str, weight: u16) -> ClusterEndpointSpec {
        ClusterEndpointSpec {
            name: name.to_owned(),
            url: Url::parse(url).expect("fixture endpoint URL is valid"),
            weight,
            name_source: SourceSpan::synthetic(format!("endpoints.{name}.name")),
            url_source: SourceSpan::synthetic(format!("endpoints.{name}.url")),
            weight_source: SourceSpan::synthetic(format!("endpoints.{name}.weight")),
            source: SourceSpan::synthetic(format!("endpoints.{name}")),
        }
    }

    fn cluster(policy: LoadBalancePolicy, endpoints: Vec<ClusterEndpointSpec>) -> ClusterSpec {
        ClusterSpec {
            id: ResourceId::new("cluster:test"),
            protocol: ClusterProtocol::Auto,
            endpoints,
            load_balance: policy,
            health: ClusterHealthSpec {
                active: Some(ActiveHealthSpec {
                    path: "/healthz".to_owned(),
                    interval: Duration::from_secs(5),
                    timeout: Duration::from_secs(1),
                    healthy_statuses: vec![StatusRange {
                        start: 200,
                        end: 299,
                    }],
                    healthy_threshold: 2,
                    unhealthy_threshold: 2,
                    source: SourceSpan::synthetic("health.active"),
                }),
                passive: Some(PassiveHealthSpec {
                    consecutive_failures: 2,
                    eject_for: Duration::from_secs(10),
                    source: SourceSpan::synthetic("health.passive"),
                }),
            },
            retry: RetrySpec {
                max_attempts: 2,
                methods: vec![Method::GET],
                retry_on: Vec::new(),
                statuses: Vec::new(),
                request_body: RetryRequestBodySpec {
                    mode: RetryBodyMode::None,
                    max_bytes: 64 * 1024,
                    source: SourceSpan::synthetic("retry.request_body"),
                },
                max_concurrent_retries: 1,
                source: SourceSpan::synthetic("retry"),
            },
            limits: ClusterLimits {
                max_in_flight: 8,
                max_in_flight_per_endpoint: 4,
                queue_timeout: Duration::ZERO,
                source: SourceSpan::synthetic("limits"),
            },
            connect_timeout: Duration::from_secs(1),
            response_timeout: Duration::from_secs(2),
            protocol_source: SourceSpan::synthetic("protocol"),
            source: SourceSpan::synthetic("cluster"),
        }
    }

    fn prepared(policy: LoadBalancePolicy, endpoints: Vec<ClusterEndpointSpec>) -> PreparedCluster {
        PreparedCluster::prepare(cluster(policy, endpoints), None).0
    }

    #[test]
    fn round_robin_is_deterministic_over_eligible_endpoints() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
                endpoint("c", "http://c.test", 1),
            ],
        );
        let now = Instant::now();
        let selected = (0..7)
            .map(|_| {
                cluster
                    .select_endpoint(now)
                    .expect("an endpoint is eligible")
                    .name()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(selected, ["a", "b", "c", "a", "b", "c", "a"]);
    }

    #[test]
    fn smooth_weighted_round_robin_uses_bounded_per_endpoint_state() {
        let cluster = prepared(
            LoadBalancePolicy::WeightedRoundRobin,
            vec![
                endpoint("a", "http://a.test", 2),
                endpoint("b", "http://b.test", 1),
            ],
        );
        let now = Instant::now();
        let selected = (0..9)
            .map(|_| {
                cluster
                    .select_endpoint(now)
                    .expect("an endpoint is eligible")
                    .name()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected.iter().filter(|name| name.as_str() == "a").count(),
            6
        );
        assert_eq!(
            selected.iter().filter(|name| name.as_str() == "b").count(),
            3
        );
        assert_eq!(
            cluster
                .weighted_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            2,
            "weighted selection stores one accumulator per endpoint"
        );
    }

    #[test]
    fn least_requests_uses_weighted_ratio_and_stable_ties() {
        let cluster = prepared(
            LoadBalancePolicy::LeastRequests,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 2),
            ],
        );
        let now = Instant::now();
        assert_eq!(
            cluster
                .select_endpoint(now)
                .expect("weighted endpoint is eligible")
                .name(),
            "b"
        );
        let endpoint_b = &cluster.endpoints[1];
        let _active = endpoint_b
            .state
            .admission
            .try_acquire(4, None)
            .expect("fixture admission is available");
        assert_eq!(
            cluster
                .select_endpoint(now)
                .expect("tie resolves to first endpoint")
                .name(),
            "a"
        );
    }

    #[test]
    fn active_health_thresholds_remove_and_restore_eligibility() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        let now = Instant::now();
        cluster.record_active_health("a", false, now);
        assert_eq!(
            cluster.endpoints[0].health_state(now),
            EndpointHealthState::UnknownEligible
        );
        cluster.record_active_health("a", false, now);
        assert_eq!(
            cluster.endpoints[0].health_state(now),
            EndpointHealthState::Unhealthy
        );
        assert!(cluster.select_endpoint(now).is_none());
        cluster.record_active_health("a", true, now);
        assert_eq!(
            cluster.endpoints[0].health_state(now),
            EndpointHealthState::Unhealthy
        );
        cluster.record_active_health("a", true, now);
        assert_eq!(
            cluster.endpoints[0].health_state(now),
            EndpointHealthState::Healthy
        );
        let runtime = &cluster.status(now).endpoints[0].runtime;
        assert_eq!(runtime.active_health_failures, 2);
        assert_eq!(runtime.active_health_successes, 2);
        assert_eq!(runtime.health_transitions, 2);
        assert_eq!(runtime.passive_ejections, 0);
    }

    #[test]
    fn passive_ejection_lazily_recovers_and_active_health_can_recover_early() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        let now = Instant::now();
        cluster.record_passive_failure("a", now);
        cluster.record_passive_failure("a", now);
        assert_eq!(
            cluster.endpoints[0].health_state(now),
            EndpointHealthState::PassivelyEjected
        );
        assert_eq!(
            cluster.endpoints[0].health_state(now + Duration::from_secs(11)),
            EndpointHealthState::UnknownEligible
        );

        let later = now + Duration::from_secs(12);
        cluster.record_passive_failure("a", later);
        cluster.record_passive_failure("a", later);
        cluster.record_active_health("a", true, later);
        cluster.record_active_health("a", true, later);
        assert_eq!(
            cluster.endpoints[0].health_state(later),
            EndpointHealthState::Healthy
        );
        let runtime = &cluster.status(later).endpoints[0].runtime;
        assert_eq!(runtime.passive_ejections, 2);
        assert_eq!(runtime.health_transitions, 4);
    }

    #[test]
    fn stale_active_failure_transitions_cannot_overwrite_passive_ejection() {
        const ACTIVE_FAILURES: usize = 32;

        let now = Instant::now();
        let state = Arc::new(EndpointRuntimeState::new_at(now));
        let stale_observation = state.health.load(Ordering::Acquire);
        assert_eq!(stale_observation, HEALTH_UNKNOWN_ELIGIBLE);

        // Model every active-health worker having observed eligibility before
        // the passive failure wins. The old read-then-swap implementation
        // changed this ejection to Unhealthy. Every stale CAS must now fail and
        // preserve the higher-priority state.
        state.transition_to(EndpointHealthState::PassivelyEjected);
        let start = Arc::new(Barrier::new(ACTIVE_FAILURES + 1));
        let workers = (0..ACTIVE_FAILURES)
            .map(|_| {
                let state = Arc::clone(&state);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    state.transition_to_unhealthy_from(stale_observation);
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        for worker in workers {
            worker.join().expect("active-health worker does not panic");
        }

        assert_eq!(
            state.health_state(now),
            EndpointHealthState::PassivelyEjected
        );
        let status = state.status(now);
        assert_eq!(status.passive_ejections, 1);
        assert_eq!(status.health_transitions, 1);
    }

    #[test]
    fn expired_ejection_cleanup_cannot_erase_a_concurrent_new_ejection() {
        let now = Instant::now();
        let expired_at = now + Duration::from_secs(11);
        let new_failure_at = now + Duration::from_secs(12);
        let plan = PassiveHealthSpec {
            consecutive_failures: 1,
            eject_for: Duration::from_secs(10),
            source: SourceSpan::synthetic("health.passive"),
        };
        let state = Arc::new(EndpointRuntimeState::new_at(now));
        state.record_passive_failure(Some(&plan), now);
        assert_eq!(
            EndpointHealthState::decode(state.health.load(Ordering::Acquire)),
            EndpointHealthState::PassivelyEjected
        );

        let transition_guard = state
            .health_transition_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let started = Arc::new(Barrier::new(2));
        let worker = {
            let state = Arc::clone(&state);
            let started = Arc::clone(&started);
            let plan = plan.clone();
            std::thread::spawn(move || {
                started.wait();
                state.record_passive_failure(Some(&plan), new_failure_at);
            })
        };
        started.wait();

        // Model the old lazy recovery winning the transition lock just before
        // a new request reports failure. Cleanup completes under the same lock,
        // then the new failure establishes its own complete ejection state.
        state.recover_expired_ejection_locked(expired_at);
        drop(transition_guard);
        worker
            .join()
            .expect("passive failure worker does not panic");

        assert_eq!(
            state.health_state(new_failure_at),
            EndpointHealthState::PassivelyEjected
        );
        assert_eq!(state.passive_failures.load(Ordering::Acquire), 1);
        assert!(state.ejection_deadline_tick.load(Ordering::Acquire) > state.tick(new_failure_at));
    }

    #[tokio::test]
    async fn admission_limits_are_fail_fast_and_raii_safe() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        let first = cluster.acquire().await.expect("first request is admitted");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(first.endpoint().active_requests(), 1);
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        drop(first);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints[0].active_requests(), 0);
        let second = cluster.acquire().await.expect("drop releases both permits");
        drop(second);
    }

    #[tokio::test]
    async fn saturated_preferred_endpoint_does_not_hide_other_capacity() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        let saturated = cluster.endpoints[0]
            .state
            .admission
            .try_acquire(1, None)
            .expect("fixture saturates the preferred endpoint");

        let admitted = cluster
            .acquire()
            .await
            .expect("capacity on the other endpoint is used");
        assert_eq!(admitted.endpoint().name(), "b");
        assert_eq!(cluster.endpoints[0].state.selections(), 0);
        assert_eq!(cluster.endpoints[1].state.selections(), 1);
        drop(admitted);
        drop(saturated);
    }

    #[tokio::test]
    async fn retry_exclusions_prefer_untried_endpoints_and_stop_after_all() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        let attempted = BTreeSet::from(["a".to_owned()]);
        let admitted = cluster
            .acquire_excluding(&attempted)
            .await
            .expect("an untried endpoint remains");
        assert_eq!(admitted.endpoint().name(), "b");
        drop(admitted);

        let attempted = BTreeSet::from(["a".to_owned(), "b".to_owned()]);
        assert!(matches!(
            cluster.acquire_excluding(&attempted).await,
            Err(ClusterAdmissionError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn status_retry_reuses_cluster_permit_and_switches_endpoint_atomically() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        let mut current = cluster.acquire().await.expect("first endpoint is admitted");
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);

        let attempted = BTreeSet::from(["a".to_owned()]);
        assert!(cluster.retarget_excluding(&mut current, &attempted).await);
        assert_eq!(current.endpoint().name(), "b");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints[0].active_requests(), 0);
        assert_eq!(cluster.endpoints[1].active_requests(), 1);
        drop(current);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints[1].active_requests(), 0);
    }

    #[tokio::test]
    async fn failed_status_retarget_retains_original_endpoint_lease() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        let saturated = cluster.endpoints[1]
            .state
            .admission
            .try_acquire(1, None)
            .expect("fixture saturates the retry endpoint");
        let mut current = cluster.acquire().await.expect("first endpoint is admitted");
        assert_eq!(current.endpoint().name(), "a");
        let attempted = BTreeSet::from(["a".to_owned()]);

        assert!(!cluster.retarget_excluding(&mut current, &attempted).await);
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints[0].active_requests(), 1);
        assert_eq!(cluster.endpoints[1].active_requests(), 1);
        drop(saturated);
        drop(current);
    }

    #[tokio::test]
    async fn cancelled_status_retarget_keeps_original_lease_owned_by_caller() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        spec.limits.queue_timeout = Duration::from_secs(10);
        let cluster = PreparedCluster::prepare(spec, None).0;
        let saturated = cluster.endpoints[1]
            .state
            .admission
            .try_acquire(1, None)
            .expect("fixture saturates the retry endpoint");
        let mut current = cluster.acquire().await.expect("first endpoint is admitted");
        let attempted = BTreeSet::from(["a".to_owned()]);

        let cancelled = tokio::time::timeout(
            Duration::from_millis(10),
            cluster.retarget_excluding(&mut current, &attempted),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints[0].active_requests(), 1);
        drop(saturated);
        drop(current);
    }

    #[tokio::test]
    async fn endpoint_release_wakes_a_waiter_without_losing_notification() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        spec.limits.max_in_flight = 2;
        spec.limits.max_in_flight_per_endpoint = 1;
        spec.limits.queue_timeout = Duration::from_secs(1);
        let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
        let first = cluster.acquire().await.expect("first request is admitted");
        let waiting_cluster = Arc::clone(&cluster);
        let waiting = tokio::spawn(async move { waiting_cluster.acquire().await });
        tokio::task::yield_now().await;
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("waiter is notified before its queue deadline")
            .expect("waiter task does not panic")
            .expect("released endpoint admits the waiter");
        drop(second);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints[0].active_requests(), 0);
    }

    #[tokio::test]
    async fn queued_admission_is_cancellation_safe() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        spec.limits.queue_timeout = Duration::from_secs(10);
        let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
        let first = cluster.acquire().await.expect("first request is admitted");
        let waiting_cluster = Arc::clone(&cluster);
        let waiting = tokio::spawn(async move { waiting_cluster.acquire().await });
        tokio::task::yield_now().await;
        waiting.abort();
        let _ = waiting.await;
        drop(first);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints[0].active_requests(), 0);
    }

    #[test]
    fn retry_budget_is_independent_and_released_on_drop() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        let retry = cluster
            .try_acquire_retry()
            .expect("first retry enters the budget");
        assert_eq!(cluster.active_retries(), 1);
        assert!(cluster.try_acquire_retry().is_none());
        drop(retry);
        assert_eq!(cluster.active_retries(), 0);
        assert!(cluster.try_acquire_retry().is_some());
    }

    #[test]
    fn cluster_status_accumulates_only_fixed_retry_and_admission_results() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        cluster.record_retry_attempt();
        cluster.record_retry_attempt();
        cluster.record_retry_exhausted();
        cluster.record_admission_failure(ClusterAdmissionError::Overloaded);
        cluster.record_admission_failure(ClusterAdmissionError::Unavailable);
        let status = cluster.status(Instant::now());
        assert_eq!(status.retry_attempts, 2);
        assert_eq!(status.retry_exhausted, 1);
        assert_eq!(status.overload_rejections, 1);
        assert_eq!(status.unavailable_rejections, 1);
        let json = serde_json::to_string(&status).expect("bounded counters serialize");
        assert!(!json.contains("http://"));
        assert!(!json.contains("a.test"));
    }

    #[test]
    fn reload_reuses_only_compatible_endpoint_runtime_state() {
        let first = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        first.record_passive_failure("a", Instant::now());
        first.record_retry_attempt();

        let mut policy_update = cluster(
            LoadBalancePolicy::LeastRequests,
            vec![
                endpoint("a", "http://a.test", 2),
                endpoint("b", "http://b.test", 1),
            ],
        );
        policy_update.retry.max_attempts = 3;
        let (second, reused) = PreparedCluster::prepare(policy_update, Some(&first));
        assert_eq!(reused, 2);
        assert!(Arc::ptr_eq(
            first.endpoints[0].runtime_state(),
            second.endpoints[0].runtime_state()
        ));
        assert_eq!(second.status(Instant::now()).retry_attempts, 1);

        let url_update = cluster(
            LoadBalancePolicy::LeastRequests,
            vec![
                endpoint("a", "http://new-a.test", 2),
                endpoint("b", "http://b.test", 1),
            ],
        );
        let (third, reused) = PreparedCluster::prepare(url_update, Some(&second));
        assert_eq!(reused, 1);
        assert!(!Arc::ptr_eq(
            second.endpoints[0].runtime_state(),
            third.endpoints[0].runtime_state()
        ));
        assert!(Arc::ptr_eq(
            second.endpoints[1].runtime_state(),
            third.endpoints[1].runtime_state()
        ));

        let mut protocol_update = cluster(
            LoadBalancePolicy::LeastRequests,
            vec![
                endpoint("a", "http://new-a.test", 2),
                endpoint("b", "http://b.test", 1),
            ],
        );
        protocol_update.protocol = ClusterProtocol::H2;
        let (fourth, reused) = PreparedCluster::prepare(protocol_update, Some(&third));
        assert_eq!(reused, 0);
        assert!(!Arc::ptr_eq(
            third.endpoints[1].runtime_state(),
            fourth.endpoints[1].runtime_state()
        ));
    }

    #[tokio::test]
    async fn health_policy_reload_isolates_health_state_but_shares_endpoint_admission() {
        let mut first_spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        first_spec.limits.max_in_flight = 2;
        first_spec.limits.max_in_flight_per_endpoint = 1;
        let first = PreparedCluster::prepare(first_spec, None).0;
        let mut next_spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        next_spec.limits.max_in_flight = 2;
        next_spec.limits.max_in_flight_per_endpoint = 1;
        next_spec
            .health
            .active
            .as_mut()
            .expect("fixture has active health")
            .path = "/ready".to_owned();

        let (second, reused) = PreparedCluster::prepare(next_spec, Some(&first));
        assert_eq!(reused, 0, "health generation must not be shared");
        assert!(!Arc::ptr_eq(
            first.endpoints[0].runtime_state(),
            second.endpoints[0].runtime_state()
        ));
        assert!(Arc::ptr_eq(
            &first.endpoints[0].runtime_state().admission,
            &second.endpoints[0].runtime_state().admission
        ));

        let old_request = first.acquire().await.expect("old request is admitted");
        assert!(matches!(
            second.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        drop(old_request);
        let new_request = second
            .acquire()
            .await
            .expect("dropping the old request releases shared admission");
        drop(new_request);
    }

    #[tokio::test]
    async fn reload_shared_counters_apply_new_limits_to_old_active_requests() {
        let mut first_spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        first_spec.limits.max_in_flight = 1;
        first_spec.limits.max_in_flight_per_endpoint = 1;
        let first = PreparedCluster::prepare(first_spec, None).0;
        let old_request = first.acquire().await.expect("old request is admitted");

        let mut second_spec = cluster(
            LoadBalancePolicy::LeastRequests,
            vec![endpoint("a", "http://a.test", 1)],
        );
        second_spec.limits.max_in_flight = 2;
        second_spec.limits.max_in_flight_per_endpoint = 2;
        let (second, reused) = PreparedCluster::prepare(second_spec, Some(&first));
        assert_eq!(reused, 1);
        let new_request = second
            .acquire()
            .await
            .expect("new limit includes and permits one request beside the old request");
        assert!(matches!(
            second.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        drop(old_request);
        drop(new_request);
        assert_eq!(first.active_requests(), 0);
        assert_eq!(second.active_requests(), 0);
    }

    #[test]
    fn supervisor_activation_is_once_per_prepared_cluster() {
        let first = Arc::new(prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        ));
        assert!(!first.supervisor_is_activated());
        assert!(first.try_activate_supervisor());
        assert!(!first.try_activate_supervisor());
        assert!(Arc::clone(&first).supervisor_is_activated());

        let replacement = PreparedCluster::prepare(
            cluster(
                LoadBalancePolicy::LeastRequests,
                vec![endpoint("a", "http://a.test", 1)],
            ),
            Some(&first),
        )
        .0;
        assert!(!replacement.supervisor_is_activated());
        assert!(replacement.try_activate_supervisor());
    }

    #[test]
    fn status_is_bounded_and_does_not_expose_endpoint_urls() {
        let cluster = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint(
                "public-name",
                "https://secret-origin.example/private",
                1,
            )],
        );
        let json = serde_json::to_string(&cluster.status(Instant::now()))
            .expect("runtime status serializes");
        assert!(json.contains("public-name"));
        assert!(!json.contains("secret-origin"));
        assert!(!json.contains("private"));
    }

    #[test]
    fn request_result_counters_exist_without_passive_ejection_policy() {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        spec.health.passive = None;
        let cluster = PreparedCluster::prepare(spec, None).0;
        let now = Instant::now();
        cluster.record_passive_failure("a", now);
        cluster.record_passive_success("a");
        let status = cluster.status(now);
        assert_eq!(status.endpoints[0].runtime.failures, 1);
        assert_eq!(status.endpoints[0].runtime.successes, 1);
        assert_eq!(
            status.endpoints[0].runtime.health,
            EndpointHealthState::UnknownEligible
        );
    }

    #[test]
    #[ignore = "manual Cluster policy benchmark; run with --release --ignored --nocapture"]
    fn cluster_policy_smoke_benchmark() {
        let iterations = std::env::var("OXIDASE_CLUSTER_BENCH_ITERATIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1_000_000)
            .max(1);
        let weighted = prepared(
            LoadBalancePolicy::WeightedRoundRobin,
            vec![
                endpoint("a", "http://a.test", 5),
                endpoint("b", "http://b.test", 3),
                endpoint("c", "http://c.test", 2),
            ],
        );
        let least = prepared(
            LoadBalancePolicy::LeastRequests,
            vec![
                endpoint("a", "http://a.test", 5),
                endpoint("b", "http://b.test", 3),
                endpoint("c", "http://c.test", 2),
            ],
        );
        let health = prepared(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://a.test", 1)],
        );
        let now = Instant::now();

        let started = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(weighted.select_endpoint(now));
        }
        let weighted_elapsed = started.elapsed();

        let started = Instant::now();
        for _ in 0..iterations {
            std::hint::black_box(least.select_endpoint(now));
        }
        let least_elapsed = started.elapsed();

        let started = Instant::now();
        for _ in 0..iterations {
            let permit = health
                .try_acquire_retry()
                .expect("benchmark retry permit is available");
            std::hint::black_box(&permit);
            drop(permit);
        }
        let retry_elapsed = started.elapsed();

        let started = Instant::now();
        for _ in 0..iterations {
            health.record_active_health("a", false, now);
            health.record_active_health("a", false, now);
            health.record_active_health("a", true, now);
            health.record_active_health("a", true, now);
        }
        let health_elapsed = started.elapsed();

        println!(
            "cluster_policy_benchmark iterations={iterations} weighted_ms={} least_requests_ms={} retry_budget_ms={} health_transition_ms={}",
            weighted_elapsed.as_millis(),
            least_elapsed.as_millis(),
            retry_elapsed.as_millis(),
            health_elapsed.as_millis(),
        );
    }
}
