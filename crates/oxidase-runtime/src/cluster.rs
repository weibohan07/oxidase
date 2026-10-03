//! Prepared upstream Cluster plans and their reload-stable runtime state.
//!
//! This module deliberately owns no connection pool and starts no background
//! tasks. Preparation is therefore side-effect free: the server may activate a
//! health supervisor only after the containing snapshot has committed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oxidase_config::{
    ActiveHealthSpec, ClusterEndpointSpec, ClusterHealthSpec, ClusterProtocol, ClusterSpec,
    LoadBalancePolicy, PassiveHealthSpec,
};
use oxidase_core::{ContentDigestBuilder, ResourceId};
use serde::Serialize;
use tokio::sync::{Notify, watch};

use crate::PreparedUpstreamTls;
use crate::discovery::{
    DiscoveryErrorCode, DiscoveryReconcileOutcome, DiscoveryResolutionState,
    DiscoveryRuntimeStatus, DnsAddressRecord, DnsFamily, DnsObservation,
    normalize_discovery_address, validate_discovery_address,
};

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
    dynamic: Option<DynamicEndpointIdentity>,
}

#[derive(Debug)]
struct DynamicEndpointIdentity {
    target: SocketAddr,
    incarnation: u64,
    logical_target: String,
    owner: Arc<()>,
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

    /// The already-validated address for a dynamic attempt. Static endpoints
    /// retain their existing resolution path and return `None`.
    #[must_use]
    pub fn dial_target(&self) -> Option<SocketAddr> {
        self.dynamic.as_ref().map(|identity| identity.target)
    }

    /// Remove/readd creates a new incarnation even for the same physical IP.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.dynamic
            .as_ref()
            .map_or(0, |identity| identity.incarnation)
    }

    #[must_use]
    pub fn logical_target(&self) -> Option<&str> {
        self.dynamic
            .as_ref()
            .map(|identity| identity.logical_target.as_str())
    }
}

/// Side-effect-free prepared Cluster resource.
///
/// Health supervisors and connection pools live at the server boundary. This
/// object provides immutable policy, deterministic selection, reload-stable
/// endpoint state, and cancellation-safe admission permits.
pub struct PreparedCluster {
    spec: ClusterSpec,
    upstream_tls: Option<Arc<PreparedUpstreamTls>>,
    membership: Arc<Mutex<EndpointMembership>>,
    runtime: Arc<ClusterRuntimeState>,
    round_robin_sequence: AtomicU64,
    supervisor_activated: AtomicBool,
    policy_retired: Mutex<watch::Sender<bool>>,
}

struct EndpointMembership {
    owner: Arc<()>,
    endpoints: Arc<[Arc<PreparedEndpoint>]>,
    weighted_state: Vec<i64>,
    generation: u64,
    active: bool,
    retired: bool,
    query_sequence: u64,
    query: Option<QueryRound>,
    families: [FamilyState; 2],
    valid_until: BTreeMap<SocketAddr, tokio::time::Instant>,
    stale_targets: BTreeSet<SocketAddr>,
    admission_counters: BTreeMap<SocketAddr, Weak<AdmissionCounter>>,
    last_success_unix_ms: Option<u64>,
    next_refresh: Option<tokio::time::Instant>,
}

#[derive(Default)]
struct FamilyState {
    records: Vec<DnsAddressRecord>,
    outcome: Option<DiscoveryResolutionState>,
    transient: Option<DiscoveryErrorCode>,
}

struct QueryRound {
    sequence: u64,
    name_revoked: bool,
}

type AdmissionOwner = (Option<Arc<()>>, Option<watch::Receiver<bool>>);

/// One commit-owned refresh round. Drop releases the one-round slot; callbacks
/// from a retired owner or another sequence cannot update current membership.
pub struct DiscoveryQueryLease {
    membership: Weak<Mutex<EndpointMembership>>,
    owner: Arc<()>,
    sequence: u64,
}

impl fmt::Debug for DiscoveryQueryLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryQueryLease")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

impl Drop for DiscoveryQueryLease {
    fn drop(&mut self) {
        if let Some(membership) = self.membership.upgrade() {
            let mut membership = membership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if Arc::ptr_eq(&membership.owner, &self.owner)
                && membership
                    .query
                    .as_ref()
                    .is_some_and(|query| query.sequence == self.sequence)
            {
                membership.query = None;
            }
        }
    }
}

impl fmt::Debug for PreparedCluster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedCluster")
            .field("id", &self.spec.id)
            .field("protocol", &self.spec.protocol)
            .field("load_balance", &self.spec.load_balance)
            .field(
                "upstream_tls",
                &self.upstream_tls.as_ref().map(|tls| tls.digest()),
            )
            .field("endpoints", &self.endpoints())
            .finish_non_exhaustive()
    }
}

impl PreparedCluster {
    /// Prepares a new immutable policy and reuses compatible runtime state.
    ///
    /// The return value counts endpoint states reused from `previous`.
    #[must_use]
    pub fn prepare(spec: ClusterSpec, previous: Option<&Self>) -> (Self, usize) {
        Self::prepare_with_tls(spec, None, previous)
    }

    /// Prepares a Cluster with its already-validated upstream TLS policy.
    #[must_use]
    pub(crate) fn prepare_with_tls(
        spec: ClusterSpec,
        upstream_tls: Option<Arc<PreparedUpstreamTls>>,
        previous: Option<&Self>,
    ) -> (Self, usize) {
        let same_cluster = previous.filter(|previous| previous.spec.id == spec.id);
        let same_protocol = same_cluster.filter(|previous| previous.spec.protocol == spec.protocol);
        let same_transport = same_protocol.filter(|previous| {
            previous.upstream_tls.as_ref().map(|tls| tls.digest())
                == upstream_tls.as_ref().map(|tls| tls.digest())
        });
        let same_health_policy = same_transport
            .filter(|previous| health_policy_compatible(&previous.spec.health, &spec.health));
        let runtime = same_cluster.map_or_else(
            || Arc::new(ClusterRuntimeState::default()),
            |previous| Arc::clone(&previous.runtime),
        );
        let previous_endpoints = same_protocol.map(Self::endpoints);
        let mut reused = 0;
        let endpoints = spec
            .endpoints
            .iter()
            .cloned()
            .map(|endpoint| {
                let previous_endpoint = previous_endpoints.as_ref().and_then(|previous| {
                    previous.iter().find(|candidate| {
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
                    dynamic: None,
                })
            })
            .collect::<Vec<_>>();
        let (policy_retired, _) = watch::channel(false);
        let membership = Arc::new(Mutex::new(EndpointMembership {
            owner: Arc::new(()),
            weighted_state: vec![0; endpoints.len()],
            endpoints: endpoints.into(),
            generation: 0,
            active: spec.discovery.is_none(),
            retired: false,
            query_sequence: 0,
            query: None,
            families: [FamilyState::default(), FamilyState::default()],
            valid_until: BTreeMap::new(),
            stale_targets: BTreeSet::new(),
            admission_counters: BTreeMap::new(),
            last_success_unix_ms: None,
            next_refresh: None,
        }));
        (
            Self {
                spec,
                upstream_tls,
                membership,
                runtime,
                round_robin_sequence: AtomicU64::new(0),
                supervisor_activated: AtomicBool::new(false),
                policy_retired: Mutex::new(policy_retired),
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
    pub fn upstream_tls(&self) -> Option<&Arc<PreparedUpstreamTls>> {
        self.upstream_tls.as_ref()
    }

    #[must_use]
    pub fn endpoints(&self) -> Arc<[Arc<PreparedEndpoint>]> {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        Arc::clone(&membership.endpoints)
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

    /// The manager calls this only after the actual retired task has stopped.
    pub fn deactivate_supervisor(&self) {
        self.supervisor_activated.store(false, Ordering::Release);
    }

    /// Activate a committed discovery owner, never from a DNS callback. An
    /// already-active resource is unchanged; explicitly resuming a retired
    /// resource creates a fresh fenced session and a cold initial address set.
    #[must_use]
    pub fn activate_discovery_policy(&self) -> bool {
        if self.spec.discovery.is_none() {
            return false;
        }
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if membership.active && !membership.retired {
            return false;
        }
        membership.owner = Arc::new(());
        membership.active = true;
        membership.retired = false;
        membership.query = None;
        membership.families = [FamilyState::default(), FamilyState::default()];
        membership.valid_until.clear();
        membership.stale_targets.clear();
        membership.last_success_unix_ms = None;
        membership.next_refresh = None;
        if !membership.endpoints.is_empty() {
            membership.endpoints = Arc::from([]);
            membership.weighted_state.clear();
            membership.generation = membership.generation.saturating_add(1);
        }
        let (retired, _) = watch::channel(false);
        *self
            .policy_retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = retired;
        true
    }

    /// Stop issuing new dynamic attempts and fence outstanding observations.
    /// Existing leases retain only their endpoint/permit and may finish.
    pub fn retire_discovery_policy(&self) {
        if self.spec.discovery.is_none() {
            return;
        }
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        membership.retired = true;
        membership.query = None;
        membership.next_refresh = None;
        if self.spec.discovery.is_some() {
            let held = membership
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.state.admission.active() > 0)
                .map(|endpoint| {
                    (
                        endpoint.dial_target(),
                        Arc::downgrade(&endpoint.state.admission),
                    )
                })
                .filter_map(|(target, counter)| target.map(|target| (target, counter)))
                .collect::<Vec<_>>();
            membership.admission_counters.extend(held);
            membership.active = false;
            membership.families = [FamilyState::default(), FamilyState::default()];
            membership.valid_until.clear();
            membership.stale_targets.clear();
            if !membership.endpoints.is_empty() {
                membership.endpoints = Arc::from([]);
                membership.weighted_state.clear();
                membership.generation = membership.generation.saturating_add(1);
            }
        }
        let _ = self
            .policy_retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send_replace(true);
        self.runtime.endpoint_released.notify_waiters();
    }

    /// This receiver is scoped to one activation session; resuming the same
    /// PreparedCluster cannot make an old receiver become live again.
    #[must_use]
    pub fn discovery_retirement(&self) -> watch::Receiver<bool> {
        self.policy_retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .subscribe()
    }

    /// One bounded refresh round per committed policy owner. It is not a
    /// background task and carries no configuration publication capability.
    pub fn begin_discovery_query(&self) -> Option<DiscoveryQueryLease> {
        self.spec.discovery.as_ref()?;
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !membership.active || membership.retired || membership.query.is_some() {
            return None;
        }
        let sequence = membership.query_sequence.checked_add(1)?;
        membership.query_sequence = sequence;
        membership.query = Some(QueryRound {
            sequence,
            name_revoked: false,
        });
        Some(DiscoveryQueryLease {
            membership: Arc::downgrade(&self.membership),
            owner: Arc::clone(&membership.owner),
            sequence,
        })
    }

    /// Record the committed supervisor's schedule while its round/session is
    /// still current. Observation metadata does not renew endpoint lifetimes.
    pub fn set_discovery_refresh(
        &self,
        query: &DiscoveryQueryLease,
        next: tokio::time::Instant,
    ) -> bool {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if membership.active
            && !membership.retired
            && Arc::ptr_eq(&membership.owner, &query.owner)
            && membership
                .query
                .as_ref()
                .is_some_and(|round| round.sequence == query.sequence)
        {
            membership.next_refresh = Some(next);
            true
        } else {
            false
        }
    }

    /// Apply a structured family result. The membership lock is also the
    /// business-lease issuance gate, so removal and acquisition are linearized.
    pub fn reconcile_dns(
        &self,
        query: &DiscoveryQueryLease,
        family: DnsFamily,
        observation: DnsObservation,
        now: tokio::time::Instant,
    ) -> DiscoveryReconcileOutcome {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(plan) = &self.spec.discovery else {
            return Self::reconcile_receipt(&membership, false, false);
        };
        let valid_query = membership.active
            && !membership.retired
            && Arc::ptr_eq(&membership.owner, &query.owner)
            && membership
                .query
                .as_ref()
                .is_some_and(|round| round.sequence == query.sequence && !round.name_revoked);
        if !valid_query {
            return Self::reconcile_receipt(&membership, false, false);
        }
        let generation = membership.generation;
        let index = family_index(family);
        match observation {
            DnsObservation::Positive { addresses } => {
                if addresses.len() > 512 {
                    membership.families[index] = FamilyState::error(
                        DiscoveryResolutionState::LimitExceeded,
                        DiscoveryErrorCode::LimitExceeded,
                    );
                } else {
                    let mut normalized = BTreeMap::new();
                    let mut rejected = false;
                    let mut invalid = false;
                    for record in addresses {
                        // A mapped AAAA may already be normalized by the
                        // resolver's strict RR-type parser.
                        let same_family = family == DnsFamily::Aaaa || record.address.is_ipv4();
                        if !same_family {
                            invalid = true;
                            break;
                        }
                        if validate_discovery_address(
                            record.address,
                            plan.port,
                            &plan.address_policy,
                        )
                        .is_err()
                        {
                            rejected = true;
                            continue;
                        }
                        let address = normalize_discovery_address(record.address);
                        normalized
                            .entry(address)
                            .and_modify(|expiry: &mut tokio::time::Instant| {
                                *expiry = (*expiry).min(record.fresh_until)
                            })
                            .or_insert(record.fresh_until);
                    }
                    let records = normalized
                        .into_iter()
                        // Deduplicate first: a TTL0 duplicate cannot be
                        // upgraded by a duplicate with a longer lifetime.
                        .filter(|(_, fresh_until)| *fresh_until > now)
                        .map(|(address, fresh_until)| DnsAddressRecord {
                            address,
                            fresh_until,
                        })
                        .collect::<Vec<_>>();
                    if invalid {
                        membership.families[index] = FamilyState::error(
                            DiscoveryResolutionState::InvalidAnswer,
                            DiscoveryErrorCode::InvalidAnswer,
                        );
                    } else if records.len() > usize::from(plan.limits.max_endpoints) {
                        membership.families[index] = FamilyState::error(
                            DiscoveryResolutionState::LimitExceeded,
                            DiscoveryErrorCode::LimitExceeded,
                        );
                    } else if records.is_empty() && rejected {
                        membership.families[index] = FamilyState::error(
                            DiscoveryResolutionState::PolicyRejected,
                            DiscoveryErrorCode::PolicyRejected,
                        );
                    } else {
                        membership.families[index] = FamilyState {
                            records,
                            outcome: Some(DiscoveryResolutionState::Fresh),
                            transient: None,
                        };
                        membership.last_success_unix_ms = Some(unix_time_millis());
                    }
                }
            }
            DnsObservation::NameNotFound => {
                membership.families = [
                    FamilyState::empty(DiscoveryResolutionState::NameNotFound),
                    FamilyState::empty(DiscoveryResolutionState::NameNotFound),
                ];
                if let Some(round) = &mut membership.query {
                    round.name_revoked = true;
                }
            }
            DnsObservation::NoData => {
                membership.families[index] = FamilyState::empty(DiscoveryResolutionState::NoData)
            }
            DnsObservation::TransientFailure { code } if code.allows_stale() => {
                membership.families[index].outcome =
                    Some(DiscoveryResolutionState::TransientFailure);
                membership.families[index].transient = Some(code);
            }
            DnsObservation::TransientFailure { code } => {
                let outcome = match code {
                    DiscoveryErrorCode::PolicyRejected => DiscoveryResolutionState::PolicyRejected,
                    DiscoveryErrorCode::InvalidAnswer => DiscoveryResolutionState::InvalidAnswer,
                    DiscoveryErrorCode::LimitExceeded => DiscoveryResolutionState::LimitExceeded,
                    _ => DiscoveryResolutionState::TransientFailure,
                };
                membership.families[index] = FamilyState::error(outcome, code);
            }
            DnsObservation::InvalidAnswer => {
                membership.families[index] = FamilyState::error(
                    DiscoveryResolutionState::InvalidAnswer,
                    DiscoveryErrorCode::InvalidAnswer,
                )
            }
            DnsObservation::PolicyRejected => {
                membership.families[index] = FamilyState::error(
                    DiscoveryResolutionState::PolicyRejected,
                    DiscoveryErrorCode::PolicyRejected,
                )
            }
            DnsObservation::LimitExceeded => {
                membership.families[index] = FamilyState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                )
            }
        }
        let eligible = membership
            .families
            .iter()
            .flat_map(|family| {
                family
                    .records
                    .iter()
                    .filter(|record| {
                        now < record.fresh_until
                            || (family
                                .transient
                                .is_some_and(DiscoveryErrorCode::allows_stale)
                                && record
                                    .fresh_until
                                    .checked_add(plan.refresh.stale_if_error)
                                    .is_some_and(|expiry| now < expiry))
                    })
                    .map(|record| record.address)
            })
            .collect::<BTreeSet<_>>()
            .len();
        if eligible > usize::from(plan.limits.max_endpoints) {
            // Retained expired bookkeeping is not membership. Reject this
            // family's overflow without discarding valid other-family peers.
            membership.families[index] = FamilyState::error(
                DiscoveryResolutionState::LimitExceeded,
                DiscoveryErrorCode::LimitExceeded,
            );
        }
        self.refresh_membership_locked(&mut membership, now);
        let mut receipt =
            Self::reconcile_receipt(&membership, true, generation != membership.generation);
        receipt.observation_error_code = membership.families[index].transient;
        drop(membership);
        self.runtime.endpoint_released.notify_waiters();
        receipt
    }

    /// Checks exact current membership for health and idle-pool ownership. An
    /// already-issued business lease does not need this check to finish.
    #[must_use]
    pub fn contains_endpoint(&self, endpoint: &Arc<PreparedEndpoint>) -> bool {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        !membership.retired
            && membership
                .endpoints
                .iter()
                .any(|current| Arc::ptr_eq(current, endpoint))
    }

    pub fn record_active_health_for(
        &self,
        endpoint: &Arc<PreparedEndpoint>,
        succeeded: bool,
        now: Instant,
    ) {
        let Some(plan) = &self.spec.health.active else {
            return;
        };
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        if !membership.retired
            && membership
                .endpoints
                .iter()
                .any(|current| Arc::ptr_eq(current, endpoint))
        {
            endpoint.state.record_active_health(succeeded, plan, now);
        }
    }

    pub fn record_passive_success_for(&self, endpoint: &Arc<PreparedEndpoint>) {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        if !membership.retired
            && membership
                .endpoints
                .iter()
                .any(|current| Arc::ptr_eq(current, endpoint))
        {
            endpoint.state.record_passive_success();
        }
    }

    pub fn record_passive_failure_for(&self, endpoint: &Arc<PreparedEndpoint>, now: Instant) {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        if !membership.retired
            && membership
                .endpoints
                .iter()
                .any(|current| Arc::ptr_eq(current, endpoint))
        {
            endpoint
                .state
                .record_passive_failure(self.spec.health.passive.as_ref(), now);
        }
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
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        if self.spec.discovery.is_some() && (!membership.active || membership.retired) {
            return None;
        }
        let eligible = membership
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
            LoadBalancePolicy::WeightedRoundRobin => {
                Self::select_weighted(&mut membership, &eligible)
            }
            LoadBalancePolicy::LeastRequests => Self::select_least_requests(&membership, &eligible),
        };
        Some(Arc::clone(&membership.endpoints[selected]))
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
        let (owner, retired) = self.admission_owner(None)?;
        self.acquire_excluding_owned(excluded, owner, retired).await
    }

    /// Retry in the original attempt's policy session. A resumed resource may
    /// serve new requests but cannot give an old logical request new authority.
    pub async fn acquire_excluding_for(
        &self,
        excluded: &BTreeSet<String>,
        previous: &Arc<PreparedEndpoint>,
    ) -> Result<ClusterRequestPermit, ClusterAdmissionError> {
        let (owner, retired) = self.admission_owner(Some(previous))?;
        self.acquire_excluding_owned(excluded, owner, retired).await
    }

    fn admission_owner(
        &self,
        previous: Option<&Arc<PreparedEndpoint>>,
    ) -> Result<AdmissionOwner, ClusterAdmissionError> {
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.spec.discovery.is_some() {
            if !membership.active
                || membership.retired
                || previous.is_some_and(|endpoint| {
                    endpoint
                        .dynamic
                        .as_ref()
                        .is_none_or(|identity| !Arc::ptr_eq(&identity.owner, &membership.owner))
                })
            {
                return Err(ClusterAdmissionError::Unavailable);
            }
            // Subscribe while holding the ownership gate so retirement/restart
            // cannot substitute a different session's watch receiver.
            Ok((
                Some(Arc::clone(&membership.owner)),
                Some(
                    self.policy_retired
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .subscribe(),
                ),
            ))
        } else if previous.is_some_and(|endpoint| {
            !membership
                .endpoints
                .iter()
                .any(|current| Arc::ptr_eq(current, endpoint))
        }) {
            Err(ClusterAdmissionError::Unavailable)
        } else {
            Ok((None, None))
        }
    }

    async fn acquire_excluding_owned(
        &self,
        excluded: &BTreeSet<String>,
        owner: Option<Arc<()>>,
        mut retired: Option<watch::Receiver<bool>>,
    ) -> Result<ClusterRequestPermit, ClusterAdmissionError> {
        let queue_timeout = self.spec.limits.queue_timeout;
        let deadline = if queue_timeout.is_zero() {
            None
        } else {
            Some(
                tokio::time::Instant::now()
                    .checked_add(queue_timeout)
                    .ok_or(ClusterAdmissionError::Overloaded)?,
            )
        };
        let admission = acquire_counter(
            Arc::clone(&self.runtime.admission),
            self.spec.limits.max_in_flight,
            deadline,
        );
        let cluster = if let Some(retired) = &mut retired {
            tokio::select! {
                biased;
                _ = retired.changed() => return Err(ClusterAdmissionError::Unavailable),
                result = admission => result,
            }
        } else {
            admission.await
        }
        .map_err(|()| ClusterAdmissionError::Overloaded)?;

        loop {
            // Register before scanning all endpoints so a release racing the
            // scan leaves a Notify permit instead of being lost.
            let released = self.runtime.endpoint_released.notified();
            match self.try_acquire_endpoint_owned(excluded, Instant::now(), owner.as_ref()) {
                EndpointAcquire::Acquired(endpoint, endpoint_permit, generation) => {
                    return Ok(ClusterRequestPermit {
                        endpoint,
                        _cluster: cluster,
                        _endpoint: endpoint_permit,
                        generation,
                        owner,
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
            let waiting = tokio::time::timeout_at(deadline, released);
            let finished = if let Some(retired) = &mut retired {
                tokio::select! {
                    biased;
                    _ = retired.changed() => return Err(ClusterAdmissionError::Unavailable),
                    result = waiting => result,
                }
            } else {
                waiting.await
            };
            if finished.is_err() {
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
        let Ok((owner, mut retired)) = self.admission_owner(Some(&current.endpoint)) else {
            return false;
        };
        let mut excluded = excluded.clone();
        excluded.insert(current.endpoint.name().to_owned());
        let queue_timeout = self.spec.limits.queue_timeout;
        let deadline = if queue_timeout.is_zero() {
            None
        } else {
            let Some(deadline) = tokio::time::Instant::now().checked_add(queue_timeout) else {
                return false;
            };
            Some(deadline)
        };

        loop {
            let released = self.runtime.endpoint_released.notified();
            match self.try_acquire_endpoint_owned(&excluded, Instant::now(), owner.as_ref()) {
                EndpointAcquire::Acquired(endpoint, endpoint_permit, generation) => {
                    let old_endpoint = std::mem::replace(&mut current._endpoint, endpoint_permit);
                    current.endpoint = endpoint;
                    current.generation = generation;
                    current.owner = owner;
                    drop(old_endpoint);
                    return true;
                }
                EndpointAcquire::Unavailable => return false,
                EndpointAcquire::Saturated => {}
            }
            let Some(deadline) = deadline else {
                return false;
            };
            let waiting = tokio::time::timeout_at(deadline, released);
            let finished = if let Some(retired) = &mut retired {
                tokio::select! {
                    biased;
                    _ = retired.changed() => return false,
                    result = waiting => result,
                }
            } else {
                waiting.await
            };
            if finished.is_err() {
                return false;
            }
        }
    }

    /// Reserves a different endpoint without consuming a second Cluster slot
    /// or changing the current attempt. This is the pre-cancellation boundary
    /// for status retry: a caller may keep its original response untouched when
    /// no replacement is admitted, and cancel the old upload only after it owns
    /// a replacement reservation. Queue cancellation drops only this wait.
    pub async fn reserve_retry_endpoint(
        &self,
        excluded: &BTreeSet<String>,
        current_name: &str,
    ) -> Option<ClusterEndpointReservation> {
        if self.spec.discovery.is_some() {
            return None;
        }
        self.reserve_retry_endpoint_owned(excluded, current_name, None, None)
            .await
    }

    /// Session-fenced status retry; does not cancel or consume the old attempt.
    pub async fn reserve_retry_endpoint_for(
        &self,
        excluded: &BTreeSet<String>,
        current: &Arc<PreparedEndpoint>,
    ) -> Option<ClusterEndpointReservation> {
        let (owner, retired) = self.admission_owner(Some(current)).ok()?;
        self.reserve_retry_endpoint_owned(excluded, current.name(), owner, retired)
            .await
    }

    async fn reserve_retry_endpoint_owned(
        &self,
        excluded: &BTreeSet<String>,
        current_name: &str,
        owner: Option<Arc<()>>,
        mut retired: Option<watch::Receiver<bool>>,
    ) -> Option<ClusterEndpointReservation> {
        let mut excluded = excluded.clone();
        excluded.insert(current_name.to_owned());
        let queue_timeout = self.spec.limits.queue_timeout;
        let deadline = if queue_timeout.is_zero() {
            None
        } else {
            Some(tokio::time::Instant::now().checked_add(queue_timeout)?)
        };
        loop {
            let released = self.runtime.endpoint_released.notified();
            match self.try_acquire_endpoint_owned(&excluded, Instant::now(), owner.as_ref()) {
                EndpointAcquire::Acquired(endpoint, endpoint_permit, generation) => {
                    return Some(ClusterEndpointReservation {
                        endpoint,
                        endpoint_permit,
                        cluster_counter: Arc::clone(&self.runtime.admission),
                        generation,
                        owner,
                    });
                }
                EndpointAcquire::Unavailable => return None,
                EndpointAcquire::Saturated => {}
            }
            let deadline = deadline?;
            let waiting = tokio::time::timeout_at(deadline, released);
            let finished = if let Some(retired) = &mut retired {
                tokio::select! {
                    biased;
                    _ = retired.changed() => return None,
                    result = waiting => result,
                }
            } else {
                waiting.await
            };
            if finished.is_err() {
                return None;
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
        if self.spec.discovery.is_some() {
            return;
        }
        let Some(plan) = &self.spec.health.active else {
            return;
        };
        if let Some(endpoint) = self.endpoint(endpoint_name) {
            endpoint.state.record_active_health(succeeded, plan, now);
        }
    }

    pub fn record_passive_success(&self, endpoint_name: &str) {
        if self.spec.discovery.is_some() {
            return;
        }
        if let Some(endpoint) = self.endpoint(endpoint_name) {
            endpoint.state.record_passive_success();
        }
    }

    pub fn record_passive_failure(&self, endpoint_name: &str, now: Instant) {
        if self.spec.discovery.is_some() {
            return;
        }
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
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observed = tokio::time::Instant::now();
        self.refresh_membership_locked(&mut membership, observed);
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
            discovery: self.discovery_status_locked(&membership, observed),
            endpoints: membership
                .endpoints
                .iter()
                .map(|endpoint| EndpointStatusSnapshot {
                    name: endpoint.name().to_owned(),
                    runtime: endpoint.state.status(now),
                })
                .collect(),
        }
    }

    fn endpoint(&self, name: &str) -> Option<Arc<PreparedEndpoint>> {
        self.endpoints()
            .iter()
            .find(|endpoint| endpoint.name() == name)
            .cloned()
    }

    #[must_use]
    pub fn discovery_status(&self) -> Option<DiscoveryRuntimeStatus> {
        self.spec.discovery.as_ref()?;
        let now = tokio::time::Instant::now();
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, now);
        self.discovery_status_locked(&membership, now)
    }

    fn discovery_status_locked(
        &self,
        membership: &EndpointMembership,
        now: tokio::time::Instant,
    ) -> Option<DiscoveryRuntimeStatus> {
        let plan = self.spec.discovery.as_ref()?;
        Some(DiscoveryRuntimeStatus {
            name: plan.name.clone(),
            resolution: membership.resolution(),
            generation: membership.generation,
            endpoint_count: membership.endpoints.len(),
            eligible_endpoints: membership
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.state.is_eligible(Instant::now()))
                .count(),
            in_flight_query: membership.query.is_some(),
            last_success_unix_ms: membership.last_success_unix_ms,
            next_expiry_ms: membership.valid_until.values().min().map(|expiry| {
                u64::try_from(expiry.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
            }),
            next_refresh_ms: membership.next_refresh.map(|next| {
                u64::try_from(next.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
            }),
            error_code: membership.error_code(),
            retired_admission_counters: membership
                .admission_counters
                .iter()
                .filter(|(target, _)| !membership.valid_until.contains_key(target))
                .count(),
        })
    }

    #[must_use]
    pub fn next_discovery_expiry(&self) -> Option<tokio::time::Instant> {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        membership.valid_until.values().copied().min()
    }

    fn reconcile_receipt(
        membership: &EndpointMembership,
        applied: bool,
        changed: bool,
    ) -> DiscoveryReconcileOutcome {
        DiscoveryReconcileOutcome {
            applied,
            changed,
            generation: membership.generation,
            endpoint_count: membership.endpoints.len(),
            next_expiry: membership.valid_until.values().copied().min(),
            error_code: membership.error_code(),
            observation_error_code: None,
        }
    }

    /// Remove expirations even when the resolver task is delayed. This lock is
    /// held through endpoint admission; no retained snapshot may mint leases.
    fn refresh_membership_locked(
        &self,
        membership: &mut EndpointMembership,
        now: tokio::time::Instant,
    ) {
        let Some(plan) = &self.spec.discovery else {
            return;
        };
        membership.admission_counters.retain(|_, counter| {
            counter
                .upgrade()
                .is_some_and(|counter| counter.active() > 0)
        });
        if !membership.active || membership.retired {
            return;
        }
        let mut desired = BTreeMap::<SocketAddr, (tokio::time::Instant, bool)>::new();
        for family in &mut membership.families {
            family.records.retain(|record| {
                record
                    .fresh_until
                    .checked_add(plan.refresh.stale_if_error)
                    .is_some_and(|expiry| now < expiry)
                    || now < record.fresh_until
            });
            for record in &family.records {
                let (expiry, stale) = if now < record.fresh_until {
                    (record.fresh_until, false)
                } else if family
                    .transient
                    .is_some_and(DiscoveryErrorCode::allows_stale)
                {
                    let Some(expiry) = record.fresh_until.checked_add(plan.refresh.stale_if_error)
                    else {
                        continue;
                    };
                    if now >= expiry {
                        continue;
                    }
                    (expiry, true)
                } else {
                    continue;
                };
                let Ok(target) =
                    validate_discovery_address(record.address, plan.port, &plan.address_policy)
                else {
                    continue;
                };
                desired
                    .entry(target)
                    .and_modify(|current| {
                        current.0 = current.0.max(expiry);
                        current.1 &= stale;
                    })
                    .or_insert((expiry, stale));
            }
        }
        let mut previous = membership
            .endpoints
            .iter()
            .filter_map(|endpoint| {
                endpoint
                    .dial_target()
                    .map(|target| (target, Arc::clone(endpoint)))
            })
            .collect::<BTreeMap<_, _>>();
        for (target, endpoint) in &previous {
            if endpoint.state.admission.active() > 0 {
                membership
                    .admission_counters
                    .insert(*target, Arc::downgrade(&endpoint.state.admission));
            }
        }
        let cap = usize::from(plan.limits.max_endpoints).saturating_add(
            usize::try_from(self.runtime.admission.active())
                .unwrap_or(usize::MAX)
                .max(self.spec.limits.max_in_flight as usize),
        );
        let new_counters = desired
            .keys()
            .filter(|target| {
                !membership.admission_counters.contains_key(target)
                    && !previous.contains_key(target)
            })
            .count();
        if desired.len() > usize::from(plan.limits.max_endpoints)
            || membership
                .admission_counters
                .len()
                .saturating_add(new_counters)
                > cap
        {
            desired.clear();
            membership.families = [
                FamilyState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                ),
                FamilyState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                ),
            ];
        }
        let changed = desired.len() != previous.len()
            || desired.keys().any(|target| !previous.contains_key(target));
        let mut endpoints = Vec::with_capacity(desired.len());
        for target in desired.keys() {
            if let Some(endpoint) = previous.remove(target) {
                endpoints.push(endpoint);
                continue;
            }
            let Some(incarnation) = self.runtime.claim_endpoint_incarnation() else {
                desired.clear();
                endpoints.clear();
                membership.families = [
                    FamilyState::error(
                        DiscoveryResolutionState::LimitExceeded,
                        DiscoveryErrorCode::LimitExceeded,
                    ),
                    FamilyState::error(
                        DiscoveryResolutionState::LimitExceeded,
                        DiscoveryErrorCode::LimitExceeded,
                    ),
                ];
                break;
            };
            let admission = membership
                .admission_counters
                .get(target)
                .and_then(Weak::upgrade)
                .unwrap_or_else(|| Arc::new(AdmissionCounter::default()));
            let state = Arc::new(EndpointRuntimeState::new_at_with_admission(
                Instant::now(),
                admission,
            ));
            let mut identity = ContentDigestBuilder::new("oxidase/discovery-endpoint/v1");
            identity
                .field_bytes("cluster", self.spec.id.as_str())
                .field_bytes("target", &plan.name)
                .field_bytes("address", target.to_string());
            endpoints.push(Arc::new(PreparedEndpoint {
                spec: ClusterEndpointSpec {
                    name: format!("discovered-{}", identity.finish().to_hex()),
                    url: plan.origin.clone(),
                    weight: 1,
                    source: plan.source.clone(),
                    name_source: plan.source.clone(),
                    url_source: plan
                        .spans
                        .get("origin")
                        .cloned()
                        .unwrap_or_else(|| plan.source.clone()),
                    weight_source: plan.source.clone(),
                },
                state,
                dynamic: Some(DynamicEndpointIdentity {
                    target: *target,
                    incarnation,
                    logical_target: plan.name.clone(),
                    owner: Arc::clone(&membership.owner),
                }),
            }));
        }
        if changed || endpoints.len() != membership.endpoints.len() {
            membership.endpoints = endpoints.into();
            membership.weighted_state = vec![0; membership.endpoints.len()];
            membership.generation = membership.generation.saturating_add(1);
        }
        membership.valid_until = desired
            .iter()
            .map(|(target, (expiry, _))| (*target, *expiry))
            .collect();
        membership.stale_targets = desired
            .iter()
            .filter_map(|(target, (_, stale))| stale.then_some(*target))
            .collect();
    }

    fn select_weighted(membership: &mut EndpointMembership, eligible: &[usize]) -> usize {
        let current = &mut membership.weighted_state;
        for (index, value) in current.iter_mut().enumerate() {
            if !eligible.contains(&index) {
                *value = 0;
            }
        }
        let total = eligible.iter().fold(0_i64, |total, index| {
            total + i64::from(membership.endpoints[*index].weight())
        });
        let mut selected = eligible[0];
        for index in eligible {
            current[*index] += i64::from(membership.endpoints[*index].weight());
            if current[*index] > current[selected] {
                selected = *index;
            }
        }
        current[selected] -= total;
        selected
    }

    fn eligible_indices(
        membership: &EndpointMembership,
        excluded: &BTreeSet<String>,
        now: Instant,
    ) -> Vec<usize> {
        membership
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, endpoint)| {
                endpoint.state.is_eligible(now) && !excluded.contains(endpoint.name())
            })
            .map(|(index, _)| index)
            .collect()
    }

    #[cfg(test)]
    fn try_acquire_endpoint(&self, excluded: &BTreeSet<String>, now: Instant) -> EndpointAcquire {
        let Ok((owner, _)) = self.admission_owner(None) else {
            return EndpointAcquire::Unavailable;
        };
        self.try_acquire_endpoint_owned(excluded, now, owner.as_ref())
    }

    fn try_acquire_endpoint_owned(
        &self,
        excluded: &BTreeSet<String>,
        now: Instant,
        owner: Option<&Arc<()>>,
    ) -> EndpointAcquire {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refresh_membership_locked(&mut membership, tokio::time::Instant::now());
        if self.spec.discovery.is_some()
            && (!membership.active
                || membership.retired
                || owner.is_none_or(|owner| !Arc::ptr_eq(owner, &membership.owner)))
        {
            return EndpointAcquire::Unavailable;
        }
        let eligible = Self::eligible_indices(&membership, excluded, now);
        if eligible.is_empty() {
            return EndpointAcquire::Unavailable;
        }
        match self.spec.load_balance {
            LoadBalancePolicy::RoundRobin => self.try_acquire_round_robin(&membership, &eligible),
            LoadBalancePolicy::WeightedRoundRobin => {
                self.try_acquire_weighted(&mut membership, &eligible)
            }
            LoadBalancePolicy::LeastRequests => {
                self.try_acquire_least_requests(&membership, &eligible)
            }
        }
    }

    fn try_endpoint_permit(
        &self,
        membership: &EndpointMembership,
        index: usize,
    ) -> Option<AdmissionPermit> {
        let permit = membership.endpoints[index].state.admission.try_acquire(
            u64::from(self.spec.limits.max_in_flight_per_endpoint),
            Some(Arc::clone(&self.runtime.endpoint_released)),
        )?;
        if membership.endpoints[index]
            .state
            .is_eligible(Instant::now())
        {
            Some(permit)
        } else {
            drop(permit);
            None
        }
    }

    fn acquired_endpoint(
        membership: &EndpointMembership,
        index: usize,
        permit: AdmissionPermit,
    ) -> EndpointAcquire {
        membership.endpoints[index].state.selected();
        EndpointAcquire::Acquired(
            Arc::clone(&membership.endpoints[index]),
            permit,
            membership.generation,
        )
    }

    fn try_acquire_round_robin(
        &self,
        membership: &EndpointMembership,
        eligible: &[usize],
    ) -> EndpointAcquire {
        // Reserve a unique starting slot before probing. Concurrent requests do
        // not all observe the same cursor even when endpoint capacity is > 1.
        let sequence = self.round_robin_sequence.fetch_add(1, Ordering::Relaxed);
        let start = sequence as usize % eligible.len();
        for offset in 0..eligible.len() {
            let index = eligible[(start + offset) % eligible.len()];
            if let Some(permit) = self.try_endpoint_permit(membership, index) {
                return Self::acquired_endpoint(membership, index, permit);
            }
        }
        EndpointAcquire::Saturated
    }

    fn try_acquire_weighted(
        &self,
        membership: &mut EndpointMembership,
        eligible: &[usize],
    ) -> EndpointAcquire {
        let current = &mut membership.weighted_state;
        for (index, value) in current.iter_mut().enumerate() {
            if !eligible.contains(&index) {
                *value = 0;
            }
        }
        let mut candidates = eligible.to_vec();
        candidates.sort_by(|left, right| {
            let left_score = current[*left] + i64::from(membership.endpoints[*left].weight());
            let right_score = current[*right] + i64::from(membership.endpoints[*right].weight());
            right_score.cmp(&left_score).then_with(|| left.cmp(right))
        });
        for index in candidates {
            let Some(permit) = self.try_endpoint_permit(membership, index) else {
                continue;
            };
            let total = eligible.iter().fold(0_i64, |total, endpoint| {
                total + i64::from(membership.endpoints[*endpoint].weight())
            });
            for endpoint in eligible {
                membership.weighted_state[*endpoint] +=
                    i64::from(membership.endpoints[*endpoint].weight());
            }
            membership.weighted_state[index] -= total;
            return Self::acquired_endpoint(membership, index, permit);
        }
        EndpointAcquire::Saturated
    }

    fn try_acquire_least_requests(
        &self,
        membership: &EndpointMembership,
        eligible: &[usize],
    ) -> EndpointAcquire {
        let mut candidates = eligible.to_vec();
        candidates.sort_by(|left, right| {
            let left_active = membership.endpoints[*left]
                .active_requests()
                .saturating_add(1);
            let right_active = membership.endpoints[*right]
                .active_requests()
                .saturating_add(1);
            let left_score =
                u128::from(left_active) * u128::from(membership.endpoints[*right].weight());
            let right_score =
                u128::from(right_active) * u128::from(membership.endpoints[*left].weight());
            left_score.cmp(&right_score).then_with(|| left.cmp(right))
        });
        for index in candidates {
            if let Some(permit) = self.try_endpoint_permit(membership, index) {
                return Self::acquired_endpoint(membership, index, permit);
            }
        }
        EndpointAcquire::Saturated
    }

    fn select_least_requests(membership: &EndpointMembership, eligible: &[usize]) -> usize {
        let mut selected = eligible[0];
        for index in eligible.iter().copied().skip(1) {
            let candidate = membership.endpoints[index]
                .active_requests()
                .saturating_add(1);
            let incumbent = membership.endpoints[selected]
                .active_requests()
                .saturating_add(1);
            let candidate_score =
                u128::from(candidate) * u128::from(membership.endpoints[selected].weight());
            let incumbent_score =
                u128::from(incumbent) * u128::from(membership.endpoints[index].weight());
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

const fn family_index(family: DnsFamily) -> usize {
    match family {
        DnsFamily::A => 0,
        DnsFamily::Aaaa => 1,
    }
}

fn same_admission_owner(left: Option<&Arc<()>>, right: Option<&Arc<()>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        _ => false,
    }
}

impl FamilyState {
    fn empty(outcome: DiscoveryResolutionState) -> Self {
        Self {
            outcome: Some(outcome),
            ..Self::default()
        }
    }

    fn error(outcome: DiscoveryResolutionState, code: DiscoveryErrorCode) -> Self {
        Self {
            records: Vec::new(),
            outcome: Some(outcome),
            transient: Some(code),
        }
    }
}

impl EndpointMembership {
    fn error_code(&self) -> Option<DiscoveryErrorCode> {
        self.families.iter().find_map(|family| family.transient)
    }

    fn resolution(&self) -> DiscoveryResolutionState {
        if self.retired {
            return DiscoveryResolutionState::Retired;
        }
        if !self.endpoints.is_empty() {
            if !self.stale_targets.is_empty() {
                return DiscoveryResolutionState::Stale;
            }
            return if self
                .families
                .iter()
                .all(|family| family.outcome == Some(DiscoveryResolutionState::Fresh))
            {
                DiscoveryResolutionState::Fresh
            } else {
                DiscoveryResolutionState::Partial
            };
        }
        for state in [
            DiscoveryResolutionState::NameNotFound,
            DiscoveryResolutionState::PolicyRejected,
            DiscoveryResolutionState::LimitExceeded,
            DiscoveryResolutionState::InvalidAnswer,
            DiscoveryResolutionState::TransientFailure,
            DiscoveryResolutionState::NoData,
        ] {
            if self
                .families
                .iter()
                .any(|family| family.outcome == Some(state))
            {
                return state;
            }
        }
        if self.families.iter().any(|family| family.outcome.is_some()) {
            DiscoveryResolutionState::Expired
        } else {
            DiscoveryResolutionState::Unresolved
        }
    }
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
    Acquired(Arc<PreparedEndpoint>, AdmissionPermit, u64),
    Unavailable,
    Saturated,
}

/// Opaque RAII admission for one replacement endpoint. It holds no additional
/// Cluster permit and never changes an existing request until explicitly
/// consumed through [`ClusterRequestPermit::retarget_reserved`].
pub struct ClusterEndpointReservation {
    endpoint: Arc<PreparedEndpoint>,
    endpoint_permit: AdmissionPermit,
    cluster_counter: Arc<AdmissionCounter>,
    generation: u64,
    owner: Option<Arc<()>>,
}

impl ClusterEndpointReservation {
    #[must_use]
    pub fn endpoint(&self) -> &Arc<PreparedEndpoint> {
        &self.endpoint
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl fmt::Debug for ClusterEndpointReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterEndpointReservation")
            .field("endpoint", &self.endpoint.name())
            .finish_non_exhaustive()
    }
}

/// RAII request admission. It must live through the complete upstream body
/// lifecycle so success, failure, cancellation, and timeout all release counts.
pub struct ClusterRequestPermit {
    endpoint: Arc<PreparedEndpoint>,
    _cluster: AdmissionPermit,
    _endpoint: AdmissionPermit,
    generation: u64,
    owner: Option<Arc<()>>,
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

    /// Member generation fixed at this attempt's admission linearization point.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn dial_target(&self) -> Option<SocketAddr> {
        self.endpoint.dial_target()
    }

    /// Commits an already admitted replacement while preserving the single
    /// Cluster permit. Call only after the old upload/attempt no longer uses
    /// its endpoint. A reservation from another runtime admission owner is
    /// rejected and released without touching this request.
    pub fn retarget_reserved(&mut self, reservation: ClusterEndpointReservation) -> bool {
        if !Arc::ptr_eq(&self._cluster.counter, &reservation.cluster_counter)
            || !same_admission_owner(self.owner.as_ref(), reservation.owner.as_ref())
        {
            return false;
        }
        let old_endpoint = std::mem::replace(&mut self._endpoint, reservation.endpoint_permit);
        self.endpoint = reservation.endpoint;
        self.generation = reservation.generation;
        drop(old_endpoint);
        true
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<DiscoveryRuntimeStatus>,
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
    endpoint_incarnations: AtomicU64,
    admission: Arc<AdmissionCounter>,
    retries: Arc<AdmissionCounter>,
    endpoint_released: Arc<Notify>,
    retry_attempts: AtomicU64,
    retry_exhausted: AtomicU64,
    overload_rejections: AtomicU64,
    unavailable_rejections: AtomicU64,
}

impl ClusterRuntimeState {
    /// Checked CAS is supported by Rust 1.88 as well as current stable. The
    /// newer `try_update` spelling is unavailable on our MSRV, while its older
    /// `fetch_update` spelling is now deprecated on Hosted stable. Never wrap
    /// this serial: old pool/callback incarnations must remain distinguishable.
    fn claim_endpoint_incarnation(&self) -> Option<u64> {
        let mut previous = self.endpoint_incarnations.load(Ordering::Acquire);
        loop {
            let next = previous.checked_add(1)?;
            match self.endpoint_incarnations.compare_exchange_weak(
                previous,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(next),
                Err(actual) => previous = actual,
            }
        }
    }
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

    pub(super) fn cluster(
        policy: LoadBalancePolicy,
        endpoints: Vec<ClusterEndpointSpec>,
    ) -> ClusterSpec {
        ClusterSpec {
            discovery: None,
            id: ResourceId::new("cluster:test"),
            protocol: ClusterProtocol::Auto,
            tls: None,
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
            timeouts: None,
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
                .membership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .weighted_state
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
        let endpoint_b = &cluster.endpoints()[1];
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
            cluster.endpoints()[0].health_state(now),
            EndpointHealthState::UnknownEligible
        );
        cluster.record_active_health("a", false, now);
        assert_eq!(
            cluster.endpoints()[0].health_state(now),
            EndpointHealthState::Unhealthy
        );
        assert!(cluster.select_endpoint(now).is_none());
        cluster.record_active_health("a", true, now);
        assert_eq!(
            cluster.endpoints()[0].health_state(now),
            EndpointHealthState::Unhealthy
        );
        cluster.record_active_health("a", true, now);
        assert_eq!(
            cluster.endpoints()[0].health_state(now),
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
            cluster.endpoints()[0].health_state(now),
            EndpointHealthState::PassivelyEjected
        );
        assert_eq!(
            cluster.endpoints()[0].health_state(now + Duration::from_secs(11)),
            EndpointHealthState::UnknownEligible
        );

        let later = now + Duration::from_secs(12);
        cluster.record_passive_failure("a", later);
        cluster.record_passive_failure("a", later);
        cluster.record_active_health("a", true, later);
        cluster.record_active_health("a", true, later);
        assert_eq!(
            cluster.endpoints()[0].health_state(later),
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 0);
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
        let saturated = cluster.endpoints()[0]
            .state
            .admission
            .try_acquire(1, None)
            .expect("fixture saturates the preferred endpoint");

        let admitted = cluster
            .acquire()
            .await
            .expect("capacity on the other endpoint is used");
        assert_eq!(admitted.endpoint().name(), "b");
        assert_eq!(cluster.endpoints()[0].state.selections(), 0);
        assert_eq!(cluster.endpoints()[1].state.selections(), 1);
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 0);
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
        drop(current);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints()[1].active_requests(), 0);
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
        let saturated = cluster.endpoints()[1]
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
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
        let saturated = cluster.endpoints()[1]
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        drop(saturated);
        drop(current);
    }

    fn retry_reservation_cluster(queue_timeout: Duration) -> PreparedCluster {
        let mut spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![
                endpoint("a", "http://a.test", 1),
                endpoint("b", "http://b.test", 1),
            ],
        );
        spec.limits.max_in_flight = 1;
        spec.limits.max_in_flight_per_endpoint = 1;
        spec.limits.queue_timeout = queue_timeout;
        PreparedCluster::prepare(spec, None).0
    }

    #[tokio::test]
    async fn retry_reservation_precedes_cancellation_and_reuses_one_cluster_permit() {
        let cluster = retry_reservation_cluster(Duration::ZERO);
        let mut current = cluster.acquire().await.expect("current admitted");
        let reservation = cluster
            .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
            .await
            .expect("other endpoint reserved despite cluster limit1");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(
            current.endpoint().name(),
            "a",
            "reservation cannot mutate the original attempt"
        );
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
        assert!(current.retarget_reserved(reservation));
        assert_eq!(current.endpoint().name(), "b");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 0);
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
        drop(current);
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(cluster.endpoints()[1].active_requests(), 0);
    }

    #[tokio::test]
    async fn unavailable_or_saturated_reservation_leaves_the_current_attempt_untouched() {
        let cluster = retry_reservation_cluster(Duration::ZERO);
        let current = cluster.acquire().await.expect("current admitted");
        let saturated = cluster.endpoints()[1]
            .state
            .admission
            .try_acquire(1, None)
            .expect("saturate replacement");
        assert!(
            cluster
                .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
                .await
                .is_none()
        );
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        drop(saturated);
        assert!(
            cluster
                .reserve_retry_endpoint(
                    &BTreeSet::from(["b".to_owned()]),
                    current.endpoint().name()
                )
                .await
                .is_none()
        );
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.endpoints()[1].active_requests(), 0);
        drop(current);
    }

    #[tokio::test]
    async fn dropping_retry_reservation_releases_only_replacement_endpoint() {
        let cluster = retry_reservation_cluster(Duration::ZERO);
        let current = cluster.acquire().await.expect("current admitted");
        let reservation = cluster
            .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
            .await
            .expect("replacement");
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
        drop(reservation);
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(cluster.endpoints()[1].active_requests(), 0);
        assert!(
            cluster
                .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
                .await
                .is_some()
        );
        assert_eq!(
            cluster.endpoints()[1].active_requests(),
            0,
            "temporary successful reservation also releases on drop"
        );
        drop(current);
    }

    #[tokio::test]
    async fn reservation_from_foreign_cluster_is_rejected_and_released() {
        let cluster = retry_reservation_cluster(Duration::ZERO);
        let foreign = retry_reservation_cluster(Duration::ZERO);
        let mut current = cluster.acquire().await.expect("current admitted");
        let reservation = foreign
            .reserve_retry_endpoint(&BTreeSet::new(), "a")
            .await
            .expect("foreign reservation");
        assert_eq!(foreign.endpoints()[1].active_requests(), 1);
        assert!(!current.retarget_reserved(reservation));
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(foreign.active_requests(), 0);
        assert_eq!(foreign.endpoints()[1].active_requests(), 0);
        drop(current);
    }

    #[tokio::test]
    async fn cancelled_retry_reservation_wait_keeps_original_permit_owned() {
        let cluster = retry_reservation_cluster(Duration::from_secs(10));
        let current = cluster.acquire().await.expect("current admitted");
        let saturated = cluster.endpoints()[1]
            .state
            .admission
            .try_acquire(1, None)
            .expect("saturate replacement");
        let cancelled = tokio::time::timeout(
            Duration::from_millis(10),
            cluster.reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name()),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(cluster.endpoints()[1].active_requests(), 1);
        drop(saturated);
        assert!(
            cluster
                .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
                .await
                .is_some(),
            "cancelled queue wait does not consume replacement capacity"
        );
        drop(current);
        assert_eq!(cluster.active_requests(), 0);
        assert!(
            cluster
                .endpoints()
                .iter()
                .all(|endpoint| endpoint.active_requests() == 0)
        );
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 0);
    }

    #[tokio::test]
    async fn unrepresentable_legacy_queue_deadline_fails_closed_without_touching_current_admission()
    {
        let cluster = retry_reservation_cluster(Duration::ZERO);
        let mut current = cluster.acquire().await.expect("original admission");
        let mut spec = cluster.spec().clone();
        spec.limits.queue_timeout = Duration::MAX;
        let excessive = PreparedCluster::prepare(spec, Some(&cluster)).0;
        assert!(matches!(
            excessive.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        assert!(
            !excessive
                .retarget_excluding(&mut current, &BTreeSet::new())
                .await
        );
        assert!(
            excessive
                .reserve_retry_endpoint(&BTreeSet::new(), current.endpoint().name())
                .await
                .is_none()
        );
        assert_eq!(current.endpoint().name(), "a");
        assert_eq!(cluster.active_requests(), 1);
        assert_eq!(cluster.endpoints()[0].active_requests(), 1);
        assert_eq!(cluster.endpoints()[1].active_requests(), 0);
        drop(current);
        assert_eq!(cluster.active_requests(), 0);
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
        assert_eq!(cluster.endpoints()[0].active_requests(), 0);
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
            first.endpoints()[0].runtime_state(),
            second.endpoints()[0].runtime_state()
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
            second.endpoints()[0].runtime_state(),
            third.endpoints()[0].runtime_state()
        ));
        assert!(Arc::ptr_eq(
            second.endpoints()[1].runtime_state(),
            third.endpoints()[1].runtime_state()
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
            third.endpoints()[1].runtime_state(),
            fourth.endpoints()[1].runtime_state()
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
            first.endpoints()[0].runtime_state(),
            second.endpoints()[0].runtime_state()
        ));
        assert!(Arc::ptr_eq(
            &first.endpoints()[0].runtime_state().admission,
            &second.endpoints()[0].runtime_state().admission
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

#[cfg(test)]
mod discovery_membership_tests {
    use super::*;
    use oxidase_config::{
        DnsAddressPolicy, DnsDiscoveryLimits, DnsDiscoverySpec, DnsRecordType, DnsRefreshSpec,
        DnsResolverSource, DnsResolverSpec,
    };
    use oxidase_core::SourceSpan;

    #[test]
    fn endpoint_incarnation_cas_is_unique_under_race_and_fails_closed_at_exhaustion() {
        let runtime = Arc::new(ClusterRuntimeState::default());
        let started = Arc::new(std::sync::Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let runtime = Arc::clone(&runtime);
                let started = Arc::clone(&started);
                std::thread::spawn(move || {
                    started.wait();
                    (0..256)
                        .map(|_| {
                            runtime
                                .claim_endpoint_incarnation()
                                .expect("bounded serial")
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let all = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker succeeds"))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            all,
            (1..=2048).collect(),
            "no incarnation can be reused across concurrent owners"
        );
        runtime
            .endpoint_incarnations
            .store(u64::MAX - 1, Ordering::Release);
        assert_eq!(runtime.claim_endpoint_incarnation(), Some(u64::MAX));
        assert_eq!(runtime.claim_endpoint_incarnation(), None);
        assert_eq!(runtime.claim_endpoint_incarnation(), None);
        assert_eq!(
            runtime.endpoint_incarnations.load(Ordering::Acquire),
            u64::MAX,
            "overflow cannot resurrect old pool identities"
        );
    }

    fn dynamic_spec() -> ClusterSpec {
        let mut spec = super::tests::cluster(LoadBalancePolicy::RoundRobin, Vec::new());
        spec.discovery = Some(DnsDiscoverySpec {
            name: "service.example.test.".to_owned(),
            record: DnsRecordType::AAndAaaa,
            port: 8080,
            origin: "http://service.example.test/base"
                .parse()
                .expect("logical origin"),
            resolver: DnsResolverSpec {
                source: DnsResolverSource::System,
                query_timeout: Duration::from_secs(2),
            },
            refresh: DnsRefreshSpec {
                min_interval: Duration::from_secs(1),
                max_interval: Duration::from_secs(60),
                jitter_percent: 10,
                stale_if_error: Duration::from_secs(10),
            },
            limits: DnsDiscoveryLimits {
                max_endpoints: 8,
                max_targets: 8,
            },
            address_policy: DnsAddressPolicy::default(),
            source: SourceSpan::synthetic("discovery.dns"),
            spans: BTreeMap::new(),
        });
        spec
    }

    fn dynamic() -> PreparedCluster {
        let cluster = PreparedCluster::prepare(dynamic_spec(), None).0;
        assert!(cluster.activate_discovery_policy());
        cluster
    }

    fn positive(addresses: &[&str], ttl: Duration) -> DnsObservation {
        let fresh_until = tokio::time::Instant::now() + ttl;
        DnsObservation::Positive {
            addresses: addresses
                .iter()
                .map(|address| DnsAddressRecord {
                    address: address.parse().expect("fixture IP"),
                    fresh_until,
                })
                .collect(),
        }
    }

    fn observe(
        cluster: &PreparedCluster,
        family: DnsFamily,
        observation: DnsObservation,
    ) -> DiscoveryReconcileOutcome {
        let query = cluster.begin_discovery_query().expect("single query slot");
        cluster.reconcile_dns(&query, family, observation, tokio::time::Instant::now())
    }

    #[tokio::test]
    async fn prepare_is_inactive_and_one_query_round_is_raii_owned() {
        let cluster = PreparedCluster::prepare(dynamic_spec(), None).0;
        assert!(cluster.begin_discovery_query().is_none());
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert_eq!(cluster.active_requests(), 0);
        assert!(cluster.activate_discovery_policy());
        assert!(!cluster.activate_discovery_policy());
        let query = cluster
            .begin_discovery_query()
            .expect("committed owner query");
        assert!(cluster.begin_discovery_query().is_none());
        assert!(cluster.discovery_status().expect("status").in_flight_query);
        drop(query);
        assert!(!cluster.discovery_status().expect("status").in_flight_query);
        assert!(cluster.begin_discovery_query().is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn lease_fixes_address_origin_and_generation_and_expiry_cannot_wait_for_supervisor() {
        let cluster = dynamic();
        let observed = observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(2)),
        );
        let lease = cluster.acquire().await.expect("fresh endpoint");
        assert_eq!(
            lease.dial_target(),
            Some("198.51.100.1:8080".parse().expect("target"))
        );
        assert_eq!(
            lease.endpoint().url().as_str(),
            "http://service.example.test/base"
        );
        assert_eq!(lease.generation(), observed.generation);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert!(cluster.endpoints().is_empty());
        assert_eq!(
            lease.dial_target(),
            Some("198.51.100.1:8080".parse().expect("fixed lease"))
        );
        assert_eq!(cluster.active_requests(), 1);
        drop(lease);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn record_reorder_duplicates_and_ttl_refresh_reuse_generation_state_and_incarnation() {
        let cluster = dynamic();
        let first = observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.2", "198.51.100.1"], Duration::from_secs(5)),
        );
        let endpoints = cluster.endpoints();
        cluster.record_passive_success_for(&endpoints[0]);
        tokio::time::advance(Duration::from_secs(1)).await;
        let refreshed = observe(
            &cluster,
            DnsFamily::A,
            positive(
                &["198.51.100.1", "198.51.100.1", "198.51.100.2"],
                Duration::from_secs(10),
            ),
        );
        let current = cluster.endpoints();
        assert_eq!(first.generation, refreshed.generation);
        assert!(!refreshed.changed);
        assert!(Arc::ptr_eq(&endpoints, &current));
        assert!(Arc::ptr_eq(
            endpoints[0].runtime_state(),
            current[0].runtime_state()
        ));
        assert_eq!(endpoints[0].incarnation(), current[0].incarnation());
        assert_eq!(
            current[0].runtime_state().status(Instant::now()).successes,
            1
        );
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(
            cluster.endpoints().len(),
            2,
            "old expiry does not invalidate a refreshed record"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn family_nodata_is_independent_and_nxdomain_fences_the_whole_round() {
        let cluster = dynamic();
        let query = cluster.begin_discovery_query().expect("query");
        cluster.reconcile_dns(
            &query,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
            tokio::time::Instant::now(),
        );
        cluster.reconcile_dns(
            &query,
            DnsFamily::Aaaa,
            positive(&["2001:db8::1"], Duration::from_secs(30)),
            tokio::time::Instant::now(),
        );
        drop(query);
        assert_eq!(cluster.endpoints().len(), 2);
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        assert_eq!(cluster.endpoints().len(), 1);
        assert!(
            cluster.endpoints()[0]
                .dial_target()
                .expect("AAAA target")
                .is_ipv6()
        );
        let query = cluster.begin_discovery_query().expect("next query");
        cluster.reconcile_dns(
            &query,
            DnsFamily::A,
            DnsObservation::NameNotFound,
            tokio::time::Instant::now(),
        );
        let late = cluster.reconcile_dns(
            &query,
            DnsFamily::Aaaa,
            positive(&["2001:db8::2"], Duration::from_secs(30)),
            tokio::time::Instant::now(),
        );
        assert!(!late.applied);
        assert!(cluster.endpoints().is_empty());
        assert_eq!(
            cluster.discovery_status().expect("status").resolution,
            DiscoveryResolutionState::NameNotFound
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stale_deadline_is_fixed_and_zero_ttl_cannot_seed_stale_reuse() {
        let cluster = dynamic();
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(2)),
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(cluster.endpoints().is_empty());
        for code in [
            DiscoveryErrorCode::Timeout,
            DiscoveryErrorCode::Refused,
            DiscoveryErrorCode::Refused,
            DiscoveryErrorCode::ServerFailure,
            DiscoveryErrorCode::Refused,
        ] {
            observe(
                &cluster,
                DnsFamily::A,
                DnsObservation::TransientFailure { code },
            );
            assert_eq!(cluster.endpoints().len(), 1);
            tokio::time::advance(Duration::from_secs(2)).await;
        }
        assert!(
            cluster.endpoints().is_empty(),
            "repeated failures never renew expiry+grace"
        );
        observe(
            &cluster,
            DnsFamily::A,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            },
        );
        assert!(cluster.endpoints().is_empty());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.2"], Duration::ZERO),
        );
        observe(
            &cluster,
            DnsFamily::A,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Network,
            },
        );
        assert!(
            cluster.endpoints().is_empty(),
            "TTL0 never supplies future fresh/stale leases"
        );
    }

    #[tokio::test]
    async fn policy_filters_each_address_and_bad_answers_do_not_enable_stale() {
        let cluster = dynamic();
        observe(
            &cluster,
            DnsFamily::A,
            positive(
                &["127.0.0.1", "198.51.100.1", "169.254.0.1"],
                Duration::from_secs(30),
            ),
        );
        assert_eq!(cluster.endpoints().len(), 1);
        assert_eq!(
            cluster.acquire().await.expect("safe address").dial_target(),
            Some("198.51.100.1:8080".parse().expect("target"))
        );
        observe(&cluster, DnsFamily::A, DnsObservation::InvalidAnswer);
        assert!(cluster.endpoints().is_empty());
        observe(
            &cluster,
            DnsFamily::A,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout,
            },
        );
        assert!(cluster.endpoints().is_empty());
        observe(
            &cluster,
            DnsFamily::Aaaa,
            positive(&["::ffff:127.0.0.1"], Duration::from_secs(30)),
        );
        assert_eq!(
            cluster.discovery_status().expect("status").error_code,
            Some(DiscoveryErrorCode::Timeout)
        );
        assert!(cluster.endpoints().is_empty());
    }

    #[tokio::test]
    async fn remove_readd_has_fresh_incarnation_and_health_but_reuses_nonzero_physical_admission() {
        let mut spec = dynamic_spec();
        spec.limits.max_in_flight = 2;
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let lease = cluster.acquire().await.expect("old lease");
        let old = Arc::clone(lease.endpoint());
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let new = Arc::clone(&cluster.endpoints()[0]);
        assert!(new.incarnation() > old.incarnation());
        assert!(!Arc::ptr_eq(old.runtime_state(), new.runtime_state()));
        assert!(Arc::ptr_eq(&old.state.admission, &new.state.admission));
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        for _ in 0..3 {
            cluster.record_active_health_for(&old, false, Instant::now());
            cluster.record_passive_failure_for(&old, Instant::now());
        }
        cluster.record_passive_failure(new.name(), Instant::now());
        assert_eq!(
            new.health_state(Instant::now()),
            EndpointHealthState::UnknownEligible
        );
        assert_eq!(
            new.state.status(Instant::now()).failures,
            0,
            "name callbacks are static-only"
        );
        drop(lease);
        assert!(cluster.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn retirement_and_resume_fence_old_queries_watchers_and_new_attempts() {
        let cluster = dynamic();
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let old_lease = cluster.acquire().await.expect("issued lease");
        let old_query = cluster.begin_discovery_query().expect("old query");
        let old_retirement = cluster.discovery_retirement();
        cluster.retire_discovery_policy();
        assert!(*old_retirement.borrow());
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert_eq!(
            cluster.active_requests(),
            1,
            "issued attempt survives retirement"
        );
        assert!(cluster.activate_discovery_policy());
        assert!(!*cluster.discovery_retirement().borrow());
        assert!(
            *old_retirement.borrow(),
            "old watch cannot resume with new session"
        );
        assert!(
            !cluster
                .reconcile_dns(
                    &old_query,
                    DnsFamily::A,
                    positive(&["198.51.100.2"], Duration::from_secs(30)),
                    tokio::time::Instant::now()
                )
                .applied
        );
        assert!(cluster.endpoints().is_empty());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        assert!(cluster.endpoints()[0].incarnation() > old_lease.endpoint().incarnation());
        drop(old_query);
        drop(old_lease);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test]
    async fn queued_admission_rechecks_membership_after_removal_and_wakes_on_replacement() {
        let mut spec = dynamic_spec();
        spec.limits.max_in_flight = 2;
        spec.limits.max_in_flight_per_endpoint = 1;
        spec.limits.queue_timeout = Duration::from_secs(5);
        let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let old = cluster.acquire().await.expect("saturated A");
        let waiter_cluster = Arc::clone(&cluster);
        let waiter = tokio::spawn(async move { waiter_cluster.acquire().await });
        while cluster.active_requests() < 2 {
            tokio::task::yield_now().await;
        }
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.2"], Duration::from_secs(30)),
        );
        let new = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("membership change wakes waiter")
            .expect("waiter task")
            .expect("B admission");
        assert_eq!(
            new.dial_target(),
            Some("198.51.100.2:8080".parse().expect("B"))
        );
        assert_eq!(
            old.dial_target(),
            Some("198.51.100.1:8080".parse().expect("A still fixed"))
        );
        drop(new);
        drop(old);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test]
    async fn retained_endpoint_snapshot_cannot_mint_a_lease_after_removal_linearization() {
        let cluster = Arc::new(dynamic());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let ready = Arc::new(std::sync::Barrier::new(2));
        let removed = Arc::new(std::sync::Barrier::new(2));
        std::thread::scope(|scope| {
            let cluster_ref = &cluster;
            let ready_ref = &ready;
            let removed_ref = &removed;
            let requester = scope.spawn(move || {
                let old_view = cluster_ref.endpoints();
                ready_ref.wait();
                removed_ref.wait();
                assert_eq!(old_view.len(), 1, "old inspection view remains immutable");
                assert!(matches!(
                    cluster_ref.try_acquire_endpoint(&BTreeSet::new(), Instant::now()),
                    EndpointAcquire::Unavailable
                ));
            });
            ready.wait();
            observe(&cluster, DnsFamily::A, DnsObservation::NoData);
            removed.wait();
            requester.join().expect("barrier requester");
        });
    }

    #[tokio::test]
    async fn physical_counter_tombstones_are_bounded_and_churn_cannot_revive_old_health() {
        let mut spec = dynamic_spec();
        spec.discovery.as_mut().expect("DNS").limits.max_endpoints = 1;
        spec.limits.max_in_flight = 2;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        let first = cluster.acquire().await.expect("first active");
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.2"], Duration::from_secs(30)),
        );
        let second = cluster.acquire().await.expect("second active");
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.3"], Duration::from_secs(30)),
        );
        let reservation = cluster
            .reserve_retry_endpoint_for(&BTreeSet::new(), first.endpoint())
            .await
            .expect("replacement reservation without another Cluster slot");
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.4"], Duration::from_secs(30)),
        );
        let status = cluster.discovery_status().expect("bounded status");
        assert_eq!(status.error_code, Some(DiscoveryErrorCode::LimitExceeded));
        assert!(cluster.endpoints().is_empty());
        assert!(status.retired_admission_counters <= 3);
        drop(reservation);
        drop(first);
        drop(second);
        assert_eq!(
            cluster
                .discovery_status()
                .expect("released status")
                .retired_admission_counters,
            0
        );
        for index in 0..1000 {
            let address = format!("198.51.{}.{}", (index / 250) + 1, index % 250 + 1);
            observe(
                &cluster,
                DnsFamily::A,
                positive(&[&address], Duration::from_secs(30)),
            );
            let lease = cluster.acquire().await.expect("bounded churn lease");
            drop(lease);
        }
        assert_eq!(cluster.active_requests(), 0);
        assert_eq!(
            cluster
                .discovery_status()
                .expect("final bounded status")
                .retired_admission_counters,
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_other_family_does_not_consume_membership_quota_or_discard_fresh_peer() {
        let mut spec = dynamic_spec();
        spec.discovery.as_mut().expect("DNS").limits.max_endpoints = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::Aaaa,
            positive(&["2001:db8::1"], Duration::from_secs(1)),
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        let receipt = observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(30)),
        );
        assert_eq!(
            receipt.observation_error_code, None,
            "expired retained AAAA is not eligible membership"
        );
        assert_eq!(
            cluster
                .acquire()
                .await
                .expect("fresh A remains available")
                .dial_target(),
            Some("198.51.100.1:8080".parse().expect("A"))
        );
        let failed_stale = observe(
            &cluster,
            DnsFamily::Aaaa,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout,
            },
        );
        assert_eq!(
            failed_stale.observation_error_code,
            Some(DiscoveryErrorCode::LimitExceeded)
        );
        assert_eq!(
            cluster.endpoints().len(),
            1,
            "stale overflow cannot evict the fresh other family"
        );
        assert!(cluster.endpoints()[0].dial_target().expect("A").is_ipv4());
    }

    #[tokio::test(start_paused = true)]
    async fn ttl0_duplicate_cannot_borrow_a_longer_duplicate_lifetime() {
        let cluster = dynamic();
        let now = tokio::time::Instant::now();
        let address = "198.51.100.1".parse().expect("IP");
        observe(
            &cluster,
            DnsFamily::A,
            DnsObservation::Positive {
                addresses: vec![
                    DnsAddressRecord {
                        address,
                        fresh_until: now,
                    },
                    DnsAddressRecord {
                        address,
                        fresh_until: now + Duration::from_secs(60),
                    },
                ],
            },
        );
        assert!(cluster.endpoints().is_empty());
        observe(
            &cluster,
            DnsFamily::A,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout,
            },
        );
        assert!(cluster.endpoints().is_empty());
    }

    #[tokio::test]
    async fn received_family_error_does_not_inherit_another_family_failure() {
        let cluster = dynamic();
        observe(
            &cluster,
            DnsFamily::Aaaa,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Network,
            },
        );
        let receipt = observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        assert_eq!(receipt.observation_error_code, None);
        assert_eq!(receipt.error_code, Some(DiscoveryErrorCode::Network));
        assert_eq!(receipt.endpoint_count, 1);
    }

    #[tokio::test]
    async fn retirement_cancels_cluster_queue_and_old_retry_cannot_join_resumed_session() {
        let mut spec = dynamic_spec();
        spec.limits.max_in_flight = 1;
        spec.limits.queue_timeout = Duration::from_secs(30);
        let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let mut old = cluster.acquire().await.expect("old session");
        let old_endpoint = Arc::clone(old.endpoint());
        let waiter_cluster = Arc::clone(&cluster);
        let (started, received) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            started.send(()).expect("waiter observer");
            waiter_cluster.acquire().await
        });
        received.await.expect("waiter started");
        cluster.retire_discovery_policy();
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.2"], Duration::from_secs(60)),
        );
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("retirement does not wait 30s queue timeout")
            .expect("waiter task");
        assert!(matches!(result, Err(ClusterAdmissionError::Unavailable)));
        assert!(matches!(
            cluster
                .acquire_excluding_for(&BTreeSet::new(), &old_endpoint)
                .await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert!(
            cluster
                .reserve_retry_endpoint_for(&BTreeSet::new(), &old_endpoint)
                .await
                .is_none()
        );
        assert!(!cluster.retarget_excluding(&mut old, &BTreeSet::new()).await);
        assert_eq!(
            old.dial_target(),
            Some("198.51.100.1:8080".parse().expect("old fixed"))
        );
        drop(old);
        assert_eq!(
            cluster
                .acquire()
                .await
                .expect("new session admitted")
                .dial_target(),
            Some("198.51.100.2:8080".parse().expect("new fixed"))
        );
        assert_eq!(cluster.active_requests(), 0);
    }
}
