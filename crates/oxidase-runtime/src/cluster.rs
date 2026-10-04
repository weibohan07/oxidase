//! Prepared upstream Cluster plans and their reload-stable runtime state.
//!
//! This module deliberately owns no connection pool and starts no background
//! tasks. Preparation is therefore side-effect free: the server may activate a
//! health supervisor only after the containing snapshot has committed.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oxidase_config::{
    ActiveHealthSpec, ClusterEndpointSpec, ClusterHealthSpec, ClusterProtocol, ClusterSpec,
    DnsDiscoverySpec, DnsRecordType, LoadBalancePolicy, PassiveHealthSpec,
};
use oxidase_core::{ContentDigestBuilder, ResourceId};
use serde::Serialize;
use tokio::sync::{Notify, watch};

use crate::PreparedUpstreamTls;
use crate::discovery::{
    DiscoveryErrorCode, DiscoveryReconcileOutcome, DiscoveryResolutionState,
    DiscoveryRuntimeStatus, DnsAddressRecord, DnsFamily, DnsObservation, SrvObservation, SrvRecord,
    SrvSelectionRng, SrvTargetAddressObservation, SrvTargetRuntimeStatus,
    normalize_discovery_address, validate_discovery_address,
};
use crate::resource_census::{ResourceCensus, ResourceKind, ResourceState, ResourceToken};

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
        Self::new_at_with_admission(
            now,
            Arc::new(AdmissionCounter::endpoint(ResourceCensus::process())),
        )
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
        self.status_with_health(now, health)
    }

    fn observed_health_state(&self, now: Instant) -> EndpointHealthState {
        let health = EndpointHealthState::decode(self.health.load(Ordering::Acquire));
        let deadline = self.ejection_deadline_tick.load(Ordering::Acquire);
        if health == EndpointHealthState::PassivelyEjected
            && deadline != 0
            && self.tick(now) >= deadline
        {
            EndpointHealthState::UnknownEligible
        } else {
            health
        }
    }

    fn observed_status(&self, now: Instant) -> EndpointRuntimeStatus {
        self.status_with_health(now, self.observed_health_state(now))
    }

    fn status_with_health(
        &self,
        now: Instant,
        health: EndpointHealthState,
    ) -> EndpointRuntimeStatus {
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
    lifecycle: ResourceToken,
}

#[derive(Debug)]
struct DynamicEndpointIdentity {
    target: SocketAddr,
    incarnation: u64,
    logical_target: String,
    owner: Arc<()>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DynamicEndpointKey {
    logical_target: String,
    target: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SrvGroupKey {
    target: String,
    port: u16,
    priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SrvGroup {
    key: SrvGroupKey,
    weight: u16,
    members: Vec<DynamicEndpointKey>,
}

type DesiredEndpoints = BTreeMap<DynamicEndpointKey, (tokio::time::Instant, bool)>;

#[derive(Default)]
struct SrvState {
    records: Vec<SrvRecord>,
    addresses: BTreeMap<String, [FamilyState; 2]>,
    outcome: Option<DiscoveryResolutionState>,
    transient: Option<DiscoveryErrorCode>,
}

impl PreparedEndpoint {
    fn dynamic_key(&self) -> Option<DynamicEndpointKey> {
        self.dynamic.as_ref().map(|identity| DynamicEndpointKey {
            logical_target: identity.logical_target.clone(),
            target: identity.target,
        })
    }
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
    lifecycle: ResourceToken,
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
    valid_until: BTreeMap<DynamicEndpointKey, tokio::time::Instant>,
    stale_targets: BTreeSet<DynamicEndpointKey>,
    admission_counters: BTreeMap<SocketAddr, AdmissionTombstone>,
    last_success_unix_ms: Option<u64>,
    next_refresh: Option<tokio::time::Instant>,
    srv: SrvState,
    srv_groups: Vec<SrvGroup>,
    srv_cursors: BTreeMap<SrvGroupKey, u64>,
    srv_random: SrvSelectionRng,
    inherited_counter_count: usize,
}

/// Business reuse may upgrade the actual counter; observation may only borrow
/// its existing admission atomic. Holding that scalar cannot keep the counter,
/// its lifecycle token, notifier, endpoint, or Cluster alive.
#[derive(Clone)]
struct AdmissionTombstone {
    counter: Weak<AdmissionCounter>,
    active: Weak<AtomicU64>,
}

impl AdmissionTombstone {
    fn new(counter: &Arc<AdmissionCounter>) -> Self {
        Self {
            counter: Arc::downgrade(counter),
            active: Arc::downgrade(&counter.active),
        }
    }

    fn upgrade(&self) -> Option<Arc<AdmissionCounter>> {
        self.counter.upgrade()
    }

    fn observed_active(&self) -> u64 {
        self.active
            .upgrade()
            .map_or(0, |active| active.load(Ordering::Acquire))
    }
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
    _lifecycle: ResourceToken,
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
        let census = previous.map_or_else(ResourceCensus::process, Self::resource_census);
        Self::prepare_with_tls_in(spec, upstream_tls, previous, census)
    }

    /// Prepare in a passive, isolated observation scope. No task is started.
    #[must_use]
    pub fn prepare_in(
        spec: ClusterSpec,
        previous: Option<&Self>,
        census: Arc<ResourceCensus>,
    ) -> (Self, usize) {
        Self::prepare_with_tls_in(spec, None, previous, census)
    }

    pub(crate) fn prepare_with_tls_in(
        spec: ClusterSpec,
        upstream_tls: Option<Arc<PreparedUpstreamTls>>,
        previous: Option<&Self>,
        census: Arc<ResourceCensus>,
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
            || Arc::new(ClusterRuntimeState::new(Arc::clone(&census))),
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
                    (None, _) => Arc::new(EndpointRuntimeState::new_at_with_admission(
                        Instant::now(),
                        Arc::new(AdmissionCounter::endpoint(Arc::clone(&census))),
                    )),
                };
                Arc::new(PreparedEndpoint {
                    spec: endpoint,
                    state,
                    dynamic: None,
                    lifecycle: census.token(ResourceKind::Endpoint, ResourceState::Candidate),
                })
            })
            .collect::<Vec<_>>();
        let mut inherited = BTreeMap::new();
        if let Some(previous) = same_cluster {
            let previous = previous
                .membership
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inherited.extend(
                previous
                    .admission_counters
                    .iter()
                    .filter(|(_, counter)| {
                        counter
                            .upgrade()
                            .is_some_and(|counter| counter.active() > 0)
                    })
                    .map(|(target, counter)| (*target, counter.clone())),
            );
            for endpoint in previous
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.state.admission.active() > 0)
            {
                if let Some(target) = endpoint.dial_target() {
                    inherited.insert(target, AdmissionTombstone::new(&endpoint.state.admission));
                }
            }
        }
        let inherited_counter_count = inherited.len();
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
            admission_counters: inherited,
            last_success_unix_ms: None,
            next_refresh: None,
            srv: SrvState::default(),
            srv_groups: Vec::new(),
            srv_cursors: BTreeMap::new(),
            // Operational entropy is not part of any correctness identity.
            srv_random: SrvSelectionRng::new(RandomState::new().hash_one(spec.id.as_str())),
            inherited_counter_count,
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
                lifecycle: census.token(ResourceKind::Cluster, ResourceState::Candidate),
            },
            reused,
        )
    }

    #[must_use]
    pub fn id(&self) -> &ResourceId {
        &self.spec.id
    }

    #[must_use]
    pub fn resource_census(&self) -> Arc<ResourceCensus> {
        self.lifecycle.census()
    }

    pub(crate) fn observe_publication(&self) {
        self.lifecycle.record_published_once();
        self.lifecycle.mark_current();
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for endpoint in membership.endpoints.iter() {
            endpoint.lifecycle.mark_current();
        }
    }

    pub(crate) fn observe_retirement(&self) {
        self.lifecycle.mark_retired();
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for endpoint in membership.endpoints.iter() {
            endpoint.lifecycle.mark_retired();
        }
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
        membership.srv = SrvState::default();
        membership.srv_groups.clear();
        membership.srv_cursors.clear();
        if !membership.endpoints.is_empty() {
            for endpoint in membership.endpoints.iter() {
                endpoint.lifecycle.mark_retired();
            }
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
                        AdmissionTombstone::new(&endpoint.state.admission),
                    )
                })
                .filter_map(|(target, counter)| target.map(|target| (target, counter)))
                .collect::<Vec<_>>();
            membership.admission_counters.extend(held);
            membership.active = false;
            membership.families = [FamilyState::default(), FamilyState::default()];
            membership.valid_until.clear();
            membership.stale_targets.clear();
            membership.srv = SrvState::default();
            membership.srv_groups.clear();
            membership.srv_cursors.clear();
            if !membership.endpoints.is_empty() {
                for endpoint in membership.endpoints.iter() {
                    endpoint.lifecycle.mark_retired();
                }
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
            _lifecycle: self
                .lifecycle
                .census()
                .token(ResourceKind::DiscoveryLease, ResourceState::Live),
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
        if plan.record != DnsRecordType::AAndAaaa {
            return Self::reconcile_receipt(&membership, false, false);
        }
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
        let was_positive = matches!(&observation, DnsObservation::Positive { .. });
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
                            plan.port.unwrap_or(0),
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
        receipt.positive_rejected = was_positive && receipt.observation_error_code.is_some();
        drop(membership);
        self.runtime.endpoint_released.notify_waiters();
        receipt
    }

    /// Reconcile one complete, bounded SRV round under the same ownership and
    /// lease-issuance gate as A/AAAA. Operational answers never publish config.
    pub fn reconcile_srv(
        &self,
        query: &DiscoveryQueryLease,
        observation: SrvObservation,
        now: tokio::time::Instant,
    ) -> DiscoveryReconcileOutcome {
        let mut membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(plan) = self
            .spec
            .discovery
            .as_ref()
            .filter(|plan| plan.record == DnsRecordType::Srv)
        else {
            return Self::reconcile_receipt(&membership, false, false);
        };
        let valid = membership.active
            && !membership.retired
            && Arc::ptr_eq(&membership.owner, &query.owner)
            && membership
                .query
                .as_ref()
                .is_some_and(|round| round.sequence == query.sequence && !round.name_revoked);
        if !valid {
            return Self::reconcile_receipt(&membership, false, false);
        }
        let generation = membership.generation;
        let mut received_error = None;
        let was_positive = matches!(&observation, SrvObservation::Positive { .. });
        let mut positive_rejected = false;
        match observation {
            SrvObservation::Positive { records, addresses } => {
                let result =
                    Self::apply_srv_positive(&mut membership, plan, records, addresses, now);
                if let Err(code) = result {
                    membership.srv = SrvState::error(error_resolution(code), code);
                    received_error = Some(code);
                    positive_rejected = true;
                } else {
                    membership.last_success_unix_ms = Some(unix_time_millis());
                    // The complete received round includes target-family
                    // failures, not merely the successful SRV lookup itself.
                    received_error = membership
                        .srv
                        .addresses
                        .values()
                        .flat_map(|families| families.iter())
                        .find_map(|family| family.transient);
                }
            }
            SrvObservation::NameNotFound | SrvObservation::ServiceUnavailable => {
                let outcome = if matches!(observation, SrvObservation::ServiceUnavailable) {
                    DiscoveryResolutionState::ServiceUnavailable
                } else {
                    DiscoveryResolutionState::NameNotFound
                };
                membership.srv = SrvState {
                    outcome: Some(outcome),
                    ..SrvState::default()
                };
                if let Some(round) = &mut membership.query {
                    round.name_revoked = true;
                }
            }
            SrvObservation::NoData => {
                membership.srv = SrvState {
                    outcome: Some(DiscoveryResolutionState::NoData),
                    ..SrvState::default()
                }
            }
            SrvObservation::TransientFailure { code } if code.allows_stale() => {
                membership.srv.outcome = Some(DiscoveryResolutionState::TransientFailure);
                membership.srv.transient = Some(code);
                received_error = Some(code);
            }
            SrvObservation::TransientFailure { code } => {
                membership.srv = SrvState::error(error_resolution(code), code);
                received_error = Some(code);
            }
            SrvObservation::PolicyRejected => {
                membership.srv = SrvState::error(
                    DiscoveryResolutionState::PolicyRejected,
                    DiscoveryErrorCode::PolicyRejected,
                );
                received_error = Some(DiscoveryErrorCode::PolicyRejected);
            }
            SrvObservation::InvalidAnswer => {
                membership.srv = SrvState::error(
                    DiscoveryResolutionState::InvalidAnswer,
                    DiscoveryErrorCode::InvalidAnswer,
                );
                received_error = Some(DiscoveryErrorCode::InvalidAnswer);
            }
            SrvObservation::LimitExceeded => {
                membership.srv = SrvState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                );
                received_error = Some(DiscoveryErrorCode::LimitExceeded);
            }
        }
        self.refresh_membership_locked(&mut membership, now);
        if membership.srv.transient == Some(DiscoveryErrorCode::LimitExceeded) {
            received_error = Some(DiscoveryErrorCode::LimitExceeded);
            positive_rejected = was_positive;
        }
        let mut receipt =
            Self::reconcile_receipt(&membership, true, generation != membership.generation);
        receipt.observation_error_code = received_error;
        receipt.positive_rejected = positive_rejected;
        drop(membership);
        self.runtime.endpoint_released.notify_waiters();
        receipt
    }

    fn apply_srv_positive(
        membership: &mut EndpointMembership,
        plan: &DnsDiscoverySpec,
        records: Vec<SrvRecord>,
        addresses: Vec<SrvTargetAddressObservation>,
        now: tokio::time::Instant,
    ) -> Result<(), DiscoveryErrorCode> {
        if records.len() > oxidase_config::MAX_DNS_RECORDS
            || addresses.len() > usize::from(plan.limits.max_targets) * 2
        {
            return Err(DiscoveryErrorCode::LimitExceeded);
        }
        if records.iter().any(|record| record.target == ".") {
            membership.srv = SrvState {
                outcome: Some(DiscoveryResolutionState::ServiceUnavailable),
                ..SrvState::default()
            };
            if let Some(round) = &mut membership.query {
                round.name_revoked = true;
            }
            return Ok(());
        }
        let mut normalized = BTreeMap::<SrvGroupKey, SrvRecord>::new();
        for mut record in records {
            record.target =
                canonical_srv_target(&record.target).ok_or(DiscoveryErrorCode::InvalidAnswer)?;
            if record.port == 0 {
                return Err(DiscoveryErrorCode::InvalidAnswer);
            }
            let key = SrvGroupKey {
                target: record.target.clone(),
                port: record.port,
                priority: record.priority,
            };
            if let Some(previous) = normalized.get_mut(&key) {
                if previous.weight != record.weight {
                    return Err(DiscoveryErrorCode::InvalidAnswer);
                }
                previous.fresh_until = previous.fresh_until.min(record.fresh_until);
            } else {
                normalized.insert(key, record);
            }
        }
        let targets = normalized
            .keys()
            .map(|key| key.target.clone())
            .collect::<BTreeSet<_>>();
        let mut bounded_names = targets.clone();
        bounded_names.insert(plan.name.clone());
        if bounded_names.len() > usize::from(plan.limits.max_targets) {
            return Err(DiscoveryErrorCode::LimitExceeded);
        }
        let mut observations = BTreeMap::new();
        let mut revoked = BTreeSet::new();
        for mut observed in addresses {
            observed.target =
                canonical_srv_target(&observed.target).ok_or(DiscoveryErrorCode::InvalidAnswer)?;
            if !targets.contains(&observed.target) {
                return Err(DiscoveryErrorCode::InvalidAnswer);
            }
            if matches!(observed.observation, DnsObservation::NameNotFound) {
                revoked.insert(observed.target.clone());
            }
            if observations
                .insert(
                    (observed.target, family_index(observed.family)),
                    observed.observation,
                )
                .is_some()
            {
                return Err(DiscoveryErrorCode::InvalidAnswer);
            }
        }
        membership
            .srv
            .addresses
            .retain(|target, _| targets.contains(target));
        for target in &targets {
            let families = membership
                .srv
                .addresses
                .entry(target.clone())
                .or_insert_with(|| [FamilyState::default(), FamilyState::default()]);
            if revoked.contains(target) {
                *families = [
                    FamilyState::empty(DiscoveryResolutionState::NameNotFound),
                    FamilyState::empty(DiscoveryResolutionState::NameNotFound),
                ];
                continue;
            }
            for (index, family) in [DnsFamily::A, DnsFamily::Aaaa].into_iter().enumerate() {
                if let Some(observation) = observations.remove(&(target.clone(), index)) {
                    Self::apply_srv_family(&mut families[index], family, observation, plan, now)?;
                }
            }
        }
        let cached_records = membership
            .srv
            .addresses
            .values()
            .flat_map(|families| families.iter())
            .map(|family| family.records.len())
            .sum::<usize>();
        if cached_records > oxidase_config::MAX_DNS_RECORDS {
            return Err(DiscoveryErrorCode::LimitExceeded);
        }
        membership.srv.records = normalized
            .into_values()
            .filter(|record| record.fresh_until > now)
            .collect();
        membership.srv.outcome = Some(if membership.srv.records.is_empty() {
            DiscoveryResolutionState::NoData
        } else {
            DiscoveryResolutionState::Fresh
        });
        membership.srv.transient = None;
        Ok(())
    }

    fn apply_srv_family(
        previous: &mut FamilyState,
        family: DnsFamily,
        observation: DnsObservation,
        plan: &DnsDiscoverySpec,
        now: tokio::time::Instant,
    ) -> Result<(), DiscoveryErrorCode> {
        match observation {
            DnsObservation::Positive { addresses } => {
                if addresses.len() > oxidase_config::MAX_DNS_RECORDS {
                    return Err(DiscoveryErrorCode::LimitExceeded);
                }
                let mut records = BTreeMap::new();
                let mut rejected = false;
                for record in addresses {
                    if family == DnsFamily::A && !record.address.is_ipv4() {
                        return Err(DiscoveryErrorCode::InvalidAnswer);
                    }
                    if validate_discovery_address(record.address, 1, &plan.address_policy).is_err()
                    {
                        rejected = true;
                        continue;
                    }
                    records
                        .entry(normalize_discovery_address(record.address))
                        .and_modify(|expiry: &mut tokio::time::Instant| {
                            *expiry = (*expiry).min(record.fresh_until)
                        })
                        .or_insert(record.fresh_until);
                }
                let records = records
                    .into_iter()
                    .filter(|(_, expiry)| *expiry > now)
                    .map(|(address, fresh_until)| DnsAddressRecord {
                        address,
                        fresh_until,
                    })
                    .collect::<Vec<_>>();
                if records.len() > usize::from(plan.limits.max_endpoints) {
                    return Err(DiscoveryErrorCode::LimitExceeded);
                }
                *previous = if records.is_empty() && rejected {
                    FamilyState::error(
                        DiscoveryResolutionState::PolicyRejected,
                        DiscoveryErrorCode::PolicyRejected,
                    )
                } else {
                    FamilyState {
                        records,
                        outcome: Some(DiscoveryResolutionState::Fresh),
                        transient: None,
                    }
                };
            }
            DnsObservation::TransientFailure { code } if code.allows_stale() => {
                previous.outcome = Some(DiscoveryResolutionState::TransientFailure);
                previous.transient = Some(code);
            }
            DnsObservation::TransientFailure { code } => {
                *previous = FamilyState::error(error_resolution(code), code)
            }
            DnsObservation::NameNotFound => {
                *previous = FamilyState::empty(DiscoveryResolutionState::NameNotFound)
            }
            DnsObservation::NoData => {
                *previous = FamilyState::empty(DiscoveryResolutionState::NoData)
            }
            DnsObservation::PolicyRejected => {
                *previous = FamilyState::error(
                    DiscoveryResolutionState::PolicyRejected,
                    DiscoveryErrorCode::PolicyRejected,
                )
            }
            DnsObservation::InvalidAnswer => {
                *previous = FamilyState::error(
                    DiscoveryResolutionState::InvalidAnswer,
                    DiscoveryErrorCode::InvalidAnswer,
                )
            }
            DnsObservation::LimitExceeded => {
                *previous = FamilyState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                )
            }
        }
        Ok(())
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
        if self
            .spec
            .discovery
            .as_ref()
            .is_some_and(|plan| plan.record == DnsRecordType::Srv)
        {
            return self.select_srv_endpoint(&mut membership, now, excluded);
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

    /// Passive status: no membership sweep, TTL renewal, health transition or
    /// admission mutation. Expired eligibility is projected without retiring
    /// objects; the existing owner and business lease paths perform maintenance.
    #[must_use]
    pub fn observed_status(&self, now: Instant) -> ClusterRuntimeStatus {
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observed = tokio::time::Instant::now();
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
            discovery: self.observed_discovery_status_locked(&membership, observed, now),
            endpoints: membership
                .endpoints
                .iter()
                .filter(|endpoint| self.observed_member_live(&membership, endpoint, observed))
                .map(|endpoint| EndpointStatusSnapshot {
                    name: endpoint.name().to_owned(),
                    runtime: endpoint.state.observed_status(now),
                })
                .collect(),
        }
    }

    /// Same passive projection as observed_status, without the endpoint detail.
    #[must_use]
    pub fn observed_discovery_status(&self) -> Option<DiscoveryRuntimeStatus> {
        self.spec.discovery.as_ref()?;
        let membership = self
            .membership
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.observed_discovery_status_locked(
            &membership,
            tokio::time::Instant::now(),
            Instant::now(),
        )
    }

    fn observed_member_live(
        &self,
        membership: &EndpointMembership,
        endpoint: &PreparedEndpoint,
        now: tokio::time::Instant,
    ) -> bool {
        if self.spec.discovery.is_none() {
            return true;
        }
        membership.active
            && !membership.retired
            && endpoint
                .dynamic_key()
                .and_then(|key| membership.valid_until.get(&key))
                .is_some_and(|expiry| now < *expiry)
    }

    fn observed_discovery_status_locked(
        &self,
        membership: &EndpointMembership,
        now: tokio::time::Instant,
        health_now: Instant,
    ) -> Option<DiscoveryRuntimeStatus> {
        let plan = self.spec.discovery.as_ref()?;
        let live = membership
            .endpoints
            .iter()
            .filter(|endpoint| self.observed_member_live(membership, endpoint, now))
            .collect::<Vec<_>>();
        let healthy = |endpoint: &&Arc<PreparedEndpoint>| {
            endpoint
                .state
                .observed_health_state(health_now)
                .is_eligible()
        };
        let groups = membership
            .srv_groups
            .iter()
            .map(|group| {
                let addresses = live
                    .iter()
                    .filter(|endpoint| {
                        endpoint
                            .dynamic_key()
                            .is_some_and(|key| group.members.binary_search(&key).is_ok())
                    })
                    .collect::<Vec<_>>();
                SrvTargetRuntimeStatus {
                    target: group.key.target.clone(),
                    port: group.key.port,
                    priority: group.key.priority,
                    weight: group.weight,
                    addresses: addresses.len(),
                    eligible_addresses: addresses
                        .iter()
                        .filter(|endpoint| {
                            endpoint
                                .state
                                .observed_health_state(health_now)
                                .is_eligible()
                        })
                        .count(),
                }
            })
            .collect::<Vec<_>>();
        let stale = live.iter().any(|endpoint| {
            endpoint
                .dynamic_key()
                .is_some_and(|key| membership.stale_targets.contains(&key))
        });
        let (retired_admission_counters, stored_admission_tombstones) =
            Self::observed_retired_admissions(membership, now);
        Some(DiscoveryRuntimeStatus {
            name: plan.name.clone(),
            resolution: membership.resolution_for(
                plan.record == DnsRecordType::Srv,
                !live.is_empty(),
                stale,
            ),
            generation: membership.generation,
            endpoint_count: live.len(),
            eligible_endpoints: live.iter().copied().filter(healthy).count(),
            in_flight_query: membership.query.is_some(),
            last_success_unix_ms: membership.last_success_unix_ms,
            next_expiry_ms: membership.valid_until.values().min().map(|expiry| {
                u64::try_from(expiry.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
            }),
            next_refresh_ms: membership.next_refresh.map(|next| {
                u64::try_from(next.saturating_duration_since(now).as_millis()).unwrap_or(u64::MAX)
            }),
            error_code: membership.error_code(),
            retired_admission_counters,
            stored_admission_tombstones,
            eligible_priority: groups
                .iter()
                .filter(|group| group.eligible_addresses > 0)
                .map(|group| group.priority)
                .min(),
            srv_targets: groups,
        })
    }

    fn observed_retired_admissions(
        membership: &EndpointMembership,
        now: tokio::time::Instant,
    ) -> (usize, usize) {
        let mut active = 0;
        let mut stored = 0;
        for (target, counter) in &membership.admission_counters {
            if membership
                .valid_until
                .iter()
                .any(|(member, expiry)| member.target == *target && now < *expiry)
            {
                continue;
            }
            stored += 1;
            // Borrow only the very same atomic used by business admission.
            // Parallel readers cannot chain strong references to the Counter.
            if counter.observed_active() > 0 {
                active += 1;
            }
        }
        (active, stored)
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
        let (retired_admission_counters, stored_admission_tombstones) =
            Self::observed_retired_admissions(membership, now);
        Some(DiscoveryRuntimeStatus {
            name: plan.name.clone(),
            resolution: membership.resolution(plan.record == DnsRecordType::Srv),
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
            retired_admission_counters,
            stored_admission_tombstones,
            eligible_priority: Self::srv_eligible_priority(membership, Instant::now()),
            srv_targets: membership
                .srv_groups
                .iter()
                .map(|group| {
                    let indices = Self::srv_group_indices(
                        membership,
                        group,
                        Instant::now(),
                        &BTreeSet::new(),
                    );
                    SrvTargetRuntimeStatus {
                        target: group.key.target.clone(),
                        port: group.key.port,
                        priority: group.key.priority,
                        weight: group.weight,
                        addresses: group.members.len(),
                        eligible_addresses: indices.len(),
                    }
                })
                .collect(),
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
            positive_rejected: false,
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
        let (mut desired, mut groups) = if plan.record == DnsRecordType::Srv {
            Self::srv_desired(membership, plan, now)
        } else {
            let mut desired = BTreeMap::<DynamicEndpointKey, (tokio::time::Instant, bool)>::new();
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
                        let Some(expiry) =
                            record.fresh_until.checked_add(plan.refresh.stale_if_error)
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
                    let Ok(target) = validate_discovery_address(
                        record.address,
                        plan.port.unwrap_or(0),
                        &plan.address_policy,
                    ) else {
                        continue;
                    };
                    desired
                        .entry(DynamicEndpointKey {
                            logical_target: plan.name.clone(),
                            target,
                        })
                        .and_modify(|current| {
                            current.0 = current.0.max(expiry);
                            current.1 &= stale;
                        })
                        .or_insert((expiry, stale));
                }
            }
            (desired, Vec::new())
        };
        let mut previous = membership
            .endpoints
            .iter()
            .filter_map(|endpoint| {
                endpoint
                    .dynamic_key()
                    .map(|target| (target, Arc::clone(endpoint)))
            })
            .collect::<BTreeMap<_, _>>();
        for (target, endpoint) in &previous {
            if endpoint.state.admission.active() > 0 {
                membership.admission_counters.insert(
                    target.target,
                    AdmissionTombstone::new(&endpoint.state.admission),
                );
            }
        }
        let cap = usize::from(plan.limits.max_endpoints).saturating_add(
            usize::try_from(self.runtime.admission.active())
                .unwrap_or(usize::MAX)
                .max(self.spec.limits.max_in_flight as usize)
                .max(membership.inherited_counter_count),
        );
        let new_counters = desired
            .keys()
            .filter(|target| {
                !membership.admission_counters.contains_key(&target.target)
                    && !previous
                        .keys()
                        .any(|previous| previous.target == target.target)
            })
            .map(|key| key.target)
            .collect::<BTreeSet<_>>()
            .len();
        if desired.len() > usize::from(plan.limits.max_endpoints)
            || membership
                .admission_counters
                .len()
                .saturating_add(new_counters)
                > cap
        {
            desired.clear();
            groups.clear();
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
            if plan.record == DnsRecordType::Srv {
                membership.srv = SrvState::error(
                    DiscoveryResolutionState::LimitExceeded,
                    DiscoveryErrorCode::LimitExceeded,
                );
            }
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
                groups.clear();
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
                if plan.record == DnsRecordType::Srv {
                    membership.srv = SrvState::error(
                        DiscoveryResolutionState::LimitExceeded,
                        DiscoveryErrorCode::LimitExceeded,
                    );
                }
                break;
            };
            let admission = membership
                .admission_counters
                .get(&target.target)
                .and_then(AdmissionTombstone::upgrade)
                .or_else(|| {
                    previous
                        .values()
                        .find(|endpoint| endpoint.dial_target() == Some(target.target))
                        .map(|endpoint| Arc::clone(&endpoint.state.admission))
                })
                .unwrap_or_else(|| Arc::new(AdmissionCounter::endpoint(self.resource_census())));
            membership
                .admission_counters
                .insert(target.target, AdmissionTombstone::new(&admission));
            let state = Arc::new(EndpointRuntimeState::new_at_with_admission(
                Instant::now(),
                admission,
            ));
            let mut identity = ContentDigestBuilder::new("oxidase/discovery-endpoint/v1");
            identity
                .field_bytes("cluster", self.spec.id.as_str())
                .field_bytes("target", &target.logical_target)
                .field_bytes("address", target.target.to_string());
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
                    target: target.target,
                    incarnation,
                    logical_target: target.logical_target.clone(),
                    owner: Arc::clone(&membership.owner),
                }),
                lifecycle: self
                    .lifecycle
                    .census()
                    .token(ResourceKind::Endpoint, ResourceState::Current),
            }));
        }
        let group_changed = groups != membership.srv_groups;
        if changed || endpoints.len() != membership.endpoints.len() {
            for old in membership.endpoints.iter() {
                if !endpoints.iter().any(|current| Arc::ptr_eq(old, current)) {
                    old.lifecycle.mark_retired();
                }
            }
            membership.endpoints = endpoints.into();
            membership.weighted_state = vec![0; membership.endpoints.len()];
        }
        if changed || group_changed {
            membership.generation = membership.generation.saturating_add(1);
        }
        membership.srv_groups = groups;
        membership.srv_cursors.retain(|group, _| {
            membership
                .srv_groups
                .iter()
                .any(|current| &current.key == group)
        });
        membership.valid_until = desired
            .iter()
            .map(|(target, (expiry, _))| (target.clone(), *expiry))
            .collect();
        membership.stale_targets = desired
            .iter()
            .filter_map(|(target, (_, stale))| stale.then_some(target.clone()))
            .collect();
    }

    fn srv_desired(
        membership: &mut EndpointMembership,
        plan: &DnsDiscoverySpec,
        now: tokio::time::Instant,
    ) -> (DesiredEndpoints, Vec<SrvGroup>) {
        let grace = plan.refresh.stale_if_error;
        membership.srv.records.retain(|record| {
            now < record.fresh_until
                || record
                    .fresh_until
                    .checked_add(grace)
                    .is_some_and(|expiry| now < expiry)
        });
        let targets = membership
            .srv
            .records
            .iter()
            .map(|record| record.target.clone())
            .collect::<BTreeSet<_>>();
        membership
            .srv
            .addresses
            .retain(|target, _| targets.contains(target));
        for families in membership.srv.addresses.values_mut() {
            for family in families {
                family.records.retain(|record| {
                    now < record.fresh_until
                        || record
                            .fresh_until
                            .checked_add(grace)
                            .is_some_and(|expiry| now < expiry)
                });
            }
        }
        let mut desired = DesiredEndpoints::new();
        let mut groups = Vec::new();
        for record in &membership.srv.records {
            let mut group = SrvGroup {
                key: SrvGroupKey {
                    target: record.target.clone(),
                    port: record.port,
                    priority: record.priority,
                },
                weight: record.weight,
                members: Vec::new(),
            };
            if let Some(families) = membership.srv.addresses.get(&record.target) {
                for family in families {
                    for address in &family.records {
                        // Original component deadlines are intersected, never
                        // restarted by a failed SRV/address/CNAME refresh.
                        let component_expiry =
                            |fresh_until: tokio::time::Instant,
                             transient: Option<DiscoveryErrorCode>| {
                                if now < fresh_until {
                                    Some(fresh_until)
                                } else if transient.is_some_and(DiscoveryErrorCode::allows_stale) {
                                    fresh_until
                                        .checked_add(grace)
                                        .filter(|expiry| now < *expiry)
                                } else {
                                    None
                                }
                            };
                        // An address failure cannot authorize stale SRV data,
                        // nor can an SRV failure authorize stale address data.
                        let Some(srv_expiry) =
                            component_expiry(record.fresh_until, membership.srv.transient)
                        else {
                            continue;
                        };
                        let Some(address_expiry) =
                            component_expiry(address.fresh_until, family.transient)
                        else {
                            continue;
                        };
                        let expiry = srv_expiry.min(address_expiry);
                        let stale = now >= record.fresh_until.min(address.fresh_until);
                        let Ok(target) = validate_discovery_address(
                            address.address,
                            record.port,
                            &plan.address_policy,
                        ) else {
                            continue;
                        };
                        let key = DynamicEndpointKey {
                            logical_target: record.target.clone(),
                            target,
                        };
                        desired
                            .entry(key.clone())
                            .and_modify(|current| {
                                current.0 = current.0.max(expiry);
                                current.1 &= stale;
                            })
                            .or_insert((expiry, stale));
                        group.members.push(key);
                    }
                }
            }
            group.members.sort();
            group.members.dedup();
            if !group.members.is_empty() || now < record.fresh_until {
                groups.push(group);
            }
        }
        (desired, groups)
    }

    fn srv_group_indices(
        membership: &EndpointMembership,
        group: &SrvGroup,
        now: Instant,
        excluded: &BTreeSet<String>,
    ) -> Vec<usize> {
        membership
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, endpoint)| {
                endpoint.state.is_eligible(now)
                    && !excluded.contains(endpoint.name())
                    && endpoint
                        .dynamic_key()
                        .is_some_and(|key| group.members.binary_search(&key).is_ok())
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn srv_eligible_priority(membership: &EndpointMembership, now: Instant) -> Option<u16> {
        membership
            .srv_groups
            .iter()
            .filter(|group| {
                !Self::srv_group_indices(membership, group, now, &BTreeSet::new()).is_empty()
            })
            .map(|group| group.key.priority)
            .min()
    }

    fn srv_candidates(
        membership: &EndpointMembership,
        now: Instant,
        excluded: &BTreeSet<String>,
    ) -> Vec<usize> {
        // Exclusions and ordinary saturation do not reclassify healthy primary
        // targets as unhealthy, so neither can silently bypass priority.
        let Some(priority) = Self::srv_eligible_priority(membership, now) else {
            return Vec::new();
        };
        membership
            .srv_groups
            .iter()
            .enumerate()
            .filter(|(_, group)| {
                group.key.priority == priority
                    && !Self::srv_group_indices(membership, group, now, excluded).is_empty()
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn srv_address_order(
        &self,
        membership: &mut EndpointMembership,
        group: usize,
        mut eligible: Vec<usize>,
    ) -> Vec<usize> {
        match self.spec.load_balance {
            LoadBalancePolicy::RoundRobin | LoadBalancePolicy::WeightedRoundRobin => {
                // DNS addresses have equal weight 1. Keep an independent
                // equal-weight RR cursor per logical target, not per IP count.
                let cursor = membership
                    .srv_cursors
                    .entry(membership.srv_groups[group].key.clone())
                    .or_default();
                let start = (*cursor as usize) % eligible.len();
                *cursor = cursor.wrapping_add(1);
                eligible.rotate_left(start);
            }
            LoadBalancePolicy::LeastRequests => eligible.sort_by(|left, right| {
                membership.endpoints[*left]
                    .active_requests()
                    .cmp(&membership.endpoints[*right].active_requests())
                    .then_with(|| left.cmp(right))
            }),
        }
        eligible
    }

    fn select_srv_endpoint(
        &self,
        membership: &mut EndpointMembership,
        now: Instant,
        excluded: &BTreeSet<String>,
    ) -> Option<Arc<PreparedEndpoint>> {
        let candidates = Self::srv_candidates(membership, now, excluded);
        let weights = candidates
            .iter()
            .map(|index| membership.srv_groups[*index].weight)
            .collect::<Vec<_>>();
        let selected = candidates[membership.srv_random.weighted_index(&weights)?];
        let addresses =
            Self::srv_group_indices(membership, &membership.srv_groups[selected], now, excluded);
        let addresses = self.srv_address_order(membership, selected, addresses);
        Some(Arc::clone(&membership.endpoints[addresses[0]]))
    }

    fn try_acquire_srv(
        &self,
        membership: &mut EndpointMembership,
        now: Instant,
        excluded: &BTreeSet<String>,
    ) -> EndpointAcquire {
        let mut candidates = Self::srv_candidates(membership, now, excluded);
        if candidates.is_empty() {
            return EndpointAcquire::Unavailable;
        }
        while !candidates.is_empty() {
            let weights = candidates
                .iter()
                .map(|index| membership.srv_groups[*index].weight)
                .collect::<Vec<_>>();
            let Some(chosen) = membership.srv_random.weighted_index(&weights) else {
                return EndpointAcquire::Unavailable;
            };
            let group = candidates.remove(chosen);
            let addresses =
                Self::srv_group_indices(membership, &membership.srv_groups[group], now, excluded);
            for index in self.srv_address_order(membership, group, addresses) {
                if let Some(permit) = self.try_endpoint_permit(membership, index) {
                    return Self::acquired_endpoint(membership, index, permit);
                }
            }
        }
        EndpointAcquire::Saturated
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
        if self
            .spec
            .discovery
            .as_ref()
            .is_some_and(|plan| plan.record == DnsRecordType::Srv)
        {
            return self.try_acquire_srv(&mut membership, now, excluded);
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

fn canonical_srv_target(source: &str) -> Option<String> {
    let name = source.strip_suffix('.').unwrap_or(source);
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        return None;
    }
    Some(format!("{}.", name.to_ascii_lowercase()))
}

const fn error_resolution(code: DiscoveryErrorCode) -> DiscoveryResolutionState {
    match code {
        DiscoveryErrorCode::PolicyRejected => DiscoveryResolutionState::PolicyRejected,
        DiscoveryErrorCode::InvalidAnswer => DiscoveryResolutionState::InvalidAnswer,
        DiscoveryErrorCode::LimitExceeded => DiscoveryResolutionState::LimitExceeded,
        _ => DiscoveryResolutionState::TransientFailure,
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

impl SrvState {
    fn error(outcome: DiscoveryResolutionState, code: DiscoveryErrorCode) -> Self {
        Self {
            outcome: Some(outcome),
            transient: Some(code),
            ..Self::default()
        }
    }
}

impl EndpointMembership {
    fn error_code(&self) -> Option<DiscoveryErrorCode> {
        self.srv
            .transient
            .or_else(|| {
                self.srv
                    .addresses
                    .values()
                    .flat_map(|families| families.iter())
                    .find_map(|family| family.transient)
            })
            .or_else(|| self.families.iter().find_map(|family| family.transient))
    }

    fn resolution(&self, srv: bool) -> DiscoveryResolutionState {
        self.resolution_for(
            srv,
            !self.endpoints.is_empty(),
            !self.stale_targets.is_empty(),
        )
    }

    fn resolution_for(
        &self,
        srv: bool,
        has_endpoints: bool,
        has_stale: bool,
    ) -> DiscoveryResolutionState {
        if self.retired {
            return DiscoveryResolutionState::Retired;
        }
        if has_endpoints {
            if has_stale {
                return DiscoveryResolutionState::Stale;
            }
            if srv {
                return if self.srv.outcome == Some(DiscoveryResolutionState::Fresh)
                    && self
                        .srv
                        .addresses
                        .values()
                        .flat_map(|families| families.iter())
                        .all(|family| {
                            matches!(
                                family.outcome,
                                Some(
                                    DiscoveryResolutionState::Fresh
                                        | DiscoveryResolutionState::NoData
                                )
                            )
                        })
                {
                    DiscoveryResolutionState::Fresh
                } else {
                    DiscoveryResolutionState::Partial
                };
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
        if srv {
            if let Some(outcome) = self.srv.outcome {
                return if outcome == DiscoveryResolutionState::Fresh {
                    DiscoveryResolutionState::Expired
                } else {
                    outcome
                };
            }
            return DiscoveryResolutionState::Unresolved;
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

struct ClusterRuntimeState {
    endpoint_incarnations: AtomicU64,
    admission: Arc<AdmissionCounter>,
    retries: Arc<AdmissionCounter>,
    endpoint_released: Arc<Notify>,
    retry_attempts: AtomicU64,
    retry_exhausted: AtomicU64,
    overload_rejections: AtomicU64,
    unavailable_rejections: AtomicU64,
    _lifecycle: ResourceToken,
}

impl Default for ClusterRuntimeState {
    fn default() -> Self {
        Self::new(ResourceCensus::process())
    }
}

impl ClusterRuntimeState {
    fn new(census: Arc<ResourceCensus>) -> Self {
        Self {
            endpoint_incarnations: AtomicU64::new(0),
            admission: Arc::new(AdmissionCounter::new(
                Arc::clone(&census),
                ResourceKind::ClusterPermit,
                false,
            )),
            retries: Arc::new(AdmissionCounter::new(
                Arc::clone(&census),
                ResourceKind::RetryPermit,
                false,
            )),
            endpoint_released: Arc::new(Notify::new()),
            retry_attempts: AtomicU64::new(0),
            retry_exhausted: AtomicU64::new(0),
            overload_rejections: AtomicU64::new(0),
            unavailable_rejections: AtomicU64::new(0),
            _lifecycle: census.token(ResourceKind::ClusterRuntime, ResourceState::Live),
        }
    }
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

#[derive(Debug)]
struct AdmissionCounter {
    active: Arc<AtomicU64>,
    released: Notify,
    census: Arc<ResourceCensus>,
    permit_kind: ResourceKind,
    _lifecycle: Option<ResourceToken>,
}

impl Default for AdmissionCounter {
    fn default() -> Self {
        Self::endpoint(ResourceCensus::process())
    }
}

impl AdmissionCounter {
    fn endpoint(census: Arc<ResourceCensus>) -> Self {
        Self::new(census, ResourceKind::EndpointPermit, true)
    }

    fn new(census: Arc<ResourceCensus>, permit_kind: ResourceKind, endpoint: bool) -> Self {
        Self {
            active: Arc::new(AtomicU64::new(0)),
            released: Notify::new(),
            _lifecycle: endpoint
                .then(|| census.token(ResourceKind::EndpointAdmission, ResourceState::Live)),
            census,
            permit_kind,
        }
    }
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
                        _lifecycle: self.census.token(self.permit_kind, ResourceState::Live),
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
    _lifecycle: ResourceToken,
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

    use crate::{ResourceCensus, ResourceCount, ResourceKind, ResourceState};
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

    pub(super) fn census_count(census: &ResourceCensus, kind: ResourceKind) -> ResourceCount {
        census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == kind)
            .expect("fixed resource kind")
    }

    pub(super) fn census_state(
        census: &ResourceCensus,
        kind: ResourceKind,
        state: ResourceState,
    ) -> u64 {
        census_count(census, kind)
            .states
            .into_iter()
            .find(|row| row.state == state)
            .expect("fixed resource state")
            .live
    }

    #[tokio::test]
    async fn lifecycle_census_tracks_shared_runtime_and_physical_admission_not_arc_counts() {
        let census = Arc::new(ResourceCensus::default());
        let spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://127.0.0.1:8080", 1)],
        );
        let old = Arc::new(PreparedCluster::prepare_in(spec.clone(), None, Arc::clone(&census)).0);
        old.observe_publication();
        let lease = old.acquire().await.expect("original lease");
        let retry = old.try_acquire_retry().expect("retry permit");
        let clones = (0..16).map(|_| Arc::clone(&old)).collect::<Vec<_>>();
        assert_eq!(census_count(&census, ResourceKind::Cluster).created, 1);
        assert_eq!(census_count(&census, ResourceKind::Endpoint).created, 1);
        let mut replacement = spec;
        replacement
            .health
            .active
            .as_mut()
            .expect("health policy")
            .path = "/other-health".to_owned();
        let current = PreparedCluster::prepare_in(replacement, Some(&old), Arc::clone(&census)).0;
        current.observe_publication();
        old.observe_retirement();
        assert_eq!(census_count(&census, ResourceKind::Cluster).live, 2);
        assert_eq!(census_count(&census, ResourceKind::ClusterRuntime).live, 1);
        assert_eq!(
            census_count(&census, ResourceKind::EndpointAdmission).live,
            1
        );
        assert_eq!(census_count(&census, ResourceKind::Endpoint).live, 2);
        assert_eq!(
            census_state(&census, ResourceKind::Endpoint, ResourceState::Retired),
            1
        );
        assert_eq!(census_count(&census, ResourceKind::ClusterPermit).live, 1);
        assert_eq!(census_count(&census, ResourceKind::EndpointPermit).live, 1);
        assert_eq!(census_count(&census, ResourceKind::RetryPermit).live, 1);
        let old_endpoint = Arc::downgrade(lease.endpoint());
        drop((clones, old));
        assert_eq!(census_count(&census, ResourceKind::Cluster).live, 1);
        assert!(
            old_endpoint.upgrade().is_some(),
            "actual lease owns the retired endpoint"
        );
        drop((lease, retry));
        assert!(old_endpoint.upgrade().is_none());
        assert_eq!(census_count(&census, ResourceKind::Endpoint).live, 1);
        assert_eq!(
            census_state(&census, ResourceKind::Endpoint, ResourceState::Retired),
            0
        );
        assert_eq!(
            census_count(&census, ResourceKind::EndpointAdmission).live,
            1,
            "current endpoint still owns the shared physical counter"
        );
        for kind in [
            ResourceKind::ClusterPermit,
            ResourceKind::EndpointPermit,
            ResourceKind::RetryPermit,
        ] {
            let row = census_count(&census, kind);
            assert_eq!((row.created, row.destroyed, row.live), (1, 1, 0));
        }
        drop(current);
        for kind in [
            ResourceKind::Cluster,
            ResourceKind::ClusterRuntime,
            ResourceKind::Endpoint,
            ResourceKind::EndpointAdmission,
        ] {
            let row = census_count(&census, kind);
            assert_eq!(row.created, row.destroyed);
            assert_eq!(row.live, 0);
        }
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[test]
    fn passive_resource_status_projects_ejection_expiry_without_changing_health_counters() {
        let census = Arc::new(ResourceCensus::default());
        let spec = cluster(
            LoadBalancePolicy::RoundRobin,
            vec![endpoint("a", "http://127.0.0.1:8080", 1)],
        );
        let cluster = PreparedCluster::prepare_in(spec, None, Arc::clone(&census)).0;
        let endpoint = Arc::clone(&cluster.endpoints()[0]);
        let now = Instant::now();
        cluster.record_passive_failure_for(&endpoint, now);
        cluster.record_passive_failure_for(&endpoint, now);
        let state = endpoint.runtime_state();
        assert_eq!(
            state.health.load(Ordering::Acquire),
            super::HEALTH_PASSIVELY_EJECTED
        );
        let transitions = state.health_transitions.load(Ordering::Relaxed);
        let deadline = state.ejection_deadline_tick.load(Ordering::Acquire);
        let before = census.sample();
        for _ in 0..100 {
            let status = cluster.observed_status(now + Duration::from_secs(11));
            assert_eq!(
                status.endpoints[0].runtime.health,
                EndpointHealthState::UnknownEligible
            );
            assert!(status.endpoints[0].runtime.ejection_remaining_ms.is_none());
        }
        assert_eq!(
            state.health.load(Ordering::Acquire),
            super::HEALTH_PASSIVELY_EJECTED
        );
        assert_eq!(
            state.health_transitions.load(Ordering::Relaxed),
            transitions
        );
        assert_eq!(
            state.ejection_deadline_tick.load(Ordering::Acquire),
            deadline
        );
        assert_eq!(census.sample().sequence_end, before.sequence_end);
        assert_eq!(
            endpoint.health_state(now + Duration::from_secs(11)),
            EndpointHealthState::UnknownEligible,
            "the existing business accessor, not observation, performs expiry"
        );
        assert_eq!(
            state.health_transitions.load(Ordering::Relaxed),
            transitions + 1
        );
        assert_eq!(census.sample().invariant_failures, 0);
    }

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
    use super::tests::{census_count, census_state};
    use super::*;
    use oxidase_config::{
        DnsAddressPolicy, DnsDiscoveryLimits, DnsDiscoverySpec, DnsRecordType, DnsRefreshSpec,
        DnsResolverSource, DnsResolverSpec,
    };
    use oxidase_core::SourceSpan;

    #[tokio::test(start_paused = true)]
    async fn passive_census_does_not_retire_expired_members_or_prune_tombstones() {
        let census = Arc::new(ResourceCensus::default());
        let cluster = PreparedCluster::prepare_in(dynamic_spec(), None, Arc::clone(&census)).0;
        cluster.observe_publication();
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let lease = cluster.acquire().await.expect("issued endpoint lease");
        let old = Arc::downgrade(lease.endpoint());
        let physical = Arc::downgrade(&lease.endpoint().state.admission);
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        assert_eq!(
            census_state(&census, ResourceKind::Endpoint, ResourceState::Retired),
            1
        );
        assert!(old.upgrade().is_some());
        let held_status = cluster.observed_discovery_status().expect("DNS status");
        assert_eq!(held_status.retired_admission_counters, 1);
        assert_eq!(held_status.stored_admission_tombstones, 1);
        drop(lease);
        assert!(
            old.upgrade().is_none(),
            "census does not own the removed endpoint"
        );
        assert!(
            physical.upgrade().is_none(),
            "the real physical counter also releases without a scrape"
        );
        let membership_size = || {
            cluster
                .membership
                .lock()
                .expect("membership")
                .admission_counters
                .len()
        };
        assert_eq!(
            membership_size(),
            1,
            "the weak tombstone exists until ordinary maintenance"
        );
        let before = census.sample();
        for _ in 0..100 {
            assert_eq!(
                cluster
                    .observed_status(Instant::now())
                    .discovery
                    .expect("DNS status")
                    .endpoint_count,
                0
            );
            assert_eq!(
                cluster
                    .observed_discovery_status()
                    .expect("DNS status")
                    .retired_admission_counters,
                0
            );
            assert_eq!(
                cluster
                    .observed_discovery_status()
                    .expect("DNS status")
                    .stored_admission_tombstones,
                1
            );
            assert_eq!(membership_size(), 1);
        }
        assert_eq!(census.sample().sequence_end, before.sequence_end);
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(1)),
        );
        let endpoint = Arc::downgrade(&cluster.endpoints()[0]);
        let generation = cluster.membership.lock().expect("membership").generation;
        let before = census.sample();
        tokio::time::advance(Duration::from_secs(2)).await;
        for _ in 0..100 {
            let status = cluster.observed_discovery_status().expect("DNS status");
            assert_eq!(status.endpoint_count, 0);
            assert_eq!(status.eligible_endpoints, 0);
            assert_eq!(status.resolution, DiscoveryResolutionState::Expired);
            assert_eq!(status.generation, generation);
        }
        assert_eq!(census.sample().sequence_end, before.sequence_end);
        assert!(
            endpoint.upgrade().is_some(),
            "read projection does not perform retirement"
        );
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert!(
            endpoint.upgrade().is_none(),
            "the existing lease linearization path performs maintenance"
        );
        assert_eq!(census_count(&census, ResourceKind::Endpoint).live, 0);
        assert_eq!(
            census_count(&census, ResourceKind::EndpointAdmission).live,
            0
        );
        let row = census_count(&census, ResourceKind::DiscoveryLease);
        assert_eq!(row.created, row.destroyed);
        assert_eq!(row.live, 0);
        drop(cluster);
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test]
    async fn passive_retired_admission_projects_actual_permits_not_weak_slot_or_object_existence() {
        let census = Arc::new(ResourceCensus::default());
        let cluster = PreparedCluster::prepare_in(dynamic_spec(), None, Arc::clone(&census)).0;
        cluster.observe_publication();
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let lease = cluster.acquire().await.expect("actual physical permit");
        let held_view = Arc::clone(lease.endpoint());
        let physical = Arc::downgrade(&held_view.state.admission);
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        let status = cluster
            .observed_discovery_status()
            .expect("held retired status");
        assert_eq!(
            (
                status.retired_admission_counters,
                status.stored_admission_tombstones
            ),
            (1, 1)
        );
        drop(lease);
        assert!(
            physical.upgrade().is_some(),
            "the deliberately held endpoint still owns its now-idle family"
        );
        let generation = cluster.membership.lock().expect("membership").generation;
        let before = census.sample();
        for _ in 0..100 {
            let status = cluster
                .observed_status(Instant::now())
                .discovery
                .expect("pure retired status");
            assert_eq!(
                (
                    status.retired_admission_counters,
                    status.stored_admission_tombstones
                ),
                (0, 1)
            );
            assert_eq!(status.generation, generation);
            assert_eq!(
                cluster
                    .membership
                    .lock()
                    .expect("membership")
                    .admission_counters
                    .len(),
                1
            );
        }
        assert_eq!(census.sample().sequence_end, before.sequence_end);
        drop(held_view);
        assert!(
            physical.upgrade().is_none(),
            "the observer did not retain its temporary read borrow"
        );
        assert_eq!(
            census_count(&census, ResourceKind::EndpointAdmission).live,
            0
        );
        let status = cluster
            .observed_discovery_status()
            .expect("fully released status");
        assert_eq!(
            (
                status.retired_admission_counters,
                status.stored_admission_tombstones
            ),
            (0, 1)
        );
        // The existing owner/lease path may perform maintenance later; pure
        // status was not required for release and did not remove bookkeeping.
        drop(cluster.endpoints());
        let status = cluster
            .observed_discovery_status()
            .expect("maintained status");
        assert_eq!(
            (
                status.retired_admission_counters,
                status.stored_admission_tombstones
            ),
            (0, 0)
        );
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test]
    async fn retained_observation_scalar_cannot_keep_the_real_admission_family_alive() {
        let census = Arc::new(ResourceCensus::default());
        let cluster = PreparedCluster::prepare_in(dynamic_spec(), None, Arc::clone(&census)).0;
        cluster.observe_publication();
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let lease = cluster.acquire().await.expect("real business permit");
        let target = lease.dial_target().expect("validated physical address");
        let counter = Arc::downgrade(&lease.endpoint().state.admission);
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        let scalar = cluster
            .membership
            .lock()
            .expect("membership")
            .admission_counters[&target]
            .active
            .upgrade()
            .expect("observer can read scalar metadata");
        assert!(
            Arc::ptr_eq(&scalar, &lease.endpoint().state.admission.active),
            "this is the business CAS atomic, not a mirrored admission state"
        );
        let scalar_weak = Arc::downgrade(&scalar);
        assert_eq!(scalar.load(Ordering::Acquire), 1);
        drop(lease);
        assert_eq!(
            scalar.load(Ordering::Acquire),
            0,
            "the actual permit Drop updates the same scalar"
        );
        assert!(
            counter.upgrade().is_none(),
            "an indefinitely retained scalar does not retain Counter/Endpoint/permit"
        );
        let family = census_count(&census, ResourceKind::EndpointAdmission);
        assert_eq!((family.created, family.destroyed, family.live), (1, 1, 0));
        let generation = cluster.membership.lock().expect("membership").generation;
        let before = census.sample();
        for _ in 0..1000 {
            let status = cluster.observed_discovery_status().expect("pure status");
            assert_eq!(
                (
                    status.retired_admission_counters,
                    status.stored_admission_tombstones
                ),
                (0, 1)
            );
            assert_eq!(status.generation, generation);
            assert_eq!(
                cluster
                    .membership
                    .lock()
                    .expect("membership")
                    .admission_counters
                    .len(),
                1
            );
        }
        assert_eq!(census.sample().sequence_end, before.sequence_end);
        assert!(counter.upgrade().is_none());
        drop(scalar);
        assert!(
            scalar_weak.upgrade().is_none(),
            "the weak bookkeeping also cannot retain scalar metadata"
        );
        drop(cluster);
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test]
    async fn removal_readdition_and_late_query_observe_real_lifetimes_without_retaining_owner() {
        let census = Arc::new(ResourceCensus::default());
        let cluster =
            Arc::new(PreparedCluster::prepare_in(dynamic_spec(), None, Arc::clone(&census)).0);
        cluster.observe_publication();
        assert!(cluster.activate_discovery_policy());
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let lease = cluster.acquire().await.expect("held old endpoint");
        let original = lease.endpoint().incarnation();
        observe(&cluster, DnsFamily::A, DnsObservation::NoData);
        observe(
            &cluster,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        assert_ne!(cluster.endpoints()[0].incarnation(), original);
        assert_eq!(census_count(&census, ResourceKind::Endpoint).live, 2);
        assert_eq!(
            census_count(&census, ResourceKind::EndpointAdmission).live,
            1,
            "actual socket admission survives a held old lease"
        );
        assert_eq!(
            census_state(&census, ResourceKind::Endpoint, ResourceState::Current),
            1
        );
        assert_eq!(
            census_state(&census, ResourceKind::Endpoint, ResourceState::Retired),
            1
        );
        let query = cluster.begin_discovery_query().expect("late query");
        cluster.retire_discovery_policy();
        assert!(
            !cluster
                .reconcile_dns(
                    &query,
                    DnsFamily::A,
                    positive(&["198.51.100.2"], Duration::from_secs(60)),
                    tokio::time::Instant::now()
                )
                .applied
        );
        assert_eq!(census_count(&census, ResourceKind::Endpoint).live, 1);
        let weak = Arc::downgrade(&cluster);
        drop(cluster);
        assert!(
            weak.upgrade().is_none(),
            "query lease and observer do not retain the Cluster"
        );
        assert_eq!(
            census_count(&census, ResourceKind::DiscoveryLease).live,
            1,
            "actual outstanding round is not faked complete by retirement"
        );
        drop((lease, query));
        for kind in [
            ResourceKind::Cluster,
            ResourceKind::ClusterRuntime,
            ResourceKind::Endpoint,
            ResourceKind::EndpointAdmission,
            ResourceKind::DiscoveryLease,
            ResourceKind::ClusterPermit,
            ResourceKind::EndpointPermit,
        ] {
            let row = census_count(&census, kind);
            assert_eq!(row.created, row.destroyed);
            assert_eq!(row.live, 0);
        }
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

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
            port: Some(8080),
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

    fn srv_spec(policy: LoadBalancePolicy) -> ClusterSpec {
        let mut spec = dynamic_spec();
        spec.load_balance = policy;
        let plan = spec.discovery.as_mut().expect("dynamic plan");
        plan.name = "_http._tcp.service.example.test.".to_owned();
        plan.record = DnsRecordType::Srv;
        plan.port = None;
        spec.health
            .active
            .as_mut()
            .expect("health")
            .healthy_threshold = 1;
        spec.health
            .active
            .as_mut()
            .expect("health")
            .unhealthy_threshold = 1;
        spec
    }

    fn srv(policy: LoadBalancePolicy) -> PreparedCluster {
        let cluster = PreparedCluster::prepare(srv_spec(policy), None).0;
        assert!(cluster.activate_discovery_policy());
        cluster.membership.lock().expect("fixture lock").srv_random = SrvSelectionRng::new(5);
        cluster
    }

    fn srv_record(target: &str, port: u16, priority: u16, weight: u16, ttl: u64) -> SrvRecord {
        SrvRecord {
            target: target.to_owned(),
            port,
            priority,
            weight,
            fresh_until: tokio::time::Instant::now() + Duration::from_secs(ttl),
        }
    }

    fn srv_addresses(
        target: &str,
        family: DnsFamily,
        addresses: &[&str],
        ttl: u64,
    ) -> SrvTargetAddressObservation {
        SrvTargetAddressObservation {
            target: target.to_owned(),
            family,
            observation: positive(addresses, Duration::from_secs(ttl)),
        }
    }

    fn srv_failure(
        target: &str,
        family: DnsFamily,
        observation: DnsObservation,
    ) -> SrvTargetAddressObservation {
        SrvTargetAddressObservation {
            target: target.to_owned(),
            family,
            observation,
        }
    }

    fn observe_srv(
        cluster: &PreparedCluster,
        observation: SrvObservation,
    ) -> DiscoveryReconcileOutcome {
        let query = cluster.begin_discovery_query().expect("single query slot");
        cluster.reconcile_srv(&query, observation, tokio::time::Instant::now())
    }

    fn srv_positive(
        cluster: &PreparedCluster,
        records: Vec<SrvRecord>,
        addresses: Vec<SrvTargetAddressObservation>,
    ) -> DiscoveryReconcileOutcome {
        observe_srv(cluster, SrvObservation::Positive { records, addresses })
    }

    #[tokio::test(start_paused = true)]
    async fn srv_weight_is_per_logical_target_not_amplified_by_address_count() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        srv_positive(
            &cluster,
            vec![
                srv_record("one.test.", 8080, 0, 1, 60),
                srv_record("three.test.", 8080, 0, 1, 60),
            ],
            vec![
                srv_addresses("one.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses(
                    "three.test.",
                    DnsFamily::A,
                    &["198.51.100.2", "198.51.100.3", "198.51.100.4"],
                    60,
                ),
            ],
        );
        let mut one = 0;
        let mut three = 0;
        let mut physical = BTreeSet::new();
        for _ in 0..4096 {
            let lease = cluster.acquire().await.expect("healthy group");
            match lease.endpoint().logical_target() {
                Some("one.test.") => one += 1,
                Some("three.test.") => three += 1,
                target => panic!("unexpected logical target {target:?}"),
            }
            physical.insert(lease.dial_target().expect("fixed address"));
            assert_eq!(
                lease.endpoint().url().as_str(),
                "http://service.example.test/base"
            );
        }
        assert!(
            one > 1500 && three > 1500,
            "three IPs do not triple target weight: {one}/{three}"
        );
        assert_eq!(
            physical.len(),
            4,
            "address RR reaches every physical address"
        );
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_lowest_healthy_priority_is_not_bypassed_by_saturation_or_retry_exclusion() {
        let mut spec = srv_spec(LoadBalancePolicy::LeastRequests);
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        srv_positive(
            &cluster,
            vec![
                srv_record("primary.test.", 8080, 10, 1, 60),
                srv_record("backup.test.", 8080, 20, 65535, 60),
            ],
            vec![
                srv_addresses("primary.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("backup.test.", DnsFamily::A, &["198.51.100.2"], 60),
            ],
        );
        let held = cluster.acquire().await.expect("primary");
        let primary = Arc::clone(held.endpoint());
        assert_eq!(primary.logical_target(), Some("primary.test."));
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        let tried = BTreeSet::from([primary.name().to_owned()]);
        assert!(
            cluster
                .reserve_retry_endpoint_for(&tried, &primary)
                .await
                .is_none()
        );
        assert!(
            cluster
                .select_endpoint_excluding(Instant::now(), &tried)
                .is_none()
        );
        cluster.record_active_health_for(&primary, false, Instant::now());
        assert_eq!(
            cluster
                .acquire()
                .await
                .expect("unhealthy primary allows backup")
                .endpoint()
                .logical_target(),
            Some("backup.test.")
        );
        cluster.record_active_health_for(&primary, true, Instant::now());
        assert_eq!(
            cluster
                .discovery_status()
                .expect("status")
                .eligible_priority,
            Some(10)
        );
        assert!(
            matches!(
                cluster.acquire().await,
                Err(ClusterAdmissionError::Overloaded)
            ),
            "recovered but held primary still cannot bypass quota"
        );
        drop(held);
        assert_eq!(
            cluster
                .acquire()
                .await
                .expect("recovered primary")
                .endpoint()
                .logical_target(),
            Some("primary.test.")
        );
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_equal_priority_can_use_another_unsaturated_target_but_never_backup() {
        let mut spec = srv_spec(LoadBalancePolicy::RoundRobin);
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 0, 60),
                srv_record("b.test.", 8080, 0, 0, 60),
                srv_record("backup.test.", 8080, 1, 65535, 60),
            ],
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("b.test.", DnsFamily::A, &["198.51.100.2"], 60),
                srv_addresses("backup.test.", DnsFamily::A, &["198.51.100.3"], 60),
            ],
        );
        let first = cluster.acquire().await.expect("first equal priority");
        let second = cluster
            .acquire()
            .await
            .expect("other equal priority target");
        assert_ne!(
            first.endpoint().logical_target(),
            second.endpoint().logical_target()
        );
        assert_ne!(first.endpoint().logical_target(), Some("backup.test."));
        assert_ne!(second.endpoint().logical_target(), Some("backup.test."));
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        drop((first, second));
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_address_lb_is_applied_only_inside_selected_target() {
        for policy in [
            LoadBalancePolicy::RoundRobin,
            LoadBalancePolicy::WeightedRoundRobin,
            LoadBalancePolicy::LeastRequests,
        ] {
            let cluster = srv(policy);
            srv_positive(
                &cluster,
                vec![srv_record("same.test.", 8080, 0, 65535, 60)],
                vec![srv_addresses(
                    "same.test.",
                    DnsFamily::A,
                    &["198.51.100.3", "198.51.100.1", "198.51.100.2"],
                    60,
                )],
            );
            let first = cluster.acquire().await.expect("first IP");
            let second = cluster.acquire().await.expect("second IP");
            let third = cluster.acquire().await.expect("third IP");
            assert_eq!(
                BTreeSet::from([
                    first.dial_target(),
                    second.dial_target(),
                    third.dial_target()
                ])
                .len(),
                3,
                "per-target policy {policy:?}"
            );
            drop((first, second, third));
            assert_eq!(cluster.active_requests(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn srv_rr_reordering_and_ttl_reuse_incarnations_but_policy_updates_change_selection() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        let addresses = || {
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("b.test.", DnsFamily::A, &["198.51.100.2"], 60),
            ]
        };
        let initial = srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 20),
                srv_record("b.test.", 8080, 0, 2, 20),
            ],
            addresses(),
        );
        let first = cluster.endpoints();
        let a = Arc::clone(&first[0]);
        cluster.record_passive_failure_for(&a, Instant::now());
        let reordered = srv_positive(
            &cluster,
            vec![
                srv_record("b.test.", 8080, 0, 2, 60),
                srv_record("A.TEST", 8080, 0, 1, 60),
            ],
            addresses(),
        );
        assert_eq!(initial.generation, reordered.generation);
        assert!(
            first
                .iter()
                .zip(cluster.endpoints().iter())
                .all(|(a, b)| Arc::ptr_eq(a, b))
        );
        let updated = srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 10, 65535, 60),
                srv_record("b.test.", 8080, 20, 0, 60),
            ],
            addresses(),
        );
        assert!(updated.generation > reordered.generation);
        assert!(
            first
                .iter()
                .zip(cluster.endpoints().iter())
                .all(|(a, b)| Arc::ptr_eq(a, b))
        );
        assert_eq!(a.incarnation(), cluster.endpoints()[0].incarnation());
        assert_eq!(a.runtime_state().failures.load(Ordering::Relaxed), 1);
        assert_eq!(
            cluster
                .discovery_status()
                .expect("status")
                .eligible_priority,
            Some(10)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn srv_same_target_multiple_priorities_share_one_physical_state() {
        let mut spec = srv_spec(LoadBalancePolicy::RoundRobin);
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("a.test.", 8080, 10, 2, 60),
            ],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        assert_eq!(cluster.endpoints().len(), 1);
        assert_eq!(
            cluster
                .discovery_status()
                .expect("groups")
                .srv_targets
                .len(),
            2
        );
        let held = cluster.acquire().await.expect("one endpoint");
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        drop(held);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_target_and_port_are_identity_but_same_physical_aliases_share_admission() {
        let mut spec = srv_spec(LoadBalancePolicy::RoundRobin);
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("alias.test.", 8080, 0, 1, 60),
            ],
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("alias.test.", DnsFamily::A, &["198.51.100.1"], 60),
            ],
        );
        let old = cluster.endpoints();
        assert_eq!(old.len(), 2);
        assert_ne!(old[0].incarnation(), old[1].incarnation());
        let held = cluster.acquire().await.expect("shared socket admission");
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 9090, 0, 1, 60)],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        let new = cluster
            .acquire()
            .await
            .expect("new physical port independent");
        assert_eq!(new.dial_target().expect("new dial").port(), 9090);
        assert!(
            old.iter()
                .all(|old| old.incarnation() != new.endpoint().incarnation())
        );
        assert_eq!(
            new.endpoint().url(),
            held.endpoint().url(),
            "logical origin is not SRV port"
        );
        drop((held, new));
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_target_nxdomain_revokes_both_families_order_independently_and_not_other_targets() {
        for reversed in [false, true] {
            let cluster = srv(LoadBalancePolicy::RoundRobin);
            let records = || {
                vec![
                    srv_record("a.test.", 8080, 0, 1, 60),
                    srv_record("b.test.", 8080, 0, 1, 60),
                ]
            };
            srv_positive(
                &cluster,
                records(),
                vec![
                    srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                    srv_addresses("a.test.", DnsFamily::Aaaa, &["2001:db8::1"], 60),
                    srv_addresses("b.test.", DnsFamily::A, &["198.51.100.2"], 60),
                ],
            );
            let mut observations = vec![
                srv_failure("a.test.", DnsFamily::A, DnsObservation::NameNotFound),
                srv_addresses("a.test.", DnsFamily::Aaaa, &["2001:db8::2"], 60),
            ];
            if reversed {
                observations.reverse();
            }
            srv_positive(&cluster, records(), observations);
            assert_eq!(cluster.endpoints().len(), 1);
            assert_eq!(
                cluster
                    .acquire()
                    .await
                    .expect("other target retained")
                    .endpoint()
                    .logical_target(),
                Some("b.test.")
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn srv_family_nodata_does_not_erase_sibling_and_duplicate_observations_fail_closed() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        let records = || vec![srv_record("a.test.", 8080, 0, 1, 60)];
        srv_positive(
            &cluster,
            records(),
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("a.test.", DnsFamily::Aaaa, &["2001:db8::1"], 60),
            ],
        );
        srv_positive(
            &cluster,
            records(),
            vec![srv_failure("a.test.", DnsFamily::A, DnsObservation::NoData)],
        );
        assert_eq!(cluster.endpoints().len(), 1);
        assert!(
            cluster
                .acquire()
                .await
                .expect("AAAA stays")
                .dial_target()
                .expect("IP")
                .is_ipv6()
        );
        let receipt = srv_positive(
            &cluster,
            records(),
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.2"], 60),
            ],
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::InvalidAnswer)
        );
        assert!(cluster.endpoints().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn srv_dot_and_service_nxdomain_fence_same_round_and_never_resurrect_stale() {
        for withdrawal in [
            SrvObservation::ServiceUnavailable,
            SrvObservation::NameNotFound,
            SrvObservation::Positive {
                records: vec![srv_record(".", 8080, 0, 0, 60)],
                addresses: Vec::new(),
            },
        ] {
            let cluster = srv(LoadBalancePolicy::RoundRobin);
            srv_positive(
                &cluster,
                vec![srv_record("a.test.", 8080, 0, 1, 60)],
                vec![srv_addresses(
                    "a.test.",
                    DnsFamily::A,
                    &["198.51.100.1"],
                    60,
                )],
            );
            let held = cluster.acquire().await.expect("old stream");
            let query = cluster.begin_discovery_query().expect("refresh");
            assert!(
                cluster
                    .reconcile_srv(&query, withdrawal, tokio::time::Instant::now())
                    .applied
            );
            assert!(
                !cluster
                    .reconcile_srv(
                        &query,
                        SrvObservation::Positive {
                            records: vec![srv_record("a.test.", 8080, 0, 1, 60)],
                            addresses: vec![srv_addresses(
                                "a.test.",
                                DnsFamily::A,
                                &["198.51.100.1"],
                                60
                            )]
                        },
                        tokio::time::Instant::now()
                    )
                    .applied
            );
            drop(query);
            observe_srv(
                &cluster,
                SrvObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout,
                },
            );
            assert!(matches!(
                cluster.acquire().await,
                Err(ClusterAdmissionError::Unavailable)
            ));
            assert_eq!(
                held.dial_target(),
                Some("198.51.100.1:8080".parse().expect("held target"))
            );
            drop(held);
            assert_eq!(cluster.active_requests(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn srv_duplicate_rr_uses_shortest_ttl_and_conflicting_weight_is_rejected() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        let receipt = srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("A.TEST", 8080, 0, 1, 1),
            ],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        assert_eq!(receipt.endpoint_count, 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        let receipt = srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("a.test.", 8080, 0, 2, 60),
            ],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::InvalidAnswer)
        );
        assert!(cluster.endpoints().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn srv_and_address_expiry_each_require_their_own_stale_authority() {
        // An SRV-only failure cannot extend an expired address, and a target
        // failure cannot extend a successfully observed but now expired SRV RR.
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 1)],
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        observe_srv(
            &cluster,
            SrvObservation::TransientFailure {
                code: DiscoveryErrorCode::Refused,
            },
        );
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));

        let cluster = srv(LoadBalancePolicy::RoundRobin);
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 1)],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 1)],
            vec![srv_failure(
                "a.test.",
                DnsFamily::A,
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout,
                },
            )],
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn srv_stale_is_bounded_by_each_original_component_deadline_not_latest_failure() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 5)],
            vec![srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 2)],
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        // A successful SRV refresh cannot extend the original failed address.
        let receipt = srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_failure(
                "a.test.",
                DnsFamily::A,
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Refused,
                },
            )],
        );
        assert!(
            !receipt.positive_rejected,
            "a failed target family does not invalidate successful service records"
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::Refused)
        );
        assert!(cluster.acquire().await.is_ok());
        tokio::time::advance(Duration::from_secs(9)).await;
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_failure(
                "a.test.",
                DnsFamily::A,
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout,
                },
            )],
        );
        assert!(cluster.acquire().await.is_ok());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(
            matches!(
                cluster.acquire().await,
                Err(ClusterAdmissionError::Unavailable)
            ),
            "original address 2s + 10s grace has expired"
        );
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_zero_ttl_and_duplicate_zero_ttl_never_seed_stale() {
        let cluster = srv(LoadBalancePolicy::RoundRobin);
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 1)],
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("a.test.", 8080, 0, 1, 0),
            ],
            vec![srv_failure(
                "a.test.",
                DnsFamily::A,
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout,
                },
            )],
        );
        observe_srv(
            &cluster,
            SrvObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout,
            },
        );
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert!(cluster.endpoints().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn dynamic_policy_replacement_retains_only_held_physical_admission_not_old_health() {
        let mut initial = dynamic_spec();
        initial.limits.max_in_flight_per_endpoint = 1;
        let old = PreparedCluster::prepare(initial.clone(), None).0;
        assert!(old.activate_discovery_policy());
        observe(
            &old,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let held = old.acquire().await.expect("old permit");
        let old_endpoint = Arc::clone(held.endpoint());
        old.record_passive_failure_for(&old_endpoint, Instant::now());
        let mut changed = initial;
        changed.discovery.as_mut().expect("plan").origin =
            "http://changed.test/base".parse().expect("origin");
        changed
            .discovery
            .as_mut()
            .expect("plan")
            .refresh
            .min_interval = Duration::from_secs(2);
        let new = PreparedCluster::prepare(changed.clone(), Some(&old)).0;
        assert!(new.activate_discovery_policy());
        observe(
            &new,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        let new_endpoint = Arc::clone(&new.endpoints()[0]);
        assert!(!Arc::ptr_eq(&old_endpoint, &new_endpoint));
        assert_ne!(old_endpoint.incarnation(), new_endpoint.incarnation());
        assert_eq!(
            new_endpoint
                .runtime_state()
                .failures
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(new_endpoint.url().host_str(), Some("changed.test"));
        assert!(matches!(
            new.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        changed.discovery.as_mut().expect("plan").port = Some(9090);
        let other_port = PreparedCluster::prepare(changed, Some(&new)).0;
        assert!(other_port.activate_discovery_policy());
        observe(
            &other_port,
            DnsFamily::A,
            positive(&["198.51.100.1"], Duration::from_secs(60)),
        );
        assert_eq!(
            other_port
                .acquire()
                .await
                .expect("different physical port")
                .dial_target()
                .expect("dial")
                .port(),
            9090
        );
        drop(held);
        assert!(new.acquire().await.is_ok());
        assert_eq!(new.active_requests(), 0);
        assert_eq!(old_endpoint.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_quota_rejections_return_received_round_codes_and_cannot_use_old_membership() {
        let mut spec = srv_spec(LoadBalancePolicy::RoundRobin);
        spec.discovery.as_mut().expect("plan").limits.max_endpoints = 1;
        spec.discovery.as_mut().expect("plan").limits.max_targets = 2;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        let receipt = srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        assert_eq!(receipt.endpoint_count, 1);
        let held = cluster.acquire().await.expect("existing request");
        let receipt = srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![
                srv_addresses("a.test.", DnsFamily::A, &["198.51.100.1"], 60),
                srv_addresses("a.test.", DnsFamily::Aaaa, &["2001:db8::1"], 60),
            ],
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::LimitExceeded)
        );
        assert!(
            receipt.positive_rejected,
            "the merged membership exceeded the complete round quota"
        );
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert_eq!(
            held.dial_target(),
            Some("198.51.100.1:8080".parse().expect("held address"))
        );
        let receipt = srv_positive(
            &cluster,
            vec![
                srv_record("a.test.", 8080, 0, 1, 60),
                srv_record("b.test.", 8080, 0, 1, 60),
            ],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::LimitExceeded),
            "service name plus distinct target names are bounded"
        );
        let receipt = srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60); 513],
            Vec::new(),
        );
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::LimitExceeded)
        );
        drop(held);
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn srv_removed_target_readdition_has_fresh_health_and_pool_identity_not_fresh_quota() {
        let mut spec = srv_spec(LoadBalancePolicy::RoundRobin);
        spec.limits.max_in_flight_per_endpoint = 1;
        let cluster = PreparedCluster::prepare(spec, None).0;
        assert!(cluster.activate_discovery_policy());
        let records = || vec![srv_record("a.test.", 8080, 0, 1, 60)];
        let addresses = || {
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )]
        };
        srv_positive(&cluster, records(), addresses());
        let held = cluster.acquire().await.expect("long request");
        let old = Arc::clone(held.endpoint());
        let generation = held.generation();
        observe_srv(&cluster, SrvObservation::NoData);
        assert!(cluster.endpoints().is_empty());
        srv_positive(&cluster, records(), addresses());
        let new = Arc::clone(&cluster.endpoints()[0]);
        assert_ne!(new.incarnation(), old.incarnation());
        assert!(cluster.discovery_status().expect("status").generation > generation);
        cluster.record_active_health_for(&old, false, Instant::now());
        cluster.record_passive_failure_for(&old, Instant::now());
        assert_eq!(new.runtime_state().failures.load(Ordering::Relaxed), 0);
        assert_eq!(
            new.runtime_state().health_state(Instant::now()),
            EndpointHealthState::UnknownEligible
        );
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Overloaded)
        ));
        assert!(!cluster.contains_endpoint(&old));
        drop(held);
        assert!(cluster.acquire().await.is_ok());
        assert_eq!(cluster.active_requests(), 0);
    }

    #[tokio::test]
    async fn srv_concurrent_retirement_linearizes_new_leases_without_revoking_old_permits() {
        let cluster = Arc::new(srv(LoadBalancePolicy::LeastRequests));
        srv_positive(
            &cluster,
            vec![srv_record("a.test.", 8080, 0, 1, 60)],
            vec![srv_addresses(
                "a.test.",
                DnsFamily::A,
                &["198.51.100.1"],
                60,
            )],
        );
        let old = cluster.acquire().await.expect("existing stream");
        let start = Arc::new(std::sync::Barrier::new(9));
        let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let workers = (0..8)
            .map(|_| {
                let cluster = Arc::clone(&cluster);
                let start = Arc::clone(&start);
                let revoked = Arc::clone(&revoked);
                std::thread::spawn(move || {
                    start.wait();
                    for _ in 0..128 {
                        let was_revoked = revoked.load(Ordering::Acquire);
                        let result = cluster.try_acquire_endpoint(&BTreeSet::new(), Instant::now());
                        if was_revoked {
                            assert!(matches!(result, EndpointAcquire::Unavailable));
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        cluster.retire_discovery_policy();
        revoked.store(true, Ordering::Release);
        for worker in workers {
            worker.join().expect("lease worker");
        }
        assert!(matches!(
            cluster.acquire().await,
            Err(ClusterAdmissionError::Unavailable)
        ));
        assert_eq!(
            cluster.active_requests(),
            1,
            "old stream permit remains valid"
        );
        drop(old);
        assert_eq!(cluster.active_requests(), 0);
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
