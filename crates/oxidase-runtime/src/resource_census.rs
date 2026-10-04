//! Passive process resource census. Tokens never hold the resource they observe.
//!
//! Creation and final destruction are distinct from Arc clones, retirement and
//! cancellation requests. Samples span multiple atomics, not a global transaction.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;

use serde::Serialize;

/// Fixed units only: never an epoch, endpoint address, request or resource name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum ResourceKind {
    SnapshotPreparation,
    Snapshot,
    Cluster,
    ClusterRuntime,
    Endpoint,
    EndpointAdmission,
    DiscoveryLease,
    ClusterPermit,
    EndpointPermit,
    RetryPermit,
    HealthSupervisor,
    HealthProbe,
    DiscoverySupervisor,
    DiscoveryRound,
    DnsQuery,
    DnsFailureMemo,
    ProxyPoolEntry,
    HealthPoolEntry,
    ProxyPoolFamily,
    HealthPoolFamily,
    UpstreamTcpConnection,
    UpstreamTlsConnection,
    UpstreamConnectAttempt,
    UpstreamTlsHandshake,
    WarmSocketSlot,
    WarmExpiryTask,
    UpstreamTask,
    UpstreamUploadTask,
    DispatchRetirementTask,
    ResponseBody,
    Tunnel,
}

impl ResourceKind {
    pub const ALL: [Self; 31] = [
        Self::SnapshotPreparation,
        Self::Snapshot,
        Self::Cluster,
        Self::ClusterRuntime,
        Self::Endpoint,
        Self::EndpointAdmission,
        Self::DiscoveryLease,
        Self::ClusterPermit,
        Self::EndpointPermit,
        Self::RetryPermit,
        Self::HealthSupervisor,
        Self::HealthProbe,
        Self::DiscoverySupervisor,
        Self::DiscoveryRound,
        Self::DnsQuery,
        Self::DnsFailureMemo,
        Self::ProxyPoolEntry,
        Self::HealthPoolEntry,
        Self::ProxyPoolFamily,
        Self::HealthPoolFamily,
        Self::UpstreamTcpConnection,
        Self::UpstreamTlsConnection,
        Self::UpstreamConnectAttempt,
        Self::UpstreamTlsHandshake,
        Self::WarmSocketSlot,
        Self::WarmExpiryTask,
        Self::UpstreamTask,
        Self::UpstreamUploadTask,
        Self::DispatchRetirementTask,
        Self::ResponseBody,
        Self::Tunnel,
    ];

    const fn detailed(self) -> bool {
        matches!(
            self,
            Self::Snapshot
                | Self::Cluster
                | Self::Endpoint
                | Self::ProxyPoolFamily
                | Self::HealthPoolFamily
                | Self::HealthSupervisor
                | Self::DiscoverySupervisor
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum ResourceState {
    Candidate,
    Current,
    Live,
    Scheduled,
    Running,
    Waiting,
    Exiting,
    Retired,
}

impl ResourceState {
    pub const ALL: [Self; 8] = [
        Self::Candidate,
        Self::Current,
        Self::Live,
        Self::Scheduled,
        Self::Running,
        Self::Waiting,
        Self::Exiting,
        Self::Retired,
    ];
}

#[derive(Debug, Default)]
struct Counters {
    created: AtomicU64,
    destroyed: AtomicU64,
    live: AtomicU64,
    published: AtomicU64,
    states: [AtomicU64; 8],
    untracked_live: AtomicU64,
}

/// Process observation only, never publication or resource ownership authority.
pub struct ResourceCensus {
    enabled: bool,
    started: Instant,
    sequence: AtomicU64,
    writers: AtomicU64,
    next_id: AtomicU64,
    invariant_failures: AtomicU64,
    counters: [Counters; 31],
    // Weak references to scalar observation metadata, NOT resources. Entries
    // leave on the actual token Drop; sample performs no sweep or maintenance.
    details: Mutex<BTreeMap<u64, Weak<Record>>>,
}

impl fmt::Debug for ResourceCensus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceCensus")
            .field("enabled", &self.enabled)
            .field(
                "invariant_failures",
                &self.invariant_failures.load(Ordering::Relaxed),
            )
            .field("detail_capacity", &MAX_DETAILS)
            .finish_non_exhaustive()
    }
}

const MAX_DETAILS: usize = 4096;

impl Default for ResourceCensus {
    fn default() -> Self {
        Self::new(true)
    }
}

impl ResourceCensus {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            started: Instant::now(),
            sequence: AtomicU64::new(0),
            writers: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            invariant_failures: AtomicU64::new(0),
            counters: std::array::from_fn(|_| Counters::default()),
            details: Mutex::new(BTreeMap::new()),
        }
    }

    /// Internal validation switch only. Disabled observations are unavailable,
    /// not fabricated zero measurements. No runtime contract depends on this.
    #[must_use]
    pub fn process() -> Arc<Self> {
        static PROCESS: OnceLock<Arc<ResourceCensus>> = OnceLock::new();
        Arc::clone(PROCESS.get_or_init(|| {
            Arc::new(Self::new(
                std::env::var_os("OXIDASE_RESOURCE_OBSERVATION").as_deref()
                    != Some(std::ffi::OsStr::new("off")),
            ))
        }))
    }

    #[must_use]
    pub fn token(self: &Arc<Self>, kind: ResourceKind, state: ResourceState) -> ResourceToken {
        ResourceToken::new(Arc::clone(self), kind, state)
    }

    fn add(&self, value: &AtomicU64) {
        if !checked_change(value, true) {
            self.invariant_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    fn subtract(&self, value: &AtomicU64) {
        if !checked_change(value, false) {
            self.invariant_failures.fetch_add(1, Ordering::Relaxed);
        }
        self.sequence.fetch_add(1, Ordering::Release);
    }

    #[must_use]
    pub fn sample(&self) -> ResourceSample {
        let start_ms = millis(self.started.elapsed().as_millis());
        let sequence_start = self.sequence.load(Ordering::Acquire);
        let mutations_in_flight_start = self.writers.load(Ordering::Acquire);
        let now = Instant::now();
        let mut oldest = [None::<u64>; 31];
        let mut oldest_exiting = [None::<u64>; 31];
        let details = self
            .details
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for record in details.values().filter_map(Weak::upgrade) {
            let state = record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.alive
                && let Some(retired) = state.retired_at
            {
                let age = millis(now.saturating_duration_since(retired).as_millis());
                let entry = &mut oldest[record.kind as usize];
                *entry = Some(entry.map_or(age, |old| old.max(age)));
            }
            if state.alive
                && let Some(exiting) = state.exiting_at
            {
                let age = millis(now.saturating_duration_since(exiting).as_millis());
                let entry = &mut oldest_exiting[record.kind as usize];
                *entry = Some(entry.map_or(age, |old| old.max(age)));
            }
        }
        let detailed_records = details.len();
        drop(details);
        let resources = if self.enabled {
            ResourceKind::ALL
                .into_iter()
                .map(|kind| {
                    let counter = &self.counters[kind as usize];
                    let untracked = counter.untracked_live.load(Ordering::Relaxed);
                    ResourceCount {
                        kind,
                        created: counter.created.load(Ordering::Relaxed),
                        destroyed: counter.destroyed.load(Ordering::Relaxed),
                        live: counter.live.load(Ordering::Relaxed),
                        published: counter.published.load(Ordering::Relaxed),
                        states: ResourceState::ALL
                            .into_iter()
                            .map(|state| StateCount {
                                state,
                                live: counter.states[state as usize].load(Ordering::Relaxed),
                            })
                            .collect(),
                        age_supported: kind.detailed(),
                        detail_untracked_live: untracked,
                        oldest_retired_age_ms: if kind.detailed() && untracked == 0 {
                            // Complete tracked set with no retired instance is zero age.
                            Some(oldest[kind as usize].unwrap_or(0))
                        } else {
                            None
                        },
                        oldest_exiting_age_ms: if kind.detailed() && untracked == 0 {
                            Some(oldest_exiting[kind as usize].unwrap_or(0))
                        } else {
                            None
                        },
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        let sequence_end = self.sequence.load(Ordering::Acquire);
        let mutations_in_flight_end = self.writers.load(Ordering::Acquire);
        let invariant_failures = self.invariant_failures.load(Ordering::Relaxed);
        let capture_end_ms = millis(self.started.elapsed().as_millis());
        ResourceSample {
            schema_version: "oxidase.resources/v1",
            enabled: self.enabled,
            capture_start_ms: start_ms,
            capture_end_ms,
            sequence_start,
            sequence_end,
            mutations_in_flight_start,
            mutations_in_flight_end,
            globally_atomic: false,
            invariant_failures,
            detailed_records,
            detail_capacity: MAX_DETAILS,
            resources,
        }
    }
}

fn millis(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn checked_change(counter: &AtomicU64, increment: bool) -> bool {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = if increment {
            current.checked_add(1)
        } else {
            current.checked_sub(1)
        };
        let Some(next) = next else {
            return false;
        };
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

fn claim_id(census: &ResourceCensus) -> Option<u64> {
    let mut current = census.next_id.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(1) else {
            census.invariant_failures.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        match census.next_id.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Some(current),
            Err(actual) => current = actual,
        }
    }
}

struct Mutation<'a>(&'a ResourceCensus);

impl<'a> Mutation<'a> {
    fn begin(census: &'a ResourceCensus) -> Self {
        census.writers.fetch_add(1, Ordering::AcqRel);
        census.sequence.fetch_add(1, Ordering::AcqRel);
        Self(census)
    }
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        self.0.sequence.fetch_add(1, Ordering::Release);
        if !checked_change(&self.0.writers, false) {
            self.0.invariant_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug)]
struct Record {
    id: Option<u64>,
    kind: ResourceKind,
    state: Mutex<RecordState>,
}

#[derive(Debug)]
struct RecordState {
    state: ResourceState,
    alive: bool,
    published: bool,
    retired_at: Option<Instant>,
    exiting_at: Option<Instant>,
}

/// One non-cloneable actual ownership unit. For a real handle clone family,
/// share `Arc<ResourceToken>`; for a distinct value clone, create a fresh token.
pub struct ResourceToken {
    census: Arc<ResourceCensus>,
    record: Option<Arc<Record>>,
    tracked: bool,
}

impl fmt::Debug for ResourceToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceToken")
            .field("kind", &self.record.as_ref().map(|record| record.kind))
            .field("state", &self.state())
            .field("tracked", &self.tracked)
            .finish_non_exhaustive()
    }
}

impl ResourceToken {
    #[must_use]
    pub fn new(census: Arc<ResourceCensus>, kind: ResourceKind, state: ResourceState) -> Self {
        if !census.enabled {
            return Self {
                census,
                record: None,
                tracked: false,
            };
        }
        let mutation = Mutation::begin(&census);
        let record = Arc::new(Record {
            id: claim_id(&census),
            kind,
            state: Mutex::new(RecordState {
                state,
                alive: true,
                published: false,
                retired_at: (state == ResourceState::Retired).then(Instant::now),
                exiting_at: (state == ResourceState::Exiting).then(Instant::now),
            }),
        });
        let mut tracked = false;
        if census.enabled {
            let counter = &census.counters[kind as usize];
            census.add(&counter.created);
            census.add(&counter.live);
            census.add(&counter.states[state as usize]);
            if kind.detailed() {
                let mut details = census
                    .details
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if details.len() < MAX_DETAILS
                    && let Some(id) = record.id
                {
                    details.insert(id, Arc::downgrade(&record));
                    tracked = true;
                } else {
                    census.add(&counter.untracked_live);
                }
            }
        }
        drop(mutation);
        Self {
            census,
            record: Some(record),
            tracked,
        }
    }

    #[must_use]
    pub fn census(&self) -> Arc<ResourceCensus> {
        Arc::clone(&self.census)
    }

    #[must_use]
    pub fn state(&self) -> ResourceState {
        self.record.as_ref().map_or(ResourceState::Live, |record| {
            record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .state
        })
    }

    pub fn transition(&self, next: ResourceState) {
        if let Some(record) = &self.record {
            transition(&self.census, record, next);
        }
    }

    /// Snapshot role is monotonic, even if a later publish's retirement hook
    /// runs before this object's delayed successful-publication hook.
    pub fn mark_current(&self) {
        if self.state() == ResourceState::Candidate {
            self.transition(ResourceState::Current);
        }
    }
    pub fn mark_retired(&self) {
        self.transition(ResourceState::Retired);
    }

    pub fn record_published_once(&self) {
        let Some(record) = &self.record else {
            return;
        };
        let _mutation = Mutation::begin(&self.census);
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.published && state.alive {
            state.published = true;
            if self.census.enabled {
                self.census
                    .add(&self.census.counters[record.kind as usize].published);
            }
        }
    }

    #[must_use]
    pub fn cancellation_handle(&self) -> ResourceCancellationHandle {
        ResourceCancellationHandle {
            census: Arc::clone(&self.census),
            record: self.record.as_ref().map_or_else(Weak::new, Arc::downgrade),
        }
    }
}

fn transition(census: &ResourceCensus, record: &Record, next: ResourceState) {
    let _mutation = Mutation::begin(census);
    let mut state = record
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !state.alive
        || state.state == next
        || (state.state == ResourceState::Retired && next != ResourceState::Retired)
        || (state.state == ResourceState::Exiting
            && !matches!(next, ResourceState::Retired | ResourceState::Exiting))
    {
        return;
    }
    if census.enabled {
        let counter = &census.counters[record.kind as usize];
        census.subtract(&counter.states[state.state as usize]);
        census.add(&counter.states[next as usize]);
    }
    state.state = next;
    if next == ResourceState::Retired {
        state.retired_at = Some(Instant::now());
    }
    if next == ResourceState::Exiting {
        state.exiting_at = Some(Instant::now());
    }
}

/// Requests observation of cancellation; does not own the future or count as
/// its completion. Dropping the future's token is the only destruction event.
#[derive(Clone)]
pub struct ResourceCancellationHandle {
    census: Arc<ResourceCensus>,
    record: Weak<Record>,
}

impl fmt::Debug for ResourceCancellationHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceCancellationHandle")
            .finish_non_exhaustive()
    }
}

impl ResourceCancellationHandle {
    pub fn cancel_requested(&self) {
        if let Some(record) = self.record.upgrade() {
            transition(&self.census, &record, ResourceState::Exiting);
        }
    }
}

impl Drop for ResourceToken {
    fn drop(&mut self) {
        let Some(record) = &self.record else {
            return;
        };
        let _mutation = Mutation::begin(&self.census);
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.alive = false;
        if self.census.enabled {
            let counter = &self.census.counters[record.kind as usize];
            self.census.subtract(&counter.states[state.state as usize]);
            self.census.subtract(&counter.live);
            self.census.add(&counter.destroyed);
            if self.tracked {
                // Release state lock before details lock: sample takes the
                // reverse order and reads only scalar metadata.
                drop(state);
                if let Some(id) = record.id {
                    self.census
                        .details
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&id);
                }
            } else if record.kind.detailed() {
                self.census.subtract(&counter.untracked_live);
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ResourceSample {
    pub schema_version: &'static str,
    pub enabled: bool,
    pub capture_start_ms: u64,
    pub capture_end_ms: u64,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub mutations_in_flight_start: u64,
    pub mutations_in_flight_end: u64,
    pub globally_atomic: bool,
    pub invariant_failures: u64,
    pub detailed_records: usize,
    pub detail_capacity: usize,
    pub resources: Vec<ResourceCount>,
}

#[derive(Debug, Serialize)]
pub struct ResourceCount {
    pub kind: ResourceKind,
    pub created: u64,
    pub destroyed: u64,
    pub live: u64,
    pub published: u64,
    pub states: Vec<StateCount>,
    pub age_supported: bool,
    pub detail_untracked_live: u64,
    pub oldest_retired_age_ms: Option<u64>,
    pub oldest_exiting_age_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct StateCount {
    pub state: ResourceState,
    pub live: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(census: &ResourceCensus, kind: ResourceKind) -> ResourceCount {
        census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == kind)
            .expect("fixed census kind exists")
    }

    #[test]
    fn clones_retirement_and_scalar_cancel_handles_do_not_fake_destruction() {
        let census = Arc::new(ResourceCensus::default());
        let token = Arc::new(census.token(ResourceKind::Snapshot, ResourceState::Candidate));
        let clone = Arc::clone(&token);
        token.record_published_once();
        token.mark_current();
        token.mark_retired();
        token.mark_current();
        let cancel = token.cancellation_handle();
        drop(token);
        let row = count(&census, ResourceKind::Snapshot);
        assert_eq!(
            (row.created, row.destroyed, row.live, row.published),
            (1, 0, 1, 1)
        );
        assert_eq!(clone.state(), ResourceState::Retired);
        drop(clone);
        cancel.cancel_requested();
        let row = count(&census, ResourceKind::Snapshot);
        assert_eq!((row.created, row.destroyed, row.live), (1, 1, 0));
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_before_first_poll_is_not_completion_until_future_drop() {
        let census = Arc::new(ResourceCensus::default());
        let token = census.token(ResourceKind::HealthSupervisor, ResourceState::Scheduled);
        let cancel = token.cancellation_handle();
        let task = tokio::spawn(async move {
            token.transition(ResourceState::Running);
            std::future::pending::<()>().await;
            drop(token);
        });
        cancel.cancel_requested();
        task.abort();
        assert_eq!(count(&census, ResourceKind::HealthSupervisor).live, 1);
        assert!(
            task.await
                .expect_err("aborted task cannot complete")
                .is_cancelled()
        );
        let row = count(&census, ResourceKind::HealthSupervisor);
        assert_eq!((row.created, row.destroyed, row.live), (1, 1, 0));
    }

    #[test]
    fn observation_is_bounded_pure_and_disabled_is_unavailable() {
        let census = Arc::new(ResourceCensus::default());
        let tokens = (0..MAX_DETAILS + 1)
            .map(|_| census.token(ResourceKind::Snapshot, ResourceState::Retired))
            .collect::<Vec<_>>();
        let before = census.sample();
        for _ in 0..100 {
            assert_eq!(census.sample().sequence_end, before.sequence_end);
        }
        let row = count(&census, ResourceKind::Snapshot);
        assert_eq!(row.detail_untracked_live, 1);
        assert!(row.oldest_retired_age_ms.is_none());
        drop(tokens);
        assert_eq!(census.sample().detailed_records, 0);
        assert_eq!(count(&census, ResourceKind::Snapshot).live, 0);
        let disabled = Arc::new(ResourceCensus::new(false));
        let disabled_token = disabled.token(ResourceKind::Snapshot, ResourceState::Live);
        assert!(
            disabled_token.record.is_none(),
            "disabled hot guard allocates no metadata"
        );
        assert!(!disabled.sample().enabled);
        assert!(disabled.sample().resources.is_empty());
    }

    #[test]
    fn underflow_is_visible_not_saturated_away() {
        let census = ResourceCensus::default();
        let counter = AtomicU64::new(0);
        census.subtract(&counter);
        assert_eq!(census.sample().invariant_failures, 1);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn delayed_publication_after_retirement_never_revives_a_snapshot() {
        let census = Arc::new(ResourceCensus::default());
        let token = census.token(ResourceKind::Snapshot, ResourceState::Candidate);
        token.mark_retired();
        token.record_published_once();
        token.record_published_once();
        token.mark_current();
        assert_eq!(token.state(), ResourceState::Retired);
        let row = count(&census, ResourceKind::Snapshot);
        assert_eq!((row.created, row.published, row.live), (1, 1, 1));
        assert_eq!(
            row.states
                .iter()
                .find(|s| s.state == ResourceState::Current)
                .expect("current state")
                .live,
            0
        );
        assert!(!format!("{token:?}").contains("counters"));
    }

    #[test]
    fn cancellation_has_its_own_exit_age_without_fake_retirement() {
        let census = Arc::new(ResourceCensus::default());
        let token = census.token(ResourceKind::HealthSupervisor, ResourceState::Running);
        token.cancellation_handle().cancel_requested();
        token
            .record
            .as_ref()
            .expect("enabled scalar metadata")
            .state
            .lock()
            .expect("test metadata lock")
            .exiting_at = Some(Instant::now() - std::time::Duration::from_secs(2));
        let row = count(&census, ResourceKind::HealthSupervisor);
        assert_eq!(row.oldest_retired_age_ms, Some(0));
        assert!(row.oldest_exiting_age_ms.expect("fully tracked exit") >= 2000);
        assert_eq!(row.live, 1);
        drop(token);
        assert_eq!(
            count(&census, ResourceKind::HealthSupervisor).oldest_exiting_age_ms,
            Some(0)
        );
    }

    #[test]
    fn exhausted_detail_identity_cannot_roll_over_and_overwrite_an_observation() {
        let census = Arc::new(ResourceCensus::default());
        census.next_id.store(u64::MAX, Ordering::Relaxed);
        let _held = census.token(ResourceKind::Snapshot, ResourceState::Retired);
        let row = count(&census, ResourceKind::Snapshot);
        assert_eq!(row.live, 1);
        assert_eq!(row.detail_untracked_live, 1);
        assert!(row.oldest_retired_age_ms.is_none());
        assert_eq!(census.sample().invariant_failures, 1);
        assert_eq!(census.next_id.load(Ordering::Relaxed), u64::MAX);
    }
}
