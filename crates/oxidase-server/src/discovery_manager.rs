//! Committed operational discovery. This module deliberately has no publisher,
//! SnapshotStore, CandidateStore, listener or control-plane capability.

use std::collections::BTreeMap;
use std::hash::{BuildHasher as _, Hasher as _};
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use oxidase_config::{DnsDiscoverySpec, DnsRecordType, MAX_DNS_DISCOVERY_CLUSTERS};
use oxidase_core::{ContentDigestBuilder, Diagnostic, ResourceId};
use oxidase_runtime::{
    DnsFamily, DnsObservation, PreparedCluster, ResourceCancellationHandle, ResourceCensus,
    ResourceKind, ResourceState, RuntimeSnapshot, SrvObservation,
};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::dns_resolver::{
    DnsResolver, MAX_DNS_QUERIES, ResolvedFamily, ResolvedSrv, validate_bootstrap,
};
use crate::leaves::ProxyClient;
use crate::metrics::Metrics;

/// Validate static/local resolver inputs without sending DNS queries. This is
/// shared by source checks, Bundle verification and pre-publication validation.
pub fn validate_discovery_bootstrap(snapshot: &RuntimeSnapshot) -> Result<(), Vec<Diagnostic>> {
    validate_discovery_policy_bootstrap(
        snapshot
            .resources
            .clusters
            .values()
            .map(|cluster| cluster.spec()),
    )
}

/// Portable validation uses the compiled policy only; it never resolves DNS or
/// reads Secret/Certificate payloads merely to verify resolver configuration.
pub fn validate_discovery_policy_bootstrap<'a>(
    clusters: impl IntoIterator<Item = &'a oxidase_config::ClusterSpec>,
) -> Result<(), Vec<Diagnostic>> {
    let diagnostics = clusters
        .into_iter()
        .filter_map(|cluster| {
            let plan = cluster.discovery.as_ref()?;
            validate_bootstrap(&plan.resolver).err().map(|error| {
                Diagnostic::new(
                    error.code(),
                    "cannot prepare the local DNS resolver inputs",
                    plan.spans
                        .get(error.field())
                        .cloned()
                        .unwrap_or_else(|| plan.source.clone()),
                )
            })
        })
        .collect::<Vec<_>>();
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics)
    }
}

struct Owner {
    cluster: Weak<PreparedCluster>,
    task: JoinHandle<()>,
    observation: ResourceCancellationHandle,
}

/// Local-only preparation result. Resolver inputs are frozen before the final
/// publication precondition, without starting a query or a permanent task.
pub(crate) struct PreparedDiscoveryOwners(BTreeMap<ResourceId, DnsResolver>);

pub(crate) struct DiscoveryPreparation {
    plans: Vec<(ResourceId, DnsDiscoverySpec)>,
    queries: Arc<Semaphore>,
    census: Arc<ResourceCensus>,
}

impl DiscoveryPreparation {
    pub(crate) fn prepare(self) -> Result<PreparedDiscoveryOwners, Vec<Diagnostic>> {
        let mut prepared = BTreeMap::new();
        let mut diagnostics = Vec::new();
        for (id, plan) in self.plans {
            match DnsResolver::with_census(
                &plan.resolver,
                Arc::clone(&self.queries),
                Arc::clone(&self.census),
            ) {
                Ok(resolver) => {
                    prepared.insert(id, resolver);
                }
                Err(error) => diagnostics.push(Diagnostic::new(
                    error.code(),
                    "cannot prepare the local DNS resolver inputs",
                    plan.spans
                        .get(error.field())
                        .cloned()
                        .unwrap_or_else(|| plan.source.clone()),
                )),
            }
        }
        if diagnostics.is_empty() {
            Ok(PreparedDiscoveryOwners(prepared))
        } else {
            Err(diagnostics)
        }
    }
}

/// Exactly one refresh task per committed resource, with bounded global DNS
/// query admission. Old snapshots do not own tasks and cannot reactivate them.
pub(crate) struct DiscoveryManager {
    owners: BTreeMap<ResourceId, Owner>,
    queries: Arc<Semaphore>,
    jitter_seed: u64,
    census: Arc<ResourceCensus>,
}

impl DiscoveryManager {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::new_with_census(ResourceCensus::process())
    }

    pub(crate) fn new_with_census(census: Arc<ResourceCensus>) -> Self {
        // RandomState receives per-process OS-seeded hash keys. Its empty hash
        // is used only to desynchronize refresh scheduling, never as identity,
        // authentication material or a correctness/content digest.
        let seed = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        Self::with_seed_and_census(seed, census)
    }

    fn with_seed_and_census(seed: u64, census: Arc<ResourceCensus>) -> Self {
        Self {
            owners: BTreeMap::new(),
            queries: Arc::new(Semaphore::new(MAX_DNS_QUERIES)),
            jitter_seed: seed,
            census,
        }
    }

    pub(crate) fn preparation_for(&self, snapshot: &RuntimeSnapshot) -> DiscoveryPreparation {
        let plans = snapshot
            .resources
            .clusters
            .iter()
            .filter_map(|(id, cluster)| {
                let plan = cluster.spec().discovery.as_ref()?;
                let reused = self.owners.get(id).is_some_and(|owner| {
                    !owner.task.is_finished()
                        && owner
                            .cluster
                            .upgrade()
                            .is_some_and(|old| Arc::ptr_eq(&old, cluster))
                });
                (!reused).then(|| (id.clone(), plan.clone()))
            })
            .collect();
        DiscoveryPreparation {
            plans,
            queries: Arc::clone(&self.queries),
            census: Arc::clone(&self.census),
        }
    }

    pub(crate) async fn activate_snapshot(
        &mut self,
        snapshot: &RuntimeSnapshot,
        proxy: &Arc<ProxyClient>,
        metrics: &Arc<Metrics>,
        mut prepared: PreparedDiscoveryOwners,
    ) {
        // Explicit cancellation is independent of old streaming requests that
        // still pin the retired immutable snapshot. Await aborted owners before
        // allocating replacements, so churn cannot accumulate closing tasks.
        let retired = self
            .owners
            .iter()
            .filter_map(|(id, owner)| {
                let keep = snapshot.resources.clusters.get(id).is_some_and(|current| {
                    current.spec().discovery.is_some()
                        && !owner.task.is_finished()
                        && owner
                            .cluster
                            .upgrade()
                            .is_some_and(|old| Arc::ptr_eq(&old, current))
                });
                (!keep).then_some(id.clone())
            })
            .collect::<Vec<_>>();
        for id in retired {
            if let Some(owner) = self.owners.remove(&id) {
                if let Some(cluster) = owner.cluster.upgrade() {
                    cluster.retire_discovery_policy();
                }
                owner.observation.cancel_requested();
                owner.task.abort();
                let _ = owner.task.await;
            }
        }
        for (id, cluster) in &snapshot.resources.clusters {
            let Some(plan) = &cluster.spec().discovery else {
                continue;
            };
            if self.owners.contains_key(id) {
                continue;
            }
            debug_assert!(self.owners.len() < MAX_DNS_DISCOVERY_CLUSTERS);
            if self.owners.len() >= MAX_DNS_DISCOVERY_CLUSTERS {
                continue;
            }
            // Consume the exact local resolver inputs validated before commit.
            // No filesystem reads or fallible resolver construction after it.
            let Some(resolver) = prepared.0.remove(id) else {
                continue;
            };
            let _ = cluster.activate_discovery_policy();
            let lifetime = self
                .census
                .token(ResourceKind::DiscoverySupervisor, ResourceState::Scheduled);
            let observation = lifetime.cancellation_handle();
            let weak = Arc::downgrade(cluster);
            let plan = plan.clone();
            let proxy = Arc::clone(proxy);
            let metrics = Arc::clone(metrics);
            let task_id = id.clone();
            let seed = self.jitter_seed;
            let task = tokio::spawn(async move {
                lifetime.transition(ResourceState::Running);
                run_owner(weak, plan, resolver, proxy, metrics, task_id, seed).await;
                drop(lifetime);
            });
            self.owners.insert(
                id.clone(),
                Owner {
                    cluster: Arc::downgrade(cluster),
                    task,
                    observation,
                },
            );
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        for (_, owner) in std::mem::take(&mut self.owners) {
            if let Some(cluster) = owner.cluster.upgrade() {
                cluster.retire_discovery_policy();
            }
            owner.observation.cancel_requested();
            owner.task.abort();
            let _ = owner.task.await;
        }
    }
}

impl Drop for DiscoveryManager {
    fn drop(&mut self) {
        for owner in self.owners.values() {
            if let Some(cluster) = owner.cluster.upgrade() {
                cluster.retire_discovery_policy();
            }
            owner.observation.cancel_requested();
            owner.task.abort();
        }
    }
}

async fn run_owner(
    weak: Weak<PreparedCluster>,
    plan: DnsDiscoverySpec,
    resolver: DnsResolver,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    id: ResourceId,
    seed: u64,
) {
    let _task = metrics.discovery_task_started();
    if plan.record == DnsRecordType::Srv {
        run_srv_owner(weak, plan, resolver, proxy, metrics, id, seed).await;
        return;
    }
    let Some(cluster) = weak.upgrade() else {
        return;
    };
    let mut retired = cluster.discovery_retirement();
    drop(cluster);
    let mut schedule = RefreshSchedule::new(&id, seed);
    loop {
        if *retired.borrow() {
            break;
        }
        let Some(cluster) = weak.upgrade() else {
            break;
        };
        let now = Instant::now();
        // Expiry processing is independent of refresh throttling. The same
        // expiry is also checked at every business-lease linearization point.
        drop(cluster.endpoints());
        proxy.prune_pools();
        let due = schedule.due(now);
        if due.is_empty() {
            let wake = cluster
                .next_discovery_expiry()
                .map_or(schedule.next(), |expiry| expiry.min(schedule.next()));
            drop(cluster);
            tokio::select! {
                biased;
                _ = retired.changed() => break,
                () = tokio::time::sleep_until(wake) => {},
            }
            continue;
        }
        let Some(query) = cluster.begin_discovery_query() else {
            break;
        };
        let _round = resolver
            .resource_census()
            .token(ResourceKind::DiscoveryRound, ResourceState::Running);
        let mut work = due
            .into_iter()
            .map(|family| {
                let resolver = &resolver;
                let plan = &plan;
                async move {
                    (
                        family,
                        resolver.resolve_family_with_schedule(plan, family).await,
                    )
                }
            })
            .collect::<FuturesUnordered<_>>();
        while let Some((family, mut answer)) = tokio::select! {
            biased;
            _ = retired.changed() => None,
            answer = work.next() => answer,
        } {
            let now = Instant::now();
            let name_removed = matches!(answer.observation, DnsObservation::NameNotFound);
            // Resolver validation is not sufficient for the merged resource
            // quota. Schedule the accepted outcome, not a raw positive TTL
            // that the membership gate rejected. This bounded cold-path copy
            // carries no request body or publication authority.
            let receipt = cluster.reconcile_dns(&query, family, answer.observation.clone(), now);
            if !receipt.applied {
                break;
            }
            normalize_reconciled_answer(&mut answer, receipt.observation_error_code);
            schedule.complete(family, &answer, &plan, now);
            metrics.record_discovery(cluster.name(), family, &answer.observation);
            cluster.set_discovery_refresh(&query, schedule.next());
            proxy.prune_pools();
            if name_removed {
                // NXDOMAIN revokes the name, not just one address family. The
                // runtime fences any concurrent late positive; cancel it here
                // too and negative-cache the complete name once.
                break;
            }
        }
        drop(work);
        drop(query);
        drop(cluster);
    }
}

async fn run_srv_owner(
    weak: Weak<PreparedCluster>,
    plan: DnsDiscoverySpec,
    resolver: DnsResolver,
    proxy: Arc<ProxyClient>,
    metrics: Arc<Metrics>,
    id: ResourceId,
    seed: u64,
) {
    let Some(cluster) = weak.upgrade() else {
        return;
    };
    let mut retired = cluster.discovery_retirement();
    drop(cluster);
    let mut schedule = RefreshSchedule::new(&id, seed);
    loop {
        if *retired.borrow() {
            break;
        }
        let Some(cluster) = weak.upgrade() else {
            break;
        };
        drop(cluster.endpoints());
        proxy.prune_pools();
        if schedule.next() > Instant::now() {
            let wake = cluster
                .next_discovery_expiry()
                .map_or(schedule.next(), |expiry| expiry.min(schedule.next()));
            drop(cluster);
            tokio::select! {
                biased;
                _ = retired.changed() => break,
                () = tokio::time::sleep_until(wake) => {},
            }
            continue;
        }
        let Some(query) = cluster.begin_discovery_query() else {
            break;
        };
        let _round = resolver
            .resource_census()
            .token(ResourceKind::DiscoveryRound, ResourceState::Running);
        let mut answer = tokio::select! {
            biased;
            _ = retired.changed() => break,
            answer = resolver.resolve_srv_with_schedule(&plan) => answer,
        };
        let now = Instant::now();
        let receipt = cluster.reconcile_srv(&query, answer.observation.clone(), now);
        if !receipt.applied {
            break;
        }
        normalize_reconciled_srv_answer(&mut answer, receipt);
        schedule.complete_srv(&answer, &plan, now);
        metrics.record_srv_discovery(cluster.name(), &answer.observation);
        cluster.set_discovery_refresh(&query, schedule.next());
        proxy.prune_pools();
        drop(query);
        drop(cluster);
    }
}

fn normalize_reconciled_srv_answer(
    answer: &mut ResolvedSrv,
    receipt: oxidase_runtime::DiscoveryReconcileOutcome,
) {
    // A successful service RRset can retain a fast target/family while a sibling
    // is unavailable. Only rejection of the entire positive input justifies
    // discarding its original expiry schedule and using whole-service backoff.
    if receipt.positive_rejected && matches!(answer.observation, SrvObservation::Positive { .. }) {
        answer.observation = match receipt.observation_error_code {
            Some(oxidase_runtime::DiscoveryErrorCode::PolicyRejected) => {
                SrvObservation::PolicyRejected
            }
            Some(oxidase_runtime::DiscoveryErrorCode::LimitExceeded) => {
                SrvObservation::LimitExceeded
            }
            _ => SrvObservation::InvalidAnswer,
        };
        answer.retry_after = None;
    }
}

fn normalize_reconciled_answer(
    answer: &mut ResolvedFamily,
    error: Option<oxidase_runtime::DiscoveryErrorCode>,
) {
    if matches!(answer.observation, DnsObservation::Positive { .. })
        && let Some(code) = error
    {
        answer.observation = match code {
            oxidase_runtime::DiscoveryErrorCode::PolicyRejected => DnsObservation::PolicyRejected,
            oxidase_runtime::DiscoveryErrorCode::LimitExceeded => DnsObservation::LimitExceeded,
            _ => DnsObservation::InvalidAnswer,
        };
        answer.retry_after = None;
    }
}

/// One bounded scheduling cache, not a second DNS answer cache. Record expiry
/// never changes when refresh/backoff is clamped, and repeated failure cannot
/// extend the runtime's fixed stale deadline.
struct RefreshSchedule {
    next: [Instant; 2],
    failures: [u8; 2],
    random: u64,
}

enum RefreshTiming {
    Positive(Option<Instant>),
    Negative(Option<Instant>),
    Failure,
}

impl RefreshSchedule {
    fn new(id: &ResourceId, startup_seed: u64) -> Self {
        let mut seed = ContentDigestBuilder::new("oxidase/dns-refresh-jitter/v1");
        seed.field_bytes("cluster", id.as_str())
            .field_u64("startup_seed", startup_seed);
        let digest = seed.finish().to_hex();
        let random = u64::from_str_radix(&digest[..16], 16).unwrap_or(1).max(1);
        Self {
            next: [Instant::now(); 2],
            failures: [0; 2],
            random,
        }
    }

    fn due(&self, now: Instant) -> Vec<DnsFamily> {
        [DnsFamily::A, DnsFamily::Aaaa]
            .into_iter()
            .enumerate()
            .filter_map(|(index, family)| (self.next[index] <= now).then_some(family))
            .collect()
    }

    fn next(&self) -> Instant {
        self.next[0].min(self.next[1])
    }

    fn complete(
        &mut self,
        family: DnsFamily,
        answer: &ResolvedFamily,
        plan: &DnsDiscoverySpec,
        now: Instant,
    ) {
        let index = usize::from(family == DnsFamily::Aaaa);
        let timing = match &answer.observation {
            DnsObservation::Positive { addresses } => {
                RefreshTiming::Positive(addresses.iter().map(|record| record.fresh_until).min())
            }
            DnsObservation::NameNotFound | DnsObservation::NoData => {
                RefreshTiming::Negative(answer.retry_after)
            }
            _ => RefreshTiming::Failure,
        };
        let next = self.advance(index, timing, plan, now);
        if matches!(answer.observation, DnsObservation::NameNotFound) {
            self.next = [next; 2];
            self.failures = [0; 2];
        } else {
            self.next[index] = next;
        }
    }

    fn complete_srv(&mut self, answer: &ResolvedSrv, plan: &DnsDiscoverySpec, now: Instant) {
        let timing = match &answer.observation {
            SrvObservation::Positive { records, addresses } => {
                let expiries = records
                    .iter()
                    .map(|record| record.fresh_until)
                    .chain(
                        addresses
                            .iter()
                            .flat_map(|target| match &target.observation {
                                DnsObservation::Positive { addresses } => addresses.as_slice(),
                                _ => &[],
                            })
                            .map(|record| record.fresh_until),
                    )
                    .chain(answer.retry_after);
                RefreshTiming::Positive(expiries.min())
            }
            SrvObservation::NameNotFound
            | SrvObservation::NoData
            | SrvObservation::ServiceUnavailable => RefreshTiming::Negative(answer.retry_after),
            _ => RefreshTiming::Failure,
        };
        let next = self.advance(0, timing, plan, now);
        self.next = [next; 2];
    }

    fn advance(
        &mut self,
        index: usize,
        timing: RefreshTiming,
        plan: &DnsDiscoverySpec,
        now: Instant,
    ) -> Instant {
        let refresh = &plan.refresh;
        let delay = match timing {
            RefreshTiming::Positive(expiry) => {
                self.failures[index] = 0;
                let remaining = expiry.map_or(Duration::ZERO, |expiry| {
                    expiry.saturating_duration_since(now)
                });
                // Early-only jitter never extends the actual TTL. The minimum
                // interval throttles queries, not the membership's expiry.
                let maximum = remaining.min(refresh.max_interval);
                self.random ^= self.random << 13;
                self.random ^= self.random >> 7;
                self.random ^= self.random << 17;
                let reduction = maximum.mul_f64(
                    f64::from(refresh.jitter_percent) / 100.0 * (self.random % 10_001) as f64
                        / 10_000.0,
                );
                maximum.saturating_sub(reduction).max(refresh.min_interval)
            }
            RefreshTiming::Negative(expiry) => {
                self.failures[index] = 0;
                expiry
                    .map_or(refresh.min_interval, |expiry| {
                        expiry.saturating_duration_since(now)
                    })
                    .min(refresh.max_interval)
                    .max(refresh.min_interval)
            }
            RefreshTiming::Failure => {
                self.failures[index] = self.failures[index].saturating_add(1).min(16);
                refresh
                    .min_interval
                    .saturating_mul(1u32 << (self.failures[index] - 1))
                    .min(refresh.max_interval)
            }
        };
        now + delay
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use oxidase_config::Compiler;
    use oxidase_runtime::{DiscoveryErrorCode, DnsAddressRecord};
    use tempfile::TempDir;

    use super::*;

    fn fixture() -> (TempDir, RuntimeSnapshot) {
        let dir = TempDir::new().expect("temporary source");
        let path = dir.path().join("gateway.yaml");
        std::fs::write(&path, "api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      discovery:\n        dns:\n          name: fixture.oxidase.invalid\n          record: a_aaaa\n          port: 8080\n          origin: http://logical.oxidase.invalid/base\n          resolver:\n            nameservers: [127.0.0.1:59999]\n          refresh:\n            min_interval: 1s\n            max_interval: 8s\n            jitter_percent: 0\n            stale_if_error: 2s\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      type: proxy\n      cluster: api\n").expect("write source");
        let snapshot =
            RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("compile policy"))
                .expect("prepare policy");
        (dir, snapshot)
    }

    fn resource_count(
        census: &ResourceCensus,
        kind: ResourceKind,
    ) -> oxidase_runtime::ResourceCount {
        census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == kind)
            .expect("fixed census kind")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn discovery_census_counts_scheduled_owner_until_actual_abort_drop_without_scrape() {
        let (_dir, snapshot) = fixture();
        let census = Arc::new(ResourceCensus::default());
        let mut manager = DiscoveryManager::with_seed_and_census(1, Arc::clone(&census));
        let prepared = manager
            .preparation_for(&snapshot)
            .prepare()
            .expect("local preparation");
        assert_eq!(
            resource_count(&census, ResourceKind::DiscoverySupervisor).live,
            0,
            "preparation cannot start permanent work"
        );
        assert_eq!(resource_count(&census, ResourceKind::DnsQuery).created, 0);
        let proxy = Arc::new(ProxyClient::new().expect("proxy pools"));
        let metrics = Arc::new(Metrics::default());
        manager
            .activate_snapshot(&snapshot, &proxy, &metrics, prepared)
            .await;
        let scheduled = resource_count(&census, ResourceKind::DiscoverySupervisor);
        assert_eq!(
            (scheduled.created, scheduled.destroyed, scheduled.live),
            (1, 0, 1)
        );
        assert_eq!(
            scheduled
                .states
                .iter()
                .find(|row| row.state == ResourceState::Scheduled)
                .expect("scheduled state")
                .live,
            1
        );
        let owner = manager.owners.values().next().expect("owner");
        owner.observation.cancel_requested();
        owner.task.abort();
        let cancelling = resource_count(&census, ResourceKind::DiscoverySupervisor);
        assert_eq!(
            cancelling.live, 1,
            "abort does not synchronously drop the unpolled future"
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
        manager.shutdown().await;
        let completed = resource_count(&census, ResourceKind::DiscoverySupervisor);
        assert_eq!(
            (completed.created, completed.destroyed, completed.live),
            (1, 1, 0)
        );
        assert_eq!(resource_count(&census, ResourceKind::DnsQuery).created, 0);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retired_discovery_drops_real_round_and_query_before_late_reply_without_scrape() {
        use crate::dns_test_fixture::{DnsFixture, FixtureReply};
        use hickory_resolver::proto::rr::rdata::A;
        use hickory_resolver::proto::rr::{RData, Record, RecordType};
        use tokio::sync::oneshot;
        let (received, arrival) = oneshot::channel();
        let received = Arc::new(std::sync::Mutex::new(Some(received)));
        let response_gate = Arc::new(Semaphore::new(0));
        let gate = Arc::clone(&response_gate);
        let dns_fixture = DnsFixture::start(move |question, _| {
            if question.query_type() != RecordType::A {
                return FixtureReply::answers(Vec::new());
            }
            if let Some(sender) = received.lock().expect("arrival signal").take() {
                let _ = sender.send(());
            }
            let mut reply = FixtureReply::answers(vec![Record::from_rdata(
                question.name().clone(),
                30,
                RData::A(A::new(192, 0, 2, 1)),
            )]);
            reply.response_gate = Some(Arc::clone(&gate));
            reply
        })
        .await;
        let (_dir, mut snapshot) = fixture();
        let mut spec = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster")
            .spec()
            .clone();
        let discovery = spec.discovery.as_mut().expect("DNS policy");
        discovery.resolver.source =
            oxidase_config::DnsResolverSource::NameServers(vec![dns_fixture.address]);
        discovery.resolver.query_timeout = Duration::from_secs(30);
        let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
        snapshot
            .resources
            .clusters
            .insert(cluster.id().clone(), Arc::clone(&cluster));
        let census = Arc::new(ResourceCensus::default());
        let mut manager = DiscoveryManager::with_seed_and_census(1, Arc::clone(&census));
        let prepared = manager
            .preparation_for(&snapshot)
            .prepare()
            .expect("local preparation");
        let proxy = Arc::new(ProxyClient::new().expect("proxy pools"));
        let metrics = Arc::new(Metrics::default());
        manager
            .activate_snapshot(&snapshot, &proxy, &metrics, prepared)
            .await;
        tokio::time::timeout(Duration::from_secs(3), arrival)
            .await
            .expect("actual A query arrived")
            .expect("arrival sender");
        assert_eq!(
            resource_count(&census, ResourceKind::DiscoverySupervisor).live,
            1
        );
        assert_eq!(
            resource_count(&census, ResourceKind::DiscoveryRound).live,
            1
        );
        assert!(resource_count(&census, ResourceKind::DnsQuery).live >= 1);
        let mut removed = snapshot.clone();
        removed.resources.clusters.clear();
        let empty_preparation = manager
            .preparation_for(&removed)
            .prepare()
            .expect("empty preparation");
        manager
            .activate_snapshot(&removed, &proxy, &metrics, empty_preparation)
            .await;
        for kind in [
            ResourceKind::DiscoverySupervisor,
            ResourceKind::DiscoveryRound,
            ResourceKind::DnsQuery,
        ] {
            let row = resource_count(&census, kind);
            assert_eq!(
                row.live, 0,
                "actual retired work dropped before reading any Admin/metrics path"
            );
            assert_eq!(row.created, row.destroyed);
        }
        let generation = cluster
            .discovery_status()
            .expect("retired membership")
            .generation;
        let sent = dns_fixture
            .counts
            .responses_for_type("fixture.oxidase.invalid.", RecordType::A);
        response_gate.add_permits(1);
        tokio::time::timeout(Duration::from_secs(3), async {
            while dns_fixture
                .counts
                .responses_for_type("fixture.oxidase.invalid.", RecordType::A)
                == sent
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late UDP reply actually sent");
        assert_eq!(
            cluster
                .discovery_status()
                .expect("still retired")
                .generation,
            generation
        );
        assert!(
            cluster.endpoints().is_empty(),
            "late retired answer cannot revive endpoint selection"
        );
        assert_eq!(census.sample().invariant_failures, 0);
        manager.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn minimum_query_interval_does_not_extend_ttl_zero_or_short_freshness() {
        let (_dir, snapshot) = fixture();
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let plan = cluster.spec().discovery.as_ref().expect("policy");
        let mut schedule = RefreshSchedule::new(cluster.id(), 1);
        let now = Instant::now();
        for lifetime in [Duration::ZERO, Duration::from_millis(100)] {
            let expiry = now + lifetime;
            let answer = ResolvedFamily {
                observation: DnsObservation::Positive {
                    addresses: vec![DnsAddressRecord {
                        address: "192.0.2.1".parse::<IpAddr>().expect("IP"),
                        fresh_until: expiry,
                    }],
                },
                retry_after: None,
            };
            schedule.complete(DnsFamily::A, &answer, plan, now);
            assert_eq!(schedule.next[0], now + Duration::from_secs(1));
            assert_eq!(
                match answer.observation {
                    DnsObservation::Positive { addresses } => addresses[0].fresh_until,
                    _ => unreachable!(),
                },
                expiry,
                "refresh throttle cannot replace record expiry"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn family_negative_cache_backoff_and_name_revocation_are_bounded_and_independent() {
        let (_dir, snapshot) = fixture();
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let plan = cluster.spec().discovery.as_ref().expect("policy");
        let mut schedule = RefreshSchedule::new(cluster.id(), 1);
        let now = Instant::now();
        schedule.complete(
            DnsFamily::A,
            &ResolvedFamily {
                observation: DnsObservation::NoData,
                retry_after: Some(now + Duration::from_secs(5)),
            },
            plan,
            now,
        );
        assert_eq!(schedule.due(now), vec![DnsFamily::Aaaa]);
        let failed = ResolvedFamily {
            observation: DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            },
            retry_after: None,
        };
        for attempt in 0..10u32 {
            schedule.complete(DnsFamily::Aaaa, &failed, plan, now);
            assert_eq!(
                schedule.next[1].duration_since(now),
                Duration::from_secs((1u64 << attempt).min(8))
            );
        }
        schedule.complete(
            DnsFamily::Aaaa,
            &ResolvedFamily {
                observation: DnsObservation::NameNotFound,
                retry_after: Some(now + Duration::from_secs(6)),
            },
            plan,
            now,
        );
        assert_eq!(schedule.next, [now + Duration::from_secs(6); 2]);
        assert!(schedule.due(now + Duration::from_secs(5)).is_empty());
        assert_eq!(schedule.due(now + Duration::from_secs(6)).len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn early_jitter_has_deterministic_seed_and_does_not_refund_ttl() {
        let (_dir, snapshot) = fixture();
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let mut plan = cluster.spec().discovery.clone().expect("policy");
        plan.refresh.jitter_percent = 50;
        let mut left = RefreshSchedule::new(cluster.id(), 1);
        let mut right = RefreshSchedule::new(cluster.id(), 1);
        let mut replica = RefreshSchedule::new(cluster.id(), 2);
        let now = Instant::now();
        let answer = ResolvedFamily {
            observation: DnsObservation::Positive {
                addresses: vec![DnsAddressRecord {
                    address: "192.0.2.1".parse().expect("IP"),
                    fresh_until: now + Duration::from_secs(6),
                }],
            },
            retry_after: None,
        };
        for _ in 0..100 {
            left.complete(DnsFamily::A, &answer, &plan, now);
            right.complete(DnsFamily::A, &answer, &plan, now);
            assert_eq!(left.next[0], right.next[0]);
            assert!(left.next[0] >= now + Duration::from_secs(3));
            assert!(left.next[0] <= now + Duration::from_secs(6));
        }
        replica.complete(DnsFamily::A, &answer, &plan, now);
        assert_ne!(
            replica.next[0], right.next[0],
            "independent startup seeds desynchronize identical replica policies"
        );
    }

    fn healthy_resource_campaign_cluster() -> (TempDir, PreparedCluster, Arc<ResourceCensus>) {
        let (dir, snapshot) = fixture();
        let mut spec = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster")
            .spec()
            .clone();
        let plan = spec.discovery.as_mut().expect("DNS policy");
        plan.refresh.min_interval = Duration::from_millis(200);
        plan.refresh.max_interval = Duration::from_secs(1);
        plan.refresh.jitter_percent = 10;
        plan.refresh.stale_if_error = Duration::from_millis(500);
        plan.resolver.query_timeout = Duration::from_millis(500);
        spec.health.active = Some(oxidase_config::ActiveHealthSpec {
            path: "/healthz".into(),
            interval: Duration::from_millis(200),
            timeout: Duration::from_millis(500),
            healthy_statuses: vec![oxidase_config::StatusRange {
                start: 200,
                end: 299,
            }],
            healthy_threshold: 1,
            unhealthy_threshold: 1,
            source: spec.source.clone(),
        });
        let census = Arc::new(ResourceCensus::default());
        let (cluster, _) = PreparedCluster::prepare_in(spec, None, Arc::clone(&census));
        assert!(cluster.activate_discovery_policy());
        (dir, cluster, census)
    }

    async fn prove_positive_refresh_timing(ttl: Duration, expires_during_query: bool) {
        let (_dir, cluster, census) = healthy_resource_campaign_cluster();
        let initial = Instant::now();
        let expiry = initial + ttl;
        let positive = |fresh_until| DnsObservation::Positive {
            addresses: vec![DnsAddressRecord {
                address: "192.0.2.1".parse().expect("IP"),
                fresh_until,
            }],
        };
        let query = cluster.begin_discovery_query().expect("initial query");
        let initial_receipt =
            cluster.reconcile_dns(&query, DnsFamily::A, positive(expiry), initial);
        assert!(initial_receipt.applied);
        assert_eq!(initial_receipt.observation_error_code, None);
        drop(query);
        let held = cluster.acquire().await.expect("fresh business lease");
        let old_endpoint = Arc::clone(held.endpoint());
        cluster.record_active_health_for(&old_endpoint, true, std::time::Instant::now());
        let health = &cluster.observed_status(std::time::Instant::now()).endpoints[0].runtime;
        assert_eq!(health.health, oxidase_runtime::EndpointHealthState::Healthy);
        assert_eq!(health.active_health_successes, 1);
        assert_eq!(health.active_health_failures, 0);

        // Seed 33 is the first seed in 0..1024 whose actual schedule for
        // cluster:api reduces a one-second interval by less than two ms.
        // The resolver performs no second positive cache lookup; this models
        // one successful, still-in-flight query, not any DNS/health failure.
        let mut schedule = RefreshSchedule::new(cluster.id(), 33);
        let plan = cluster.spec().discovery.as_ref().expect("DNS policy");
        schedule.complete(
            DnsFamily::A,
            &ResolvedFamily {
                observation: positive(expiry),
                retry_after: None,
            },
            plan,
            initial,
        );
        let query_started = schedule.next[0];
        assert_eq!(query_started - initial, Duration::from_micros(998_250));
        let reply_delay = Duration::from_millis(2);
        let reply_at = query_started + reply_delay;
        tokio::time::advance(query_started - Instant::now()).await;
        let query = cluster
            .begin_discovery_query()
            .expect("positive refresh query");
        assert!(
            cluster
                .observed_discovery_status()
                .expect("status")
                .in_flight_query
        );

        if expires_during_query {
            assert!(query_started < expiry && expiry < reply_at);
            tokio::time::advance(expiry - Instant::now()).await;
            assert!(matches!(
                cluster.acquire().await,
                Err(oxidase_runtime::ClusterAdmissionError::Unavailable)
            ));
            let status = cluster.observed_discovery_status().expect("expired status");
            assert!(status.in_flight_query);
            assert_eq!(status.eligible_endpoints, 0);
            assert_eq!(status.error_code, None);
            assert_eq!(old_endpoint.active_requests(), 1);
            assert_eq!(
                old_endpoint.health_state(std::time::Instant::now()),
                oxidase_runtime::EndpointHealthState::Healthy
            );
            assert_eq!(
                held.endpoint().dial_target(),
                Some("192.0.2.1:8080".parse().expect("dial target"))
            );
        } else {
            // The exact same one-second maximum refresh and bounded query
            // timeout finish strictly inside the original five-second TTL.
            assert!(query_started + plan.resolver.query_timeout < expiry);
        }
        tokio::time::advance(reply_at - Instant::now()).await;
        if !expires_during_query {
            let during_query = cluster.acquire().await.expect("unexpired admission");
            assert!(Arc::ptr_eq(during_query.endpoint(), &old_endpoint));
            assert_eq!(
                cluster
                    .observed_discovery_status()
                    .expect("status")
                    .error_code,
                None
            );
            drop(during_query);
        }
        let receipt =
            cluster.reconcile_dns(&query, DnsFamily::A, positive(reply_at + ttl), reply_at);
        assert!(receipt.applied);
        assert_eq!(receipt.observation_error_code, None);
        drop(query);
        let next = cluster.acquire().await.expect("fresh positive admitted");
        assert_eq!(next.endpoint().dial_target(), old_endpoint.dial_target());
        if expires_during_query {
            assert_ne!(next.endpoint().incarnation(), old_endpoint.incarnation());
        } else {
            assert!(Arc::ptr_eq(next.endpoint(), &old_endpoint));
        }
        drop(next);
        drop(held);
        assert_eq!(old_endpoint.active_requests(), 0);
        assert_eq!(
            resource_count(&census, ResourceKind::HealthSupervisor).created,
            0
        );
        assert_eq!(
            resource_count(&census, ResourceKind::DiscoverySupervisor).created,
            0
        );
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_one_second_ttl_can_expire_during_two_ms_positive_refresh() {
        prove_positive_refresh_timing(Duration::from_secs(1), true).await;
    }

    #[tokio::test(start_paused = true)]
    async fn five_second_ttl_keeps_same_healthy_member_during_two_ms_positive_refresh() {
        prove_positive_refresh_timing(Duration::from_secs(5), false).await;
    }

    #[tokio::test(start_paused = true)]
    async fn merged_quota_rejection_uses_failure_backoff_not_rejected_positive_ttl() {
        let (_dir, snapshot) = fixture();
        let mut spec = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster")
            .spec()
            .clone();
        spec.discovery
            .as_mut()
            .expect("policy")
            .limits
            .max_endpoints = 1;
        let (cluster, _) = PreparedCluster::prepare(spec, None);
        assert!(cluster.activate_discovery_policy());
        let query = cluster.begin_discovery_query().expect("query round");
        let now = Instant::now();
        let positive = |address: &str| DnsObservation::Positive {
            addresses: vec![DnsAddressRecord {
                address: address.parse().expect("IP"),
                fresh_until: now + Duration::from_secs(60),
            }],
        };
        cluster.reconcile_dns(&query, DnsFamily::A, positive("192.0.2.1"), now);
        let mut answer = ResolvedFamily {
            observation: positive("2001:db8::1"),
            retry_after: None,
        };
        let receipt =
            cluster.reconcile_dns(&query, DnsFamily::Aaaa, answer.observation.clone(), now);
        assert_eq!(
            receipt.observation_error_code,
            Some(DiscoveryErrorCode::LimitExceeded)
        );
        normalize_reconciled_answer(&mut answer, receipt.observation_error_code);
        let mut schedule = RefreshSchedule::new(cluster.id(), 1);
        schedule.complete(
            DnsFamily::Aaaa,
            &answer,
            cluster.spec().discovery.as_ref().expect("policy"),
            now,
        );
        assert_eq!(
            schedule.next[1],
            now + Duration::from_secs(1),
            "rejected raw TTL must not hide quota recovery for a minute"
        );
        assert_eq!(
            cluster.endpoints().len(),
            1,
            "valid other family remains available"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn srv_refresh_uses_original_component_expiry_and_target_negative_deadline() {
        let (_dir, snapshot) = fixture();
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let plan = cluster.spec().discovery.as_ref().expect("policy");
        let mut schedule = RefreshSchedule::new(cluster.id(), 42);
        let now = Instant::now();
        let mut answer = ResolvedSrv {
            observation: SrvObservation::Positive {
                records: vec![oxidase_runtime::SrvRecord {
                    target: "target.example.test.".to_owned(),
                    port: 8443,
                    priority: 0,
                    weight: 1,
                    fresh_until: now + Duration::from_secs(60),
                }],
                addresses: vec![oxidase_runtime::SrvTargetAddressObservation {
                    target: "target.example.test.".to_owned(),
                    family: DnsFamily::A,
                    observation: DnsObservation::Positive {
                        addresses: vec![DnsAddressRecord {
                            address: "192.0.2.1".parse().expect("IP"),
                            fresh_until: now + Duration::from_secs(6),
                        }],
                    },
                }],
            },
            retry_after: Some(now + Duration::from_secs(3)),
        };
        schedule.complete_srv(&answer, plan, now);
        assert_eq!(schedule.next, [now + Duration::from_secs(3); 2]);
        answer.retry_after = None;
        schedule.complete_srv(&answer, plan, now + Duration::from_secs(5));
        assert_eq!(
            schedule.next,
            [now + Duration::from_secs(6); 2],
            "round completion cannot refund address TTL"
        );
        schedule.complete_srv(&answer, plan, now + Duration::from_secs(7));
        assert_eq!(
            schedule.next,
            [now + Duration::from_secs(8); 2],
            "expired answers only throttle queries, not leases"
        );
        answer.observation = SrvObservation::ServiceUnavailable;
        answer.retry_after = Some(now + Duration::from_secs(12));
        schedule.complete_srv(&answer, plan, now + Duration::from_secs(10));
        assert_eq!(schedule.next, [now + Duration::from_secs(12); 2]);
    }

    #[tokio::test(start_paused = true)]
    async fn partial_srv_target_failure_keeps_positive_ttl_schedule_instead_of_service_backoff() {
        let (_dir, snapshot) = fixture();
        let mut spec = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster")
            .spec()
            .clone();
        let plan = spec.discovery.as_mut().expect("plan");
        plan.record = DnsRecordType::Srv;
        plan.name = "_http._tcp.service.example.test.".to_owned();
        plan.port = None;
        plan.refresh.max_interval = Duration::from_secs(60);
        plan.refresh.jitter_percent = 0;
        let (cluster, _) = PreparedCluster::prepare(spec, None);
        assert!(cluster.activate_discovery_policy());
        let plan = cluster.spec().discovery.as_ref().expect("plan");
        let mut schedule = RefreshSchedule::new(cluster.id(), 1);
        let metrics = Metrics::default();
        let now = Instant::now();
        for step in 0..10 {
            let now = now + Duration::from_secs(step);
            let query = cluster.begin_discovery_query().expect("single round");
            let mut answer = ResolvedSrv {
                observation: SrvObservation::Positive {
                    records: vec![oxidase_runtime::SrvRecord {
                        target: "target.example.test.".to_owned(),
                        port: 8443,
                        priority: 0,
                        weight: 1,
                        fresh_until: now + Duration::from_secs(5),
                    }],
                    addresses: vec![
                        oxidase_runtime::SrvTargetAddressObservation {
                            target: "target.example.test.".to_owned(),
                            family: DnsFamily::A,
                            observation: DnsObservation::Positive {
                                addresses: vec![DnsAddressRecord {
                                    address: "192.0.2.1".parse().expect("IP"),
                                    fresh_until: now + Duration::from_secs(5),
                                }],
                            },
                        },
                        oxidase_runtime::SrvTargetAddressObservation {
                            target: "target.example.test.".to_owned(),
                            family: DnsFamily::Aaaa,
                            observation: DnsObservation::TransientFailure {
                                code: DiscoveryErrorCode::ServerFailure,
                            },
                        },
                    ],
                },
                retry_after: Some(now + Duration::from_secs(2)),
            };
            let receipt = cluster.reconcile_srv(&query, answer.observation.clone(), now);
            assert!(receipt.applied);
            assert_eq!(
                receipt.observation_error_code,
                Some(DiscoveryErrorCode::ServerFailure)
            );
            normalize_reconciled_srv_answer(&mut answer, receipt);
            assert!(
                matches!(answer.observation, SrvObservation::Positive { .. }),
                "a failed sibling is not malformed service data"
            );
            schedule.complete_srv(&answer, plan, now);
            metrics.record_srv_discovery(cluster.name(), &answer.observation);
            assert_eq!(schedule.next, [now + Duration::from_secs(2); 2]);
            assert_eq!(
                schedule.failures[0], 0,
                "whole-service exponential backoff cannot hide positive TTL"
            );
            assert_eq!(cluster.endpoints().len(), 1);
        }
        let rendered = metrics.render_prometheus_for(&snapshot);
        assert!(rendered.contains(
            "oxidase_discovery_queries_total{cluster=\"api\",family=\"srv\",result=\"positive\"} 10"
        ));
        assert!(rendered.contains(
            "oxidase_discovery_queries_total{cluster=\"api\",family=\"srv\",result=\"invalid_answer\"} 0"
        ));
    }
}
