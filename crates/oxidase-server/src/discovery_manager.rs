//! Committed operational discovery. This module deliberately has no publisher,
//! SnapshotStore, CandidateStore, listener or control-plane capability.

use std::collections::BTreeMap;
use std::hash::{BuildHasher as _, Hasher as _};
use std::sync::{Arc, Weak};

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use oxidase_config::{DnsDiscoverySpec, MAX_DNS_DISCOVERY_CLUSTERS};
use oxidase_core::{ContentDigestBuilder, Diagnostic, ResourceId};
use oxidase_runtime::{DnsFamily, DnsObservation, PreparedCluster, RuntimeSnapshot};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::dns_resolver::{DnsResolver, MAX_DNS_QUERIES, ResolvedFamily, validate_bootstrap};
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
}

/// Local-only preparation result. Resolver inputs are frozen before the final
/// publication precondition, without starting a query or a permanent task.
pub(crate) struct PreparedDiscoveryOwners(BTreeMap<ResourceId, DnsResolver>);

pub(crate) struct DiscoveryPreparation {
    plans: Vec<(ResourceId, DnsDiscoverySpec)>,
    queries: Arc<Semaphore>,
}

impl DiscoveryPreparation {
    pub(crate) fn prepare(self) -> Result<PreparedDiscoveryOwners, Vec<Diagnostic>> {
        let mut prepared = BTreeMap::new();
        let mut diagnostics = Vec::new();
        for (id, plan) in self.plans {
            match DnsResolver::new(&plan.resolver, Arc::clone(&self.queries)) {
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
}

impl DiscoveryManager {
    pub(crate) fn new() -> Self {
        // RandomState receives per-process OS-seeded hash keys. Its empty hash
        // is used only to desynchronize refresh scheduling, never as identity,
        // authentication material or a correctness/content digest.
        let seed = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        Self::with_seed(seed)
    }

    fn with_seed(seed: u64) -> Self {
        Self {
            owners: BTreeMap::new(),
            queries: Arc::new(Semaphore::new(MAX_DNS_QUERIES)),
            jitter_seed: seed,
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
            let task = tokio::spawn(run_owner(
                Arc::downgrade(cluster),
                plan.clone(),
                resolver,
                Arc::clone(proxy),
                Arc::clone(metrics),
                id.clone(),
                self.jitter_seed,
            ));
            self.owners.insert(
                id.clone(),
                Owner {
                    cluster: Arc::downgrade(cluster),
                    task,
                },
            );
        }
    }

    pub(crate) async fn shutdown(&mut self) {
        for (_, owner) in std::mem::take(&mut self.owners) {
            if let Some(cluster) = owner.cluster.upgrade() {
                cluster.retire_discovery_policy();
            }
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
        let refresh = &plan.refresh;
        let delay = match &answer.observation {
            DnsObservation::Positive { addresses } => {
                self.failures[index] = 0;
                let remaining = addresses
                    .iter()
                    .map(|record| record.fresh_until.saturating_duration_since(now))
                    .min()
                    .unwrap_or_default();
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
            DnsObservation::NameNotFound | DnsObservation::NoData => {
                self.failures[index] = 0;
                answer
                    .retry_after
                    .map_or(refresh.min_interval, |expiry| {
                        expiry.saturating_duration_since(now)
                    })
                    .min(refresh.max_interval)
                    .max(refresh.min_interval)
            }
            _ => {
                self.failures[index] = self.failures[index].saturating_add(1).min(16);
                refresh
                    .min_interval
                    .saturating_mul(1u32 << (self.failures[index] - 1))
                    .min(refresh.max_interval)
            }
        };
        let next = now + delay;
        if matches!(answer.observation, DnsObservation::NameNotFound) {
            self.next = [next; 2];
            self.failures = [0; 2];
        } else {
            self.next[index] = next;
        }
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
}
