//! Bounded long-lived pools shared by Proxy and active health probing.
//!
//! Only current resource owners retain strong registry entries. Already-issued
//! attempts own their Client independently; retiring a registry entry cannot
//! move their streams to another target. There is no accumulated weak-key cache.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};

use http_body::Body;
use hyper_util::client::legacy::Client;
use oxidase_config::ClusterProtocol;
use oxidase_core::ResourceId;
use oxidase_runtime::{PreparedCluster, RuntimeSnapshot};

use crate::body::BoxError;
use crate::upstream_transport::{DirectConnector, PoolIdentity, build_upstream_pool};

pub(crate) struct BoundedPoolRegistry<B> {
    max_entries: usize,
    inner: Mutex<Registry<B>>,
}

struct Registry<B> {
    reconciled: bool,
    clock: u64,
    current: BTreeMap<ResourceId, Weak<PreparedCluster>>,
    entries: BTreeMap<PoolIdentity, PoolEntry<B>>,
}

struct PoolEntry<B> {
    pool: Arc<Client<DirectConnector, B>>,
    owner: Weak<PreparedCluster>,
    cluster: ResourceId,
    endpoint: String,
    connector: DirectConnector,
    last_used: u64,
}

impl<B> BoundedPoolRegistry<B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            inner: Mutex::new(Registry {
                reconciled: false,
                clock: 0,
                current: BTreeMap::new(),
                entries: BTreeMap::new(),
            }),
        }
    }

    pub(crate) fn reconcile_snapshot(&self, snapshot: &RuntimeSnapshot) {
        let mut registry = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry.reconciled = true;
        registry.current = snapshot
            .resources
            .clusters
            .iter()
            .map(|(id, cluster)| (id.clone(), Arc::downgrade(cluster)))
            .collect();
        // A policy-only replacement may preserve the full transport identity.
        // Rebind the weak owner only after checking immutable origin/TLS/timing.
        registry.entries.retain(|_, entry| {
            let Some(current) = snapshot.resources.clusters.get(&entry.cluster) else {
                return false;
            };
            if entry
                .connector
                .compatible_with_cluster(current, &entry.endpoint)
            {
                entry.owner = Arc::downgrade(current);
                true
            } else {
                false
            }
        });
        drop(registry);
        debug_assert!(self.pools_count() <= self.max_entries);
    }

    pub(crate) fn get_or_build(
        &self,
        key: PoolIdentity,
        cluster: &Arc<PreparedCluster>,
        connector: DirectConnector,
        protocol: ClusterProtocol,
        max_idle: usize,
    ) -> Arc<Client<DirectConnector, B>> {
        let mut registry = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .entries
            .retain(|_, entry| entry.owner.strong_count() > 0);
        registry.clock = registry.clock.saturating_add(1);
        let now = registry.clock;
        if let Some(entry) = registry.entries.get_mut(&key) {
            entry.last_used = now;
            return Arc::clone(&entry.pool);
        }
        let pool = Arc::new(build_upstream_pool(connector.clone(), protocol, max_idle));
        let current_owner = !registry.reconciled
            || registry
                .current
                .get(cluster.id())
                .and_then(Weak::upgrade)
                .is_some_and(|owner| Arc::ptr_eq(&owner, cluster));
        if !current_owner {
            // A request pinned before publication can reach Proxy afterwards.
            // Its private Arc dies with that attempt instead of retaining the
            // retired resource in a global strong or weak-key map.
            return pool;
        }
        if registry.entries.len() >= self.max_entries {
            let least_recent = registry
                .entries
                .iter()
                .min_by_key(|(_, entry)| (Arc::strong_count(&entry.pool) > 1, entry.last_used))
                .map(|(key, _)| *key);
            if let Some(key) = least_recent {
                registry.entries.remove(&key);
            }
        }
        // Recover the static endpoint name from its domain-separated key;
        // names are configuration-bounded and never derived from request data.
        let endpoint = cluster
            .endpoints()
            .iter()
            .find(|endpoint| connector.pool_identity(cluster.id(), endpoint.name()) == key)
            .map_or_else(String::new, |endpoint| endpoint.name().to_owned());
        registry.entries.insert(
            key,
            PoolEntry {
                pool: Arc::clone(&pool),
                owner: Arc::downgrade(cluster),
                cluster: cluster.id().clone(),
                endpoint,
                connector,
                last_used: now,
            },
        );
        pool
    }

    pub(crate) fn get_existing(
        &self,
        key: PoolIdentity,
    ) -> Option<Arc<Client<DirectConnector, B>>> {
        let mut registry = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .entries
            .retain(|_, entry| entry.owner.strong_count() > 0);
        registry.clock = registry.clock.saturating_add(1);
        let now = registry.clock;
        let entry = registry.entries.get_mut(&key)?;
        entry.last_used = now;
        Some(Arc::clone(&entry.pool))
    }

    pub(crate) fn pools_count(&self) -> usize {
        let mut registry = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        registry
            .entries
            .retain(|_, entry| entry.owner.strong_count() > 0);
        registry.entries.len()
    }

    /// A physical reconnect failure retires only this exact Client. Existing
    /// attempts keep their own Arc; a late old attempt cannot evict a newer
    /// pool published under the same endpoint identity.
    pub(crate) fn retire_failed_pool(&self, failed: &Arc<Client<DirectConnector, B>>) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .retain(|_, entry| !Arc::ptr_eq(&entry.pool, failed));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use http_body_util::Empty;
    use oxidase_config::Compiler;
    use tempfile::TempDir;

    use super::*;
    use crate::upstream_transport::{DialTarget, LogicalOrigin, TransportTimeouts};

    fn snapshot(retry_attempts: u32) -> RuntimeSnapshot {
        let directory = TempDir::new().expect("temporary fixture");
        let path = directory.path().join("gateway.yaml");
        std::fs::write(&path, format!("api_version: oxidase.dev/v1alpha1\nkind: gateway\nresources:\n  clusters:\n    api:\n      endpoints:\n        - name: a\n          url: http://127.0.0.1:8001/a\n        - name: b\n          url: http://127.0.0.1:8002/b\n        - name: c\n          url: http://127.0.0.1:8003/c\n      retry:\n        max_attempts: {retry_attempts}\n        methods: [GET]\n        retry_on: [connect_failure]\nlisteners:\n  - name: public\n    bind: 127.0.0.1:0\n    service:\n      type: respond\n")).expect("fixture written");
        RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("fixture compiles"))
            .expect("fixture prepares")
    }

    fn pool(
        registry: &BoundedPoolRegistry<Empty<Bytes>>,
        cluster: &Arc<PreparedCluster>,
        index: usize,
    ) -> Arc<Client<DirectConnector, Empty<Bytes>>> {
        let endpoint = &cluster.endpoints()[index];
        let origin = LogicalOrigin::from_url(endpoint.url()).expect("logical origin");
        let target = DialTarget::new(
            format!("127.0.0.1:{}", 8001 + index)
                .parse()
                .expect("test address"),
        )
        .expect("target");
        let connector = DirectConnector::new(
            origin,
            target,
            cluster.protocol(),
            None,
            TransportTimeouts::for_cluster(cluster),
        )
        .expect("connector");
        let key = connector.pool_identity(cluster.id(), endpoint.name());
        registry.get_or_build(key, cluster, connector, cluster.protocol(), 2)
    }

    #[tokio::test]
    async fn strong_pool_entries_are_bounded_idle_lru_is_reclaimed_and_active_arc_survives() {
        let snapshot = snapshot(1);
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        let registry = BoundedPoolRegistry::new(2);
        registry.reconcile_snapshot(&snapshot);
        let active = pool(&registry, &cluster, 0);
        let idle = pool(&registry, &cluster, 1);
        let idle_weak = Arc::downgrade(&idle);
        drop(idle);
        let third = pool(&registry, &cluster, 2);
        assert_eq!(registry.pools_count(), 2);
        assert!(
            idle_weak.upgrade().is_none(),
            "no weak-key registry resurrects retired idle pool"
        );
        assert!(
            Arc::ptr_eq(&active, &pool(&registry, &cluster, 0)),
            "active lease survives bounded eviction"
        );
        drop(third);
        drop(active);
    }

    #[tokio::test]
    async fn retirement_removes_all_cached_keys_without_pinning_resource_or_existing_client() {
        let snapshot = snapshot(1);
        let cluster = Arc::clone(
            snapshot
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        let weak_owner = Arc::downgrade(&cluster);
        let registry = BoundedPoolRegistry::new(2);
        registry.reconcile_snapshot(&snapshot);
        let old = pool(&registry, &cluster, 0);
        let mut removed = snapshot.clone();
        removed.resources.clusters.clear();
        registry.reconcile_snapshot(&removed);
        assert_eq!(registry.pools_count(), 0);
        let retired = pool(&registry, &cluster, 0);
        assert!(!Arc::ptr_eq(&old, &retired));
        assert_eq!(
            registry.pools_count(),
            0,
            "late pinned attempt is not reinserted"
        );
        drop(snapshot);
        drop(cluster);
        assert!(
            weak_owner.upgrade().is_none(),
            "client/registry do not own Cluster tasks"
        );
        drop(old);
        drop(retired);
    }

    #[tokio::test]
    async fn compatible_policy_reload_reuses_pool_but_changed_transport_is_not_rebound() {
        let snapshot_a = snapshot(1);
        let cluster_a = Arc::clone(
            snapshot_a
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        let registry = BoundedPoolRegistry::new(2);
        registry.reconcile_snapshot(&snapshot_a);
        let pool_a = pool(&registry, &cluster_a, 0);
        let snapshot_b = snapshot(2);
        let cluster_b = Arc::clone(
            snapshot_b
                .resources
                .clusters
                .values()
                .next()
                .expect("cluster"),
        );
        assert!(!Arc::ptr_eq(&cluster_a, &cluster_b));
        registry.reconcile_snapshot(&snapshot_b);
        assert!(
            Arc::ptr_eq(&pool_a, &pool(&registry, &cluster_b, 0)),
            "retry policy does not change transport identity"
        );

        let mut spec = cluster_b.spec().clone();
        spec.connect_timeout = Duration::from_millis(200);
        let (changed, _) = PreparedCluster::prepare(spec, Some(cluster_b.as_ref()));
        let changed = Arc::new(changed);
        let mut snapshot_changed = snapshot_b.clone();
        snapshot_changed
            .resources
            .clusters
            .insert(changed.id().clone(), Arc::clone(&changed));
        registry.reconcile_snapshot(&snapshot_changed);
        assert_eq!(registry.pools_count(), 0);
        assert!(!Arc::ptr_eq(&pool_a, &pool(&registry, &changed, 0)));
    }

    #[tokio::test]
    async fn protocol_change_retires_normal_h2_pool_but_preserves_explicit_http1_upgrade_override()
    {
        let mut snapshot = snapshot(1);
        let source = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster")
            .spec()
            .clone();
        let mut h2 = source.clone();
        h2.protocol = ClusterProtocol::H2;
        let h2 = Arc::new(PreparedCluster::prepare(h2, None).0);
        snapshot
            .resources
            .clusters
            .insert(h2.id().clone(), Arc::clone(&h2));
        let registry = BoundedPoolRegistry::<Empty<Bytes>>::new(8);
        registry.reconcile_snapshot(&snapshot);
        let old_normal = pool(&registry, &h2, 0);
        let endpoint = &h2.endpoints()[0];
        let connector = DirectConnector::new(
            LogicalOrigin::from_url(endpoint.url()).expect("origin"),
            DialTarget::new("127.0.0.1:8001".parse().expect("address")).expect("target"),
            ClusterProtocol::Http1,
            None,
            TransportTimeouts::for_cluster(&h2),
        )
        .expect("connector")
        .for_http1_upgrade();
        let upgrade_key = connector.pool_identity(h2.id(), endpoint.name());
        let upgrade = registry.get_or_build(upgrade_key, &h2, connector, ClusterProtocol::Http1, 2);
        assert_eq!(registry.pools_count(), 2);
        let mut http1 = source;
        http1.protocol = ClusterProtocol::Http1;
        let http1 = Arc::new(PreparedCluster::prepare(http1, Some(&h2)).0);
        snapshot
            .resources
            .clusters
            .insert(http1.id().clone(), Arc::clone(&http1));
        registry.reconcile_snapshot(&snapshot);
        assert_eq!(
            registry.pools_count(),
            1,
            "ordinary old H2 protocol cannot survive policy change"
        );
        assert!(Arc::ptr_eq(
            &upgrade,
            &registry
                .get_existing(upgrade_key)
                .expect("intentional H1 override remains compatible")
        ));
        let normal = pool(&registry, &http1, 0);
        assert!(!Arc::ptr_eq(&old_normal, &normal));
        assert!(!Arc::ptr_eq(&upgrade, &normal));
    }

    #[tokio::test]
    async fn failed_pool_retirement_uses_exact_arc_and_cannot_remove_a_newer_replacement() {
        let snapshot = snapshot(1);
        let cluster = snapshot
            .resources
            .clusters
            .values()
            .next()
            .expect("cluster");
        let registry = BoundedPoolRegistry::new(2);
        registry.reconcile_snapshot(&snapshot);
        let failed = pool(&registry, cluster, 0);
        let sibling = pool(&registry, cluster, 1);
        registry.retire_failed_pool(&failed);
        assert_eq!(registry.pools_count(), 1);
        let replacement = pool(&registry, cluster, 0);
        assert!(!Arc::ptr_eq(&failed, &replacement));
        registry.retire_failed_pool(&failed);
        assert_eq!(registry.pools_count(), 2);
        assert!(Arc::ptr_eq(&replacement, &pool(&registry, cluster, 0)));
        assert!(Arc::ptr_eq(&sibling, &pool(&registry, cluster, 1)));
        assert_eq!(
            Arc::strong_count(&failed),
            1,
            "issued failed Client remains independently owned"
        );
    }
}
