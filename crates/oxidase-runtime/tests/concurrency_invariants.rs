//! Deterministic concurrency coverage for runtime publication and Cluster state.
//!
//! These tests deliberately contain no network I/O. Barriers keep permits and
//! activation claims alive across the observation point so scheduling cannot
//! turn a concurrency assertion into a timing assertion.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use http::Method;
use oxidase_config::{
    ClusterEndpointSpec, ClusterHealthSpec, ClusterLimits, ClusterProtocol, ClusterSpec, Compiler,
    LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryRequestBodySpec, RetrySpec,
};
use oxidase_core::{ResourceId, SourceSpan};
use oxidase_runtime::{
    ClusterAdmissionError, EndpointHealthState, PreparedCluster, RuntimeSnapshot, SnapshotStore,
};
use tempfile::TempDir;
use tokio::sync::{Barrier as AsyncBarrier, Semaphore, mpsc};
use url::Url;

fn endpoint(name: &str, url: &str) -> ClusterEndpointSpec {
    ClusterEndpointSpec {
        name: name.to_owned(),
        url: Url::parse(url).expect("fixture endpoint URL is valid"),
        weight: 1,
        name_source: SourceSpan::synthetic(format!("endpoints.{name}.name")),
        url_source: SourceSpan::synthetic(format!("endpoints.{name}.url")),
        weight_source: SourceSpan::synthetic(format!("endpoints.{name}.weight")),
        source: SourceSpan::synthetic(format!("endpoints.{name}")),
    }
}

fn cluster_spec(endpoints: Vec<ClusterEndpointSpec>) -> ClusterSpec {
    ClusterSpec {
        id: ResourceId::new("cluster:concurrency"),
        protocol: ClusterProtocol::Auto,
        tls: None,
        endpoints,
        load_balance: LoadBalancePolicy::RoundRobin,
        health: ClusterHealthSpec {
            active: None,
            passive: Some(PassiveHealthSpec {
                consecutive_failures: 2,
                eject_for: Duration::from_secs(30),
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

fn snapshot(directory: &TempDir, suffix: &str) -> RuntimeSnapshot {
    let path = directory.path().join(format!("{suffix}.yaml"));
    std::fs::write(
        &path,
        format!(
            r#"api_version: oxidase.dev/v1alpha1
kind: gateway
services:
  {suffix}:
    type: respond
    body:
      text: {suffix}
listeners:
  - name: public
    bind: 127.0.0.1:0
    service:
      ref: {suffix}
"#
        ),
    )
    .expect("fixture source is written");
    RuntimeSnapshot::prepare(Compiler::compile_path(path).expect("fixture source compiles"))
        .expect("fixture snapshot prepares")
}

#[test]
fn concurrent_snapshot_publication_keeps_listener_plan_and_graph_coherent() {
    const READERS: usize = 8;
    const PUBLISHES: usize = 2_000;

    let directory = TempDir::new().expect("temporary directory is available");
    let old = snapshot(&directory, "old");
    let new = snapshot(&directory, "new");
    let old_version = old.config_version.to_string();
    let new_version = new.config_version.to_string();
    assert_ne!(old_version, new_version);

    let store = Arc::new(SnapshotStore::new(old.clone()));
    let old_pin = store.pin();
    let old_pin_weak = Arc::downgrade(&old_pin);
    let start = Arc::new(Barrier::new(READERS + 1));
    let readers = (0..READERS)
        .map(|_| {
            let store = Arc::clone(&store);
            let start = Arc::clone(&start);
            let old_version = old_version.clone();
            let new_version = new_version.clone();
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..PUBLISHES {
                    let pinned = store.pin();
                    let plan = pinned
                        .prepared_listener_for("public")
                        .expect("published snapshot has its listener plan");
                    let program = pinned
                        .program_for("public")
                        .expect("published snapshot has its Service program");
                    assert_eq!(plan.service, program.entry);
                    assert!(program.graph.get(&program.entry).is_some());
                    let expected_service = match pinned.config_version.as_str() {
                        version if version == old_version => "service:old",
                        version if version == new_version => "service:new",
                        version => panic!("unexpected published version {version}"),
                    };
                    assert_eq!(plan.service.as_str(), expected_service);
                }
            })
        })
        .collect::<Vec<_>>();

    start.wait();
    for sequence in 0..PUBLISHES {
        let replacement = if sequence % 2 == 0 {
            old.clone()
        } else {
            new.clone()
        };
        drop(store.publish(replacement));
    }
    for reader in readers {
        reader.join().expect("snapshot reader does not panic");
    }

    drop(store.publish(new.clone()));
    assert_eq!(
        store.pin().config_version.as_str(),
        new.config_version.as_str()
    );
    assert_eq!(
        old_pin
            .prepared_listener_for("public")
            .expect("old pin keeps its listener plan")
            .service
            .as_str(),
        "service:old"
    );
    drop(old);
    drop(old_pin);
    assert!(
        old_pin_weak.upgrade().is_none(),
        "the displaced snapshot is released after its last pin"
    );
}

#[test]
fn concurrent_passive_failures_cross_the_threshold_once() {
    const FAILURES: usize = 16;

    let mut spec = cluster_spec(vec![endpoint("a", "http://a.test")]);
    spec.health
        .passive
        .as_mut()
        .expect("fixture has passive health")
        .consecutive_failures = FAILURES as u32;
    let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
    let now = Instant::now();
    let start = Arc::new(Barrier::new(FAILURES + 1));
    let workers = (0..FAILURES)
        .map(|_| {
            let cluster = Arc::clone(&cluster);
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                cluster.record_passive_failure("a", now);
            })
        })
        .collect::<Vec<_>>();
    start.wait();
    for worker in workers {
        worker.join().expect("health worker does not panic");
    }

    let endpoint = &cluster.status(now).endpoints[0].runtime;
    assert_eq!(endpoint.health, EndpointHealthState::PassivelyEjected);
    assert_eq!(endpoint.failures, FAILURES as u64);
    assert_eq!(endpoint.passive_ejections, 1);
    assert_eq!(endpoint.health_transitions, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_admission_never_exceeds_cluster_or_endpoint_limits() {
    const REQUESTS: usize = 32;
    const CLUSTER_LIMIT: usize = 4;
    const ENDPOINT_LIMIT: usize = 2;

    let mut spec = cluster_spec(vec![
        endpoint("a", "http://a.test"),
        endpoint("b", "http://b.test"),
    ]);
    spec.limits.max_in_flight = CLUSTER_LIMIT as u32;
    spec.limits.max_in_flight_per_endpoint = ENDPOINT_LIMIT as u32;
    let cluster = Arc::new(PreparedCluster::prepare(spec, None).0);
    let start = Arc::new(AsyncBarrier::new(REQUESTS + 1));
    let release = Arc::new(Semaphore::new(0));
    let (observed_tx, mut observed_rx) = mpsc::unbounded_channel();
    let mut workers = Vec::with_capacity(REQUESTS);
    for _ in 0..REQUESTS {
        let cluster = Arc::clone(&cluster);
        let start = Arc::clone(&start);
        let release = Arc::clone(&release);
        let observed_tx = observed_tx.clone();
        workers.push(tokio::spawn(async move {
            start.wait().await;
            match cluster.acquire().await {
                Ok(permit) => {
                    observed_tx
                        .send(Some(permit.endpoint().name().to_owned()))
                        .expect("observer remains available");
                    let release = release.acquire().await.expect("release gate remains open");
                    drop(release);
                    drop(permit);
                }
                Err(ClusterAdmissionError::Overloaded) => {
                    observed_tx.send(None).expect("observer remains available");
                }
                Err(ClusterAdmissionError::Unavailable) => {
                    panic!("healthy fixture endpoints must remain available");
                }
            }
        }));
    }
    drop(observed_tx);

    start.wait().await;
    let mut admitted_by_endpoint = BTreeMap::<String, usize>::new();
    for _ in 0..REQUESTS {
        if let Some(endpoint) = observed_rx
            .recv()
            .await
            .expect("every worker reports one admission result")
        {
            *admitted_by_endpoint.entry(endpoint).or_default() += 1;
        }
    }
    assert_eq!(admitted_by_endpoint.values().sum::<usize>(), CLUSTER_LIMIT);
    assert_eq!(admitted_by_endpoint.get("a"), Some(&ENDPOINT_LIMIT));
    assert_eq!(admitted_by_endpoint.get("b"), Some(&ENDPOINT_LIMIT));
    assert_eq!(cluster.active_requests(), CLUSTER_LIMIT as u64);
    assert!(
        cluster
            .endpoints()
            .iter()
            .all(|endpoint| endpoint.active_requests() == ENDPOINT_LIMIT as u64)
    );

    release.add_permits(CLUSTER_LIMIT);
    for worker in workers {
        worker.await.expect("admission worker does not panic");
    }
    assert_eq!(cluster.active_requests(), 0);
    assert!(
        cluster
            .endpoints()
            .iter()
            .all(|endpoint| endpoint.active_requests() == 0)
    );
}

#[test]
fn retry_budget_and_supervisor_activation_have_single_concurrent_winners() {
    const WORKERS: usize = 16;

    let cluster = Arc::new(
        PreparedCluster::prepare(cluster_spec(vec![endpoint("a", "http://a.test")]), None).0,
    );

    let run_race = |operation: Arc<dyn Fn() -> bool + Send + Sync>| {
        let start = Arc::new(Barrier::new(WORKERS + 1));
        let observation = Arc::new(Barrier::new(WORKERS + 1));
        let workers = (0..WORKERS)
            .map(|_| {
                let operation = Arc::clone(&operation);
                let start = Arc::clone(&start);
                let observation = Arc::clone(&observation);
                std::thread::spawn(move || {
                    start.wait();
                    let won = operation();
                    observation.wait();
                    won
                })
            })
            .collect::<Vec<_>>();
        start.wait();
        observation.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("race worker does not panic"))
            .filter(|won| *won)
            .count()
    };

    let retry_cluster = Arc::clone(&cluster);
    let retry_holders = Arc::new(std::sync::Mutex::new(Vec::new()));
    let retry_holders_for_operation = Arc::clone(&retry_holders);
    let retry_winners = run_race(Arc::new(move || {
        let Some(permit) = retry_cluster.try_acquire_retry() else {
            return false;
        };
        retry_holders_for_operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(permit);
        true
    }));
    assert_eq!(retry_winners, 1);
    assert_eq!(cluster.active_retries(), 1);
    retry_holders
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    assert_eq!(cluster.active_retries(), 0);

    let supervisor_cluster = Arc::clone(&cluster);
    let activation_winners = run_race(Arc::new(move || {
        supervisor_cluster.try_activate_supervisor()
    }));
    assert_eq!(activation_winners, 1);
    assert!(cluster.supervisor_is_activated());
}
