use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use oxidase_config::{DnsRecordType, LoadBalancePolicy};
use oxidase_runtime::{
    ClusterRequestPermit, DiscoveryErrorCode, DnsAddressRecord, DnsFamily, DnsObservation,
    PreparedCluster, SrvObservation, SrvRecord, SrvSelectionRng, SrvTargetAddressObservation,
    validate_discovery_address,
};
use tokio::time::Instant;

use crate::discovery_support::{self, byte};

const MAX_OPERATIONS: usize = 128;
const MAX_HELD: usize = 8;
const TARGETS: [&str; 3] = ["a.example.test.", "b.example.test.", "c.example.test."];
const ADDRESSES: [&str; 9] = [
    "198.51.100.1",
    "198.51.100.2",
    "2001:db8::1",
    "::ffff:198.51.100.1",
    "127.0.0.1",
    "::ffff:127.0.0.1",
    "169.254.0.1",
    "0.0.0.0",
    "ff02::1",
];

struct Held {
    permit: ClusterRequestPermit,
    target: Option<SocketAddr>,
    origin: String,
}

pub fn run(data: &[u8]) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .expect("bounded current-thread test runtime");
    runtime.block_on(exercise(&data[..data.len().min(12 * MAX_OPERATIONS)]));
}

async fn exercise(data: &[u8]) {
    // Bootstrap success in every iteration; this is not merely a parser fuzzer.
    assert!(
        discovery_support::plan()
            .required_features()
            .contains(oxidase_config::DNS_SRV_DISCOVERY_FEATURE)
    );
    let mut cluster = PreparedCluster::prepare(discovery_support::spec(true), None).0;
    assert!(
        cluster.begin_discovery_query().is_none(),
        "prepare starts no discovery task"
    );
    assert!(cluster.activate_discovery_policy());
    publish(&cluster, &[], true);
    drop(cluster.acquire().await.expect("valid bootstrap lease"));
    let mut held = Vec::<Held>::new();

    for operation in data.chunks(12).take(MAX_OPERATIONS) {
        match byte(operation, 0) % 16 {
            0 | 1 => publish(&cluster, operation, false),
            2 => observe_failure(&cluster, operation),
            3 => revoke(&cluster, true),
            4 => revoke(&cluster, false),
            5 => tokio::time::advance(Duration::from_millis(u64::from(byte(operation, 1)))).await,
            6 => {
                if held.len() < MAX_HELD
                    && let Ok(permit) = cluster.acquire().await
                {
                    let target = permit.dial_target();
                    let endpoint = permit.endpoint();
                    assert!(cluster.contains_endpoint(endpoint));
                    let policy = &cluster
                        .spec()
                        .discovery
                        .as_ref()
                        .expect("DNS")
                        .address_policy;
                    let dial = target.expect("discovery fixes actual SocketAddr");
                    assert_eq!(
                        validate_discovery_address(dial.ip(), dial.port(), policy),
                        Ok(dial)
                    );
                    assert_eq!(
                        endpoint.url(),
                        &cluster.spec().discovery.as_ref().expect("DNS").origin
                    );
                    held.push(Held {
                        origin: endpoint.url().to_string(),
                        permit,
                        target,
                    });
                }
            }
            7 => {
                if !held.is_empty() {
                    held.swap_remove(usize::from(byte(operation, 1)) % held.len());
                }
            }
            8 | 9 => {
                if let Some(endpoint) = held
                    .get(usize::from(byte(operation, 1)) % held.len().max(1))
                    .map(|held| Arc::clone(held.permit.endpoint()))
                    .or_else(|| cluster.endpoints().first().cloned())
                {
                    if byte(operation, 0) % 16 == 8 {
                        cluster.record_active_health_for(
                            &endpoint,
                            byte(operation, 2) & 1 == 0,
                            Instant::now().into_std(),
                        );
                    } else if byte(operation, 2) & 1 == 0 {
                        cluster.record_passive_success_for(&endpoint);
                    } else {
                        cluster.record_passive_failure_for(&endpoint, Instant::now().into_std());
                    }
                }
            }
            10 => {
                if let Some(old) = held.first_mut() {
                    let endpoint = Arc::clone(old.permit.endpoint());
                    let tried = BTreeSet::from([endpoint.name().to_owned()]);
                    if let Some(reservation) =
                        cluster.reserve_retry_endpoint_for(&tried, &endpoint).await
                    {
                        if byte(operation, 1) & 1 == 0 {
                            // Retry reservation cancellation leaves the old lease intact.
                            drop(reservation);
                        } else if old.permit.retarget_reserved(reservation) {
                            old.target = old.permit.dial_target();
                            old.origin = old.permit.endpoint().url().to_string();
                        }
                    }
                }
                drop(cluster.try_acquire_retry());
            }
            11 => {
                let query = cluster.begin_discovery_query();
                cluster.retire_discovery_policy();
                assert!(cluster.acquire().await.is_err());
                assert!(cluster.begin_discovery_query().is_none());
                assert!(cluster.activate_discovery_policy());
                if let Some(query) = query {
                    assert!(
                        !cluster
                            .reconcile_srv(&query, SrvObservation::NoData, Instant::now())
                            .applied
                    );
                    assert!(
                        !cluster
                            .reconcile_dns(
                                &query,
                                DnsFamily::A,
                                DnsObservation::NoData,
                                Instant::now()
                            )
                            .applied
                    );
                }
            }
            12 => {
                let old_query = cluster.begin_discovery_query();
                let mut spec = cluster.spec().clone();
                spec.load_balance = match byte(operation, 1) % 3 {
                    0 => LoadBalancePolicy::RoundRobin,
                    1 => LoadBalancePolicy::WeightedRoundRobin,
                    _ => LoadBalancePolicy::LeastRequests,
                };
                spec.limits.max_in_flight = u32::from(byte(operation, 2) % 8 + 1);
                spec.limits.max_in_flight_per_endpoint = u32::from(byte(operation, 3) % 2 + 1);
                let plan = spec.discovery.as_mut().expect("DNS plan");
                let srv = byte(operation, 4) & 1 == 0;
                plan.record = if srv {
                    DnsRecordType::Srv
                } else {
                    DnsRecordType::AAndAaaa
                };
                plan.name = if srv {
                    "_http._tcp.lookup.example.test."
                } else {
                    "lookup.example.test."
                }
                .to_owned();
                plan.port = (!srv).then_some(8080);
                plan.address_policy.allow_loopback = byte(operation, 5) & 1 != 0;
                let replacement = PreparedCluster::prepare(spec, Some(&cluster)).0;
                cluster.retire_discovery_policy();
                cluster = replacement;
                assert!(cluster.activate_discovery_policy());
                if let Some(query) = old_query {
                    assert!(
                        !cluster
                            .reconcile_srv(&query, SrvObservation::NoData, Instant::now())
                            .applied
                    );
                    assert!(
                        !cluster
                            .reconcile_dns(
                                &query,
                                DnsFamily::A,
                                DnsObservation::NoData,
                                Instant::now()
                            )
                            .applied
                    );
                }
            }
            13 => {
                let weights = [
                    u16::from(byte(operation, 1)),
                    u16::from_le_bytes([byte(operation, 2), byte(operation, 3)]),
                    0,
                    u16::MAX,
                ];
                let mut rng = SrvSelectionRng::new(u64::from(byte(operation, 4)));
                let mut repeat = SrvSelectionRng::new(u64::from(byte(operation, 4)));
                for _ in 0..8 {
                    let selected = rng.weighted_index(&weights).expect("bounded weights");
                    assert!(selected < weights.len());
                    assert_eq!(Some(selected), repeat.weighted_index(&weights));
                }
                assert!(rng.weighted_index(&[]).is_none());
                assert!(rng.weighted_index(&[0, 0, 0]).is_some());
            }
            14 => {
                let _ = cluster.select_endpoint(Instant::now().into_std());
                let bytes = serde_json::to_vec(&cluster.status(Instant::now().into_std()))
                    .expect("bounded status serializes");
                let _: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("valid status JSON");
            }
            _ => exact_deadline_oracle().await,
        }
        check(&cluster, &held);
    }
    held.clear();
    assert_eq!(
        cluster.active_requests(),
        0,
        "all upload/response leases release"
    );
    assert_eq!(cluster.active_retries(), 0);
    cluster.retire_discovery_policy();
    assert!(cluster.endpoints().is_empty());
}

fn check(cluster: &PreparedCluster, held: &[Held]) {
    assert_eq!(cluster.active_requests(), held.len() as u64);
    assert!(cluster.active_requests() <= MAX_HELD as u64);
    assert_eq!(cluster.active_retries(), 0);
    let plan = cluster.spec().discovery.as_ref().expect("discovery plan");
    let endpoints = cluster.endpoints();
    assert!(endpoints.len() <= usize::from(plan.limits.max_endpoints));
    let names = endpoints
        .iter()
        .map(|endpoint| endpoint.name())
        .collect::<BTreeSet<_>>();
    assert_eq!(names.len(), endpoints.len());
    for endpoint in &*endpoints {
        let dial = endpoint.dial_target().expect("never a second DNS lookup");
        assert_eq!(
            validate_discovery_address(dial.ip(), dial.port(), &plan.address_policy),
            Ok(dial)
        );
        assert_eq!(endpoint.url(), &plan.origin);
        assert_ne!(endpoint.incarnation(), 0);
    }
    let status = cluster
        .discovery_status()
        .expect("bounded operational status");
    assert!(status.srv_targets.len() <= oxidase_config::MAX_DNS_RECORDS);
    assert!(status.retired_admission_counters <= usize::from(plan.limits.max_endpoints) + MAX_HELD);
    for old in held {
        assert_eq!(
            old.permit.dial_target(),
            old.target,
            "refresh never rewrites an issued lease"
        );
        assert_eq!(old.permit.endpoint().url().as_str(), old.origin);
    }
}

fn publish(cluster: &PreparedCluster, data: &[u8], bootstrap: bool) {
    let Some(query) = cluster.begin_discovery_query() else {
        return;
    };
    let now = Instant::now();
    let fresh_until = now
        + Duration::from_millis(if bootstrap {
            100
        } else {
            u64::from(byte(data, 6))
        });
    let address: IpAddr = if bootstrap {
        "198.51.100.1"
    } else {
        ADDRESSES[usize::from(byte(data, 2)) % ADDRESSES.len()]
    }
    .parse()
    .expect("test-only IP");
    let family = if address.is_ipv6() {
        DnsFamily::Aaaa
    } else {
        DnsFamily::A
    };
    let mut addresses = vec![DnsAddressRecord {
        address,
        fresh_until,
    }];
    if bootstrap || byte(data, 9) & 4 != 0 {
        addresses.push(DnsAddressRecord {
            address: if family == DnsFamily::A {
                "198.51.100.2"
            } else {
                "2001:db8::2"
            }
            .parse()
            .expect("documentation IP"),
            fresh_until: now
                + Duration::from_millis(if bootstrap {
                    100
                } else {
                    u64::from(byte(data, 3))
                }),
        });
    }
    let observation = DnsObservation::Positive { addresses };
    if cluster.spec().discovery.as_ref().expect("DNS").record == DnsRecordType::Srv {
        let target = TARGETS[usize::from(byte(data, 1)) % TARGETS.len()].to_owned();
        let port = if !bootstrap && byte(data, 4) == 255 {
            0
        } else {
            8080 + u16::from(byte(data, 4) & 1)
        };
        let record = SrvRecord {
            target: target.clone(),
            port,
            priority: u16::from(byte(data, 5)),
            weight: u16::from_le_bytes([byte(data, 10), byte(data, 11)]),
            fresh_until,
        };
        let mut records = vec![record.clone()];
        let mut observations = vec![SrvTargetAddressObservation {
            target: target.clone(),
            family,
            observation,
        }];
        if !bootstrap && byte(data, 0) & 1 != 0 && byte(data, 9).is_multiple_of(4) {
            let mut duplicate = record.clone();
            duplicate.weight = duplicate.weight.wrapping_add(u16::from(byte(data, 3) & 1));
            duplicate.fresh_until = now + Duration::from_millis(u64::from(byte(data, 3)));
            records.push(duplicate);
        }
        if bootstrap || !byte(data, 9).is_multiple_of(4) {
            let mut second = record;
            if !bootstrap && byte(data, 9) % 4 == 2 {
                // The same DNS target at another port is a distinct physical
                // member, without multiplying a target's address lookup.
                second.port = second.port.wrapping_add(1);
                second.priority = second.priority.wrapping_add(1);
            } else {
                second.target =
                    TARGETS[(usize::from(byte(data, 1)) + 1) % TARGETS.len()].to_owned();
                second.priority = if bootstrap || byte(data, 9) % 4 == 3 {
                    second.priority
                } else {
                    second.priority + 1
                };
                second.weight = second.weight.wrapping_add(u16::MAX);
                let sibling = match byte(data, 7) % 4 {
                    0 if !bootstrap => DnsObservation::NoData,
                    1 if !bootstrap => DnsObservation::NameNotFound,
                    2 if !bootstrap => DnsObservation::TransientFailure {
                        code: DiscoveryErrorCode::Refused,
                    },
                    _ => DnsObservation::Positive {
                        addresses: vec![DnsAddressRecord {
                            address: "198.51.100.3".parse().expect("documentation IP"),
                            fresh_until,
                        }],
                    },
                };
                observations.push(SrvTargetAddressObservation {
                    target: second.target.clone(),
                    family: DnsFamily::A,
                    observation: sibling,
                });
                if !bootstrap && byte(data, 7) % 4 == 1 {
                    // Contradictory sibling positive cannot resurrect target
                    // NXDOMAIN in either ordering of a complete round.
                    observations.push(SrvTargetAddressObservation {
                        target: second.target.clone(),
                        family: DnsFamily::Aaaa,
                        observation: DnsObservation::Positive {
                            addresses: vec![DnsAddressRecord {
                                address: "2001:db8::3".parse().expect("documentation IP"),
                                fresh_until,
                            }],
                        },
                    });
                    if byte(data, 8) & 1 != 0 {
                        observations.reverse();
                    }
                }
            }
            records.push(second);
        }
        let receipt = cluster.reconcile_srv(
            &query,
            SrvObservation::Positive {
                records,
                addresses: observations,
            },
            now,
        );
        assert!(receipt.applied);
    } else {
        assert!(
            cluster
                .reconcile_dns(&query, family, observation, now)
                .applied
        );
    }
}

fn observe_failure(cluster: &PreparedCluster, data: &[u8]) {
    let Some(query) = cluster.begin_discovery_query() else {
        return;
    };
    let code = match byte(data, 8) % 7 {
        0 => DiscoveryErrorCode::Timeout,
        1 => DiscoveryErrorCode::Network,
        2 => DiscoveryErrorCode::ServerFailure,
        3 => DiscoveryErrorCode::Refused,
        4 => DiscoveryErrorCode::PolicyRejected,
        5 => DiscoveryErrorCode::InvalidAnswer,
        _ => DiscoveryErrorCode::LimitExceeded,
    };
    if cluster.spec().discovery.as_ref().expect("DNS").record == DnsRecordType::Srv {
        cluster.reconcile_srv(
            &query,
            SrvObservation::TransientFailure { code },
            Instant::now(),
        );
    } else {
        let family = if byte(data, 7) & 1 == 0 {
            DnsFamily::A
        } else {
            DnsFamily::Aaaa
        };
        cluster.reconcile_dns(
            &query,
            family,
            DnsObservation::TransientFailure { code },
            Instant::now(),
        );
    }
}

fn revoke(cluster: &PreparedCluster, nxdomain: bool) {
    let Some(query) = cluster.begin_discovery_query() else {
        return;
    };
    if cluster.spec().discovery.as_ref().expect("DNS").record == DnsRecordType::Srv {
        let observation = if nxdomain {
            SrvObservation::NameNotFound
        } else {
            SrvObservation::NoData
        };
        cluster.reconcile_srv(&query, observation, Instant::now());
        if nxdomain {
            assert!(
                !cluster
                    .reconcile_srv(&query, SrvObservation::NoData, Instant::now())
                    .applied
            );
        }
    } else {
        let observation = if nxdomain {
            DnsObservation::NameNotFound
        } else {
            DnsObservation::NoData
        };
        cluster.reconcile_dns(&query, DnsFamily::A, observation, Instant::now());
        if nxdomain {
            assert!(
                !cluster
                    .reconcile_dns(
                        &query,
                        DnsFamily::Aaaa,
                        DnsObservation::NoData,
                        Instant::now()
                    )
                    .applied
            );
        }
    }
}

async fn exact_deadline_oracle() {
    // Independent fixed-expiry oracle, including a repeated failure. This
    // deliberately reaches the limit boundary instead of relying on a timer task.
    let cluster = PreparedCluster::prepare(discovery_support::spec(false), None).0;
    assert!(cluster.activate_discovery_policy());
    let start = Instant::now();
    let query = cluster.begin_discovery_query().expect("new family round");
    cluster.reconcile_dns(
        &query,
        DnsFamily::A,
        DnsObservation::Positive {
            addresses: vec![DnsAddressRecord {
                address: "198.51.100.1".parse().expect("documentation IP"),
                fresh_until: start + Duration::from_millis(10),
            }],
        },
        start,
    );
    drop(query);
    tokio::time::advance(Duration::from_millis(10)).await;
    observe_failure(&cluster, &[]);
    assert!(
        cluster.acquire().await.is_ok(),
        "temporary error permits finite original stale data"
    );
    tokio::time::advance(Duration::from_millis(49)).await;
    observe_failure(&cluster, &[]);
    assert!(cluster.acquire().await.is_ok());
    tokio::time::advance(Duration::from_millis(1)).await;
    observe_failure(&cluster, &[]);
    assert!(
        cluster.acquire().await.is_err(),
        "failure cannot renew expiry + grace"
    );
    assert_eq!(cluster.active_requests(), 0);
}
