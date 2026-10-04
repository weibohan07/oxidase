//! Bounded raw DNS observation. Membership, freshness/stale policy and refresh
//! scheduling belong to the committed Resource, not this transport boundary.
//! Hickory owns wire parsing, UDP/TCP fallback and query-ID validation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt as _;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::xfer::DnsHandle;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::{DnsRequestOptions, DnsResponse, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_resolver::{NameServerPool, PoolContext, TlsConfig};
use oxidase_config::{
    DnsAddressPolicy, DnsDiscoverySpec, DnsResolverSource, DnsResolverSpec, MAX_DNS_CNAME_DEPTH,
    MAX_DNS_NAMESERVERS, MAX_DNS_RECORDS, MAX_DNS_RESPONSE_BYTES, normalize_dns_ip,
};
use oxidase_runtime::{
    DiscoveryErrorCode, DnsAddressRecord, DnsFamily, DnsObservation, ResourceCensus, ResourceKind,
    ResourceState, ResourceToken, SrvObservation, SrvRecord, SrvTargetAddressObservation,
};
use tokio::sync::Semaphore;
use tokio::time::Instant;

pub(crate) const MAX_DNS_QUERIES: usize = 64;

pub(crate) struct DnsResolver {
    pool: NameServerPool<TokioRuntimeProvider>,
    query_timeout: Duration,
    admission: Arc<Semaphore>,
    target_failures: Mutex<BTreeMap<(String, bool), TargetFailureMemo>>,
    census: Arc<ResourceCensus>,
}

pub(crate) struct ResolvedFamily {
    pub(crate) observation: DnsObservation,
    /// SOA-derived negative expiry only. The supervisor separately caps its
    /// next query by max_interval and applies a non-busy-loop scheduling floor.
    pub(crate) retry_after: Option<Instant>,
}

pub(crate) struct ResolvedSrv {
    pub(crate) observation: SrvObservation,
    /// Whole-RRset negative expiry, or the earliest target-family memo expiry
    /// after a positive RRset. This schedules queries, never extends membership.
    pub(crate) retry_after: Option<Instant>,
}

struct TargetFailureMemo {
    _lifetime: ResourceToken,
    observation: DnsObservation,
    /// Operational query suppression, capped by the resource refresh policy.
    not_before: Instant,
    /// Original SOA/CNAME negative expiration; never rebased by a cache read.
    retry_after: Option<Instant>,
    failures: u8,
}

struct TargetResolution {
    target: String,
    family: DnsFamily,
    result: ResolvedFamily,
    cached: bool,
}

/// Counts observable results, not opaque EDNS/error bytes discarded by Hickory.
/// Individual wire packets remain bounded by Hickory at 65,535 bytes.
#[derive(Default)]
struct SrvRoundBudget {
    totals: Mutex<AnswerBudget>,
    exhausted: AtomicBool,
}

impl SrvRoundBudget {
    fn reserve_name(&self, name: &Name, limit: usize) -> Result<(), DnsObservation> {
        let mut budget = self
            .totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        budget.names.insert(name.clone());
        if budget.names.len() > limit {
            self.exhausted.store(true, Ordering::Relaxed);
            return Err(DnsObservation::LimitExceeded);
        }
        Ok(())
    }

    fn charge(&self, response: &DnsResponse) -> Result<(), DnsObservation> {
        let result = self
            .totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .charge(response);
        if result.is_err() {
            self.exhausted.store(true, Ordering::Relaxed);
        }
        result
    }

    fn charge_error(&self, error: &NetError) -> Result<(), DnsObservation> {
        let NetError::Dns(DnsError::NoRecordsFound(records)) = error else {
            return Ok(());
        };
        let mut message = hickory_resolver::proto::op::Message::error_msg(
            0,
            hickory_resolver::proto::op::OpCode::Query,
            records.response_code,
        );
        message.queries.push((*records.query).clone());
        if let Some(authorities) = &records.authorities {
            message.authorities = authorities.to_vec();
        }
        if let Some(servers) = &records.ns {
            for server in servers.iter() {
                message.additionals.extend(server.glue.iter().cloned());
            }
        }
        let response = DnsResponse::from_message(message).map_err(|_| {
            self.exhausted.store(true, Ordering::Relaxed);
            DnsObservation::LimitExceeded
        })?;
        self.charge(&response)
    }

    fn exhausted(&self, limit: usize) -> bool {
        let budget = self
            .totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.exhausted.load(Ordering::Relaxed)
            || budget.names.len() > limit
            || budget.records > MAX_DNS_RECORDS
            || budget.bytes > MAX_DNS_RESPONSE_BYTES
    }
}

/// Bootstrap errors carry fixed diagnostic codes, never resolver file content.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum DnsResolverBootstrapError {
    #[error("discovery.system_resolver: local resolver settings could not be loaded")]
    SystemConfiguration,
    #[error("discovery.nameservers: resolver requires between one and four IP nameservers")]
    NameServerLimit,
    #[error("discovery.nameservers: invalid nameserver address or transport")]
    NameServerAddress,
    #[error("discovery.resolver: DNS transport could not be constructed")]
    Transport,
}

impl DnsResolverBootstrapError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::SystemConfiguration => "discovery.system_resolver",
            Self::NameServerLimit => "discovery.nameserver_limit",
            Self::NameServerAddress => "discovery.nameserver_address",
            Self::Transport => "discovery.resolver_transport",
        }
    }

    pub(crate) const fn field(self) -> &'static str {
        match self {
            Self::SystemConfiguration => "resolver.system",
            Self::NameServerLimit | Self::NameServerAddress => "resolver.nameservers",
            Self::Transport => "resolver",
        }
    }
}

/// Checks only local resolver inputs. The pool is dropped without polling a
/// query, creating a DNS socket, or starting an operational supervisor.
pub(crate) fn validate_bootstrap(spec: &DnsResolverSpec) -> Result<(), DnsResolverBootstrapError> {
    DnsResolver::new(spec, Arc::new(Semaphore::new(MAX_DNS_QUERIES))).map(drop)
}

impl DnsResolver {
    /// Only committed-owner bootstrap calls this. It may read local resolver
    /// inputs, but it cannot send a DNS query or start a refresh supervisor.
    pub(crate) fn new(
        spec: &DnsResolverSpec,
        admission: Arc<Semaphore>,
    ) -> Result<Self, DnsResolverBootstrapError> {
        Self::with_census(spec, admission, ResourceCensus::process())
    }

    pub(crate) fn with_census(
        spec: &DnsResolverSpec,
        admission: Arc<Semaphore>,
        census: Arc<ResourceCensus>,
    ) -> Result<Self, DnsResolverBootstrapError> {
        let mut servers = match &spec.source {
            DnsResolverSource::NameServers(addresses) => addresses
                .iter()
                .map(|address| server(*address))
                .collect::<Result<Vec<_>, _>>()?,
            DnsResolverSource::System => {
                let (config, _) = hickory_resolver::system_conf::read_system_conf()
                    .map_err(|_| DnsResolverBootstrapError::SystemConfiguration)?;
                let mut servers = Vec::new();
                for configured in config.name_servers {
                    // Copy only numeric IP:port UDP/TCP inputs, not search,
                    // hosts-file, encrypted discovery or implicit DNS names.
                    let port = configured
                        .connections
                        .iter()
                        .find(|connection| {
                            matches!(
                                connection.protocol,
                                hickory_resolver::config::ProtocolConfig::Udp
                                    | hickory_resolver::config::ProtocolConfig::Tcp
                            )
                        })
                        .map(|connection| connection.port)
                        .ok_or(DnsResolverBootstrapError::NameServerAddress)?;
                    let address = SocketAddr::new(configured.ip, port);
                    if !servers.iter().any(|existing: &NameServerConfig| {
                        existing.ip == address.ip()
                            && existing.connections[0].port == address.port()
                    }) {
                        servers.push(server(address)?);
                    }
                }
                servers
            }
        };
        if servers.is_empty() || servers.len() > MAX_DNS_NAMESERVERS {
            return Err(DnsResolverBootstrapError::NameServerLimit);
        }
        servers.sort_by_key(|server| (server.ip, server.connections[0].port));
        servers.dedup_by_key(|server| (server.ip, server.connections[0].port));
        let mut options = ResolverOpts::default();
        options.timeout = spec.query_timeout;
        options.attempts = 1;
        options.cache_size = 0;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 32;
        options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        let tls = TlsConfig::new().map_err(|_| DnsResolverBootstrapError::Transport)?;
        Ok(Self {
            pool: NameServerPool::from_config(
                servers,
                Arc::new(PoolContext::new(options, tls)),
                TokioRuntimeProvider::default(),
            ),
            query_timeout: spec.query_timeout,
            admission,
            target_failures: Mutex::new(BTreeMap::new()),
            census,
        })
    }

    pub(crate) fn resource_census(&self) -> &Arc<ResourceCensus> {
        &self.census
    }

    /// A and AAAA complete independently. Every selected RR's expiration is
    /// anchored at the response that supplied it, and constrained by each CNAME
    /// edge's original expiration. No cached result receives a restarted TTL.
    #[cfg(test)]
    pub(crate) async fn resolve_family(
        &self,
        spec: &DnsDiscoverySpec,
        family: DnsFamily,
    ) -> DnsObservation {
        self.resolve_family_with_schedule(spec, family)
            .await
            .observation
    }

    pub(crate) async fn resolve_family_with_schedule(
        &self,
        spec: &DnsDiscoverySpec,
        family: DnsFamily,
    ) -> ResolvedFamily {
        // One logical family resolution including its CNAME chain; this is
        // not a count of packets or Hickory's private transport tasks.
        let observation = self
            .census
            .token(ResourceKind::DnsQuery, ResourceState::Waiting);
        let Some(deadline) = Instant::now().checked_add(self.query_timeout) else {
            return ResolvedFamily {
                observation: DnsObservation::InvalidAnswer,
                retry_after: None,
            };
        };
        let mut retry_after = None;
        let work = async {
            let Ok(_permit) = self.admission.acquire().await else {
                return DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Network,
                };
            };
            observation.transition(ResourceState::Running);
            self.resolve_admitted(spec, family, &mut retry_after).await
        };
        let observation = match tokio::time::timeout_at(deadline, work).await {
            Ok(answer) => answer,
            Err(_) => DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout,
            },
        };
        ResolvedFamily {
            observation,
            retry_after,
        }
    }

    async fn resolve_admitted(
        &self,
        spec: &DnsDiscoverySpec,
        family: DnsFamily,
        retry_after: &mut Option<Instant>,
    ) -> DnsObservation {
        self.resolve_address_chain(spec, &spec.name, family, retry_after, None)
            .await
    }

    async fn resolve_address_chain(
        &self,
        spec: &DnsDiscoverySpec,
        target: &str,
        family: DnsFamily,
        retry_after: &mut Option<Instant>,
        round: Option<&SrvRoundBudget>,
    ) -> DnsObservation {
        let Ok(mut name) = canonical_name(target) else {
            return DnsObservation::InvalidAnswer;
        };
        let kind = match family {
            DnsFamily::A => RecordType::A,
            DnsFamily::Aaaa => RecordType::AAAA,
        };
        let mut budget = AnswerBudget::default();
        let mut chain_until = None;
        if let Err(answer) = budget.visit(&name, spec.limits.max_targets as usize) {
            return answer;
        }
        if let Some(round) = round
            && let Err(answer) = round.reserve_name(&name, spec.limits.max_targets as usize)
        {
            return answer;
        }
        loop {
            let mut stream = self.pool.lookup(
                Query::query(name.clone(), kind),
                DnsRequestOptions::default(),
            );
            let response = match stream.next().await {
                Some(Ok(response)) => response,
                Some(Err(error)) => {
                    if let Some(round) = round
                        && let Err(answer) = round.charge_error(&error)
                    {
                        return answer;
                    }
                    *retry_after = negative_error_expiry(&error, Instant::now()).map(|expiry| {
                        chain_until.map_or(expiry, |chain: Instant| chain.min(expiry))
                    });
                    return classify_error(error);
                }
                None => {
                    return DnsObservation::TransientFailure {
                        code: DiscoveryErrorCode::Network,
                    };
                }
            };
            let observed = Instant::now();
            if let Some(round) = round
                && let Err(answer) = round.charge(&response)
            {
                return answer;
            }
            if let Err(answer) = budget.charge(&response) {
                return answer;
            }
            if response.queries.len() != 1
                || response.queries[0].name() != &name
                || response.queries[0].query_type() != kind
                || response.queries[0].query_class() != DNSClass::IN
            {
                return DnsObservation::InvalidAnswer;
            }
            match response.response_code {
                ResponseCode::NXDomain => {
                    *retry_after = negative_response_expiry(&response, &name, observed)
                        .map(|expiry| chain_until.map_or(expiry, |chain| chain.min(expiry)));
                    return DnsObservation::NameNotFound;
                }
                ResponseCode::NoError => {}
                ResponseCode::ServFail => {
                    return DnsObservation::TransientFailure {
                        code: DiscoveryErrorCode::ServerFailure,
                    };
                }
                ResponseCode::Refused => {
                    return DnsObservation::TransientFailure {
                        code: DiscoveryErrorCode::Refused,
                    };
                }
                _ => return DnsObservation::InvalidAnswer,
            }
            let mut followed_in_packet = false;
            loop {
                let mut aliases = BTreeMap::<Name, u32>::new();
                let mut addresses = BTreeMap::<IpAddr, Instant>::new();
                let mut rejected = false;
                for record in response.answers.iter().filter(|record| record.name == name) {
                    if record.dns_class != DNSClass::IN {
                        return DnsObservation::InvalidAnswer;
                    }
                    match &record.data {
                        RData::CNAME(alias) => {
                            let Ok(alias) = canonical_name(&alias.0.to_ascii()) else {
                                return DnsObservation::InvalidAnswer;
                            };
                            aliases
                                .entry(alias)
                                .and_modify(|ttl| *ttl = (*ttl).min(record.ttl))
                                .or_insert(record.ttl);
                        }
                        RData::A(address) if family == DnsFamily::A => {
                            rejected |= !add_address(
                                &mut addresses,
                                IpAddr::V4(address.0),
                                record.ttl,
                                observed,
                                chain_until,
                                &spec.address_policy,
                            );
                        }
                        RData::AAAA(address) if family == DnsFamily::Aaaa => {
                            rejected |= !add_address(
                                &mut addresses,
                                IpAddr::V6(address.0),
                                record.ttl,
                                observed,
                                chain_until,
                                &spec.address_policy,
                            );
                        }
                        _ => {}
                    }
                }
                if aliases.len() > 1 || (!aliases.is_empty() && (!addresses.is_empty() || rejected))
                {
                    return DnsObservation::InvalidAnswer;
                }
                if !addresses.is_empty() {
                    if addresses.len() > spec.limits.max_endpoints as usize {
                        return DnsObservation::LimitExceeded;
                    }
                    return DnsObservation::Positive {
                        addresses: addresses
                            .into_iter()
                            .map(|(address, fresh_until)| DnsAddressRecord {
                                address,
                                fresh_until,
                            })
                            .collect(),
                    };
                }
                if rejected {
                    return DnsObservation::PolicyRejected;
                }
                let Some((alias, ttl)) = aliases.into_iter().next() else {
                    if followed_in_packet {
                        break;
                    }
                    *retry_after = negative_response_expiry(&response, &name, observed)
                        .map(|expiry| chain_until.map_or(expiry, |chain| chain.min(expiry)));
                    return DnsObservation::NoData;
                };
                if let Err(answer) = budget.visit(&alias, spec.limits.max_targets as usize) {
                    return answer;
                }
                if let Some(round) = round
                    && let Err(answer) =
                        round.reserve_name(&alias, spec.limits.max_targets as usize)
                {
                    return answer;
                }
                budget.cname_depth += 1;
                if budget.cname_depth > MAX_DNS_CNAME_DEPTH {
                    return DnsObservation::LimitExceeded;
                }
                let Some(expiry) = observed.checked_add(Duration::from_secs(u64::from(ttl))) else {
                    return DnsObservation::InvalidAnswer;
                };
                chain_until =
                    Some(chain_until.map_or(expiry, |previous: Instant| previous.min(expiry)));
                name = alias;
                followed_in_packet = true;
            }
        }
    }
}

impl DnsResolver {
    fn cached_target_failure(&self, target: &str, family: DnsFamily) -> Option<ResolvedFamily> {
        self.target_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(target.to_owned(), family == DnsFamily::Aaaa))
            .filter(|memo| Instant::now() < memo.not_before)
            .map(|memo| ResolvedFamily {
                observation: memo.observation.clone(),
                retry_after: memo.retry_after,
            })
    }

    fn memo_target_result(
        &self,
        target: &str,
        family: DnsFamily,
        result: &ResolvedFamily,
        spec: &DnsDiscoverySpec,
    ) {
        let key = (target.to_owned(), family == DnsFamily::Aaaa);
        let mut memo = self
            .target_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(result.observation, DnsObservation::Positive { .. }) {
            memo.remove(&key);
            return;
        }
        let now = Instant::now();
        let negative = matches!(
            result.observation,
            DnsObservation::NameNotFound | DnsObservation::NoData
        );
        let failures = if negative {
            0
        } else {
            memo.get(&key)
                .map_or(0, |memo| memo.failures)
                .saturating_add(1)
                .min(16)
        };
        let delay = if negative {
            spec.refresh.min_interval
        } else {
            spec.refresh
                .min_interval
                .saturating_mul(1u32 << (failures - 1))
                .min(spec.refresh.max_interval)
        };
        let not_before = if negative {
            result
                .retry_after
                .filter(|expiry| *expiry > now)
                .unwrap_or(now + delay)
                .min(now + spec.refresh.max_interval)
        } else {
            now + delay
        };
        memo.insert(
            key,
            TargetFailureMemo {
                _lifetime: self
                    .census
                    .token(ResourceKind::DnsFailureMemo, ResourceState::Live),
                observation: result.observation.clone(),
                not_before,
                retry_after: result.retry_after,
                failures,
            },
        );
        debug_assert!(memo.len() <= usize::from(spec.limits.max_targets) * 2);
    }

    /// One deadline spans the service RRset and every target/family lookup.
    /// A successful RRset plus completed target results survives other targets'
    /// deadline expiry; pending target families receive explicit timeout results.
    pub(crate) async fn resolve_srv_with_schedule(&self, spec: &DnsDiscoverySpec) -> ResolvedSrv {
        let Some(deadline) = Instant::now().checked_add(self.query_timeout) else {
            return srv_failure(DnsObservation::InvalidAnswer, None);
        };
        let round = SrvRoundBudget::default();
        let records =
            match tokio::time::timeout_at(deadline, self.resolve_srv_records(spec, &round)).await {
                Ok(Ok(records)) => records,
                Ok(Err(answer)) => {
                    if !matches!(answer.observation, SrvObservation::TransientFailure { .. }) {
                        self.target_failures
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clear();
                    }
                    return answer;
                }
                Err(_) => {
                    return srv_failure(
                        DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::Timeout,
                        },
                        None,
                    );
                }
            };
        let present = records
            .iter()
            .map(|record| record.target.clone())
            .collect::<BTreeSet<_>>();
        self.target_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|(target, _), _| present.contains(target));
        let targets = records
            .iter()
            .filter(|record| record.fresh_until > Instant::now())
            .map(|record| record.target.clone())
            .collect::<BTreeSet<_>>();
        let mut pending = targets
            .iter()
            .flat_map(|target| [(target.clone(), false), (target.clone(), true)])
            .collect::<BTreeSet<_>>();
        // Four family futures imply at most four active target jobs. Unlike a
        // join per target, this releases a fast A result even if its AAAA stalls.
        let mut work = futures_util::stream::iter(pending.iter().cloned().collect::<Vec<_>>())
            .map(|(target, aaaa)| {
                let round = &round;
                async move {
                    let family = if aaaa { DnsFamily::Aaaa } else { DnsFamily::A };
                    if let Some(result) = self.cached_target_failure(&target, family) {
                        return TargetResolution {
                            target,
                            family,
                            result,
                            cached: true,
                        };
                    }
                    let mut retry_after = None;
                    let query = self
                        .census
                        .token(ResourceKind::DnsQuery, ResourceState::Waiting);
                    let observation = match self.admission.acquire().await {
                        Ok(_permit) => {
                            query.transition(ResourceState::Running);
                            self.resolve_address_chain(
                                spec,
                                &target,
                                family,
                                &mut retry_after,
                                Some(round),
                            )
                            .await
                        }
                        Err(_) => DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::Network,
                        },
                    };
                    TargetResolution {
                        target,
                        family,
                        result: ResolvedFamily {
                            observation,
                            retry_after,
                        },
                        cached: false,
                    }
                }
            })
            .buffer_unordered(4);
        let mut addresses = Vec::new();
        let mut revoked = BTreeSet::new();
        loop {
            let completed = tokio::select! {
                biased;
                ()=tokio::time::sleep_until(deadline)=>None,
                answer=work.next()=>answer,
            };
            let Some(answer) = completed else {
                break;
            };
            pending.remove(&(answer.target.clone(), answer.family == DnsFamily::Aaaa));
            if round.exhausted(spec.limits.max_targets as usize)
                || matches!(answer.result.observation, DnsObservation::LimitExceeded)
            {
                return srv_failure(DnsObservation::LimitExceeded, None);
            }
            if revoked.contains(&answer.target) {
                continue;
            }
            if matches!(answer.result.observation, DnsObservation::NameNotFound) {
                revoked.insert(answer.target.clone());
                addresses.retain(|previous: &SrvTargetAddressObservation| {
                    previous.target != answer.target
                });
                for family in [DnsFamily::A, DnsFamily::Aaaa] {
                    pending.remove(&(answer.target.clone(), family == DnsFamily::Aaaa));
                    if !answer.cached {
                        self.memo_target_result(&answer.target, family, &answer.result, spec);
                    }
                    addresses.push(SrvTargetAddressObservation {
                        target: answer.target.clone(),
                        family,
                        observation: DnsObservation::NameNotFound,
                    });
                }
            } else {
                if !answer.cached {
                    self.memo_target_result(&answer.target, answer.family, &answer.result, spec);
                }
                addresses.push(SrvTargetAddressObservation {
                    target: answer.target,
                    family: answer.family,
                    observation: answer.result.observation,
                });
            }
        }
        drop(work);
        for (target, aaaa) in pending {
            let family = if aaaa { DnsFamily::Aaaa } else { DnsFamily::A };
            let result = ResolvedFamily {
                observation: DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout,
                },
                retry_after: None,
            };
            self.memo_target_result(&target, family, &result, spec);
            addresses.push(SrvTargetAddressObservation {
                target,
                family,
                observation: result.observation,
            });
        }
        addresses.sort_by(|left, right| {
            (&left.target, left.family == DnsFamily::Aaaa)
                .cmp(&(&right.target, right.family == DnsFamily::Aaaa))
        });
        let retry_after = self
            .target_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .map(|memo| memo.not_before)
            .min();
        ResolvedSrv {
            observation: SrvObservation::Positive { records, addresses },
            retry_after,
        }
    }

    async fn resolve_srv_records(
        &self,
        spec: &DnsDiscoverySpec,
        round: &SrvRoundBudget,
    ) -> Result<Vec<SrvRecord>, ResolvedSrv> {
        let observation = self
            .census
            .token(ResourceKind::DnsQuery, ResourceState::Waiting);
        let Ok(_permit) = self.admission.acquire().await else {
            return Err(srv_failure(
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Network,
                },
                None,
            ));
        };
        observation.transition(ResourceState::Running);
        let mut name = canonical_service_name(&spec.name)
            .map_err(|_| srv_failure(DnsObservation::InvalidAnswer, None))?;
        let mut local = AnswerBudget::default();
        local
            .visit(&name, spec.limits.max_targets as usize)
            .map_err(|error| srv_failure(error, None))?;
        round
            .reserve_name(&name, spec.limits.max_targets as usize)
            .map_err(|error| srv_failure(error, None))?;
        let mut chain_until = None;
        loop {
            let mut query = self.pool.lookup(
                Query::query(name.clone(), RecordType::SRV),
                DnsRequestOptions::default(),
            );
            let response = match query.next().await {
                Some(Ok(response)) => response,
                Some(Err(error)) => {
                    round
                        .charge_error(&error)
                        .map_err(|error| srv_failure(error, None))?;
                    let retry_after = negative_error_expiry(&error, Instant::now())
                        .map(|until| chain_until.map_or(until, |chain: Instant| chain.min(until)));
                    return Err(srv_failure(classify_error(error), retry_after));
                }
                None => {
                    return Err(srv_failure(
                        DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::Network,
                        },
                        None,
                    ));
                }
            };
            let observed = Instant::now();
            round
                .charge(&response)
                .map_err(|error| srv_failure(error, None))?;
            if response.queries.len() != 1
                || response.queries[0].name() != &name
                || response.queries[0].query_type() != RecordType::SRV
                || response.queries[0].query_class() != DNSClass::IN
            {
                return Err(srv_failure(DnsObservation::InvalidAnswer, None));
            }
            if response.response_code != ResponseCode::NoError {
                let retry_after = negative_response_expiry(&response, &name, observed)
                    .map(|until| chain_until.map_or(until, |chain| chain.min(until)));
                return Err(srv_failure(
                    match response.response_code {
                        ResponseCode::NXDomain => DnsObservation::NameNotFound,
                        ResponseCode::ServFail => DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::ServerFailure,
                        },
                        ResponseCode::Refused => DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::Refused,
                        },
                        _ => DnsObservation::InvalidAnswer,
                    },
                    retry_after,
                ));
            }
            let mut followed = false;
            loop {
                let mut aliases = BTreeMap::<Name, u32>::new();
                let mut records = BTreeMap::<(String, u16, u16), SrvRecord>::new();
                let mut dots = BTreeSet::new();
                for record in response.answers.iter().filter(|record| record.name == name) {
                    if record.dns_class != DNSClass::IN {
                        return Err(srv_failure(DnsObservation::InvalidAnswer, None));
                    }
                    match &record.data {
                        RData::CNAME(alias) => {
                            let alias = canonical_service_name(&alias.0.to_ascii())
                                .map_err(|_| srv_failure(DnsObservation::InvalidAnswer, None))?;
                            aliases
                                .entry(alias)
                                .and_modify(|ttl| *ttl = (*ttl).min(record.ttl))
                                .or_insert(record.ttl);
                        }
                        RData::SRV(srv) => {
                            if srv.target.is_root() {
                                dots.insert((srv.port, srv.priority, srv.weight));
                                continue;
                            }
                            if srv.port == 0 {
                                return Err(srv_failure(DnsObservation::InvalidAnswer, None));
                            }
                            let target = canonical_name(&srv.target.to_ascii())
                                .map_err(|_| srv_failure(DnsObservation::InvalidAnswer, None))?;
                            round
                                .reserve_name(&target, spec.limits.max_targets as usize)
                                .map_err(|error| srv_failure(error, None))?;
                            let fresh = observed
                                .checked_add(Duration::from_secs(u64::from(record.ttl)))
                                .ok_or_else(|| srv_failure(DnsObservation::InvalidAnswer, None))?;
                            let fresh_until = chain_until.map_or(fresh, |chain| chain.min(fresh));
                            let target = target.to_ascii();
                            let key = (target.clone(), srv.port, srv.priority);
                            if let Some(previous) = records.get_mut(&key) {
                                if previous.weight != srv.weight {
                                    return Err(srv_failure(DnsObservation::InvalidAnswer, None));
                                }
                                previous.fresh_until = previous.fresh_until.min(fresh_until);
                            } else {
                                records.insert(
                                    key,
                                    SrvRecord {
                                        target,
                                        port: srv.port,
                                        priority: srv.priority,
                                        weight: srv.weight,
                                        fresh_until,
                                    },
                                );
                            }
                        }
                        _ => {}
                    }
                }
                if aliases.len() > 1
                    || (!aliases.is_empty() && (!records.is_empty() || !dots.is_empty()))
                    || (!dots.is_empty() && !records.is_empty())
                    || dots.len() > 1
                {
                    return Err(srv_failure(DnsObservation::InvalidAnswer, None));
                }
                if !dots.is_empty() {
                    return Err(ResolvedSrv {
                        observation: SrvObservation::ServiceUnavailable,
                        retry_after: None,
                    });
                }
                if !records.is_empty() {
                    return Ok(records.into_values().collect());
                }
                let Some((alias, ttl)) = aliases.into_iter().next() else {
                    if followed {
                        break;
                    }
                    let retry_after = negative_response_expiry(&response, &name, observed)
                        .map(|until| chain_until.map_or(until, |chain| chain.min(until)));
                    return Err(srv_failure(DnsObservation::NoData, retry_after));
                };
                local
                    .visit(&alias, spec.limits.max_targets as usize)
                    .map_err(|error| srv_failure(error, None))?;
                round
                    .reserve_name(&alias, spec.limits.max_targets as usize)
                    .map_err(|error| srv_failure(error, None))?;
                local.cname_depth += 1;
                if local.cname_depth > MAX_DNS_CNAME_DEPTH {
                    return Err(srv_failure(DnsObservation::LimitExceeded, None));
                }
                let fresh = observed
                    .checked_add(Duration::from_secs(u64::from(ttl)))
                    .ok_or_else(|| srv_failure(DnsObservation::InvalidAnswer, None))?;
                chain_until = Some(chain_until.map_or(fresh, |chain| chain.min(fresh)));
                name = alias;
                followed = true;
            }
        }
    }
}

fn srv_failure(observation: DnsObservation, retry_after: Option<Instant>) -> ResolvedSrv {
    let observation = match observation {
        DnsObservation::NameNotFound => SrvObservation::NameNotFound,
        DnsObservation::NoData => SrvObservation::NoData,
        DnsObservation::TransientFailure { code } => SrvObservation::TransientFailure { code },
        DnsObservation::PolicyRejected => SrvObservation::PolicyRejected,
        DnsObservation::InvalidAnswer | DnsObservation::Positive { .. } => {
            SrvObservation::InvalidAnswer
        }
        DnsObservation::LimitExceeded => SrvObservation::LimitExceeded,
    };
    ResolvedSrv {
        observation,
        retry_after,
    }
}

fn canonical_service_name(text: &str) -> Result<Name, ()> {
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty()
        || text.len() > 253
        || !text.is_ascii()
        || text.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
    {
        return Err(());
    }
    Name::from_ascii(format!("{}.", text.to_ascii_lowercase())).map_err(|_| ())
}

fn server(address: SocketAddr) -> Result<NameServerConfig, DnsResolverBootstrapError> {
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address, SocketAddr::V6(address) if address.scope_id()!=0)
    {
        return Err(DnsResolverBootstrapError::NameServerAddress);
    }
    let mut udp = ConnectionConfig::udp();
    udp.port = address.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = address.port();
    Ok(NameServerConfig::new(address.ip(), true, vec![udp, tcp]))
}

fn canonical_name(text: &str) -> Result<Name, ()> {
    let text = text.strip_suffix('.').unwrap_or(text);
    if text.is_empty()
        || text.len() > 253
        || !text.is_ascii()
        || text.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(());
    }
    Name::from_ascii(format!("{}.", text.to_ascii_lowercase())).map_err(|_| ())
}

#[derive(Default)]
struct AnswerBudget {
    names: BTreeSet<Name>,
    cname_depth: usize,
    records: usize,
    bytes: usize,
}

impl AnswerBudget {
    fn visit(&mut self, name: &Name, limit: usize) -> Result<(), DnsObservation> {
        if !self.names.insert(name.clone()) {
            return Err(DnsObservation::InvalidAnswer);
        }
        if self.names.len() > limit {
            return Err(DnsObservation::LimitExceeded);
        }
        Ok(())
    }

    fn charge(&mut self, response: &DnsResponse) -> Result<(), DnsObservation> {
        self.records = self
            .records
            .saturating_add(response.answers.len())
            .saturating_add(response.authorities.len())
            .saturating_add(response.additionals.len());
        self.bytes = self.bytes.saturating_add(response.as_buffer().len());
        if response.truncation
            || self.records > MAX_DNS_RECORDS
            || self.bytes > MAX_DNS_RESPONSE_BYTES
        {
            return Err(DnsObservation::LimitExceeded);
        }
        Ok(())
    }
}

fn add_address(
    addresses: &mut BTreeMap<IpAddr, Instant>,
    address: IpAddr,
    ttl: u32,
    observed: Instant,
    chain_until: Option<Instant>,
    policy: &DnsAddressPolicy,
) -> bool {
    let address = normalize_dns_ip(address);
    if !policy.allows(address) {
        return false;
    }
    let Some(expiry) = observed.checked_add(Duration::from_secs(u64::from(ttl))) else {
        return false;
    };
    let expiry = chain_until.map_or(expiry, |until| until.min(expiry));
    addresses
        .entry(address)
        .and_modify(|previous| *previous = (*previous).min(expiry))
        .or_insert(expiry);
    true
}

fn classify_error(error: NetError) -> DnsObservation {
    match error {
        NetError::Dns(DnsError::NoRecordsFound(records))
            if records
                .authorities
                .as_ref()
                .is_some_and(|records| records.len() > MAX_DNS_RECORDS) =>
        {
            DnsObservation::LimitExceeded
        }
        NetError::Dns(DnsError::NoRecordsFound(records)) => match records.response_code {
            ResponseCode::NXDomain => DnsObservation::NameNotFound,
            ResponseCode::NoError => DnsObservation::NoData,
            ResponseCode::ServFail => DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            },
            ResponseCode::Refused => DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Refused,
            },
            _ => DnsObservation::InvalidAnswer,
        },
        NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)) => {
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            }
        }
        NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)) => {
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Refused,
            }
        }
        NetError::Timeout => DnsObservation::TransientFailure {
            code: DiscoveryErrorCode::Timeout,
        },
        NetError::Io(_) | NetError::NoConnections | NetError::Busy => {
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Network,
            }
        }
        NetError::Truncated => DnsObservation::LimitExceeded,
        _ => DnsObservation::InvalidAnswer,
    }
}

fn negative_response_expiry(
    response: &DnsResponse,
    name: &Name,
    observed: Instant,
) -> Option<Instant> {
    response
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) if record.name.zone_of(name) && record.dns_class == DNSClass::IN => {
                observed.checked_add(Duration::from_secs(u64::from(record.ttl.min(soa.minimum))))
            }
            _ => None,
        })
        .min()
}

fn negative_error_expiry(error: &NetError, observed: Instant) -> Option<Instant> {
    let NetError::Dns(DnsError::NoRecordsFound(records)) = error else {
        return None;
    };
    if !matches!(
        records.response_code,
        ResponseCode::NXDomain | ResponseCode::NoError
    ) || records
        .authorities
        .as_ref()
        .is_some_and(|records| records.len() > MAX_DNS_RECORDS)
    {
        return None;
    }
    let soa = records.soa.as_ref()?;
    if !soa.name.zone_of(records.query.name()) || soa.dns_class != DNSClass::IN {
        return None;
    }
    observed.checked_add(Duration::from_secs(u64::from(
        soa.ttl.min(soa.data.minimum),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_test_fixture::{DnsFixture, FixtureReply};
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, SOA, SRV, TXT};
    use oxidase_config::{DnsDiscoveryLimits, DnsRecordType, DnsRefreshSpec};
    use oxidase_core::SourceSpan;
    use std::sync::atomic::{AtomicU8, Ordering};

    fn spec(address: SocketAddr) -> DnsDiscoverySpec {
        DnsDiscoverySpec {
            name: "fixture.oxidase.invalid.".to_owned(),
            record: DnsRecordType::AAndAaaa,
            port: Some(8443),
            origin: "http://fixture.oxidase.invalid/base"
                .parse()
                .expect("logical origin"),
            resolver: DnsResolverSpec {
                source: DnsResolverSource::NameServers(vec![address]),
                query_timeout: Duration::from_secs(2),
            },
            refresh: DnsRefreshSpec {
                min_interval: Duration::from_secs(1),
                max_interval: Duration::from_secs(60),
                jitter_percent: 0,
                stale_if_error: Duration::from_secs(30),
            },
            limits: DnsDiscoveryLimits {
                max_endpoints: 256,
                max_targets: 32,
            },
            address_policy: DnsAddressPolicy::default(),
            source: SourceSpan::synthetic("discovery.dns"),
            spans: BTreeMap::new(),
        }
    }

    fn resolver(spec: &DnsDiscoverySpec) -> DnsResolver {
        DnsResolver::new(&spec.resolver, Arc::new(Semaphore::new(MAX_DNS_QUERIES)))
            .expect("explicit numeric resolver bootstrap")
    }

    fn address_record(name: &Name, ip: &str, ttl: u32) -> Record {
        let data = match ip.parse().expect("test IP") {
            IpAddr::V4(ip) => RData::A(A(ip)),
            IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
        };
        Record::from_rdata(name.clone(), ttl, data)
    }

    fn positive(observation: DnsObservation) -> Vec<DnsAddressRecord> {
        let DnsObservation::Positive { addresses } = observation else {
            panic!("expected positive: {observation:?}")
        };
        addresses
    }

    #[tokio::test]
    async fn raw_queries_observe_independent_families_deduplicate_and_preserve_zero_ttl() {
        let fixture = DnsFixture::start(|question, _| {
            let ip = if question.query_type() == RecordType::A {
                "192.0.2.1"
            } else {
                "2001:db8::1"
            };
            FixtureReply::answers(vec![
                address_record(question.name(), ip, 0),
                address_record(question.name(), ip, 30),
            ])
        })
        .await;
        let spec = spec(fixture.address);
        let resolver = resolver(&spec);
        for family in [DnsFamily::A, DnsFamily::Aaaa] {
            let before = Instant::now();
            let addresses = positive(resolver.resolve_family(&spec, family).await);
            assert_eq!(addresses.len(), 1);
            assert!(
                addresses[0].fresh_until >= before && addresses[0].fresh_until <= Instant::now(),
                "zero TTL never becomes reusable future freshness"
            );
        }
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 2);
        assert_eq!(fixture.counts.tcp.load(Ordering::Relaxed), 0);
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.counts.responses_for(&spec.name) != 2 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("both fixture replies were actually sent");
        assert_eq!(
            fixture.counts.responses_for_type(&spec.name, RecordType::A),
            1
        );
    }

    #[tokio::test]
    async fn udp_truncation_falls_back_to_same_numeric_nameserver_tcp() {
        let fixture = DnsFixture::start(|question, _| {
            let mut reply =
                FixtureReply::answers(vec![address_record(question.name(), "192.0.2.7", 20)]);
            reply.truncate_udp = true;
            reply
        })
        .await;
        let spec = spec(fixture.address);
        let addresses = positive(resolver(&spec).resolve_family(&spec, DnsFamily::A).await);
        assert_eq!(
            addresses[0].address,
            "192.0.2.7".parse::<IpAddr>().expect("IP")
        );
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 1);
        assert_eq!(fixture.counts.tcp.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cname_hops_keep_original_edge_expiry_and_cannot_reset_at_final_response() {
        let fixture = DnsFixture::start(|question, _| {
            if question.name() == &canonical_name("fixture.oxidase.invalid").expect("name") {
                FixtureReply::answers(vec![Record::from_rdata(
                    question.name().clone(),
                    1,
                    RData::CNAME(CNAME(
                        canonical_name("TARGET.OXIDASE.INVALID.").expect("name"),
                    )),
                )])
            } else {
                let mut reply =
                    FixtureReply::answers(vec![address_record(question.name(), "192.0.2.8", 60)]);
                reply.delay = Duration::from_millis(25);
                reply
            }
        })
        .await;
        let spec = spec(fixture.address);
        let before = Instant::now();
        let addresses = positive(resolver(&spec).resolve_family(&spec, DnsFamily::A).await);
        assert!(addresses[0].fresh_until >= before + Duration::from_secs(1));
        assert!(
            addresses[0].fresh_until < Instant::now() + Duration::from_secs(1),
            "final reply cannot refresh first CNAME TTL"
        );
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn cname_cycles_ambiguous_aliases_and_configured_target_limits_fail_closed() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |question, _| {
            let original = canonical_name("fixture.oxidase.invalid").expect("name");
            let alias = canonical_name("alias.oxidase.invalid").expect("name");
            let mut records = vec![Record::from_rdata(
                original.clone(),
                5,
                RData::CNAME(CNAME(alias.clone())),
            )];
            if handler_mode.load(Ordering::Relaxed) == 0 {
                records.push(Record::from_rdata(alias, 5, RData::CNAME(CNAME(original))));
            } else if handler_mode.load(Ordering::Relaxed) == 1 {
                records.push(Record::from_rdata(
                    question.name().clone(),
                    5,
                    RData::CNAME(CNAME(
                        canonical_name("other.oxidase.invalid").expect("name"),
                    )),
                ));
            }
            FixtureReply::answers(records)
        })
        .await;
        let mut spec = spec(fixture.address);
        let resolver = resolver(&spec);
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::InvalidAnswer
        );
        mode.store(1, Ordering::Relaxed);
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::InvalidAnswer
        );
        mode.store(2, Ordering::Relaxed);
        spec.limits.max_targets = 1;
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::LimitExceeded
        );
    }

    #[tokio::test]
    async fn deletion_transient_and_policy_results_are_not_collapsed_into_empty_addresses() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture =
            DnsFixture::start(
                move |question, _| match handler_mode.load(Ordering::Relaxed) {
                    0 => FixtureReply::code(ResponseCode::NXDomain),
                    1 => FixtureReply::code(ResponseCode::NoError),
                    2 => FixtureReply::code(ResponseCode::ServFail),
                    3 => FixtureReply::code(ResponseCode::Refused),
                    4 => FixtureReply::answers(vec![address_record(
                        question.name(),
                        "127.0.0.1",
                        10,
                    )]),
                    _ => FixtureReply::answers(vec![
                        address_record(question.name(), "127.0.0.1", 10),
                        address_record(question.name(), "192.0.2.9", 10),
                    ]),
                },
            )
            .await;
        let spec = spec(fixture.address);
        let resolver = resolver(&spec);
        let expected = [
            DnsObservation::NameNotFound,
            DnsObservation::NoData,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            },
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Refused,
            },
            DnsObservation::PolicyRejected,
        ];
        for (index, expected) in expected.into_iter().enumerate() {
            mode.store(index as u8, Ordering::Relaxed);
            assert_eq!(resolver.resolve_family(&spec, DnsFamily::A).await, expected);
        }
        mode.store(5, Ordering::Relaxed);
        let addresses = positive(resolver.resolve_family(&spec, DnsFamily::A).await);
        assert_eq!(addresses.len(), 1);
        assert_eq!(
            addresses[0].address,
            "192.0.2.9".parse::<IpAddr>().expect("IP")
        );
    }

    #[tokio::test]
    async fn family_query_deadline_includes_all_cname_work_and_local_admission() {
        let fixture = DnsFixture::start(|question, _| {
            let mut reply =
                if question.name() == &canonical_name("fixture.oxidase.invalid").expect("name") {
                    FixtureReply::answers(vec![Record::from_rdata(
                        question.name().clone(),
                        60,
                        RData::CNAME(CNAME(
                            canonical_name("later.oxidase.invalid").expect("name"),
                        )),
                    )])
                } else {
                    FixtureReply::answers(vec![address_record(question.name(), "192.0.2.10", 60)])
                };
            reply.delay = Duration::from_millis(40);
            reply
        })
        .await;
        let mut spec = spec(fixture.address);
        spec.resolver.query_timeout = Duration::from_millis(65);
        let resolver = resolver(&spec);
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout
            }
        );
        let quota = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&quota)
            .acquire_owned()
            .await
            .expect("held global quota");
        let resolver = DnsResolver::new(&spec.resolver, Arc::clone(&quota)).expect("resolver");
        let previous = fixture.counts.udp.load(Ordering::Relaxed);
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::Timeout
            }
        );
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            previous,
            "admission timeout must not send a DNS packet"
        );
        assert_eq!(quota.available_permits(), 0);
        drop(permit);
        assert_eq!(quota.available_permits(), 1);
    }

    #[tokio::test]
    async fn hickory_inflight_singleflight_does_not_create_a_second_cache_or_ttl() {
        let fixture = DnsFixture::start(|question, _| {
            let mut reply =
                FixtureReply::answers(vec![address_record(question.name(), "192.0.2.11", 3)]);
            reply.delay = Duration::from_millis(30);
            reply
        })
        .await;
        let spec = spec(fixture.address);
        let resolver = resolver(&spec);
        let (first, second) = tokio::join!(
            resolver.resolve_family(&spec, DnsFamily::A),
            resolver.resolve_family(&spec, DnsFamily::A)
        );
        assert_eq!(positive(first)[0].address, positive(second)[0].address);
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            1,
            "only in-flight work coalesces"
        );
        assert!(matches!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::Positive { .. }
        ));
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            2,
            "completed responses are never retained in a second resolver cache"
        );
    }

    #[test]
    fn bounded_answer_counts_encoded_bytes_and_canonical_names_are_checked() {
        assert_eq!(
            canonical_name("MiXeD.Example."),
            canonical_name("mixed.example")
        );
        for invalid in ["", "bad..", "::1", "_srv.example", "*.example", "a..b"] {
            assert!(canonical_name(invalid).is_err());
        }
        let name = canonical_name("fixture.oxidase.invalid").expect("name");
        let mut message = Message::response(1, OpCode::Query);
        message.answers = vec![address_record(&name, "192.0.2.12", 1); MAX_DNS_RECORDS + 1];
        let response = DnsResponse::from_message(message).expect("encoded test response");
        assert_eq!(
            AnswerBudget::default().charge(&response),
            Err(DnsObservation::LimitExceeded)
        );
        let mut message = Message::response(1, OpCode::Query);
        message.answers = (0..150)
            .map(|_| {
                Record::from_rdata(name.clone(), 1, RData::TXT(TXT::new(vec!["x".repeat(240)])))
            })
            .collect();
        let response = DnsResponse::from_message(message).expect("encoded oversized response");
        assert!(response.as_buffer().len() > MAX_DNS_RESPONSE_BYTES / 2);
        assert!(
            !response.truncation,
            "Hickory bounds each individual wire message"
        );
        let mut budget = AnswerBudget::default();
        assert!(budget.charge(&response).is_ok());
        assert_eq!(budget.charge(&response), Err(DnsObservation::LimitExceeded));
    }

    #[test]
    fn address_policy_normalizes_mapped_ipv4_before_filtering_and_deduplication() {
        let mut addresses = BTreeMap::new();
        let mut rejected = false;
        let now = Instant::now();
        let policy = DnsAddressPolicy::default();
        for ip in [
            "::ffff:127.0.0.1",
            "::",
            "ff02::1",
            "255.255.255.255",
            "169.254.1.1",
        ] {
            rejected |= !add_address(
                &mut addresses,
                ip.parse().expect("IP"),
                1,
                now,
                None,
                &policy,
            );
        }
        assert!(rejected && addresses.is_empty());
        for ip in ["192.0.2.13", "::ffff:192.0.2.13"] {
            assert!(add_address(
                &mut addresses,
                ip.parse().expect("IP"),
                2,
                now,
                None,
                &policy,
            ));
        }
        assert_eq!(addresses.len(), 1);
    }

    #[tokio::test]
    async fn cname_depth_eight_is_allowed_but_ninth_edge_is_rejected() {
        let depth = Arc::new(AtomicU8::new(8));
        let handler_depth = Arc::clone(&depth);
        let fixture = DnsFixture::start(move |question, _| {
            let mut owner = question.name().clone();
            let mut records = Vec::new();
            for index in 0..handler_depth.load(Ordering::Relaxed) {
                let target =
                    canonical_name(&format!("hop{index}.oxidase.invalid")).expect("static name");
                records.push(Record::from_rdata(
                    owner,
                    60,
                    RData::CNAME(CNAME(target.clone())),
                ));
                owner = target;
            }
            records.push(address_record(&owner, "192.0.2.14", 60));
            FixtureReply::answers(records)
        })
        .await;
        let spec = spec(fixture.address);
        let resolver = resolver(&spec);
        assert_eq!(
            positive(resolver.resolve_family(&spec, DnsFamily::A).await).len(),
            1
        );
        depth.store(9, Ordering::Relaxed);
        assert_eq!(
            resolver.resolve_family(&spec, DnsFamily::A).await,
            DnsObservation::LimitExceeded
        );
    }

    #[tokio::test]
    async fn real_tcp_answer_record_and_endpoint_limits_are_enforced_after_decode() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |question, _| {
            let count = if handler_mode.load(Ordering::Relaxed) == 0 {
                MAX_DNS_RECORDS
            } else {
                MAX_DNS_RECORDS + 1
            };
            let mut reply =
                FixtureReply::answers(vec![
                    address_record(question.name(), "192.0.2.15", 60);
                    count
                ]);
            reply.truncate_udp = true;
            reply
        })
        .await;
        let policy = spec(fixture.address);
        let client = resolver(&policy);
        assert_eq!(
            positive(client.resolve_family(&policy, DnsFamily::A).await).len(),
            1
        );
        mode.store(1, Ordering::Relaxed);
        assert_eq!(
            client.resolve_family(&policy, DnsFamily::A).await,
            DnsObservation::LimitExceeded
        );
        let fixture = DnsFixture::start(|question, _| {
            FixtureReply::answers(vec![
                address_record(question.name(), "192.0.2.15", 60),
                address_record(question.name(), "192.0.2.16", 60),
            ])
        })
        .await;
        let mut limited = spec(fixture.address);
        limited.limits.max_endpoints = 1;
        assert_eq!(
            resolver(&limited)
                .resolve_family(&limited, DnsFamily::A)
                .await,
            DnsObservation::LimitExceeded
        );
    }

    #[tokio::test]
    async fn local_bootstrap_validation_never_opens_a_dns_socket_or_sends_a_query() {
        let fixture = DnsFixture::start(|_, _| unreachable!("no query is allowed")).await;
        let policy = spec(fixture.address);
        validate_bootstrap(&policy.resolver).expect("only local numeric inputs");
        tokio::task::yield_now().await;
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.counts.tcp.load(Ordering::Relaxed), 0);
    }

    fn soa(owner: &str, ttl: u32, minimum: u32) -> Record {
        Record::from_rdata(
            canonical_name(owner).expect("zone"),
            ttl,
            RData::SOA(SOA::new(
                canonical_name("ns.oxidase.invalid").expect("DNS"),
                canonical_name("hostmaster.oxidase.invalid").expect("DNS"),
                1,
                60,
                60,
                60,
                minimum,
            )),
        )
    }

    #[tokio::test]
    async fn negative_schedule_uses_valid_soa_minimum_and_never_adds_a_second_cache() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |_, _| {
            let mode = handler_mode.load(Ordering::Relaxed);
            let mut reply = FixtureReply::code(if mode == 0 {
                ResponseCode::NXDomain
            } else {
                ResponseCode::NoError
            });
            reply.authorities.push(soa(
                if mode == 2 {
                    "other.invalid"
                } else {
                    "oxidase.invalid"
                },
                10,
                7,
            ));
            reply
        })
        .await;
        let policy = spec(fixture.address);
        let client = resolver(&policy);
        for (mode_value, expected) in [
            (0, DnsObservation::NameNotFound),
            (1, DnsObservation::NoData),
        ] {
            mode.store(mode_value, Ordering::Relaxed);
            let before = Instant::now();
            let resolved = client
                .resolve_family_with_schedule(&policy, DnsFamily::A)
                .await;
            assert_eq!(resolved.observation, expected);
            let expiry = resolved
                .retry_after
                .expect("matching SOA provides negative expiration");
            assert!(
                expiry >= before + Duration::from_secs(7)
                    && expiry <= Instant::now() + Duration::from_secs(7)
            );
        }
        mode.store(2, Ordering::Relaxed);
        let resolved = client
            .resolve_family_with_schedule(&policy, DnsFamily::A)
            .await;
        assert_eq!(resolved.observation, DnsObservation::NoData);
        assert!(
            resolved.retry_after.is_none(),
            "unrelated SOA cannot control negative query scheduling"
        );
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            3,
            "completed negative replies have no hidden library cache"
        );
    }

    #[tokio::test]
    async fn negative_alias_target_schedule_is_bounded_by_original_cname_expiration() {
        let fixture = DnsFixture::start(|question, _| {
            if question.name() == &canonical_name("fixture.oxidase.invalid").expect("name") {
                FixtureReply::answers(vec![Record::from_rdata(
                    question.name().clone(),
                    1,
                    RData::CNAME(CNAME(
                        canonical_name("missing.oxidase.invalid").expect("name"),
                    )),
                )])
            } else {
                let mut reply = FixtureReply::code(ResponseCode::NXDomain);
                reply.authorities.push(soa("oxidase.invalid", 60, 30));
                reply.delay = Duration::from_millis(25);
                reply
            }
        })
        .await;
        let policy = spec(fixture.address);
        let before = Instant::now();
        let resolved = resolver(&policy)
            .resolve_family_with_schedule(&policy, DnsFamily::A)
            .await;
        assert_eq!(resolved.observation, DnsObservation::NameNotFound);
        let expiry = resolved
            .retry_after
            .expect("SOA schedule constrained by alias");
        assert!(expiry >= before + Duration::from_secs(1));
        assert!(expiry < Instant::now() + Duration::from_secs(1));
    }

    fn srv_spec(address: SocketAddr) -> DnsDiscoverySpec {
        let mut spec = spec(address);
        spec.record = DnsRecordType::Srv;
        spec.port = None;
        spec.name = "_http._tcp.fixture.oxidase.invalid.".to_owned();
        spec
    }

    fn srv_record(
        name: &Name,
        target: &str,
        port: u16,
        priority: u16,
        weight: u16,
        ttl: u32,
    ) -> Record {
        let target = if target == "." {
            Name::root()
        } else {
            canonical_name(target).expect("target hostname")
        };
        Record::from_rdata(
            name.clone(),
            ttl,
            RData::SRV(SRV::new(priority, weight, port, target)),
        )
    }

    fn srv_positive(answer: ResolvedSrv) -> (Vec<SrvRecord>, Vec<SrvTargetAddressObservation>) {
        let SrvObservation::Positive { records, addresses } = answer.observation else {
            panic!("expected positive SRV, got {:?}", answer.observation);
        };
        (records, addresses)
    }

    #[tokio::test]
    async fn srv_preserves_zero_max_weights_ports_priorities_and_coalesces_target_families() {
        let fixture = DnsFixture::start(|question, _| {
            if question.query_type() == RecordType::SRV {
                FixtureReply::answers(vec![
                    srv_record(question.name(), "node.oxidase.invalid", 8001, 10, 0, 60),
                    srv_record(question.name(), "NODE.oxidase.invalid.", 8001, 10, 0, 1),
                    srv_record(
                        question.name(),
                        "node.oxidase.invalid",
                        8002,
                        10,
                        u16::MAX,
                        30,
                    ),
                    srv_record(question.name(), "node.oxidase.invalid", 8001, 20, 7, 20),
                ])
            } else {
                FixtureReply::answers(vec![address_record(
                    question.name(),
                    if question.query_type() == RecordType::A {
                        "192.0.2.1"
                    } else {
                        "2001:db8::1"
                    },
                    60,
                )])
            }
        })
        .await;
        let policy = srv_spec(fixture.address);
        let before = Instant::now();
        let (records, addresses) =
            srv_positive(resolver(&policy).resolve_srv_with_schedule(&policy).await);
        assert_eq!(records.len(), 3);
        assert_eq!(
            (records[0].port, records[0].priority, records[0].weight),
            (8001, 10, 0)
        );
        assert!(
            records[0].fresh_until >= before + Duration::from_secs(1)
                && records[0].fresh_until <= Instant::now() + Duration::from_secs(1)
        );
        assert!(records.iter().any(|record| record.weight == u16::MAX));
        assert_eq!(
            addresses.len(),
            2,
            "same target with several ports/priorities is looked up once per family"
        );
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn srv_dot_withdrawal_skips_addresses_and_mixed_dot_or_conflicting_weights_are_invalid() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |question, _| {
            assert_eq!(
                question.query_type(),
                RecordType::SRV,
                "withdrawal must never perform target lookup"
            );
            FixtureReply::answers(match handler_mode.load(Ordering::Relaxed) {
                0 => vec![srv_record(question.name(), ".", 0, 0, 0, 30)],
                1 => vec![
                    srv_record(question.name(), ".", 0, 0, 0, 30),
                    srv_record(question.name(), "node.oxidase.invalid", 8000, 0, 1, 30),
                ],
                2 => vec![
                    srv_record(question.name(), "node.oxidase.invalid", 8000, 0, 1, 30),
                    srv_record(question.name(), "node.oxidase.invalid", 8000, 0, 2, 30),
                ],
                3 => vec![
                    srv_record(question.name(), ".", 0, 0, 0, 30),
                    srv_record(question.name(), ".", 0, 0, 0, 10),
                ],
                _ => vec![
                    srv_record(question.name(), ".", 0, 0, 0, 30),
                    srv_record(question.name(), ".", 0, 1, 0, 30),
                ],
            })
        })
        .await;
        let policy = srv_spec(fixture.address);
        let client = resolver(&policy);
        for (value, expected) in [
            (0, SrvObservation::ServiceUnavailable),
            (1, SrvObservation::InvalidAnswer),
            (2, SrvObservation::InvalidAnswer),
            (3, SrvObservation::ServiceUnavailable),
            (4, SrvObservation::InvalidAnswer),
        ] {
            mode.store(value, Ordering::Relaxed);
            assert_eq!(
                client.resolve_srv_with_schedule(&policy).await.observation,
                expected
            );
        }
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn srv_service_and_target_cname_expirations_are_independent_and_keep_target_identity() {
        let fixture = DnsFixture::start(|question, _| {
            let name = question.name().to_ascii();
            if name == "_http._tcp.fixture.oxidase.invalid." {
                FixtureReply::answers(vec![Record::from_rdata(
                    question.name().clone(),
                    1,
                    RData::CNAME(CNAME(
                        canonical_service_name("_http._tcp.alias.oxidase.invalid")
                            .expect("service alias"),
                    )),
                )])
            } else if question.query_type() == RecordType::SRV {
                FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "original.oxidase.invalid",
                    8443,
                    10,
                    1,
                    60,
                )])
            } else if name == "original.oxidase.invalid." {
                FixtureReply::answers(vec![Record::from_rdata(
                    question.name().clone(),
                    2,
                    RData::CNAME(CNAME(
                        canonical_name("backing.oxidase.invalid").expect("alias"),
                    )),
                )])
            } else {
                FixtureReply::answers(vec![address_record(
                    question.name(),
                    if question.query_type() == RecordType::A {
                        "192.0.2.2"
                    } else {
                        "2001:db8::2"
                    },
                    60,
                )])
            }
        })
        .await;
        let policy = srv_spec(fixture.address);
        let before = Instant::now();
        let (records, addresses) =
            srv_positive(resolver(&policy).resolve_srv_with_schedule(&policy).await);
        assert_eq!(records[0].target, "original.oxidase.invalid.");
        assert!(
            records[0].fresh_until >= before + Duration::from_secs(1)
                && records[0].fresh_until <= Instant::now() + Duration::from_secs(1)
        );
        for address in addresses {
            assert_eq!(address.target, "original.oxidase.invalid.");
            for address in positive(address.observation) {
                assert!(
                    address.fresh_until >= before + Duration::from_secs(2)
                        && address.fresh_until <= Instant::now() + Duration::from_secs(2)
                );
            }
        }
    }

    #[tokio::test]
    async fn srv_whole_round_timeout_preserves_fast_target_and_releases_single_global_slot() {
        let fixture = DnsFixture::start(|question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![
                    srv_record(question.name(), "fast.oxidase.invalid", 8000, 0, 1, 1),
                    srv_record(question.name(), "slow.oxidase.invalid", 8000, 1, 1, 1),
                ]);
            }
            let mut reply = FixtureReply::answers(vec![address_record(
                question.name(),
                if question.query_type() == RecordType::A {
                    "192.0.2.3"
                } else {
                    "2001:db8::3"
                },
                1,
            )]);
            if question.name().to_ascii() == "slow.oxidase.invalid."
                || question.query_type() == RecordType::AAAA
            {
                reply.delay = Duration::from_millis(250);
            }
            reply
        })
        .await;
        let mut policy = srv_spec(fixture.address);
        policy.resolver.query_timeout = Duration::from_millis(100);
        let quota = Arc::new(Semaphore::new(1));
        let client = DnsResolver::new(&policy.resolver, Arc::clone(&quota))
            .expect("one shared actual query slot");
        let started = Instant::now();
        let (_, addresses) = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "targets cannot obtain fresh round deadlines"
        );
        assert_eq!(
            quota.available_permits(),
            1,
            "SRV parent cannot hold query quota while waiting for targets"
        );
        assert!(
            addresses
                .iter()
                .any(|address| address.target == "fast.oxidase.invalid."
                    && address.family == DnsFamily::A
                    && matches!(address.observation, DnsObservation::Positive { .. }))
        );
        assert!(
            addresses.iter().any(|address| {
                address.target == "fast.oxidase.invalid."
                    && address.family == DnsFamily::Aaaa
                    && matches!(
                        address.observation,
                        DnsObservation::TransientFailure {
                            code: DiscoveryErrorCode::Timeout
                        }
                    )
            }),
            "a stalled sibling family cannot erase the completed A observation"
        );
        for address in addresses
            .iter()
            .filter(|address| address.target == "slow.oxidase.invalid.")
        {
            assert!(matches!(
                address.observation,
                DnsObservation::TransientFailure {
                    code: DiscoveryErrorCode::Timeout
                }
            ));
        }
        for address in addresses
            .iter()
            .filter(|address| address.target == "fast.oxidase.invalid.")
        {
            if let DnsObservation::Positive { addresses } = &address.observation {
                assert!(
                    addresses[0].fresh_until < Instant::now() + Duration::from_secs(1),
                    "partial completion retains its original expiry"
                );
            }
        }
    }

    #[tokio::test]
    async fn srv_negative_target_memo_respects_soa_across_short_and_zero_rrset_refreshes() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "missing.oxidase.invalid",
                    8000,
                    0,
                    1,
                    if handler_mode.load(Ordering::Relaxed) == 1 {
                        0
                    } else {
                        1
                    },
                )]);
            }
            let mut reply = FixtureReply::code(ResponseCode::NoError);
            reply.authorities.push(soa("oxidase.invalid", 30, 5));
            reply
        })
        .await;
        let policy = srv_spec(fixture.address);
        let client = resolver(&policy);
        let _ = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        let before = client
            .target_failures
            .lock()
            .expect("memo")
            .iter()
            .map(|(key, value)| (key.clone(), value.not_before))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 3);
        let _ = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            4,
            "only SRV RRset, not either negative family, is queried before SOA expiry"
        );
        mode.store(1, Ordering::Relaxed);
        let _ = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 5);
        mode.store(0, Ordering::Relaxed);
        let _ = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 6);
        let after = client
            .target_failures
            .lock()
            .expect("memo")
            .iter()
            .map(|(key, value)| (key.clone(), value.not_before))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(before, after, "cache hits never restart negative TTL");
        let scheduled = client.resolve_srv_with_schedule(&policy).await;
        assert_eq!(scheduled.retry_after, before.values().copied().min());
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 7);
    }

    #[tokio::test]
    async fn srv_negative_target_refresh_ceiling_recovers_before_long_soa_expiry_without_sliding() {
        let mode = Arc::new(AtomicU8::new(0));
        let handler_mode = Arc::clone(&mode);
        let fixture = DnsFixture::start(move |question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "recovering.oxidase.invalid",
                    8000,
                    0,
                    1,
                    60,
                )]);
            }
            if handler_mode.load(Ordering::Relaxed) == 0 {
                let mut reply = FixtureReply::code(ResponseCode::NoError);
                reply.authorities.push(soa("oxidase.invalid", 60, 60));
                return reply;
            }
            FixtureReply::answers(vec![address_record(
                question.name(),
                if question.query_type() == RecordType::A {
                    "192.0.2.40"
                } else {
                    "2001:db8::40"
                },
                60,
            )])
        })
        .await;
        let mut policy = srv_spec(fixture.address);
        // Test-adjusted monotonic bounds avoid a multi-second sleep; the
        // compiler's production refresh constraints are tested separately.
        policy.refresh.min_interval = Duration::from_millis(5);
        policy.refresh.max_interval = Duration::from_millis(50);
        let client = resolver(&policy);
        let before = Instant::now();
        let initial = client.resolve_srv_with_schedule(&policy).await;
        let first = client
            .target_failures
            .lock()
            .expect("memo")
            .iter()
            .map(|(key, value)| (key.clone(), (value.not_before, value.retry_after)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 3);
        assert_eq!(first.len(), 2);
        for (not_before, received_expiry) in first.values() {
            assert!(*not_before <= Instant::now() + Duration::from_millis(50));
            assert!(
                received_expiry.is_some_and(|expiry| expiry >= before + Duration::from_secs(60)),
                "the raw negative TTL remains distinct from the operational ceiling"
            );
        }
        assert_eq!(
            initial.retry_after,
            first.values().map(|value| value.0).min()
        );
        let cached = client.resolve_srv_with_schedule(&policy).await;
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 4);
        let unchanged = client
            .target_failures
            .lock()
            .expect("memo")
            .iter()
            .map(|(key, value)| (key.clone(), (value.not_before, value.retry_after)))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(first, unchanged, "neither deadline slides on a cache hit");
        assert_eq!(cached.retry_after, initial.retry_after);
        mode.store(1, Ordering::Relaxed);
        let ceiling = first.values().map(|value| value.0).max().expect("ceiling");
        tokio::time::sleep_until(ceiling + Duration::from_millis(5)).await;
        let (_, recovered) = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 7);
        assert_eq!(recovered.len(), 2);
        assert!(
            recovered
                .iter()
                .all(|family| matches!(family.observation, DnsObservation::Positive { .. })),
            "both address families can recover before the original60s SOA expiry"
        );
        assert!(client.target_failures.lock().expect("memo").is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn srv_failure_memo_has_bounded_non_sliding_backoff_and_positive_recovery() {
        let mut policy = srv_spec("127.0.0.1:5300".parse().expect("numeric resolver"));
        policy.refresh.max_interval = Duration::from_secs(4);
        let client = resolver(&policy);
        let target = "failed.oxidase.invalid.";
        let failed = ResolvedFamily {
            observation: DnsObservation::TransientFailure {
                code: DiscoveryErrorCode::ServerFailure,
            },
            retry_after: None,
        };
        for seconds in [1, 2, 4, 4] {
            let before = Instant::now();
            client.memo_target_result(target, DnsFamily::A, &failed, &policy);
            let first = client
                .cached_target_failure(target, DnsFamily::A)
                .expect("memo");
            let suppressed_until = client.target_failures.lock().expect("memo")
                [&(target.to_owned(), false)]
                .not_before;
            assert_eq!(suppressed_until, before + Duration::from_secs(seconds));
            assert!(
                first.retry_after.is_none(),
                "transient errors have no SOA expiry"
            );
            tokio::time::advance(Duration::from_millis(100)).await;
            let repeated = client
                .cached_target_failure(target, DnsFamily::A)
                .expect("memo");
            assert_eq!(first.retry_after, repeated.retry_after);
            assert_eq!(
                client.target_failures.lock().expect("memo")[&(target.to_owned(), false)]
                    .not_before,
                suppressed_until
            );
            tokio::time::advance(Duration::from_secs(seconds)).await;
            assert!(client.cached_target_failure(target, DnsFamily::A).is_none());
        }
        client.memo_target_result(
            target,
            DnsFamily::A,
            &ResolvedFamily {
                observation: DnsObservation::Positive { addresses: vec![] },
                retry_after: None,
            },
            &policy,
        );
        assert!(client.target_failures.lock().expect("memo").is_empty());
    }

    #[tokio::test]
    async fn srv_failure_memo_prunes_removed_targets_instead_of_growing_with_churn() {
        let target = Arc::new(AtomicU8::new(0));
        let handler_target = Arc::clone(&target);
        let fixture = DnsFixture::start(move |question, _| {
            if question.query_type() == RecordType::SRV {
                let target = format!(
                    "node-{}.oxidase.invalid",
                    handler_target.load(Ordering::Relaxed)
                );
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    &target,
                    8000,
                    0,
                    1,
                    60,
                )]);
            }
            let mut reply = FixtureReply::code(ResponseCode::NoError);
            reply.authorities.push(soa("oxidase.invalid", 30, 5));
            reply
        })
        .await;
        let mut policy = srv_spec(fixture.address);
        policy.limits.max_targets = 2;
        let client = resolver(&policy);
        for value in 0..10 {
            target.store(value, Ordering::Relaxed);
            let _ = srv_positive(client.resolve_srv_with_schedule(&policy).await);
            let memo = client.target_failures.lock().expect("memo");
            assert_eq!(memo.len(), 2);
            assert!(
                memo.keys()
                    .all(|(name, _)| { name == &format!("node-{value}.oxidase.invalid.") }),
                "a removed target cannot retain an operational negative/failure entry"
            );
        }
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 30);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_query_census_separates_waiting_admission_from_execution_and_drops_without_scrape()
    {
        use oxidase_runtime::{ResourceCensus, ResourceKind, ResourceState};
        let fixture = DnsFixture::start(|question, _| {
            FixtureReply::answers(vec![address_record(question.name(), "192.0.2.1", 30)])
        })
        .await;
        let policy = spec(fixture.address);
        let census = Arc::new(ResourceCensus::default());
        let admission = Arc::new(Semaphore::new(1));
        let held = admission.acquire().await.expect("held DNS admission");
        let resolver = DnsResolver::with_census(
            &policy.resolver,
            Arc::clone(&admission),
            Arc::clone(&census),
        )
        .expect("local resolver");
        let mut query = Box::pin(resolver.resolve_family_with_schedule(&policy, DnsFamily::A));
        assert!(futures_util::poll!(query.as_mut()).is_pending());
        let waiting = census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == ResourceKind::DnsQuery)
            .expect("query count");
        assert_eq!(
            (waiting.created, waiting.destroyed, waiting.live),
            (1, 0, 1)
        );
        assert_eq!(
            waiting
                .states
                .iter()
                .find(|row| row.state == ResourceState::Waiting)
                .expect("waiting")
                .live,
            1
        );
        assert_eq!(
            waiting
                .states
                .iter()
                .find(|row| row.state == ResourceState::Running)
                .expect("running")
                .live,
            0
        );
        assert_eq!(
            fixture.counts.udp.load(Ordering::Acquire),
            0,
            "no DNS IO before quota"
        );
        drop(query);
        let cancelled = census
            .sample()
            .resources
            .into_iter()
            .find(|row| row.kind == ResourceKind::DnsQuery)
            .expect("query count");
        assert_eq!(
            (cancelled.created, cancelled.destroyed, cancelled.live),
            (1, 1, 0)
        );
        drop(held);
        assert_eq!(admission.available_permits(), 1);
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_failure_memo_census_counts_real_entries_and_owner_drop_not_cached_reads() {
        use oxidase_runtime::{ResourceCensus, ResourceKind};
        let policy = spec("127.0.0.1:59999".parse().expect("local unused resolver"));
        let census = Arc::new(ResourceCensus::default());
        let resolver = DnsResolver::with_census(
            &policy.resolver,
            Arc::new(Semaphore::new(1)),
            Arc::clone(&census),
        )
        .expect("local resolver");
        let failed = ResolvedFamily {
            observation: DnsObservation::NoData,
            retry_after: Some(Instant::now() + Duration::from_secs(30)),
        };
        let memo_count = || {
            census
                .sample()
                .resources
                .into_iter()
                .find(|row| row.kind == ResourceKind::DnsFailureMemo)
                .expect("memo count")
        };
        resolver.memo_target_result("target.example.test.", DnsFamily::A, &failed, &policy);
        for _ in 0..100 {
            assert!(
                resolver
                    .cached_target_failure("target.example.test.", DnsFamily::A)
                    .is_some()
            );
        }
        assert_eq!(
            (
                memo_count().created,
                memo_count().destroyed,
                memo_count().live
            ),
            (1, 0, 1)
        );
        resolver.memo_target_result("target.example.test.", DnsFamily::A, &failed, &policy);
        assert_eq!(
            (
                memo_count().created,
                memo_count().destroyed,
                memo_count().live
            ),
            (2, 1, 1)
        );
        drop(resolver);
        assert_eq!(
            (
                memo_count().created,
                memo_count().destroyed,
                memo_count().live
            ),
            (2, 2, 0)
        );
        assert_eq!(census.sample().invariant_failures, 0);
    }

    #[tokio::test]
    async fn srv_tcp_fallback_and_address_policy_use_the_same_bounded_raw_pool() {
        let fixture = DnsFixture::start(|question, _| {
            let mut reply = match question.query_type() {
                RecordType::SRV => FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "node.oxidase.invalid",
                    65535,
                    0,
                    1,
                    60,
                )]),
                RecordType::A => FixtureReply::answers(vec![
                    address_record(question.name(), "192.0.2.10", 60),
                    address_record(question.name(), "127.0.0.1", 60),
                ]),
                RecordType::AAAA => FixtureReply::answers(vec![
                    address_record(question.name(), "::ffff:192.0.2.10", 60),
                    address_record(question.name(), "::1", 60),
                ]),
                _ => unreachable!("SRV and its address families only"),
            };
            reply.truncate_udp = true;
            reply
        })
        .await;
        let policy = srv_spec(fixture.address);
        let (records, addresses) =
            srv_positive(resolver(&policy).resolve_srv_with_schedule(&policy).await);
        assert_eq!(records[0].port, u16::MAX);
        for family in addresses {
            let normalized = positive(family.observation);
            assert_eq!(normalized.len(), 1);
            assert_eq!(
                normalized[0].address,
                "192.0.2.10".parse::<IpAddr>().expect("documentation IP")
            );
        }
        assert_eq!(fixture.counts.udp.load(Ordering::Relaxed), 3);
        assert_eq!(fixture.counts.tcp.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn srv_target_nxdomain_fences_late_positive_and_negative_memo_is_target_wide() {
        let fixture = DnsFixture::start(|question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "missing.oxidase.invalid",
                    8000,
                    0,
                    1,
                    30,
                )]);
            }
            if question.query_type() == RecordType::A {
                let mut reply = FixtureReply::code(ResponseCode::NXDomain);
                reply.authorities.push(soa("oxidase.invalid", 30, 5));
                reply
            } else {
                let mut reply =
                    FixtureReply::answers(vec![address_record(question.name(), "2001:db8::4", 30)]);
                reply.delay = Duration::from_millis(20);
                reply
            }
        })
        .await;
        let policy = srv_spec(fixture.address);
        let client = resolver(&policy);
        let (_, addresses) = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert_eq!(addresses.len(), 2);
        assert!(
            addresses
                .iter()
                .all(|address| address.observation == DnsObservation::NameNotFound)
        );
        let calls = fixture.counts.udp.load(Ordering::Relaxed);
        let (_, addresses) = srv_positive(client.resolve_srv_with_schedule(&policy).await);
        assert!(
            addresses
                .iter()
                .all(|address| address.observation == DnsObservation::NameNotFound)
        );
        assert_eq!(
            fixture.counts.udp.load(Ordering::Relaxed),
            calls + 1,
            "target NXDOMAIN suppresses both address families"
        );
    }

    #[tokio::test]
    async fn srv_aggregate_limits_include_negative_authorities_and_unique_query_names() {
        let fixture = DnsFixture::start(|question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "negative.oxidase.invalid",
                    8000,
                    0,
                    1,
                    30,
                )]);
            }
            let mut reply = FixtureReply::code(ResponseCode::NoError);
            reply.authorities = vec![soa("oxidase.invalid", 30, 5); MAX_DNS_RECORDS];
            reply.truncate_udp = true;
            reply
        })
        .await;
        let policy = srv_spec(fixture.address);
        assert_eq!(
            resolver(&policy)
                .resolve_srv_with_schedule(&policy)
                .await
                .observation,
            SrvObservation::LimitExceeded,
            "initial SRV RR plus retained negative authority RR must share512 budget"
        );
        let fixture = DnsFixture::start(|question, _| {
            if question.query_type() == RecordType::SRV {
                return FixtureReply::answers(vec![srv_record(
                    question.name(),
                    "node.oxidase.invalid",
                    8000,
                    0,
                    1,
                    30,
                )]);
            }
            FixtureReply::answers(vec![Record::from_rdata(
                question.name().clone(),
                30,
                RData::CNAME(CNAME(
                    canonical_name("alias.oxidase.invalid").expect("alias"),
                )),
            )])
        })
        .await;
        let mut policy = srv_spec(fixture.address);
        policy.limits.max_targets = 2;
        assert_eq!(
            resolver(&policy)
                .resolve_srv_with_schedule(&policy)
                .await
                .observation,
            SrvObservation::LimitExceeded,
            "service + SRV target + CNAME count distinct names across all queries"
        );
    }

    #[test]
    fn srv_observable_byte_budget_exhaustion_is_latched_even_for_retained_error_payload() {
        let name = canonical_name("negative.oxidase.invalid").expect("name");
        let mut message = Message::response(1, OpCode::Query);
        message.answers = (0..150)
            .map(|_| {
                Record::from_rdata(name.clone(), 1, RData::TXT(TXT::new(vec!["x".repeat(240)])))
            })
            .collect();
        let response = DnsResponse::from_message(message).expect("bounded packet");
        let round = SrvRoundBudget::default();
        assert!(round.charge(&response).is_ok());
        assert_eq!(round.charge(&response), Err(DnsObservation::LimitExceeded));
        assert!(round.exhausted(32));
        let exact = SrvRoundBudget::default();
        exact.totals.lock().expect("budget").bytes =
            MAX_DNS_RESPONSE_BYTES - response.as_buffer().len();
        assert!(
            exact.charge(&response).is_ok(),
            "the exact bound is allowed"
        );
        assert!(!exact.exhausted(32));
        let mut negative = hickory_resolver::net::NoRecords::new(
            Query::query(name, RecordType::A),
            ResponseCode::NXDomain,
        );
        negative.authorities = Some(Arc::from(response.answers.clone()));
        let error = NetError::Dns(DnsError::NoRecordsFound(negative));
        let negative_round = SrvRoundBudget::default();
        assert!(negative_round.charge_error(&error).is_ok());
        assert_eq!(
            negative_round.charge_error(&error),
            Err(DnsObservation::LimitExceeded),
            "retained negative authority payload participates in the round budget"
        );
        assert!(negative_round.exhausted(32));
    }
}
