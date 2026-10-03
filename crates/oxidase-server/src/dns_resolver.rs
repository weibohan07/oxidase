//! Bounded raw DNS observation. Membership, freshness/stale policy and refresh
//! scheduling belong to the committed Resource, not this transport boundary.
//! Hickory owns wire parsing, UDP/TCP fallback and query-ID validation.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
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
use oxidase_runtime::{DiscoveryErrorCode, DnsAddressRecord, DnsFamily, DnsObservation};
use tokio::sync::Semaphore;
use tokio::time::Instant;

pub(crate) const MAX_DNS_QUERIES: usize = 64;

pub(crate) struct DnsResolver {
    pool: NameServerPool<TokioRuntimeProvider>,
    query_timeout: Duration,
    admission: Arc<Semaphore>,
}

pub(crate) struct ResolvedFamily {
    pub(crate) observation: DnsObservation,
    /// SOA-derived negative expiry only. The supervisor separately caps its
    /// next query by max_interval and applies a non-busy-loop scheduling floor.
    pub(crate) retry_after: Option<Instant>,
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
        })
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
        let Ok(mut name) = canonical_name(&spec.name) else {
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
        loop {
            let mut stream = self.pool.lookup(
                Query::query(name.clone(), kind),
                DnsRequestOptions::default(),
            );
            let response = match stream.next().await {
                Some(Ok(response)) => response,
                Some(Err(error)) => {
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
#[path = "../tests/support/dns_fixture.rs"]
mod fixture;

#[cfg(test)]
mod tests {
    use super::fixture::{DnsFixture, FixtureReply};
    use super::*;
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{A, AAAA, CNAME, SOA, TXT};
    use oxidase_config::{DnsDiscoveryLimits, DnsRecordType, DnsRefreshSpec};
    use oxidase_core::SourceSpan;
    use std::sync::atomic::{AtomicU8, Ordering};

    fn spec(address: SocketAddr) -> DnsDiscoverySpec {
        DnsDiscoverySpec {
            name: "fixture.oxidase.invalid.".to_owned(),
            record: DnsRecordType::AAndAaaa,
            port: 8443,
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
}
