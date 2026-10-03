//! Compiler-owned DNS discovery policy, without resolver or transport types.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use oxidase_core::SourceSpan;
use url::Url;

pub const DNS_ADDRESS_DISCOVERY_FEATURE: &str = "dns-address-discovery";
pub const DNS_SRV_DISCOVERY_FEATURE: &str = "dns-srv-discovery";
pub const MAX_DNS_DISCOVERY_CLUSTERS: usize = 128;
pub const MAX_DNS_NAMESERVERS: usize = 4;
pub const MAX_DNS_ENDPOINTS: u16 = 256;
pub const MAX_DNS_TARGETS: u16 = 32;
pub const MAX_DNS_RECORDS: usize = 512;
pub const MAX_DNS_CNAME_DEPTH: usize = 8;
pub const MAX_DNS_RESPONSE_BYTES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    AAndAaaa,
    Srv,
}

impl DnsRecordType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AAndAaaa => "a_aaaa",
            Self::Srv => "srv",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResolverSource {
    System,
    NameServers(Vec<SocketAddr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolverSpec {
    pub source: DnsResolverSource,
    pub query_timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRefreshSpec {
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub jitter_percent: u8,
    pub stale_if_error: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDiscoveryLimits {
    pub max_endpoints: u16,
    /// Initial name and distinct CNAME target names, never address count.
    pub max_targets: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsAddressPolicy {
    pub allow_private: bool,
    pub allow_loopback: bool,
    pub allow_link_local: bool,
}

impl Default for DnsAddressPolicy {
    fn default() -> Self {
        Self {
            allow_private: true,
            allow_loopback: false,
            allow_link_local: false,
        }
    }
}

impl DnsAddressPolicy {
    /// Applies policy after mapped-v6 normalization. Unspecified, multicast and
    /// broadcast targets are never valid business endpoints.
    #[must_use]
    pub fn allows(self, address: IpAddr) -> bool {
        let address = normalize_dns_ip(address);
        if address.is_unspecified() || address.is_multicast() {
            return false;
        }
        if address.is_loopback() && !self.allow_loopback {
            return false;
        }
        match address {
            IpAddr::V4(ip) => {
                !ip.is_broadcast()
                    && (self.allow_private || !ip.is_private())
                    && (self.allow_link_local || !ip.is_link_local())
            }
            IpAddr::V6(ip) => {
                (self.allow_private || !ip.is_unique_local())
                    && (self.allow_link_local || !ip.is_unicast_link_local())
            }
        }
    }
}

#[must_use]
pub fn normalize_dns_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(address, IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDiscoverySpec {
    /// Canonical lower-case absolute DNS name, including its final dot.
    pub name: String,
    pub record: DnsRecordType,
    /// A/AAAA physical dial port. SRV uses each target RR port and has no override.
    pub port: Option<u16>,
    pub origin: Url,
    pub resolver: DnsResolverSpec,
    pub refresh: DnsRefreshSpec,
    pub limits: DnsDiscoveryLimits,
    pub address_policy: DnsAddressPolicy,
    pub source: SourceSpan,
    /// Relative policy fields, for example `resolver.query_timeout`.
    pub spans: BTreeMap<String, SourceSpan>,
}

impl DnsDiscoverySpec {
    #[must_use]
    pub fn source_span(&self, field: &str) -> SourceSpan {
        self.spans.get(field).unwrap_or(&self.source).clone()
    }

    pub(crate) fn validate(&self) -> Result<(), DnsPolicyError> {
        let name = match self.record {
            DnsRecordType::AAndAaaa => normalize_dns_name(&self.name)?,
            DnsRecordType::Srv => normalize_srv_name(&self.name)?,
        };
        if name != self.name {
            return Err(policy_error(
                "name",
                "DNS name must be canonical lower-case FQDN",
            ));
        }
        match (self.record, self.port) {
            (DnsRecordType::AAndAaaa, Some(port)) if port != 0 => {}
            (DnsRecordType::Srv, None) => {}
            (DnsRecordType::AAndAaaa, _) => {
                return Err(policy_error(
                    "port",
                    "A/AAAA DNS dial port must be in 1..=65535",
                ));
            }
            (DnsRecordType::Srv, Some(_)) => {
                return Err(policy_error(
                    "port",
                    "SRV dial ports come from the records; no fixed port may be configured",
                ));
            }
        }
        validate_dns_origin(&self.origin)?;
        validate_dns_duration("resolver.query_timeout", self.resolver.query_timeout, false)?;
        if let DnsResolverSource::NameServers(servers) = &self.resolver.source {
            if servers.is_empty() || servers.len() > MAX_DNS_NAMESERVERS {
                return Err(policy_error(
                    "resolver.nameservers",
                    "configure 1 through 4 explicit IP:port nameservers",
                ));
            }
            for (index, address) in servers.iter().enumerate() {
                validate_dns_nameserver(*address).map_err(|mut error| {
                    error.field = format!("resolver.nameservers[{index}]");
                    error
                })?;
            }
            if servers.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(policy_error(
                    "resolver.nameservers",
                    "nameservers must be sorted and unique",
                ));
            }
        }
        validate_dns_duration("refresh.min_interval", self.refresh.min_interval, false)?;
        validate_dns_duration("refresh.max_interval", self.refresh.max_interval, false)?;
        validate_dns_duration("refresh.stale_if_error", self.refresh.stale_if_error, true)?;
        if self.refresh.min_interval > self.refresh.max_interval {
            return Err(policy_error(
                "refresh.max_interval",
                "max_interval must not be less than min_interval",
            ));
        }
        if self.refresh.jitter_percent > 100 {
            return Err(policy_error(
                "refresh.jitter_percent",
                "jitter_percent must be in 0..=100",
            ));
        }
        if !(1..=MAX_DNS_ENDPOINTS).contains(&self.limits.max_endpoints) {
            return Err(policy_error(
                "limits.max_endpoints",
                "max_endpoints must be in 1..=256",
            ));
        }
        if !(1..=MAX_DNS_TARGETS).contains(&self.limits.max_targets) {
            return Err(policy_error(
                "limits.max_targets",
                "max_targets must be in 1..=32",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct DnsPolicyError {
    pub field: String,
    pub message: &'static str,
}

fn policy_error(field: &str, message: &'static str) -> DnsPolicyError {
    DnsPolicyError {
        field: field.to_owned(),
        message,
    }
}

pub(crate) fn normalize_dns_name(source: &str) -> Result<String, DnsPolicyError> {
    let name = source.strip_suffix('.').unwrap_or(source);
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.parse::<IpAddr>().is_ok()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(policy_error(
            "name",
            "use a non-empty ASCII DNS hostname, not an IP, wildcard, underscore, or zone identifier",
        ));
    }
    Ok(format!("{}.", name.to_ascii_lowercase()))
}

/// SRV query grammar is deliberately separate from HTTP/TLS hostname grammar.
pub(crate) fn normalize_srv_name(source: &str) -> Result<String, DnsPolicyError> {
    let name = source.strip_suffix('.').unwrap_or(source);
    let mut parts = name.splitn(3, '.');
    let service = parts.next().unwrap_or_default();
    let transport = parts.next().unwrap_or_default();
    let host = parts.next().unwrap_or_default();
    let label = service.strip_prefix('_').unwrap_or_default();
    if name.len() > 253
        || !name.is_ascii()
        || host.ends_with('.')
        || label.is_empty()
        || service.len() > 63
        || label.starts_with('-')
        || label.ends_with('-')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !transport.eq_ignore_ascii_case("_tcp")
    {
        return Err(policy_error(
            "name",
            "use the ASCII SRV question `_service._tcp.hostname`; UDP, wildcards and empty service labels are unsupported",
        ));
    }
    let host = normalize_dns_name(host).map_err(|_| policy_error("name", "SRV question must end in a plain ASCII DNS hostname, not an IP, service label or zone identifier"))?;
    Ok(format!("{}._tcp.{host}", service.to_ascii_lowercase()))
}

pub(crate) fn validate_dns_origin(origin: &Url) -> Result<(), DnsPolicyError> {
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.port() == Some(0)
    {
        return Err(policy_error(
            "origin",
            "origin must be a fixed http(s) origin/base path without credentials, query, or fragment",
        ));
    }
    Ok(())
}

pub(crate) fn parse_dns_origin(source: &str) -> Result<Url, DnsPolicyError> {
    if source.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(policy_error(
            "origin",
            "origin must not contain control characters",
        ));
    }
    let origin = Url::parse(source).map_err(|_| {
        policy_error(
            "origin",
            "origin must be a valid fixed http(s) origin/base path",
        )
    })?;
    validate_dns_origin(&origin)?;
    Ok(origin)
}

pub(crate) fn validate_dns_nameserver(address: SocketAddr) -> Result<(), DnsPolicyError> {
    let ip = normalize_dns_ip(address.ip());
    if address.port() == 0
        || ip.is_unspecified()
        || ip.is_multicast()
        || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0)
        || matches!(ip, IpAddr::V4(address) if address.is_broadcast())
    {
        return Err(policy_error(
            "resolver.nameservers",
            "nameserver must be a concrete unicast IP:port without a zone identifier",
        ));
    }
    Ok(())
}

fn validate_dns_duration(
    field: &str,
    duration: Duration,
    zero_allowed: bool,
) -> Result<(), DnsPolicyError> {
    if (!zero_allowed && duration.is_zero()) || duration > crate::MAX_UPSTREAM_PHASE_TIMEOUT {
        return Err(policy_error(
            field,
            "DNS durations must be positive and at most 24h; stale_if_error alone may be zero",
        ));
    }
    Ok(())
}
