//! Operational DNS observations, independent of configuration publication.
//!
//! The resolver supplies already bounded, parsed observations. This module
//! carries no resolver implementation types and never owns a publisher.

use std::net::{IpAddr, SocketAddr};

use oxidase_config::DnsAddressPolicy;
use serde::Serialize;
use tokio::time::Instant;

/// DNS address families are reconciled separately: A NODATA cannot erase AAAA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsFamily {
    A,
    Aaaa,
}

/// One observed address with its original absolute monotonic expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsAddressRecord {
    pub address: IpAddr,
    pub fresh_until: Instant,
}

/// Fixed error codes are safe for aggregate metrics and bounded Admin status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryErrorCode {
    Timeout,
    Network,
    ServerFailure,
    Refused,
    PolicyRejected,
    InvalidAnswer,
    LimitExceeded,
}

impl DiscoveryErrorCode {
    /// Only temporary resolver failures may enable finite stale use.
    #[must_use]
    pub const fn allows_stale(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::Network | Self::ServerFailure | Self::Refused
        )
    }
}

/// Resolver outcomes retain deletion/failure semantics rather than collapsing
/// to an empty address list. Positive expiries include the CNAME chain bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsObservation {
    Positive { addresses: Vec<DnsAddressRecord> },
    NameNotFound,
    NoData,
    TransientFailure { code: DiscoveryErrorCode },
    PolicyRejected,
    InvalidAnswer,
    LimitExceeded,
}

/// Current operational availability; none of these states change readiness,
/// a RuntimeOrigin, ConfigVersion or a PublishedRuntime ETag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryResolutionState {
    Unresolved,
    Fresh,
    Partial,
    Stale,
    Expired,
    NameNotFound,
    NoData,
    TransientFailure,
    PolicyRejected,
    InvalidAnswer,
    LimitExceeded,
    Retired,
}

/// A bounded, authenticated status view. Wall time is observation metadata
/// only; eligibility always checks the monotonic deadlines in the membership.
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryRuntimeStatus {
    pub name: String,
    pub resolution: DiscoveryResolutionState,
    pub generation: u64,
    pub endpoint_count: usize,
    pub eligible_endpoints: usize,
    pub in_flight_query: bool,
    pub last_success_unix_ms: Option<u64>,
    pub next_expiry_ms: Option<u64>,
    pub next_refresh_ms: Option<u64>,
    pub error_code: Option<DiscoveryErrorCode>,
    pub retired_admission_counters: usize,
}

/// Reconciliation receipt, with no authority to publish configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryReconcileOutcome {
    pub applied: bool,
    pub changed: bool,
    pub generation: u64,
    pub endpoint_count: usize,
    pub next_expiry: Option<Instant>,
    pub error_code: Option<DiscoveryErrorCode>,
    /// Received-family validation failure, not an unrelated family's status.
    pub observation_error_code: Option<DiscoveryErrorCode>,
}

/// Why an address cannot become a business DialTarget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryAddressError {
    PortZero,
    Unspecified,
    Multicast,
    Broadcast,
    PrivateDisallowed,
    LoopbackDisallowed,
    LinkLocalDisallowed,
}

/// Canonicalize mapped IPv4 before applying the same IPv4 address policy.
#[must_use]
pub fn normalize_discovery_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

/// Validate once, then connect exactly this SocketAddr. The server's dynamic
/// connector must not hand the configured DNS name to another resolver.
pub fn validate_discovery_address(
    address: IpAddr,
    port: u16,
    policy: &DnsAddressPolicy,
) -> Result<SocketAddr, DiscoveryAddressError> {
    if port == 0 {
        return Err(DiscoveryAddressError::PortZero);
    }
    let address = normalize_discovery_address(address);
    if address.is_unspecified() {
        return Err(DiscoveryAddressError::Unspecified);
    }
    if address.is_multicast() {
        return Err(DiscoveryAddressError::Multicast);
    }
    if matches!(address, IpAddr::V4(address) if address.is_broadcast()) {
        return Err(DiscoveryAddressError::Broadcast);
    }
    if address.is_loopback() && !policy.allow_loopback {
        return Err(DiscoveryAddressError::LoopbackDisallowed);
    }
    let (private, link_local) = match address {
        IpAddr::V4(address) => (address.is_private(), address.is_link_local()),
        IpAddr::V6(address) => (address.is_unique_local(), address.is_unicast_link_local()),
    };
    if link_local && !policy.allow_link_local {
        return Err(DiscoveryAddressError::LinkLocalDisallowed);
    }
    if private && !policy.allow_private {
        return Err(DiscoveryAddressError::PrivateDisallowed);
    }
    Ok(SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ipv4_cannot_bypass_the_ipv4_policy() {
        let policy = DnsAddressPolicy::default();
        for (plain, mapped) in [
            ("127.0.0.1", "::ffff:127.0.0.1"),
            ("169.254.0.1", "::ffff:169.254.0.1"),
            ("0.0.0.0", "::ffff:0.0.0.0"),
            ("224.0.0.1", "::ffff:224.0.0.1"),
            ("255.255.255.255", "::ffff:255.255.255.255"),
        ] {
            assert_eq!(
                validate_discovery_address(plain.parse().expect("IPv4"), 8080, &policy),
                validate_discovery_address(mapped.parse().expect("mapped"), 8080, &policy)
            );
            assert!(!policy.allows(mapped.parse().expect("mapped")));
        }
        assert_eq!(
            validate_discovery_address(
                "::ffff:198.51.100.1".parse().expect("mapped"),
                8080,
                &policy
            ),
            Ok("198.51.100.1:8080".parse().expect("canonical socket"))
        );
    }

    #[test]
    fn address_policy_is_identical_at_compilation_and_lease_validation() {
        let samples = [
            "127.0.0.1",
            "198.51.100.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "::1",
            "ff02::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ];
        for mask in 0..8 {
            let policy = DnsAddressPolicy {
                allow_private: mask & 1 != 0,
                allow_loopback: mask & 2 != 0,
                allow_link_local: mask & 4 != 0,
            };
            for address in samples {
                let address = address.parse().expect("IP");
                assert_eq!(
                    validate_discovery_address(address, 8080, &policy).is_ok(),
                    policy.allows(address)
                );
            }
        }
        assert_eq!(
            validate_discovery_address(
                "198.51.100.1".parse().expect("IP"),
                0,
                &DnsAddressPolicy::default()
            ),
            Err(DiscoveryAddressError::PortZero)
        );
    }
}
