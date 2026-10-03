//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
pub mod portable;
mod source;

pub use compiler::{
    ActiveHealthSpec, AdminAuditDestination, AdminAuditSpec, AdminAuthMode, AdminAuthSpec,
    AdminBundleTrustSpec, AdminCandidateLimits, AdminHistoryLimits, AdminHttpsListenSpec,
    AdminListenSpec, AdminPermissions, AdminSpec, AdminStorageSpec, AdminUnixListenSpec,
    BundleAssetMode, BundleAssetsSpec, BundleAssetsSummary, BundleSpec, BundleSummary,
    CertificateSpec, ClientAuthMode, ClientAuthSpec, ClusterEndpointSpec, ClusterHealthSpec,
    ClusterLimits, ClusterProtocol, ClusterSpec, ClusterSummary, ClusterTlsSpec,
    ClusterTlsTrustSpec, CompiledGateway, CompiledListener, CompiledResources, Compiler,
    GatewaySummary, Http1Settings, Http2Settings, HttpListenerSpec, HttpVersion, ListenerLimits,
    ListenerProtocol, LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryCause,
    RetryRequestBodySpec, RetrySpec, SecretSpec, SiteSpec, SniCertificateSpec, SniPattern,
    StatusRange, TlsListenerSpec, TrustStoreSpec, UpstreamTimeoutSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use portable::{
    PORTABLE_GATEWAY_CONFIG_SCHEMA_V1, PortableAdminAuditV1, PortableAdminAuthV1,
    PortableAdminBundleTrustV1, PortableAdminCandidateLimitsV1, PortableAdminHistoryLimitsV1,
    PortableAdminListenV1, PortableAdminPermissionsV1, PortableAdminStorageV1, PortableAdminV1,
    PortableConfigError, PortableGatewayConfigV1, PortableGatewayPlanV1,
    portable_source_display_path,
};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
/// Required Bundle capability for the phased upstream deadline contract.
pub const UPSTREAM_DEADLINES_FEATURE: &str = "upstream-deadlines";
/// Fixed, cross-platform ceiling for every new phased timeout. Legacy duration
/// parsing remains unchanged; adapters fail closed if its deadline is impossible.
pub const MAX_UPSTREAM_PHASE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);
