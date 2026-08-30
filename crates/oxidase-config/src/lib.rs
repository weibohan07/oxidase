//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
pub mod portable;
mod source;

pub use compiler::{
    ActiveHealthSpec, BundleAssetMode, BundleAssetsSpec, BundleAssetsSummary, BundleSpec,
    BundleSummary, CertificateSpec, ClientAuthMode, ClientAuthSpec, ClusterEndpointSpec,
    ClusterHealthSpec, ClusterLimits, ClusterProtocol, ClusterSpec, ClusterSummary, ClusterTlsSpec,
    ClusterTlsTrustSpec, CompiledGateway, CompiledListener, CompiledResources, Compiler,
    GatewaySummary, Http1Settings, Http2Settings, HttpListenerSpec, HttpVersion, ListenerLimits,
    ListenerProtocol, LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryCause,
    RetryRequestBodySpec, RetrySpec, SecretSpec, SiteSpec, SniCertificateSpec, SniPattern,
    StatusRange, TlsListenerSpec, TrustStoreSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use portable::{
    PORTABLE_GATEWAY_CONFIG_SCHEMA_V1, PortableConfigError, PortableGatewayConfigV1,
    PortableGatewayPlanV1, portable_source_display_path,
};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
