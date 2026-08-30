//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
mod source;

pub use compiler::{
    ActiveHealthSpec, CertificateSpec, ClientAuthMode, ClientAuthSpec, ClusterEndpointSpec,
    ClusterHealthSpec, ClusterLimits, ClusterProtocol, ClusterSpec, ClusterSummary, ClusterTlsSpec,
    ClusterTlsTrustSpec, CompiledGateway, CompiledListener, CompiledResources, Compiler,
    GatewaySummary, Http1Settings, Http2Settings, HttpListenerSpec, HttpVersion, ListenerLimits,
    ListenerProtocol, LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryCause,
    RetryRequestBodySpec, RetrySpec, SecretSpec, SiteSpec, SniCertificateSpec, SniPattern,
    StatusRange, TlsListenerSpec, TrustStoreSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
