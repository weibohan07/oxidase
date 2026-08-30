//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
mod source;

pub use compiler::{
    ActiveHealthSpec, CertificateSpec, ClusterEndpointSpec, ClusterHealthSpec, ClusterLimits,
    ClusterProtocol, ClusterSpec, ClusterSummary, CompiledGateway, CompiledListener,
    CompiledResources, Compiler, GatewaySummary, Http1Settings, Http2Settings, HttpListenerSpec,
    HttpVersion, ListenerProtocol, LoadBalancePolicy, PassiveHealthSpec, RetryBodyMode, RetryCause,
    RetryRequestBodySpec, RetrySpec, SiteSpec, SniCertificateSpec, SniPattern, StatusRange,
    TlsListenerSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
