//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
mod source;

pub use compiler::{
    CertificateSpec, ClusterProtocol, ClusterSpec, ClusterSummary, CompiledGateway,
    CompiledListener, CompiledResources, Compiler, GatewaySummary, Http1Settings, Http2Settings,
    HttpListenerSpec, HttpVersion, ListenerProtocol, SiteSpec, SniCertificateSpec, SniPattern,
    TlsListenerSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
