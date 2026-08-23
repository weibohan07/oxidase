//! Strict source configuration parsing and Service-program compilation.

mod compiler;
mod diagnostic;
mod source;
mod strict_yaml;

pub use compiler::{
    ClusterSpec, CompiledGateway, CompiledListener, CompiledResources, Compiler, GatewaySummary,
    SiteSpec,
};
pub use diagnostic::{CompileError, Diagnostic};
pub use source::{ConfigTestSource, ExplainRequestSource, TestExpectationSource};

pub const API_VERSION: &str = "oxidase.dev/v1alpha1";
