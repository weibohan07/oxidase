//! Hyper-based listener and proxy data plane.

mod admin;
mod admin_audit;
mod body;
mod cluster_health;
mod connection;
mod ingress;
mod leaves;
mod metrics;
mod protocol;
mod proxy_body;
mod response;
mod server;
mod static_targets;
mod upgrade;
mod upstream_pool;
mod upstream_timing;
mod upstream_transport;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

pub use body::{BoxError, GatewayBody, GatewayBodyPlan};
pub use metrics::Metrics;
pub use server::{
    AdminEndpoint, GatewayServer, ReloadError, ReloadHandle, ReloadReport, RunningServer,
    ServerError,
};

pub const DATA_PLANE: &str = "hyper";
