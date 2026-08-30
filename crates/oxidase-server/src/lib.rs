//! Hyper-based listener and proxy data plane.

mod body;
mod connection;
mod leaves;
mod metrics;
#[allow(
    dead_code,
    reason = "the protocol bridge consumes this server-local boundary in its integration step"
)]
mod protocol;
mod response;
mod server;

pub use body::{BoxError, GatewayBody, GatewayBodyPlan};
pub use metrics::Metrics;
pub use server::{
    GatewayServer, ReloadError, ReloadHandle, ReloadReport, RunningServer, ServerError,
};

pub const DATA_PLANE: &str = "hyper";
