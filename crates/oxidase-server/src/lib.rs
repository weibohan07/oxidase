//! Hyper-based listener and proxy data plane.

mod body;
mod cluster_health;
mod connection;
mod leaves;
mod metrics;
mod protocol;
mod proxy_body;
mod response;
mod server;
mod upgrade;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;

pub use body::{BoxError, GatewayBody, GatewayBodyPlan};
pub use metrics::Metrics;
pub use server::{
    GatewayServer, ReloadError, ReloadHandle, ReloadReport, RunningServer, ServerError,
};

pub const DATA_PLANE: &str = "hyper";
