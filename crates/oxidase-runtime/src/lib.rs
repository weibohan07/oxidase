//! Transactional Service execution and immutable runtime snapshots.

mod executor;
mod snapshot;

pub use executor::{
    BoxLeafFuture, ExecutionReport, ExecutionTrace, Executor, LeafExecutor, TraceEvent,
};
pub use snapshot::{
    PreparationError, ResourceRegistry, ResourceReuse, RuntimeSnapshot, SnapshotStore,
};

pub const RUNTIME_FORMAT_VERSION: u32 = 1;
