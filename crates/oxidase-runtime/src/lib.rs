//! Transactional Service execution and immutable runtime snapshots.

mod executor;
mod snapshot;

pub use executor::{
    BoxLeafFuture, ExecutionObserver, ExecutionReport, ExecutionTrace, Executor,
    ExplainTraceCollector, LeafExecutor, NoopExecutionObserver, NoopTraceSink,
    ServiceObservationContext, ServiceObservationOutcome, ServiceObservationResult, TraceDetail,
    TraceEvent, TraceSink,
};
pub use snapshot::{
    PreparationError, ResourceRegistry, ResourceReuse, RuntimeSnapshot, SnapshotStore,
};

pub const RUNTIME_FORMAT_VERSION: u32 = 1;
