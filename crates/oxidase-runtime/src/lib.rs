//! Transactional Service execution and immutable runtime snapshots.

mod cluster;
mod executor;
mod governance;
mod snapshot;
mod tls;

pub use executor::{
    BoxLeafFuture, ExecutionObserver, ExecutionReport, ExecutionTrace, Executor,
    ExplainTraceCollector, LeafExecutor, NoopExecutionObserver, NoopTraceSink,
    ServiceObservationContext, ServiceObservationOutcome, ServiceObservationResult, TraceDetail,
    TraceEvent, TraceSink,
};
pub use governance::{
    ConcurrencyPermit, ConcurrencyRejection, GovernanceRegistry, GovernanceReuse,
    RateLimitDecision, RateLimitRejection,
};
pub use snapshot::{
    PreparationError, PreparationErrorKind, ResourceRegistry, ResourceReuse, RuntimeSnapshot,
    SnapshotStore,
};
pub use tls::{
    CertificatePreparationErrorKind, PreparedCertificate, PreparedCertificateResolver,
    PreparedListenerPlan, PreparedTlsListener, TlsListenerPreparationErrorKind,
};

pub const RUNTIME_FORMAT_VERSION: u32 = 1;
pub use cluster::{
    ClusterAdmissionError, ClusterRequestPermit, ClusterRetryPermit, ClusterRuntimeStatus,
    EndpointHealthState, EndpointRuntimeState, EndpointRuntimeStatus, EndpointStatusSnapshot,
    PreparedCluster, PreparedEndpoint,
};
