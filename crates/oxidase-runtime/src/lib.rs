//! Transactional Service execution and immutable runtime snapshots.

mod bundle_activation;
mod candidate;
mod cluster;
mod executor;
mod governance;
mod portable;
mod regular_file;
mod secret;
mod snapshot;
mod tls;
mod trust;
mod upstream_tls;

pub use bundle_activation::{
    BundleActivationError, PreparedBundleActivation, bundle_runtime_capabilities,
    prepare_bundle_archive,
};
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
pub use portable::{
    PORTABLE_RUNTIME_PLAN_SCHEMA_V1, PortablePublicCertificateV1, PortablePublicTrustStoreV1,
    PortableRuntimeError, PortableRuntimeExportV1, PortableRuntimePlanV1,
};
pub use secret::{PreparedSecret, SecretBytes, SecretPreparationErrorKind};
pub use snapshot::{
    PreparationError, PreparationErrorKind, ResourceRegistry, ResourceReuse, RuntimeSnapshot,
    SnapshotStore,
};
pub use tls::{
    CertificatePreparationErrorKind, MAX_CERTIFICATE_CHAIN_BYTES, MAX_PRIVATE_KEY_BYTES,
    PreparedCertificate, PreparedCertificateResolver, PreparedListenerPlan, PreparedTlsListener,
    TlsClientMetadataError, TlsListenerPreparationErrorKind, verified_client_metadata,
};
pub use trust::{PreparedTrustStore, TrustStorePreparationErrorKind};
pub use upstream_tls::{PreparedUpstreamTls, UpstreamTlsPreparationErrorKind};

pub const RUNTIME_FORMAT_VERSION: u32 = 1;
pub use candidate::{
    ActivationOutcome, AuditAction, AuditEvent, AuditResult, CandidateOperationContext,
    CandidateRecord, CandidateSignaturePolicy, CandidateStatus, CandidateStore,
    CandidateStoreError, CandidateStoreLimits, CurrentActivation, SnapshotHistoryRecord,
    StageOutcome, ValidationOutcome,
};
pub use cluster::{
    ClusterAdmissionError, ClusterRequestPermit, ClusterRetryPermit, ClusterRuntimeStatus,
    EndpointHealthState, EndpointRuntimeState, EndpointRuntimeStatus, EndpointStatusSnapshot,
    PreparedCluster, PreparedEndpoint,
};
