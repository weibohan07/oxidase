//! Transactional Service execution and immutable runtime snapshots.

mod admin_token;
mod bundle_activation;
mod candidate;
mod cluster;
mod discovery;
mod executor;
mod governance;
mod portable;
mod publication;
mod regular_file;
mod secret;
mod snapshot;
mod tls;
mod trust;
mod upstream_tls;

pub use admin_token::{AdminBearerToken, AdminBearerTokenError, MAX_ADMIN_BEARER_TOKEN_BYTES};
pub use bundle_activation::{
    BundleActivationError, PreparedBundleActivation, bundle_runtime_capabilities,
    prepare_bundle_archive, prepare_bundle_archive_controlled,
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
pub use publication::{PublishedRuntime, RuntimeOrigin, ServingState};
pub use regular_file::SensitiveFileIdentity;
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
    AuditAction, AuditEvent, AuditResult, CandidateOperationContext, CandidateRecord,
    CandidateSignaturePolicy, CandidateStatus, CandidateStore, CandidateStoreError,
    CandidateStoreLimits, CandidateWorkControl, OperationBegin, OperationPhase, OperationReceipt,
    SnapshotHistoryRecord, StageOutcome, validate_candidate_journal_bytes,
};
pub use cluster::{
    ClusterAdmissionError, ClusterEndpointReservation, ClusterRequestPermit, ClusterRetryPermit,
    ClusterRuntimeStatus, DiscoveryQueryLease, EndpointHealthState, EndpointRuntimeState,
    EndpointRuntimeStatus, EndpointStatusSnapshot, PreparedCluster, PreparedEndpoint,
};
pub use discovery::{
    DiscoveryAddressError, DiscoveryErrorCode, DiscoveryReconcileOutcome, DiscoveryResolutionState,
    DiscoveryRuntimeStatus, DnsAddressRecord, DnsFamily, DnsObservation,
    normalize_discovery_address, validate_discovery_address,
};
