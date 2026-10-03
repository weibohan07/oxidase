//! Durable artifacts and bounded control-plane operation receipts.
//!
//! The server manager is the only publication authority. This store never decides
//! whether an artifact is the running configuration. A durable intent precedes
//! publication; completion follows it even when the HTTP caller has disappeared.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use oxidase_bundle::{
    BundleArchive, BundleCapabilities, BundleDigest, BundleLimits, BundleVerificationKey,
    SignatureRequirement,
};
use oxidase_core::ContentDigestBuilder;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};

const STATE_SCHEMA: &str = "oxidase.candidate-store/v2";
const STATE_FILE: &str = "state.json";
const CANDIDATE_DIRECTORY: &str = "candidates";
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const UPLOAD_PREFIX: &str = ".oxidase-upload-";
const STATE_PREFIX: &str = ".oxidase-state-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateStoreLimits {
    pub max_candidates: usize,
    pub max_total_bytes: u64,
    pub max_candidate_bytes: u64,
    pub max_history_snapshots: usize,
    pub max_history_bytes: u64,
    pub max_idempotency_entries: usize,
    pub max_audit_events: usize,
}

impl Default for CandidateStoreLimits {
    fn default() -> Self {
        Self {
            max_candidates: 16,
            max_total_bytes: 2 * 1024 * 1024 * 1024,
            max_candidate_bytes: 1024 * 1024 * 1024,
            max_history_snapshots: 5,
            max_history_bytes: 1024 * 1024 * 1024,
            max_idempotency_entries: 1024,
            max_audit_events: 4096,
        }
    }
}

#[derive(Clone)]
pub struct CandidateSignaturePolicy {
    trusted_keys: Vec<BundleVerificationKey>,
    allow_unsigned: bool,
}

impl CandidateSignaturePolicy {
    #[must_use]
    pub fn require_trusted(trusted_keys: Vec<BundleVerificationKey>) -> Self {
        Self {
            trusted_keys,
            allow_unsigned: false,
        }
    }

    #[must_use]
    pub fn allow_unsigned_for_development() -> Self {
        Self {
            trusted_keys: Vec::new(),
            allow_unsigned: true,
        }
    }
}

impl std::fmt::Debug for CandidateSignaturePolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateSignaturePolicy")
            .field("trusted_key_count", &self.trusted_keys.len())
            .field("allow_unsigned", &self.allow_unsigned)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    Staged,
    Validated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRecord {
    pub digest: BundleDigest,
    pub file_digest: BundleDigest,
    pub bytes: u64,
    pub status: CandidateStatus,
    pub sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotHistoryRecord {
    pub digest: BundleDigest,
    pub config_version: String,
    pub bytes: u64,
    pub sequence: u64,
    pub committed_revision: u64,
    pub operation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateOperationContext {
    pub request_id: String,
    pub principal: String,
    pub if_match: Option<String>,
    pub idempotency_key: Option<String>,
}

impl CandidateOperationContext {
    #[must_use]
    pub fn internal(request_id: impl Into<String>) -> Self {
        Self {
            request_id: request_id.into(),
            principal: "internal".to_owned(),
            if_match: None,
            idempotency_key: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Stage,
    Validate,
    Activate,
    Rollback,
    ReloadSource,
    Drain,
}

impl AuditAction {
    const fn text(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Validate => "validate",
            Self::Activate => "activate",
            Self::Rollback => "rollback",
            Self::ReloadSource => "reload_source",
            Self::Drain => "drain",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp_unix_millis: u128,
    pub request_id: String,
    pub principal: String,
    pub action: AuditAction,
    pub candidate_digest: Option<BundleDigest>,
    pub previous_version: Option<String>,
    pub new_version: Option<String>,
    pub result: AuditResult,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Accepted,
    Preparing,
    Committed,
    Failed,
    Cancelled,
    RecoveryRequired,
}

impl OperationPhase {
    #[must_use]
    pub const fn is_finished(self) -> bool {
        !matches!(self, Self::Accepted | Self::Preparing)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub operation_id: String,
    pub request_id: String,
    pub principal: String,
    pub action: AuditAction,
    pub target_digest: Option<BundleDigest>,
    pub expected_etag: Option<String>,
    pub phase: OperationPhase,
    pub previous_revision: Option<u64>,
    pub committed_revision: Option<u64>,
    pub config_version: Option<String>,
    pub error_code: Option<String>,
    pub updated_unix_millis: u128,
    // This marker must survive a crash between publication and completion.
    pub commit_intent: bool,
    /// Required completion audit has not yet been acknowledged and persisted.
    #[serde(default)]
    pub audit_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBegin {
    pub receipt: OperationReceipt,
    pub replayed: bool,
}

/// Cooperatively cancels bounded blocking preparation. The blocking worker owns
/// admission until it actually returns; dropping its caller never frees capacity.
#[derive(Debug, Clone, Default)]
pub struct CandidateWorkControl {
    cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
}

impl CandidateWorkControl {
    #[must_use]
    pub fn with_deadline(deadline: Instant) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Some(deadline),
        }
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub fn checkpoint(&self) -> Result<(), CandidateStoreError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(CandidateStoreError::new(
                "candidate.cancelled",
                "candidate operation was cancelled",
            ));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(CandidateStoreError::new(
                "candidate.deadline",
                "candidate operation deadline elapsed",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    pub candidate: CandidateRecord,
    pub already_present: bool,
}

#[derive(Debug)]
pub struct CandidateStore {
    root: PathBuf,
    candidates_directory: PathBuf,
    root_identity: FileIdentity,
    candidates_identity: FileIdentity,
    _process_lock: File,
    limits: CandidateStoreLimits,
    signature_policy: CandidateSignaturePolicy,
    capabilities: BundleCapabilities,
    state: arc_swap::ArcSwap<PersistentState>,
    writer: Mutex<()>,
    operation_gate: Arc<AsyncMutex<()>>,
    preparation_admission: Arc<Semaphore>,
    recovery_required: AtomicBool,
    volatile_receipts: Mutex<BTreeMap<String, OperationReceipt>>,
    audit: Mutex<VecDeque<AuditEvent>>,
    audit_sequence: AtomicU64,
    #[cfg(test)]
    fault: Mutex<Option<FaultPoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentState {
    schema_version: String,
    candidates: BTreeMap<BundleDigest, CandidateRecord>,
    history: VecDeque<SnapshotHistoryRecord>,
    operations: BTreeMap<String, OperationRecord>,
    operation_order: VecDeque<String>,
    tombstones: BTreeSet<BundleDigest>,
    next_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecord {
    receipt: OperationReceipt,
    fingerprint: String,
    idempotency_key: Option<String>,
}

impl Default for PersistentState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA.to_owned(),
            candidates: BTreeMap::new(),
            history: VecDeque::new(),
            operations: BTreeMap::new(),
            operation_order: VecDeque::new(),
            tombstones: BTreeSet::new(),
            next_sequence: 1,
        }
    }
}

impl CandidateStore {
    pub fn open(
        root: impl Into<PathBuf>,
        limits: CandidateStoreLimits,
        signature_policy: CandidateSignaturePolicy,
        capabilities: BundleCapabilities,
    ) -> Result<Arc<Self>, CandidateStoreError> {
        validate_limits(&limits)?;
        let root = root.into();
        ensure_private_directory(&root)?;
        let root_identity = FileIdentity::of(
            &std::fs::symlink_metadata(&root)
                .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?,
        );
        let process_lock = open_regular(&root.join(".oxidase-lock"), true, 4096)?;
        #[cfg(unix)]
        rustix::fs::flock(
            &process_lock,
            rustix::fs::FlockOperation::NonBlockingLockExclusive,
        )
        .map_err(|_| {
            CandidateStoreError::new(
                "candidate.storage_locked",
                "candidate storage is already owned by another process",
            )
        })?;
        #[cfg(not(unix))]
        return Err(CandidateStoreError::new(
            "candidate.storage_platform",
            "durable candidate storage currently requires Unix file locking",
        ));
        let candidates_directory = root.join(CANDIDATE_DIRECTORY);
        ensure_private_directory(&candidates_directory)?;
        let candidates_identity = FileIdentity::of(
            &std::fs::symlink_metadata(&candidates_directory)
                .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?,
        );
        let state = load_state(&root)?;
        validate_persistent_state(&state, &limits)?;
        let store = Arc::new(Self {
            root,
            candidates_directory,
            root_identity,
            candidates_identity,
            _process_lock: process_lock,
            limits,
            signature_policy,
            capabilities,
            state: arc_swap::ArcSwap::from_pointee(state),
            writer: Mutex::new(()),
            operation_gate: Arc::new(AsyncMutex::new(())),
            preparation_admission: Arc::new(Semaphore::new(1)),
            recovery_required: AtomicBool::new(false),
            volatile_receipts: Mutex::new(BTreeMap::new()),
            audit: Mutex::new(VecDeque::new()),
            audit_sequence: AtomicU64::new(1),
            #[cfg(test)]
            fault: Mutex::new(None),
        });
        store.reconcile_files()?;
        store.recover_operations()?;
        Ok(store)
    }

    /// A replay proves principal, key, action, target, precondition, and body
    /// identity. The manager may query it before CAS because it does not create
    /// or publish any state; an unrelated old precondition is still rejected.
    pub fn replay_operation(
        &self,
        context: &CandidateOperationContext,
        action: AuditAction,
        target: Option<BundleDigest>,
        body_digest: Option<BundleDigest>,
    ) -> Result<Option<OperationReceipt>, CandidateStoreError> {
        validate_context(context)?;
        let Some(key) = &context.idempotency_key else {
            return Ok(None);
        };
        let state = self.lock_state();
        let Some(record) = state.operations.values().find(|record| {
            record.receipt.principal == context.principal
                && record.idempotency_key.as_ref() == Some(key)
        }) else {
            return Ok(None);
        };
        if record.fingerprint != operation_fingerprint(context, action, target, body_digest) {
            return Err(CandidateStoreError::new(
                "candidate.idempotency_conflict",
                "idempotency key already identifies a different request",
            ));
        }
        Ok(Some(
            self.volatile_receipts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&record.receipt.operation_id)
                .cloned()
                .unwrap_or_else(|| record.receipt.clone()),
        ))
    }

    /// Storage history is never consulted here as a runtime current value.
    pub fn begin_operation(
        &self,
        context: &CandidateOperationContext,
        action: AuditAction,
        target: Option<BundleDigest>,
        body_digest: Option<BundleDigest>,
    ) -> Result<OperationBegin, CandidateStoreError> {
        self.begin_operation_inner(context, action, target, body_digest, false)
    }

    /// Accepts protected work with durable evidence that completion audit is
    /// still owed. A crash cannot turn an unaudited committed outcome into a
    /// fully completed operation merely because its runtime receipt is durable.
    pub fn begin_operation_audited(
        &self,
        context: &CandidateOperationContext,
        action: AuditAction,
        target: Option<BundleDigest>,
        body_digest: Option<BundleDigest>,
    ) -> Result<OperationBegin, CandidateStoreError> {
        self.begin_operation_inner(context, action, target, body_digest, true)
    }

    fn begin_operation_inner(
        &self,
        context: &CandidateOperationContext,
        action: AuditAction,
        target: Option<BundleDigest>,
        body_digest: Option<BundleDigest>,
        audit_pending: bool,
    ) -> Result<OperationBegin, CandidateStoreError> {
        validate_context(context)?;
        let fingerprint = operation_fingerprint(context, action, target, body_digest);
        let _write = self.lock_writer();
        let state = self.lock_state();
        if let Some(key) = &context.idempotency_key
            && let Some(record) = state.operations.values().find(|record| {
                record.receipt.principal == context.principal
                    && record.idempotency_key.as_ref() == Some(key)
            })
        {
            if record.fingerprint != fingerprint {
                return Err(CandidateStoreError::new(
                    "candidate.idempotency_conflict",
                    "idempotency key already identifies a different request",
                ));
            }
            let receipt = self
                .volatile_receipts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&record.receipt.operation_id)
                .cloned()
                .unwrap_or_else(|| record.receipt.clone());
            return Ok(OperationBegin {
                receipt,
                replayed: true,
            });
        }
        self.ensure_mutations_allowed()?;
        let mut next = (*state).clone();
        evict_operations(&mut next, self.limits.max_idempotency_entries)?;
        let sequence = next_sequence(&mut next)?;
        let operation_id = format!("op-{sequence:016x}");
        let receipt = OperationReceipt {
            operation_id: operation_id.clone(),
            request_id: context.request_id.clone(),
            principal: context.principal.clone(),
            action,
            target_digest: target,
            expected_etag: context.if_match.clone(),
            phase: OperationPhase::Accepted,
            previous_revision: None,
            committed_revision: None,
            config_version: None,
            error_code: None,
            updated_unix_millis: timestamp(),
            commit_intent: false,
            audit_pending,
        };
        next.operations.insert(
            operation_id.clone(),
            OperationRecord {
                receipt: receipt.clone(),
                fingerprint,
                idempotency_key: context.idempotency_key.clone(),
            },
        );
        next.operation_order.push_back(operation_id);
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        Ok(OperationBegin {
            receipt,
            replayed: false,
        })
    }

    pub fn mark_preparing(
        &self,
        operation_id: &str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.update_receipt(operation_id, |receipt| {
            if receipt.phase != OperationPhase::Accepted {
                return Err(invalid_transition());
            }
            receipt.phase = OperationPhase::Preparing;
            Ok(())
        })
    }

    /// Clear the outbox marker only after the required sink acknowledges its
    /// completed outcome. This durable update is also part of commit ownership.
    pub fn complete_audit(
        &self,
        operation_id: &str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.update_receipt(operation_id, |receipt| {
            if !receipt.phase.is_finished() {
                return Err(invalid_transition());
            }
            receipt.audit_pending = false;
            Ok(())
        })
    }

    /// Called only by the publication manager, after final CAS/deadline checking
    /// and listener prebinding, immediately before its non-cancellable commit.
    pub fn begin_intent(
        &self,
        operation_id: &str,
        previous_revision: u64,
        intended_config_version: &str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        validate_bounded_text("config version", intended_config_version)?;
        self.update_receipt(operation_id, |receipt| {
            if !matches!(
                receipt.phase,
                OperationPhase::Accepted | OperationPhase::Preparing
            ) || receipt.commit_intent
            {
                return Err(invalid_transition());
            }
            receipt.phase = OperationPhase::Preparing;
            receipt.previous_revision = Some(previous_revision);
            receipt.config_version = Some(intended_config_version.to_owned());
            receipt.commit_intent = true;
            Ok(())
        })
    }

    /// A post-publication error is a queryable recovery result, never an ordinary
    /// failure that could imply the data plane did not change.
    #[must_use]
    pub fn complete_committed(
        &self,
        operation_id: &str,
        committed_revision: u64,
        config_version: &str,
    ) -> OperationReceipt {
        let result =
            self.complete_committed_inner(operation_id, committed_revision, config_version);
        match result {
            Ok(receipt) => receipt,
            Err(error) => self.force_recovery_receipt(
                operation_id,
                committed_revision,
                config_version,
                error.code(),
            ),
        }
    }

    /// Records a proven no-publication outcome (for example, repeated drain).
    /// Its revision is observational and it never creates Bundle history.
    pub fn complete_unchanged(
        &self,
        operation_id: &str,
        revision: u64,
        config_version: &str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        validate_bounded_text("config version", config_version)?;
        self.update_receipt(operation_id, |receipt| {
            if !matches!(
                receipt.phase,
                OperationPhase::Accepted | OperationPhase::Preparing
            ) {
                return Err(invalid_transition());
            }
            receipt.phase = OperationPhase::Committed;
            receipt.previous_revision = Some(revision);
            receipt.committed_revision = Some(revision);
            receipt.config_version = Some(config_version.to_owned());
            receipt.commit_intent = false;
            Ok(())
        })
    }

    /// The manager calls this when a completion worker or another required
    /// post-commit delivery fails. It preserves the known published revision,
    /// exposes an actionable receipt, and prevents further mutation.
    #[must_use]
    pub fn force_recovery_receipt(
        &self,
        operation_id: &str,
        revision: u64,
        config_version: &str,
        code: &'static str,
    ) -> OperationReceipt {
        self.recovery_required.store(true, Ordering::Release);
        let mut receipt = self
            .operation(operation_id)
            .unwrap_or_else(|| OperationReceipt {
                operation_id: operation_id.to_owned(),
                request_id: "manager".to_owned(),
                principal: "internal".to_owned(),
                action: AuditAction::Activate,
                target_digest: None,
                expected_etag: None,
                phase: OperationPhase::RecoveryRequired,
                previous_revision: None,
                committed_revision: None,
                config_version: None,
                error_code: None,
                updated_unix_millis: timestamp(),
                commit_intent: true,
                audit_pending: true,
            });
        receipt.phase = OperationPhase::RecoveryRequired;
        receipt.committed_revision = Some(revision);
        receipt.config_version = Some(config_version.to_owned());
        receipt.error_code = Some(code.to_owned());
        receipt.updated_unix_millis = timestamp();
        // When storage is still available, persist the recovery marker too. If
        // it is unavailable the existing durable intent remains the recovery
        // evidence and this volatile overlay exposes the known current result.
        {
            let _write = self.lock_writer();
            let state = self.lock_state();
            let mut next = (*state).clone();
            if let Some(record) = next.operations.get_mut(operation_id) {
                record.receipt = receipt.clone();
                if self.persist_locked(&next).is_ok() {
                    self.state.store(Arc::new(next));
                }
            }
        }
        self.volatile_receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(operation_id.to_owned(), receipt.clone());
        receipt
    }

    /// Records a failure while the manager can prove that no runtime publication
    /// happened. Unlike post-commit recovery, it never invents a committed revision.
    #[must_use]
    pub fn force_uncommitted_recovery_receipt(
        &self,
        operation_id: &str,
        code: &'static str,
    ) -> OperationReceipt {
        self.recovery_required.store(true, Ordering::Release);
        let mut receipt = self
            .operation(operation_id)
            .unwrap_or_else(|| OperationReceipt {
                operation_id: operation_id.to_owned(),
                request_id: "manager".to_owned(),
                principal: "internal".to_owned(),
                action: AuditAction::ReloadSource,
                target_digest: None,
                expected_etag: None,
                phase: OperationPhase::RecoveryRequired,
                previous_revision: None,
                committed_revision: None,
                config_version: None,
                error_code: None,
                updated_unix_millis: timestamp(),
                commit_intent: false,
                audit_pending: true,
            });
        // Preserve an already-known publication rather than allowing accidental
        // use of this API to erase it. Normal callers only use uncommitted records.
        if receipt.committed_revision.is_none() {
            receipt.commit_intent = false;
        }
        receipt.phase = OperationPhase::RecoveryRequired;
        receipt.error_code = Some(code.to_owned());
        receipt.updated_unix_millis = timestamp();
        {
            let _write = self.lock_writer();
            let state = self.lock_state();
            let mut next = (*state).clone();
            if let Some(record) = next.operations.get_mut(operation_id) {
                record.receipt = receipt.clone();
                if self.persist_locked(&next).is_ok() {
                    self.state.store(Arc::new(next));
                }
            }
        }
        self.volatile_receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(operation_id.to_owned(), receipt.clone());
        receipt
    }

    fn complete_committed_inner(
        &self,
        operation_id: &str,
        committed_revision: u64,
        config_version: &str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        validate_bounded_text("config version", config_version)?;
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        let record = next
            .operations
            .get_mut(operation_id)
            .ok_or_else(operation_missing)?;
        if !record.receipt.commit_intent
            || record.receipt.phase != OperationPhase::Preparing
            || record.receipt.config_version.as_deref() != Some(config_version)
            || record
                .receipt
                .previous_revision
                .is_none_or(|before| committed_revision <= before)
        {
            return Err(invalid_transition());
        }
        record.receipt.phase = OperationPhase::Committed;
        record.receipt.committed_revision = Some(committed_revision);
        record.receipt.updated_unix_millis = timestamp();
        let receipt = record.receipt.clone();
        if matches!(
            receipt.action,
            AuditAction::Activate | AuditAction::Rollback
        ) {
            let digest = receipt.target_digest.ok_or_else(invalid_transition)?;
            let candidate = next
                .candidates
                .get(&digest)
                .cloned()
                .ok_or_else(candidate_missing)?;
            let sequence = next_sequence(&mut next)?;
            next.history.push_back(SnapshotHistoryRecord {
                digest,
                config_version: config_version.to_owned(),
                bytes: candidate.bytes,
                sequence,
                committed_revision,
                operation_id: operation_id.to_owned(),
            });
            evict_history(&mut next, &self.limits);
        }
        #[cfg(test)]
        self.inject(FaultPoint::Completion)?;
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        Ok(receipt)
    }

    pub fn finish_failed(
        &self,
        operation_id: &str,
        code: &'static str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.finish_noncommitted(operation_id, OperationPhase::Failed, code)
    }
    pub fn finish_cancelled(
        &self,
        operation_id: &str,
        code: &'static str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.finish_noncommitted(operation_id, OperationPhase::Cancelled, code)
    }
    fn finish_noncommitted(
        &self,
        operation_id: &str,
        phase: OperationPhase,
        code: &'static str,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.update_receipt(operation_id, |receipt| {
            if receipt.phase.is_finished() {
                return Err(invalid_transition());
            }
            // A manager can prove an intent was never published after a bind/CAS
            // failure. It must call this before yielding publication ownership.
            receipt.phase = phase;
            receipt.commit_intent = false;
            receipt.error_code = Some(code.to_owned());
            Ok(())
        })
    }

    fn update_receipt(
        &self,
        operation_id: &str,
        update: impl FnOnce(&mut OperationReceipt) -> Result<(), CandidateStoreError>,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        self.ensure_mutations_allowed()?;
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        let record = next
            .operations
            .get_mut(operation_id)
            .ok_or_else(operation_missing)?;
        update(&mut record.receipt)?;
        record.receipt.updated_unix_millis = timestamp();
        let receipt = record.receipt.clone();
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        Ok(receipt)
    }

    #[must_use]
    pub fn operation(&self, operation_id: &str) -> Option<OperationReceipt> {
        if let Some(receipt) = self
            .volatile_receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(operation_id)
            .cloned()
        {
            return Some(receipt);
        }
        self.lock_state()
            .operations
            .get(operation_id)
            .map(|record| record.receipt.clone())
    }
    #[must_use]
    pub fn operations(&self) -> Vec<OperationReceipt> {
        let receipts = self
            .lock_state()
            .operations
            .values()
            .map(|record| record.receipt.clone())
            .collect::<Vec<_>>();
        let volatile = self
            .volatile_receipts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        receipts
            .into_iter()
            .map(|receipt| {
                volatile
                    .get(&receipt.operation_id)
                    .cloned()
                    .unwrap_or(receipt)
            })
            .collect()
    }
    #[must_use]
    pub fn max_recorded_revision(&self) -> u64 {
        let operations = self
            .operations()
            .iter()
            .filter_map(|receipt| receipt.committed_revision.or(receipt.previous_revision))
            .max()
            .unwrap_or(0);
        operations.max(
            self.lock_state()
                .history
                .iter()
                .map(|record| record.committed_revision)
                .max()
                .unwrap_or(0),
        )
    }
    pub fn ensure_mutations_allowed(&self) -> Result<(), CandidateStoreError> {
        if self.recovery_required.load(Ordering::Acquire) {
            return Err(CandidateStoreError::new(
                "candidate.recovery_required",
                "candidate storage requires operator recovery; read-only inspection remains available",
            ));
        }
        self.check_directory_identity()
    }

    pub async fn stage_bytes(
        self: &Arc<Self>,
        bytes: &[u8],
        context: &CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError> {
        if bytes.len() as u64 > self.limits.max_candidate_bytes {
            return Err(candidate_limit());
        }
        self.stage_reader(std::io::Cursor::new(bytes.to_vec()), context.clone())
            .await
    }
    pub async fn stage_reader<R>(
        self: &Arc<Self>,
        reader: R,
        context: CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError>
    where
        R: Read + Send + 'static,
    {
        self.stage_reader_controlled(reader, context, CandidateWorkControl::default())
            .await
    }
    pub async fn stage_reader_controlled<R>(
        self: &Arc<Self>,
        reader: R,
        context: CandidateOperationContext,
        control: CandidateWorkControl,
    ) -> Result<StageOutcome, CandidateStoreError>
    where
        R: Read + Send + 'static,
    {
        self.stage_worker(reader, context, control, None).await
    }

    /// Uses the detached HTTP operation's already-durable receipt. Registration
    /// does not finish that receipt; the owner calls `finish_staged` after checking
    /// cancellation and recording the operation outcome.
    pub async fn stage_reader_for_operation<R>(
        self: &Arc<Self>,
        reader: R,
        context: CandidateOperationContext,
        control: CandidateWorkControl,
        operation_id: String,
    ) -> Result<StageOutcome, CandidateStoreError>
    where
        R: Read + Send + 'static,
    {
        self.stage_worker(reader, context, control, Some(operation_id))
            .await
    }

    #[must_use]
    pub fn upload_directory(&self) -> PathBuf {
        self.candidates_directory.clone()
    }

    pub fn create_upload_spool(&self) -> Result<tempfile::NamedTempFile, CandidateStoreError> {
        self.ensure_mutations_allowed()?;
        tempfile::Builder::new()
            .prefix(UPLOAD_PREFIX)
            .suffix(".tmp")
            .tempfile_in(&self.candidates_directory)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))
    }

    /// Capacity includes the upload and the verified anonymous Bundle copy.
    /// The HTTP upload owner calls this off the async worker before each write.
    pub fn reserve_upload_capacity(&self, incoming_bytes: u64) -> Result<(), CandidateStoreError> {
        self.ensure_mutations_allowed()?;
        if incoming_bytes > self.limits.max_candidate_bytes {
            return Err(candidate_limit());
        }
        self.reserve_workspace_bytes(
            incoming_bytes.checked_mul(2).ok_or_else(candidate_limit)?,
            None,
        )
    }

    /// Adopts the upload spool so stage never makes a second storage copy. Only
    /// spools created in this store's recognized namespace are accepted.
    pub async fn stage_spool_for_operation(
        self: &Arc<Self>,
        spool: tempfile::NamedTempFile,
        context: CandidateOperationContext,
        control: CandidateWorkControl,
        operation_id: String,
        shared_admission: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let permit = Arc::clone(&self.preparation_admission)
            .try_acquire_owned()
            .map_err(|_| {
                CandidateStoreError::new(
                    "candidate.busy",
                    "candidate preparation capacity is occupied",
                )
            })?;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _shared_admission = shared_admission;
            let _permit = permit;
            let _operation = store.operation_gate.blocking_lock();
            store.ensure_mutations_allowed()?;
            validate_context(&context)?;
            let file_metadata = spool
                .as_file()
                .metadata()
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
            let path_metadata = std::fs::symlink_metadata(spool.path())
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
            if spool.path().parent() != Some(store.candidates_directory.as_path())
                || !spool
                    .path()
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(UPLOAD_PREFIX) && name.ends_with(".tmp"))
                || !path_metadata.is_file()
                || path_metadata.file_type().is_symlink()
                || FileIdentity::of(&file_metadata) != FileIdentity::of(&path_metadata)
            {
                return Err(unsafe_store_object());
            }
            let bytes = file_metadata.len();
            store.reserve_upload_capacity(bytes)?;
            control.checkpoint()?;
            spool
                .as_file()
                .sync_all()
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
            store.finalize_upload(spool, bytes, &context, &control, Some(&operation_id))
        })
        .await
        .map_err(|_| {
            CandidateStoreError::new("candidate.stage_io", "candidate staging worker failed")
        })?
    }

    async fn stage_worker<R>(
        self: &Arc<Self>,
        reader: R,
        context: CandidateOperationContext,
        control: CandidateWorkControl,
        operation_id: Option<String>,
    ) -> Result<StageOutcome, CandidateStoreError>
    where
        R: Read + Send + 'static,
    {
        let permit = Arc::clone(&self.preparation_admission)
            .try_acquire_owned()
            .map_err(|_| {
                CandidateStoreError::new(
                    "candidate.busy",
                    "candidate preparation capacity is occupied",
                )
            })?;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _operation = store.operation_gate.blocking_lock();
            validate_context(&context)?;
            store.ensure_mutations_allowed()?;
            let result =
                store.stage_reader_inner(reader, &context, &control, operation_id.as_deref());
            store.record_audit(
                &context,
                AuditAction::Stage,
                result.as_ref().ok().map(|outcome| outcome.candidate.digest),
                None,
                None,
                result
                    .as_ref()
                    .map(|_| ())
                    .map_err(CandidateStoreError::code),
            );
            result
        })
        .await
        .map_err(|_| {
            CandidateStoreError::new("candidate.stage_io", "candidate staging worker failed")
        })?
    }
    pub async fn stage_file(
        self: &Arc<Self>,
        path: impl Into<PathBuf>,
        context: CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let path = path.into();
        let file = open_regular(&path, false, self.limits.max_candidate_bytes)?;
        self.stage_reader(file, context).await
    }

    /// Artifact verification is bounded and runs under owned blocking admission.
    pub async fn verified_archive(
        self: &Arc<Self>,
        digest: BundleDigest,
    ) -> Result<Arc<BundleArchive>, CandidateStoreError> {
        self.verified_archive_controlled(digest, CandidateWorkControl::default())
            .await
    }

    pub async fn verified_archive_controlled(
        self: &Arc<Self>,
        digest: BundleDigest,
        control: CandidateWorkControl,
    ) -> Result<Arc<BundleArchive>, CandidateStoreError> {
        let permit = Arc::clone(&self.preparation_admission)
            .try_acquire_owned()
            .map_err(|_| {
                CandidateStoreError::new(
                    "candidate.busy",
                    "candidate preparation capacity is occupied",
                )
            })?;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _operation = store.operation_gate.blocking_lock();
            store.ensure_mutations_allowed()?;
            let record = store
                .lock_state()
                .candidates
                .get(&digest)
                .cloned()
                .ok_or_else(candidate_missing)?;
            store.reserve_workspace_bytes(record.bytes, Some(digest))?;
            store
                .open_candidate_controlled(digest, &control)
                .map(Arc::new)
        })
        .await
        .map_err(|_| {
            CandidateStoreError::new(
                "candidate.validation_worker",
                "candidate verification worker failed",
            )
        })?
    }

    /// Transfers the shared preparation permit into verification and returns it
    /// alongside the pinned archive for the next blocking preparation stage. On
    /// caller cancellation, the executing worker keeps the permit until it ends.
    pub async fn verified_archive_admitted(
        self: &Arc<Self>,
        digest: BundleDigest,
        control: CandidateWorkControl,
        shared_admission: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(BundleArchive, tokio::sync::OwnedSemaphorePermit), CandidateStoreError> {
        let permit = Arc::clone(&self.preparation_admission)
            .try_acquire_owned()
            .map_err(|_| {
                CandidateStoreError::new(
                    "candidate.busy",
                    "candidate preparation capacity is occupied",
                )
            })?;
        let store = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _operation = store.operation_gate.blocking_lock();
            store.ensure_mutations_allowed()?;
            control.checkpoint()?;
            let record = store
                .lock_state()
                .candidates
                .get(&digest)
                .cloned()
                .ok_or_else(candidate_missing)?;
            store.reserve_workspace_bytes(record.bytes, Some(digest))?;
            let archive = store.open_candidate_controlled(digest, &control)?;
            Ok((archive, shared_admission))
        })
        .await
        .map_err(|_| {
            CandidateStoreError::new(
                "candidate.validation_worker",
                "candidate verification worker failed",
            )
        })?
    }

    pub fn ensure_candidate_activatable(
        &self,
        digest: BundleDigest,
        rollback: bool,
    ) -> Result<(), CandidateStoreError> {
        self.ensure_mutations_allowed()?;
        let state = self.lock_state();
        if state
            .candidates
            .get(&digest)
            .ok_or_else(candidate_missing)?
            .status
            != CandidateStatus::Validated
        {
            return Err(CandidateStoreError::new(
                "candidate.not_validated",
                "candidate must be validated before activation",
            ));
        }
        if rollback && !state.history.iter().any(|record| record.digest == digest) {
            return Err(CandidateStoreError::new(
                "candidate.rollback_missing",
                "rollback target is not retained activation history",
            ));
        }
        Ok(())
    }

    pub fn complete_validation(
        &self,
        operation_id: &str,
        digest: BundleDigest,
    ) -> Result<CandidateRecord, CandidateStoreError> {
        self.ensure_mutations_allowed()?;
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        let sequence = next_sequence(&mut next)?;
        let candidate = next
            .candidates
            .get_mut(&digest)
            .ok_or_else(candidate_missing)?;
        candidate.status = CandidateStatus::Validated;
        candidate.sequence = sequence;
        let candidate = candidate.clone();
        let record = next
            .operations
            .get_mut(operation_id)
            .ok_or_else(operation_missing)?;
        if record.receipt.action != AuditAction::Validate
            || record.receipt.target_digest != Some(digest)
            || record.receipt.phase != OperationPhase::Preparing
            || record.receipt.commit_intent
        {
            return Err(invalid_transition());
        }
        record.receipt.phase = OperationPhase::Committed;
        record.receipt.updated_unix_millis = timestamp();
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        Ok(candidate)
    }

    pub fn finish_staged(
        &self,
        operation_id: &str,
        digest: BundleDigest,
    ) -> Result<OperationReceipt, CandidateStoreError> {
        if !self.lock_state().candidates.contains_key(&digest) {
            return Err(candidate_missing());
        }
        self.update_receipt(operation_id, |receipt| {
            if receipt.action != AuditAction::Stage
                || !matches!(
                    receipt.phase,
                    OperationPhase::Accepted | OperationPhase::Preparing
                )
                || receipt.commit_intent
                || receipt.target_digest.is_some_and(|target| target != digest)
            {
                return Err(invalid_transition());
            }
            receipt.target_digest = Some(digest);
            receipt.phase = OperationPhase::Committed;
            Ok(())
        })
    }

    #[must_use]
    pub fn candidates(&self) -> Vec<CandidateRecord> {
        self.lock_state().candidates.values().cloned().collect()
    }
    #[must_use]
    pub fn history(&self) -> Vec<SnapshotHistoryRecord> {
        self.lock_state().history.iter().cloned().collect()
    }
    #[must_use]
    pub fn candidate_path(&self, digest: BundleDigest) -> PathBuf {
        self.candidates_directory.join(format!("{digest}.oxb"))
    }
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEvent> {
        self.audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    fn stage_reader_inner(
        &self,
        mut reader: impl Read,
        context: &CandidateOperationContext,
        control: &CandidateWorkControl,
        external_operation_id: Option<&str>,
    ) -> Result<StageOutcome, CandidateStoreError> {
        self.check_signature_policy()?;
        let mut temporary = self.create_upload_spool()?;
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            control.checkpoint()?;
            let read = reader
                .read(&mut buffer)
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
            if read == 0 {
                break;
            }
            bytes = bytes.checked_add(read as u64).ok_or_else(candidate_limit)?;
            if bytes > self.limits.max_candidate_bytes {
                return Err(candidate_limit());
            }
            self.reserve_upload_capacity(bytes)?;
            temporary
                .write_all(&buffer[..read])
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        }
        control.checkpoint()?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        #[cfg(test)]
        self.inject(FaultPoint::UploadComplete)?;
        self.finalize_upload(temporary, bytes, context, control, external_operation_id)
    }

    fn finalize_upload(
        &self,
        temporary: tempfile::NamedTempFile,
        bytes: u64,
        context: &CandidateOperationContext,
        control: &CandidateWorkControl,
        external_operation_id: Option<&str>,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let archive = self.read_verified_archive_controlled(temporary.path(), control)?;
        control.checkpoint()?;
        let digest = archive.content_digest();
        let file_digest = archive.file_digest();
        let begin = if let Some(operation_id) = external_operation_id {
            let receipt = self.operation(operation_id).ok_or_else(operation_missing)?;
            if receipt.action != AuditAction::Stage
                || receipt.principal != context.principal
                || receipt.phase.is_finished()
                || receipt.target_digest.is_some_and(|target| target != digest)
            {
                return Err(invalid_transition());
            }
            OperationBegin {
                receipt,
                replayed: false,
            }
        } else {
            self.begin_operation(context, AuditAction::Stage, Some(digest), Some(file_digest))?
        };
        if begin.replayed {
            if begin.receipt.phase != OperationPhase::Committed {
                return Err(operation_in_progress());
            }
            let candidate = self
                .lock_state()
                .candidates
                .get(&digest)
                .cloned()
                .ok_or_else(candidate_missing)?;
            return Ok(StageOutcome {
                candidate,
                already_present: true,
            });
        }
        let operation_id = begin.receipt.operation_id;
        self.reserve_candidate_slot(digest)?;
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        if let Some(existing) = next.candidates.get(&digest).cloned() {
            if external_operation_id.is_none() {
                let receipt = &mut next
                    .operations
                    .get_mut(&operation_id)
                    .ok_or_else(operation_missing)?
                    .receipt;
                receipt.phase = OperationPhase::Committed;
            }
            self.persist_locked(&next)?;
            self.state.store(Arc::new(next));
            return Ok(StageOutcome {
                candidate: existing,
                already_present: true,
            });
        }
        if next.candidates.len() >= self.limits.max_candidates {
            return Err(candidate_capacity());
        }
        let destination = self.candidate_path(digest);
        temporary
            .as_file()
            .set_permissions(readonly_permissions(temporary.as_file())?)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        self.check_directory_identity()?;
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error.error))?;
        let registration = (|| {
            #[cfg(test)]
            self.inject(FaultPoint::ArtifactDirectoryFsync)?;
            sync_directory(&self.candidates_directory)?;
            #[cfg(test)]
            self.inject(FaultPoint::ArtifactRenamed)?;
            let candidate = CandidateRecord {
                digest,
                file_digest,
                bytes,
                status: CandidateStatus::Staged,
                sequence: next_sequence(&mut next)?,
            };
            next.candidates.insert(digest, candidate.clone());
            if external_operation_id.is_none() {
                next.operations
                    .get_mut(&operation_id)
                    .ok_or_else(operation_missing)?
                    .receipt
                    .phase = OperationPhase::Committed;
            }
            self.persist_locked(&next)?;
            self.state.store(Arc::new(next));
            Ok(StageOutcome {
                candidate,
                already_present: false,
            })
        })();
        if registration.is_err() {
            // The renamed artifact can be absent from the durable/read index.
            // Stop admission before its unaccounted bytes or slot can be reused;
            // restart verifies and imports this single reserved orphan.
            self.recovery_required.store(true, Ordering::Release);
        }
        registration
    }

    fn reserve_candidate_slot(
        &self,
        incoming_digest: BundleDigest,
    ) -> Result<(), CandidateStoreError> {
        let _write = self.lock_writer();
        let state = self.lock_state();
        if state.candidates.contains_key(&incoming_digest)
            || state.candidates.len() < self.limits.max_candidates
        {
            return Ok(());
        }
        let mut next = (*state).clone();
        let protected = next
            .history
            .iter()
            .map(|record| record.digest)
            .chain(
                next.operations
                    .values()
                    .filter(|record| {
                        !record.receipt.phase.is_finished() || record.receipt.audit_pending
                    })
                    .filter_map(|record| record.receipt.target_digest),
            )
            .collect::<BTreeSet<_>>();
        let digest = next
            .candidates
            .values()
            .filter(|candidate| !protected.contains(&candidate.digest))
            .min_by_key(|candidate| candidate.sequence)
            .map(|candidate| candidate.digest)
            .ok_or_else(candidate_capacity)?;
        next.candidates.remove(&digest);
        next.tombstones.insert(digest);
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        #[cfg(test)]
        self.inject(FaultPoint::GcIndexed)?;
        drop(state);
        drop(_write);
        self.collect_tombstones()
    }

    fn reserve_workspace_bytes(
        &self,
        incoming: u64,
        protected_digest: Option<BundleDigest>,
    ) -> Result<(), CandidateStoreError> {
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        loop {
            let total = checked_total(next.candidates.values().map(|record| record.bytes))?;
            if total
                .checked_add(incoming)
                .is_some_and(|total| total <= self.limits.max_total_bytes)
            {
                break;
            }
            let protected = next
                .history
                .iter()
                .map(|record| record.digest)
                .chain(
                    next.operations
                        .values()
                        .filter(|record| {
                            !record.receipt.phase.is_finished() || record.receipt.audit_pending
                        })
                        .filter_map(|record| record.receipt.target_digest),
                )
                .chain(protected_digest)
                .collect::<BTreeSet<_>>();
            let digest = next
                .candidates
                .values()
                .filter(|candidate| !protected.contains(&candidate.digest))
                .min_by_key(|candidate| candidate.sequence)
                .map(|candidate| candidate.digest)
                .ok_or_else(candidate_capacity)?;
            next.candidates.remove(&digest);
            next.tombstones.insert(digest);
        }
        if !next.tombstones.is_empty() {
            self.persist_locked(&next)?;
            self.state.store(Arc::new(next));
            #[cfg(test)]
            self.inject(FaultPoint::GcIndexed)?;
            drop(state);
            drop(_write);
            self.collect_tombstones()?;
        }
        Ok(())
    }

    fn collect_tombstones(&self) -> Result<(), CandidateStoreError> {
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        for digest in &next.tombstones {
            self.check_directory_identity()?;
            let path = self.candidate_path(*digest);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    std::fs::remove_file(path)
                        .map_err(|error| CandidateStoreError::io("candidate.evict", error))?;
                }
                Ok(_) => {
                    return Err(CandidateStoreError::new(
                        "candidate.evict",
                        "unsafe candidate eviction object",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(CandidateStoreError::io("candidate.evict", error)),
            }
        }
        sync_directory(&self.candidates_directory)?;
        next.tombstones.clear();
        self.persist_locked(&next)?;
        self.state.store(Arc::new(next));
        Ok(())
    }

    fn open_candidate(&self, digest: BundleDigest) -> Result<BundleArchive, CandidateStoreError> {
        self.open_candidate_controlled(digest, &CandidateWorkControl::default())
    }

    fn open_candidate_controlled(
        &self,
        digest: BundleDigest,
        control: &CandidateWorkControl,
    ) -> Result<BundleArchive, CandidateStoreError> {
        self.check_directory_identity()?;
        let record = self
            .lock_state()
            .candidates
            .get(&digest)
            .cloned()
            .ok_or_else(candidate_missing)?;
        let archive =
            self.read_verified_archive_controlled(&self.candidate_path(digest), control)?;
        if archive.content_digest() != digest
            || archive.file_digest() != record.file_digest
            || archive.encoded_size() != record.bytes
        {
            return Err(CandidateStoreError::new(
                "candidate.corrupt",
                "stored candidate differs from its durable record",
            ));
        }
        Ok(archive)
    }
    fn check_signature_policy(&self) -> Result<(), CandidateStoreError> {
        if !self.signature_policy.allow_unsigned && self.signature_policy.trusted_keys.is_empty() {
            return Err(CandidateStoreError::new(
                "candidate.signature_policy",
                "candidate operations require trusted verification keys",
            ));
        }
        Ok(())
    }
    fn read_verified_archive(&self, path: &Path) -> Result<BundleArchive, CandidateStoreError> {
        self.read_verified_archive_controlled(path, &CandidateWorkControl::default())
    }

    fn read_verified_archive_controlled(
        &self,
        path: &Path,
        control: &CandidateWorkControl,
    ) -> Result<BundleArchive, CandidateStoreError> {
        self.check_signature_policy()?;
        let file = open_regular(path, false, self.limits.max_candidate_bytes)?;
        let result = BundleArchive::read_file_with_checkpoint(
            file,
            &BundleLimits {
                max_bundle_bytes: self.limits.max_candidate_bytes,
                ..BundleLimits::default()
            },
            || {
                control.checkpoint().map_err(|_| {
                    oxidase_bundle::BundleError::new(
                        oxidase_bundle::BundleErrorKind::Io,
                        "candidate operation interrupted",
                    )
                })
            },
        );
        control.checkpoint()?;
        let archive = result.map_err(CandidateStoreError::bundle)?;
        archive.verify().map_err(CandidateStoreError::bundle)?;
        archive
            .verify_capabilities(&self.capabilities)
            .map_err(CandidateStoreError::bundle)?;
        archive
            .verify_ed25519(
                &self.signature_policy.trusted_keys,
                if self.signature_policy.allow_unsigned {
                    SignatureRequirement::AllowUnsigned
                } else {
                    SignatureRequirement::RequireAnyTrusted
                },
            )
            .map_err(CandidateStoreError::bundle)?;
        Ok(archive)
    }

    fn reconcile_files(&self) -> Result<(), CandidateStoreError> {
        self.collect_tombstones()?;
        let records = self.candidates();
        for record in &records {
            self.open_candidate(record.digest)?;
        }
        let expected = records
            .iter()
            .map(|record| record.digest)
            .collect::<BTreeSet<_>>();
        let mut orphan_records = Vec::new();
        for entry in std::fs::read_dir(&self.candidates_directory)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?
        {
            let entry = entry.map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(unsafe_store_object)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(unsafe_store_object());
            }
            if name.starts_with(UPLOAD_PREFIX) && name.ends_with(".tmp") {
                std::fs::remove_file(entry.path())
                    .map_err(|error| CandidateStoreError::io("candidate.recovery", error))?;
                continue;
            }
            let digest: BundleDigest = name
                .strip_suffix(".oxb")
                .and_then(|value| {
                    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
                })
                .ok_or_else(unsafe_store_object)?;
            if expected.contains(&digest) {
                continue;
            }
            let archive = self.read_verified_archive(&entry.path())?;
            if archive.content_digest() != digest {
                return Err(unsafe_store_object());
            }
            orphan_records.push(CandidateRecord {
                digest,
                file_digest: archive.file_digest(),
                bytes: archive.encoded_size(),
                status: CandidateStatus::Staged,
                sequence: 0,
            });
        }
        for entry in std::fs::read_dir(&self.root)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?
        {
            let entry = entry.map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(unsafe_store_object)?;
            if matches!(name, STATE_FILE | CANDIDATE_DIRECTORY | ".oxidase-lock") {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            if name.starts_with(STATE_PREFIX)
                && name.ends_with(".tmp")
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
            {
                std::fs::remove_file(entry.path())
                    .map_err(|error| CandidateStoreError::io("candidate.recovery", error))?;
            } else {
                return Err(unsafe_store_object());
            }
        }
        if !orphan_records.is_empty() {
            let _write = self.lock_writer();
            let state = self.lock_state();
            let mut next = (*state).clone();
            orphan_records.sort_by_key(|record| record.digest);
            for mut record in orphan_records {
                record.sequence = next_sequence(&mut next)?;
                next.candidates.insert(record.digest, record);
            }
            validate_persistent_state(&next, &self.limits)?;
            self.persist_locked(&next)?;
            self.state.store(Arc::new(next));
        }
        Ok(())
    }

    fn recover_operations(&self) -> Result<(), CandidateStoreError> {
        let _write = self.lock_writer();
        let state = self.lock_state();
        let mut next = (*state).clone();
        let mut changed = false;
        for record in next.operations.values_mut() {
            let receipt = &mut record.receipt;
            if receipt.audit_pending && receipt.phase != OperationPhase::RecoveryRequired {
                receipt.phase = OperationPhase::RecoveryRequired;
                receipt.error_code = Some("candidate.audit_unknown".to_owned());
                receipt.updated_unix_millis = timestamp();
                changed = true;
            } else if matches!(
                receipt.phase,
                OperationPhase::Accepted | OperationPhase::Preparing
            ) {
                receipt.phase = if receipt.commit_intent {
                    OperationPhase::RecoveryRequired
                } else {
                    OperationPhase::Cancelled
                };
                receipt.error_code = Some(
                    if receipt.commit_intent {
                        "candidate.publication_unknown"
                    } else {
                        "candidate.process_interrupted"
                    }
                    .to_owned(),
                );
                receipt.updated_unix_millis = timestamp();
                changed = true;
            }
            if receipt.phase == OperationPhase::RecoveryRequired {
                self.recovery_required.store(true, Ordering::Release);
            }
        }
        if changed {
            self.persist_locked(&next)?;
            self.state.store(Arc::new(next));
        }
        Ok(())
    }

    fn check_directory_identity(&self) -> Result<(), CandidateStoreError> {
        for (path, identity) in [
            (&self.root, self.root_identity),
            (&self.candidates_directory, self.candidates_identity),
        ] {
            check_parent_chain(path)?;
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || FileIdentity::of(&metadata) != identity
            {
                self.recovery_required.store(true, Ordering::Release);
                return Err(CandidateStoreError::new(
                    "candidate.storage_replaced",
                    "candidate storage directory identity changed",
                ));
            }
        }
        Ok(())
    }
    fn persist_locked(&self, state: &PersistentState) -> Result<(), CandidateStoreError> {
        self.check_directory_identity()?;
        let bytes = serde_json::to_vec(state).map_err(|_| {
            CandidateStoreError::new("candidate.state", "cannot encode candidate state")
        })?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(CandidateStoreError::new(
                "candidate.state_limit",
                "candidate state exceeds fixed byte limit",
            ));
        }
        let mut temporary = tempfile::Builder::new()
            .prefix(STATE_PREFIX)
            .suffix(".tmp")
            .tempfile_in(&self.root)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        temporary
            .write_all(&bytes)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        #[cfg(test)]
        self.inject(FaultPoint::StateFsync)?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        self.check_directory_identity()?;
        let destination = self.root.join(STATE_FILE);
        if std::fs::symlink_metadata(&destination)
            .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
        {
            return Err(unsafe_store_object());
        }
        #[cfg(test)]
        self.inject(FaultPoint::StateRename)?;
        temporary
            .persist(destination)
            .map_err(|error| CandidateStoreError::io("candidate.state", error.error))?;
        #[cfg(test)]
        let synced = self
            .inject(FaultPoint::DirectoryFsync)
            .and_then(|()| sync_directory(&self.root));
        #[cfg(not(test))]
        let synced = sync_directory(&self.root);
        if synced.is_err() {
            self.recovery_required.store(true, Ordering::Release);
        }
        synced
    }
    fn lock_state(&self) -> Arc<PersistentState> {
        self.state.load_full()
    }
    fn lock_writer(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    #[allow(clippy::too_many_arguments)]
    fn record_audit(
        &self,
        context: &CandidateOperationContext,
        action: AuditAction,
        digest: Option<BundleDigest>,
        previous_version: Option<String>,
        new_version: Option<String>,
        result: Result<(), &'static str>,
    ) {
        let mut audit = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if audit.len() == self.limits.max_audit_events {
            audit.pop_front();
        }
        audit.push_back(AuditEvent {
            sequence: self.audit_sequence.fetch_add(1, Ordering::Relaxed),
            timestamp_unix_millis: timestamp(),
            request_id: context.request_id.clone(),
            principal: context.principal.clone(),
            action,
            candidate_digest: digest,
            previous_version,
            new_version,
            result: if result.is_ok() {
                AuditResult::Success
            } else {
                AuditResult::Failure
            },
            error_code: result.err().map(str::to_owned),
        });
    }
    #[cfg(test)]
    fn inject(&self, point: FaultPoint) -> Result<(), CandidateStoreError> {
        let mut fault = self.fault.lock().expect("test fault lock");
        if *fault == Some(point) {
            *fault = None;
            return Err(CandidateStoreError::new(
                "candidate.injected_fault",
                "injected storage failure",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateStoreError {
    code: &'static str,
    message: String,
    diagnostics: Vec<oxidase_core::Diagnostic>,
}
impl CandidateStoreError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        }
    }
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<oxidase_core::Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
    #[must_use]
    pub fn diagnostics(&self) -> &[oxidase_core::Diagnostic] {
        &self.diagnostics
    }
    fn io(code: &'static str, error: std::io::Error) -> Self {
        Self::new(code, format!("candidate storage I/O failed: {error}"))
    }
    fn bundle(error: oxidase_bundle::BundleError) -> Self {
        Self::new(error.code(), error.message())
    }
}
impl std::fmt::Display for CandidateStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for CandidateStoreError {}

fn validate_limits(limits: &CandidateStoreLimits) -> Result<(), CandidateStoreError> {
    if limits.max_candidates == 0
        || limits.max_total_bytes == 0
        || limits.max_candidate_bytes == 0
        || limits.max_total_bytes < limits.max_candidate_bytes
        || limits.max_history_snapshots == 0
        || limits.max_history_bytes < limits.max_candidate_bytes
        || limits.max_idempotency_entries == 0
        || limits.max_audit_events == 0
    {
        return Err(CandidateStoreError::new(
            "candidate.invalid_limits",
            "candidate limits must be non-zero and hold one maximum candidate",
        ));
    }
    Ok(())
}
fn validate_context(context: &CandidateOperationContext) -> Result<(), CandidateStoreError> {
    validate_bounded_text("request id", &context.request_id)?;
    validate_bounded_text("principal", &context.principal)?;
    for (label, value) in [
        ("If-Match", &context.if_match),
        ("idempotency key", &context.idempotency_key),
    ] {
        if let Some(value) = value {
            validate_bounded_text(label, value)?;
        }
    }
    Ok(())
}
fn validate_bounded_text(label: &str, value: &str) -> Result<(), CandidateStoreError> {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CandidateStoreError::new(
            "candidate.invalid_metadata",
            format!("{label} must be bounded non-empty ASCII without controls"),
        ));
    }
    Ok(())
}
fn operation_fingerprint(
    context: &CandidateOperationContext,
    action: AuditAction,
    target: Option<BundleDigest>,
    body: Option<BundleDigest>,
) -> String {
    let mut builder = ContentDigestBuilder::new("oxidase/admin-operation/v1");
    builder
        .field_bytes("principal", &context.principal)
        .field_bytes("action", action.text())
        .field_bytes(
            "target",
            target.map_or_else(String::new, |digest| digest.to_string()),
        )
        .field_bytes("expected_etag", context.if_match.as_deref().unwrap_or(""))
        .field_bytes(
            "body_digest",
            body.map_or_else(String::new, |digest| digest.to_string()),
        );
    builder.finish().to_hex()
}
fn timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}
fn next_sequence(state: &mut PersistentState) -> Result<u64, CandidateStoreError> {
    let sequence = state.next_sequence;
    state.next_sequence = sequence.checked_add(1).ok_or_else(|| {
        CandidateStoreError::new("candidate.state", "operation sequence exhausted")
    })?;
    Ok(sequence)
}
fn evict_operations(
    state: &mut PersistentState,
    maximum: usize,
) -> Result<(), CandidateStoreError> {
    while state.operations.len() >= maximum {
        let index = state
            .operation_order
            .iter()
            .position(|id| {
                state.operations.get(id).is_some_and(|record| {
                    record.receipt.phase.is_finished()
                        && record.receipt.phase != OperationPhase::RecoveryRequired
                        && !record.receipt.audit_pending
                })
            })
            .ok_or_else(|| {
                CandidateStoreError::new(
                    "candidate.operation_capacity",
                    "operation retention is full of unfinished operations",
                )
            })?;
        let id = state
            .operation_order
            .remove(index)
            .expect("existing operation index");
        state.operations.remove(&id);
    }
    Ok(())
}
fn evict_history(state: &mut PersistentState, limits: &CandidateStoreLimits) {
    while state.history.len() > limits.max_history_snapshots
        || !checked_total(state.history.iter().map(|record| record.bytes))
            .is_ok_and(|bytes| bytes <= limits.max_history_bytes)
    {
        state.history.pop_front();
    }
}
fn checked_total(mut values: impl Iterator<Item = u64>) -> Result<u64, CandidateStoreError> {
    values.try_fold(0_u64, |total, value| {
        total.checked_add(value).ok_or_else(candidate_limit)
    })
}
fn validate_persistent_state(
    state: &PersistentState,
    limits: &CandidateStoreLimits,
) -> Result<(), CandidateStoreError> {
    if state.schema_version != STATE_SCHEMA {
        return Err(CandidateStoreError::new(
            "candidate.state_schema",
            "unsupported candidate journal schema",
        ));
    }
    if state.next_sequence == 0 {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "journal sequence must be positive",
        ));
    }
    if state.candidates.len() > limits.max_candidates
        || state.operations.len() > limits.max_idempotency_entries
        || state.history.len() > limits.max_history_snapshots
        || state.tombstones.len() > limits.max_candidates
        || checked_total(state.candidates.values().map(|record| record.bytes))?
            > limits.max_total_bytes
        || checked_total(state.history.iter().map(|record| record.bytes))?
            > limits.max_history_bytes
    {
        return Err(CandidateStoreError::new(
            "candidate.state_limit",
            "candidate journal exceeds configured bounds",
        ));
    }
    for (digest, record) in &state.candidates {
        if *digest != record.digest
            || record.bytes > limits.max_candidate_bytes
            || record.sequence == 0
            || record.sequence >= state.next_sequence
            || state.tombstones.contains(digest)
        {
            return Err(CandidateStoreError::new(
                "candidate.state",
                "inconsistent candidate journal identity",
            ));
        }
    }
    let ids = state
        .operation_order
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if ids.len() != state.operation_order.len() || ids != state.operations.keys().cloned().collect()
    {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "inconsistent operation retention index",
        ));
    }
    let mut keys = BTreeSet::new();
    for (id, record) in &state.operations {
        let receipt = &record.receipt;
        validate_bounded_text("operation id", id)?;
        validate_bounded_text("request id", &receipt.request_id)?;
        validate_bounded_text("principal", &receipt.principal)?;
        if let Some(etag) = &receipt.expected_etag {
            validate_bounded_text("If-Match", etag)?;
        }
        if let Some(key) = &record.idempotency_key {
            validate_bounded_text("idempotency key", key)?;
        }
        if let Some(code) = &receipt.error_code {
            validate_bounded_text("error code", code)?;
        }
        let sequence = id
            .strip_prefix("op-")
            .filter(|value| value.len() == 16)
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(unsafe_store_object)?;
        if id != &receipt.operation_id
            || sequence == 0
            || sequence >= state.next_sequence
            || record.fingerprint.len() != 64
            || !record
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || record
                .idempotency_key
                .as_ref()
                .is_some_and(|key| !keys.insert((receipt.principal.clone(), key.clone())))
        {
            return Err(CandidateStoreError::new(
                "candidate.state",
                "inconsistent operation journal record",
            ));
        }
        if let Some(version) = &receipt.config_version {
            validate_bounded_text("config version", version)?;
        }
        if matches!(
            receipt.action,
            AuditAction::Activate | AuditAction::Rollback | AuditAction::Validate
        ) && receipt.target_digest.is_none()
        {
            return Err(unsafe_store_object());
        }
        if matches!(
            receipt.action,
            AuditAction::Drain | AuditAction::ReloadSource
        ) && receipt.target_digest.is_some()
        {
            return Err(unsafe_store_object());
        }
        if receipt.commit_intent {
            if receipt.previous_revision.is_none()
                || receipt.config_version.is_none()
                || !matches!(
                    receipt.phase,
                    OperationPhase::Preparing
                        | OperationPhase::Committed
                        | OperationPhase::RecoveryRequired
                )
            {
                return Err(unsafe_store_object());
            }
            if receipt.phase == OperationPhase::Committed
                && !receipt
                    .previous_revision
                    .zip(receipt.committed_revision)
                    .is_some_and(|(before, after)| after > before)
            {
                return Err(unsafe_store_object());
            }
        }
        if matches!(
            receipt.phase,
            OperationPhase::Accepted
                | OperationPhase::Preparing
                | OperationPhase::Failed
                | OperationPhase::Cancelled
        ) && receipt.committed_revision.is_some()
        {
            return Err(unsafe_store_object());
        }
        if receipt.phase == OperationPhase::Accepted
            && (receipt.commit_intent
                || receipt.previous_revision.is_some()
                || receipt.config_version.is_some())
        {
            return Err(unsafe_store_object());
        }
    }
    for record in &state.history {
        validate_bounded_text("config version", &record.config_version)?;
        if !state
            .candidates
            .get(&record.digest)
            .is_some_and(|candidate| candidate.bytes == record.bytes)
            || record.sequence == 0
            || record.sequence >= state.next_sequence
        {
            return Err(CandidateStoreError::new(
                "candidate.state",
                "history references absent artifact",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}
impl FileIdentity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            Self {}
        }
    }
}
fn check_parent_chain(path: &Path) -> Result<(), CandidateStoreError> {
    if !path.is_absolute() {
        return Err(CandidateStoreError::new(
            "candidate.storage_path",
            "candidate storage must have an absolute path",
        ));
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CandidateStoreError::new(
                "candidate.storage_path",
                "candidate storage parent must be a real directory",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            // Sticky shared temporary parents protect an owned child. Other
            // group/world-writable parents can replace it and are rejected.
            if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
                return Err(CandidateStoreError::new(
                    "candidate.storage_parent",
                    "candidate storage parent is writable by untrusted users",
                ));
            }
        }
    }
    Ok(())
}
fn ensure_private_directory(path: &Path) -> Result<(), CandidateStoreError> {
    check_parent_chain(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(unsafe_store_object());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt as _;
                if metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.mode() & 0o077 != 0
                {
                    return Err(CandidateStoreError::new(
                        "candidate.storage_permissions",
                        "candidate storage must be owned by this user and mode 0700",
                    ));
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder
                .create(path)
                .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?;
        }
        Err(error) => return Err(CandidateStoreError::io("candidate.storage_path", error)),
    }
    Ok(())
}
fn open_regular(path: &Path, create: bool, maximum: u64) -> Result<File, CandidateStoreError> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => None,
        Err(error) => return Err(CandidateStoreError::io("candidate.state", error)),
    };
    if before.as_ref().is_some_and(|metadata| {
        metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum
    }) {
        return Err(unsafe_store_object());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC)
                .bits() as i32,
        );
    }
    let file = options
        .open(path)
        .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
    let after = file
        .metadata()
        .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
    if !after.is_file()
        || after.len() > maximum
        || before
            .as_ref()
            .is_some_and(|before| FileIdentity::of(before) != FileIdentity::of(&after))
    {
        return Err(unsafe_store_object());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if after.uid() != rustix::process::geteuid().as_raw() || after.mode() & 0o022 != 0 {
            return Err(unsafe_store_object());
        }
    }
    Ok(file)
}
fn readonly_permissions(file: &File) -> Result<std::fs::Permissions, CandidateStoreError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?
        .permissions();
    permissions.set_readonly(true);
    Ok(permissions)
}
fn sync_directory(path: &Path) -> Result<(), CandidateStoreError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| CandidateStoreError::io("candidate.sync", error))?;
    Ok(())
}
fn load_state(root: &Path) -> Result<PersistentState, CandidateStoreError> {
    let path = root.join(STATE_FILE);
    if matches!(std::fs::symlink_metadata(&path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(PersistentState::default());
    }
    let file = open_regular(&path, false, MAX_STATE_BYTES)?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(candidate_limit());
    }
    parse_journal_bytes(&bytes)
}

/// Validates bounded durable journal bytes without filesystem I/O, including
/// migration and all identity/retention invariants. This is the fuzz boundary.
pub fn validate_candidate_journal_bytes(
    bytes: &[u8],
    limits: &CandidateStoreLimits,
) -> Result<(), CandidateStoreError> {
    validate_limits(limits)?;
    validate_persistent_state(&parse_journal_bytes(bytes)?, limits)
}

fn parse_journal_bytes(bytes: &[u8]) -> Result<PersistentState, CandidateStoreError> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(CandidateStoreError::new(
            "candidate.state_limit",
            "candidate journal exceeds fixed byte limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| CandidateStoreError::new("candidate.state", "candidate journal is corrupt"))?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_str)
        == Some("oxidase.candidate-store/v1")
    {
        let legacy: LegacyPersistentState = serde_json::from_value(value).map_err(|_| {
            CandidateStoreError::new("candidate.state", "legacy candidate journal is corrupt")
        })?;
        return legacy.migrate();
    }
    serde_json::from_value(value).map_err(|_| {
        CandidateStoreError::new(
            "candidate.state",
            "candidate journal is corrupt or uses an unsupported schema",
        )
    })
}

// The WIP v1 independent current is deliberately discarded. Its idempotency
// keys lacked principal/complete fingerprints and cannot safely be replayed.
// Legacy activation history remains inspectable, with revision zero meaning
// that no published runtime revision was recorded by that format.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistentState {
    schema_version: String,
    candidates: BTreeMap<BundleDigest, CandidateRecord>,
    history: VecDeque<LegacyHistory>,
    current: Option<LegacyCurrent>,
    idempotency: BTreeMap<String, LegacyIdempotency>,
    idempotency_order: VecDeque<String>,
    next_sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyHistory {
    digest: BundleDigest,
    config_version: String,
    bytes: u64,
    sequence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCurrent {
    digest: BundleDigest,
    config_version: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyIdempotency {
    action: AuditAction,
    digest: BundleDigest,
    previous_version: Option<String>,
    new_version: Option<String>,
}
impl LegacyPersistentState {
    fn migrate(self) -> Result<PersistentState, CandidateStoreError> {
        if self.schema_version != "oxidase.candidate-store/v1" || self.next_sequence == 0 {
            return Err(CandidateStoreError::new(
                "candidate.state",
                "invalid legacy journal sequence",
            ));
        }
        if let Some(current) = self.current {
            validate_bounded_text("legacy config version", &current.config_version)?;
            if !self.candidates.contains_key(&current.digest) {
                return Err(unsafe_store_object());
            }
        }
        let keys = self
            .idempotency_order
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if keys.len() != self.idempotency_order.len()
            || keys != self.idempotency.keys().cloned().collect()
        {
            return Err(unsafe_store_object());
        }
        for (key, record) in self.idempotency {
            validate_bounded_text("legacy idempotency key", &key)?;
            if !matches!(
                record.action,
                AuditAction::Stage
                    | AuditAction::Validate
                    | AuditAction::Activate
                    | AuditAction::Rollback
            ) || !self.candidates.contains_key(&record.digest)
            {
                return Err(unsafe_store_object());
            }
            for version in [record.previous_version, record.new_version]
                .into_iter()
                .flatten()
            {
                validate_bounded_text("legacy config version", &version)?;
            }
        }
        let history = self
            .history
            .into_iter()
            .map(|record| SnapshotHistoryRecord {
                digest: record.digest,
                config_version: record.config_version,
                bytes: record.bytes,
                sequence: record.sequence,
                committed_revision: 0,
                operation_id: format!("legacy-{:016x}", record.sequence),
            })
            .collect();
        Ok(PersistentState {
            candidates: self.candidates,
            history,
            next_sequence: self.next_sequence,
            ..PersistentState::default()
        })
    }
}
fn unsafe_store_object() -> CandidateStoreError {
    CandidateStoreError::new(
        "candidate.state",
        "unexpected or unsafe candidate storage object",
    )
}
fn candidate_limit() -> CandidateStoreError {
    CandidateStoreError::new("candidate.limit", "candidate exceeds configured byte limit")
}
fn candidate_capacity() -> CandidateStoreError {
    CandidateStoreError::new(
        "candidate.capacity",
        "candidate capacity is occupied by retained or pending artifacts",
    )
}
fn candidate_missing() -> CandidateStoreError {
    CandidateStoreError::new("candidate.not_found", "candidate is not staged")
}
fn operation_missing() -> CandidateStoreError {
    CandidateStoreError::new("candidate.operation_missing", "operation is not retained")
}
fn operation_in_progress() -> CandidateStoreError {
    CandidateStoreError::new(
        "candidate.operation_in_progress",
        "operation has not committed; query its receipt",
    )
}
fn invalid_transition() -> CandidateStoreError {
    CandidateStoreError::new(
        "candidate.operation_state",
        "invalid operation journal transition",
    )
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    UploadComplete,
    ArtifactRenamed,
    ArtifactDirectoryFsync,
    GcIndexed,
    StateFsync,
    StateRename,
    DirectoryFsync,
    Completion,
}

#[cfg(test)]
#[path = "candidate_tests.rs"]
mod tests;
