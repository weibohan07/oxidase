//! Content-addressed Bundle candidate storage for the secure control plane.
//!
//! This module owns durable artifacts and serialized activation bookkeeping.
//! It deliberately delegates snapshot preparation and publication to a caller
//! callback so the server's existing prepare/commit/drain manager remains the
//! sole data-plane publication boundary.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use oxidase_bundle::{
    BundleArchive, BundleCapabilities, BundleDigest, BundleLimits, BundleVerificationKey,
    SignatureRequirement,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

const STATE_SCHEMA: &str = "oxidase.candidate-store/v1";
const STATE_FILE: &str = "state.json";
const CANDIDATE_DIRECTORY: &str = "candidates";
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentActivation {
    pub digest: BundleDigest,
    pub config_version: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageOutcome {
    pub candidate: CandidateRecord,
    pub already_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutcome {
    pub candidate: CandidateRecord,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationOutcome {
    pub digest: BundleDigest,
    pub previous_version: Option<String>,
    pub current_version: String,
    pub idempotent_replay: bool,
    pub already_current: bool,
}

#[derive(Debug)]
pub struct CandidateStore {
    root: PathBuf,
    candidates_directory: PathBuf,
    limits: CandidateStoreLimits,
    signature_policy: CandidateSignaturePolicy,
    capabilities: BundleCapabilities,
    state: Mutex<PersistentState>,
    operation_gate: AsyncMutex<()>,
    audit: Mutex<VecDeque<AuditEvent>>,
    audit_sequence: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistentState {
    schema_version: String,
    candidates: BTreeMap<BundleDigest, CandidateRecord>,
    history: VecDeque<SnapshotHistoryRecord>,
    current: Option<CurrentActivation>,
    idempotency: BTreeMap<String, IdempotencyRecord>,
    idempotency_order: VecDeque<String>,
    next_sequence: u64,
}

impl Default for PersistentState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA.to_owned(),
            candidates: BTreeMap::new(),
            history: VecDeque::new(),
            current: None,
            idempotency: BTreeMap::new(),
            idempotency_order: VecDeque::new(),
            next_sequence: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdempotencyRecord {
    action: AuditAction,
    digest: BundleDigest,
    previous_version: Option<String>,
    new_version: Option<String>,
}

impl CandidateStore {
    pub fn open(
        root: impl Into<PathBuf>,
        limits: CandidateStoreLimits,
        signature_policy: CandidateSignaturePolicy,
        capabilities: BundleCapabilities,
    ) -> Result<Arc<Self>, CandidateStoreError> {
        validate_limits(&limits)?;
        if !signature_policy.allow_unsigned && signature_policy.trusted_keys.is_empty() {
            return Err(CandidateStoreError::new(
                "candidate.signature_policy",
                "signed candidates require at least one trusted verification key",
            ));
        }
        let root = root.into();
        ensure_private_directory(&root)?;
        let candidates_directory = root.join(CANDIDATE_DIRECTORY);
        ensure_private_directory(&candidates_directory)?;
        let state = load_state(&root)?;
        validate_persistent_state(&state, &limits)?;
        let store = Arc::new(Self {
            root,
            candidates_directory,
            limits,
            signature_policy,
            capabilities,
            state: Mutex::new(state),
            operation_gate: AsyncMutex::new(()),
            audit: Mutex::new(VecDeque::new()),
            audit_sequence: AtomicU64::new(1),
        });
        store.reconcile_files()?;
        Ok(store)
    }

    pub async fn stage_bytes(
        &self,
        bytes: &[u8],
        context: &CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let _operation = self.operation_gate.lock().await;
        validate_context(context)?;
        self.check_if_match(context)?;
        let result = self.stage_reader_inner(bytes, Some(context));
        match &result {
            Ok(outcome) => self.record_audit(
                context,
                AuditAction::Stage,
                Some(outcome.candidate.digest),
                None,
                None,
                Ok(()),
            ),
            Err(error) => self.record_audit(
                context,
                AuditAction::Stage,
                None,
                None,
                None,
                Err(error.code()),
            ),
        }
        result
    }

    /// Stages an already bounded reader without first collecting it in memory.
    ///
    /// The blocking file and Bundle parser work runs on Tokio's blocking pool;
    /// the operation gate remains held so two mutations can never race on the
    /// durable state file or capacity accounting. The reader is owned by the
    /// operation and may therefore be an adapter over an upload spool.
    pub async fn stage_reader<R>(
        self: &Arc<Self>,
        reader: R,
        context: CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError>
    where
        R: Read + Send + 'static,
    {
        let context_for_worker = context.clone();
        let store = Arc::clone(self);
        let result = tokio::task::spawn_blocking(move || {
            // The worker owns the gate while it performs blocking I/O. If
            // the caller drops this future, Tokio lets the worker finish and
            // the gate still prevents a concurrent mutation from racing it.
            let _operation = store.operation_gate.blocking_lock();
            validate_context(&context_for_worker)?;
            store.check_if_match(&context_for_worker)?;
            store.stage_reader_inner(reader, Some(&context_for_worker))
        })
        .await
        .map_err(|error| {
            CandidateStoreError::new(
                "candidate.stage_io",
                format!("candidate staging worker failed: {error}"),
            )
        })?;
        match &result {
            Ok(outcome) => self.record_audit(
                &context,
                AuditAction::Stage,
                Some(outcome.candidate.digest),
                None,
                None,
                Ok(()),
            ),
            Err(error) => self.record_audit(
                &context,
                AuditAction::Stage,
                None,
                None,
                None,
                Err(error.code()),
            ),
        }
        result
    }

    /// Convenience adapter for a private temporary upload file. The file is
    /// opened only after a symlink and regular-file check and is read once by
    /// `stage_reader`; callers remain responsible for deleting their spool.
    pub async fn stage_file(
        self: &Arc<Self>,
        path: impl Into<PathBuf>,
        context: CandidateOperationContext,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let path = path.into();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CandidateStoreError::new(
                "candidate.stage_io",
                "candidate upload must be a regular file",
            ));
        }
        let file = File::open(&path)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        self.stage_reader(file, context).await
    }

    pub async fn validate_candidate<F, Fut>(
        &self,
        digest: BundleDigest,
        context: &CandidateOperationContext,
        validate: F,
    ) -> Result<ValidationOutcome, CandidateStoreError>
    where
        F: FnOnce(Arc<BundleArchive>) -> Fut,
        Fut: std::future::Future<Output = Result<(), CandidateStoreError>>,
    {
        let _operation = self.operation_gate.lock().await;
        validate_context(context)?;
        self.check_if_match(context)?;
        if let Some(record) = self.idempotent_validation(context, digest)? {
            return Ok(ValidationOutcome {
                candidate: record,
                idempotent_replay: true,
            });
        }
        let archive = Arc::new(self.open_candidate(digest)?);
        if let Err(error) = validate(archive).await {
            self.record_audit(
                context,
                AuditAction::Validate,
                Some(digest),
                self.current_version(),
                None,
                Err(error.code()),
            );
            return Err(error);
        }
        let mut state = self.lock_state();
        let sequence = next_sequence(&mut state);
        let candidate = state.candidates.get_mut(&digest).ok_or_else(|| {
            CandidateStoreError::new("candidate.not_found", "candidate is not staged")
        })?;
        candidate.status = CandidateStatus::Validated;
        candidate.sequence = sequence;
        let candidate = candidate.clone();
        let validation_previous_version = state
            .current
            .as_ref()
            .map(|current| current.config_version.clone());
        remember_idempotency(
            &mut state,
            &self.limits,
            context,
            IdempotencyRecord {
                action: AuditAction::Validate,
                digest,
                previous_version: validation_previous_version,
                new_version: None,
            },
        )?;
        self.persist_locked(&state)?;
        drop(state);
        self.record_audit(
            context,
            AuditAction::Validate,
            Some(digest),
            self.current_version(),
            None,
            Ok(()),
        );
        Ok(ValidationOutcome {
            candidate,
            idempotent_replay: false,
        })
    }

    pub async fn activate_candidate<F, Fut>(
        &self,
        digest: BundleDigest,
        context: &CandidateOperationContext,
        activate: F,
    ) -> Result<ActivationOutcome, CandidateStoreError>
    where
        F: FnOnce(Arc<BundleArchive>) -> Fut,
        Fut: std::future::Future<Output = Result<String, CandidateStoreError>>,
    {
        self.activate_inner(digest, context, AuditAction::Activate, false, activate)
            .await
    }

    pub async fn rollback<F, Fut>(
        &self,
        digest: BundleDigest,
        context: &CandidateOperationContext,
        activate: F,
    ) -> Result<ActivationOutcome, CandidateStoreError>
    where
        F: FnOnce(Arc<BundleArchive>) -> Fut,
        Fut: std::future::Future<Output = Result<String, CandidateStoreError>>,
    {
        self.activate_inner(digest, context, AuditAction::Rollback, true, activate)
            .await
    }

    async fn activate_inner<F, Fut>(
        &self,
        digest: BundleDigest,
        context: &CandidateOperationContext,
        action: AuditAction,
        require_history: bool,
        activate: F,
    ) -> Result<ActivationOutcome, CandidateStoreError>
    where
        F: FnOnce(Arc<BundleArchive>) -> Fut,
        Fut: std::future::Future<Output = Result<String, CandidateStoreError>>,
    {
        let _operation = self.operation_gate.lock().await;
        validate_context(context)?;
        self.check_if_match(context)?;
        if let Some(outcome) = self.idempotent_activation(context, digest, action)? {
            return Ok(outcome);
        }
        let previous_version = self.current_version();
        {
            let state = self.lock_state();
            let candidate = state.candidates.get(&digest).ok_or_else(|| {
                CandidateStoreError::new("candidate.not_found", "candidate is not staged")
            })?;
            if candidate.status != CandidateStatus::Validated {
                return Err(CandidateStoreError::new(
                    "candidate.not_validated",
                    "candidate must be validated before activation",
                ));
            }
            if require_history && !state.history.iter().any(|entry| entry.digest == digest) {
                return Err(CandidateStoreError::new(
                    "candidate.rollback_missing",
                    "rollback target is not in retained activation history",
                ));
            }
            if state
                .current
                .as_ref()
                .is_some_and(|current| current.digest == digest)
            {
                return Ok(ActivationOutcome {
                    digest,
                    previous_version: previous_version.clone(),
                    current_version: previous_version.unwrap_or_default(),
                    idempotent_replay: false,
                    already_current: true,
                });
            }
        }
        let archive = Arc::new(self.open_candidate(digest)?);
        let new_version = match activate(archive).await {
            Ok(version) => version,
            Err(error) => {
                self.record_audit(
                    context,
                    action,
                    Some(digest),
                    previous_version.clone(),
                    None,
                    Err(error.code()),
                );
                return Err(error);
            }
        };
        validate_bounded_text("new config version", &new_version)?;
        let mut state = self.lock_state();
        let candidate = state.candidates.get(&digest).cloned().ok_or_else(|| {
            CandidateStoreError::new("candidate.not_found", "candidate disappeared")
        })?;
        let sequence = next_sequence(&mut state);
        state.history.retain(|entry| entry.digest != digest);
        state.history.push_back(SnapshotHistoryRecord {
            digest,
            config_version: new_version.clone(),
            bytes: candidate.bytes,
            sequence,
        });
        evict_history(&mut state, &self.limits);
        state.current = Some(CurrentActivation {
            digest,
            config_version: new_version.clone(),
        });
        remember_idempotency(
            &mut state,
            &self.limits,
            context,
            IdempotencyRecord {
                action,
                digest,
                previous_version: previous_version.clone(),
                new_version: Some(new_version.clone()),
            },
        )?;
        self.persist_locked(&state)?;
        drop(state);
        self.record_audit(
            context,
            action,
            Some(digest),
            previous_version.clone(),
            Some(new_version.clone()),
            Ok(()),
        );
        Ok(ActivationOutcome {
            digest,
            previous_version,
            current_version: new_version,
            idempotent_replay: false,
            already_current: false,
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
    pub fn current(&self) -> Option<CurrentActivation> {
        self.lock_state().current.clone()
    }

    pub fn seed_current(
        &self,
        digest: BundleDigest,
        config_version: impl Into<String>,
    ) -> Result<(), CandidateStoreError> {
        let config_version = config_version.into();
        validate_bounded_text("config version", &config_version)?;
        let mut state = self.lock_state();
        if !state.candidates.contains_key(&digest) {
            return Err(CandidateStoreError::new(
                "candidate.not_found",
                "current digest is not in candidate storage",
            ));
        }
        state.current = Some(CurrentActivation {
            digest,
            config_version,
        });
        self.persist_locked(&state)
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
        context: Option<&CandidateOperationContext>,
    ) -> Result<StageOutcome, CandidateStoreError> {
        let mut temporary = tempfile::NamedTempFile::new_in(&self.candidates_directory)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        let mut bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
            if read == 0 {
                break;
            }
            bytes = bytes.checked_add(read as u64).ok_or_else(|| {
                CandidateStoreError::new("candidate.limit", "candidate size overflows u64")
            })?;
            if bytes > self.limits.max_candidate_bytes {
                return Err(CandidateStoreError::new(
                    "candidate.limit",
                    "candidate exceeds configured byte limit",
                ));
            }
            temporary
                .write_all(&buffer[..read])
                .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        }
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
        let archive = BundleArchive::read_path(
            temporary.path(),
            &BundleLimits {
                max_bundle_bytes: self.limits.max_candidate_bytes,
                ..BundleLimits::default()
            },
        )
        .map_err(CandidateStoreError::bundle)?;
        archive.verify().map_err(CandidateStoreError::bundle)?;
        archive
            .verify_capabilities(&self.capabilities)
            .map_err(CandidateStoreError::bundle)?;
        let requirement = if self.signature_policy.allow_unsigned {
            SignatureRequirement::AllowUnsigned
        } else {
            SignatureRequirement::RequireAnyTrusted
        };
        archive
            .verify_ed25519(&self.signature_policy.trusted_keys, requirement)
            .map_err(CandidateStoreError::bundle)?;
        let digest = archive.content_digest();
        let file_digest = archive.file_digest();
        let destination = self.candidate_path(digest);
        let mut state = self.lock_state();
        if let Some(context) = context
            && let Some(key) = &context.idempotency_key
            && let Some(record) = state.idempotency.get(key)
        {
            if record.action != AuditAction::Stage || record.digest != digest {
                return Err(CandidateStoreError::new(
                    "candidate.idempotency_conflict",
                    "idempotency key was already used for a different operation",
                ));
            }
            let existing = state.candidates.get(&digest).cloned().ok_or_else(|| {
                CandidateStoreError::new(
                    "candidate.state",
                    "idempotency record references missing candidate",
                )
            })?;
            return Ok(StageOutcome {
                candidate: existing,
                already_present: true,
            });
        }
        if let Some(existing) = state.candidates.get(&digest).cloned() {
            if let Some(context) = context
                && context.idempotency_key.is_some()
            {
                remember_idempotency(
                    &mut state,
                    &self.limits,
                    context,
                    IdempotencyRecord {
                        action: AuditAction::Stage,
                        digest,
                        previous_version: None,
                        new_version: None,
                    },
                )?;
                self.persist_locked(&state)?;
            }
            return Ok(StageOutcome {
                candidate: existing,
                already_present: true,
            });
        }
        evict_candidates_for(&mut state, &self.limits, bytes, &self.candidates_directory)?;
        temporary
            .persist_noclobber(&destination)
            .map_err(|error| CandidateStoreError::io("candidate.stage_io", error.error))?;
        make_read_only(&destination)?;
        sync_directory(&self.candidates_directory)?;
        let sequence = next_sequence(&mut state);
        let candidate = CandidateRecord {
            digest,
            file_digest,
            bytes,
            status: CandidateStatus::Staged,
            sequence,
        };
        state.candidates.insert(digest, candidate.clone());
        if let Some(context) = context {
            remember_idempotency(
                &mut state,
                &self.limits,
                context,
                IdempotencyRecord {
                    action: AuditAction::Stage,
                    digest,
                    previous_version: None,
                    new_version: None,
                },
            )?;
        }
        self.persist_locked(&state)?;
        Ok(StageOutcome {
            candidate,
            already_present: false,
        })
    }

    fn open_candidate(&self, digest: BundleDigest) -> Result<BundleArchive, CandidateStoreError> {
        let state = self.lock_state();
        let record = state.candidates.get(&digest).cloned().ok_or_else(|| {
            CandidateStoreError::new("candidate.not_found", "candidate is not staged")
        })?;
        drop(state);
        let archive = BundleArchive::read_path(
            self.candidate_path(digest),
            &BundleLimits {
                max_bundle_bytes: self.limits.max_candidate_bytes,
                ..BundleLimits::default()
            },
        )
        .map_err(CandidateStoreError::bundle)?;
        if archive.content_digest() != digest
            || archive.file_digest() != record.file_digest
            || archive.encoded_size() != record.bytes
        {
            return Err(CandidateStoreError::new(
                "candidate.corrupt",
                "stored candidate no longer matches its durable record",
            ));
        }
        archive.verify().map_err(CandidateStoreError::bundle)?;
        archive
            .verify_capabilities(&self.capabilities)
            .map_err(CandidateStoreError::bundle)?;
        let requirement = if self.signature_policy.allow_unsigned {
            SignatureRequirement::AllowUnsigned
        } else {
            SignatureRequirement::RequireAnyTrusted
        };
        archive
            .verify_ed25519(&self.signature_policy.trusted_keys, requirement)
            .map_err(CandidateStoreError::bundle)?;
        Ok(archive)
    }

    /// Returns the content-addressed path for a staged candidate. The path is
    /// derived solely from the validated digest; callers cannot select an
    /// arbitrary filesystem path through this API.
    #[must_use]
    pub fn candidate_path(&self, digest: BundleDigest) -> PathBuf {
        self.candidates_directory.join(format!("{digest}.oxb"))
    }

    fn reconcile_files(&self) -> Result<(), CandidateStoreError> {
        let state = self.lock_state();
        for (digest, record) in &state.candidates {
            let path = self.candidate_path(*digest);
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != record.bytes
            {
                return Err(CandidateStoreError::new(
                    "candidate.state",
                    "candidate state references an invalid filesystem object",
                ));
            }
        }
        let expected = state
            .candidates
            .keys()
            .map(|digest| format!("{digest}.oxb"))
            .collect::<BTreeSet<_>>();
        let entries = std::fs::read_dir(&self.candidates_directory)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        for entry in entries {
            let entry = entry.map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
            let name = entry.file_name();
            let valid_name = name.to_str().is_some_and(|name| expected.contains(name));
            if metadata.file_type().is_symlink() || !metadata.is_file() || !valid_name {
                return Err(CandidateStoreError::new(
                    "candidate.state",
                    "candidate directory contains an unexpected or unsafe filesystem object",
                ));
            }
        }
        Ok(())
    }

    fn check_if_match(
        &self,
        context: &CandidateOperationContext,
    ) -> Result<(), CandidateStoreError> {
        if let Some(expected) = &context.if_match {
            let actual = self.current_version();
            if actual.as_deref() != Some(expected.as_str()) {
                return Err(CandidateStoreError::new(
                    "candidate.precondition",
                    "If-Match does not match the current config version",
                ));
            }
        }
        Ok(())
    }

    fn current_version(&self) -> Option<String> {
        self.lock_state()
            .current
            .as_ref()
            .map(|current| current.config_version.clone())
    }

    fn idempotent_validation(
        &self,
        context: &CandidateOperationContext,
        digest: BundleDigest,
    ) -> Result<Option<CandidateRecord>, CandidateStoreError> {
        let Some(key) = &context.idempotency_key else {
            return Ok(None);
        };
        let state = self.lock_state();
        let Some(record) = state.idempotency.get(key) else {
            return Ok(None);
        };
        if record.action != AuditAction::Validate || record.digest != digest {
            return Err(CandidateStoreError::new(
                "candidate.idempotency_conflict",
                "idempotency key was already used for a different operation",
            ));
        }
        Ok(state.candidates.get(&digest).cloned())
    }

    fn idempotent_activation(
        &self,
        context: &CandidateOperationContext,
        digest: BundleDigest,
        action: AuditAction,
    ) -> Result<Option<ActivationOutcome>, CandidateStoreError> {
        let Some(key) = &context.idempotency_key else {
            return Ok(None);
        };
        let state = self.lock_state();
        let Some(record) = state.idempotency.get(key) else {
            return Ok(None);
        };
        if record.action != action || record.digest != digest {
            return Err(CandidateStoreError::new(
                "candidate.idempotency_conflict",
                "idempotency key was already used for a different operation",
            ));
        }
        Ok(Some(ActivationOutcome {
            digest,
            previous_version: record.previous_version.clone(),
            current_version: record.new_version.clone().unwrap_or_default(),
            idempotent_replay: true,
            already_current: false,
        }))
    }

    fn persist_locked(&self, state: &PersistentState) -> Result<(), CandidateStoreError> {
        let bytes = serde_json::to_vec(state).map_err(|error| {
            CandidateStoreError::new(
                "candidate.state",
                format!("cannot encode candidate state: {error}"),
            )
        })?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(CandidateStoreError::new(
                "candidate.state_limit",
                "candidate state exceeds its fixed byte limit",
            ));
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&self.root)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        temporary
            .write_all(&bytes)
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
        temporary
            .persist(self.root.join(STATE_FILE))
            .map_err(|error| CandidateStoreError::io("candidate.state", error.error))?;
        sync_directory(&self.root)
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PersistentState> {
        self.state
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
        let sequence = self
            .audit_sequence
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let timestamp_unix_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let mut audit = self
            .audit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if audit.len() == self.limits.max_audit_events {
            audit.pop_front();
        }
        audit.push_back(AuditEvent {
            sequence,
            timestamp_unix_millis,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateStoreError {
    code: &'static str,
    message: String,
}

impl CandidateStoreError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
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
            "candidate limits must be non-zero and history bytes must hold one maximum candidate",
        ));
    }
    Ok(())
}

fn validate_context(context: &CandidateOperationContext) -> Result<(), CandidateStoreError> {
    validate_bounded_text("request id", &context.request_id)?;
    validate_bounded_text("principal", &context.principal)?;
    if let Some(value) = &context.if_match {
        validate_bounded_text("If-Match", value)?;
    }
    if let Some(value) = &context.idempotency_key {
        validate_bounded_text("idempotency key", value)?;
    }
    Ok(())
}

fn validate_bounded_text(label: &str, value: &str) -> Result<(), CandidateStoreError> {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.contains(['\0', '\r', '\n'])
    {
        return Err(CandidateStoreError::new(
            "candidate.invalid_metadata",
            format!("{label} must be non-empty bounded ASCII without control delimiters"),
        ));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<(), CandidateStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CandidateStoreError::new(
                    "candidate.storage_path",
                    "candidate storage path must be a real directory, not a symlink",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(path)
                .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?;
        }
        Err(error) => return Err(CandidateStoreError::io("candidate.storage_path", error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| CandidateStoreError::io("candidate.storage_path", error))?;
    }
    Ok(())
}

fn make_read_only(path: &Path) -> Result<(), CandidateStoreError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CandidateStoreError::new(
            "candidate.stage_io",
            "candidate destination must be a regular file",
        ));
    }
    let mut permissions = metadata.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions)
        .map_err(|error| CandidateStoreError::io("candidate.stage_io", error))
}

fn sync_directory(path: &Path) -> Result<(), CandidateStoreError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| CandidateStoreError::io("candidate.sync", error))?;
    }
    Ok(())
}

fn load_state(root: &Path) -> Result<PersistentState, CandidateStoreError> {
    let path = root.join(STATE_FILE);
    let path_metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(CandidateStoreError::io("candidate.state", error)),
    };
    if path_metadata
        .as_ref()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "candidate state must not be a symbolic link",
        ));
    }
    let mut file = match OpenOptions::new().read(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PersistentState::default());
        }
        Err(error) => return Err(CandidateStoreError::io("candidate.state", error)),
    };
    let metadata = file
        .metadata()
        .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "candidate state is not a bounded regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| CandidateStoreError::io("candidate.state", error))?;
    let state: PersistentState = serde_json::from_slice(&bytes).map_err(|error| {
        CandidateStoreError::new(
            "candidate.state",
            format!("candidate state is invalid JSON: {error}"),
        )
    })?;
    if state.schema_version != STATE_SCHEMA {
        return Err(CandidateStoreError::new(
            "candidate.state_schema",
            "candidate state schema is unsupported",
        ));
    }
    Ok(state)
}

fn validate_persistent_state(
    state: &PersistentState,
    limits: &CandidateStoreLimits,
) -> Result<(), CandidateStoreError> {
    if state.candidates.len() > limits.max_candidates
        || state.idempotency.len() > limits.max_idempotency_entries
        || state.history.len() > limits.max_history_snapshots
        || state
            .candidates
            .values()
            .map(|value| value.bytes)
            .sum::<u64>()
            > limits.max_total_bytes
        || state.history.iter().map(|value| value.bytes).sum::<u64>() > limits.max_history_bytes
    {
        return Err(CandidateStoreError::new(
            "candidate.state_limit",
            "candidate state exceeds configured storage limits",
        ));
    }
    if state
        .candidates
        .values()
        .any(|candidate| candidate.bytes > limits.max_candidate_bytes)
        || state
            .history
            .iter()
            .any(|entry| entry.bytes > limits.max_candidate_bytes)
    {
        return Err(CandidateStoreError::new(
            "candidate.state_limit",
            "candidate state contains an object larger than the configured candidate limit",
        ));
    }
    let candidate_keys = state.candidates.keys().copied().collect::<BTreeSet<_>>();
    if state
        .candidates
        .iter()
        .any(|(key, record)| key != &record.digest)
    {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "candidate state key does not match its content digest",
        ));
    }
    if state
        .history
        .iter()
        .any(|entry| validate_bounded_text("config version", &entry.config_version).is_err())
        || state.current.as_ref().is_some_and(|current| {
            validate_bounded_text("config version", &current.config_version).is_err()
        })
    {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "candidate state contains an invalid config version",
        ));
    }
    if state
        .history
        .iter()
        .any(|entry| !candidate_keys.contains(&entry.digest))
        || state
            .current
            .as_ref()
            .is_some_and(|current| !candidate_keys.contains(&current.digest))
    {
        return Err(CandidateStoreError::new(
            "candidate.state",
            "candidate history references missing content",
        ));
    }
    Ok(())
}

fn next_sequence(state: &mut PersistentState) -> u64 {
    let sequence = state.next_sequence;
    state.next_sequence = state.next_sequence.saturating_add(1);
    sequence
}

fn evict_history(state: &mut PersistentState, limits: &CandidateStoreLimits) {
    while state.history.len() > limits.max_history_snapshots
        || state.history.iter().map(|entry| entry.bytes).sum::<u64>() > limits.max_history_bytes
    {
        state.history.pop_front();
    }
}

fn evict_candidates_for(
    state: &mut PersistentState,
    limits: &CandidateStoreLimits,
    incoming_bytes: u64,
    directory: &Path,
) -> Result<(), CandidateStoreError> {
    loop {
        let total = state
            .candidates
            .values()
            .map(|value| value.bytes)
            .sum::<u64>();
        if state.candidates.len() < limits.max_candidates
            && total.saturating_add(incoming_bytes) <= limits.max_total_bytes
        {
            return Ok(());
        }
        let protected = state
            .history
            .iter()
            .map(|entry| entry.digest)
            .chain(state.current.as_ref().map(|current| current.digest))
            .collect::<BTreeSet<_>>();
        let Some(evict) = state
            .candidates
            .values()
            .filter(|candidate| !protected.contains(&candidate.digest))
            .min_by_key(|candidate| candidate.sequence)
            .cloned()
        else {
            return Err(CandidateStoreError::new(
                "candidate.capacity",
                "candidate storage is full and all retained content is protected by history",
            ));
        };
        let path = directory.join(format!("{}.oxb", evict.digest));
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| CandidateStoreError::io("candidate.evict", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CandidateStoreError::new(
                "candidate.evict",
                "candidate eviction target must be a regular file",
            ));
        }
        std::fs::remove_file(&path)
            .map_err(|error| CandidateStoreError::io("candidate.evict", error))?;
        state.candidates.remove(&evict.digest);
    }
}

fn remember_idempotency(
    state: &mut PersistentState,
    limits: &CandidateStoreLimits,
    context: &CandidateOperationContext,
    record: IdempotencyRecord,
) -> Result<(), CandidateStoreError> {
    let Some(key) = &context.idempotency_key else {
        return Ok(());
    };
    if let Some(existing) = state.idempotency.get(key) {
        if existing != &record {
            return Err(CandidateStoreError::new(
                "candidate.idempotency_conflict",
                "idempotency key was already used for a different successful operation",
            ));
        }
        return Ok(());
    }
    state.idempotency.insert(key.clone(), record);
    state.idempotency_order.push_back(key.clone());
    while state.idempotency.len() > limits.max_idempotency_entries {
        if let Some(oldest) = state.idempotency_order.pop_front() {
            state.idempotency.remove(&oldest);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::sync::Arc;

    use oxidase_bundle::{BuildMetadata, BundleBuilder, BundleManifest, BundleSigningKey};
    use tempfile::tempdir;

    use super::*;

    fn bundle_bytes(label: &str) -> Vec<u8> {
        let manifest = BundleManifest::new(
            BuildMetadata {
                tool_version: "test".to_owned(),
                source_commit: None,
                gateway_api: "oxidase.dev/v1alpha1".to_owned(),
                oxista_api: "v1".to_owned(),
            },
            "0.3.0-alpha.1",
        );
        let mut builder = BundleBuilder::new(manifest);
        builder.manifest_mut().optional_metadata.insert(
            "test".to_owned(),
            oxidase_bundle::CanonicalValue::String(label.to_owned()),
        );
        builder.build().expect("test bundle builds")
    }

    fn candidate_store(
        root: impl Into<std::path::PathBuf>,
        limits: CandidateStoreLimits,
    ) -> Arc<CandidateStore> {
        CandidateStore::open(
            root,
            limits,
            CandidateSignaturePolicy::allow_unsigned_for_development(),
            BundleCapabilities::default(),
        )
        .expect("candidate store opens")
    }

    fn context() -> CandidateOperationContext {
        CandidateOperationContext {
            request_id: "request-1".to_owned(),
            principal: "operator".to_owned(),
            if_match: None,
            idempotency_key: None,
        }
    }

    #[tokio::test]
    async fn stage_is_content_addressed_durable_and_idempotent() {
        let directory = tempdir().expect("temporary directory");
        let store = candidate_store(
            directory.path().join("state"),
            CandidateStoreLimits::default(),
        );
        let bytes = bundle_bytes("one");
        let mut stage_context = context();
        stage_context.idempotency_key = Some("stage-1".to_owned());
        let first = store
            .stage_bytes(&bytes, &stage_context)
            .await
            .expect("stage succeeds");
        let second = store
            .stage_bytes(&bytes, &stage_context)
            .await
            .expect("duplicate stage succeeds");
        assert!(!first.already_present);
        assert!(second.already_present);
        assert_eq!(first.candidate, second.candidate);

        let path = directory
            .path()
            .join("state/candidates")
            .join(format!("{}.oxb", first.candidate.digest));
        let metadata = fs::metadata(&path).expect("candidate file exists");
        assert!(metadata.permissions().readonly());

        drop(store);
        let reopened = candidate_store(
            directory.path().join("state"),
            CandidateStoreLimits::default(),
        );
        assert_eq!(reopened.candidates(), vec![first.candidate.clone()]);
        let streamed = reopened
            .stage_reader(Cursor::new(bundle_bytes("two")), context())
            .await
            .expect("owned reader stages without a collected request body");
        assert_ne!(streamed.candidate.digest, first.candidate.digest);
    }

    #[tokio::test]
    async fn signature_policy_is_fail_closed_by_default() {
        let directory = tempdir().expect("temporary directory");
        let error = CandidateStore::open(
            directory.path().join("state"),
            CandidateStoreLimits::default(),
            CandidateSignaturePolicy::require_trusted(vec![
                BundleSigningKey::from_bytes("test", &[7_u8; 32])
                    .expect("key")
                    .verification_key(),
            ]),
            BundleCapabilities::default(),
        )
        .expect("store opens");
        let error = error
            .stage_bytes(&bundle_bytes("unsigned"), &context())
            .await
            .expect_err("unsigned candidate is rejected");
        assert_eq!(error.code(), "bundle.signature_required");
    }

    #[tokio::test]
    async fn activation_is_serialized_and_retains_bounded_history() {
        let directory = tempdir().expect("temporary directory");
        let limits = CandidateStoreLimits {
            max_history_snapshots: 1,
            ..CandidateStoreLimits::default()
        };
        let store = candidate_store(directory.path().join("state"), limits);
        let bytes = bundle_bytes("one");
        let staged = store.stage_bytes(&bytes, &context()).await.expect("stage");
        let digest = staged.candidate.digest;
        store
            .validate_candidate(digest, &context(), |_archive| async { Ok(()) })
            .await
            .expect("validate");
        let mut activation_context = context();
        activation_context.idempotency_key = Some("activate-1".to_owned());
        let activated = store
            .activate_candidate(digest, &activation_context, |_archive| async {
                Ok("version-1".to_owned())
            })
            .await
            .expect("activate");
        assert_eq!(activated.current_version, "version-1");
        let replay = store
            .activate_candidate(digest, &activation_context, |_archive| async {
                panic!("idempotent replay must not invoke activation callback")
            })
            .await
            .expect("replay");
        assert!(replay.idempotent_replay);
        assert_eq!(
            store.current().expect("current").config_version,
            "version-1"
        );
        assert_eq!(store.history().len(), 1);
        assert!(
            store
                .audit_events()
                .iter()
                .any(|event| event.action == AuditAction::Activate
                    && event.result == AuditResult::Success)
        );
    }

    #[tokio::test]
    async fn if_match_rejects_stale_mutation_without_calling_callback() {
        let directory = tempdir().expect("temporary directory");
        let store = candidate_store(
            directory.path().join("state"),
            CandidateStoreLimits::default(),
        );
        let staged = store
            .stage_bytes(&bundle_bytes("one"), &context())
            .await
            .expect("stage");
        store
            .validate_candidate(staged.candidate.digest, &context(), |_archive| async {
                Ok(())
            })
            .await
            .expect("validate");
        store
            .activate_candidate(staged.candidate.digest, &context(), |_archive| async {
                Ok("version-1".to_owned())
            })
            .await
            .expect("activate");
        let mut stale = context();
        stale.if_match = Some("stale-version".to_owned());
        let stage_error = store
            .stage_bytes(&bundle_bytes("two"), &stale)
            .await
            .expect_err("staging also enforces the current-version precondition");
        assert_eq!(stage_error.code(), "candidate.precondition");
        let error = store
            .validate_candidate(staged.candidate.digest, &stale, |_archive| async {
                panic!("stale precondition must fail before callback")
            })
            .await
            .expect_err("stale mutation must be rejected");
        assert_eq!(error.code(), "candidate.precondition");
    }

    #[test]
    fn state_symlink_is_rejected() {
        let directory = tempdir().expect("temporary directory");
        let root = directory.path().join("state");
        fs::create_dir(&root).expect("state directory");
        fs::write(directory.path().join("state-target"), b"{}").expect("state target");
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            directory.path().join("state-target"),
            root.join("state.json"),
        )
        .expect("state symlink");
        #[cfg(unix)]
        assert_eq!(
            CandidateStore::open(
                root,
                CandidateStoreLimits::default(),
                CandidateSignaturePolicy::allow_unsigned_for_development(),
                BundleCapabilities::default(),
            )
            .expect_err("state symlink must be rejected")
            .code(),
            "candidate.state"
        );
    }
}
