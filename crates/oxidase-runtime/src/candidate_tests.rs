use super::*;

use oxidase_bundle::{BuildMetadata, BundleBuilder, BundleManifest, CanonicalValue};
use std::process::{Command, Stdio};
use tempfile::TempDir;

#[test]
fn structured_failure_diagnostics_survive_clone_but_do_not_enter_receipts() {
    let diagnostic = oxidase_core::Diagnostic::new(
        "test.field",
        "invalid template argument",
        oxidase_core::SourceSpan::synthetic("templates.params.item"),
    );
    let error = CandidateStoreError::new("candidate.prepare", "candidate preparation failed")
        .with_diagnostics(vec![diagnostic.clone()]);
    assert_eq!(error.clone().diagnostics(), &[diagnostic]);
    let directory = temp();
    let candidate_store = store(&root(&directory), CandidateStoreLimits::default());
    let begin = candidate_store
        .begin_operation(&context(None), AuditAction::Drain, None, None)
        .expect("begin");
    let receipt = candidate_store
        .finish_failed(&begin.receipt.operation_id, error.code())
        .expect("failed receipt");
    let encoded = serde_json::to_string(&receipt).expect("receipt encodes");
    assert!(!encoded.contains("templates.params.item"));
    assert!(!encoded.contains("invalid template argument"));
}

#[test]
fn uncommitted_recovery_never_claims_a_published_revision() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let begin = candidate_store
        .begin_operation(&context(None), AuditAction::ReloadSource, None, None)
        .expect("begin");
    candidate_store
        .begin_intent(&begin.receipt.operation_id, 7, "intended-B")
        .expect("durable intent");
    fault(&candidate_store, FaultPoint::StateRename);
    assert!(
        candidate_store
            .finish_cancelled(&begin.receipt.operation_id, "candidate.cancelled")
            .is_err()
    );
    let recovered = candidate_store.force_uncommitted_recovery_receipt(
        &begin.receipt.operation_id,
        "candidate.cancel_record_failed",
    );
    assert_eq!(recovered.phase, OperationPhase::RecoveryRequired);
    assert_eq!(recovered.committed_revision, None);
    assert!(!recovered.commit_intent);
    assert_eq!(recovered.previous_revision, Some(7));
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    assert_eq!(
        reopened
            .operation(&begin.receipt.operation_id)
            .expect("retained recovery")
            .committed_revision,
        None
    );
    assert_eq!(
        reopened
            .ensure_mutations_allowed()
            .expect_err("recovery fails closed")
            .code(),
        "candidate.recovery_required"
    );
}

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
    builder
        .manifest_mut()
        .optional_metadata
        .insert("test".to_owned(), CanonicalValue::String(label.to_owned()));
    builder.build().expect("test bundle")
}
fn temp() -> TempDir {
    tempfile::tempdir().expect("temporary test directory")
}
fn root(directory: &TempDir) -> PathBuf {
    directory
        .path()
        .canonicalize()
        .expect("test operation succeeds")
        .join("store")
}
fn store(path: &Path, limits: CandidateStoreLimits) -> Arc<CandidateStore> {
    CandidateStore::open(
        path,
        limits,
        CandidateSignaturePolicy::allow_unsigned_for_development(),
        BundleCapabilities::default(),
    )
    .expect("candidate store")
}
fn context(key: Option<&str>) -> CandidateOperationContext {
    CandidateOperationContext {
        request_id: "request-1".to_owned(),
        principal: "operator".to_owned(),
        if_match: Some("boot-1-revision-1".to_owned()),
        idempotency_key: key.map(str::to_owned),
    }
}
fn fault(store: &CandidateStore, point: FaultPoint) {
    *store.fault.lock().expect("test operation succeeds") = Some(point);
}

#[tokio::test]
async fn stage_reopens_verified_artifact_and_never_owns_runtime_current() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let bytes = bundle_bytes("A");
    let staged = candidate_store
        .stage_bytes(&bytes, &context(Some("upload")))
        .await
        .expect("test operation succeeds");
    let replay = candidate_store
        .stage_bytes(&bytes, &context(Some("upload")))
        .await
        .expect("test operation succeeds");
    assert!(replay.already_present);
    assert_eq!(replay.candidate, staged.candidate);
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    assert_eq!(reopened.candidates(), vec![staged.candidate]);
    assert!(reopened.history().is_empty());
    assert!(
        !std::fs::read_to_string(path.join(STATE_FILE))
            .expect("test operation succeeds")
            .contains("\"current\"")
    );
}

#[test]
fn empty_signature_keys_allow_journal_but_never_unsigned_candidates() {
    let directory = temp();
    let candidate_store = CandidateStore::open(
        root(&directory),
        CandidateStoreLimits::default(),
        CandidateSignaturePolicy::require_trusted(Vec::new()),
        BundleCapabilities::default(),
    )
    .expect("test operation succeeds");
    let operation = candidate_store
        .begin_operation(&context(Some("drain")), AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&operation.receipt.operation_id, 1, "version-A")
        .expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .complete_committed(&operation.receipt.operation_id, 2, "version-A")
            .phase,
        OperationPhase::Committed
    );
    assert_eq!(
        candidate_store
            .check_signature_policy()
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.signature_policy"
    );
}

#[test]
fn idempotency_is_principal_scoped_and_uses_complete_fingerprint() {
    let directory = temp();
    let candidate_store = store(&root(&directory), CandidateStoreLimits::default());
    let ctx = context(Some("key"));
    let first = candidate_store
        .begin_operation(&ctx, AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&first.receipt.operation_id, 1, "A")
        .expect("test operation succeeds");
    let _ = candidate_store.complete_committed(&first.receipt.operation_id, 2, "A");
    let replay = candidate_store
        .begin_operation(&ctx, AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    assert!(replay.replayed);
    assert_eq!(replay.receipt.committed_revision, Some(2));
    let mut stale_different_request = ctx.clone();
    stale_different_request.if_match = Some("different-precondition".to_owned());
    assert_eq!(
        candidate_store
            .begin_operation(&stale_different_request, AuditAction::Drain, None, None)
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.idempotency_conflict"
    );
    assert_eq!(
        candidate_store
            .begin_operation(&ctx, AuditAction::ReloadSource, None, None)
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.idempotency_conflict"
    );
    let mut other_principal = ctx;
    other_principal.principal = "other-operator".to_owned();
    let independent = candidate_store
        .begin_operation(&other_principal, AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    assert!(!independent.replayed);
    assert_ne!(independent.receipt.operation_id, first.receipt.operation_id);
}

#[test]
fn state_faults_do_not_mutate_shared_state_before_durability() {
    for point in [FaultPoint::StateFsync, FaultPoint::StateRename] {
        let directory = temp();
        let path = root(&directory);
        let candidate_store = store(&path, CandidateStoreLimits::default());
        fault(&candidate_store, point);
        assert_eq!(
            candidate_store
                .begin_operation(&context(Some("key")), AuditAction::Drain, None, None)
                .expect_err("test rejects invalid operation")
                .code(),
            "candidate.injected_fault"
        );
        assert!(candidate_store.operations().is_empty());
        let first = candidate_store
            .begin_operation(&context(Some("key")), AuditAction::Drain, None, None)
            .expect("test operation succeeds");
        assert_eq!(first.receipt.operation_id, "op-0000000000000001");
    }
}

#[test]
fn post_publish_completion_failure_is_queryable_and_blocks_mutation() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let operation = candidate_store
        .begin_operation(
            &context(Some("activation")),
            AuditAction::ReloadSource,
            None,
            None,
        )
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&operation.receipt.operation_id, 7, "published-B")
        .expect("test operation succeeds");
    fault(&candidate_store, FaultPoint::Completion);
    // The real manager has already published B. It cannot return ordinary failure.
    let receipt =
        candidate_store.complete_committed(&operation.receipt.operation_id, 8, "published-B");
    assert_eq!(receipt.phase, OperationPhase::RecoveryRequired);
    assert_eq!(receipt.committed_revision, Some(8));
    assert_eq!(
        candidate_store.operation(&receipt.operation_id),
        Some(receipt.clone())
    );
    assert_eq!(
        candidate_store
            .begin_operation(&context(Some("other")), AuditAction::Drain, None, None)
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.recovery_required"
    );
    assert_eq!(
        candidate_store
            .begin_operation(
                &context(Some("activation")),
                AuditAction::ReloadSource,
                None,
                None
            )
            .expect("test operation succeeds")
            .receipt,
        receipt
    );
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    let recovered = reopened
        .operation(&operation.receipt.operation_id)
        .expect("test operation succeeds");
    assert_eq!(recovered.phase, OperationPhase::RecoveryRequired);
    assert_eq!(
        recovered.error_code.as_deref(),
        Some("candidate.injected_fault")
    );
    assert_eq!(
        reopened
            .ensure_mutations_allowed()
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.recovery_required"
    );
}

#[test]
fn audit_acknowledgment_is_durable_and_pending_completion_is_not_evictable() {
    let directory = temp();
    let path = root(&directory);
    let limits = CandidateStoreLimits {
        max_idempotency_entries: 1,
        ..CandidateStoreLimits::default()
    };
    let candidate_store = store(&path, limits.clone());
    let begin = candidate_store
        .begin_operation_audited(&context(Some("audited")), AuditAction::Drain, None, None)
        .expect("durable audit outbox accepted");
    assert!(begin.receipt.audit_pending);
    candidate_store
        .begin_intent(&begin.receipt.operation_id, 1, "A")
        .expect("intent");
    let committed = candidate_store.complete_committed(&begin.receipt.operation_id, 2, "A");
    assert_eq!(committed.phase, OperationPhase::Committed);
    assert!(committed.audit_pending);
    assert_eq!(
        candidate_store
            .begin_operation(&context(Some("other")), AuditAction::Drain, None, None)
            .expect_err("pending audit cannot be evicted as a finished receipt")
            .code(),
        "candidate.operation_capacity"
    );
    let completed = candidate_store
        .complete_audit(&begin.receipt.operation_id)
        .expect("sink acknowledgment is persisted");
    assert!(!completed.audit_pending);
    drop(candidate_store);
    let reopened = store(&path, limits);
    assert_eq!(
        reopened.operation(&begin.receipt.operation_id),
        Some(completed)
    );
    reopened
        .ensure_mutations_allowed()
        .expect("audit is complete");
    reopened
        .begin_operation(&context(Some("other")), AuditAction::Drain, None, None)
        .expect("fully acknowledged receipt can be evicted");
}

#[test]
fn failed_audit_ack_persistence_retains_known_committed_revision_on_restart() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let begin = candidate_store
        .begin_operation_audited(&context(None), AuditAction::ReloadSource, None, None)
        .expect("durable audit outbox accepted");
    candidate_store
        .begin_intent(&begin.receipt.operation_id, 7, "B")
        .expect("intent");
    let committed = candidate_store.complete_committed(&begin.receipt.operation_id, 8, "B");
    assert_eq!(committed.phase, OperationPhase::Committed);
    fault(&candidate_store, FaultPoint::StateRename);
    assert!(
        candidate_store
            .complete_audit(&begin.receipt.operation_id)
            .is_err()
    );
    assert!(
        candidate_store
            .operation(&begin.receipt.operation_id)
            .expect("receipt")
            .audit_pending
    );
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    let receipt = reopened
        .operation(&begin.receipt.operation_id)
        .expect("receipt");
    assert_eq!(receipt.phase, OperationPhase::RecoveryRequired);
    assert_eq!(receipt.committed_revision, Some(8));
    assert_eq!(receipt.previous_revision, Some(7));
    assert_eq!(
        receipt.error_code.as_deref(),
        Some("candidate.audit_unknown")
    );
    assert!(receipt.audit_pending);
    assert_eq!(
        reopened
            .ensure_mutations_allowed()
            .expect_err("audit is unresolved")
            .code(),
        "candidate.recovery_required"
    );
}

#[tokio::test]
async fn artifact_rename_failure_recovers_orphan_as_staged_not_as_published() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    fault(&candidate_store, FaultPoint::ArtifactRenamed);
    assert_eq!(
        candidate_store
            .stage_bytes(&bundle_bytes("A"), &context(Some("stage")))
            .await
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.injected_fault"
    );
    assert!(candidate_store.candidates().is_empty());
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    assert_eq!(reopened.candidates().len(), 1);
    assert_eq!(reopened.candidates()[0].status, CandidateStatus::Staged);
    assert!(reopened.history().is_empty());
    assert!(
        reopened
            .operations()
            .iter()
            .all(|receipt| receipt.phase == OperationPhase::Cancelled)
    );
}

#[tokio::test]
async fn artifact_registration_failure_closes_admission_before_reserved_capacity_is_reused() {
    for point in [
        FaultPoint::ArtifactDirectoryFsync,
        FaultPoint::ArtifactRenamed,
        FaultPoint::StateFsync,
        FaultPoint::StateRename,
        FaultPoint::DirectoryFsync,
    ] {
        let directory = temp();
        let path = root(&directory);
        let a = bundle_bytes("A");
        let b = bundle_bytes("B");
        let limits = CandidateStoreLimits {
            max_candidates: 1,
            max_total_bytes: 2 * a.len() as u64,
            max_candidate_bytes: a.len() as u64,
            ..CandidateStoreLimits::default()
        };
        let candidate_store = store(&path, limits.clone());
        let ctx = context(Some("stage-A"));
        let begin = candidate_store
            .begin_operation(&ctx, AuditAction::Stage, None, None)
            .expect("accepted receipt precedes registration fault");
        fault(&candidate_store, point);
        let error = candidate_store
            .stage_reader_for_operation(
                std::io::Cursor::new(a.clone()),
                ctx.clone(),
                CandidateWorkControl::default(),
                begin.receipt.operation_id,
            )
            .await
            .expect_err("registration fault leaves one renamed artifact");
        assert_eq!(error.code(), "candidate.injected_fault");
        assert!(candidate_store.candidates().is_empty());
        for (bytes, key) in [(a, "retry-A"), (b, "stage-B")] {
            assert_eq!(
                candidate_store
                    .stage_bytes(&bytes, &context(Some(key)))
                    .await
                    .expect_err("unindexed artifact keeps its reserved slot and byte budget")
                    .code(),
                "candidate.recovery_required"
            );
        }
        assert_eq!(
            std::fs::read_dir(path.join(CANDIDATE_DIRECTORY))
                .expect("artifact directory")
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "oxb"))
                .count(),
            1,
            "failed registration cannot accumulate invisible artifacts"
        );
        drop(candidate_store);
        let reopened = store(&path, limits);
        assert_eq!(reopened.candidates().len(), 1);
        assert_eq!(reopened.candidates()[0].status, CandidateStatus::Staged);
        assert!(reopened.history().is_empty());
        assert!(
            reopened
                .operations()
                .iter()
                .all(|receipt| receipt.phase == OperationPhase::Cancelled)
        );
    }
}

#[tokio::test]
async fn gc_persists_tombstone_before_deleting_artifact() {
    let directory = temp();
    let path = root(&directory);
    let a = bundle_bytes("A");
    let b = bundle_bytes("B");
    let limits = CandidateStoreLimits {
        max_candidates: 1,
        max_total_bytes: 2 * a.len() as u64 + 1,
        max_candidate_bytes: a.len() as u64 + 1,
        max_history_bytes: 1024 * 1024,
        ..CandidateStoreLimits::default()
    };
    let candidate_store = store(&path, limits.clone());
    let a = candidate_store
        .stage_bytes(&a, &context(Some("stage-A")))
        .await
        .expect("test operation succeeds");
    fault(&candidate_store, FaultPoint::GcIndexed);
    assert_eq!(
        candidate_store
            .stage_bytes(&b, &context(Some("stage-B")))
            .await
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.injected_fault"
    );
    assert!(candidate_store.candidate_path(a.candidate.digest).exists());
    assert!(candidate_store.candidates().is_empty());
    drop(candidate_store);
    let reopened = store(&path, limits);
    assert!(!reopened.candidate_path(a.candidate.digest).exists());
    assert!(reopened.candidates().is_empty());
}

#[test]
fn second_process_lock_and_replaced_directory_are_rejected() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let error = CandidateStore::open(
        &path,
        CandidateStoreLimits::default(),
        CandidateSignaturePolicy::allow_unsigned_for_development(),
        BundleCapabilities::default(),
    )
    .expect_err("test rejects invalid operation");
    assert_eq!(error.code(), "candidate.storage_locked");
    std::fs::rename(&path, path.with_file_name("retired-store")).expect("test operation succeeds");
    std::fs::create_dir(&path).expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .ensure_mutations_allowed()
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.storage_replaced"
    );
}

#[test]
fn unknown_objects_and_corrupt_artifacts_are_not_silently_removed() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let unexpected = path.join("candidates/unknown-file");
    std::fs::write(&unexpected, b"untrusted").expect("test operation succeeds");
    drop(candidate_store);
    let error = CandidateStore::open(
        &path,
        CandidateStoreLimits::default(),
        CandidateSignaturePolicy::allow_unsigned_for_development(),
        BundleCapabilities::default(),
    )
    .expect_err("test rejects invalid operation");
    assert_eq!(error.code(), "candidate.state");
    assert!(unexpected.exists());
}

#[test]
fn untrusted_writable_parent_and_final_symlink_are_rejected() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = temp();
    let parent = directory
        .path()
        .canonicalize()
        .expect("test operation succeeds")
        .join("untrusted");
    std::fs::create_dir(&parent).expect("test operation succeeds");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777))
        .expect("test operation succeeds");
    assert_eq!(
        CandidateStore::open(
            parent.join("store"),
            CandidateStoreLimits::default(),
            CandidateSignaturePolicy::allow_unsigned_for_development(),
            BundleCapabilities::default()
        )
        .expect_err("test rejects invalid operation")
        .code(),
        "candidate.storage_parent"
    );
    let target = directory
        .path()
        .canonicalize()
        .expect("test operation succeeds")
        .join("real");
    std::fs::create_dir(&target).expect("test operation succeeds");
    let link = directory
        .path()
        .canonicalize()
        .expect("test operation succeeds")
        .join("link");
    symlink(&target, &link).expect("test operation succeeds");
    assert_eq!(
        CandidateStore::open(
            &link,
            CandidateStoreLimits::default(),
            CandidateSignaturePolicy::allow_unsigned_for_development(),
            BundleCapabilities::default()
        )
        .expect_err("test rejects invalid operation")
        .code(),
        "candidate.state"
    );
}

#[test]
fn bounded_operations_never_evict_pending_or_recovery_receipts() {
    let directory = temp();
    let limits = CandidateStoreLimits {
        max_idempotency_entries: 1,
        ..CandidateStoreLimits::default()
    };
    let candidate_store = store(&root(&directory), limits);
    let first = candidate_store
        .begin_operation(&context(Some("first")), AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .begin_operation(&context(Some("second")), AuditAction::Drain, None, None)
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.operation_capacity"
    );
    candidate_store
        .finish_cancelled(&first.receipt.operation_id, "candidate.cancelled")
        .expect("test operation succeeds");
    candidate_store
        .begin_operation(&context(Some("second")), AuditAction::Drain, None, None)
        .expect("test operation succeeds");
    assert!(
        candidate_store
            .operation(&first.receipt.operation_id)
            .is_none()
    );
}

#[test]
fn read_queries_do_not_wait_for_durable_writer() {
    let directory = temp();
    let candidate_store = store(&root(&directory), CandidateStoreLimits::default());
    let operation = candidate_store
        .begin_operation(&context(None), AuditAction::Drain, None, None)
        .expect("begin");
    let writer = candidate_store.lock_writer();
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let reader_store = Arc::clone(&candidate_store);
    let id = operation.receipt.operation_id;
    let reader = std::thread::spawn(move || {
        assert!(reader_store.operation(&id).is_some());
        assert!(reader_store.history().is_empty());
        done_tx.send(()).expect("reader completes");
    });
    // The writer is deliberately held throughout the receipt/history reads.
    done_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("read-only view remains accessible during fsync");
    drop(writer);
    reader.join().expect("reader thread joins");
}

#[test]
fn directory_fsync_ambiguity_preserves_old_memory_and_blocks_new_mutation() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    fault(&candidate_store, FaultPoint::DirectoryFsync);
    assert!(
        candidate_store
            .begin_operation(&context(None), AuditAction::Drain, None, None)
            .is_err()
    );
    assert!(candidate_store.operations().is_empty());
    assert_eq!(
        candidate_store
            .ensure_mutations_allowed()
            .expect_err("ambiguity fails closed")
            .code(),
        "candidate.recovery_required"
    );
    drop(candidate_store);
    let reopened = store(&path, CandidateStoreLimits::default());
    // No publication intent was recorded; the accepted operation is cancelled.
    assert_eq!(reopened.operations()[0].phase, OperationPhase::Cancelled);
    reopened
        .ensure_mutations_allowed()
        .expect("explicit startup is safe after cancelled precommit intent");
}

#[tokio::test]
async fn adopted_upload_uses_one_storage_file_and_accounts_copy_peak() {
    let directory = temp();
    let path = root(&directory);
    let bytes = bundle_bytes("A");
    let candidate_store = store(
        &path,
        CandidateStoreLimits {
            max_candidate_bytes: bytes.len() as u64,
            max_total_bytes: bytes.len() as u64 * 2,
            ..CandidateStoreLimits::default()
        },
    );
    let begin = candidate_store
        .begin_operation(
            &context(Some("adopt")),
            AuditAction::Stage,
            None,
            Some(BundleDigest::of_bytes(&bytes)),
        )
        .expect("operation begins");
    candidate_store
        .mark_preparing(&begin.receipt.operation_id)
        .expect("preparing");
    let mut upload = candidate_store.create_upload_spool().expect("owned upload");
    let original_path = upload.path().to_owned();
    candidate_store
        .reserve_upload_capacity(bytes.len() as u64)
        .expect("exact copy peak fits");
    upload.write_all(&bytes).expect("write upload");
    let outcome = candidate_store
        .stage_spool_for_operation(
            upload,
            context(Some("adopt")),
            CandidateWorkControl::default(),
            begin.receipt.operation_id.clone(),
            None,
        )
        .await
        .expect("adopt stage succeeds");
    assert!(!original_path.exists());
    assert_eq!(
        std::fs::read_dir(candidate_store.upload_directory())
            .expect("candidate directory")
            .count(),
        1
    );
    assert_eq!(
        candidate_store
            .operation(&begin.receipt.operation_id)
            .expect("receipt")
            .phase,
        OperationPhase::Preparing
    );
    assert_eq!(
        candidate_store
            .finish_staged(&begin.receipt.operation_id, outcome.candidate.digest)
            .expect("finish")
            .phase,
        OperationPhase::Committed
    );
    assert_eq!(
        candidate_store
            .reserve_upload_capacity(bytes.len() as u64 + 1)
            .expect_err("byte limit")
            .code(),
        "candidate.limit"
    );
}

#[test]
fn journal_rejects_inconsistent_phase_and_retention_fields() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let operation = candidate_store
        .begin_operation(&context(None), AuditAction::Drain, None, None)
        .expect("begin");
    let bytes = std::fs::read(path.join(STATE_FILE)).expect("read journal");
    validate_candidate_journal_bytes(&bytes, &CandidateStoreLimits::default())
        .expect("real journal validates");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("journal JSON");
    value["operations"][&operation.receipt.operation_id]["receipt"]["commit_intent"] =
        serde_json::Value::Bool(true);
    assert!(
        validate_candidate_journal_bytes(
            &serde_json::to_vec(&value).expect("encode"),
            &CandidateStoreLimits::default()
        )
        .is_err()
    );
    value["operations"][&operation.receipt.operation_id]["receipt"]["commit_intent"] =
        serde_json::Value::Bool(false);
    value["operations"][&operation.receipt.operation_id]["receipt"]["expected_etag"] =
        serde_json::Value::String("invalid\ncontrol".to_owned());
    assert!(
        validate_candidate_journal_bytes(
            &serde_json::to_vec(&value).expect("encode"),
            &CandidateStoreLimits::default()
        )
        .is_err()
    );
}

#[tokio::test]
async fn legacy_current_is_discarded_while_verified_history_is_preserved() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(&path, CandidateStoreLimits::default());
    let staged = candidate_store
        .stage_bytes(&bundle_bytes("A"), &context(None))
        .await
        .expect("test operation succeeds");
    drop(candidate_store);
    let state = serde_json::json!({
        "schema_version": "oxidase.candidate-store/v1",
        "candidates": { staged.candidate.digest.to_string(): staged.candidate },
        "history": [{"digest":staged.candidate.digest,"config_version":"historical-A","bytes":staged.candidate.bytes,"sequence":3}],
        "current": {"digest":staged.candidate.digest,"config_version":"historical-A"},
        "idempotency": {"old-unscoped-key":{"action":"activate","digest":staged.candidate.digest,"previous_version":null,"new_version":"historical-A"}},
        "idempotency_order":["old-unscoped-key"], "next_sequence":4
    });
    std::fs::write(
        path.join(STATE_FILE),
        serde_json::to_vec(&state).expect("test operation succeeds"),
    )
    .expect("test operation succeeds");
    let reopened = store(&path, CandidateStoreLimits::default());
    assert_eq!(reopened.history()[0].config_version, "historical-A");
    assert_eq!(reopened.history()[0].committed_revision, 0);
    assert!(reopened.operations().is_empty());
    reopened
        .ensure_mutations_allowed()
        .expect("test operation succeeds");
    let fresh = reopened
        .begin_operation(
            &context(Some("old-unscoped-key")),
            AuditAction::ReloadSource,
            None,
            None,
        )
        .expect("test operation succeeds");
    assert!(!fresh.replayed);
    assert!(
        !std::fs::read_to_string(path.join(STATE_FILE))
            .expect("test operation succeeds")
            .contains("\"current\"")
    );
}

#[tokio::test]
async fn retained_history_only_records_completed_runtime_publication() {
    let directory = temp();
    let path = root(&directory);
    let candidate_store = store(
        &path,
        CandidateStoreLimits {
            max_history_snapshots: 1,
            ..CandidateStoreLimits::default()
        },
    );
    let a = candidate_store
        .stage_bytes(&bundle_bytes("A"), &context(None))
        .await
        .expect("test operation succeeds")
        .candidate
        .digest;
    let validation = candidate_store
        .begin_operation(&context(None), AuditAction::Validate, Some(a), None)
        .expect("test operation succeeds");
    candidate_store
        .mark_preparing(&validation.receipt.operation_id)
        .expect("test operation succeeds");
    candidate_store
        .complete_validation(&validation.receipt.operation_id, a)
        .expect("test operation succeeds");
    let first = candidate_store
        .begin_operation(&context(None), AuditAction::Activate, Some(a), None)
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&first.receipt.operation_id, 1, "A")
        .expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .complete_committed(&first.receipt.operation_id, 2, "A")
            .phase,
        OperationPhase::Committed
    );
    assert_eq!(candidate_store.history()[0].committed_revision, 2);
    // Source publication is recorded as an operation but never invented as a
    // recoverable Bundle artifact. It does not replace the last Bundle history.
    let source = candidate_store
        .begin_operation(&context(None), AuditAction::ReloadSource, None, None)
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&source.receipt.operation_id, 2, "source-B")
        .expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .complete_committed(&source.receipt.operation_id, 3, "source-B")
            .phase,
        OperationPhase::Committed
    );
    let second = candidate_store
        .begin_operation(&context(None), AuditAction::Activate, Some(a), None)
        .expect("test operation succeeds");
    candidate_store
        .begin_intent(&second.receipt.operation_id, 3, "A")
        .expect("test operation succeeds");
    assert_eq!(
        candidate_store
            .complete_committed(&second.receipt.operation_id, 4, "A")
            .phase,
        OperationPhase::Committed
    );
    assert_eq!(candidate_store.history().len(), 1);
    assert_eq!(candidate_store.history()[0].committed_revision, 4);
    assert_eq!(candidate_store.max_recorded_revision(), 4);
}

struct BlockedReader {
    entered: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
    bytes: std::io::Cursor<Vec<u8>>,
    first: bool,
}
impl Read for BlockedReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.first {
            self.first = false;
            self.entered.send(()).expect("test operation succeeds");
            self.release.recv().expect("test operation succeeds");
        }
        self.bytes.read(buffer)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_caller_does_not_release_running_worker_capacity() {
    let directory = temp();
    let candidate_store = store(&root(&directory), CandidateStoreLimits::default());
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let reader = BlockedReader {
        entered: entered_tx,
        release: release_rx,
        bytes: std::io::Cursor::new(bundle_bytes("A")),
        first: true,
    };
    let work = CandidateWorkControl::default();
    let worker_control = work.clone();
    let worker_store = Arc::clone(&candidate_store);
    let task = tokio::spawn(async move {
        worker_store
            .stage_reader_controlled(reader, context(None), worker_control)
            .await
    });
    tokio::task::spawn_blocking(move || entered_rx.recv().expect("test operation succeeds"))
        .await
        .expect("test operation succeeds");
    task.abort();
    let _ = task.await;
    work.cancel();
    assert_eq!(
        candidate_store
            .stage_bytes(&bundle_bytes("B"), &context(None))
            .await
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.busy"
    );
    // Read-only inspection is immediately available while the reader is blocked.
    assert!(candidate_store.candidates().is_empty());
    release_tx.send(()).expect("test operation succeeds");
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if candidate_store.preparation_admission.available_permits() == 1 {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert!(candidate_store.candidates().is_empty());
    candidate_store
        .stage_bytes(&bundle_bytes("B"), &context(None))
        .await
        .expect("test operation succeeds");
}

#[tokio::test]
async fn exact_candidate_byte_limit_and_cancelled_preparation() {
    let directory = temp();
    let bytes = bundle_bytes("A");
    let candidate_store = store(
        &root(&directory),
        CandidateStoreLimits {
            max_candidate_bytes: bytes.len() as u64,
            ..CandidateStoreLimits::default()
        },
    );
    candidate_store
        .stage_bytes(&bytes, &context(None))
        .await
        .expect("test operation succeeds");
    let mut oversized = bytes.clone();
    oversized.push(0);
    assert_eq!(
        candidate_store
            .stage_bytes(&oversized, &context(None))
            .await
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.limit"
    );
    let cancelled = CandidateWorkControl::default();
    cancelled.cancel();
    assert_eq!(
        candidate_store
            .stage_reader_controlled(std::io::Cursor::new(bytes), context(None), cancelled)
            .await
            .expect_err("test rejects invalid operation")
            .code(),
        "candidate.cancelled"
    );
}

/// Real child process rendezvous. The parent kills it while its store lock and
/// durable crash-window state are live; destructors cannot repair the state.
#[tokio::test]
async fn crash_child() {
    let Ok(path) = std::env::var("OXIDASE_CANDIDATE_CRASH_ROOT") else {
        return;
    };
    let mode = std::env::var("OXIDASE_CANDIDATE_CRASH_MODE").expect("test operation succeeds");
    let ready = PathBuf::from(
        std::env::var("OXIDASE_CANDIDATE_CRASH_READY").expect("test operation succeeds"),
    );
    let path = PathBuf::from(path);
    let limits = if mode == "gc" {
        CandidateStoreLimits {
            max_total_bytes: bundle_bytes("A").len() as u64 * 2 + 1,
            max_candidate_bytes: bundle_bytes("A").len() as u64 + 1,
            ..CandidateStoreLimits::default()
        }
    } else {
        CandidateStoreLimits::default()
    };
    let candidate_store = store(&path, limits);
    if mode == "intent" {
        let operation = candidate_store
            .begin_operation(
                &context(Some("crash")),
                AuditAction::ReloadSource,
                None,
                None,
            )
            .expect("test operation succeeds");
        candidate_store
            .begin_intent(&operation.receipt.operation_id, 1, "B")
            .expect("test operation succeeds");
    } else if mode == "completion" {
        let operation = candidate_store
            .begin_operation(
                &context(Some("crash")),
                AuditAction::ReloadSource,
                None,
                None,
            )
            .expect("test operation succeeds");
        candidate_store
            .begin_intent(&operation.receipt.operation_id, 1, "B")
            .expect("test operation succeeds");
        fault(&candidate_store, FaultPoint::Completion);
        assert_eq!(
            candidate_store
                .complete_committed(&operation.receipt.operation_id, 2, "B")
                .phase,
            OperationPhase::RecoveryRequired
        );
    } else if mode == "audit_completion" {
        let staged = candidate_store
            .stage_bytes(&bundle_bytes("A"), &context(Some("stage-A")))
            .await
            .expect("artifact staged");
        let digest = staged.candidate.digest;
        let validation = candidate_store
            .begin_operation(
                &context(Some("validate-A")),
                AuditAction::Validate,
                Some(digest),
                None,
            )
            .expect("validation accepted");
        candidate_store
            .mark_preparing(&validation.receipt.operation_id)
            .expect("validation preparing");
        candidate_store
            .complete_validation(&validation.receipt.operation_id, digest)
            .expect("artifact validated");
        let operation = candidate_store
            .begin_operation_audited(
                &context(Some("audited-A")),
                AuditAction::Activate,
                Some(digest),
                None,
            )
            .expect("durable completion audit outbox");
        candidate_store
            .begin_intent(&operation.receipt.operation_id, 1, "A")
            .expect("publication intent");
        let receipt = candidate_store.complete_committed(&operation.receipt.operation_id, 2, "A");
        assert_eq!(receipt.phase, OperationPhase::Committed);
        assert!(receipt.audit_pending);
        assert_eq!(candidate_store.history().len(), 1);
        // Deliberately no sink acknowledgment: the parent kills this process
        // after durable completion while its required audit is still owed.
    } else if mode == "artifact" {
        fault(&candidate_store, FaultPoint::ArtifactRenamed);
        assert!(
            candidate_store
                .stage_bytes(&bundle_bytes("A"), &context(Some("crash")))
                .await
                .is_err()
        );
    } else if mode == "upload" {
        let mut spool = tempfile::Builder::new()
            .prefix(UPLOAD_PREFIX)
            .suffix(".tmp")
            .tempfile_in(path.join(CANDIDATE_DIRECTORY))
            .expect("test operation succeeds");
        spool
            .write_all(b"incomplete-upload")
            .expect("test operation succeeds");
        spool.as_file().sync_all().expect("test operation succeeds");
        let (_, spool_path) = spool.keep().expect("test operation succeeds");
        assert!(spool_path.exists());
    } else if mode == "gc" {
        candidate_store
            .stage_bytes(&bundle_bytes("A"), &context(Some("A")))
            .await
            .expect("stage A");
        fault(&candidate_store, FaultPoint::GcIndexed);
        assert!(
            candidate_store
                .stage_bytes(&bundle_bytes("B"), &context(Some("B")))
                .await
                .is_err()
        );
    } else if matches!(mode.as_str(), "state_fsync" | "state_rename") {
        fault(
            &candidate_store,
            if mode == "state_fsync" {
                FaultPoint::StateFsync
            } else {
                FaultPoint::StateRename
            },
        );
        assert!(
            candidate_store
                .begin_operation(&context(None), AuditAction::Drain, None, None)
                .is_err()
        );
    } else {
        panic!("unexpected child mode");
    }
    std::fs::write(ready, b"ready").expect("test operation succeeds");
    loop {
        std::thread::park();
    }
}

#[test]
fn killed_process_restarts_with_explicit_recovery_or_staged_artifact() {
    for mode in [
        "intent",
        "completion",
        "audit_completion",
        "artifact",
        "upload",
        "gc",
        "state_fsync",
        "state_rename",
    ] {
        let directory = temp();
        let path = root(&directory);
        let ready = directory
            .path()
            .canonicalize()
            .expect("test operation succeeds")
            .join("child-ready");
        let mut child = Command::new(std::env::current_exe().expect("test operation succeeds"))
            .args(["--exact", "candidate::tests::crash_child", "--nocapture"])
            .env("OXIDASE_CANDIDATE_CRASH_ROOT", &path)
            .env("OXIDASE_CANDIDATE_CRASH_MODE", mode)
            .env("OXIDASE_CANDIDATE_CRASH_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test operation succeeds");
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        while !ready.exists() {
            if let Some(status) = child.try_wait().expect("test operation succeeds") {
                panic!("crash child exited early: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("child rendezvous deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        // Confirm a simultaneously alive second process cannot enter this root.
        assert_eq!(
            CandidateStore::open(
                &path,
                CandidateStoreLimits::default(),
                CandidateSignaturePolicy::allow_unsigned_for_development(),
                BundleCapabilities::default()
            )
            .expect_err("test rejects invalid operation")
            .code(),
            "candidate.storage_locked"
        );
        child.kill().expect("test operation succeeds");
        assert!(!child.wait().expect("test operation succeeds").success());
        let reopened = store(&path, CandidateStoreLimits::default());
        if matches!(mode, "intent" | "completion") {
            assert_eq!(
                reopened.operations()[0].phase,
                OperationPhase::RecoveryRequired
            );
            assert_eq!(
                reopened
                    .ensure_mutations_allowed()
                    .expect_err("test rejects invalid operation")
                    .code(),
                "candidate.recovery_required"
            );
        } else if mode == "audit_completion" {
            let receipts = reopened.operations();
            let receipt = receipts
                .iter()
                .find(|receipt| receipt.action == AuditAction::Activate)
                .expect("activation receipt");
            assert_eq!(receipt.phase, OperationPhase::RecoveryRequired);
            assert_eq!(receipt.committed_revision, Some(2));
            assert_eq!(receipt.config_version.as_deref(), Some("A"));
            assert_eq!(
                receipt.error_code.as_deref(),
                Some("candidate.audit_unknown")
            );
            assert!(receipt.audit_pending);
            assert_eq!(reopened.history().len(), 1);
            assert_eq!(
                reopened.history()[0].digest,
                receipt.target_digest.expect("activation digest")
            );
            assert_eq!(reopened.history()[0].committed_revision, 2);
            assert_eq!(reopened.candidates().len(), 1);
            assert_eq!(
                reopened
                    .ensure_mutations_allowed()
                    .expect_err("audit crash fails closed")
                    .code(),
                "candidate.recovery_required"
            );
        } else if mode == "artifact" {
            assert_eq!(reopened.candidates().len(), 1);
            assert_eq!(reopened.candidates()[0].status, CandidateStatus::Staged);
            assert!(reopened.history().is_empty());
            reopened
                .ensure_mutations_allowed()
                .expect("test operation succeeds");
        } else {
            assert_eq!(
                std::fs::read_dir(path.join(CANDIDATE_DIRECTORY))
                    .expect("test operation succeeds")
                    .count(),
                0
            );
            reopened
                .ensure_mutations_allowed()
                .expect("test operation succeeds");
        }
    }
}
