#![no_main]

use libfuzzer_sys::fuzz_target;
use oxidase_runtime::{CandidateStoreLimits, validate_candidate_journal_bytes};

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 64 * 1024 {
        return;
    }
    let limits = CandidateStoreLimits {
        max_candidates: 8,
        max_total_bytes: 1024 * 1024,
        max_candidate_bytes: 512 * 1024,
        max_history_snapshots: 5,
        max_history_bytes: 1024 * 1024,
        max_idempotency_entries: 32,
        max_audit_events: 32,
    };
    let first = validate_candidate_journal_bytes(bytes, &limits);
    let second = validate_candidate_journal_bytes(bytes, &limits);
    assert_eq!(
        first.as_ref().map(|()| ()).map_err(|error| error.code()),
        second.as_ref().map(|()| ()).map_err(|error| error.code())
    );
});
