# Control-plane persistence and recovery

This protocol applies to the local alpha Admin API, not to distributed deployment
coordination. Workspace remains `0.3.0-alpha.1`.

## Authorities and durable order

`PublishedRuntime` in the server manager is the only current-runtime authority.
It atomically owns snapshot, process epoch/revision, Source/Bundle origin, and
serving state. Artifact history is evidence of completed activations, never proof
of the currently running program. A restarted process explicitly prepares its
selected Source or Bundle input and creates a new conditional epoch.

The candidate store persists bounded artifacts and operation receipts. Writers
build a next state, fsync a temporary state file, rename it, sync the parent, then
swap the immutable read view. A write mutex serializes this work; readonly queries
continue to see the prior complete view during a slow persistence step.

For runtime publication, the manager validates final CAS/cancellation/deadline
and prebinds, records intent durably, publishes, then records completion. The
manager, not the HTTP future, owns completion and required audit. Pre-commit errors
preserve last-known-good. An already-published result cannot be represented as an
ordinary failed operation whose target never ran.

Protected receipts atomically start with `audit_pending: true`. A terminal
operation remains protected from eviction until its JSONL completion is acknowledged
and `complete_audit` durably clears that marker. This includes stage/validate,
which commit storage changes without publishing a runtime revision. A process
killed between durable completion and audit acknowledgment cannot silently resume
mutation: restart retains the known result and reports `candidate.audit_unknown`.

| Interrupted boundary | Restart result |
| --- | --- |
| incomplete/complete upload before registration | recognized temp reclaimed; no publication inferred |
| artifact rename before index registration | digest/signature/structure-verified orphan imported as staged |
| GC index/tombstone persisted before deletion | resume deletion, then persist tombstone completion |
| accepted/preparing receipt with no publication intent | cancelled (`candidate.process_interrupted`) |
| durable intent without completion | recovery-required (`candidate.publication_unknown`) |
| durable committed completion | retained receipt/history, independently of explicit startup input |
| committed completion with unacknowledged durable audit marker | recovery-required; preserve known revision/history, close mutation |
| post-publication completion/audit persistence failure | known committed revision exposed where available; new mutation closed |
| failed pre-publication cancellation/failure record | recovery-required without an invented committed revision |
| corrupt/unknown/symlink storage object | explicit startup error; do not swallow or delete it |

A durable recovery marker survives restart when writing it succeeds. If disk
remains unavailable, the live process exposes a volatile receipt overlay while the
existing durable intent remains the restart evidence. Readers may still inspect
safe state and the data plane may still serve its pinned published snapshot. New
protected mutation fails closed.

## Storage contract

Use a canonical absolute private `0700` root owned by the runtime account and
trusted parent directories. Non-sticky group/world-writable parents are rejected.
The exclusive process lock remains held for the store lifetime. Regular files are
opened without following the final symlink, with nonblocking opens and inode/type/
size checks. Directory replacement invalidates the store rather than redirecting
future writes. These checks do not claim safety against a compromised OS or an
attacker already running with the runtime account's privileges.

Only identified `.oxidase-upload-*.tmp`, `.oxidase-state-*.tmp`, canonical digest
artifacts, and persisted GC tombstones belong to the recovery namespace. Unknown
files and corrupt content are preserved as errors. Upload capacity includes the
incoming file and verified anonymous copy; adoption avoids another full copy.
Counts, artifact bytes, history, operation records, and encoded state are bounded.
Pending/recovery receipts are never evicted to admit more operations.

Legacy WIP v1 stores can migrate verified candidates and activation history.
Their independent current is discarded, history revision zero means no runtime
revision was recorded, and old keys without principal/full fingerprints cannot
authorize idempotent replay.

## Operator recovery

1. Read the current endpoint and operation receipt while Admin is available.
   Distinguish the process's current input/revision from the uncertain predecessor
   operation. Do not automatically retry a recovery-required activation.
2. Stop the process before inspecting or replacing storage. Preserve the complete
   locked store, journal, artifacts, and audit logs as evidence. Never edit a live
   state file or delete the intent just to reopen admission.
3. Verify the chosen immutable Bundle offline with the configured public keys, or
   explicitly choose and check a Source input. Revalidate current Secret/private-key/
   reference-Asset inputs. A journal record alone cannot bypass those checks.
4. If the old intent cannot be reconciled from reliable evidence, retain the old
   root and restart the chosen input with a fresh private storage root. Updating
   fixed Admin bootstrap may require rebuilding/signing that deployment Bundle.
   The new process creates a new epoch. Old history remains evidence, not a falsely
   recovered activation in the new store.

There is no online journal-edit/reconciliation endpoint in this alpha. Ambiguous
intent recovery is an explicit restart/bootstrap procedure, not an automatic
exactly-once claim or restoration of old credential bytes. The acceptance matrix
records real killed-subprocess tests separately from normal Drop/reopen tests.
