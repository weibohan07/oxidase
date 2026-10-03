# ADR 0012: Secure control plane and staged activation

- Status: Accepted; final PR5 qualification tracked separately
- Date: 2026-08-30
- Transaction/recovery decision updated: 2026-10-03

## Context

The initial PR5 WIP had an independent durable current value and completed storage
bookkeeping only after an awaited HTTP callback. Source reload, cancellation,
failed fsync, and process crashes could separate that record from the running
snapshot. The control plane requires one publication owner and a recoverable local
transaction using the existing data plane.

## Decision

The server manager arbitrates activate, rollback, source reload, watcher commits,
and drain. SnapshotStore atomically contains PublishedRuntime: snapshot, process
epoch/revision, config version, Source/Bundle origin, and serving state. CandidateStore
owns artifacts/history/receipts and never decides which program is running. Startup
explicitly chooses Source or Bundle, independently of storage history.

HTTP If-Match uses the process-specific revision ETag and is checked after prepare
and prebind at the final publication boundary. Watcher work captures its starting
revision and requires Source/Running authority at commit. Ordinary file events
cannot undo Bundle deployment or drain. Explicit source reload uses retained
SourceOrigin; Bundle-only startup cannot guess a YAML input. Stage/validation
conditions apply at manager acceptance and thereafter to immutable artifacts, not
to an unchanged runtime throughout their read-only preparation lifetime.

Admin transport, TLS/Trust, normalized bearer material, permissions, verification
keys, storage limits, and audit policy form one fixed startup bootstrap. Requests
cannot mix its old permissions/TLS with new data-plane token/limits. Data-only
Bundles may omit the already-bound Admin Secret; changed supplied bootstrap fields
fail with `admin.restart_required`. Online transport/credential/policy rebinding is
outside this alpha. Authentication uses bearer, verified mTLS, or both; explicitly
warned development-only `unsafe_none` is constrained. Permissions are independent,
static, and shared by authenticated identities, not a multi-user role platform.

Server and ctl share bearer-file parsing: 1..=8192 visible ASCII bytes, optionally
one final LF or CRLF. General Secrets remain raw bytes. Comparison is constant-time
and token debug material is redacted.

Each accepted mutation has a bounded durable receipt. Principal, Idempotency-Key,
action, target, expected ETag, and applicable body digest form an unambiguous SHA-256
fingerprint. Identical retained requests replay; changed requests conflict. Responses
distinguish committed and current revisions. Count-bounded replay is not exactly-once.

The publication protocol is:

```text
accepted -> preparing -> final condition/deadline/cancel check + prebind
-> durable intent -> runtime publication -> durable completion -> audit completion
```

The manager owns commit completion independently of HTTP lifetime. Before commit,
cooperative cancellation and a total deadline stop work. Hash/parse/copy/scan workers
hold bounded shared admission until they actually return. A dropped caller cannot
release the executing worker's permit early.

Durable updates build a next-state copy, write/sync a named temporary file, rename
and sync its parent, then publish an immutable ArcSwap view. The writer mutex
serializes persistence while receipt/history readers see the previous view.
Pre-publication failure keeps last-known-good. Post-publication completion/audit
failure exposes recovery-required with the known committed revision and closes
new protected mutation; it never claims the change was undone.

One canonical absolute process-owned private `0700` storage root has an exclusive
cross-process lock. Trusted parents, no-follow/nonblocking regular-file handles,
inode identity checks, and directory-replacement checks supplement digest names.
Unsafe objects, unknown files, and corrupt journals/artifacts fail explicitly.
Locking targets supported Unix deployment platforms, not cross-host consensus.

GC persists tombstones/index changes before deletion. Restart finishes that
protocol, cleans recognized temp files, and verifies renamed orphan artifacts before
importing them as staged. Every retained artifact is rechecked for digest, signature,
compatibility, and structure. Legacy WIP v1 history can be retained, but its current
value and unscoped replay keys cannot authorize runtime state or replay.

Interrupted work without intent becomes cancelled. Unfinished intent becomes
recovery-required: restart cannot prove whether its predecessor published. Explicit
startup selects its input while unresolved journal ambiguity closes new protected
mutation. Recovery retains evidence and does not silently replay uncertain work.
Uploads are safely adopted; peak capacity counts the upload and anonymous verified
copy. History and operation retention have independent limits. Rollback verifies
current external Secret/private-key/reference Assets, never old in-memory credentials.

Drain disables readiness before retiring data-plane listeners/connections. Live/Admin
remain available. Repeat drain has no new side effect, and watcher work cannot reopen
the runtime. Explicit activation/restart resumes through normal preparation.

Audit is bounded JSONL to stderr/stdout or a safe private file. Noise/read events
enqueue without waiting and count drops. Protected operations reserve accepted and
completion slots, acknowledging accepted delivery before side effects. Required
completion belongs to commit ownership. Post-commit failure marks recovery-required.
Accepted records persist an audit-pending marker atomically. Successful completion
delivery clears it through another durable state transition; restart with a pending
marker fails closed even if publication/completion had already succeeded. Storage-only
stage/validate results retain their digest/action without inventing a runtime revision.
Files are flushed/synced; process streams cannot certify collector durability.
Fields are controlled identities/action/digest/revisions/result/code, never bodies
or credentials.

## Consequences

This is a single-process local transaction system, with fixed Admin bootstrap,
count-bounded replay, Unix storage locking, current-file rollback validation, and
operator-assisted ambiguous-intent recovery. It preserves prepare/validate/commit/
drain and last-known-good. No distributed consensus, arbitrary remote execution,
multi-user roles, DNS discovery, OpenTelemetry, or packaging are added by PR5.

Workspace remains `0.3.0-alpha.1`; Gateway is `oxidase.dev/v1alpha1`, Oxista v1,
Bundle `oxidase.bundle/v1`, and Admin `oxidase.admin/v1`. Actual tests, crash/fuzz
campaigns, final PR checks, and post-merge main checks are recorded in
[the acceptance matrix](../verification/control-plane-acceptance.md).
