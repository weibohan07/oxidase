# Oxidase Admin API

`oxidase.admin/v1` is an alpha local control plane, independent of data-plane
Listeners. The workspace remains `0.3.0-alpha.1`. Actual qualification is tracked
in [the acceptance matrix](verification/control-plane-acceptance.md); local checks
and configured workflows do not establish a completed Hosted gate.

## Bootstrap and authentication

The optional top-level `admin` block selects a Unix socket or HTTPS. Modes are
`bearer`, rustls-verified `mtls`, `bearer_and_mtls`, and explicitly warned
development-only `unsafe_none`. All authenticated principals share one static
permission set; this is not a multi-user role platform.

Transport, TLS/Trust, normalized bearer material, permissions, verification keys,
storage/upload bounds, and audit policy form one coherent process-start bootstrap.
Requests do not combine these with a newer data-plane snapshot. A data-only Bundle
without the Admin Secret cannot remove prepared authentication. A candidate that
supplies changed bootstrap policy is rejected with `admin.restart_required`.
Credential, permission, and transport changes require restart in this alpha.

The server and ctl share the bearer-file grammar: 1..=8192 visible ASCII token
bytes, optionally followed by exactly one LF or CRLF. Empty values, embedded
whitespace/controls, multiple final newlines, trailing spaces, and oversized tokens
fail. General Secrets still preserve raw bytes. Comparison is constant-time;
token debug output is redacted. Duplicate Authorization fields are rejected.

Unix sockets use trusted owned directories, reject symlinks and unsafe permission
boundaries, detect live sockets before removing stale ones, and clean up only the
bound inode. Candidate storage uses a canonical absolute process-owned `0700`
directory and trusted parents. Group/world-writable non-sticky parents are
rejected. An exclusive cross-process lock rejects a second store owner. Directory
replacement fails closed rather than writing into the replacement path.

## Identity and conditions

The manager owns one atomic `PublishedRuntime`: request snapshot, process epoch,
monotonic process revision, config version, Source/Bundle origin, and
`running`/`draining`/`drained` serving state. Bundle digest is artifact identity;
config version is prepared-content identity. HTTP conditions use the runtime ETag:

```http
If-Match: "runtime-<process-epoch>-<revision>"
```

Read it from the current endpoint's ETag or JSON `etag`. Restart creates a new
epoch; an old process's token cannot authorize a new mutation. Historical storage
never claims which program is actually running.

| Operation | Condition | Effect |
| --- | --- | --- |
| stage | runtime condition at manager acceptance; immutable artifact thereafter | registers artifact, no runtime publication |
| validate | runtime condition at manager acceptance; exact artifact verified/prepared | records validation, no runtime publication |
| activate / rollback | final condition after prepare/prebind, before commit | publishes Bundle runtime |
| reload-source | same final commit condition | publishes explicit Source runtime |
| watcher | captured revision and Source/Running authority at commit | stale work rejected |
| drain | final condition before serving-state transition | disables readiness and retires traffic |

Absent If-Match is `428`; malformed/repeated conditions are rejected; stale
conditions are `412`. Stage/validate do not promise that the runtime remains
unchanged for their entire read/preparation lifetime. Ordinary watcher events
cannot reclaim Source authority after Bundle activation or reopen a drained runtime.
`reload-source` uses the retained explicit Source startup path; Bundle-only startup
returns `admin.source_unavailable` instead of guessing a YAML path.

DNS generation is a separate operational Cluster identity, not another runtime
revision. Authorized discovery refresh never changes ETag, RuntimeOrigin, serving
state, ConfigVersion, permissions, CandidateStore history, an operation receipt or
durable recovery fencing. A conditional activation using an unchanged runtime
ETag does not become stale merely because an A/AAAA or SRV answer changed.

The manager retires replaced/removed discovery owners at normal publication and
fences their late callbacks. Old issued streams keep their completion resources,
not permission to publish an old resolver result. Drain retires owners even when
old requests still pin a snapshot; a completed query cannot reopen a Listener.
Explicit permitted activation, rollback or Source reload can resume traffic via
normal prepare/commit and a fresh cold owner, preserving their existing final CAS.
If last-known-good is still Running after a post-commit persistence/audit failure,
its authorized operational refresh may continue, but cannot clear recovery-required
or restore protected mutation admission. Restart never trusts serialized live DNS
answers.

## Routes and permissions

| Method | Route | Permission |
| --- | --- | --- |
| GET / HEAD | `/health/live`, `/health/ready`, `/metrics` | read |
| GET / HEAD | `/api/v1/runtime`, `/api/v1/clusters` | read |
| GET / HEAD | `/api/v1/snapshots/current`, `/api/v1/snapshots` | read |
| GET / HEAD | `/api/v1/operations/{operation_id}` | read |
| POST | `/api/v1/candidates` | stage |
| POST | `/api/v1/candidates/{digest}/validate` | stage |
| POST | `/api/v1/candidates/{digest}/activate` | activate |
| POST | `/api/v1/snapshots/{digest}/rollback` | rollback |
| POST | `/api/v1/drain` | drain |
| POST | `/api/v1/reload-source` | reload_source |

Permissions are independent. Drain-only/source-reload-only bootstrap does not
require Bundle verification keys. A caller without read can supply explicit
If-Match to invoke its permitted mutation. Artifact operations require trusted
Ed25519 signatures. Digests are validated identities, never arbitrary paths.

Stage requires `application/vnd.oxidase.bundle`. Other mutations use
`application/json` with empty object or empty body. Unexpected fields, trailers,
unsupported media types, and over-limit bodies fail. `/api/v1/*` errors use a JSON
envelope with `schema_version` and `code`; preparation diagnostics are projected to
safe source/line/field labels. Private paths, bodies, tokens, and certificate text
are omitted. Unknown routes are JSON `404`; `405` includes Allow. Health/metrics
retain their text protocols.

Snapshots list actual successful retained Bundle activations separately from the
live current description. History includes digest, config version, committed
revision, operation ID, and bytes. Source-only startup is not invented as a rollback
artifact. Rollback verifies and prepares again, validating current external Secret,
private-key, and reference-Asset files; it cannot resurrect old credential bytes.
`admin.bundle_trust.deployment_root` resolves relative references and is not a
filesystem sandbox for trusted signed Bundles' explicit absolute references.

`GET /api/v1/clusters` adds bounded discovery policy and observed status, including
resolution state, generation, eligibility, expirations/next refresh and fixed
error codes. This uses the same authenticated `read` permission; it is not a
DNS-cache write interface. Dynamic IPs, SRV targets, generation and error messages
are not metric labels. Explain and Bundle inspection show compiled policy and
explicitly leave actual endpoint choice to runtime state. None of these views
becomes a second publication authority.

## Receipts, execution, and recovery

Durable receipts have phases `accepted`, `preparing`, `committed`, `failed`,
`cancelled`, and `recovery_required`. Query the operation ID after a lost response.
Its committed revision is separate from `current_revision`/`current_etag`; replaying
an old success does not claim it is current.

Idempotency is scoped to principal, key, and a SHA-256 fingerprint of action,
target, If-Match, and applicable body digest. Changed requests conflict with `409`.
Proven replay can precede current CAS. Different principals do not share receipts.
Retention is count-bounded (1024 records by default); only finished non-recovery
records can be evicted. This is a replay window, not an exactly-once guarantee.

A total 60-second server deadline covers admission, upload, and preparation.
Blocking hash/parse/copy workers check cooperative cancellation and own admission
until they actually return. Source and Bundle preparation share bounded admission.
Source reads and Asset hashes checkpoint at most every 64 KiB. Gateway documents
and Oxista text sources are bounded at 16 MiB each; Gateway import depth/count are
bounded at 128/4096. Ordinary Asset bytes are streamed, not collected into that
text budget. Invalid regular-file replacements and oversized sources fail safely.
Read-only immutable views and data-plane requests remain available during slow
work. Pre-commit cancellation prevents publication; after commit starts the manager
finishes accounting/audit independently of the HTTP future. A timeout may return
`202` with an operation ID for later inspection.

Publication records a durable intent before the runtime changes and durable
completion afterward. Pre-publication failures preserve last-known-good.
Post-publication persistence/audit failure exposes recovery-required with the known
committed revision and stops new protected mutation. It cannot imply publication
was undone. Restart verifies retained artifacts. Work without intent becomes
cancelled; unfinished intents become recovery-required because restart cannot
prove whether publication happened. Valid renamed orphans recover as staged.
Recognized temp files are reclaimed, unknown/unsafe objects fail explicitly, and GC
persists tombstones/index changes before deletion. Legacy WIP v1 history can migrate,
but its independent current and unscoped idempotency records are discarded. See
[the recovery protocol](control-plane-recovery.md).

Uploads are safely adopted instead of copied again. Peak capacity includes the
upload and anonymous verified copy alongside registered artifacts. History, count,
receipt, and parser limits are separate. Per-candidate maximum is a ceiling, not a
promise that it fits alongside protected history. Drain makes readiness false
before retirement; liveness/Admin remain available. Explicit activation or restart
resumes serving through normal preparation.

## Audit

```yaml
admin:
  audit:
    destination: file
    file: /var/log/oxidase/admin-audit.jsonl
    queue_capacity: 128
```

Destinations are stdout, stderr (default), or a safe local file. Queue capacity is
2..=4096 messages. Noise/read events enqueue nonblocking and count drops. Protected
mutations reserve accepted/completion slots and acknowledge the accepted record
before side effects. Safe-file protected writes flush/sync; process streams cannot
certify a downstream collector's durability. Events contain controlled identities,
operation/action/digest/revisions/result/code, never Headers, bodies, or credentials.
Pre-commit audit failure rejects mutation; post-commit failure preserves its known
result and closes admission. Metrics expose delivery, failure, drops, and health.
The journal retains `audit_pending` until the completion acknowledgment is itself
recorded durably. Restart with an uncleared marker reports recovery-required,
including storage-only stage/validate outcomes without a fake runtime revision.
Operators manage collector durability, file capacity, and rotation/restart.

## `oxidase ctl`

Use exactly one `--unix SOCKET` or `--https ORIGIN`. HTTPS origins cannot include
credentials, a path, query, or fragment. Protected inputs are `--token-file`,
`--ca-bundle`, and paired `--client-certificate`/`--client-key` as applicable.

```bash
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token status
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token snapshots
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token stage gateway.oxb
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token validate <digest>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token \
  --if-match '"runtime-<epoch>-<revision>"' --idempotency-key deploy-A \
  --connect-timeout 5s --timeout 60s activate <digest>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token \
  operation status <operation-id>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token reload-source
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token drain
```

`history` aliases `snapshots`. Explicit If-Match omits preliminary read, allowing
restricted mutations without read permission. Otherwise ctl first reads the ETag;
it never refreshes a `412` and blindly retries. Connect/TLS and total deadlines,
bounded regular-file/response reads, and HTTP driver cancellation apply on every
exit path.
System trust-store enumeration and bounded CA/client-identity parsing run in a
single admitted blocking worker before TCP connection. The total timeout covers
waiting and preparation; the connection timeout covers TCP and TLS afterwards.
Cancellation cannot release that worker's admission until the actual OS work
returns, even though a native trust-store call itself cannot be forcibly stopped.
