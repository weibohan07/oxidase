# ADR 0012: Secure control plane and staged activation

- Status: Accepted design; PR5 implementation in progress
- Date: 2026-08-30
- Implementation notes updated: 2026-10-03

## Context

The historical management listener was an opt-in, read-only HTTP endpoint selected
by a CLI bind address. It had no deployable authentication policy and therefore
could not safely accept snapshots or mutate the live runtime. Oxidase v0.4 needs a
control plane without weakening the data-plane snapshot and last-known-good
invariants.

The control plane handles untrusted network input and untrusted Bundle bytes. It
must not expose Secret material, accept an unsigned candidate by default, write to
caller-selected paths, or run two activation transactions concurrently.

## Decision

### Compiler-owned Admin plan

The optional top-level `admin` block compiles into one immutable `AdminSpec`. The
import graph may contain at most one such block. Unknown fields are rejected at
the shared strict-YAML boundary.

```yaml
admin:
  listen:
    unix:
      path: /run/oxidase/admin.sock
      mode: "0660"

  auth:
    mode: bearer
    token_secret: admin-token

  storage:
    directory: /var/lib/oxidase/admin

  bundle_trust:
    deployment_root: /srv/oxidase/current
    verification_keys:
      - /etc/oxidase/operators/current.pub
      - /etc/oxidase/operators/next.pub

  permissions:
    read: true
    stage: true
    activate: true
    rollback: true
    drain: true
    reload_source: false

  candidates:
    max_count: 8
    max_bytes: 512MiB
    max_candidate_bytes: 256MiB

  history:
    max_snapshots: 5
    max_bytes: 1GiB
```

`listen` is exactly one of:

- `unix`, with an absolute socket path and an octal mode string; or
- `https`, with a bind address, Certificate Resource, and the existing strict
  TLS client-auth plan.

For HTTPS the compiler-owned shape is:

```yaml
listen:
  https:
    bind: 127.0.0.1:7590
    certificate: admin-cert
    client_auth:
      mode: required
      trust_store: operators
```

The compiled Admin plan carries transport, authentication, authorization, storage
limits, and history limits. The current server binds and prepares the Admin
transport, policy, TLS configuration, verification keys, and candidate store only
at startup; these do not follow subsequent request snapshots. Changes to those
settings require a process restart. Secret bytes remain exclusively
inside the prepared Resource registry. Portable Bundles contain the Admin policy,
Secret Resource identity, and external runtime path references, never token bytes,
private keys, or signing keys.

### Authentication

`auth.mode` is one of:

- `bearer`: requires `token_secret`;
- `mtls`: requires HTTPS and `client_auth.mode: required`;
- `bearer_and_mtls`: requires both conditions; or
- `unsafe_none`: explicit development-only escape hatch.

There is deliberately no `none` value. `unsafe_none` compiles only for a Unix
socket or loopback HTTPS without client authentication and emits a warning.
Deployments should not use it. Bearer comparison is constant-time and the token is
never logged. A verified client-certificate identity comes only from rustls
verification metadata, not a caller header.

### Authorization

Permissions are independent, deny by default except read access:

```text
read, stage, activate, rollback, drain, reload_source
```

Every route maps to one permission before handler execution. Transport
authentication is not authorization. A configuration with no enabled operation is
rejected as inert.

### Signed candidates and local storage

`storage.directory` is required and must be an absolute local path. The runtime opens or creates only descendants of
this local state root, rejects symlink/path-traversal escapes, writes a temporary
file, syncs it, and atomically renames it to a content-addressed name. Upload path
components never influence a filesystem path.
The mutable state directory and Bundle deployment root are intentionally not
source-watcher dependencies; candidate/history writes must not trigger reload
loops. Verification-key files are dependencies, but the bound CandidateStore
retains the keys loaded at startup; key rotation currently requires a restart.

`bundle_trust.verification_keys` contains external Ed25519 public-key paths. When
`stage`, `activate`, or `rollback` is allowed, at least one key is required. Thus
the normal control plane fails closed for unsigned Bundles. Read-only and drain/
source-reload deployments may omit Bundle keys. At most 32 rotation keys are
accepted and duplicate resolved paths are rejected. Private signing keys are
offline CLI inputs and are not server Resources.

The compiler accepts independent drain/source-reload permissions without Bundle
keys. The current server, however, constructs mutation handling only when
`stage`, `activate`, or `rollback` is enabled. A drain/source-reload-only deployment
returns `503 admin.control_unavailable` for those operations. Supporting that
configuration is unfinished.

`bundle_trust.deployment_root` is distinct from state storage: it resolves
external Asset, Secret, and private-key references inside a staged Bundle. Source
mode defaults it to the root Gateway document's directory. Portable plans encode
that choice explicitly; they never infer it from `storage.directory` or an upload
filename. Explicit absolute Bundle references are also accepted, so the deployment
root is not a general filesystem sandbox for a signed Bundle.

Candidate count, per-candidate bytes, total candidate bytes, history count, and
history bytes are independently bounded. Candidate and history eviction is
deterministic. Only completely uploaded, parsed, signature-verified candidates
can enter the staged set.

### Validate, activate, rollback

The intended mutating transaction order is:

```text
authenticate -> authorize -> body/content-type limits -> store candidate
-> verify signature and Bundle -> prepare -> If-Match check -> commit -> drain
```

Validation does not publish. Activation operations are serialized. `If-Match`
compares the currently published config version immediately before commit, so a
stale operator cannot overwrite a newer activation. Repeating an activation of
the already-current digest is idempotent.

History contains only successfully activated snapshot descriptors. The current
`GET /api/v1/snapshots` response exposes only the current config version, not the
retained CandidateStore history. Rollback is a
new prepare transaction, not resurrection of an old in-memory object. External
Secret, private-key, and reference-Asset paths are reopened and validated against
current files. Public certificate chains and Trust Store roots are reconstructed
and validated from the retained Bundle. A failed prepare leaves the current
snapshot unchanged.

### Audit and backpressure

The target is one structured audit outcome for each authenticated mutating request,
containing the request ID, bounded principal identity, action, candidate digest,
old/new versions, result, and stable error code, without bearer tokens, certificate
bytes, Bundle/source bodies, or Secret values.

The current implementation records only some CandidateStore stage, validate,
activate, and rollback paths in a bounded, process-local memory ring. Early
failures, idempotent paths, drain, and source reload are not comprehensively
covered. The ring evicts its oldest event at capacity and has no configured output
sink, durable delivery, or drop counter. Complete audit delivery remains work in
progress.

## Implementation boundary

PR5 is work in progress as of 2026-10-03 and has no established Hosted validation
for these changes. The release remains `0.3.0-alpha.1`; the API remains alpha.
Admin JSON errors currently use `oxidase.admin/v1` with a `code` field, separately
from the CLI's `oxidase.diagnostics/v1` envelope. Candidate validation, staging work
after upload, and activation have no total execution deadline yet.

## Consequences

- The old CLI-only read-only bind remains a compatibility surface during the
  alpha transition, but it is not a mutation-capable control plane.
- Server activation code can consume a single compiled type from YAML or a
  portable Bundle without interpreting source.
- Operators must provision local storage and verification keys before granting
  mutation permissions.
- Multi-principal role tables, remote object storage, distributed consensus, and
  an unauthenticated production mode remain out of scope.
