# Oxidase Admin API

Oxidase Admin API `oxidase.admin/v1` is an alpha, authenticated control-plane API.
It is independent from data-plane listeners and is disabled when the top-level
`admin` block is absent. It is not a stable public API yet.

This document describes the PR5 work in progress as of 2026-10-03. Hosted
validation has not been established for these changes. The release version remains
`0.3.0-alpha.1`.

## Transport and authentication

Supported transports are a Unix domain socket and HTTPS. HTTPS uses the same
prepared Certificate and Trust Store Resources as ingress TLS, but has an
independent listener lifecycle. Plain TCP is not supported.

Authentication modes are `bearer`, `mtls`, `bearer_and_mtls`, and the explicit
development-only `unsafe_none`. Bearer tokens are read from a file-backed Secret
Resource and compared in constant time. mTLS principals are derived only from a
successfully verified client certificate. Supplying identity-like headers never
creates a principal.

Clients send bearer credentials as:

```http
Authorization: Bearer <token>
```

Authentication failures return a safe `401`; authorization failures return `403`.
API responses and stored audit events do not echo credentials or certificate
details.

The bound Admin transport, authentication mode and Secret identity, permissions,
TLS configuration, Bundle verification keys, and candidate-store settings are
fixed at process startup. Restart the process after changing these settings;
source reload or Bundle activation does not reconcile the bound Admin listener.

## Media types and concurrency

JSON request bodies require `Content-Type: application/json`. Bundle uploads use
`Content-Type: application/vnd.oxidase.bundle`. Unsupported
media types return `415`, oversized requests return `413`, and malformed documents
return a JSON error response. Body reception and mutation-gate waits are bounded;
drain and source reload also have execution timeouts. Candidate validation,
staging work after upload, and activation do not yet have a total execution
deadline.

Admin mutation handlers share one gate. Source-watcher reload preparation uses a
separate gate; publication is serialized by the server manager. Every
state-changing request requires:

```http
If-Match: "<current-config-version>"
```

A stale precondition returns `412`. Repeating an already-completed idempotent
operation returns the current result rather than publishing a second generation.

## Read routes

| Method | Route | Permission | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health/live` | `read` | Process liveness |
| `GET` | `/health/ready` | `read` | Published-runtime readiness |
| `GET` | `/metrics` | `read` | Prometheus text exposition |
| `GET` | `/api/v1/clusters` | `read` | Bounded Cluster state |
| `GET` | `/api/v1/runtime` | `read` | Current config version and Resource/Listener counts |
| `GET` | `/api/v1/snapshots/current` | `read` | Current public snapshot identity |
| `GET` | `/api/v1/snapshots` | `read` | Current version as a one-entry list; retained history is not exposed |

Read responses omit Secret values, private-key paths, bearer tokens, uploaded
Bundle bytes, and unbounded request-derived values.

## Mutation routes

| Method | Route | Permission | Semantics |
| --- | --- | --- | --- |
| `POST` | `/api/v1/candidates` | `stage` | Atomically upload and stage a signed `.oxb` |
| `POST` | `/api/v1/candidates/{digest}/validate` | `stage` | Parse, verify, and prepare without publication |
| `POST` | `/api/v1/candidates/{digest}/activate` | `activate` | Re-prepare and atomically publish a validated candidate |
| `POST` | `/api/v1/snapshots/{digest}/rollback` | `rollback` | Re-prepare and publish a retained snapshot |
| `POST` | `/api/v1/drain` | `drain` | Stop new work and gracefully drain transports |
| `POST` | `/api/v1/reload-source` | `reload_source` | Request one normal source reload transaction |

Candidate identifiers are canonical Bundle content digests. A route segment is
parsed as a digest, never as a filesystem path. Uploaded candidates are bounded by
`admin.candidates`; retained snapshots are bounded by `admin.history`.

Deployment-relative references from staged Bundles resolve against the separately
compiled `admin.bundle_trust.deployment_root`; explicit absolute references are
also accepted. The deployment root is not the candidate/history storage directory
and is never derived from an HTTP filename or digest segment. It is not a general
filesystem sandbox for signed Bundle contents.

The default stage/activate/rollback policy requires a valid Ed25519 signature from
one of `admin.bundle_trust.verification_keys`. Signature, parse, compatibility, or
preparation failure never changes the published snapshot.

In this implementation, the mutation handler is created only when at least one of
`stage`, `activate`, or `rollback` is enabled. A configuration granting only
`drain` and/or `reload_source` compiles, but those requests currently return `503`
with `admin.control_unavailable`. Independent operation of these permissions is
unfinished.

## Diagnostics

Admin JSON error responses currently use a code-only envelope:

```json
{
  "schema_version": "oxidase.admin/v1",
  "code": "admin.precondition_failed"
}
```

This is separate from the CLI's `oxidase.diagnostics/v1` error output. Unknown
routes and unsupported methods may return plain text. API error bodies omit
filesystem paths beneath the Admin storage root, tokens, certificate material,
and uploaded bytes.

## Audit events

Some CandidateStore stage, validate, activate, and rollback paths record an event
in a bounded, process-local memory ring with:

```text
timestamp, request_id, principal, action, candidate_digest,
previous_version, new_version, result, error_code
```

The stored events omit authorization headers, request bodies, private certificate
data, source text, and Secret material. Early failures, idempotent paths, drain,
and source reload are not comprehensively covered. The ring evicts its oldest
event at capacity; it has no configured output sink, durable delivery, or drop
counter. A complete audit trail is not implemented. Admin request-derived values
do not become metrics labels.

## `oxidase ctl`

The companion client requires exactly one endpoint: `--unix SOCKET` or
`--https URL`. The HTTPS URL must be an origin with no credentials, path, query,
or fragment. Supply a bearer credential with `--token-file FILE`; mTLS requires
both `--client-certificate PEM` and `--client-key PEM`. `--ca-bundle PEM` adds
HTTPS trust roots.

```bash
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token status
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token clusters
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token stage gateway.oxb
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token validate <digest>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token activate <digest>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token rollback <digest>
oxidase ctl --unix /run/oxidase/admin.sock --token-file /etc/oxidase/admin.token drain

oxidase ctl --https https://admin.example:7590/ --ca-bundle operators-ca.pem \
  --client-certificate operator.pem --client-key operator.key status
```

Credentials are supplied through protected runtime inputs, not command output.
The client fetches the current config version before each mutation and sends
`If-Match`. Stage must be followed by validate before activation. These mutation
commands therefore also need `read` permission. Successful output is the Admin
JSON response, pretty-printed by default; CLI failures use human diagnostics or
the shared JSON diagnostics schema selected by the global `--diagnostic-format`.
