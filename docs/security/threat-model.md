# Threat model

This document describes the security boundary of the Oxidase v0.3 data plane and
the v0.4 hardening line. It is a design and verification input, not a claim that the
alpha is production-ready. A control is listed as implemented only when the current
runtime and regression tests exercise it.

## Security objectives

Oxidase aims to preserve these properties under malformed or adversarial input:

1. one accepted request has one unambiguous HTTP message boundary;
2. untrusted input cannot create a trusted Upgrade, filesystem path, identity, or
   control-plane capability;
3. request execution stays within one pinned, immutable `RuntimeSnapshot`;
4. failed preparation cannot change the published data plane or leave background
   tasks behind;
5. bodies and protocol frames remain streaming and cancellation-safe;
6. private material and high-cardinality request data do not enter diagnostics,
   logs, client errors, or metric labels; and
7. CPU, memory, connections, streams, retries, tasks, and mutable key spaces have
   explicit bounds or are documented residual risks.

Availability against volumetric denial of service is not guaranteed. Operating
system limits and upstream capacity remain part of the deployment boundary.

## Assets

- Service programs, Site and Cluster plans, and the currently published snapshot;
- private keys, future Secret Resources, trust roots, and operator credentials;
- request/response bodies, bindings, client TLS metadata, and upstream data;
- listener sockets, pooled upstream connections, permits, tasks, and file handles;
- configuration, Oxista source, candidate dependencies, and future bundle files;
- audit, access-log, tracing, metrics, and diagnostic outputs; and
- management actions such as prepare, activate, rollback, drain, and reload.

## Actors and trust boundaries

| Actor or boundary | Trust | Consequence |
| --- | --- | --- |
| Downstream client | Untrusted | Bytes, HTTP fields, TLS ClientHello, H2 frames, bodies, trailers, cancellation, and timing are hostile. |
| Upstream origin | Untrusted by default | Response framing, headers, trailers, redirects, resets, timing, and Upgrade responses require protocol validation. |
| Configuration author | Privileged but fallible | Source is strictly compiled; accepted fields must have runtime meaning. Configuration is not allowed to mint trusted transport capabilities. |
| Local source/certificate directory | Deployment trust boundary | Files can change between reloads. Each candidate is rediscovered, digested, parsed, and prepared before atomic publication. |
| Administrator | Privileged | The v0.3 read-only admin listener relies on network isolation. Authenticated staged control is a later v0.4 boundary. |
| Bundle producer | Not yet trusted by runtime | Portable bundles and signing do not exist in v0.3. YAML/source preparation remains authoritative. |
| DNS resolver | Operating-system/upstream dependency | v0.3 endpoints are static. Dynamic discovery must treat answers, TTLs, and rebinding as untrusted input. |
| Operating system | Trusted computing base | Filesystem permissions, scheduling, entropy, clocks, sockets, and resource limits are assumed to work as specified. |
| Metrics/log backend | External sink | Emitted labels and fields must be bounded and non-secret even if the sink is less trusted than the process. |

## Threat inventory and controls

### HTTP message ambiguity

**Threats:** request smuggling, response splitting, `Content-Length`/`Transfer-
Encoding` ambiguity, inconsistent duplicate lengths, duplicate or empty `Host`,
obsolete line folding, invalid chunk syntax, undeclared trailers, absolute-form or
authority-form confusion, and user-controlled hop-by-hop fields.

**Controls:** Hyper parses wire messages; source-level Header policy rejects
framing/hop-by-hop fields; runtime sanitization removes standard and
`Connection`-nominated fields; the response finalizer derives safe body/framing
metadata; HTTP/1 Upgrade requires a server-private capability; trailer guards
validate declarations and cross-protocol eligibility. The wire regression corpus
asserts rejection or one deterministic interpretation for ambiguous forms.

**Residual:** Hyper is part of the trusted parsing boundary. Oxidase does not act as
an arbitrary CONNECT proxy. External differential/smuggling suites may classify a
transparent reverse-proxy behavior differently, so raw findings require manual
triage against Oxidase's documented boundary.

### HTTP/2 and HPACK

**Threats:** malformed or duplicate pseudo-headers, invalid ordering, connection
headers, illegal `TE`, HPACK/header expansion, stream churn, rapid resets, DATA in
an invalid state, and GOAWAY/reload races.

**Controls:** Hyper validates the H2 state machine and HPACK; configured
`max_header_list_size` and `max_concurrent_streams` are applied by the connection
driver; protocol sanitization keeps only exact `TE: trailers`; every stream pins a
snapshot; retirement initiates graceful shutdown/GOAWAY and has a finite abort
deadline. Regression tests exercise malformed frames, settings boundaries, resets,
and concurrent drain.

**Residual:** v0.3 has no configurable per-peer stream-churn or request rate policy.
Listener-wide and per-IP governance belongs to the next v0.4 layer.

### TLS and SNI

**Threats:** handshake CPU exhaustion, malformed ClientHello/SNI, SNI-based metric
cardinality, incompatible ALPN, invalid chains or keys, certificate rotation races,
and disclosure of key material.

**Controls:** rustls safe TLS 1.2/1.3 defaults; a five-second default handshake
deadline; a fixed 128-handshake-per-listener gate; strict exact/single-label
wildcard SNI compilation; fixed-enum ALPN metrics; key/certificate proof during
prepare; same-bind transport-plan swap for new connections; last-known-good on a
failed candidate; current-time validity checks for every chain entry; adjacent
issuer-name and signature verification in leaf-first order; and redacted key
handling.

**Residual:** an expired or not-yet-valid certificate is a hard prepare failure,
because publication would immediately serve it to new connections. The current
source-reload path therefore cannot pre-stage a future certificate; a future staged
artifact may retain the reference, but activation must revalidate time. Client
authentication, trust-store Resources, and authenticated identity metadata are not
yet implemented.

### Upgrade, tunnels, gRPC, and trailers

**Threats:** source-forged `101`, ambiguous Upgrade tokens, unbounded tunnel
lifetime, half-close leaks, trailer smuggling, oversized trailers, lost
`grpc-status`, and treating a post-head failure as a retryable 502.

**Controls:** only validated HTTP/1 ingress and Proxy response paths can construct
the private Upgrade capability; both tokens must match; tunnels retain their pinned
snapshot and admission permit and are cancelled at drain timeout; DATA, trailers,
end-of-stream, and errors are preserved by body adapters; forbidden/undeclared
trailers fail the stream; a post-head error remains a stream error and cannot retry
or enter Fallback.

**Residual:** RFC 8441 H2 WebSocket, arbitrary CONNECT, WebTransport, and gRPC-Web
are intentionally unsupported. v0.3 bounds tunnel lifetime on retirement but does
not yet expose general connection/tunnel quotas.

### Retry and upstream health

**Threats:** retry amplification, replaying unsafe bodies, repeatedly selecting one
failed endpoint, health-check amplification, client cancellations poisoning health,
and leaked permits or supervisors.

**Controls:** retries are off by default; methods, causes/statuses, body replay,
attempts, and concurrent retry count are explicit and bounded; retries occur only
before the downstream head and prefer an untried endpoint; buffered replay is
explicit and size-bounded; active checks have independent timeouts and bounded body
discard; client cancellation is not passive failure; candidate preparation starts
no supervisor; owned permits and weak task ownership release on cancellation/drop.

### Files, Sites, and templates

**Threats:** traversal, percent/double-encoding tricks, symlink escape, exposing
source or backing assets, malicious YAML graph features, template injection,
unbounded rendering, and stale candidate dependency sets.

**Controls:** normalized origin-form paths, canonical-root checks, private/denied
matchers, symlink validation, strict YAML without aliases/anchors/tags/flow maps,
compile-time expressions/templates, typed lexical includes, shared render budgets,
HTML autoescape, content digests, and failed-candidate dependency tracking.

### Secrets and observability

**Threats:** key/token leakage through `Debug`, diagnostics, manifests, client
errors, labels, access logs, or high-cardinality tracing; response splitting through
dynamic Header values.

**Controls:** private keys use redacted prepared types; dynamic Header values are
parsed as `HeaderValue`; client errors are fixed safe envelopes; metrics labels use
configured names and fixed enums; Explain is not collected on production requests.

**Residual:** file Secret Resources, authenticated administration, access-log field
policy, and OpenTelemetry export are not implemented in v0.3.

### Snapshot, task, and resource leaks

**Threats:** publication races, old snapshots retained forever, listener plan swaps
mixing generations, health tasks from failed candidates, leaked connection/stream/
tunnel counters, retry permits, or file bodies.

**Controls:** immutable `Arc` snapshots, atomic store publication, request/stream
pinning, prepare-before-commit, listener prebind, transport-plan swap for future
accepts, weakly owned Cluster supervisors, graceful drain followed by abort, and
RAII body/tunnel/admission guards. Deterministic concurrency tests cover these pure
state transitions; loopback tests cover I/O cancellation.

## Security change requirements

A new accepted field or protocol transition must document its trust source, bounds,
snapshot/reload lifetime, cancellation path, observability cardinality, and safe
failure behavior. A confirmed P0/P1 found by conformance or fuzzing requires a
regression test and threat-model update before the responsible PR merges.
