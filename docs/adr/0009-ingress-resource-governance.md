# ADR 0009: ingress resource governance

Status: accepted for `0.4.0-alpha.1`

## Context

Oxidase already bounds several protocol-specific resources, but v0.3 does not
provide one explicit ownership model for accepted connections, peer-address state,
request-body bytes, concurrent Service executions, or keyed request rates. These
limits must preserve streaming bodies, transactional Fallback, per-stream snapshot
pinning, retained listener sockets, and trusted Upgrade lifetimes.

## Decision

### Listener ownership

Connection admission is owned by the active listener socket, independently of a
`RuntimeSnapshot`. A retained socket retains one bounded admission state while every
new accept reads the current immutable listener plan. Rebinding creates a new state.
The state counts all accepted transports, including TLS handshakes, and maintains a
capacity-bounded map keyed only by the normalized kernel peer IP. IPv4-mapped IPv6
addresses use their IPv4 identity. Client forwarding headers never affect admission.

Every accepted connection holds an RAII permit through handshake, HTTP connection,
and any trusted Upgrade tunnel. Idle per-IP entries are evicted after they have no
active connections. At map capacity, a previously unseen peer is rejected closed;
the data plane never grows an unbounded peer map.

HTTP/1 applies listener header-count and decoded-header-byte limits in addition to
the parser's bounded allocation. HTTP/2 applies the smaller of the listener header
budget and its protocol-specific header-list budget. The request-count limit is per
HTTP/1 connection and per accepted HTTP/2 stream; reaching it begins graceful
retirement (connection close for H1 and GOAWAY for H2) rather than creating an
unbounded stream task. Connection and request/response body idle deadlines are
driver timers, not elapsed-wall-time checks performed after work has already
completed.

Idle peer identities are tracked by a bounded ordered expiry index, so a rotating
unknown-peer flood does not force a full map scan on every rejected accept. Completed
connection tasks are reaped between accepts. The pre-control-plane admin listener
uses a fixed 256-connection safety cap as well.

### Request body limits

`request_body_limit` is a lexical wrapper. Executor recursion carries the effective
limit as an immutable value, using the minimum for nested wrappers. The limit is not
stored in the one-shot body and therefore disappears automatically if a child is
cancelled, fails, or declines; a Fallback sibling cannot inherit it.

A trusted `Content-Length` above the limit returns 413 before child execution.
Unknown-length HTTP/1 chunked and HTTP/2 bodies are counted per DATA frame in the
existing streaming adapter. Trailers do not count. A pre-response-head overflow
returns 413; after a response head has escaped, the request/upstream stream is
cancelled and the connection records a body error because the status can no longer
be rewritten safely. Explicit retry buffering uses the smaller of its own bound and
the active request-body bound.
An end-of-stream `Incoming` takes a direct empty path and does not allocate a body
timer.

### Concurrent Service executions

`concurrency_limit` state is keyed by compiler-owned `ServiceId` inside the prepared
snapshot governance registry. Acquisition occurs before body consumption. Active
permits are cancellation-safe and transfer to the handled response body or trusted
Upgrade tunnel, so streaming completion, error, cancellation, drain, and tunnel
termination all release exactly once. Declined, Failed, timeout, and configured
rejection paths release immediately.

The waiting queue is bounded to `max_in_flight`; `queue_timeout: 0ms` is fail-fast.
This fixed rule avoids another DSL field while ensuring that a configured wrapper
cannot create an unbounded waiter set. Compatible reloads reuse the active counter,
and a changed limit applies to subsequent admission without forgetting requests
that started under a pinned old snapshot.

### Keyed rate limits

`rate_limit` uses a monotonic fixed-point token bucket. The only v1alpha1 key sources
are the verified peer IP and a named lexical binding. Binding keys accept bounded
scalar text of at most 256 bytes; missing, composite, or oversized values fail
closed. Actual key values never enter metrics or logs.

Each limiter owns a capacity-bounded map and removes entries idle for `idle_ttl`
through a bounded ordered expiry index before admitting a new key. If the map is
full and no idle key is eligible, the new key fails closed with 429. `Retry-After` is
the ceiling of the monotonic refill wait, with a minimum of one second. State is
reused only when key source, rate, burst, capacity, and idle TTL are identical; a
policy change starts a new bounded bucket generation.

### Explain, tests, and metrics

Explain reports each protection wrapper and its static policy but never emits the
runtime peer or binding key. Runtime metrics use only configured limiter names and
fixed result labels. `request_body_limit=evaluated` means the lexical ceiling was
installed, not that an unknown-length upload already completed; later failures use
the response/body lifecycle telemetry. All configured-name registries are capped
across reload churn. Declarative single-request tests can observe 413/429 and normal
pass-through; contention, cancellation, H2, Upgrade, and eviction semantics remain
wire/state-machine integration tests.

## Consequences

- No new global mutable map or alternate data plane is introduced.
- Body streaming remains the default; only existing explicit retry buffering may
  collect a bounded request body.
- Retained listener sockets and snapshot-scoped Service governance have distinct
  reuse rules.
- A response-body or tunnel lifecycle guard is now part of the server-local body
  plan, but Hyper types remain outside `oxidase-core` and the source compiler.
- This ADR does not define trusted proxy headers, distributed rate limits, shared
  cross-process state, or a configurable client-identity provider.
