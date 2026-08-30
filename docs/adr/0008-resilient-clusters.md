# ADR 0008: Resilient Cluster runtime

- Status: Accepted
- Date: 2026-08-30

## Context

Oxidase currently compiles a Cluster into an upstream protocol, a list of URLs,
and timeouts. Proxy selects URLs with a process-wide sequence and uses one of the
long-lived upstream pools. That preserves streaming and connection reuse, but it
does not provide endpoint identity, health, overload protection, safe retry, or
reload-stable runtime state.

These capabilities belong to the Resource and data-plane boundary. They must not
become Service types, enter the core Service algebra, or create a second Proxy
path. A failed candidate must not start a health task, and an old request must
retain the exact PreparedCluster that its pinned snapshot selected.

## Decision

### Compiled plan and endpoint identity

`oxidase-config` compiles every Cluster into a pure, immutable plan. A structured
endpoint has a unique configured name, canonical HTTP(S) URL, and weight in
`1..=1000`. The legacy URL-string shorthand remains supported and deterministically
lowers to `endpoint-0`, `endpoint-1`, and so on with weight 1. Generated shorthand
names change when source order changes and are alpha inspection identities, not
stable external identifiers.

An endpoint runtime identity is the tuple:

```text
Cluster ResourceId
endpoint name
canonical URL
upstream protocol
```

Endpoint URLs may contain a base path, but not credentials, a query, or a fragment.
Metrics and the conservative admin view use endpoint names, never URL paths or
queries.

### Preparation, activation, and reuse

`PreparedCluster` owns the immutable compiled plan plus prepared endpoints and
bounded mutable runtime state. `EndpointRuntimeState` contains health state,
consecutive health/passive results, the passive-ejection deadline, active request
count, selection counters, and fixed result counters. Mutable state is owned by the
PreparedCluster/endpoint and is not stored in a global HashMap.

Candidate preparation constructs plans and reuses compatible endpoint state, but
does not start persistent tasks. Publication activates a `ClusterSupervisor` and
its active health checks. A failed candidate therefore leaves no task. Reused
clusters do not duplicate supervisors. Removed clusters stop accepting new work;
old snapshots keep their PreparedCluster alive until the last pinned request is
released, then cancellation and weak ownership let every health task stop without
an Arc cycle.

When only load-balancing, health, retry, or concurrency policy changes, compatible
endpoint state is reused under the identity above and the new policy takes effect.
A URL or upstream-protocol change creates a new endpoint state and does not reuse
an incompatible connection/state identity.

### Load balancing

Three policies select only currently eligible endpoints:

- `round_robin` requires every endpoint weight to be 1;
- `weighted_round_robin` uses smooth deterministic weighted round robin without an
  array proportional to the sum of weights;
- `least_requests` minimizes `(active_requests + 1) / weight` by cross
  multiplication and uses source order as the deterministic tie-break.

Every selected attempt owns an active-request guard. Success, failure, timeout,
client cancellation, retry, and failed Upgrade all release it exactly once.

### Health and passive ejection

Endpoints begin `UnknownEligible`, so enabling active health checks does not create
a cold-start outage. Consecutive active failures move an endpoint to `Unhealthy`;
the configured number of consecutive successes moves it to `Healthy`. Unhealthy
endpoints remain health-check targets but are excluded from normal selection.

Active checks issue a direct request to the endpoint's configured origin-form path,
use the Cluster protocol pool, enforce their own timeout, never traverse the
Service graph, never retry, and drain at most a bounded response body. Results and
transitions use fixed, bounded metric labels.

Configured connection, response-head timeout, reset/refused-stream, upstream TLS,
and selected status failures contribute to passive failure state. Client
cancellation does not. Reaching the passive threshold produces
`PassivelyEjected` until `eject_for` expires. Expiry returns the endpoint to
eligible probation. A successful active check reaching `healthy_threshold` may
restore an ejected endpoint early. A successful normal response resets the
applicable passive failure streak.

No eligible endpoint yields `UpstreamUnavailable`. Exhausted Cluster or endpoint
concurrency yields `UpstreamOverloaded`. Both map to a safe 503 at the root and can
be matched explicitly by Recover.

### Concurrency protection

Cluster and per-endpoint semaphores enforce `max_in_flight` and
`max_in_flight_per_endpoint`. `queue_timeout: 0ms` is fail-fast; a positive value
waits no longer than that duration. No request body is consumed before both permits
are obtained. Cancellation-safe owned permits cover every attempt and Upgrade
handoff.

### Explicit replay and retry

`max_attempts` includes the first attempt and defaults to 1. A later attempt is
allowed only when all of the following remain true:

1. the method is explicitly configured;
2. the pre-head failure/status matches configured retry policy;
3. no downstream response head was sent;
4. the request body is empty, or explicit bounded buffering made it replayable;
5. attempt and concurrent-retry limits remain;
6. an eligible endpoint remains.

The next attempt prefers an eligible endpoint not yet tried. Once every eligible
endpoint has been tried, retry stops rather than cycling back to one endpoint.
Initial requests do not consume the retry semaphore. A retry uses a non-waiting
permit from `max_concurrent_retries`; if none is available, Oxidase returns the
current failure or response instead of adding a queue.

`request_body.mode: none` is the default: only an actually empty request is
replayable. `mode: buffer` collects once before the first upstream attempt and
enforces `max_bytes`; overflow returns 413 without an upstream attempt. Each retry
receives an independent body over the same bounded bytes. Buffering is never
implicit or unbounded. POST is never retryable by default; explicitly listing it
emits a structured warning that idempotency responsibility belongs to the
operator.

For a configured retry status, the data plane has not yet published the response
head. It drops the response body and tries the next endpoint. Once a response head
is sent, a later stream error remains a body/stream error and cannot become 502 or
trigger retry or Fallback.

### Observation and inspection

Cluster and endpoint labels are configuration-bounded names. Metrics cover
selection, fixed health result/state, passive ejection, retry attempt/exhaustion,
in-flight permits, overload, and absence of eligible endpoints. Paths, queries,
client addresses, URLs, and error strings are not labels.

`GET /api/v1/clusters` exposes a conservative read-only view: Cluster/endpoint
names, policy, health state, active requests, counters, last transition, and
remaining ejection time. It does not expose request data, credentials, certificate
material, or private-key data.

For a symbolic Proxy leaf, Explain emits a `cluster` plan with the protocol,
load-balancing policy, endpoint count, active/passive health thresholds, retry
contract, and concurrency limits. Its fixed `endpoint_selection` note says that
actual endpoint selection is runtime-state dependent. It deliberately emits no
selected endpoint: eligibility, ejection, and least-request counters do not exist
in symbolic execution.

Declarative tests can assert `cluster`, `cluster_protocol`, and `load_balance`.
They validate the compiled resource and immutable policy only; ordinary tests do
not predict a live endpoint or health state.

## Consequences

- Proxy remains one streaming Service path backed by long-lived protocol pools.
- Runtime liveness state has explicit ownership and can survive compatible reloads.
- Normal traffic is bounded before consuming a request body.
- Retrying a body is an explicit, bounded opt-in rather than an inferred property.
- Health tasks start only after publication and end with their PreparedCluster.
- String endpoints remain source compatible but structured endpoint names are
  preferred for stable metrics and state reuse.

## Rejected alternatives

- A global endpoint-state registry obscures snapshot ownership and leaks removed
  resource state.
- Starting health checks during candidate preparation leaks work from failed
  reloads.
- Expanding integer weights into a selection array permits pathological memory
  use.
- Retrying after a response head or partially streamed body cannot preserve HTTP
  framing or replay correctness.
- Default request-body buffering violates Oxidase's streaming contract.
- Treating client cancellation as endpoint failure causes healthy endpoints to be
  ejected by downstream behavior.

## Current non-goals

Dynamic DNS/service discovery, outlier consensus across processes, distributed
state, circuit breaking beyond the stated limits/ejection model, hedging, arbitrary
retry scripting, cache Services, and a writable Cluster admin API remain out of
scope.
