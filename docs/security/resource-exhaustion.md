# Resource-exhaustion model

Oxidase is streaming by default, but streaming alone does not bound all work. This
document inventories each resource, its current bound, its owner, and residual
v0.3 risk. Operating-system limits remain a required outer boundary.

| Resource | Current owner and bound | Release path | Residual risk |
| --- | --- | --- | --- |
| TLS handshakes | Listener-local semaphore, fixed at 128; configured timeout, default 5s | Permit drops after success/failure/timeout | Limit is not yet configurable or per-IP. |
| HTTP/1 request head | Hyper timer, default 30s; at most 100 fields, 64 KiB decoded head, and 8 KiB request target | Connection closes on timeout or parser/limit rejection | Limits are safe fixed defaults, not yet configurable or per-IP. |
| HTTP/2 streams | Hyper `max_concurrent_streams`, default 256 | Stream task completion/cancel | Rapid reset/request-rate policy is not yet per-peer. |
| HTTP/2 Header list | Hyper `max_header_list_size`, default 64 KiB | Per decoded head | HPACK dynamic-table behavior remains Hyper's boundary. |
| Cluster attempts | Cluster and endpoint semaphores | Owned permits cover response/tunnel or error | Listener admission is not yet coupled to Cluster admission. |
| Retry amplification | `max_attempts`, non-waiting retry semaphore, untried endpoint rule | Permit per retry | Operator can explicitly choose risky methods/statuses. |
| Retry body replay | Off by default or one explicit bounded buffer | Buffer drops with request | Buffering consumes configured memory before first attempt. |
| Health checks | One activated supervisor per prepared Cluster; finite interval/timeout; 64 KiB response discard | Weak ownership and removal cancellation | Very large endpoint sets can still create proportional periodic work. |
| Site/Proxy body | Streaming frames and idle timeout | Body drop cancels source/file/upstream | Listener-level body size and body-idle policies are not yet uniform. |
| Template render | Shared output, loop, include, expression, and time budgets | Per render | Complex but in-budget templates consume CPU by design. |
| Observe/metrics | Config-bounded names and fixed result enums | Process lifetime counters | Number of configured names determines series count. |
| WebSocket tunnel | One task, pinned snapshot, Cluster permit, drain deadline | EOF/error/cancel/drain | No general tunnel count or lifetime limit before listener retirement. |
| Snapshots | Current store plus requests/tasks pinning old `Arc`s | Last request/task drops | Long-lived streams/tunnels intentionally retain old state. |
| Candidate dependencies | Finite discovered filesystem set per attempted source tree | Replaced after next attempt | Very large Site trees require proportional metadata. |

## Required cancellation invariants

- A future dropped before a permit is acquired must not consume the request body.
- A future dropped after admission releases Cluster, endpoint, retry, connection,
  stream, and future ingress-governance counters exactly once.
- A response body drop cancels upstream/file work and records a fixed termination
  reason without allocating an error label.
- An Upgrade tunnel owns its permits and pinned snapshot until both copy directions
  end or drain aborts it.
- Failed candidate preparation starts no persistent listener, health, discovery, or
  exporter task.
- Replaced tasks must not own the last strong `Arc` to the Resource they supervise.

## Bounds required for new v0.4 components

Ingress limits, rate-limit key maps, Secret files, bundle tables/blobs, candidate
storage/history, admin request bodies, audit/export queues, DNS answer sets, access
log buffers, and telemetry batches must each define:

1. a numeric size/count/time bound with a safe default;
2. behavior at capacity, including fail-open versus fail-closed;
3. ownership and reload-state reuse identity;
4. cancellation and shutdown behavior;
5. bounded labels/attributes; and
6. deterministic tests for exact limit and limit-plus-one.

No field may be accepted until all six have executable semantics.

## Qualification

Unit and loopback tests prove individual counters and guards. Short macOS campaigns
exercise lifecycle composition but do not provide RSS/file-descriptor qualification.
A later v0.4 Linux workflow must record warm-up baseline, time series, peak, final,
and shutdown state for RSS, open descriptors, tasks, connections, streams, tunnels,
permits, old snapshots, supervisors, and discovery tasks. A bounded campaign is
evidence for that commit and duration only, not a long-term stability claim.
