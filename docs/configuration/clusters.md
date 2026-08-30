# Resilient Clusters

A Cluster is a shared Resource selected by a `Proxy` Service. Compilation produces
an immutable plan; publication activates bounded endpoint runtime state and active
health checks. Cluster state does not enter the Service algebra and failed
candidates never leave health tasks behind.

## Complete example

```yaml
resources:
  clusters:
    api:
      protocol: h2
      endpoints:
        - name: api-a
          url: https://api-a.example.test:8443
          weight: 2
        - name: api-b
          url: https://api-b.example.test:8443
          weight: 1
      load_balance:
        policy: weighted_round_robin
      health:
        active:
          path: /healthz
          interval: 5s
          timeout: 1s
          healthy_statuses: ["200-299"]
          healthy_threshold: 2
          unhealthy_threshold: 3
        passive:
          consecutive_failures: 3
          eject_for: 30s
      retry:
        max_attempts: 2
        methods: [GET, HEAD]
        retry_on: [connect_failure, response_header_timeout, refused_stream]
        statuses: [502, 503, 504]
        request_body:
          mode: none
          max_bytes: 64KiB
        max_concurrent_retries: 32
      limits:
        max_in_flight: 1024
        max_in_flight_per_endpoint: 256
        queue_timeout: 0ms
      connect_timeout: 5s
      response_timeout: 30s
```

Every accepted field above has runtime meaning. Unknown fields and unsupported
values fail compilation with a source diagnostic.

## Endpoints and protocol

Structured endpoint names are unique within a Cluster and contain 1–128 ASCII
letters, digits, dots, underscores, or hyphens. Weights are `1..=1000`. Endpoint
URLs are HTTP(S) origins with an optional base path, but no credentials, query, or
fragment. The legacy shorthand remains valid:

```yaml
endpoints:
  - http://127.0.0.1:3000
```

It lowers to `endpoint-0`, `endpoint-1`, and so on with weight 1. These generated
names change with source order and are not stable external identifiers. Prefer
configured names for stable metrics and reload reuse.

`protocol` is one of:

- `auto`: HTTPS negotiates H2 or H1 with ALPN; cleartext uses HTTP/1.1;
- `http1`: forces HTTP/1.1;
- `h2`: requires H2 over TLS and uses H2 prior knowledge for cleartext upstreams.

Oxidase owns long-lived pools for these policies; it does not create one client per
request.

## Load balancing

- `round_robin` uses deterministic atomic rotation and requires every weight to be
  1;
- `weighted_round_robin` uses smooth weighted rotation without expanding weights
  into a large array;
- `least_requests` minimizes `(active_requests + 1) / weight` with source order as
  the deterministic tie-break.

Only eligible endpoints participate. Active-request guards are released on normal
completion, errors, timeouts, cancellation, retries, and failed Upgrade handoff.

## Health state

Endpoints begin `UnknownEligible`, so enabling active checks does not cause a
cold-start outage. Consecutive active successes and failures move endpoints to
`Healthy` or `Unhealthy` at their configured thresholds. Unhealthy endpoints stay
in the health-check set but are not selected for application traffic.

Active checks call the configured origin-form path directly, use their own timeout,
do not traverse the Service graph, do not retry, and discard only a bounded response
body. Status values accept exact codes or inclusive ranges such as `"200-299"`.

Configured connect failures, response-head timeouts, H2 refused/reset conditions,
upstream TLS failures, and configured retryable 5xx responses can contribute to
passive failure state. Client cancellation does not. At the threshold an endpoint
becomes `PassivelyEjected`; expiry returns it to eligible probation. Reaching the
active healthy threshold may restore it early.

When no endpoint is eligible, Proxy fails with `UpstreamUnavailable`. Capacity
exhaustion fails with `UpstreamOverloaded`. Both map to a safe 503 by default and
can be selected independently by `Recover`.

## Bounded admission

`max_in_flight` limits the Cluster and `max_in_flight_per_endpoint` limits each
endpoint. `queue_timeout: 0ms` fails immediately; a positive value waits at most
that duration. Oxidase obtains both permits before consuming the request body.
Permits are cancellation-safe and cover streaming responses and trusted tunnels.

## Retry contract

`max_attempts` includes the first attempt and defaults to 1. A retry occurs only
when all of these conditions hold:

1. the method is explicitly listed;
2. a pre-response-head cause or status is explicitly listed;
3. no response head has reached the downstream;
4. the body is empty or was made replayable by explicit bounded buffering;
5. attempt and concurrent-retry limits remain;
6. an eligible, not-yet-tried endpoint remains.

Supported causes are `connect_failure`, `response_header_timeout`,
`refused_stream`, and `reset`. A status retry drops the uncommitted upstream body
before selecting the next endpoint. Oxidase stops after each eligible endpoint was
tried rather than cycling back indefinitely. A non-waiting
`max_concurrent_retries` semaphore limits amplification; initial attempts do not
consume it.

`request_body.mode: none` retries only an actually empty body. `mode: buffer`
collects the request exactly once before the first attempt and rejects a body over
`max_bytes` with 413. Buffering is never implicit or unbounded. POST is never
retryable by default; explicitly listing it emits a warning because the operator is
assuming idempotency responsibility.

## Reload, admin, and metrics

Runtime state is reused only for the same Cluster Resource ID, endpoint name,
canonical URL, and upstream protocol. Policy-only changes can retain health and
counters; changing URL or protocol creates new endpoint state. Health supervisors
start only after commit, stop after removal and release of old pinned snapshots,
and use weak ownership to avoid task cycles.

With `--admin-bind`, `GET /api/v1/clusters` returns sorted Cluster and endpoint
names, protocol/policy, health state, active counts, fixed counters, last transition,
and remaining ejection time. It does not return origins, request data, credentials,
or certificate material.

Prometheus output includes bounded Cluster/endpoint selection, in-flight, health,
ejection, retry, and admission series. Labels are limited to configured Cluster and
endpoint names plus fixed protocol/policy/result/state enums. URLs, paths, queries,
client addresses, Header values, and error strings are never labels. Bind the admin
listener only to a trusted network.

## Current limits

Endpoints are static configuration. Dynamic DNS/service discovery, cross-process
health consensus, hedging, arbitrary retry scripting, writable admin operations,
and a general circuit-breaker policy beyond bounded admission/passive ejection are
not implemented. The current `response_timeout` bounds connect plus request upload
and response-head latency as one deadline; separate per-phase timing and
observability are not exposed yet.
