# Operations

Oxidase v0.3 remains an alpha. The current gates exercise the implementation, but
this document does not claim production readiness.

## Startup and validation

`oxidase check <config>` performs the same configuration and Oxista preparation as
serve/reload without binding sockets. `oxidase test <config>` then runs declarative
request expectations. Use both before deployment.

`oxidase serve <config>` prepares every resource and listener before accepting
traffic. Certificate chains, private keys, key/certificate consistency, SNI rules,
TLS server configurations, Sites, and listener sockets all validate before
publication. Any initial compile, resource preparation, or bind failure prevents
partial startup. Source parsing uses one strict YAML subset for Gateway, `.oxsite`, `.oxr`,
`.oxt`, and explain request documents: duplicate keys, anchors, aliases, merge keys,
custom tags, tab indentation, and flow mappings are rejected; flow sequences are
allowed. Literal and folded block scalars (including chomping and indentation
indicators accepted by the YAML decoder) are supported; their contents are not
mistaken for mapping keys or YAML graph features by the strict pre-scan.

## Reload

Use `oxidase serve <config> --watch` for the portable dependency watcher. Candidate
configuration, imports, templates, response documents, assets, and resources are
fully prepared first. Synchronous reads, site scans, template compilation, and
fingerprints run on a single-concurrency blocking compiler worker, not a Tokio async
worker. New listener sockets are prebound and publication remains serialized by the
manager.

Certificate chain and private-key paths, including missing declared paths and their
parents, are watcher dependencies. A candidate key is always parsed and positively
matched to its leaf certificate even when the public chain digest is unchanged.
Private-key bytes and fingerprints are never emitted in diagnostics, manifests,
logs, or metrics.

Site preparation is a single candidate pipeline: scan to `SiteSourceIndex`, compare
its SHA-256 identity with the published resource, then either reuse the old
`Arc<SiteSnapshot>` or compile directly from that index. Asset, Brotli, and gzip
bytes are each read once per candidate; only Oxista text sources are retained in
memory. This is deliberately not an mtime-only cross-reload digest cache.

The watcher tracks the union of published dependencies and the last attempted
candidate. A failed new import therefore remains watched, including its declared
path and parent directory; fixing only that imported file triggers another attempt.
Failed Site preparation likewise returns partial dependencies: the Site root and
manifest, every scanned OXT/OXR/asset, template roots and includes, backing and
precompressed candidates, missing declared paths, and relevant parent directories.
Fixing an existing invalid OXT/OXR or creating only a missing template is sufficient
to trigger a new attempt while the last-known-good snapshot continues serving.
An unchanged failure becomes the current filesystem baseline instead of producing a
log loop. Events arriving during preparation collapse into one latest dirty retry.

Requests pin one immutable snapshot through Service execution. Retired listeners
stop accepting before publication. Each HTTP/1 connection then receives Hyper's
graceful-shutdown signal; each HTTP/2 connection receives graceful shutdown/GOAWAY
and stops admitting new streams. Idle connections close promptly, active requests
may finish on their pinned snapshot, and only connections exceeding the configured
drain deadline are aborted. HTTP/2 pins the Service snapshot per request/stream, not
per connection, so a new stream accepted after publication sees the new snapshot.

When listener name and bind remain unchanged, the listening socket is retained.
Every newly accepted connection loads the current prepared TLS/HTTP plan; certificate
or protocol-setting changes therefore do not require a rebind. Existing TLS
connections keep the rustls configuration selected at their handshake. Invalid
certificate rotation remains a failed candidate and the last-known-good certificate
continues serving.

The watcher polls every 500ms. A filesystem edit that preserves path, byte length,
and modification timestamp can still be missed until another observed dependency
changes.

Filesystem watch stamps and content identity are separate. A watch stamp uses path,
kind, length, and mtime to decide whether to attempt a reload. Config/Site/Cluster
identity and ETags use complete SHA-256 content digests with domain-separated,
length-prefixed structured fields. A triggered preparation therefore never treats
the watch stamp itself as proof that content is unchanged.

## Response finalization

Every handled root response passes through one `ResponseFinalizer` immediately
before Hyper. It owns wire framing and enforces these rules:

- informational, 204, 205, and 304 responses send no message body; a suppressed 205
  cannot retain a nonzero length derived from its discarded body;
- HEAD sends no body while retaining a known GET representation length;
- `Content-Length` is derived only from trusted bytes or selected asset metadata;
- unknown-length Proxy streams do not inherit an unverified upstream length;
- Connection-nominated and standard hop-by-hop headers are removed;
- `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Keep-Alive`,
  `Proxy-Connection`, `TE`, and `Trailer` cannot be controlled from Gateway or
  Oxista source, including an outer response Transform.

Hyper remains responsible for final HTTP/1 or HTTP/2 transport framing after this
normalization. The runtime sanitizer is wire-protocol aware: HTTP/1 removes
Connection-nominated and standard hop-by-hop fields; HTTP/2 additionally rejects
the prohibited connection fields and retains `TE` only when its value is exactly
`trailers`. Ordinary configuration still cannot opt out of these rules. Only Proxy
can attach validated response-trailer metadata or the private trusted capability
needed to finalize an HTTP/1 `101 Switching Protocols` response.

## TLS and HTTP versions

Cleartext listeners support HTTP/1.1 only. HTTPS listeners use rustls TLS 1.2/1.3
defaults and select enabled HTTP versions through ALPN. Exact SNI rules win over a
single-label left-most wildcard; unmatched or absent SNI uses the configured default
certificate. See [`configuration/tls.md`](configuration/tls.md) and
[`configuration/http2.md`](configuration/http2.md) for the DSL, defaults, and
rejected configurations.

Connection-derived request metadata is read-only:

- `request.http_version` is `"1.1"` or `"2"`;
- `request.tls.enabled` distinguishes cleartext and TLS;
- `request.tls.server_name`, `request.tls.alpn`, and `request.tls.version` describe
  the accepted TLS connection and are null/absent as appropriate for cleartext.

Forwarded/X-Forwarded scheme metadata is constructed from the accepted connection,
not from client-supplied forwarding Headers. Raw SNI and peer addresses may appear
as controlled tracing fields but never as metric labels.

## Protocol bridging

A Cluster's upstream protocol is `auto`, `http1`, or `h2`. `auto` uses HTTPS ALPN
and cleartext HTTP/1; `http1` forces HTTP/1.1; `h2` requires H2 over TLS and uses H2
prior knowledge for a cleartext upstream. The server owns one reusable pool for
each policy. A transparent gRPC route therefore uses an H2 downstream and a Proxy
whose Cluster is explicitly `protocol: h2`; Oxidase forwards DATA and terminal
trailers without parsing protobuf, changing gRPC message frames, or translating
`grpc-status` into the HTTP status.

The current black-box TLS/H2 fixture verifies downstream request trailers, upstream
response trailers, multiple opaque gRPC messages, and `grpc-status`/`grpc-message`
trailers. gRPC-Web is not implemented. Cross-version trailer forwarding has stricter
HTTP/1 rules: a downstream HTTP/1 client must advertise `TE: trailers`, and response
trailer names must have appeared in the initial trusted `Trailer` declaration.
Unsafe or undeclared trailers terminate the streaming body with a protocol error;
they are not silently dropped and cannot become a synthetic 502 after the response
head. Socket-level fixtures verify an HTTP/1 chunked request crossing to H2, declared
H2 response trailers crossing to an accepting HTTP/1 client, explicit failure for
undeclared trailers, and an upstream post-head reset remaining a body error rather
than becoming 502.

HTTP/1 Proxy owns a private Upgrade capability extracted by the connection driver.
Both the downstream request and upstream 101 response must contain one valid,
matching Upgrade protocol and `Connection: upgrade`; user Respond/OXR/Transform
output cannot construct this capability. The upstream attempt is forced through
the HTTP/1 pool. Once both Hyper upgrade futures resolve, the connection owner
copies bytes bidirectionally without application buffering and keeps the request's
snapshot alive. A retained Listener leaves the tunnel running across reload;
retirement permits it to run until the normal drain deadline, after which the
connection task is aborted.

This is generic Upgrade transport and does not inspect WebSocket frames. Focused
unit tests cover validation, matching 101 responses, partial byte accounting,
bidirectional copy, and first-EOF cancellation. Socket tests cover plain and TLS
HTTP/1 handshakes, WebSocket-style bytes in both directions, downstream/upstream
close, reload with an old pinned tunnel and a new Listener, bounded drain-time abort,
non-Proxy 101 isolation, and tunnel metrics. HTTP/2 extended CONNECT, arbitrary
CONNECT tunnels, h2c Upgrade, and WebTransport are rejected.

## Cluster operation

Prepared Clusters select only eligible endpoints and obtain Cluster plus endpoint
permits before consuming the request body. A Cluster with no eligible endpoint
fails as `UpstreamUnavailable`; exhausted or timed-out admission fails as
`UpstreamOverloaded`. Both have a safe default 503 and remain separately recoverable.

Active health tasks start only after a snapshot commits. They make direct bounded
requests with their own timeout and never traverse the Service graph or retry.
Unhealthy endpoints remain probed. Consecutive active successes can restore an
unhealthy or passively ejected endpoint; passive ejection also expires after its
configured duration. Client cancellation is not counted as endpoint failure.

Retry is disabled unless `max_attempts` exceeds one and explicit methods plus causes
or statuses are configured. It ends before a downstream response head, prefers an
untried eligible endpoint, and never becomes Fallback. Empty bodies are replayable;
non-empty bodies require `request_body.mode: buffer` and are rejected with 413 when
they exceed `max_bytes`. The independent retry semaphore is non-waiting, preventing
retry amplification from creating another queue. See
[`configuration/clusters.md`](configuration/clusters.md) for the complete contract.

Compatible endpoint health/counter state is reused across reload only when Cluster
ID, endpoint name, canonical URL, upstream protocol, and the complete health policy
match. A health-policy change creates a new health generation so a supervisor held
by an old pinned snapshot cannot write the new policy's state. The endpoint admission
counter remains shared across that generation boundary, so old requests continue to
count toward the new per-endpoint limit. Candidate prepare does not start a
supervisor. Removed Cluster supervisors stop after old pinned snapshots release
them; URL/protocol changes receive fresh endpoint and admission state.

## Asset request order

For a Site asset, request handling is fixed to this order:

1. only for GET, classify Range as absent, ignored, or one valid bytes range;
2. choose identity, Brotli, or gzip using `Accept-Encoding` quality values; a valid
   single range prefers identity only when identity is acceptable;
3. install metadata for that exact representation;
4. evaluate `If-None-Match`, or only when absent, `If-Modified-Since`;
5. for an eligible identity response, evaluate `If-Range`, resolve the byte range,
   and build the final 200, 206, 304, 406, or 416 response before finalization.

Each representation has its own content-derived ETag, length, and modification
time. Strong tags are `"sha256-<64 lowercase hex>"`; weak configuration emits the
same representation digest with `W/`. HEAD and all other non-GET methods ignore
Range and If-Range while retaining
normal negotiation and validator behavior. Unknown units, malformed bytes ranges,
and multiple ranges are ignored and receive a full negotiated representation. If a
valid single range arrives with `identity;q=0`, Range is ignored and a full br/gzip
representation may be selected. Only a syntactically valid but unsatisfiable single
bytes range returns 416 with `Content-Range: bytes */length`. `Vary:
Accept-Encoding` is merged without duplicating the token.

Oxista response policies execute by layer: global defaults, logical-resource
extension defaults, profiles in declared order, then local OXR headers. Every layer
runs remove, set, add in that order. Ordinary assets and OXR-backed assets share the
same logical extension policy, including when a compressed representation is sent.

## Health and metrics

The management listener is opt-in and independent from user traffic:

```bash
oxidase serve config.yaml --watch --admin-bind 127.0.0.1:7590
```

It serves:

- `/health/live`: process/event-loop liveness;
- `/health/ready`: a prepared snapshot with at least one user listener;
- `/metrics`: Prometheus text with fixed outcome, status-class, latency, active
  request, reload, transport, tunnel, and Cluster counters;
- `/api/v1/clusters`: deterministic read-only Cluster/endpoint runtime status.

An explicit `Observe` wrapper adds bounded production series:

- `oxidase_observe_total{observe,outcome}`;
- `oxidase_observe_status_total{observe,class}` and fixed error classes;
- `oxidase_observe_response_head_duration_seconds_bucket`.

Observe latency ends when the child returns its outcome/response head. It does not
include streaming body delivery. The root body adapter separately exports emitted
byte totals, body lifetime buckets, and a fixed termination reason of `completed`,
`error`, `cancelled`, or `timeout`. Dropping a client response does not cause body
collection; it drops the upstream/file stream and releases the active-request guard.

Transport telemetry adds series keyed by configured Listener name and fixed enums
for accepted/active connections by `protocol="http1|h2"`, TLS handshake result and
duration, negotiated ALPN, active HTTP/2 streams, and graceful/forced HTTP/2
shutdown. Result and protocol values are closed enums; SNI values, certificate
paths, client IPs, URLs, and Headers are not labels. Each Listener permits at most
128 simultaneous TLS handshakes; excess accepts fail immediately with the fixed
`overloaded` result.

Trusted HTTP/1 tunnels add only listener-scoped bounded series:

- `oxidase_tunnels_started_total` and `oxidase_active_tunnels`;
- `oxidase_tunnel_bytes_total{direction}`, where direction is one of
  `downstream_to_upstream` or `upstream_to_downstream`;
- `oxidase_tunnel_terminations_total{reason}`, where reason is one of
  `downstream_closed`, `upstream_closed`, `error`, or `cancelled`.

Dropping an unfinished tunnel guard records `cancelled`, so a drain-time abort does
not leak the active gauge. Upgrade protocol values and WebSocket application data
are never labels.

Cluster telemetry uses only configured `cluster`/`endpoint` names and fixed
protocol, policy, health, and result enums. It includes selection, active requests,
success/failure, health checks/transitions, passive ejection, retry, and admission
series. The JSON admin view contains the same conservative names and counters plus
last transition/ejection remaining. Neither endpoint origins nor request data,
credentials, certificate material, paths, queries, client addresses, or error
strings are returned or used as labels.

Do not expose the admin bind directly to an untrusted network. Metric labels are
intentionally bounded and never contain raw URLs, headers, user IDs, or Service
source values.

User HTTP/1 mode and the management HTTP/1 listener use Hyper's timer-backed request
header read timeout (30 seconds by default). TLS has a separate handshake timeout
(5 seconds by default). HTTP/2 applies configured maximum concurrent streams,
maximum Header list size, keepalive interval, and keepalive timeout without adding a
custom parser or a new `100-continue` policy.

For a manual short soak (not part of ordinary CI), run:

```bash
OXIDASE_SOAK_ITERATIONS=1000 cargo test -p oxidase-server \
  manual_proxy_reload_keepalive_and_cancellation_soak --locked \
  -- --ignored --nocapture
```

It combines one persistent HTTP/1 client, periodic atomic reload, downstream
cancellation, and an 8 MiB streaming Asset. Treat the output as an observation aid
for memory/fd monitoring, not as a performance or reliability guarantee.

## Manual regression benchmarks

These ignored/manual entrypoints are local regression tools. They do not run in the
ordinary test suite, set no CI latency threshold, and are not performance or capacity
guarantees:

```bash
# TLS handshakes plus sequential H1 and multiplexed H2 requests (binds loopback)
cargo test -p oxidase-server --test tls_h2 \
  tls_http1_http2_smoke_benchmark --release --locked -- --ignored --nocapture

# compiled exact/wildcard/default SNI resolution
cargo test -p oxidase-runtime sni_resolver_smoke_benchmark \
  --release --locked -- --ignored --nocapture

# weighted RR, least requests, retry permits, and health transitions
cargo test -p oxidase-runtime cluster_policy_smoke_benchmark \
  --release --locked -- --ignored --nocapture

# short path through a large shared ServiceGraph
cargo run -p oxidase-runtime --example service_program_bench --release --locked

# typed OXT include/render and synthetic Site preparation
cargo test -p oxidase-site typed_include_render_smoke_benchmark \
  --release --locked -- --ignored --nocapture
cargo test -p oxidase-site synthetic_site_preparation_smoke_benchmark \
  --release --locked -- --ignored --nocapture

# frame-local RequestFrame evaluation caches
cargo test -p oxidase-core request_evaluation_context_smoke_benchmark \
  --release --locked -- --ignored --nocapture
```

Record the exact commit, command, machine, build profile, iteration count, and output
when using these tools. Compare only like-for-like runs; a one-machine smoke result
must not be published as a general performance claim.

## Logging

Set `RUST_LOG`, for example `RUST_LOG=oxidase=debug`. Access events correlate a
request ID, config version, listener, bounded outcome/status, and latency. Internal
failure details, including template parameter contract failures, go to structured
logs; clients receive only safe generic errors. OXT output/loop/include/expression/
time budget failures map to `TemplateLimit` for selective Recover; evaluation,
argument, and response-metadata failures remain `InvalidState`.
