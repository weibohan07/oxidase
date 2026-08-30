# Operations

Oxidase v0.2 remains an alpha. The current gates exercise the implementation, but
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
normalization. Upgrades and trailers are not implemented.

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
  request, and reload counters.

An explicit `Observe` wrapper adds bounded production series:

- `oxidase_observe_total{observe,outcome}`;
- `oxidase_observe_status_total{observe,class}` and fixed error classes;
- `oxidase_observe_response_head_duration_seconds_bucket`.

Observe latency ends when the child returns its outcome/response head. It does not
include streaming body delivery. The root body adapter separately exports emitted
byte totals, body lifetime buckets, and a fixed termination reason of `completed`,
`error`, `cancelled`, or `timeout`. Dropping a client response does not cause body
collection; it drops the upstream/file stream and releases the active-request guard.

Transport telemetry adds fixed-label series for accepted/active connections by
`protocol="http1|h2"`, TLS handshake result and duration, negotiated ALPN, active
HTTP/2 streams, and graceful/forced HTTP/2 shutdown. Result and protocol values are
closed enums; SNI values, certificate paths, client IPs, URLs, and Headers are not
labels.

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

## Logging

Set `RUST_LOG`, for example `RUST_LOG=oxidase=debug`. Access events correlate a
request ID, config version, listener, bounded outcome/status, and latency. Internal
failure details, including template parameter contract failures, go to structured
logs; clients receive only safe generic errors. OXT output/loop/include/expression/
time budget failures map to `TemplateLimit` for selective Recover; evaluation,
argument, and response-metadata failures remain `InvalidState`.
