# Operations

Oxidase v0.2 remains an alpha. The current gates exercise the implementation, but
this document does not claim production readiness.

## Startup and validation

`oxidase check <config>` performs the same configuration and Oxista preparation as
serve/reload without binding sockets. `oxidase test <config>` then runs declarative
request expectations. Use both before deployment.

`oxidase serve <config>` prepares every resource and listener before accepting
traffic. Any initial compile, site preparation, or bind failure prevents partial
startup. Source parsing uses one strict YAML subset for Gateway, `.oxsite`, `.oxr`,
`.oxt`, and explain request documents: duplicate keys, anchors, aliases, merge keys,
custom tags, tab indentation, and flow mappings are rejected; flow sequences are
allowed.

## Reload

Use `oxidase serve <config> --watch` for the portable dependency watcher. Candidate
configuration, imports, templates, response documents, assets, and resources are
fully prepared first. Synchronous reads, site scans, template compilation, and
fingerprints run on a single-concurrency blocking compiler worker, not a Tokio async
worker. New listener sockets are prebound and publication remains serialized by the
manager.

The watcher tracks the union of published dependencies and the last attempted
candidate. A failed new import therefore remains watched, including its declared
path and parent directory; fixing only that imported file triggers another attempt.
An unchanged failure becomes the current filesystem baseline instead of producing a
log loop. Events arriving during preparation collapse into one latest dirty retry.

Requests pin one immutable snapshot through Service execution. Retired listeners
stop accepting before publication. Each HTTP/1 connection then receives Hyper's
graceful-shutdown signal: idle keep-alive connections close promptly, active
requests may finish on their pinned old snapshot, and only connections exceeding
the configured drain deadline are aborted.

The watcher polls every 500ms. A filesystem edit that preserves path, byte length,
and modification timestamp can still be missed until another observed dependency
changes.

## Response finalization

Every handled root response passes through one `ResponseFinalizer` immediately
before Hyper. It owns wire framing and enforces these rules:

- informational, 204, and 304 responses send no message body;
- HEAD sends no body while retaining a known GET representation length;
- `Content-Length` is derived only from trusted bytes or selected asset metadata;
- unknown-length Proxy streams do not inherit an unverified upstream length;
- Connection-nominated and standard hop-by-hop headers are removed;
- `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Keep-Alive`,
  `Proxy-Connection`, `TE`, and `Trailer` cannot be controlled from Gateway or
  Oxista source, including an outer response Transform.

Hyper remains responsible for the final HTTP/1 transport framing after this
normalization. Upgrades and trailers are not implemented.

## Asset request order

For a Site asset, request handling is fixed to this order:

1. choose identity, Brotli, or gzip using `Accept-Encoding` quality values;
2. install metadata for that exact representation;
3. evaluate `If-None-Match`, or only when absent, `If-Modified-Since`;
4. for an eligible identity response, evaluate `If-Range` and one byte Range;
5. build the final 200, 206, 304, 406, or 416 response and pass it to the finalizer.

Each representation has its own content-derived ETag, length, and modification
time. A Range request forces identity; if identity is explicitly unacceptable, the
result is 406. Multipart ranges are deliberately rejected with 416. `Vary:
Accept-Encoding` is merged without duplicating the token.

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

Do not expose the admin bind directly to an untrusted network. Metric labels are
intentionally bounded and never contain raw URLs, headers, user IDs, or Service
source values.

## Logging

Set `RUST_LOG`, for example `RUST_LOG=oxidase=debug`. Access events correlate a
request ID, config version, listener, bounded outcome/status, and latency. Internal
failure details, including template parameter contract failures, go to structured
logs; clients receive only safe generic errors.
