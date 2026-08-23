# Implementation status

Last updated: 2026-08-23

## Baseline

- v0.2 branch: `refactor/service-program-v2`
- public base: `cb9e86ab7b5ae0424c6cad0b0b3788ae54ca501a`
- v0.1 baseline tests: 30 passed
- v0.1 baseline Clippy: command succeeded with 39 warnings

## Completed

- Repository architecture contract, vision, Service algebra, Oxista boundary, and
  Hyper data-plane decision.
- Phase 0 Cargo workspace layout with seven intentionally layered crates.
- Compiled host/path/value Patterns with typed placeholders, lexical capture output,
  restricted custom regex, and representative v0.1 semantic tests.
- Phase 1 typed values, stable IDs/source spans, unified expression and interpolation
  compilers, lexical binding scopes, immutable Service graph IR, and transactional
  request frames.
- Pure in-memory execution for Respond, Redirect, Route, Fallback, Transform,
  Observe, Timeout, Recover, Reenter, Site and Proxy leaf boundaries.
- Graph validation rejects implicit reference cycles, zero Reenter budgets, missing
  nodes, and body-consuming fallback candidates before later alternatives.
- Phase 2 strict `oxidase.dev/v1alpha1` source AST and compiler with maintained YAML
  parsing, duplicate/unknown-key rejection, relative imports, import-cycle checks,
  named and inline Services, resource references, and Router-to-Route lowering.
- `oxidase check`, symbolic `explain`, deterministic `compile` manifest, and
  declarative `test` commands all use the same compiler and normalized plans.
- Phase 3 Oxista compiler for strict `.oxsite`, `.oxr`, and `.oxt` sources. Site
  preparation validates typed inputs, scans once, builds a private/public index,
  compiles template dependencies, and produces an immutable `SiteSnapshot`.
- OXR supports Redirect, sibling/relative streaming Asset plans, text, empty,
  structured JSON, inline templates, and external templates with parameter
  contracts. OXT supports interpolation, `if/elif/else`, `for/else`, `with`, static
  `include`, comments, and raw blocks with autoescape and bounded execution.
- Required `basic-gateway` and `oxista-site` examples compile and their three
  declarative gateway tests pass. `check` now prepares every Site through the same
  path that reload will use.
- Phase 4 Tokio + Hyper HTTP/1.1 data plane with prepare-all listener binding,
  arbitrary root Service execution, connection-derived peer/scheme metadata, safe
  root outcome mapping, structured tracing fields, and bounded graceful drain.
- Site bytes and assets are adapted to HTTP without default collection. Asset files
  use async streaming, single byte ranges, HEAD, ETag/Last-Modified conditionals,
  and Brotli/gzip representation selection.
- `oxidase serve` now runs the prepared gateway. Real loopback tests cover
  Respond/Redirect/Route/fallback, streaming asset range responses, and shutdown.
- Phase 5 Proxy uses one long-lived Hyper client and connection pool for all
  requests, streams downstream request and upstream response bodies, supports
  HTTP/HTTPS plus upstream HTTP/2 ALPN, and never collects the normal proxy path.
- Proxy removes Connection-nominated and standard hop-by-hop headers, applies a
  target-Host and sanitized connection-derived Forwarded/X-Forwarded policy,
  preserves raw path/query representation, enforces response-header and body-idle
  timeouts, and returns classified Failed outcomes.
- A real fixture-upstream test covers POST streaming, query preservation, forwarding
  headers, response header sanitization, connection-pool reuse, and timeout mapping.
- Phase 6 reload compiles and prepares a complete candidate against the current
  snapshot, content-fingerprints Site/Cluster resources for Arc reuse, prebinds every
  added/changed listener, stops removed accept loops, atomically publishes, and
  drains retired connections.
- `serve --watch` polls the complete config/Oxista file-and-directory dependency
  graph with debounce. Failed compile, resource preparation, or listener bind leaves
  the last-known-good snapshot untouched.
- Integration tests prove invalid and bind-conflicting reload rollback, listener
  retain/add/remove behavior, old long-running requests crossing a commit, and new
  requests immediately observing the new version.

## Currently runnable

- A v1alpha1 config and Oxista site can be fully prepared, served over HTTP/1.1,
  executed in memory, explained, reloaded, and tested. Forty-eight workspace tests pass,
  including two real listener tests that require permission to bind loopback ports.

## Not implemented

- Inbound TLS/HTTP2 and Phase 7 hardening capabilities.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed but currently reports missing fields as `Null`;
  Oxista strict-undefined policy is not wired yet.
- Site and Proxy are real Service nodes but only their runtime leaf boundary exists;
  no production I/O implementation is advertised yet.
- `compile` writes a deterministic inspection manifest, not a portable executable
  snapshot containing site assets or connection state.
- Semantic diagnostics retain file and field path but do not yet recover exact
  scalar lines for every lowering error.
- OXT `extends`/`block` is explicitly rejected; inheritance is not claimed.
- Symlinked files are checked against the canonical root, but their alias path is not
  indexed in this release; directory symlinks are rejected rather than traversed.
- Asset range and precompressed metadata is compiled, but actual range/content
  negotiation is HTTP/1.1 only; multipart ranges are deliberately rejected.
- Listener serving supports HTTP/1.1 only. TLS, HTTP/2, upgrades, trailers, gRPC,
  and `100-continue` policy remain unimplemented.
- Cluster health checks, retry policy, stable per-cluster health state, and
  configurable Forwarded trust policy are not implemented. The current secure
  default always replaces incoming forwarding metadata.
- The response-header timeout currently bounds connect plus upload/header latency as
  one deadline; per-phase connect/write timing is not separately observable yet.
- Explicit slow-client, client-disconnect, and upstream-mid-body disconnect tests
  remain for hardening, though dropped Hyper bodies propagate cancellation.
- The portable watcher polls every 500ms. An edit that preserves path, byte length,
  and filesystem modification timestamp could be missed until another dependency
  changes; triggered preparation itself uses full content fingerprints.
- Renaming a Listener while reusing its exact occupied address is rejected on
  platforms without safe port sharing, preserving last-known-good. Unchanged names
  and ordinary add/remove/address transitions are supported.

## Next concrete work

Add bounded metrics and management listeners, strengthen cancellation/security
tests, add property/fuzz harnesses, document operations and migration, and finish
release-quality CI/security files.
