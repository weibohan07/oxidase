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

## Currently runnable

- A v1alpha1 config and Oxista site can be fully prepared, served over HTTP/1.1,
  executed in memory, explained, and tested. Forty-four workspace tests pass,
  including two real listener tests that require permission to bind loopback ports.

## Not implemented

- Production Proxy, TLS/HTTP2, and listener-aware atomic reload.

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
- Proxy currently returns a safe 502 from the production listener; no upstream I/O
  is performed yet.
- Listener serving supports HTTP/1.1 only. TLS, HTTP/2, upgrades, trailers, gRPC,
  and `100-continue` policy remain unimplemented.

## Next concrete work

Implement reusable Cluster clients, streaming Proxy request/response bodies,
hop-by-hop header policy, forwarding metadata, timeouts, and upstream integration
tests.
