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
- Phase 7 adds an opt-in, separately bound management listener with live/ready
  health and Prometheus text metrics. Outcome, status-class, latency, active request,
  and reload labels are fixed and bounded.
- Redirect and constant header validation fail closed; property-style generated
  Pattern/path tests, template-limit tests, and seven cargo-fuzz harnesses cover the
  highest-risk parsers and resolvers.
- CI, dependency-policy, security, contributing, operations, migration, and manual
  benchmark entrypoints are present. The superseded v0.1 source tree was removed;
  its implementation remains in Git history.

## Currently runnable

- A v1alpha1 config and Oxista site can be fully prepared, served over HTTP/1.1,
  executed in memory, explained, reloaded, observed, and tested. Fifty-three
  workspace tests pass, including five real listener/upstream tests that require
  permission to bind loopback ports.

## Not implemented

- Inbound TLS/HTTP2, WebSocket/upgrades, trailers/gRPC, OXT inheritance, and a
  self-contained executable snapshot artifact.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed and reports missing fields as `Null`; Oxista
  enforces its configured strict-undefined policy at template interpolation.
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
- Redirects currently allow only local absolute paths. Intentional cross-origin
  redirects require a future explicit allow policy.
- The admin listener is CLI-configured rather than part of the gateway source and is
  not dynamically rebound during config reload.

## Validation boundary

- Local workspace and fuzz format checks: passed.
- Local Clippy with workspace/all-targets/all-features and warnings denied: passed.
- Local workspace tests: 53 passed; loopback tests ran outside the restricted
  sandbox.
- Local workspace docs with warnings denied and release workspace build: passed.
- `cargo deny check`: advisories, bans, licenses, and sources passed after upgrading
  `bytes` to 1.12.1 for RUSTSEC-2026-0007; one allowed indirect `syn` duplication
  warning remains.
- All seven fuzz harnesses compile offline; no long fuzz campaign was run.
- The release-mode manual smoke benchmark completed 100,000 in-memory programs in
  about 195ms on this machine. This is a local smoke result, not a performance claim.
- Example `check`, three declarative tests, `explain`, and compilation manifest:
  passed.
- Hosted CI: configured but not run in this work session.

## Next concrete work

Add inbound TLS/HTTP2 listener lifecycle, OXT `extends`/`block`, precise semantic
source markers, disconnect/slow-client campaigns, and long-running fuzz/benchmark
baselines before a stable release.
