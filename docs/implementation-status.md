# Implementation status

Last updated: 2026-08-23

## Baseline

- hardening branch: `hardening/v0.2-alpha-correctness`
- public starting point: `f202a3644badffedf93eeb7b2b421a6726c05595`
- release line: `0.2.0-alpha`; production readiness is not claimed

## Completed

- Repository architecture contract, vision, Service algebra, Oxista boundary, and
  Hyper data-plane decision.
- Phase 0 Cargo workspace layout with eight intentionally layered crates, including
  the shared `oxidase-source` strict parser.
- Compiled host/path/value Patterns with typed placeholders, lexical capture output,
  restricted custom regex, and representative v0.1 semantic tests.
- Phase 1 typed values, stable IDs/source spans, unified expression and interpolation
  compilers, lexical binding scopes, immutable Service graph IR, and transactional
  request frames. Compiler-owned source-file identity plus field path prevents
  cross-import inline Service/Route collisions, and duplicate node insertion fails.
- Listener programs share one `Arc<ServiceGraph>`; request program views do not clone
  the node map. Production execution uses a no-op trace sink, while explain/tests
  explicitly collect structured traces without changing the executed graph.
- Pure in-memory execution for Respond, Redirect, Route, Fallback, Transform,
  Observe, Timeout, Recover, Reenter, Site and Proxy leaf boundaries.
- Graph validation rejects implicit reference cycles, zero Reenter budgets, missing
  nodes, and body-consuming fallback candidates before later alternatives.
- Phase 2 strict `oxidase.dev/v1alpha1` source AST and compiler with one YAML subset
  shared by Gateway, `.oxsite`, `.oxr`, `.oxt`, and request documents. It rejects
  duplicate/unknown keys, anchors, aliases, merge keys, tags, tab indentation, and
  flow mappings while allowing flow sequences. Relative imports, import-cycle
  checks, named/inline Services, resource references, and Router lowering remain.
- `oxidase check`, symbolic `explain`, deterministic `compile` manifest, and
  declarative `test` commands all use the same compiler and normalized plans.
- Phase 3 Oxista compiler for strict `.oxsite`, `.oxr`, and `.oxt` sources. Site
  preparation validates typed inputs, scans once, builds a private/public index,
  compiles template dependencies, and produces an immutable `SiteSnapshot`.
- OXR supports Redirect, sibling/relative streaming Asset plans, text, empty,
  structured JSON, inline templates, and external templates with parameter
  contracts. OXT supports interpolation, `if/elif/else`, `for/else`, `with`, static
  `include`, comments, and raw blocks with autoescape and bounded execution.
- HTML/text OXT output now controls default autoescape and Content-Type. Dynamic
  template arguments are checked immediately before render; URL means absolute URL,
  and `safe_html` is rejected until Value can carry trusted provenance. Unsupported
  or inert v1 field values fail with field-specific migration guidance.
- Required `basic-gateway` and `oxista-site` examples compile and their three
  declarative gateway tests pass. `check` now prepares every Site through the same
  path that reload will use.
- Phase 4 Tokio + Hyper HTTP/1.1 data plane with prepare-all listener binding,
  arbitrary root Service execution, connection-derived peer/scheme metadata, safe
  root outcome mapping, structured tracing fields, and bounded graceful drain.
- Site bytes and assets are adapted to HTTP without default collection. Identity,
  Brotli, and gzip representations own independent length/ETag/mtime metadata.
  Quality negotiation, validator precedence, representation-aware 304, If-Range,
  suffix/open-ended/single ranges, HEAD, 406, and 416 are covered on the wire.
- One root `ResponseFinalizer` owns HTTP framing for Respond, Redirect, Site, Proxy,
  and Transform output. It strips hop-by-hop/untrusted framing metadata and enforces
  HEAD, 1xx, 204, and 304 body semantics. Source header policy rejects direct
  control of dangerous framing and hop-by-hop headers.
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
- Blocking compilation/preparation runs through a one-concurrency `spawn_blocking`
  worker. `serve --watch` polls published plus last-attempt dependencies with
  debounce and latest-dirty coalescing. Failed imports and missing declared paths
  remain observed while the last-known-good snapshot stays active.
- Retired HTTP/1 connections receive Hyper graceful shutdown. Idle keep-alive closes
  promptly, active requests finish on their pinned snapshot, and the drain timeout
  is the only point at which remaining tasks are aborted.
- Integration tests prove invalid and bind-conflicting reload rollback, listener
  retain/add/remove behavior, old long-running requests crossing a commit, and new
  requests immediately observing the new version.
- Phase 7 adds an opt-in, separately bound management listener with live/ready
  health and Prometheus text metrics. Outcome, status-class, latency, active request,
  and reload labels are fixed and bounded.
- Redirect and constant header validation fail closed; property-style generated
  Pattern/path tests, template-limit tests, and seven cargo-fuzz harnesses cover the
  highest-risk parsers and resolvers.
- CI has distinct Rust 1.88 MSRV, stable workspace, cargo-deny, and fuzz compile
  jobs. Dependency-policy, security, contributing, operations, migration, and
  benchmark entrypoints are present. The superseded v0.1 implementation remains in
  Git history.

## Currently runnable

- A v1alpha1 config and Oxista site can be fully prepared, served over HTTP/1.1,
  executed in memory, explained, reloaded, observed, and tested. Eighty-seven
  workspace tests pass, including real listener/upstream/watcher tests that require
  permission to bind loopback ports.

## Not implemented

- Inbound TLS/HTTP2, WebSocket/upgrades, trailers/gRPC, OXT inheritance, and a
  self-contained executable snapshot artifact.
- Cluster health checks/retries, WASM/plugins, ACME, Web UI, Kubernetes integration,
  HTTP/3, and a general-purpose cache server.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed and reports missing fields as `Null`; Oxista
  enforces its configured strict-undefined policy at template interpolation.
- `compile` writes a deterministic inspection manifest, not a portable executable
  snapshot containing site assets or connection state.
- Semantic diagnostics retain file and field path but do not yet recover exact
  scalar lines for every lowering error.
- OXT `extends`/`block` is explicitly rejected; inheritance is not claimed.
- OXT JSON output is rejected in favor of structured OXR JSON. `safe_html` is also
  rejected until the Value model can represent audited provenance.
- Symlinked files are checked against the canonical root, but their alias path is not
  indexed in this release; directory symlinks are rejected rather than traversed.
- Asset negotiation is HTTP/1.1 only. Range forces identity, multipart ranges are
  deliberately rejected, and this is not a general content-negotiation framework.
- Listener serving supports HTTP/1.1 only. TLS, HTTP/2, upgrades, trailers, gRPC,
  and `100-continue` policy remain unimplemented.
- Cluster health checks, retry policy, stable per-cluster health state, and
  configurable Forwarded trust policy are not implemented. The current secure
  default always replaces incoming forwarding metadata.
- The response-header timeout currently bounds connect plus upload/header latency as
  one deadline; per-phase connect/write timing is not separately observable yet.
- Explicit slow-client and upstream-mid-body disconnect campaigns remain, though
  active drain, timeout abort, and dropped-body cancellation paths are tested.
- The portable watcher polls every 500ms. An edit that preserves path, byte length,
  and filesystem modification timestamp could be missed until another dependency
  changes; triggered preparation itself uses full content fingerprints. Failed
  candidate dependencies and edits during preparation are covered.
- Renaming a Listener while reusing its exact occupied address is rejected on
  platforms without safe port sharing, preserving last-known-good. Unchanged names
  and ordinary add/remove/address transitions are supported.
- Redirects currently allow only local absolute paths. Intentional cross-origin
  redirects require a future explicit allow policy.
- The admin listener is CLI-configured rather than part of the gateway source and is
  not dynamically rebound during config reload.

## Validation boundary

- Rust 1.88 was installed locally; MSRV workspace all-target/all-feature check and
  all 87 workspace tests passed.
- Stable formatting, workspace/all-target/all-feature Clippy with warnings denied,
  all 87 workspace tests, docs with warnings denied, and the release workspace build
  passed. Loopback tests ran with the required local permission.
- `cargo deny check` passed advisories, bans, licenses, and sources; one allowed
  indirect `syn` duplicate-version warning remains.
- All seven fuzz harnesses compile; no long fuzz campaign was run.
- Example `check`, three declarative tests, `explain`, and deterministic manifest
  compilation passed.
- The release-mode shared-graph smoke benchmark executed 100,000 short paths through
  a 4,097-node graph in about 171ms on this machine. This is a local regression
  smoke result, not a performance guarantee.
- Hosted CI is configured but has not run in this work session. Branch-protection
  settings were not changed or independently verified.

## Next concrete work

1. Add precise scalar source markers and richer multi-file diagnostics.
2. Run sustained fuzz, slow-client, and upstream mid-body disconnect campaigns with
   repeatable benchmark baselines.
3. Design the next explicit transport increment (inbound TLS and HTTP/2 lifecycle)
   without weakening snapshot pinning or graceful drain.
