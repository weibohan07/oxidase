# Implementation status

Last updated: 2026-08-30

## Baseline

- active milestone branch: `feat/v0.3-resilient-clusters`
- public starting point: protocol-bridging merge `150046085e58c71d88b322d2693a4e588e1d1d78`
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
- `Observe` has production semantics independent from explain tracing. Only explicit
  wrappers create structured response-head scopes with bounded configured-name,
  outcome, status-class, error-class, latency, listener, version, and nesting data.
  A separate streaming body adapter counts emitted bytes and classifies completion,
  body error, idle timeout, or downstream cancellation while keeping the normal
  execution trace sink disabled.
- Graph validation rejects implicit reference cycles, zero Reenter budgets, missing
  nodes, and body-consuming fallback candidates before later alternatives.
- Phase 2 strict `oxidase.dev/v1alpha1` source AST and compiler with one YAML subset
  shared by Gateway, `.oxsite`, `.oxr`, `.oxt`, and request documents. It rejects
  duplicate/unknown keys, anchors, aliases, merge keys, tags, tab indentation, and
  flow mappings while allowing flow sequences and correctly treating literal/folded
  block scalar contents as opaque text. Relative imports, import-cycle checks,
  named/inline Services, resource references, and Router lowering remain.
- `oxidase check`, symbolic `explain`, deterministic `compile` manifest, and
  declarative `test` commands all use the same compiler and normalized plans.
- Phase 3 Oxista compiler for strict `.oxsite`, `.oxr`, and `.oxt` sources. Site
  preparation validates typed inputs, scans once, builds a private/public index,
  compiles template dependencies, and produces an immutable `SiteSnapshot`.
- OXR supports Redirect, sibling/relative streaming Asset plans, text, empty,
  structured JSON, inline templates, and external templates with parameter
  contracts. OXT supports interpolation, `if/elif/else`, `for/else`, `with`, static
  `include`, comments, and raw blocks with autoescape and bounded execution.
- Static OXT include is a typed lexical call: a quoted target plus optional
  `with name=expression ...` and trailing `only`. Preparation rejects missing,
  unknown, duplicate, constant-type, and cycle errors. Dynamic values are checked
  at runtime; normal calls inherit caller locals, while `only` retains only the five
  read-only public roots before pushing explicit arguments. Child scopes and
  autoescape never leak back to parents.
- One shared `RenderBudget` charges every expression and loop body before execution,
  checks include depth before entry, checks output before append, and checkpoints
  time cooperatively. Nested includes cannot reset any budget; exactly N operations
  are allowed for a limit of N.
- HTML/text OXT output now controls default autoescape and Content-Type. Dynamic
  template arguments are checked immediately before render; URL means absolute URL,
  and `safe_html` is rejected until Value can carry trusted provenance. Unsupported
  or inert v1 field values fail with field-specific migration guidance.
- External OXT metadata preserves omission and inherits Site output/autoescape
  defaults before output-derived fallback. Custom 404 templates must be callable
  without required parameters, use their effective Content-Type/autoescape and
  receive `defaults.response` headers; HEAD preserves their full representation
  length without a body.
- Oxista header policies retain global, logical-extension, profile, and local OXR
  layers, with remove/set/add executed inside each layer. Ordinary assets now share
  `defaults.by_extension` with OXR-backed assets, including br/gzip responses.
- `visibility.deny` compiles exact relative paths, exact component-name rules, and
  exact final-extension rules with case-sensitive semantics. Invalid or ambiguous
  patterns fail at compilation; denied directories are pruned without skipping
  symlink escape validation.
- Required `basic-gateway` and `oxista-site` examples compile and their three
  declarative gateway tests pass. `check` now prepares every Site through the same
  path that reload will use.
- Phase 4 Tokio + Hyper HTTP/1.1 data plane with prepare-all listener binding,
  arbitrary root Service execution, connection-derived peer/scheme metadata, safe
  root outcome mapping, structured tracing fields, and bounded graceful drain.
- Certificate resources are prepared before publication with strict PEM/X.509
  parsing, exactly one PKCS#8/PKCS#1/SEC1 private key, positive key/leaf consistency
  validation, and no private material in Debug, diagnostics, manifests, logs, or
  metrics. Certificate and key paths remain reload dependencies. Reuse identity is
  the public certificate chain digest; a candidate private key is nevertheless
  parsed and matched on every preparation before old signing state can be reused.
- HTTPS listeners use rustls with safe TLS 1.2/1.3 defaults and an explicit ring
  crypto provider. Exact ASCII SNI names take precedence over one-label left-most
  wildcards and then the default certificate; SNI rules are checked against leaf
  subjectAltName during preparation. Handshakes have a configured timeout and ALPN
  advertises only enabled `h2`/`http/1.1` protocols. Each Listener also has a fixed
  128-handshake non-waiting concurrency gate; overload closes the new socket instead
  of queueing an unbounded task.
- The inbound connection driver supports cleartext HTTP/1.1 and ALPN-selected HTTPS
  HTTP/1.1 or HTTP/2. HTTP/2 applies bounded concurrent-stream/header-list settings
  plus configured keepalive, and each request/stream pins the current snapshot at
  request start rather than pinning one Service snapshot for the entire connection.
  Request expressions expose connection-derived HTTP version and TLS enabled/SNI/
  ALPN/version metadata.
- A retained listener socket loads the published transport plan for each accept.
  Certificate, Service, protocol, and HTTP-setting changes therefore affect new
  connections without rebinding, while existing TLS connections retain their old
  rustls state. Invalid certificate/SNI candidates never publish and last-known-good
  remains active. Retired HTTP/1 connections receive graceful shutdown; HTTP/2
  connections receive graceful shutdown/GOAWAY and are aborted only at drain expiry.
- Site bytes and assets are adapted to HTTP without default collection. Identity,
  Brotli, and gzip representations own independent length/ETag/mtime metadata.
  Quality negotiation, validator precedence, representation-aware 304, If-Range,
  suffix/open-ended/single ranges, HEAD, 406, and 416 are covered on the wire. Range
  applies only to GET; unknown units, malformed or multiple ranges, and ranges with
  identity excluded are ignored in favor of a full negotiated representation.
- Correctness identity is a complete 32-byte SHA-256 `ContentDigest`. Structured
  config, Site, Cluster, snapshot, and watch-stamp builders use explicit domains and
  length-prefixed fields. Config mappings canonicalize key order; Cluster endpoint
  order remains semantic. Strong representation ETags are
  `"sha256-<64 lowercase hex>"` over final bytes, with weak mode using `W/`.
- Candidate Site preparation is `scan -> SiteSourceIndex -> compile -> SiteSnapshot`.
  Each ordinary or compressed file is streamed for its digest once; Oxista text is
  retained, large Asset bytes are not, and unchanged indexes reuse the old
  `Arc<SiteSnapshot>`. Tests cover OXT/compressed changes, add/delete/rename,
  symlink-target identity, and one-read counters.
- One root `ResponseFinalizer` owns HTTP framing for Respond, Redirect, Site, Proxy,
  and Transform output. It strips hop-by-hop/untrusted framing metadata and enforces
  HEAD, 1xx, 204, 205, and 304 body semantics. Source header policy rejects direct
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
- Cluster source compiles `auto`, `http1`, or `h2` upstream protocol policy. The
  server owns one long-lived pool for each policy: `auto` uses HTTPS ALPN and
  cleartext HTTP/1, `http1` forces HTTP/1.1, and `h2` requires TLS H2 or uses
  cleartext H2 prior knowledge. Protocol changes participate in Cluster identity.
- Cluster resources prepare into immutable plans plus reload-compatible endpoint
  runtime state. Round robin, smooth weighted round robin, and weighted
  least-requests select only eligible endpoints; bounded Cluster/endpoint admission
  happens before request-body consumption. Active checks start only after commit,
  passive failure thresholds eject endpoints, and compatible reloads retain health
  and counters without a global state map.
- Retry is disabled by default. A retry requires an explicitly listed method and
  pre-response-head cause/status, an untried eligible endpoint, an available
  non-waiting retry permit, and an empty or explicitly bounded replay body. Buffer
  overflow returns 413 before an upstream attempt; post-head stream errors cannot
  retry or become Fallback.
- Symbolic Proxy explain output includes the Cluster protocol, load-balancing
  policy, health/retry/limit summary, and an explicit runtime-dependent endpoint
  selection note. Declarative tests can assert the Cluster resource, protocol, and
  load-balancing policy without pretending to predict live endpoint state.
- Proxy body adapters preserve DATA, trailer, end-of-stream, and error frames.
  HTTP/2 retains only the exact `TE: trailers` value and rejects connection-specific
  fields; HTTP/1 continues to remove Connection-nominated and hop-by-hop fields. A
  TLS/H2 black-box fixture proves request/response trailers and opaque multi-message
  gRPC forwarding, including terminal `grpc-status` and `grpc-message` trailers.
- HTTP/1 ingress and Proxy now carry a server-local trusted Upgrade capability.
  Validation requires a single protocol and matching upstream 101; non-Proxy
  Services and user Header policy cannot construct it. Focused tests cover malformed
  handshakes, H2/CONNECT rejection, protocol matching, partial-byte accounting,
  bidirectional copy, and first-EOF cancellation. Socket tests cover plain/TLS H1,
  both byte directions and close origins, reload with a pinned old tunnel and a new
  Listener, drain-time abort, non-Proxy 101 isolation, unsupported H2/h2c/CONNECT
  rejection, and bounded tunnel metrics.
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
- Failed Site preparation carries its structured error plus partial dependencies
  through runtime preparation into reload state. Existing invalid OXT/OXR files,
  missing templates, scanned assets, template roots, backing/precompressed
  candidates, and their parent directories remain watched and can recover without
  another Gateway edit.
- Retired HTTP/1 and HTTP/2 connections receive Hyper graceful shutdown. Idle
  keep-alive closes promptly, HTTP/2 stops admitting new streams, active requests
  finish on their pinned snapshot, and the drain timeout is the only point at which
  remaining tasks are aborted.
- Integration tests prove invalid and bind-conflicting reload rollback, listener
  retain/add/remove behavior, old long-running requests crossing a commit, and new
  requests immediately observing the new version.
- Phase 7 adds an opt-in, separately bound management listener with live/ready
  health and Prometheus text metrics. Outcome, status-class, latency, active request,
  and reload labels are fixed and bounded.
- Transport metrics use configured Listener names and fixed protocol/result enums
  for accepted and active HTTP/1 or HTTP/2 connections, TLS handshake
  result/duration, negotiated ALPN, active H2 streams, and graceful/forced H2
  shutdown. Trusted tunnels add started/active counts, two fixed byte directions,
  and fixed downstream-closed/upstream-closed/error/cancelled terminations. Dropping
  an unfinished tunnel records cancellation. Raw SNI, peer IP, paths, Upgrade
  protocols, certificate paths, and request data are not metric labels.
- Data-plane HTTP/1 mode and the management HTTP/1 listener use Hyper's timer-backed
  30-second request-header timeout. Real socket tests cover a stalled header, progress within
  the deadline, upstream mid-body truncation, paced versus stalled response bodies,
  client download cancellation, client upload cancellation, active-request cleanup,
  and post-failure pool reuse.
- Shared YAML parsing now returns `SourceDocument<T>` with original text and exact
  key/value byte plus line/column ranges. Gateway semantic lowering uses these
  ranges for listeners, references, endpoints, durations, Headers, Patterns,
  Expressions, and Transform metadata. OXR Header policies, OXT tokens, and include
  edges retain exact spans, including CRLF and Unicode-column tests.
- One renderer-neutral Diagnostic model now carries stable code, severity, exact
  primary span, secondary labels, related cross-file spans, notes/help, and
  structured import/include chains through config, Site preparation, Runtime, and
  reload. Site inputs relate the Gateway injection to the `.oxsite` declaration.
- `check`, `compile`, `test`, and `serve` accept a global human/JSON diagnostic
  format. JSON emits one deterministic `oxidase.diagnostics/v1` envelope with
  explicit path encoding and no ANSI or human stdout; I/O and bind failures remain
  valid JSON with a nonzero exit. Successful Explain keeps its own JSON document.
- `RequestFrame` lazily caches effective Headers, query values, request namespace,
  visible bindings, and its Arc-backed evaluation context. Unchanged clones share
  caches; binding children and mutable overlays invalidate only affected layers.
- Redirect and constant header validation fail closed; property-style generated
  Pattern/path tests, template-limit tests, and seven cargo-fuzz harnesses cover the
  highest-risk parsers and resolvers.
- Template rendering and argument validation use structured errors. Only
  output/loop/include-depth/expression-step/time budgets map to `TemplateLimit` for
  Recover; other render/argument/response failures map to `InvalidState`, and asset
  I/O remains `SiteIo`.
- CI has distinct Rust 1.88 MSRV, stable workspace, cargo-deny, and fuzz compile
  jobs. The stable job includes a release build and the workflow supports manual
  dispatch. Dependency-policy, security, contributing, operations, migration, and
  benchmark entrypoints are present. The superseded v0.1 implementation remains in
  Git history.

## Currently runnable

- A v1alpha1 config and Oxista site can be fully prepared, served over cleartext
  HTTP/1.1 or TLS HTTP/1.1/HTTP/2, executed in memory, explained, reloaded, observed,
  and tested. The integration suite includes real listener/upstream/watcher/TLS/H2
  tests that require permission to bind loopback ports; manual smoke benchmarks
  remain ignored by the ordinary test suite.
- An H2 Proxy with an explicitly H2 Cluster can transparently forward request and
  response trailers plus opaque gRPC DATA. The integration fixture verifies terminal
  gRPC status/message trailers without a gRPC-specific Service or protobuf parser.
- An HTTP/1 Proxy can transparently pass a validated generic Upgrade, including
  WebSocket traffic, over cleartext or TLS. Socket fixtures cover both byte/close
  directions, snapshot pinning across reload, new-Listener publication, bounded
  retirement drain, trusted-capability isolation, and tunnel telemetry.
- A Proxy backed by a prepared Cluster applies configured load balancing, health
  eligibility, bounded admission, and safe pre-head retry while preserving the
  same streaming H1/H2 pools and request-pinned snapshot semantics.

## Not implemented

- gRPC-Web, OXT inheritance, and a self-contained executable snapshot artifact.
- Cleartext h2c, client-certificate authentication/mTLS, ACME, OCSP stapling,
  user-configurable TLS cipher suites, HTTP/3, HTTP/2 extended CONNECT, arbitrary
  CONNECT tunneling, and WebTransport.
- Dynamic Cluster discovery, WASM/plugins, Web UI, Kubernetes integration, and a
  general-purpose cache server.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed and reports missing fields as `Null`; Oxista
  enforces its configured strict-undefined policy at template interpolation.
- `compile` writes a deterministic inspection manifest, not a portable executable
  snapshot containing site assets or connection state.
- Gateway and the implemented `.oxsite`/`.oxr`/`.oxt` semantic checks now retain
  exact ranges and structured cross-file relationships. The JSON schema is alpha;
  successful Explain remains its separate explain schema, and non-fatal live reload
  events remain structured operational logs on stderr rather than additional JSON
  documents on stdout.
- Generated inline Service/Route IDs are deterministic within one source program
  but can change when the import set changes. They are alpha inspection identities,
  not durable API keys, metrics labels, control-plane IDs, or configuration refs.
- OXT `extends`/`block` is explicitly rejected; inheritance is not claimed.
- OXT JSON output is rejected in favor of structured OXR JSON. `safe_html` is also
  rejected until the Value model can represent audited provenance.
- Symlinked files are checked against the canonical root, but their alias path is not
  indexed in this release; directory symlinks are rejected rather than traversed.
- Asset negotiation is not a general content-negotiation framework. Range is
  implemented only for GET and only for one bytes range;
  unknown units, malformed syntax, and multipart ranges are deliberately ignored.
- Cleartext listeners support HTTP/1.1 only; configuring `h2` is rejected because
  h2c is not implemented. HTTPS listeners support HTTP/1.1 and HTTP/2 through ALPN,
  and H2-to-H2 Proxy paths preserve validated trailers. Basic transparent gRPC
  forwards opaque DATA and terminal trailers only; protobuf inspection, gRPC-Web,
  and a new `100-continue` policy remain unimplemented.
- H2-to-HTTP/1 response trailers require both downstream `TE: trailers` and an
  initial trusted `Trailer` declaration; an unsafe or undeclared late field ends the
  body with a protocol error rather than being dropped. Wire fixtures cover both
  H1-to-H2 request trailers and declared/rejected H2-to-H1 response cases. HTTP/1
  Upgrade is Proxy-only and capability-gated; H2 extended CONNECT remains rejected.
- TLS uses rustls defaults for TLS 1.2/1.3. Client certificates/mTLS, ACME, OCSP
  stapling, custom cipher-suite policy, and automatic certificate issuance are not
  implemented. SNI wildcards match exactly one left-most DNS label and must appear
  literally in the selected leaf certificate subjectAltName.
- Cluster endpoints are static configuration: dynamic DNS/service discovery,
  cross-process health consensus, hedging, and arbitrary retry scripting are not
  implemented. Retry never occurs after a downstream response head and request-body
  replay exists only through explicit bounded buffering. Configurable Forwarded
  trust policy is not implemented; the current secure default always replaces
  incoming forwarding metadata.
- The response-header timeout currently bounds connect plus upload/header latency as
  one deadline; per-phase connect/write timing is not separately observable yet.
- The adversarial streaming fixtures cover representative disconnect and timeout
  boundaries, but no long-duration memory/fd soak or sustained fuzz campaign is
  claimed.
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

- Rust 1.88 was installed locally; the locked MSRV workspace
  all-target/all-feature check and locked workspace test suite passed.
- Stable formatting and locked workspace/all-target/all-feature Clippy with warnings
  denied passed. The current diagnostic branch has 154 passing non-ignored workspace
  tests and four ignored manual benchmarks/soaks; loopback tests ran with the required
  local permission. Final docs, release, MSRV, deny, and fuzz gates are rerun before
  PR publication.
- `cargo deny check` passed advisories, bans, licenses, and sources; one allowed
  indirect `syn` duplicate-version warning remains.
- All seven fuzz harnesses compile; no long fuzz campaign was run.
- Protocol-bridging targeted validation passed seven trusted-Upgrade unit tests,
  six trailer/gRPC/reset loopback tests, and five plain/TLS Upgrade socket tests.
  These results cover the supported cross-protocol trailer and HTTP/1 WebSocket
  matrix, but do not stand in for the final locked workspace or hosted gates.
- Example `check`, three declarative tests, `explain`, and deterministic manifest
  compilation passed.
- Release-mode local smoke measurements on this machine: 100,000 short executions
  through one shared 4,097-node graph in about 58ms; 100,000 cached RequestFrame
  contexts in about 0.49ms; 50,000 typed-include renders in about 40ms; Site scan /
  compile around 20ms / 3ms for 1,000 assets and 250ms / 39ms for 10,000 assets.
  These are regression observations, not performance guarantees.
- The ignored manual proxy soak harness was exercised for 20 keep-alive iterations
  with periodic reload plus downstream cancellation and an 8 MiB Asset. This was a
  short harness validation, not a sustained soak claim.
- Semantic-closure PR #3 passed all four required jobs in run `32657427210`, and its
  merged `main` push passed run `32657645424`, including Ubuntu loopback tests and
  the stable release build. `main` branch protection was enabled and read back with
  strict/up-to-date required checks for `MSRV 1.88`, `Stable workspace`,
  `Dependency policy`, and `Fuzz harness compile smoke`; signed commits and admin
  enforcement remain off.

## Next concrete work

1. Complete the resilient-Cluster PR's locked local and hosted gates without
   weakening streaming or retry boundaries.
2. Add the secure/resilient example and operator documentation for the compiled
   Cluster contract.
3. Add sustained protocol/cluster fuzz and soak campaigns during final v0.3 alpha
   hardening; ordinary CI should retain only bounded integration smoke coverage.
