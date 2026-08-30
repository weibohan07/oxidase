# Implementation status

Last updated: 2026-08-30

## Baseline

- active milestone branch: `feat/v0.4-portable-bundles`
- public starting point: v0.4 trust/mTLS merge `8f45b04`
- release line: `0.3.0-alpha.1`; Gateway remains `oxidase.dev/v1alpha1`, Oxista
  remains v1, and production readiness is not claimed

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
  parsing, exactly one PKCS#8/PKCS#1/SEC1 private key, positive key/leaf consistency,
  current-time validity for every chain entry, and leaf-first adjacent issuer-name
  plus signature verification. Expired, not-yet-valid, misordered, unrelated, or
  mismatched candidates fail with field diagnostics and preserve last-known-good.
  No private material enters Debug, diagnostics, manifests, logs, or metrics.
  Certificate/key paths remain reload dependencies. Reuse identity is the public
  chain digest; a candidate key is still parsed and matched before reuse.
- File-backed Secret Resources are bounded (64 KiB by default), require a regular
  file, preserve exact bytes, and stay out of compiler IR and inspection-safe
  summaries. Debug/Display/Serialize output is redacted; equal-length comparisons
  avoid data-dependent early exit. The shared allocation is zeroized on final drop,
  with explicit OS/cache/allocator limitations, and permissive Unix modes warn.
  Live runtime ConfigVersion uses an opaque per-prepared-resource token rather than
  exposing the deterministic Secret fingerprint. The deterministic compile/
  inspection identity excludes both Secret contents and those random activation
  tokens, so repeated manifests remain byte-stable and intentionally cannot
  distinguish Secret rotations.
- Trust Store Resources strictly accept a non-empty, certificate-only ASCII PEM
  bundle, normalize duplicate/order-equivalent DER, and provide a content-stable
  root set to inbound and upstream TLS. Secret, Trust Store, certificate, and key
  files all participate in candidate dependency watching; invalid rotation remains
  last-known-good.
- HTTPS listeners use rustls with safe TLS 1.2/1.3 defaults and an explicit ring
  crypto provider. Exact ASCII SNI names take precedence over one-label left-most
  wildcards and then the default certificate; SNI rules are checked against leaf
  subjectAltName during preparation. Handshakes have a configured timeout and ALPN
  advertises only enabled `h2`/`http/1.1` protocols. Each Listener also has a fixed
  128-handshake non-waiting concurrency gate; overload closes the new socket instead
  of queueing an unbounded task.
- HTTPS Listener client authentication supports `none`, `optional`, and `required`.
  Optional mode admits anonymous clients but rejects an invalid presented chain;
  required mode requires a chain verified by the configured Trust Store. Only
  verified, bounded leaf SHA-256/subject/DNS-SAN/URI-SAN metadata enters the request
  expression namespace. The subject is informational, and identity values are not
  metrics labels or automatic authorization roles.
- The inbound connection driver supports cleartext HTTP/1.1 and ALPN-selected HTTPS
  HTTP/1.1 or HTTP/2. HTTP/2 applies bounded concurrent-stream/header-list settings
  plus configured keepalive, and each request/stream pins the current snapshot at
  request start rather than pinning one Service snapshot for the entire connection.
  Request expressions expose connection-derived HTTP version and TLS enabled/SNI/
  ALPN/version metadata.
- HTTP/1 ingress defaults to 100 decoded fields and 64 KiB decoded head storage;
  these are now configurable Listener limits. An 8 KiB request target remains a
  conservative fixed bound in addition to the HTTP/1 header-read timeout.
  Duplicate/empty/missing Host, unsupported authority-form/CONNECT, and ambiguous
  targets fail before Service execution. Absolute-form and H2 authority replace any
  conflicting Host so expressions, forwarding metadata, and upstream Host observe
  one canonical value.
- Every Listener now compiles a finite ingress policy. Defaults are 10,000 active
  connections, 100 connections per normalized kernel peer IP, 2 minutes without
  wire progress, 30-second request- and response-body idle deadlines, 64 KiB/100
  decoded Headers, and 1,000 accepted requests or streams per connection. HTTP/1
  applies the request budget to sequential/keep-alive requests; HTTP/2 applies it to
  streams and retires the connection with GOAWAY after the last admitted stream.
  Total/per-IP accounting is RAII-owned by the retained socket and includes TLS
  handshakes and trusted Upgrade lifetimes. The peer map is capacity-bounded, evicts
  idle identities, normalizes IPv4-mapped IPv6, and never trusts forwarding Headers.
- Listener request/response body idle deadlines are progress deadlines, not total
  transfer durations. Request DATA is wrapped without collection; downstream body
  frame stalls and socket write stalls are classified as timeouts. Header count and
  decoded-size limits apply to both HTTP versions, with HTTP/2 also retaining its
  protocol-specific header-list ceiling.
- Bodyless/HEAD requests do not allocate the request-body timeout adapter. HTTP/1
  reserves independent bounded parser allowance for the request target and framing
  before applying the configured decoded Header budget.
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
- HTTPS Clusters support system roots, a custom Trust Store, or their union; an
  exact DNS/IP verification name; and an existing Certificate Resource as the
  upstream client identity. Proxy and active-health pools include the complete TLS
  policy digest, so trust, client-certificate, or verification-name changes cannot
  reuse incompatible connections. There is no certificate-verification bypass.
- Cluster resources prepare into immutable plans plus reload-compatible endpoint
  runtime state. Round robin, smooth weighted round robin, and weighted
  least-requests select only eligible endpoints; bounded Cluster/endpoint admission
  happens before request-body consumption. Active checks start only after commit,
  passive failure thresholds eject endpoints, and compatible reloads retain health
  and counters without a global state map.
- Active-health failure now uses an atomic conditional transition and cannot race
  with a passive ejection to overwrite `PassivelyEjected`. Active success at the
  configured threshold remains the one deliberate early-recovery path. Passive
  ejection expiry and a concurrent new ejection are serialized, and health-policy
  reloads isolate supervisor generations while retaining shared endpoint admission.
  Deterministic concurrent tests cover stale observations, admission, retry permits,
  supervisor activation, snapshot publication, body cancellation, and
  transport/tunnel guards.
- Retry is disabled by default. A retry requires an explicitly listed method and
  pre-response-head cause/status, an untried eligible endpoint, an available
  non-waiting retry permit, and an empty or explicitly bounded replay body. Buffer
  overflow returns 413 before an upstream attempt; post-head stream errors cannot
  retry or become Fallback.
- Symbolic Proxy explain output includes the Cluster protocol, load-balancing
  policy, health/retry/limit summary, and an explicit runtime-dependent endpoint
  selection note. Declarative tests can assert the Cluster resource, protocol, and
  load-balancing policy without pretending to predict live endpoint state.
- Three protection wrappers compile into the ordinary Service graph.
  `RequestBodyLimit` rejects a known oversized Content-Length before its child,
  otherwise counts streamed DATA (not trailers) and composes nested limits by their
  minimum. `ConcurrencyLimit` acquires before body consumption and retains its RAII
  permit through a handled response body or trusted Upgrade tunnel. `RateLimit`
  uses a monotonic token bucket keyed only by the actual peer IP or a Boolean,
  integer, or string lexical binding of at most 256 bytes. Missing/invalid bindings
  and a full non-evictable key map fail closed with 429.
- Peer and rate-key expiry use ordered bounded indexes rather than scanning the full
  configured capacity for each rotating rejected identity. Completed data-plane and
  admin connection tasks are reaped between accepts; the current admin listener has
  a fixed 256-live-connection safety cap pending its source-level control plane.
- Concurrency queues are bounded to `max_in_flight`; `queue_timeout: 0ms` is
  fail-fast. Concurrency state reuses the compiler-owned Service identity across
  compatible reloads so old active work remains counted while a new limit governs
  admission. Rate state reuses only when key source, rate, burst, `max_keys`, and
  `idle_ttl` all match. A changed rate policy starts a new bounded generation.
- Observe, Listener transport, and governance metric registries have finite
  reload-churn caps. Existing governance series update without allocating new label
  keys, and runtime peer/binding values never enter a series identity.
- Proxy body adapters preserve DATA, trailer, end-of-stream, and error frames.
  HTTP/2 retains only the exact `TE: trailers` value and rejects connection-specific
  fields; HTTP/1 continues to remove Connection-nominated and hop-by-hop fields. A
  TLS/H2 black-box fixture proves request/response trailers and opaque multi-message
  gRPC forwarding, including terminal `grpc-status` and `grpc-message` trailers.
- Request and response trailer guards reject late routing, authentication,
  request-condition, response-control, cookie, and representation-metadata fields in
  addition to framing/hop-by-hop and connection-derived forwarding identity fields.
  H2-to-H1 request trailers require an exact initial declaration; undeclared frames
  fail explicitly instead of being silently discarded by the H1 encoder. Malformed
  downstream body framing retains explicit provenance across Hyper's upstream client
  and maps to a safe 400 before any upstream response head rather than being
  misclassified as an upstream 502.
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
- The management listener also exposes deterministic read-only
  `GET /api/v1/clusters` status. Cluster/endpoint names, fixed policies and health
  states, active counts, result counters, transitions, and ejection remaining are
  visible; origins, request data, credentials, and certificate material are not.
  Prometheus Cluster labels are limited to configured names and fixed enums.
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
  Pattern/path tests, template-limit tests, and twelve cargo-fuzz harnesses cover the
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
- Security documentation inventories downstream/upstream/config/admin/file/DNS/
  telemetry trust boundaries and every current exhaustion owner/release path. A
  separate manual conformance workflow pins and SHA-256 verifies h2spec, Autobahn,
  tlsfuzzer, tlslite-ng, HTTPWookiee, and their direct Python wheels; normal CI has
  no dependency on those downloads. Raw results are uploaded per suite and are not
  interpreted as passing merely because a tool process exited zero.
- The PR1 local campaigns actually ran: h2spec covered 147 cases with no unexpected
  failure after exact-fingerprint triage of known protocol/tool divergences and
  focused raw-frame safety regressions; fixed tlsfuzzer probes passed 12/12;
  Autobahn covered 247 cases with no failed behavior; and HTTPWookiee ran 243 tests
  with no unexpected failure/error after fixing malformed-body 502 classification.
  Eight explicitly named HTTPWookiee parser-boundary divergences remain documented
  and backed by raw single-message tests. These are local results, not Hosted status;
  see `docs/security/conformance-audit.md`.
- `examples/secure-resilient-gateway` compiles an HTTPS H2/H1 Listener, test-only
  Certificate Resource, observed route, weighted H2 Cluster with health/retry/
  admission policy, and Oxista Site. Its local fixture configuration provides two
  H2-only HTTPS upstream listeners; the committed key is publicly known and clearly
  forbidden for production use.
- Portable `.oxb` artifacts use the explicit `oxidase.bundle/v1` container rather
  than serializing Rust compiler/runtime objects. The fixed network-order header,
  canonical JSON manifest/signature envelope, domain-separated SHA-256 identity,
  raw digest-ordered blob table, and parser allocations/counts are bounded. Unknown
  required capabilities, section schemas, format flags, or incompatible strict
  semantic runtime versions fail before preparation.
- Stable `oxidase.service-program/v1`, `oxidase.gateway-config/v1`, and portable Site
  DTOs reconstruct Patterns, Expressions, Templates, Listener transport, SNI/client
  authentication, Cluster policies, and Site snapshots without reading Gateway or
  Oxista YAML. Textual sockets, URLs, methods, status ranges, paths, references, and
  protocol settings are reparsed; expected Site IDs must match supplied sections.
- Bundle `embed` mode is the source default and deduplicates identical Asset bytes as
  uncompressed content-addressed blobs. Production startup streams the verified
  archive into an anonymous temporary spool, pins it, and serves bounded blob slices,
  including range responses; this requires bounded memory plus temporary disk up to
  the Bundle size. `reference` mode uses an explicit absolute/deployment-root path
  plus expected length/digest; current working directory is never an implicit base.
  Each unique verified reference is copied into an anonymous temporary spool, so
  both path replacement and later writes to the source inode are isolated from the
  published snapshot.
- Public certificate chains can be reconstructed from the artifact. Secret contents
  and certificate private keys are excluded; only typed, redacted runtime file
  references remain and are reopened/revalidated with explicit size bounds during
  candidate preparation. Ed25519 signatures cover the domain-separated canonical
  content digest, support multiple trusted verification keys for rotation, and
  leave content identity stable when another signature is attached.
- Bundle CLI operations build atomically, inspect with sensitive paths redacted by
  default, verify, diff, sign, and serve the compiled artifact. Bundle startup
  executes the same prepare/publish path without YAML and preserves listener/Cluster/
  Site/data-plane semantics. A bounded parser fuzz target also drives arbitrary and
  structured corruptions through verification, capability, inspect, and diff paths;
  harness compilation is not reported as a fuzz campaign.

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
- Listener connection/peer/header/request limits and the three protection wrappers
  are runnable on the existing HTTP/1.1 and HTTP/2 data plane. Request-body and
  admission rejection occur before child execution when determinable; post-head
  streaming failure cancels the stream rather than fabricating a replacement status.
- An HTTPS Listener can require or optionally request a client certificate from a
  configured Trust Store on HTTP/1.1 or HTTP/2. Verified client identity is visible
  to the existing expression/template namespace. HTTPS Cluster traffic and active
  checks can use custom roots and an upstream client Certificate Resource.
- A verified `.oxb` can start the same gateway without its Gateway/Oxista YAML
  sources. Embedded and referenced Assets remain streaming, and an invalid digest,
  signature policy, capability, sensitive reference, or portable section prevents
  publication rather than partially replacing the current snapshot.

## Not implemented

- gRPC-Web, OXT inheritance, and a portable executable snapshot of live process
  state.
- Cleartext h2c, ACME, OCSP stapling, user-configurable TLS cipher suites, HTTP/3,
  HTTP/2 extended CONNECT, arbitrary CONNECT tunneling, and WebTransport.
- Dynamic Cluster discovery, WASM/plugins, Web UI, Kubernetes integration, and a
  general-purpose cache server.
- Authenticated/staged Admin activation and rollback, DNS/SRV discovery, standard
  access-log/OpenTelemetry export, and deployment/release packaging remain future
  v0.4 PRs.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed and reports missing fields as `Null`; Oxista
  enforces its configured strict-undefined policy at template interpolation.
- `compile` writes a deterministic inspection manifest; portable deployment uses the
  distinct Bundle workflow. A Bundle contains compiled program/resource/Site data
  and optional Asset bytes, but never live connections, health state, limiter
  buckets, tasks, pools, or other process state.
- `oxidase.bundle/v1` is alpha. There is no encrypted/delta/remote-registry format,
  HSM integration, transparency log, or promise that unknown required semantics can
  be downgraded. Referenced Assets and sensitive runtime references must be provided
  separately at the explicit deployment root. Embedded and referenced Asset serving
  pins anonymous verified spools, so path replacement and later source-inode writes
  cannot redirect an old snapshot's bytes; digest-addressed artifact paths remain
  recommended operationally.
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
- H2-to-HTTP/1 request and response trailers require an initial trusted `Trailer`
  declaration; responses additionally require downstream `TE: trailers`. An unsafe
  or undeclared late field ends the body with a protocol error rather than being
  dropped. Wire fixtures cover H1-to-H2 request trailers and declared/rejected
  H2-to-H1 request and response cases. HTTP/1 Upgrade is Proxy-only and
  capability-gated; H2 extended CONNECT remains rejected.
- TLS uses rustls defaults for TLS 1.2/1.3. Inbound mTLS verifies against one custom
  Trust Store; upstream TLS can combine native and one custom Trust Store and can
  present one Certificate Resource. There is no CRL/OCSP revocation, certificate
  pinning, SPIFFE policy engine, automatic role mapping, ACME, custom cipher-suite
  policy, or automatic certificate issuance. SNI wildcards match exactly one
  left-most DNS label and must appear literally in the selected leaf certificate
  subjectAltName.
- Cluster endpoints are static configuration: dynamic DNS/service discovery,
  cross-process health consensus, hedging, and arbitrary retry scripting are not
  implemented. Retry never occurs after a downstream response head and request-body
  replay exists only through explicit bounded buffering. Configurable Forwarded
  trust policy is not implemented; the current secure default always replaces
  incoming forwarding metadata.
- The response-header timeout currently bounds connect plus upload/header latency as
  one deadline; per-phase connect/write timing is not separately observable yet.
- The adversarial streaming fixtures cover representative disconnect and timeout
  boundaries. Manual fuzz and soak tools are separate from ordinary CI; their
  existence is not evidence of a long-duration reliability campaign.
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
- Ingress governance is local to one Oxidase process. There is no trusted-proxy
  client-identity policy, distributed rate-limit store, cross-process connection
  budget, or arbitrary Header-derived limiter key. The actual kernel peer address is
  the only network identity; lexical binding keys are scalar and limited to 256
  bytes.
- A streamed request-body limit can return 413 only before a downstream response
  head is committed. If an upstream response has already begun, exceeding the limit
  cancels the body/upstream path and records a body error; HTTP does not permit
  replacing that already-sent head with a synthetic 413.

## Validation boundary

- Every milestone PR is required to pass the locked Rust 1.88 check/test, stable
  fmt/Clippy/test/doc/release-build, cargo-deny, and fuzz compile jobs before normal
  protected-main merge. Evidence is commit-specific; a green older workflow is not
  treated as proof for the current head.
- Loopback TLS/H2/gRPC/WebSocket/Cluster tests require permission to bind ephemeral
  ports. Ordinary CI runs bounded integration fixtures and does not run an indefinite
  soak or fuzz campaign.
- External conformance is a manually dispatched per-suite matrix using pinned Action
  commits, source checksums, an immutable Autobahn image digest, loopback fixtures,
  real failure exit propagation, and raw artifacts. Tool findings still require
  protocol-boundary triage; fetching or compiling a suite is not a campaign.
- Manual regression entrypoints cover TLS handshake plus H1/H2 traffic, SNI lookup,
  weighted/least-request selection, retry admission, health transitions, shared
  ServiceGraph execution, typed include/render, Site preparation, and RequestFrame
  evaluation. They print observations only and are not performance guarantees; see
  `docs/operations.md` for exact commands.
- The secure/resilient gateway and fixture upstream configurations pass the same
  compiler path as `serve`; live use of the publicly known test certificate requires
  an isolated local trust/host setup and is not a deployment recipe.

## Next concrete work

1. Build the authenticated Admin API with bounded candidate storage, signature-
   required stage/validate/activate, rollback history, RBAC, and audit redaction.
2. Add commit-activated DNS/SRV discovery, deterministic endpoint reconciliation,
   address policy, stale-if-error, and separate upstream phase timeouts.
3. Add bounded access logs and optional OpenTelemetry, deployment packaging, release
   artifacts, and commit-specific Linux qualification/fuzz evidence.
