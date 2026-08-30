# Architecture

Oxidase treats gateway configuration as source code for a small declarative HTTP
Service language. The compiler resolves and validates that source, lowers syntax
sugar into a normalized Service plan, prepares referenced resources, and publishes
an immutable runtime snapshot. A listener pins one snapshot and executes its root
Service for the lifetime of each request.

The workspace is intentionally layered:

- `oxidase-core`: values, SHA-256 content identities, IDs, the renderer-neutral
  Diagnostic/SourceSpan model, patterns, expressions, lazy transactional request
  frames, Service IR, protocol-independent outcomes, and the stable portable
  Service-program DTO.
- `oxidase-source`: the shared strict YAML subset plus `SourceDocument<T>` original
  text and field-path span indexes.
- `oxidase-config`: strict source models, import/reference resolution, diagnostics,
  Certificate/Listener transport plans, immutable Cluster policies, lowering, and
  the stable portable Gateway transport/Resource DTO.
- `oxidase-site`: the single-scan `SiteSourceIndex`, typed lexical OXT compiler,
  immutable site resources, and stable portable Site/template DTOs.
- `oxidase-bundle`: the bounded `oxidase.bundle/v1` container, canonical manifest,
  raw content-addressed blobs, capability negotiation, inspection/diff, and
  domain-separated Ed25519 signing/verification.
- `oxidase-runtime`: transactional request frames, Service execution, prepared
  Certificate/TLS and Cluster plans, bounded endpoint state, resources, snapshots,
  and publication. Private signing material remains opaque and never enters Service
  IR.
- `oxidase-server`: the selected HTTP data plane, production Observe/body telemetry,
  listener socket/transport lifecycle, rustls handshakes, ALPN-selected HTTP/1.1 or
  HTTP/2 connection drivers, active Cluster supervisors, the streaming proxy/body
  adapter, protocol-aware trailer handling, and trusted HTTP/1 Upgrade tunnels.
- `oxidase-cli`: source and Bundle build/inspect/verify/diff/sign/serve commands plus
  the final human/JSON diagnostic rendering boundary.
- `oxidase-testkit`: reusable fixtures for integration and protocol tests.

Detailed constraints live in `docs/architecture/` and accepted decisions in
`docs/adr/`.

Listener sockets and immutable transport plans have separate lifetimes. Reload can
retain a socket while atomically publishing a new certificate, protocol settings,
and Service snapshot. A newly accepted connection captures that transport plan;
existing TLS connections retain their old rustls state. HTTP requests, including
individual streams on a long-lived HTTP/2 connection, pin the current
`RuntimeSnapshot` only when the request starts. Listener retirement drives HTTP/1
graceful shutdown or HTTP/2 GOAWAY, then aborts only after the bounded drain period.

Inbound TLS and Hyper remain confined to runtime/server layers. `oxidase-core`
contains only protocol-neutral request metadata (`http_version` plus safe TLS
connection facts), so Service Algebra, Oxista, expressions, and patterns do not
depend on rustls or Hyper types.

Cluster preparation and activation are separate. A candidate snapshot builds or
reuses `PreparedCluster` endpoint state without starting permanent work. Publication
activates active-health supervisors; weak ownership and old snapshot lifetimes stop
them after removal. Compatible reload reuse requires the Cluster Resource ID,
endpoint name, canonical URL, and upstream protocol to match. Selection, health,
passive ejection, admission, and retry state remain owned by that Resource instead
of a global registry.

The data plane preserves Hyper frames through timeout, telemetry, Proxy, and
protocol adapters. H2 trailers therefore remain trailers for transparent gRPC.
HTTP/1 Upgrade is a private capability produced only by the validated Proxy path;
ordinary Service responses still pass through the same protocol-aware finalizer and
cannot opt into hop-by-hop framing.

Portable Bundle loading joins independently versioned stable sections for the
Service graph, Gateway transport/resources, and Site snapshots. Every textual URL,
socket, method, status, SNI rule, expression, Pattern, Template, and resource
reference is reparsed and cross-checked before runtime preparation. No YAML is read
on this path, and no regex, Hyper, rustls, pointer, task, socket, pool, limiter, or
health-state object is deserialized. Expected Site IDs must exactly match supplied
Site sections.

Bundle Asset storage preserves the existing data plane. Embedded representations
are raw, digest-ordered file slices read from a verified anonymous spool; replacing
or rewriting the original Bundle cannot change an old snapshot. Referenced Assets
are resolved only from an explicit absolute/deployment-root base, have their length
and SHA-256 digest verified, and are copied into snapshot-owned verified spools
before publication. Secret bytes and certificate private keys remain file-backed
runtime references; public certificate chains may be carried in the Bundle. The
loader still executes prepare, validate, commit, and drain, so a Bundle is a
deployment representation of the program rather than a second runtime or a
serialization of live state.
