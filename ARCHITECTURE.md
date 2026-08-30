# Architecture

Oxidase treats gateway configuration as source code for a small declarative HTTP
Service language. The compiler resolves and validates that source, lowers syntax
sugar into a normalized Service plan, prepares referenced resources, and publishes
an immutable runtime snapshot. A listener pins one snapshot and executes its root
Service for the lifetime of each request.

The workspace is intentionally layered:

- `oxidase-core`: values, SHA-256 content identities, IDs, the renderer-neutral
  Diagnostic/SourceSpan model, patterns, expressions, lazy transactional request
  frames, Service IR, and protocol-independent outcomes.
- `oxidase-source`: the shared strict YAML subset plus `SourceDocument<T>` original
  text and field-path span indexes.
- `oxidase-config`: strict source models, import/reference resolution, diagnostics,
  Certificate/Listener transport plans, and lowering.
- `oxidase-site`: the single-scan `SiteSourceIndex`, typed lexical OXT compiler, and
  immutable site resources.
- `oxidase-runtime`: transactional request frames, Service execution, prepared
  Certificate/TLS plans, resources, snapshots, and publication. Private signing
  material remains opaque and never enters Service IR.
- `oxidase-server`: the selected HTTP data plane, production Observe/body telemetry,
  listener socket/transport lifecycle, rustls handshakes, ALPN-selected HTTP/1.1 or
  HTTP/2 connection drivers, and the streaming proxy adapter.
- `oxidase-cli`: `check`, `explain`, `compile`, `test`, and `serve` commands plus the
  final human/JSON diagnostic rendering boundary.
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
