# Oxidase contributor contract

These instructions apply to the entire repository.

Oxidase v0.3 is a declarative HTTP Service program compiler and runtime. Treat the
files that remain under the historical root `src/` as v0.1 reference material, not
as the architecture to extend.

## Architectural invariants

- A listener binds to any root Service. A Router is source syntax and must compile
  into the same Service plan used by every other configuration form.
- Preserve the `Handled`, `Declined`, and `Failed` distinction. HTTP error status
  codes are handled responses; fallback advances only on `Declined`; recovery is
  explicit.
- Service programs and shared resources are separate graphs. In particular,
  `Proxy` is a Service and `Cluster` is a Resource; `Site` is a Service and
  `SiteSnapshot` is a Resource; Certificate material is a Resource and never a
  user-visible Service.
- Parse and compile configuration, patterns, expressions, templates, and sites
  before publication. Request handling must not interpret source files.
- Request overlays and lexical bindings are transactional. A declined or failed
  candidate must not leak captures or request mutations into its siblings.
- Request and response bodies are streaming by default. Never add an unconditional
  body collection step or construct a new upstream client per request. Retry body
  replay is allowed only behind explicit bounded configuration.
- A request pins one immutable runtime snapshot. Failed reloads retain the current
  last-known-good snapshot.
- Listener sockets, immutable TLS/HTTP plans, and request snapshots have distinct
  lifetimes. Preserve certificate rotation without rebind, per-stream snapshot
  pinning, and graceful HTTP/1/H2 retirement.
- Prepared Cluster runtime state belongs to its Resource. Failed candidates must
  not start health tasks; reload reuse must validate Cluster ID, endpoint name,
  canonical URL, and protocol; permits and counters must be cancellation-safe.
- Preserve frame semantics across every body adapter: DATA, trailers, end of stream,
  and errors. A trusted HTTP/1 Upgrade capability must never be constructible from
  Gateway or Oxista source.
- Site source files (`*.oxsite`, `*.oxr`, `*.oxt`), template roots, private
  directories, and backing assets governed by OXR are never public assets.

## Engineering workflow

- Keep internal crate dependencies directed: core -> site/config -> runtime ->
  server -> cli. Do not introduce a cycle to save a small amount of code.
- Keep Hyper, rustls, and connection-driver types out of `oxidase-core`, Oxista, and
  the general expression/pattern layers.
- Prefer concrete enums, immutable plans, and explicit errors. Add a trait only at
  a real boundary with multiple consumers (for example, the runtime/data-plane
  boundary).
- Use Conventional Commits and keep logical commits buildable.
- Before a logical commit run the relevant tests. Before handoff run formatting,
  workspace Clippy with warnings denied, workspace tests, and workspace docs.
- Update `docs/implementation-status.md` whenever an advertised capability or a
  known limitation changes. Do not describe planned or stubbed behavior as done.
