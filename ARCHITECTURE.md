# Architecture

Oxidase treats gateway configuration as source code for a small declarative HTTP
Service language. The compiler resolves and validates that source, lowers syntax
sugar into a normalized Service plan, prepares referenced resources, and publishes
an immutable runtime snapshot. A listener pins one snapshot and executes its root
Service for the lifetime of each request.

The workspace is intentionally layered:

- `oxidase-core`: values, IDs, source locations, patterns, expressions, Service IR,
  and protocol-independent outcomes.
- `oxidase-config`: strict source models, import/reference resolution, diagnostics,
  and lowering.
- `oxidase-site`: the Oxista compiler and immutable site resources.
- `oxidase-runtime`: transactional request frames, Service execution, resources,
  snapshots, and publication.
- `oxidase-server`: the selected HTTP data plane, listener lifecycle, and proxy
  adapter.
- `oxidase-cli`: `check`, `explain`, `compile`, `test`, and `serve` commands.
- `oxidase-testkit`: reusable fixtures for integration and protocol tests.

Detailed constraints live in `docs/architecture/` and accepted decisions in
`docs/adr/`.

