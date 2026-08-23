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

## Currently runnable

- A v1alpha1 config can be compiled into normalized IR, checked, symbolically
  executed with a full node/route trace, and tested without opening a socket.
  Thirty-two workspace tests pass. It is not yet a network gateway because no
  production leaf adapter exists.

## Not implemented

- Oxista compiler, listener, production Proxy, and atomic reload. `serve` currently
  performs compilation and returns an explicit not-implemented error.

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

## Next concrete work

Implement `.oxsite`, `.oxr`, and the initial `.oxt` compiler; build a secure,
immutable `SiteSnapshot`; and add the required Oxista example site.
