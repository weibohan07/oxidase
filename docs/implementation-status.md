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

## Currently runnable

- A complete Service graph can be executed against an in-memory leaf adapter and
  produces a node/route trace. Twenty-four workspace tests pass. It is not yet a
  network gateway because no source compiler or production leaf adapter exists.

## Not implemented

- Configuration compiler, Oxista compiler, listener, production Proxy, atomic
  reload, and the v0.2 CLI.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Expression evaluation is typed but currently reports missing fields as `Null`;
  Oxista strict-undefined policy is not wired yet.
- Site and Proxy are real Service nodes but only their runtime leaf boundary exists;
  no production I/O implementation is advertised yet.

## Next concrete work

Implement the strict v1alpha1 source AST, imports/references, diagnostics, lowering,
and `check`/`explain` commands through the same compilation pipeline.
