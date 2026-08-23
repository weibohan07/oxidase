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

## Currently runnable

- The v0.2 workspace builds and its six Pattern regression tests pass. It is not yet
  a usable gateway.

## Not implemented

- Core Service executor, configuration compiler, Oxista compiler, listener, Proxy,
  atomic reload, and the v0.2 CLI.

## Known limitations

- Pattern custom regex deliberately supports only a conservative first subset.
- Workspace crates other than `oxidase-core` expose only their version boundary;
  no source configuration or request execution is advertised yet.

## Next concrete work

Implement typed values, expressions, immutable Service IR, transactional request
frames, and the pure in-memory Service executor for Phase 1.
