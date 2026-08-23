# Contributing

Read `AGENTS.md`, `ARCHITECTURE.md`, and the relevant ADR before changing behavior.
New features must preserve the Service/Resource boundary, three-state outcome
semantics, transactional frames, compile-before-publish pipeline, and streaming body
defaults.

Use Conventional Commits and keep logical commits buildable. Before submitting:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

HTTP tests bind ephemeral loopback ports. If a sandbox denies socket binds, run the
same command in an environment that permits local networking and report that
boundary explicitly.

Tests should target semantic boundaries and risks. Avoid tests for trivial getters
or field movement. Update `docs/implementation-status.md` whenever a capability or
known limitation changes, and add an ADR when a decision changes a public semantic
boundary.

Fuzz targets live under `fuzz/` and run with `cargo fuzz run <target>`. A manual
release-mode executor smoke benchmark is available with:

```bash
cargo run --release -p oxidase-runtime --example service_program_bench
```
