# Bounded property-driven fuzzing

The fuzz workspace uses its own locked `Cargo.lock`. Ordinary CI only runs
`cargo check --manifest-path fuzz/Cargo.toml --bins --locked`; that is compilation,
not evidence of a campaign. `cargo-fuzz` does not expose a `--locked` switch, so
manual campaigns use offline Cargo and compare the lockfile digest before/after.

## Discovery targets

- `discovery_runtime` drives the production A/AAAA/SRV membership API, two-stage
  target/address selection, policy replacement, health callbacks, retry
  reservations, cancellation/drop and owner retirement. Each input has at most
  128 operations and 8 held leases. A fresh paused current-thread Tokio runtime
  advances monotonic time without sleeping. Assertions check fixed DialTargets,
  logical origins, bounded membership/state, owner fencing, original expiry plus
  finite stale grace, and complete permit release. It opens no network socket or
  resolver. Test addresses are documentation values or local policy examples.
- `portable_discovery` decodes raw and derived source-free runtime-plan JSON,
  discovery policy and all six phased durations. It reaches actual reference-free
  HTTP snapshot preparation, checks canonical round trips, rejects incomplete or
  unknown policy, and verifies that an executable capability stripped from a
  digest-valid Bundle is still rejected by the runtime decoder. Arbitrary Secret,
  certificate and TLS-root references are never opened. No DNS query is made.

Both targets bootstrap a valid compiled fixture once per process, remove its
YAML source, and keep real semantic success paths hot instead of rejecting nearly
all random bytes at the first parser boundary. The runtime input is a sequence of
12-byte zero-padded operations; the portable input selects a bounded mutation and
also attempts raw JSON decoding. Seed inputs are included under `seeds/`.

The same property drivers have deterministic seed/operation smoke tests:

```sh
cargo test --manifest-path fuzz/Cargo.toml --test discovery_seed_drivers --locked
```

These tests execute each operation/policy-mutation branch and 32 fixed-seed mixed
programs. They are not libFuzzer campaigns or network/concurrency qualification.

Actual local ASan campaigns ran on clean implementation
`9812a2db26d3f973e74cdae4c6eab7f13a9833b7`, using cargo-fuzz 0.13.2 and
Rust nightly 1.100.0 (2026-08-29), dev/debug assertions and offline Cargo:

| Target | Seed | Actual fuzz seconds | Executions | Corpus files before/after | Peak fuzzer RSS MiB |
| --- | --- | --- | --- | --- | --- |
| discovery_runtime | 600401 | 61 | 1050 | 2 / 289 | 244 |
| portable_discovery | 600402 | 61 | 238 | 2 / 59 | 445 |

Both exited zero, with no crash, timeout, OOM or failure artifact. The head,
source-set SHA-256 and both lockfiles were unchanged before/after each run. These
are bounded macOS aarch64 property campaigns, not Hosted campaigns, gateway RSS
measurements or proof of absence of bugs. Exact commands, tool versions, source
hashes, corpus statistics and raw logs are retained in
[`docs/verification/artifacts`](../docs/verification/artifacts/)
as `discovery-6d-asan-*-9812a2d.{json,log.gz}`; see the
[acceptance ledger](../docs/verification/discovery-acceptance.md).
