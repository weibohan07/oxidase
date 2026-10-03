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

The planned ASan campaigns use cargo-fuzz 0.13.2, installed nightly, and at least
60 seconds per target, seeds 600401/600402. **Campaigns are not run yet.** Record
the exact commit and dirty/source/lock hashes, command, tool versions, duration,
execution/corpus statistics, peak RSS, exit status, artifacts and raw logs. A
bounded local campaign is not a Hosted campaign or proof of absence of bugs.
