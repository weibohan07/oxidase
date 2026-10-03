# Phase-six process qualification

This is a bounded alpha validation procedure, not production readiness or a
long-term reliability guarantee. Actual runs, commits, failures and artifacts
belong to [the acceptance ledger](discovery-acceptance.md). A workflow definition,
an ignored test or a compiled fuzz target is not an executed campaign.

## Distinct processes and resource attribution

The validation-only `oxidase-discovery-soak` binary is part of the existing soak
crate, not a production gateway or a second data plane. Its controller/load PID
starts the actual `oxidase serve` CLI gateway, a local DNS fixture and an upstream
fixture as separate processes. Fixtures acknowledge their own PIDs and ephemeral
addresses. No public DNS, fixed open port, OpenSSL, curl or Docker is required.
All generated signing keys, TLS identities and bearer tokens are test-only.
Private key/token bytes must not be copied to qualification artifacts.

On Linux, RSS and FD samples read `/proc/<gateway_pid>/status` and
`/proc/<gateway_pid>/fd`, never `/proc/self` in the controller. Raw authenticated
metrics, runtime and Cluster observations are retained with each sample. Missing
measurements, including unexported pool/old-snapshot/task counters, are `null`, not
invented zeroes. The old in-process soak output cannot substitute for this evidence.

Warm-up, steady load and cooldown have separate labels. The gateway remains alive
after load and terminal drain so idle resources can fall back before shutdown.
Inspect phase-specific slopes, peaks and recovery, not only baseline/final values;
allocator RSS need not become zero. Forced child termination is a failure, not a
successful graceful-drain measurement. Existing CLI shutdown uses SIGINT here;
this tool does not claim a new SIGTERM contract or deployment integration.

## Commands

```sh
cargo build -p oxidase-cli -p oxidase-soak --release --locked
target/release/oxidase-discovery-soak run \
  --gateway target/release/oxidase --campaign discovery \
  --duration 10m --concurrency 8 --seed 600601 --reload-interval 3s \
  --payload-size 32768 --warm-up 30s --cooldown 120s --sample-interval 1s \
  --output /tmp/oxidase-discovery-results
target/release/oxidase-discovery-soak run \
  --gateway target/release/oxidase --campaign protocol \
  --duration 2m --concurrency 6 --seed 600602 --reload-interval 3s \
  --payload-size 32768 --warm-up 30s --cooldown 120s --sample-interval 1s \
  --output /tmp/oxidase-discovery-protocol-results
```

Use fresh output directories. The tool validates bounded durations, concurrency
and payload limits. A short ordinary-CI smoke verifies process wiring; it is not
the ten-minute Linux campaign. Protocol coverage must observe actual TLS/H2 DATA,
gRPC trailers and HTTP/1 Upgrade bytes, signed Bundle activation/rollback and drain,
not merely count configured Service nodes.

Listener `bind: 0` avoids fixed-port assumptions. Bundle changes before drain
reuse its bound socket. Terminal drain is last: a later resume can select a new
ephemeral socket, and current Admin replies deliberately do not introduce a new
address-discovery/publisher API. Explicit public-operation resume is also covered
by the normal integration tests.

## Hosted manual qualification

The existing registered `External conformance` workflow has a separate
`discovery-qualification` dispatch choice. It skips external suite downloads,
builds with the lockfile, runs both campaigns on Ubuntu and uploads original logs,
PID-scoped time series, summaries, exact revision/dirty state and environment even
when a campaign fails. Run it against the exact qualification branch/head:

```sh
gh workflow run conformance.yml --ref hardening/v0.4-discovery-qualification \
  -f suite=discovery-qualification -f qualification_duration=10m \
  -f qualification_concurrency=8 -f qualification_seed=600601
```

A dispatch run does not replace the final PR head's four required CI checks or
the independent merged-main push run. All three evidence classes stay separate.

## Scope boundaries

DNS generation cannot publish configuration, amend Admin ETags/origin/history,
clear durable recovery fencing or reopen drained listeners. DNS fixtures and
workload control never write SnapshotStore directly. Existing stage/activate,
rollback and reload-source operations retain their own authentication, permission,
CAS, idempotency and completion semantics.

This task does not add OpenTelemetry, a new access log, Docker/systemd/release
packaging, DNSSEC/DoH/DoT, dynamic Admin bootstrap, a version bump or a Git release.
