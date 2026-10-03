# Phase-six acceptance evidence

Scope: 6A–6D only. Actual starting protected main:
`ebfb7549bf9c1ddd91384cf85cff4098982b8acf`.
Gateway/Oxista/Bundle/Admin remain alpha and workspace stays `0.3.0-alpha.1`.
This is an evidence ledger, not a claim that in-progress stages are implemented.

## Baseline

The clean starting main passed all nine requested gates: fmt, workspace Clippy
all-target/all-feature with warnings denied, workspace tests, docs with warnings
denied, cargo-deny, release build, Rust 1.88 all-target/all-feature check, Rust 1.88
workspace tests, and locked fuzz-bin compilation. The raw generated baseline log
was saved at `/private/tmp/oxidase-phase6-baseline.PyNoGU` during this run.
Existing ignored manual benchmarks/soak were not counted as executed.

## Stage status

| Stage | Implementation | Local / Hosted / campaign evidence |
| --- | --- | --- |
| 6A transport identity/deadlines | in progress | baseline only; no final-head acceptance yet |
| 6B A/AAAA discovery | not implemented by this branch | NOT RUN |
| 6C SRV discovery | not implemented by this branch | NOT RUN |
| 6D integration/qualification | not implemented by this branch | NOT RUN |

Exact requirement-to-regression mappings and PR head/merge/run receipts are added
only after actual execution. DNS observations must never change PublishedRuntime's
ETag, origin, serving state or publication authority. No stage-seven work, version
bump, tag or Release belongs to this delivery.
