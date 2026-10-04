# Resource lifecycle acceptance: phase 7A

Scope: 7A.1–7A.3 only. Actual clean protected starting main:
`495a906f267da979d8d5562947c421d56bd56ea8`.
Workspace remains `0.3.0-alpha.1`; Gateway `oxidase.dev/v1alpha1`, Oxista v1,
Bundle `oxidase.bundle/v1`, Admin `oxidase.admin/v1` remain alpha.
No Access Log, OpenTelemetry, packaging, tag or Release belongs to this task.

The source ownership decision is [ADR 0016](../adr/0016-resource-lifecycle-census.md).
This initial Draft records design and baseline, not completed implementation or
memory qualification. Three sequential protected PRs require independent final
head and merged-main checks. The phase-six positive RSS drift and null observations
remain historical UNKNOWN; no new experiment retroactively explains them.

## Baseline

All nine requested local commands executed on unchanged `495a906` and PASS:
fmt; locked workspace all-target/all-feature denied-warning Clippy; locked
workspace tests; locked no-deps denied-warning docs; cargo-deny; locked workspace
release build; locked Rust 1.88 all-target/all-feature check; locked Rust 1.88
workspace tests; locked fuzz-bin compile. Existing ignored manual tests were not
counted as executed. Baseline raw log and JSON receipt are retained locally in
`/private/tmp/oxidase-7a-baseline.JXaYo0/` pending evidence archival.
This is local macOS validation, not a Linux campaign or new Hosted check.

## Requirement ledger

| ID | Contract | Current evidence |
| --- | --- | --- |
| RL-01 | actual snapshot/Cluster/endpoint/admission units, Arc/value clone distinction | design; implementation NOT RUN |
| RL-02 | pool registry, Client family, physical IO and warm/task units separate | design; implementation NOT RUN |
| RL-03 | scheduled / waiting / executing / cancellation requested / actual task exit | design; implementation NOT RUN |
| RL-04 | observation owns no resources, pure reads and bounded scalar detail | design; implementation NOT RUN |
| RL-05 | old issued streams pin resources, new leases honor retirement | existing 6D invariants; new census proof NOT RUN |
| RL-06 | no-scrape Running retirement, 0/low/high scrape controls | NOT RUN |
| RL-07 | healthy and fault lanes fully validate DATA/trailers with all operations classified | NOT RUN |
| RL-08 | bounded fault windows and real recovery deadlines, AAAA/timeout/post-head failure | NOT RUN |
| RL-09 | warm / steady / recovery-running / quiet-running / post-drain measurements | NOT RUN |
| RL-10 | independent verifier rejects missing data, false healthy, leak and lost results | NOT RUN |
| RL-11 | exact implementation/tool/binary/PID identity and untruncated raw evidence | NOT RUN |
| RL-12 | evidence-driven attribution, necessary regression-backed fixes and Linux repeat | INCONCLUSIVE until executed |
| RL-13 | final-head and independent main CI for all three PRs | NOT RUN |

Implementation, bounded runtime qualification and memory attribution are separate
conclusions. Missing required data or unclosed attribution cannot become PASS
because code, an interface, a workflow, or a green build exists.
