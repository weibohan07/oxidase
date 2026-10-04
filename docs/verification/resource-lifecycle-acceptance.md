# Resource lifecycle acceptance: phase 7A

Scope: 7A.1–7A.3 only. Actual clean protected starting main:
`495a906f267da979d8d5562947c421d56bd56ea8`.
Workspace remains `0.3.0-alpha.1`; Gateway `oxidase.dev/v1alpha1`, Oxista v1,
Bundle `oxidase.bundle/v1`, Admin `oxidase.admin/v1` remain alpha.
No Access Log, OpenTelemetry, packaging, tag or Release belongs to this task.

The source ownership decision is [ADR 0016](../adr/0016-resource-lifecycle-census.md).
Draft [PR #20](https://github.com/weibohan07/oxidase/pull/20) records the first
implementation; it does not qualify memory. Three sequential protected PRs require independent final
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

## 7A.1 implemented boundaries and development executions

Real guards now cover snapshot instances/runtime preparation, Cluster and shared
runtime, endpoint/admission family, issued permits and DNS leases, scheduled
supervisors, quota-waiting/executing probe/query futures, negative memo entries,
Proxy/Health registry entries and Client clone families, physical TCP/TLS IO,
connect/handshake/warm/expiry/upload/owned-executor/dispatch-cleanup work, response
adapters and trusted tunnels. Units/coverage and allowed current retention are
defined in [operations](../operations/resource-observation.md), not inferred from
map lengths. Capture windows/sequences are explicitly non-atomic. Pure
observation does not drive lifecycle maintenance or grant publication authority.

The confirmed pre-poll cleanup **accounting** bug has a real failing regression:
scheduled worker count remained 1 after runtime dropped its never-polled future.
Capturing its guard before spawn repairs the same test to workers=0 and actual
created/destroyed/live=1/1/0. This is not proof of a production memory leak or an
explanation of older RSS drift. Health empty-round pool retention is observed as
a separate hypothesis, not changed on speculation in this PR.

Executed development regressions (not final-head or Hosted acceptance):

- stable/Rust 1.88 runtime lifecycle and original library suites pass, including
  direct/Arc clone, actual 16-thread publication, controlled failed prepare,
  source-free Bundle, shared physical admission, TTL/health pure read and actual
  membership/lease last release; two old manual benchmarks remain ignored.
- stable/Rust 1.88 health/discovery/resolver suites pass 14/8/28 tests, including
  scheduled pre-poll abort, real blocked probe, global-quota cancellation, late
  DNS-send retirement and actual memo replacement/owner Drop.
- stable/Rust 1.88 upstream suites pass 46 tests and two held-H2 tests: native
  Client clone family, 5000 create/drop generations, registry retirement while
  DATA/status trailers finish, actual peer CANCEL/EOF, warm consumption/90s expiry/
  owner Drop and TCP/TLS close confirmation. TLS socket teardown may legitimately
  acknowledge RST instead of FIN; the test permits only those explicit close
  results, never arbitrary I/O success or ignored error.
- real Unix Admin route auth/read denial/HEAD/405 and complete runtime JSON/ETag/
  Arc identity invariance pass. Existing 24 Admin and six DNS/TLS/H2 wire tests
  also pass; no fifth-/sixth-stage assertion was skipped or relaxed.
- stable/Rust 1.88 new actual TLS/H2 Asset tests pass 2/2: flow-controlled old
  stream crosses normal manager reload, complete DATA/EOF/no-trailers or actual
  RST releases its retired snapshot while Running; same-connection new streams
  remain correct. No scrape or drain causes this release.
- Respond-body adapter tests verify complete DATA/trailers, error and cancellation
  across snapshot publication; all 100 intermediate samples are pure. Sampler
  missing/disabled series stay null; all three old null units have actual sources.

Initial environment-only loopback denial and development fixture failures are
retained in raw local logs, not silently labeled PASS. Final-head local/Hosted
receipts and merged-main CI are recorded on PR #20 after actual execution; the
design-only Draft head `f75b670` run `37183775955` passed four required jobs, but
cannot substitute for its final implementation head.

Implementation, bounded runtime qualification and memory attribution are separate
conclusions. Missing required data or unclosed attribution cannot become PASS
because code, an interface, a workflow, or a green build exists.
