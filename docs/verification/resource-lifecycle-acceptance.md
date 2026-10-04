# Resource lifecycle acceptance: phase 7A

Scope: 7A.1–7A.3 only. Actual clean protected starting main:
`495a906f267da979d8d5562947c421d56bd56ea8`.
Workspace remains `0.3.0-alpha.1`; Gateway `oxidase.dev/v1alpha1`, Oxista v1,
Bundle `oxidase.bundle/v1`, Admin `oxidase.admin/v1` remain alpha.
No Access Log, OpenTelemetry, packaging, tag or Release belongs to this task.

The source ownership decision is [ADR 0016](../adr/0016-resource-lifecycle-census.md).
[PR #20](https://github.com/weibohan07/oxidase/pull/20) records the first
implementation; it does not qualify memory. Three sequential protected PRs require independent final
head and merged-main checks. The phase-six positive RSS drift and null observations
remain historical UNKNOWN; no new experiment retroactively explains them.

## Baseline

7A.1 final head `e3b34744b88c55eea132c774fa10deba0358b577` passed all nine
requested local gates and the four required Hosted jobs in run `37186858528`.
It was normally merged as `7bd6d486d89aeb19e6785d65d15600a7435d6925`.
The independent main push run `37187599520` also passed all four jobs. Those are
implementation receipts, not a Linux memory/campaign qualification. 7A.2 starts
from this merged main and preserves all historical failures.

7A.2 final head `98c5de65c1d515ea60cab9a956533c4386de2be0` passed all nine
local gates and four final-head required jobs (`37196664266`). Normal merge
`54b0fc65be52b72f3354791674905b9205277f3a` independently passed main push
`37197386244`. Both stable and Rust 1.88 Linux jobs executed the actual resource
implementation smoke and independent adversarial corpus; earlier failures below
were not overwritten. The 61-second ASan `discovery_runtime` campaign at that
head executed 3304 inputs with seed 600401, no crash/timeout/OOM; 538 MiB peak RSS
belongs to the **fuzzer**, not the gateway. This does not prove retention bounds.

7A.3 Draft PR #22 starts from `54b0fc6`. Its first normal-release, separate-runner
H/C pilot (`37197630141`, seed 700211) failed. The original archives and replay,
confirmed validation defects, resident curves and remaining attribution gaps are
in [the attribution ledger](resource-retention-attribution.md). New tool head
`6ccab8e81602f549f0d2a0c1138d659e9c2006bc` requires separate repeat evidence;
its green build alone cannot close those failures.

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
| RL-01 | actual snapshot/Cluster/endpoint/admission units, Arc/value clone distinction | PASS_IMPLEMENTATION: PR #20 final-head and merged-main gates; campaign qualification pending |
| RL-02 | pool registry, Client family, physical IO and warm/task units separate | PASS_IMPLEMENTATION: held-H2, actual IO close and warm expiry regressions; library-private internals not inferred |
| RL-03 | scheduled / waiting / executing / cancellation requested / actual task exit | PASS_IMPLEMENTATION: blocked probe/query, pre-poll cancellation and late callback regressions |
| RL-04 | observation owns no resources, pure reads and bounded scalar detail | PASS_IMPLEMENTATION: 5000 generations, disabled/missing series and authenticated pure reads |
| RL-05 | old issued streams pin resources, new leases honor retirement | PASS_IMPLEMENTATION: real old TLS/H2 stream/Asset publication and cancellation; campaign pending |
| RL-06 | no-scrape Running retirement, 0/low/high scrape controls | PASS_IMPLEMENTATION; three complete Linux Respond controls, positive drift INCONCLUSIVE and no-scrape Running lifecycle unavailable |
| RL-07 | healthy and fault lanes fully validate DATA/trailers with all operations classified | PASS_IMPLEMENTATION; full H wire/conservation verified, final C has 5 unwindowed 504s + missing cancel ACK and remains FAIL |
| RL-08 | bounded fault windows and real recovery deadlines, AAAA/timeout/post-head failure | PASS_IMPLEMENTATION: strict oracle and regression-backed repairs; final normal IPv6 control 504 remains FAIL, no whole C qualification |
| RL-09 | warm / steady / recovery-running / quiet-running / post-drain measurements | formal H completed all minima with actual Running reclamation; original INCONCLUSIVE, all C attempts so far stopped early |
| RL-10 | independent verifier rejects missing data, false healthy, leak and lost results | PASS_IMPLEMENTATION: negative corpus and actual Hosted artifact rejections; never promotes controller claim to PASS |
| RL-11 | exact implementation/tool/binary/PID identity and untruncated raw evidence | PASS_IMPLEMENTATION; sealed formal H and original C/provider/per-file/frozen-replay indices, earlier truncated C remains FAIL |
| RL-12 | evidence-driven attribution, necessary regression-backed fixes and Linux repeat | INCONCLUSIVE: real native allocation capture, multiple preserved Linux repeats and regression-backed tool repairs; no proven production-retention defect or full memory attribution |
| RL-13 | final-head and independent main CI for all three PRs | PR #20 and #21 PASS; PR #22 Draft, final delivery pending |

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

### Intermediate final-gate failures retained

Head `c800823` ran Hosted `37185387986`: stable Clippy failed at a duplicated
test-only `Connection as _` import under Rust 1.99; MSRV failed in process
qualification. Its local complete gate also stopped at the two real process
smokes: the new passive view had accidentally reported stored weak slots in the
older `retired_admission_counters` field, while that field means still-outstanding
noncurrent physical admission. It must retain that active-family projection and
report raw weak storage separately, without pruning on read or changing leases.
The old smoke's actual zero-active assertion is not removed or relaxed. New
health/pool/snapshot observations likewise replace obsolete null assertions with
real unit-specific checks; bounded current registry ownership is not forced to
zero after drain. Required checks must rerun on the repaired head.

Implementation, bounded runtime qualification and memory attribution are separate
conclusions. Missing required data or unclosed attribution cannot become PASS
because code, an interface, a workflow, or a green build exists.

The final implementation repeat is recorded in the
[attribution ledger](resource-retention-attribution.md#final-implementation-repeat-and-delivery-boundary).
It preserves final C `37211766238` FAIL, not a tool-generated success: all 62870
operations were conserved, but normal IPv6/worker 504s and a missing ACK remain.
Its recovery/Quiet never started. Full H met time minima and had no unexpected
outcome, but still has TLS-close, structural-capacity and resident-attribution
INCONCLUSIVE criteria. **7A 尚未完整通过** even if all three implementation PRs
are normally merged with independently green required/main checks.

## 7A.2 original Hosted failures (not qualification results)

PR #21 base is `7bd6d486d89aeb19e6785d65d15600a7435d6925`.
Foundation `adf38d68d521934a93d213b9acdf4cf23e6767c1` had four successful
required jobs in `37188449757`; this predates the actual campaign code.
Implementation `bfa28d512436c2ea28f052aeca23eb489681d01a` generated invalid
workflow run `37191716080`: `runner.temp` was incorrectly referenced in job-level
env. No jobs executed, so that failure is not a gateway measurement.

After the workflow-context repair, head
`c503ab59606dac3d9081ed7a8f11aa201920b0e7` ran `37191938838`:
Dependency policy/Fuzz compile PASS, MSRV/Stable workspace FAIL. The real Linux
smoke artifacts are retained, not relabeled by subsequent tool repairs:

| Job | Artifact | Archive SHA-256 | Actual stopping condition |
| --- | --- | --- | --- |
| MSRV 1.88 (`111405802103`) | `11299825079` | `fabff440a320a02435224ab0e635b0a9be7847c064c1f3088a342e9d3f451a75` | prelude TLS Upgrade peer closed without `close_notify`; no worker qualification |
| Stable workspace (`111405802240`) | `11298828178` | `82dfab9e30091a4531831ebfa55758f19e1abdaee43b8ae824c8ca1720ff075e` | sampler readiness deadline; no measured steady phase |

The Upgrade runtime intentionally cancels the other copy direction at first EOF.
The validation tool must record complete echoes, actual client shutdown and the
actual peer termination separately: lack of TLS `close_notify` is **not** a fake
clean EOF. Its graceful-TLS-close assertion remains INCONCLUSIVE; other reset,
timeout or incomplete-echo failures cannot be excused by that classification.
The original sampler failure did not record its internal startup substage; full
debug executable hashing is a hypothesis to verify with new bounded stage
timestamps, not an established causal explanation of that old run. A separate
debug startup budget does not extend production deadlines or measured phases.

Artifacts expire after the workflow retention period; replay uses the original
archive bytes plus checksum, not new tool-generated replacement evidence.

### Next actual Linux oracle rejection

Head `0db05e61bcf1763e62c8f4b2193d3b8eeaca08b4` passed all nine local macOS
gates without a source change, but Hosted `37195361755` failed. Stable Rust 1.99
stopped on the new `chunks_exact_to_as_chunks` Clippy lint; its Linux smoke never
ran. Rust 1.88 completed the real implementation smoke/controller and rejected
its evidence independently. Artifact `11301305852` archive SHA-256 is
`3a5e3486d791876ef82ceafae1715463bbb94e3238d959125b5822575497b022`.

The original held gRPC was physically A, but the old Upgrade was physically B:
initial DNS `both` had been cached before setup switched to `a`. Complete echo
bytes do not prove an A lease survived A withdrawal. The oracle's rejection is
correct; setup must fix A **before** Gateway preparation and validate both old
flows against actual A, without hidden retries or rewriting the old artifact.

All 74 original Admin captures contain the three labelled metric families. The
receipt incorrectly requested unlabelled keys while the decoder preserved full
labelsets, causing false missing-gauge findings. The repair requests all five
actual fixed series (requests, H1/H2 connections, H2 streams, tunnels); missing
either protocol, wrong listener/label, duplicate series or NaN remains failure.
No aggregation default or zero replacement is used.

The new startup timestamps actually measured self-executable hashing at
16.536330851 seconds, with preceding cheap identity validation at 459511 ns.
This supports the separate debug startup-budget change on this run. It does not
manufacture missing timestamps for the older `c503ab5` failure or explain RSS.
Normal workers conserved 543 offered/received operations (536 HTTP admissions,
7 Upgrade admissions, 12 connection attempts); conservation alone did not grant
qualification to the invalid retained-flow proof. This is a short implementation
run, not an hour-scale resource or memory campaign.
