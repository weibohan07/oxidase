# Control-plane acceptance evidence

Scope: finish phase five only. Starting feature HEAD:
`8694bde9dfce2356a55a2f13ca54c1adb107c39d`; starting main:
`e018b2e24d87185e545cf1b0efb6200acff30f08`.
Production and fuzz-source commit: `a1958382a102c20735098f3646a23dfa1127588a`.
Subsequent `37ca1c0` changes only a deterministic HTTP/2 test fixture, not fuzzed
libraries/harnesses. Documentation revisions are not new functional evidence.

Workspace remains `0.3.0-alpha.1`; Gateway `oxidase.dev/v1alpha1`, Oxista v1,
Bundle `oxidase.bundle/v1`, and Admin `oxidase.admin/v1` remain alpha.
This is bounded local qualification, not production readiness or a long soak.

## Requirement → implementation → executed regression

All local PASS entries below were actually executed, with loopback permission
where required. They do not stand in for final-head Hosted checks.

| Requirement | Implementation | Executed regression | Result / boundary |
| --- | --- | --- | --- |
| CP-01 runtime current | atomic PublishedRuntime; artifacts/history never determine current | `source_reload_between_bundle_activations_does_not_create_false_already_current`, `retained_history_does_not_claim_to_be_the_runtime_after_source_restart`, Bundle-only boot | PASS; Source without an artifact is not Bundle-rollbackable |
| CP-02 final conditions | manager CAS after prepare/prebind; watcher additionally requires Source + Running | `stale_source_preparation_cannot_overwrite_a_bundle_publication`, stale source/drain and simultaneous activation wire tests | PASS; original ETag is never silently refreshed |
| CP-03 commit / cancellation | durable intent; manager-owned completion; separate pre/post-publication recovery | `published_runtime_survives_caller_cancellation_and_completion_storage_failure`, lost-response receipt query, storage fsync/rename tests | PASS; known publication survives caller loss, ambiguous bookkeeping closes mutation |
| Audit crash window | durable audit-pending receipt; clear only after acknowledged completion | `required_stage_audit_failure_is_durable_recovery_without_a_runtime_revision`, persisted ACK/ACK failure and killed-child `audit_completion` | PASS; storage-only outcomes do not invent a runtime revision |
| GC / orphan capacity | tombstone-first GC; post-rename registration failure closes admission | GC/rename faults, continued-admission capacity test, killed upload/artifact/GC subprocesses | PASS; verified orphans recover as staged, unknown/corrupt objects are not swallowed |
| Store process / path boundary | exclusive process lock, private root, safe open and inode checks | second-process lock, writable-parent/symlink/directory replacement tests | PASS on Unix; no cross-host consensus claim |
| Read isolation / limits | ArcSwap read view; bounded receipts, adopted upload and copy-peak accounting | blocked durable writer with successful reads; exact byte limits; caller-cancelled worker retains admission | PASS; actual work owns its permit |
| CP-04 drain / independent permission | Running → Draining → Drained, journal without signing capability | drain-only, reload-only, readless drain, repeated drain, readiness and watcher refusal | PASS; explicit activation/restart resumes traffic |
| CP-05 bootstrap | coherent retained token/TLS/Trust/permission/key/limit plan | data-only Bundle preserves Admin; incompatible candidate rejected; sensitive hardlink and audit-file overlap tests | PASS; bootstrap changes require restart |
| CP-06 token / transport | shared one-line token parser and verified mTLS principal | Unix bearer, HTTPS bearer, required/combined mTLS; no newline/LF/CRLF and invalid-token/header tests | PASS; static shared permission set, not multi-user roles |
| CP-07 receipts / replay / ctl | principal+key+full fingerprint, queryable operation, explicit condition and total deadlines | exact old-ETag replay, conflicting key/principal tests; HTTP driver timeout/bounds tests; real ctl demonstrations | PASS; count-bounded retention, not exactly-once |
| Complete API / safe diagnostics | JSON API errors and sanitized structured spans | 404/405/413/415/428/412, Allow, invalid body/trailers; rollback failures compare original coordinates | PASS; file and dynamic mapping-key text are masked |
| Audit delivery | reserved bounded completion, safe JSONL file, noise drop counters | real JSONL failure/success/replay/drain/reload matrix; overflow/write/cancellation tests | PASS; stdout/stderr cannot prove downstream collector durability |
| Cooperative source / Bundle work | shared owned admission, 64 KiB checkpoints and bounded text | interrupted config import/read, Site hash and compile callbacks, FIFO replacement, controlled Bundle copy/hash | PASS; 16 MiB/document text, 128/4096 import depth/count; Assets remain streamed |
| Explicit offline recovery | preserve old evidence; verify chosen input; fresh private root restart | killed-server recovery serves Source B while old mutation is closed, then fresh-root Source B mutation works | PASS; no online journal-edit/reconciliation API |

## Actual commands

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked` | PASS; existing manual benchmark/soak ignores remain ignores |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked` | PASS |
| `cargo deny check` | PASS; allowed duplicate-dependency warnings remain |
| `cargo build --workspace --release --locked` | PASS |
| `cargo +1.88.0 check --workspace --all-targets --all-features --locked` | PASS |
| `cargo +1.88.0 test --workspace --locked` | PASS after the H2 fixture race fix; the initial failure is described below |
| `cargo check --manifest-path fuzz/Cargo.toml --bins --locked` | PASS |
| basic Gateway `check`, `test`, `explain --request .../home.yaml` | PASS |
| secure-resilient Gateway `check` | PASS with access to the macOS system CA store |
| secure-admin Gateway `check`, `test` | PASS; public test-only token intentionally emits a 0644 warning |
| `cargo test -p oxidase-cli --test admin_ctl --test admin_ctl_real_server --locked` | PASS; real build/sign/stage/validate/A/B/history/rollback/query/reload/drain demo and readless explicit condition |
| `cargo test -p oxidase-server --test admin_control_plane --locked` | PASS; 23 entries include two subprocess helpers |
| `cargo test -p oxidase-runtime candidate::tests --locked` | PASS; 26 entries include subprocess helper |

The initial MSRV run exposed a pre-existing raw H2 fixture race: a Respond could
finish a stream before the invalid WINDOW_UPDATE arrived, which permits late
updates to be ignored. The repaired fixture holds a Proxy stream open and still
requires FLOW_CONTROL_ERROR. Both targeted stable/MSRV and full MSRV runs passed
after repair; the protocol assertion was not weakened.

## Real crash/fault evidence

The journal suite rendezvouses with and kills actual subprocesses in eight modes:
`intent`, `completion`, `artifact`, `upload`, `gc`, `state_fsync`,
`state_rename`, and `audit_completion`. No destructor repairs a killed child's
state. The last mode preserves a known committed revision/history while rejecting
new mutation because audit completion was not durably acknowledged.

Additional real server processes verify startup origin, last-known-good traffic,
retained-history accuracy, unresolved-intent closure, and operator recovery using
a fresh private root. Old journal, artifact and audit bytes remain unchanged.
The manager test injects persistence failure only after atomic publication and
closes the result receiver at that same boundary; actual new-version wire traffic
continues and the receipt records recovery-required.

## Actual bounded fuzz campaigns

Nightly `1.100.0-nightly (fd7ed57df)`, LLVM 23.1, aarch64 macOS, AddressSanitizer.
Both targets exited 0 with no crash, timeout, OOM, ASan diagnostic, or artifact.
This is local fuzzing, not a Hosted campaign or proof of absence of bugs.

| Target | Seed | libFuzzer / wall seconds | Executions | Active corpus | New units | Peak RSS |
| --- | --- | --- | --- | --- | --- | --- |
| admin_request, current seeds explicitly included | 424242 | 61 / 63.52 | 299431 | 1228 → 1427 | 1342 | 537 MB |
| candidate_journal | 424243 | 61 / 70.52 | 251695 | 341 → 407 | 649 | 532 MB |

```sh
CARGO_NET_OFFLINE=true cargo +nightly fuzz run admin_request fuzz/corpus/admin_request fuzz/seeds/admin_request --dev --sanitizer address -- -max_total_time=60 -seed=424242 -timeout=10 -rss_limit_mb=2048 -max_len=32768 -print_final_stats=1
CARGO_NET_OFFLINE=true cargo +nightly fuzz run candidate_journal --dev --sanitizer address -- -max_total_time=60 -seed=424243 -timeout=10 -rss_limit_mb=2048 -max_len=65536 -print_final_stats=1
```

Retained corpora were used (filesystem counts Admin 2495 → 3687 plus four current
seed files, Candidate 427 → 985). These runs are reproducible commands, not a claim
that a future changing corpus produces identical execution counts.
Saved losslessly compressed raw logs: [Admin](artifacts/control-plane-admin-asan.log.gz),
[Candidate journal](artifacts/control-plane-journal-asan.log.gz). SHA-256 of the
decompressed original output respectively:
`52c17280b945b29d66d3cb48e8250cbff91b47eb54d9ad257a7a15dca739c180`,
`7410f4234a4088f3c23bfdbb1f207abb9c406912c8c0b0dd7df7d4ee272d7a6d`.

## Hosted delivery authority

[PR #15](https://github.com/weibohan07/oxidase/pull/15) retains the final-head
required-check rollup, normal merge metadata, and delivery evidence with exact
run IDs. The initial WIP run `37102543250` failed (TLS advisory, toolchain
deprecation, stale fuzz lock). Foundation run
[37105034477](https://github.com/weibohan07/oxidase/actions/runs/37105034477) passed
on `d6793ad`; it does not qualify this final implementation. Final head and merged
main must each have their own green run; neither local tests nor this document
substitutes for those checks.

## Explicit scope limits

Single-process local control plane; fixed startup Admin bootstrap; static shared
permissions; count-bounded replay; Unix local storage lock; explicit offline
restart/bootstrap reconciliation for uncertain intent; no distributed transaction
or automatic old-secret restoration. DNS discovery, OpenTelemetry, packaging,
later milestones, tags and Releases are outside this PR.
