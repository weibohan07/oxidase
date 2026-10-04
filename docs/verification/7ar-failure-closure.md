# 7A-R failure closure

Starting protected main: `41a21ac836688b5698638ac8354753c6b8e44d5a`.
Baseline worktree: `c0db6cde862b3101ed3939e5c7dfa1d68fe6a891`.
Candidate production files, fixtures, lockfiles and analyzer are initially identical
to that baseline; the four intervening changed files are evidence/documents only.
Workspace and APIs remain unchanged. No later product phase belongs to this task.

## Frozen questions before experiments

| Case | Original fact | First falsifiable question | Status |
| --- | --- | --- | --- |
| R-504-CONTROL | C 37211766238 / control-1-15, full safe 504 at ~5.001 s | Does the operation reach the intended upstream; which operation-bound timer fires, and which await cannot progress? | UNRESOLVED |
| R-504-WORKER | Same C, five ordinary worker 504s | Do physical connection/dispatch times overlap the control failure, or are different uploads/heads waiting? | UNRESOLVED |
| R-CANCEL | Same C / 8:172, required upstream Drop ACK missing | Does the held response remain alive on the same upstream operation after downstream cancellation; does its healthy sibling finish? | UNRESOLVED |
| R-H2 | Earlier C 37209014444, GOAWAY/enhance and unknown causes | Which hop initiates GOAWAY and what locked h2 source condition triggers it? | UNRESOLVED |
| R-TLS-CLOSE | H 37204003262, 4625 notices | Distinguish unique closure operations from duplicate analysis; test real per-hop shutdown and incomplete-message negatives. | UNRESOLVED |
| R-CAPACITY | Frozen H, 21 actual kinds lack proofs | Which ownership/admission inputs bound current plus retired generations before construction? | UNRESOLVED |
| R-ALLOCATION | Only separate debug H1 trace exists | What remains allocated at comparable Running checkpoints in actual TLS/H2 Proxy/gRPC? | UNRESOLVED |

## First registered focused baseline

Use exact original C implementation/fixture/analyzer, seed 700218, Linux normal
release, TLS H1/H2, IPv6, original eight workers plus cancel/Upgrade lanes,
32768-byte responses, 1048576-byte uploads, unchanged 1000-request retirement
and all original deadlines/fault order. Preserve the original 180-second warmup.
Only the measured steady duration is limited to the first 90 seconds for diagnosis;
60/30/30-second recovery/quiet/post-drain are not formal qualification minima.
This is a focused reproduction, never a one-hour qualification PASS.

Prediction: the first control sequence reaches positive AAAA and the original
failure region. A non-reproduction refutes deterministic-seed sufficiency, not
the original failure. At most three same-recipe attempts are allowed before a
new distinguishing barrier/experiment; all results are retained. No load reduction,
business retry, timeout extension, feature disablement or new error allowance.

## Original preservation and replay (executed)

Local ignored archive directory:
`/Users/weibohan/Workspace/oxidase/target/qualification-evidence/7ar-originals/`.
Do not run `cargo clean` before retaining these archives elsewhere in an authorized
workspace. No third-party storage, permission expansion or production Secret is used.

| Original | Artifact | ZIP SHA-256 | Bytes | Provider expiry |
| --- | --- | --- | ---: | --- |
| Final C | 11306813903 | `24dd32f3aa3ae5c2d5fb78a69820f2127db805ba18f7a0b30d852c1c71251c91` | 1412778 | 2026-11-03T15:12:36Z |
| Historical H2 C | 11305458830 | `773f7a734cb7633013c9c388dc0b1cee265f1a7c35113f9d78e652987f95138f` | 6487823 | 2026-11-03T14:35:26Z |
| Formal H | 11305298669 | `2a66efa8eaa0120ae5e4e5166d7e13386a62dd4c00d4a3b9a68ca422490063e7` | 38012471 | 2026-11-03T14:29:58Z |

All three were re-downloaded; each provider digest equals the downloaded archive
and original local ZIP. Final C verified all 36 original per-file hashes. Its
frozen c0db analyzer SHA-256 is
`9de0d99e9142bbee55f19830068f2acce4e7227ca0bb75b6d72b8f5f890b9b05`.
Independent replay returned 1/FAIL and is byte-identical to the original report
(`9e8050b6d4916a10b1125ff46e5880113da0c737275cf864f243803613703883`).
Source-set, binary and PID/start identities remain in the original receipt and
existing index; current summaries do not replace original bytes or fill missing
Recovery/Quiet data. H/H2-C complete-file replay is tracked separately.

## Delivery/qualification

No case is closed by this initial ledger or by ordinary CI. Each closure requires
old counterexample, cause, minimal fix, same counterexample and original-load
repeat. Formal H/C must use the same frozen final implementation and tool source.
7A remains unqualified while any important case is FAIL/UNRESOLVED/INCONCLUSIVE.
