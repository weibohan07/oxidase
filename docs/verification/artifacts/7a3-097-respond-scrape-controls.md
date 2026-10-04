# Frozen 097 Respond-only scrape isolation controls

Source: 097c6ec373439fadd0a3204314fa47309740918c. These are matched controls on independent GitHub-hosted machines, not H/C qualification or a statistical performance guarantee.

Each original archive passed its provider SHA-256 and all 31 checksum-manifest entries. The frozen analyzer SHA-256 is 1c5321e65523d3713a5833826be049eb237c529c9bd385f3fa800d5a85d0b0be. Each independent replay exited 2 (INCONCLUSIVE) and was bit-identical to the original analysis.json. GitHub jobs failed because exit 2 is nonzero, not because these Respond requests failed.

| Run | Admin period | Artifact ID | ZIP SHA-256 | Offered = terminal = verified full wire responses |
| --- | --- | --- | --- | --- |
| 37204272371 | first/final only | 11303873518 | 39054d4391845596ebdd30962c923e0962325d85daf223e82b13a438aa7df8fe | 170467 |
| 37204274513 | 1000 ms | 11304312617 | e2feab04b442a03b5d9e81ff725c77b32a31bc82a046107b36a9f87daa6f7465 | 170443 |
| 37204276220 | 250 ms | 11303634063 | 6f8f9f462058efa7ed918096916e53f2c5e93e69e9f74830379008b5fda104ff | 170522 |

All 16-byte Respond bodies, their full digest, EOF, Content-Type, absent trailers and absent upstream metadata independently matched the recipe. All 168 per-run deliberate 1000-request connection retirements were accounted for; 176 connection preparations were recorded per run. There were no abandoned or unexpected workload terminals.

Matched parameters: seed 700215, concurrency 8, minimum operation interval 20 ms per worker, OS interval 1000 ms, warmup 30 s, steady 300 s, Running recovery 120 s, quiet 60 s, post-drain 60 s. Configured payload 32768 and upload 1 MiB do not describe these actual local Respond bodies. Each capture had 570 periodic OS samples plus bootstrap; maximum periodic OS gaps were 1.000778/1.000969/1.001018 s respectively. Periodic Admin captures were 0/570/2280 plus bootstrap and final checkpoints. First/final-only Admin sampling cannot establish Running resource lifetimes.

| Admin period | Steady RSS baseline/peak/final KiB | Steady RSS delta/slope KiB per second | Recovery RSS delta | Quiet RSS | Post-drain RSS | Steady FD |
| --- | --- | --- | --- | --- | --- | --- |
| first/final | 21156/21852/21832 | +676 / 1.72245 | -28 | 21748 flat | 21752 flat | 21 flat |
| 1000 ms | 21900/22576/22520 | +620 / 1.17232 | -160 | 22276 to 22260 | 22264 flat | 28 flat |
| 250 ms | 21648/22128/22128 | +480 / 0.86395 | +144 | 22236 flat | 22240 flat | 28 flat |

PSS/PrivateDirty/RSS curves remain separate in original analysis and comparison.json. No retained-allocation attribution exists in these captures, so every positive drift remains INCONCLUSIVE. Cross-machine values cannot establish a scrape-frequency effect. The first/final control has a large PrivateDirty decrease despite positive RSS/PSS drift; no allocator explanation is asserted.

Periodic Admin controls observed one current Snapshot and zero retired snapshots. They had no Clusters, health/discovery tasks, upstream pools, or tunnels; zero counts for those kinds are unexercised, not cleanup proof. ResponseBody objects were actually created/destroyed (170443/170522 each by final checkpoint); 250-ms sampling caught at most one live body. Quiet live body count was zero. The first/final control provides final facts only, not Running facts. Periodic Admin opens seven independent concurrent Unix requests per capture, consistent with, but not statistical proof of, the observed seven-FD offset.

This checked-in JSON index preserves provider metadata, counts, findings,
sampling and phase durations, not replacement raw measurements. Untouched ZIPs,
extracted files, frozen analyzer and deterministic replay reports are retained
locally at `/private/tmp/oxidase-7a-isolated-scrape-controls.XPncmN/` and in the
listed GitHub artifacts (30-day retention). Re-download the exact artifact and
verify its archive and per-file hashes before replay; artifact expiration does
not authorize regenerated evidence under the old run ID.
