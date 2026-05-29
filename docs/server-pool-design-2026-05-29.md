# Server-pool parallelism — design & deep gap analysis (2026-05-29)

## 1. Why this exists

Profiling bouncyhsm's full round (clean, contention-free) gives:

| Component | Time |
|---|---|
| call (PKCS#11 ops) | 45.3 min |
| setup | 5.2 min |
| teardown | 0.5 min |
| harness gap (startup/collection/merge/escalation) | 17.3 min |
| **total wall** | **68.2 min** |

The dominant cost is the **.NET server's per-call processing** (MessagePack ser/deser + BouncyCastle *managed* crypto), ~2-3 ms × ~400k calls. The TCP socket itself is ~1 % (per `bouncyhsm-transport-2026-05-28.md`). Every single-token lever is exhausted and **none help**: InMemory persistence (−71 %), Server GC (−79 %), `DOTNET_TieredPGO` (0), `logging=Warning` (0); ReadyToRun only helps cold-start (negligible over a 50-min run). The cost is inherent compute on one serial token stream.

The 3 ACVP-AES MCT files alone are **~33 min** (cfb128/ofb/cfb8 ≈ 11 min each): ~18 Monte-Carlo tests, each ~100k *chained* single-block ops ≈ 110 s. Chaining forbids in-test parallelism and 2 RPCs/op is the floor, so single-token this is irreducible.

**Conclusion:** the only PKCS#11-safe way to go faster is to run **multiple independent server+token instances in parallel**, each driven by its own serial test process — never concurrent access to one token (which PKCS#11 does not guarantee is safe). This document designs that "server pool" and reviews its gaps before implementation.

## 2. Core architecture — K parallel containers + merge (RECOMMENDED)

Two shapes were considered; the **container-level** one is recommended (see §2.1 for why).

```
   shard the file list                K independent containers                merge
   (balanced, pre-selected)           (each = the EXISTING provider image,    (combine the
                                        1 server + 1 token, fully isolated)     K artifact dirs)
                                   ┌────────────────────────────────────┐
  files ──► shard 0 ──────────────►│ docker run … TARGETS=shard0         │──► /artifacts/p-shard0 ─┐
        ──► shard 1 ──────────────►│ docker run … TARGETS=shard1         │──► /artifacts/p-shard1 ─┤
        ──► shard 2 ──────────────►│ docker run … TARGETS=shard2         │──► /artifacts/p-shard2 ─┼─► pkcs11-check
        ──► shard 3 ──────────────►│ docker run … TARGETS=shard3         │──► /artifacts/p-shard3 ─┘   merge-shards
                                   └────────────────────────────────────┘                              ▼
                                    run in parallel; each is today's              /artifacts/p/{results,coverage,quality}.json
                                    full `pkcs11-check test` over its subset       + report.jsonl  (combined)
```

**Key property:** each *container* runs the existing single-server pipeline over a disjoint subset of test files. One container = one server = one token, accessed serially. No concurrent same-token access — the PKCS#11 hazard is structurally impossible, *and* containers are isolated at the OS level (separate filesystems, network namespaces, memory, LiteDB file, ports) so there is zero shared mutable state between shards.

**Reuse, don't rebuild:** each container is **today's image and today's `pkcs11-check test`, unchanged** — it just receives a subset of files via `PKCS11_CHECK_TARGETS` and its own `PKCS11_CHECK_ARTIFACT_DIR`. Crash-survival, per-file isolation, state/resume, outcome classification: all preserved per shard, untouched. The only NEW code is provider-agnostic: **(a) shard the file list, (b) launch K containers in parallel, (c) `merge-shards` the artifact dirs.**

### 2.1 Why containers, not N-servers-in-one-image

| Concern | N servers in one image | **K parallel containers** |
|---|---|---|
| Per-image changes | Each provider image rewritten to spawn+health-gate N servers/tokens | **None** — existing images unchanged |
| Generalization | Per-provider lifecycle code (bouncyhsm ports, softhsm2 token dirs, NSS DBs…) | **Trivial & uniform** — every image already runs exactly 1 isolated instance |
| Isolation | Shared FS / ports / memory inside one container; risk of cross-token leakage | **Full OS isolation** per shard |
| Lifecycle | Custom N-server start/health/teardown inside the image | **Docker does it** (`docker run`/compose) |
| Config "data" coupling | Server config baked/duplicated in one image | **Stays in compose/env, not the image** |
| Failure blast radius | One container OOM kills all N servers | One shard dies, others unaffected |

The container approach is what the rest of this document now assumes. (N-servers-in-one-image remains a fallback only for an environment where launching multiple containers is impossible.)

The cost is a little more RAM (K full containers vs K servers in one), but image *layers* are shared and runtime memory is modest (see §9) — a fine trade for a vastly simpler, provider-agnostic design.

## 3. Why NOT pytest-xdist (confirmed)

xdist is a dependency but the plugin has **zero** xdist awareness (no `workerinput`/`worker_id`/`PYTEST_XDIST_WORKER`). Using `-n N` would:
- distribute individual *test items* across workers **sharing one token** (the unsafe case) unless `--dist=loadfile`, and even then
- lose all coverage: `config.stash` accumulates per worker and `pytest_sessionfinish` on a worker is **never forwarded** to the controller → `coverage.json` empty;
- collapse our distinct `crashed`/`timeout` outcomes into xdist's "worker crashed" → "failed", breaking the classification model;
- fight our own crash-survival/iterative-deselect loop.

The server-pool model (N separate `run_isolated_pytest_units` processes) sidesteps all of this and **preserves the classification model**, which xdist cannot.

## 4. What merges cleanly (validated against the code)

| Artifact | Merge operation | Status |
|---|---|---|
| `results.json` `summary.*` | **sum** the 9 int counters | trivial |
| `results.json` `units[]` | **concatenate** (shards disjoint, no overlap) | trivial |
| `report.jsonl` | **concatenate** the N worker files | trivial |
| `coverage.json` | run existing `extract_coverage_from_jsonl` on the concatenated jsonl — it already unions names + sums `Counter`s + recomputes `not_invoked`/`uncalled` | **logic already exists** |
| `quality.json` | regenerate via `build_quality_audit(merged_results, merged_coverage, concat_records)` — it's a pure derived function | regenerate, don't merge |

The merge is essentially "concatenate the JSONL, then reuse the existing end-of-run aggregation once." This is the single most reassuring finding: **the hard part (coverage union) is already implemented and tested.**

## 5. Path-collision inventory (must isolate per worker)

`run_isolated_pytest_units` writes 6 paths derived from its `state_file` / `report_config`, all of which collide if workers share a dir:

1. `state_file` (per-unit `save_run_state`)
2. `<state>.report-records/<sha256(unit)>.jsonl` shard dir
3. `policy_file` (promoted_files / crashed_tests, atomic-rename, no lock)
4. `report.jsonl`
5. `results.json`
6. `coverage.json` + `quality.json`

**Mitigation:** give each worker its own `artifact_dir/worker-<i>/` (state, policy, report, results, coverage, quality all under it). Temp files (manifest, per-unit jsonl, deselect, retry) already use `tempfile.mkstemp` → no collision. `BOUNCY_HSM_CFG_STRING` is already in `_FINGERPRINT_ENV_KEYS`, so each worker's state/policy fingerprint differs naturally.

## 6. Server endpoint routing

The bouncyhsm C shim reads `BOUNCY_HSM_CFG_STRING` (`Server=host;Port=p;`) at `C_Initialize`, inherited by every subprocess a worker spawns (`env = os.environ.copy()`). So routing worker *i* → port `8765+i` is just setting that env per worker. No CLI/transport change needed. One preflight manifest is shared read-only (identical servers ⇒ identical mechanism list).

## 7. GAP ANALYSIS (the hard parts)

### G1 — Shard balance (HIGH impact on speedup) [tractable]
Naïve round-robin can pile the 3 ~11-min MCT files onto one worker → that worker dominates → no speedup. Need **longest-processing-time-first bin-packing** using per-file durations from a prior run's `results.json` (`units[].duration_s`). Without a prior run, fall back to a small static "known-heavy" list (the MCT + wycheproof_ecdsa + acvp_rsa files) spread across workers first, rest round-robin. Speedup ceiling = total / max-worker-load; good balance is the difference between ~4× and ~2×.

### G2 — State-dependent outcomes / determinism (HIGH — the real semantic cost) [mitigate + document]
bouncyhsm's crashes are **state-accumulation dependent** (per `xdist-investigation-2026-05-28.md`: a multiblock crash only fired *after* earlier files put the token into a certain state). Sharding files onto N fresh tokens changes that accumulation, so a pool run can legitimately **report different crashes/outcomes** than a single-token run — it may *hide* an accumulation-triggered crash or *surface* a new one. For a tool whose job is stable, comparable bug reports this is a genuine semantic change, not just a perf knob.
**Mitigations:** (a) pool mode is **opt-in**, single-token remains the canonical findings mode; (b) keep `CKA_TOKEN`-object-creating / known-interacting files grouped on one worker where identifiable; (c) record pool topology in `results.json` metadata so a run's provenance is explicit. **Recommendation:** treat pool mode as the *fast* mode and single-token as the *canonical* mode; document that crash-set may differ.

### G3 — Bootstrap-count inflation (MEDIUM) [fix in merge]
`C_Initialize`/bootstrap functions run once **per worker**, so summing `bootstrap_counts` across N workers over-counts ~N×, and `called_counts` for session-setup functions inflate too. `extract_coverage_from_jsonl` blindly sums. **Fix:** the merge must treat bootstrap/session-fixture counts specially (max, or per-worker-normalized, or tagged). Names (union) are unaffected — only counts. Coverage *breadth* (which functions/mechanisms exercised) stays correct; only call-count *totals* need de-inflation.

### G4 — Crash classification (LOW — actually a strength) [preserved]
Because each worker is a full `run_isolated_pytest_units`, per-worker crash-survival/iterative-deselect and the `crashed`/`timeout`/`failed` distinction are **preserved exactly**; the merge just sums buckets. This is strictly better than xdist.

### G5 — Lifecycle (LOW with containers) [docker does it]
With the container model there is **no in-image multi-server lifecycle to build** — `docker run`/compose starts/stops each shard's container, and each container already starts its own single server+token via the existing entrypoint. The orchestrator just launches K containers in parallel and waits. Resource (measured): each bouncyhsm container ≈ 1 core + ~0.8 GiB server + ~0.5 GiB python ≈ **~1.3 GiB**; box 12 cores / 18 GiB ⇒ K=4-6 comfortable. Readiness/health is already handled inside each container's entrypoint (slot-create curl).

### G6 — Generalization (LOW with containers) [free]
This is the big win of the container model: **it generalizes for free.** Every provider image already runs exactly one isolated instance, so "K shards = K containers of that image" works identically for bouncyhsm, softhsm2, NSS, kryoptic, opencryptoki — no per-provider pool code. Whether a provider *benefits* still varies (bouncyhsm/opencryptoki are network/daemon and per-call-bound → big win; softhsm2/NSS/kryoptic are in-process and already fast → little gain), so sharding is **opt-in via shard count** (K=1 = today). The merge + shard + launch code is 100 % provider-agnostic.

### G7 — Resume with a pool (LOW) [defer or per-worker]
Each worker already has its own `state_file` → resume is per-worker for free. A pool-level `--resume` just resumes each worker over its original shard. Defer polish; per-worker resume works.

### G8 — Manifest / preflight (LOW) [share]
One preflight against any one server produces a manifest valid for all identical servers; pass the same `--p11-manifest` read-only to all workers. Saves N−1 preflights.

### G9 — Failure isolation between workers (LOW) [handle]
If a worker process dies (OOM, server crash), the coordinator must still merge the survivors and report the dead shard's units as a clear error, not silently drop them. `parallel`-style "collect all, mark failures" with the dead worker's units surfaced as `error`.

## 8. Configurability surface (container model)

Three small, provider-agnostic pieces — **no provider image changes**:

1. **`pkcs11-check shard-units`** (new helper): given the testcases dir (+ optional prior `results.json` for durations), emit K balanced file-lists. Pure planning, no devices.
2. **`docker/test-parallel.sh <provider> --shards K`** (new launcher): calls `shard-units`, then runs K `docker compose run` in parallel — each with `PKCS11_CHECK_TARGETS="<shard i files>"` and `PKCS11_CHECK_ARTIFACT_DIR=/artifacts/<provider>-shard-i` (shared `../artifacts` mount, distinct subdirs → no collision), waits for all, then calls merge.
3. **`pkcs11-check merge-shards <dir…> -o <out>`** (new subcommand): the core deliverable — combine the K artifact dirs into one `results.json` + `coverage.json` + `quality.json` + `report.jsonl`.

`--shards 1` (default) = today's single-container behavior, byte-for-byte. `results.json` gains a `shards: {count, files_per_shard}` provenance field. Shard count per provider lives in the launcher/CI, not in any image.

## 9. Expected payoff

With good sharding (G1), wall ≈ `max-worker-load + pool overhead`. The ~33-min MCT block split across 3-4 workers → ~9-11 min; the rest (~18 min of work) spreads too. Realistic target **~20-30 min at N=4** (down from 68 min completing-MCT, or from ~54 min legacy-timeout). The idle-resource headroom (only 2/12 cores used today) confirms this is feasible without contention.

## 10. Implementation plan (phased, after review)

1. **`merge-shards` subcommand** (no parallelism yet) — combine K artifact dirs: sum `results.summary`, concat `units`, concat `report.jsonl` → reuse `extract_coverage_from_jsonl` for `coverage.json` (with G3 bootstrap de-inflation) → regenerate `quality.json`. Fully unit-testable offline against the existing single-container artifacts (split one run's units into 2 fake shards, merge, assert == original). **Lowest-risk, highest-value, build first.**
2. **`shard-units` helper** — LPT bin-packing over prior `duration_s` (+ static heavy-file fallback) → K file-lists. Unit-tested.
3. **`docker/test-parallel.sh`** — shard → K parallel `docker compose run` (distinct TARGETS + artifact subdirs) → wait-all → `merge-shards`. No image changes.
4. **Validate**: K=4 bouncyhsm round; compare wall-clock + **counts/coverage vs single-container** (expect coverage *breadth* identical; crash-set may differ per G2 — document); confirm merged `results.json` total == sum of shards.
5. (Later) optional `--shards` convenience flag inside `pkcs11-check test` that drives steps 1-3 for local (non-docker) multi-token runs.

## 11. Open questions for review

1. **Determinism (G2):** OK to treat pool mode as *fast/non-canonical* (crash-set may differ from single-token), with single-token remaining the reference? Or must pool runs reproduce the exact single-token crash-set (which constrains sharding / may be impossible)?
2. **Default N** for bouncyhsm in CI (4? 6?) and whether other providers ever enable it.
3. **Bootstrap counts (G3):** acceptable to report per-worker-deduplicated call counts (breadth exact, totals de-inflated), or do call-count totals need to match single-token exactly?
4. Container model confirmed over N-servers-in-one-image? (Recommended: yes — provider-agnostic, no image changes.)
5. Shard granularity = **whole files** (preserves per-file isolation + fixture sharing). Agreed? (Per-test sharding would break file-scoped fixtures and isolation.)
