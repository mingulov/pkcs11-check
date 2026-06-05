# Docker / Pooled Execution Speedup — Plan (2026-06-04)

Follows docs/findings/test-execution-speedup-gap-analysis-2026-06-04.md, which
optimized a *single* `pkcs11-check test` run (plugin autoload-off, collection
cache, vector cache, `slow` markers). This plan targets how the suite actually
runs **at scale**, across providers, in Docker — where different levers dominate.

## The two real execution models

1. **Local pooled** — `docker/test_pool.py`. Every `(provider, file-batch)` is a
   `docker compose run --rm test-<provider>` container; K (default **3**) run at
   once, mixed across providers; results merged per provider (`*-shard-N` →
   `*-pooled`). `SHARD_MAP` shards only bouncyhsm(8)/opencryptoki(3); all other
   providers run **undivided** (one container, full suite). Wall ≈
   `max(largest single batch, total_work / K)`. Source is `COPY`'d into the
   image; **vendor data is bind-mounted read-only** (`../data:/app/data:ro`, so
   identical mtimes in every container); each `--rm` container's `~/.cache` is
   **ephemeral**.
2. **CI** — `.github/workflows/providers.yml`. GitHub **matrix: one job per
   provider** [softhsm2, kryoptic, nss], full suite serial on a fresh runner,
   vector data restored from an `actions/cache`. No sharding within a job.

Key consequence: in both models the per-container/per-job filesystem is fresh,
so the **collection cache and vector cache (from the single-run work) give
little here** — each container does exactly one collection, and a `--rm`
container or fresh CI runner never gets a second, warm read. The high-leverage
moves are about **what runs**, **how it's split**, and **how parallel** it is.

## Where the wall time goes (pooled)

- **The long pole is one heavy file in one shard.** The AES-multiblock files
  (`test_cfb8/ofb/cfb128.py`) run ~**11 min each on bouncyhsm** and are
  indivisible at file granularity (`sharding.py` even weights them at 660 s).
  Pool wall ≈ that single batch.
- **`plan_shards` is called without durations.** `test_pool.py` does
  `plan_shards(files, n)` — no `duration_by_unit`, so it balances by **count**
  (+ heavy-basename isolation), not measured time, even though
  `duration_by_unit_from_results()` exists for exactly this.
- **Undivided big providers are their own poles.** kryoptic ~870 s, nss ~550 s,
  softhsm2 ~465 s each run as a single container.
- K=3 caps throughput: wall ≈ total_work / 3 regardless of host cores.

## Levers (ranked by impact × leverage of already-shipped work)

### P1 — `--skip-slow` fast pool/CI lane ★ biggest, nearly free
The 11-min multiblock files and the DSA/DH/paramgen stragglers are exactly the
cases just tagged `@pytest.mark.slow`. A `--marker "not slow"` pooled run drops
them, so the **pool's long pole collapses** (bouncyhsm −53%; its ~840 s
multiblock shard → ~240 s ecdsa). Wire `PKCS11_CHECK_MARKER="not slow"` through
the pool/compose (already plumbed in `run-pkcs11-check.sh`). Keep a scheduled
**full** run for the long cases. Effort: trivial. Impact: large.

### P2 — time-balanced pool sharding ★ easy, real
Feed measured durations into the planner:
`plan_shards(files, n, duration_by_unit=duration_by_unit_from_results(prior pooled results.json))`.
LPT over real times (vs count) is "the difference between ~Nx and ~2x" per the
module's own docstring — biggest on bouncyhsm's 8 shards. Effort: ~10 lines in
`test_pool.py`. Impact: medium-large on multi-shard providers.

### P3 — raise K to host/runner cores
Wall ≈ total_work / K. Each container is its own server+token (PKCS#11-safe), so
K scales with cores. Default 3 → `min(cores−1, …)`. Effort: a default + doc.
Impact: large where cores are available (CI runners, beefy hosts).

### P4 — shard the big undivided providers
softhsm2/kryoptic/nss each run >5 min as one container. Add them to `SHARD_MAP`
(e.g. 2–4) so the pool parallelizes them and per-container collection shrinks.
Pairs with P2 (time-balance) and P3 (K). Effort: config + validate partition
(the pool already verifies "nothing dropped"). Impact: medium; needs K headroom.

### P5 — shared, pre-warmed vector-cache volume
Because vendor data is bind-mounted ro with identical mtimes everywhere, a host
`~/.cache/pkcs11-check/vectors` warmed once and mounted into every container
hits for all of them (the vector cache key is data mtime+size only — provider/
target independent). Mount it via the compose `x-common` volumes. Effort: warm
step + one volume line. Impact: small per container × many containers; biggest
on the ACVP-heavy PQC files.

### P6 — shard each CI provider job
`providers.yml` runs one job per provider. Add a shard axis to the matrix
(`provider × shard_index`) and run a file subset per job via the existing
`core/sharding.py` / `cli/shard_cmd.py`. GitHub gives many parallel runners, so
this cuts per-provider wall ~linearly. Effort: matrix + a shard flag in the run
step. Impact: large for CI latency.

### Already active inside every container/job
Plugin **autoload-off (Lever 1)** trims ~0.13 s off each of the per-file
subprocesses a container runs — real in both models, no change needed.

### Not worth it here
- **Collection cache across containers:** its digest includes targets + module,
  so every shard/provider container has a unique key — no cross-container reuse
  unless re-keyed to per-file markers (module-dependent skip markers + `-m`/`-k`
  make that risky). Skip.
- **pytest-xdist inside a container:** rejected earlier — false
  `CKR_TOKEN_NOT_RECOGNIZED` on a shared token. Parallelism stays at the
  container/shard layer (separate tokens).

## Recommended sequence

1. **P1** (`--skip-slow` fast lane, pool + CI) — biggest cut, reuses the `slow`
   markers; add a scheduled full run.
2. **P2** (time-balanced pool sharding) — ~10 lines, compounds with everything.
3. **P3 + P4** (raise K; shard the big providers) — parallelism where it pays.
4. **P6** (CI shard matrix) — CI latency.
5. **P5** (shared vector-cache volume) — incremental.

Headline: the `slow` markers shipped for the single-run case are also the
**single biggest pooled/CI lever** (P1) — they remove the 11-minute stragglers
that set the pool's wall. Everything else is parallelism + balance.
</content>
