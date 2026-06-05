# Docker / Pooled Execution — Deep Audit (2026-06-04)

Second-pass audit of the multi-container pooled model (`docker/test_pool.py`),
focused on what the first plan (docker-pooled-speedup-plan-2026-06-04.md, P1–P6)
did **not** cover: image builds, container/daemon startup ×N, the pool scheduler,
resource contention among K workers, and artifact I/O. Four parallel read-only
audits; all numbers measured on this host (**12 cores / 16 GB**) against
`artifacts/_base/*-pooled/`.

## The model in numbers (measured)

- Default pool work **W = 10,054 s (2.79 h)** over 10 providers / **19 container
  batches**; K=3.
- **Pool wall ≈ max(heaviest batch, W/K).** Today heaviest batch = **1270 s**,
  W/K = 3351 s — but the heaviest *single file* is only **842 s** (`test_ofb.py`
  on bouncyhsm, an ACVP-AES MCT). So the 1270 s pole is a **fixable scheduling
  artifact**, not physics.
- **In-container parallelism is 1** — `file_runner.py:2217` runs units strictly
  serially (`subprocess.Popen` per file); `--isolation auto` is *crash survival*,
  not CPU parallelism. So **K is the only parallelism knob**, and K=3 on 12 cores
  leaves the host **~75 % idle**.
- Each `--rm` container's `~/.cache` is ephemeral → the collection cache is
  **cold in all 19 containers** (~13 s full-suite collection, never reused).
- A full run writes **~11.9 GB** to the artifact bind mount; each provider's
  `report.jsonl` is **~214–313 MB** and is parsed **load-all** (1.4 GB RSS,
  ~13 s) several times during postprocess/merge.

## New findings, ranked (NEW = beyond P1–P6)

### Tier 1 — biggest wins

**T1. Parallelize image builds + shared base image (NEW — cold-run dominant).**
`test_pool.py:191-196` builds 10–17 images in a **serial** `for` loop; most
compile from source (OpenSSL ×~7, kryoptic/Rust `cargo --release`, NSS via `hg
clone`+`build.sh`, opencryptoki, softhsm2, bouncyhsm `.NET`). This is **tens of
minutes before a single test runs** and is the dominant cost of a cold pooled
run. Two levers: (a) run builds through the already-imported `ThreadPoolExecutor`
(cap ~2–3, lower per-build `-j`/`CARGO_BUILD_JOBS` so total threads ≈ cores —
clone/fetch phases overlap compile phases); (b) a **shared per-distro base**
(python3.14 + uv + `uv sync` + test-tools + fault-proxy built once) instead of
re-doing that ~10–17× — every provider currently rebuilds the identical Python
stack. Effort: low (a) / medium (b). Risk: med (CPU/RAM oversubscription —
mitigate with capped concurrency + reduced `-j`).

**T2. Time-balanced + duration-first scheduling (refines P2; NEW: ordering).**
`test_pool.py:202` calls `plan_shards(files, n)` *without* measured durations →
count-balanced. Feeding `duration_by_unit_from_results("artifacts/<p>-pooled/
results.json")` (helper already exists, `sharding.py:19`) cuts bouncyhsm's
heaviest batch **1270 s → 842 s (−34 % on the global pole)** — straight to the
file floor, zero new containers. **NEW:** the pool also *sorts by shard-count*
(`:215`), not batch duration, so all K slots can pile onto one provider; sorting
by batch duration (start the 1270 s/868 s poles first) adds **−10 % at K≥4**.
Effort: ~10 lines. Risk: very low (falls back to count when no oracle).

**T3. Raise K to ~6 + per-service `mem_limit` (refines P3; NEW: RAM ceiling).**
Host is 75 % idle and in-container parallelism is 1, so K is the lever:
simulated **K=3→6 ≈ 60 m → 34 m (−43 %)**. The true ceiling is **RAM (16 GB),
not the 12 cores** — K containers × (pytest RSS + bouncyhsm JVM + ~330 MB report
flush) → practical **K≈6–8**. Add `mem_limit`/`cpus` (none today,
`docker-compose.test.yml:22-24`) to fail-fast instead of OOM-thrash. Effort:
trivial (`-j 6`) + small (limits). Risk: low with limits.

**T4. Stream the JSONL readers + single-pass merge (NEW; byte-identical, safe).**
Every reader is **load-all**: `_load_report_log_records` (`file_runner.py:787`),
`extract_coverage_from_jsonl` (`:1162`), and `postprocess_jsonl_to_unified`
(`:1241`) which **reads the 214 MB file twice**; `merge_shard_dirs`
(`merge.py:202-248`) makes ~3 more full passes (and rewrites the whole file when
promoting traces). Measured: **12.9 s wall, 1.42 GB peak RSS per shard**, ×K
concurrent ≈ 4 GB host RAM just for JSON object graphs. Convert to streaming
(`for line in open(...)`) and fold coverage+quality+promote into **one** pass →
flat RSS (~tens of MB), fewer passes. **Output is identical — safe to apply
unconditionally, no finding loss.** Effort: medium. Impact: high (the clearest
pipeline bottleneck).

### Tier 2

**T5. Make the collection cache usable in Docker (NEW; activates Lever 2).**
The content-addressed collection cache is cold in every `--rm` container (~13 s ×
~8 undivided providers = **>100 s**, zero reuse). Either mount a cache volume +
`XDG_CACHE_HOME=/cache` (digest-keyed → safe; first container warms it, the rest
hit), or precompute the manifest **once on the host** (`save_collection_manifest`
exists, `collection.py:130`) and pass it via the already-mounted `/artifacts`.
Effort: low–med. Risk: low (digest guarantees a hit only when collection is
provably identical).

**T6. bouncyhsm `sleep 4` → readiness poll (NEW; cheapest high-value).**
`bouncyhsm/run-bouncyhsm.sh:21` sleeps 4 s unconditionally; the server answers in
**~0.5 s** (verified). 3.5 s wasted × 8 shards = **~28 s/run**. Replace with a
bounded `curl` poll (script already uses curl). Effort: trivial. Risk: none
(strictly safer than a blind sleep). Same pattern for opencryptoki `sleep 2` ×3
and tpm2 `sleep 1`+`sleep 2` (~9 s more).

**T7. Artifacts to container tmpfs + copy `report.jsonl` once + gzip (NEW).**
K containers each write **~439 MB** (report.jsonl 214 MB **+** a duplicate
215 MB `.state.json.report-records/` of the same records + quality 7 MB) to one
bind mount; host merge writes ~4 GB more → ~11.9 GB/run. Write intermediates to
container-local tmpfs, persist only the final `report.jsonl` (gzip’d, ~10×
smaller) → host writes **~11.9 GB → ~0.4 GB**. Crash/finding data preserved (the
persisted report carries crashes + rv-traces). Gate the tmpfs report-records
behind a "no-resume" flag (they exist for resume). Effort: medium. Risk: low.

**T8. BuildKit cache mounts + registry/GHA cache (NEW).**
No `--mount=type=cache` (cargo/dnf/apt/uv re-fetch every miss) and the builder is
the `docker` driver (no `--cache-from/--cache-to`). Cache mounts make ref-bump
rebuilds recompile only what changed; a `docker-container` builder + registry/GHA
cache makes **cold** runs pull warm OpenSSL/Rust/NSS layers — and is the
prerequisite for an image-based CI shard matrix (P6). Effort: low (mounts) / med
(registry). Risk: low.

### Tier 3

**T9. `subprocess_per_test` split of the 3 ACVP-MCT files (NEW; beats the floor).**
`test_ofb/cfb8/cfb128.py` ~842 s each set the indivisible-file floor. They’re now
`@pytest.mark.slow` (so `--skip-slow` removes them from fast lanes), but the
**full** run still hits 842 s. Marking them `subprocess_per_test` lets
`plan_shards` spread one file’s ~2144 cases across shards (→ ~210 s). Caveat: each
MCT case chains ~100k ops; per-test spawn (token re-init) overhead may erode the
win — **spike before committing**, on bouncyhsm only. No other default-provider
file exceeds 280 s. Effort: medium. Risk: medium (MCT correctness/overhead).

**T10. Dynamic shard counts + finer bouncyhsm tail (NEW).**
`SHARD_MAP` is hand-tuned; derive per-provider shard count from prior wall so no
batch exceeds ~W/K. After T2, bump bouncyhsm 8→12 to fill the idle tail at high K
(simulated lightest batch → 239 s). Effort: low. Risk: low (more JVM starts; net
positive only at K≥5).

**T11. Fast-lane artifact slimming (NEW; opt-out only).**
Only **2.2 %** of records are fail/xfail. A fast lane can emit full detail
(rv-trace + longrepr) only for non-pass outcomes + minimal `{nodeid, outcome,
duration}` for passes, and/or set `PKCS11_CHECK_RV_TRACE_COMPACT=""` (already
supported; recording itself is cheap, ~22 ms/provider — the cost is the 8 % of
bytes). **Opt-out only — rv-traces/crash-journals/fail-longreprs are findings and
stay on by default.**

**T12. Shared OpenSSL/NSS builder stages; skip redundant slot0 builds (NEW).**
OpenSSL compiles from source up to 7× (some identical tags); a shared
OpenSSL-builder stage dedupes it. `nss-slot0`/`-pqc-slot0`/`-main-slot0` reuse
their base image but `test_pool.py:192` still issues a separate `build_image` for
each (3 redundant serial build invocations). Effort: low–med. Risk: low.

### Rejected / already-good
- **Sharing a daemon across shards** (e.g. one bouncyhsm server for 8 shards):
  breaks the "one container == one token" invariant (concurrent same-token
  access). High risk, rejected — kill the wasteful sleeps (T6) instead.
- **`docker compose run` → `docker run`**: ~2–5 s/run total; not worth the
  per-service env/volume reproduction risk.
- **Collection cache across containers via its own digest**: target/module-keyed
  → no cross-container reuse without re-keying (risky); T5's shared-volume/host-
  manifest is the right path instead.
- Already good: deps-before-source layer split, lean `.dockerignore`, data
  bind-mounted (not COPY'd), `uv run --no-sync`, ACVP-MCT files already isolated
  into 1-file shards, `state.json` kept small via report-record sharding.

## Recommended sequence

1. **T4** (stream/single-pass postprocess) — unconditional, byte-identical, kills
   the memory/IO bottleneck; helps every run.
2. **T2 + T3** (duration-fed + duration-ordered sharding; K=6 + `mem_limit`) —
   ~60 m → ~30–34 m, mostly free CPU + ~15 lines.
3. **T6** (readiness polls) + **T5** (collection-cache volume/manifest) — cheap,
   token-safe, ~130 s combined.
4. **T1 + T8** (parallel builds + shared base + cache mounts) — the cold-run /
   CI-build cost, the largest absolute time for fresh runs.
5. **T7** (tmpfs + gzip artifacts), **T9/T10** (MCT split, dynamic shards),
   **T11/T12** (fast-lane slimming, builder dedup) — incremental.

**Headline:** the pool's wall is set by (a) **serial image builds** (cold runs),
(b) a **count-balanced scheduler leaving the host 75 % idle** (warm runs), and
(c) **load-all JSON postprocess** (memory/IO). None were touched by the single-
run work; T1–T4 address all three, and T2/T3 alone roughly halve the warm wall.
</content>
