# Test-Execution Speedup — Gap Analysis (2026-06-04)

Investigation only; no behavior changed by this document. Goal: significantly
speed up a general suite run while (a) keeping the ability to run everything,
and (b) **never weakening crash survival or hiding findings**. All numbers are
measured on this host against softhsm2 unless noted; figures are order-of-
magnitude, not release statistics.

## Executive summary

There are **two independent speed axes**:

1. **Long individual test cases** — a *small* number of genuinely heavy cases
   (RSA-4096 ops/keygen, DSA/DH parameter generation, AES large-multiblock,
   leak/churn/fuzz loops). Only ~59 cases exceed 5 s (worst provider). Marking
   them `@pytest.mark.slow` lets a basic run use `-m "not slow"`. Big win on
   network backends (bouncyhsm −53%), modest on local. *(Tracked separately;
   this doc focuses on axis 2.)*

2. **Non-test overhead** — on a local provider, **only ~23 % of wallclock is
   actual PKCS#11 calls.** The other ~77 % is subprocess startup, pytest
   collection, vector parsing, and fixture setup/teardown. This is the larger,
   provider-general lever and the subject of this analysis.

**The single best non-test win** is disabling unused pytest **plugin autoload**
in each isolated subprocess: verified identical results, zero crash-survival
impact, low effort, ≈ **37–80 s/run** saved. After that, **collection-metadata
caching** and **vector-parse caching** remove redundant repeated work, and
**batched isolation** is the big structural lever if we want more.

**Explicitly rejected:** pytest-xdist / forked parallelism as an in-suite
default — it survives crashes but **manufactures false `CKR_TOKEN_NOT_RECOGNIZED`
findings** on a shared token (verified). Parallelism belongs at the CI-shard
layer (separate tokens), where it already lives.

## Measured cost model (softhsm2, 465 s wallclock, ~78.7k tests, 246 files)

| Bucket | Cost | Notes |
|---|---|---|
| Actual `C_*` call time | ~108 s (23 %) | the only "real" work |
| Per-file **subprocess startup** | ~120 s | 246 spawns × ~0.5 s (autoload ON); ~half is wasted plugin autoload |
| **Collection** (parent + per-file) | ~80–130 s | parent full marker pass 13–18 s once; each file re-collects in its own subprocess |
| **Vector JSON parse** at import | ~0.2–0.6 s × (parent + per-file) | parsed ~2× per isolated run |
| Fixture **setup/teardown** | ~35 s | dominated by `C_Login`/`C_Logout`; heavy vector files already module-scoped |

Correction to earlier rough estimates: a big vector *module import* is
~140–235 ms (not ~1 s); collecting `test_wycheproof_ecdsa.py` (28,829 items) is
~1.1–1.95 s of pytest-internal time (the rest of the apparent "5 s" is fixed
interpreter+plugin startup). pytest has **no built-in collection cache**
(verified: consecutive runs show no warm-up).

## Axis 2 — non-test overhead levers

### Lever 1 — Disable plugin autoload in per-unit subprocesses ★ do first
Every isolated subprocess autoloads **8 third-party plugins**; the run path only
needs `pkcs11-check`, `pytest_reportlog` (the runner injects `--report-log`),
and `timeout` (the `timeout=300` ini). `hypothesis`, `pytest-benchmark`,
`pytest-cov`, `xdist` are dead weight in ~244/246 files.

- Mechanism: in the per-unit `cmd` builder (`core/file_runner.py:2237-2247`) set
  `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` and prepend `-p pkcs11-check
  -p pytest_reportlog -p timeout` (entry-point names, not module paths).
  Conditionally add `-p hypothesispytest` only for `test_fuzz.py` and
  `-p benchmark` only for `test_benchmark.py` (the unit path is known per
  iteration).
- Saving: ~0.15–0.35 s/spawn × 246 ≈ **37–80 s/run** (~30–50 % of startup).
- Verified: outcomes and report-log JSONL **identical** with autoload off.
- Effort low · crash-survival impact **none** (still 1 subprocess/unit) ·
  user-visible output **none**.

### Lever 2 — Persistent, mtime-keyed collection-metadata cache
The parent runs one full `--collect-only` (`core/collection.py:60`, ~13–18 s for
106 k items) purely to read per-file markers, then each file re-collects in its
own subprocess. The serialization to cache this already exists
(`save_collection_manifest`/`load_collection_manifest`, `core/collection.py:26-57`)
but is used one-shot (written then deleted) — not as a persistent cache.

- Mechanism: persist marker rows under `.pytest_cache/` keyed by
  (file path, mtime, size); on the next run re-collect only changed files,
  reuse cached marker rows for the rest. Bust on pytest/plugin version change;
  add `--no-collection-cache`.
- Saving: most of the 13–18 s parent pass on warm runs.
- Effort medium · risk low (caches only *which tests exist and their markers* —
  never outcomes or vector contents; invalidated on any source change).

### Lever 3 — Vector-parse cache (stdlib pickle, mtime-keyed) + build at fetch time
Loaders (`wycheproof/wycheproof_loader.py`, `acvp/acvp_loader.py`) `json.load`
on every call with no memoization; vectors are parsed in the parent collection
*and* again in each file subprocess. Fetched data is 772 MB (ACVP 668 MB);
biggest single files 20–36 MB. Pickle parses ~2.8× faster than stdlib `json`;
no new dependency.

- Mechanism: loaders read/write a sibling `.pkl` cache validated by source
  mtime+size, falling back to JSON (source of truth stays intact); optionally
  build the cache at fetch time (`cli/fetch_cmd.py:204`) so first/CI runs are
  warm. Add `functools.cache`/load-once-per-process memoization (copy per-vector
  mutable dicts, or guard the `_group`/`_hash_fn` attachment).
- Saving: ~0.3–0.6 s/run on softhsm2; more on ACVP-heavy SLH-DSA/KDA and on
  every isolated subprocess re-import; benefits every CI provider job.
- Effort low · risk low · `data/` is gitignored so caches are auto-untracked ·
  **never reduces vector counts.**

### Lever 4 — Batched isolation with per-file crash-fallback ★ big structural lever
Run several marker-clean, no-crash-history files in **one** subprocess; on clean
exit you saved N−1 startups; on a crash (`rc<0`) re-run that batch's files
individually to localize the culprit and continue. The attribution machinery
already exists: `_identify_crash_culprit` (`core/file_runner.py:1681`) +
iterative deselect loop (`:2647`) + escalate-to-per-test (`:2919`); the adaptive
policy file already records per-backend crash history (the batch-eligibility
selector).

- Saving: batching ~210 marker-clean files in groups of ~10 cuts ~190 startups
  ≈ **60–95 s/run** (overlaps Lever 1).
- Effort medium · risk low-ish: a batch crash still only kills that batch's
  subprocess and is recorded; the only real risk (crash mis-attribution between
  files) is already mitigated by the fall-back-to-per-test path. Requires a new
  "batch unit" concept in `run_isolated_pytest_units` and care that
  `--max-crashes-per-file` accounting maps back to individual files.

### Lever 5 — Fixture scope audit + per-group key-import hoisting
- The module-scoped session fixture already amortizes `C_OpenSession`/`C_Login`
  for the heavy vector files (verified `test_wycheproof_ecdsa.py:293` uses
  `p11_module_session`). Remaining win is a **careful per-file audit** of the
  ~149 `p11_raw_session` files — minor on softhsm2 (~0.5 ms/test), but
  47–80 ms/test on OpenCryptoki/BouncyHSM. **Must NOT widen** lifecycle/login/
  PIN/`@destructive`/`subprocess_per_test` tests (would corrupt isolation and
  mask findings).
- Wycheproof re-imports the group public key per vector even though it is
  identical across the group (75–94 % redundant: ~22 k/29 k ECDSA, ~10 k/11 k
  RSA). Hoisting to a per-(file,group) key-handle cache on the shared session
  saves ~1.6 s on softhsm2 but **minutes on token-backed/networked providers**.
  The crypto op under test still runs per vector — only the object import is
  amortized; a key-import failure is still surfaced once per group.
- Effort medium · risk low-medium (key the cache by exact bytes+attrs, clear per
  module, exclude attribute-policy tests).

### Lever 6 — Lazy `fixtures`/`config` import in the plugin
`plugin.py:22` eagerly imports `fixtures → config`, pulling the whole
`pydantic_settings`/`pydantic` chain (~47 ms) into every subprocess even when no
fixture is used during collection. Deferring it saves up to ~47 ms × 246 ≈
10–12 s, but only for subprocesses that never build the config.
- Effort medium · risk medium (pytest must still discover fixtures — verify with
  `--fixtures`).

### Rejected — pytest-xdist / forked parallelism as a suite default
xdist (installed) **does** survive worker SIGSEGV (verified: reports
`worker 'gw0' crashed`, exits rc=1) and keeps interpreters warm. **But** running
the suite `-n4` against a single softhsm2 token produced **19 spurious
`CKR_TOKEN_NOT_RECOGNIZED` errors** — concurrent processes initializing the same
token store manufacture false findings and perturb real crash reproduction. This
directly conflicts with the bug-finding mission. pytest-forked is not installed
and effectively unmaintained. **Keep parallelism at the CI-shard layer (separate
tokens), which already exists.**

## Recommended roadmap

- **Phase 1 (low risk, high value, provider-general):** Lever 1 (autoload off) +
  Lever 3 (vector-parse cache). Verified-safe, no isolation/output change.
  Expected ~40–85 s/run on local providers, more on networked.
- **Phase 2 (medium):** Lever 2 (collection-metadata cache) + Lever 6 (lazy
  plugin imports). Removes redundant repeated collection/import.
- **Phase 3 (structural):** Lever 4 (batched isolation). Largest additional win;
  needs careful crash-fallback design + review.
- **Phase 4 (provider-targeted):** Lever 5 (key-import hoisting, fixture audit) —
  biggest payoff on token-backed/networked HSMs.
- **Orthogonal:** the `slow` marker (axis 1) for a fast basic profile via
  `-m "not slow"`.

## Findings-safety guarantees

None of the recommended levers reduce the set of collected items, their ids,
vector counts, or test outcomes, and none weaken crash survival:
- Caches (Levers 2, 3) store only *which tests/markers exist* and *parsed
  vectors*, invalidated by source mtime/size + tool version — never outcomes.
- Autoload-off (Lever 1) and batching (Lever 4) keep one-crash-per-subprocess
  survival; batching falls back to per-file on any crash.
- Fixture/key-import changes (Lever 5) still surface every failure; lifecycle
  tests stay function-scoped.

## Key file:line references

- Per-unit subprocess cmd build: `src/pkcs11_check/core/file_runner.py:2237-2247`
- Crash attribution / deselect loop: `core/file_runner.py:1681`, `:2647`, `:2919`;
  policy file `:333`, `:1767`
- Full-suite marker collection + (unused-for-persistence) serializers:
  `src/pkcs11_check/core/collection.py:26-57`, `:60`, `:123`
- Plugin eager imports / manifest reuse: `src/pkcs11_check/plugin.py:14-51`,
  `:22`, `:236-243`
- Vector loaders / parametrize: `testcases/wycheproof/wycheproof_loader.py`,
  `testcases/acvp/acvp_loader.py`, `testcases/wycheproof/test_wycheproof_ecdsa.py:257-293`
- Data paths: `src/pkcs11_check/testcases/data/__init__.py:71-76`
- Fixtures: `src/pkcs11_check/fixtures.py:63,94,386,517,530`
- Fetch seam for build-time cache: `src/pkcs11_check/cli/fetch_cmd.py:167,204`
</content>
</invoke>
