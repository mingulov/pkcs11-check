# pkcs11-check — Next-Steps Goals (2026-06-04)

Three independent lanes of remaining work, each written as a **startable goal**:
pick one, and the detailed task-by-task implementation plan follows. They don't
block each other and can run in any order.

| Lane | Goal in one line | Readiness | Risk |
|---|---|---|---|
| **A. Perf** | Cut the comprehensive pooled run from ~hours toward ~30 min, coverage-neutral | **Ready** (analysis done) | Low |
| **B. Fix phase** | Turn the catalogued provider findings + harness-blocked probes into *surfaced* findings | Ready (backbone exists) | Medium (must never hide a finding) |
| **C. Usability** | Make a newcomer productive against their own module in <5 min | Needs a short brainstorm first | Low |

---

## Lane A — Performance (Docker pooled)

**Goal:** a full multi-provider pooled run completes in roughly half the current
wall, with **byte-identical results** (no test dropped, no finding hidden).

**Why pick this:** the analysis is finished (`docs/findings/docker-pooled-
deep-audit-2026-06-04.md`), the wins are mechanical, and nothing touches
coverage. Single-run perf already shipped this session.

**Scope, in execution order (each is its own plan/PR):**
1. **T4 — streaming postprocess** *(do first; it also lifts the K=4 memory cap)*.
   Convert the load-all JSONL readers + multi-pass merge to single-pass streaming.
   - Files: `src/pkcs11_check/core/file_runner.py` (`_load_report_log_records`,
     `extract_coverage_from_jsonl`, `postprocess_jsonl_to_unified` — dedup the
     double read), `src/pkcs11_check/core/merge.py` (`merge_shard_dirs` + the 3
     full passes), test `tests/test_merge_streaming.py`.
   - DoD: same output bytes as today (golden-file test on a sample report.jsonl);
     peak RSS flat (~tens of MB vs 1.4 GB); meta-suite green.
2. **Per-provider duration-fed + duration-ordered sharding.**
   - File: `docker/test_pool.py` — pass `duration_by_unit=duration_by_unit_from_
     results(Path(f"artifacts/{p}-pooled/results.json"))` into `plan_shards`, and
     sort work items by batch duration (not shard count).
   - DoD: dry-run shows the heaviest batch balanced toward the file floor; falls
     back to count-balance when no prior results.json.
3. **Goal-driven autotuner.** Replace hand-tuned `SHARD_MAP` + fixed K with one
   target: `--target-wall 30m` / `--max-batch 300s` / `--saturate`, deriving K
   (cores/RAM, capped at 4 until T4 lands) and per-provider shard counts from
   measured durations; report when a single file is the binding floor.
4. **Parallel image builds + shared per-distro base.** Wrap the serial build loop
   in the existing `ThreadPoolExecutor` (cap 2–3, reduce per-build `-j`); add a
   shared `pkcs11-check-base` image to kill N× redundant `uv sync`/test-tools.
5. **Vectors → marshal at fetch** (supersede the runtime vector cache for Docker;
   precompiled binaries ride in the bind-mounted/cached `data/`).
6. **Cheap wins:** readiness polls instead of fixed sleeps (bouncyhsm `sleep 4`,
   etc.); artifacts to tmpfs + gzip the persisted `report.jsonl`.

**First task to start:** T4, step 1 — write a golden-file test that captures the
exact `postprocess_jsonl_to_unified` + `merge_shard_dirs` output on a small
fixture report.jsonl, so the streaming rewrite is provably byte-identical.

**Measure of success:** a before/after full pooled run (baseline commit vs HEAD)
on softhsm2+kryoptic+nss showing wall reduced with identical summaries.

---

## Lane B — Fix phase (apply the finding catalog)

**Goal:** every harness-blocked probe actually *runs* and surfaces real provider
behaviour; every catalogued provider finding is either confirmed (with a
regression test) or shown fixed — under the guard-rails in
`docs/findings/fix-plan.md`.

**Why pick this:** this is the product's core mission (find & report module
bugs). The classification backbone is shipped (46/46); the fix phase consumes
`docs/findings/catalog.md` / `failure-inventory.json` / `crash-inventory.json`.

**Non-negotiable guard-rails (from fix-plan.md):**
- A harness fix must make the probe *actually run* and surface real behaviour
  (crash → `fail`/finding; clean reject → pass; wrong accept → finding) — never a
  no-op or blanket pass.
- Every fix gets a dedicated regression test that re-triggers the original issue
  (prefer an offline **mock-`raw` meta-test** in `tests/*_runtime_classification.py`).
- Verify the *effect*, not the return code. CKR changes go through
  `src/pkcs11_check/testcases/ckr/_ckr_spec.py`.
- Doc-sync: update `docs/module-issues.md` in the same change.

**Scope, in order:**
1. Triage `catalog.md` + the inventories into a prioritized list; the
   **harness-blocked probes (PC-*)** come first — they currently *hide* real
   behaviour, the worst class.
2. Per finding (TDD): write the failing mock-`raw` meta-test → fix the harness →
   confirm the probe surfaces real behaviour → update `module-issues.md`.
3. Re-run the affected provider's artifacts to confirm the probe now executes.

**First task to start:** pick the top harness-blocked probe (e.g. PC-1 GCM
NULL-AAD), and write its failing mock-`raw` meta-test that re-triggers the block.

**Measure of success:** each fixed item has a green regression test + a
`module-issues.md` entry; a re-run shows the probe running, not skipped.

---

## Lane C — Usability / onboarding (adoption)

**Goal:** a developer with their own PKCS#11 module gets a meaningful first run
in under ~5 minutes, without reading the architecture docs.

**Why pick this:** it's the least-developed area and the one that gates external
adoption. Today the tool is an expert tool (token/slot/PIN setup + ~800 MB
vectors + Docker matrix are real friction).

**This lane needs a short brainstorm first** — requirements aren't pinned down.
Candidate scope to refine in that brainstorm:
- `pkcs11-check doctor` — diagnose module load / slot / PIN / token-init and print
  the exact next step.
- A `quickstart` path + optional auto-token-provisioning helper.
- Make the heavy vector suites **opt-in** so first-run is light (smoke by default).
- A "first run in 60 seconds" doc.
- Stabilize the CLI/findings contract toward 1.0.

**First task to start:** a focused brainstorm (`superpowers:brainstorming`) on the
onboarding flow → pick the 2–3 highest-friction points → then a detailed plan.

**Measure of success:** measured "time to first meaningful run" for a new user
drops to minutes; a documented quickstart + a `doctor` command exist.

---

## How to use this

Set a goal by naming a lane (or a concrete target like "pooled run under
30 minutes" → Lane A). On selection, the detailed task-by-task plan is written
for that lane and execution begins. Recommended default: **Lane A, starting with
T4** — highest mechanical leverage, zero coverage risk, and it unlocks the K cap.
</content>
