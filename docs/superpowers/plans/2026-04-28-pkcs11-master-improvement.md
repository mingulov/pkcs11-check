# PKCS#11-check Master Improvement Plan (Iterative, /loop-driven)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is designed to be re-entered repeatedly via `/loop` until the **Exit Criteria** are met.

**Goal:** Bring pkcs11-check to a state where every PKCS#11 module under test produces only **investigated, justified findings** — no unexplained failures, no missing-but-relevant mechanisms, no spec-noncompliance gaps in the test framework itself. Each module's pass/fail/xfail/skip count is traceable to a specific cause documented in `docs/module-issues.md`.

**Architecture:**
1. Pull fresh upstream test vector data and refresh the disabled-tests baseline.
2. Rebuild every Docker provider image (the `*-main` HEAD-tracking targets in particular) and execute the full test suite per provider, collecting artifacts.
3. For each new failure / new xfail / disappeared-pass, perform a triage investigation against the OASIS PKCS#11 spec and vendor-specific extensions. Outcome of each: real module bug | spec-allowed deviation (note + xfail) | pkcs11-check bug (queue Phase 5 fix).
4. Audit pkcs11-check's own functionality (helpers, fixtures, raw bindings, CLI, marker plumbing, isolation).
5. Gap analysis vs. PKCS#11 v2.40 / v3.0 / v3.1 / v3.2 surface area: enumerate untested mechanisms, untested CKR codes, missing security tests, missing CVE regressions.
6. Implement fixes (TDD, one PR-sized commit per fix) for everything classified as a pkcs11-check bug or gap in steps 3–5.
7. Re-enter Phase 1 to verify. Loop until no fix tasks remain and a full Phase 1 run produces no untriaged findings.

**Tech stack:** Python 3.13+ / uv / pytest / typer / rich / ruff / mypy --strict / Docker / pkcs11_check.raw (pure ctypes).

**Spec references:** OASIS spec at `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/`. Relevant vendor extension headers/docs:
- SoftHSM2: `https://github.com/softhsm/SoftHSMv2` (master / main)
- Kryoptic: `https://github.com/latchset/kryoptic`
- NSS: `https://hg.mozilla.org/projects/nss` (`pk11pub.h`, `pkcs11n.h`)
- OpenCryptoki: `https://github.com/opencryptoki/opencryptoki` (`opencryptoki.h`, `tok_specific.h`)
- BouncyHSM: `https://github.com/harrison314/BouncyHsm`
- tpm2-pkcs11: `https://github.com/tpm2-software/tpm2-pkcs11`

---

## How to run with /loop

Run from the repo root:

```bash
/loop "Open docs/superpowers/plans/2026-04-28-pkcs11-master-improvement.md and follow the 'Iteration Protocol' section: pick the highest-priority outstanding task, execute it fully per the per-phase rules, update the State Tracker, commit, then ScheduleWakeup if more work remains. Honour the Exit Criteria — if met, write a final summary and stop."
```

This uses /loop's **dynamic mode** (no fixed interval) so the model self-paces with `ScheduleWakeup`. Phase 1 (full Docker rebuild + test) can take 60+ minutes; per-finding investigations take 5–15 minutes each.

A fixed-interval variant for autonomous overnight runs:

```bash
/loop 30m "<same prompt as above>"
```

(Use only when a long-running phase is parked — fixed cadence will fire mid-run otherwise.)

---

## Iteration Protocol

Every tick of /loop, do **exactly** the following:

1. Read the **State Tracker** section at the bottom of this file.
2. If the Exit Criteria are met, write `## Loop Exit — Met YYYY-MM-DD` and halt (do NOT call `ScheduleWakeup`).
3. Else, pick the first unchecked task in this priority order:
   - Phase 5 fix tasks for **already-triaged** findings (drains the queue first).
   - Phase 2 triage tasks for **untriaged findings** from the most recent Phase 1 run.
   - Phase 1 sub-tasks (rebuild + test rounds) if Phase 2 queue is empty AND State Tracker says a Phase 1 run is due.
   - Phase 3 audit sub-tasks if Phases 1, 2, 5 quiesced for this iteration.
   - Phase 4 gap analysis sub-tasks once Phase 3 is complete for this iteration.
   - Phase 0 data refresh if last refresh > 7 days ago OR a manual `[ ] Phase 0 due` marker is set.
4. Execute the task per its phase's rules (below). Mark the checkbox done. **Commit** with a message matching the per-phase commit prefix.
5. Update the State Tracker (current iteration #, current phase, findings table delta, last action timestamp).
6. If more outstanding work, call `ScheduleWakeup` with delay 60–270 s for active short tasks, or 1200–1800 s for "wait for Docker rebuild to finish" idles. Otherwise, halt.

**Hard rules** (per `CLAUDE.md` and project memory):
- NEVER skip / suppress / disable real failures or crashes — failures ARE findings.
- NEVER reduce test vector counts to work around module limitations.
- NEVER use bare `except Exception: pass`. Every CKR check lists specific acceptable codes.
- Use `compliance.note(...)` for spec deviations that aren't bugs; `pytest.xfail(reason=...)` only with evidence and a spec reference in the reason string.
- All work merges to `dev` only. Never touch `main`.
- All commands prefixed `uv run`; tools are NOT on PATH.
- PIN values never logged.

---

## Phase 0 — Refresh Dependent Components

**Goal:** Fetch the latest upstream test vectors and disabled-tests baseline; verify integrity; surface any vector-set changes that would change test counts.

**Files:**
- `src/pkcs11_check/testcases/data/sources.toml` — pinned manifest (commit + SHA-256 + include filter per source)
- `src/pkcs11_check/testcases/data/` — own KAT JSONs (sha*.json, aes_ecb.json, mechanism_vectors/)
- `data/wycheproof/`, `data/cctv/`, `data/acvp/`, `data/x509-limbo/` — gitignored extracted directories
- `data/disabled-tests.txt` — disabled-tests baseline (tracked)
- `src/pkcs11_check/cli/fetch_cmd.py` — fetch-data + fetch-disabled implementation

**Commit prefix:** `chore(data):`

### Phase 0 Tasks

- [x] **0.1 — Inspect current pinned commits**

```bash
uv run pkcs11-check fetch-data --status
```
Expected: status table shows each source as PRESENT or MISSING with current pinned commit.

**Result (iter 1, 2026-04-28):** all 4 sources PRESENT. Note: `uv run` is silently broken in this shell (exit 120, no output); used `.venv/bin/pkcs11-check` directly. Logged as fix-queue row UV-001.

- [x] **0.2 — Check upstream HEAD for each source vs. pinned commit**

For each `[<name>]` block in `src/pkcs11_check/testcases/data/sources.toml`, fetch the upstream HEAD commit SHA and compare:

```bash
for repo in C2SP/wycheproof C2SP/CCTV usnistgov/ACVP-Server C2SP/x509-limbo; do
  echo "$repo:"
  curl -sSL "https://api.github.com/repos/$repo/commits?per_page=1" \
    | python3 -c "import json,sys; print('  HEAD:', json.load(sys.stdin)[0]['sha'])"
done
```
Expected: prints HEAD SHA per repo. Compare against `commit = "..."` in `sources.toml`.

**Result (iter 1, 2026-04-28):** all 4 behind upstream:

| source | pinned | pinned date | HEAD | HEAD date |
|---|---|---|---|---|
| wycheproof | 78898104 | 2026-03-11 | 4d535535 | 2026-04-28 |
| cctv | d091f096 | 2026-03-09 | 67c1397a | 2026-04-27 |
| acvp | 3611942e | 2026-03-11 | 15c0f3de | 2026-04-16 |
| x509-limbo | 9d594748 | 2026-03-03 | 086b0da8 | 2026-04-27 |

- [x] **0.3 — Decide per-source whether to bump**

For each source where HEAD ≠ pinned:
- If the diff is purely additive new vectors, prefer to bump.
- If upstream rewrote history or changed schema, write a note in the State Tracker `data_decisions` block and SKIP the bump (open a manual investigation task in Phase 4).

**Result (iter 1, 2026-04-28):** decided BUMP all 4 — these are all additive test corpora (Google Wycheproof, C2SP CCTV, NIST ACVP, C2SP x509-limbo) with no history rewrites in their workflow. 5–8 weeks of catch-up. Per-source rows in `data_decisions` table below. Each per-source bump (0.4–0.5) is its own task in subsequent /loop ticks so any schema breakage is caught and reverted in isolation.

- [ ] **0.4 — For each source to bump, compute new archive SHA-256**

Procedure (template — replace `<name>` and `<new_commit>`):
```bash
NAME=<name> NEWSHA=<new_commit>
URL=$(python3 -c "import tomllib; m=tomllib.loads(open('src/pkcs11_check/testcases/data/sources.toml').read()); s=m['$NAME']; print(f'https://github.com/{s[\"repo\"]}/archive/$NEWSHA.zip')")
curl -sSL "$URL" -o /tmp/$NAME.zip
sha256sum /tmp/$NAME.zip
```
Record the printed SHA. Update `sources.toml` setting `commit = "<new_commit>"` and `archive_sha256 = "<computed_sha>"`.

- [ ] **0.5 — Re-fetch data and verify**

```bash
uv run pkcs11-check fetch-data <name>
uv run pkcs11-check fetch-data --status
```
Expected: both commands succeed; status shows PRESENT with new commit.

- [ ] **0.6 — Refresh disabled-tests baseline**

```bash
uv run pkcs11-check fetch-disabled
```
Expected: prints download progress, writes `data/disabled-tests.txt`. Diff vs. pre-refresh: `git diff data/disabled-tests.txt`. Material diffs go into Phase 4 review queue.

- [ ] **0.7 — Run meta-tests to ensure data plumbing still works**

```bash
uv run python -m pytest tests/ -q
uv run ruff check src/ tests/
uv run mypy src/
```
Expected: all green. If meta-tests fail because the new data has a schema change, do NOT skip them — fix the loader in `src/pkcs11_check/testcases/` and add a regression test.

- [ ] **0.8 — Commit Phase 0**

```bash
git add src/pkcs11_check/testcases/data/sources.toml data/disabled-tests.txt
git commit -m "chore(data): refresh test vectors to <date>; bump <names>"
```

- [ ] **0.9 — Update State Tracker**

Set `phase0_last_run = YYYY-MM-DD` and `phase1_due = true` (the data changed → tests must rerun).

---

## Phase 1 — Docker Provider Refresh + Test Rounds

**Goal:** Rebuild every `*-main` Docker target (HEAD-tracking) and re-run the full test suite per provider against the latest pkcs11-check on `dev`. Collect artifacts. Diff results vs. previous run; the diff is the input queue for Phase 2.

**Files:**
- `docker/test-all.sh` — provider runner
- `docker/test.sh` — single-provider runner
- `docker/<provider>/Dockerfile.main` — HEAD-tracking image
- `docker/run-with-artifacts.sh` — artifact collector
- `artifacts/<provider>/{results,state,quality,coverage}.json` — per-run artifacts
- `artifacts/<provider>/console.log`, `report.jsonl` — full pytest output

**Commit prefix:** `chore(test-results):` — for snapshot commits of the artifacts/ directory after a clean run; do NOT commit per-iteration if artifacts churn.

### Phase 1 Tasks

- [ ] **1.1 — Force a no-cache rebuild of every `*-main` provider**

```bash
for tag in softhsm2-main kryoptic-main nss-main opencryptoki-master bouncyhsm tpm2; do
  docker compose -f docker/docker-compose.test.yml build --no-cache test-$tag 2>&1 | tail -20
done
```
Expected: each builds to completion. If any fails, do NOT proceed — file a Phase 5 task `fix: docker build for <tag>` with the build error.

- [ ] **1.2 — Snapshot pre-run results**

```bash
mkdir -p .baseline-runs/$(date +%Y-%m-%d)
cp -r artifacts/* .baseline-runs/$(date +%Y-%m-%d)/ 2>/dev/null || true
```
(`.baseline-runs/` is gitignored — local-only snapshots used for diffing.)

- [ ] **1.3 — Run full default-provider matrix**

```bash
bash docker/test-all.sh 2>&1 | tee /tmp/test-all.log
```
Expected: each provider runs to completion (or times out — recorded as a finding). Long-running: 60–120 min total. Use `ScheduleWakeup` ≥ 1800 s.

- [ ] **1.4 — Run the non-default providers**

```bash
for tag in softhsm2 kryoptic kryoptic-fips nss nss-pqc opencryptoki pkcs11-mock qryptotoken; do
  bash docker/test.sh $tag 2>&1 | tee /tmp/test-$tag.log
done
```
Expected: each completes (some have minimal mechanism support — that's fine, capture the artifact).

- [ ] **1.5 — Diff results.json per provider**

```bash
for d in artifacts/*/; do
  p=$(basename $d)
  echo "=== $p ==="
  diff <(jq -S . .baseline-runs/$(date +%Y-%m-%d)/$p/results.json 2>/dev/null || echo '{}') \
       <(jq -S . $d/results.json) || true
done
```
Expected: prints per-provider deltas. Each delta line (a passed→failed, passed→xfailed, missing→passed transition) becomes a row in the State Tracker findings table with `triaged = no`.

- [ ] **1.6 — Extract failure summaries**

For each provider with failures, produce a line-per-failure summary:
```bash
for d in artifacts/*/; do
  p=$(basename $d)
  jq -r 'select(.outcome=="failed") | "\(.nodeid)\t\(.longrepr // "no-repr" | tostring | .[0:200])"' \
    $d/report.jsonl > $d/failures.tsv
  echo "$p: $(wc -l < $d/failures.tsv) failures"
done
```
Expected: a `failures.tsv` per provider listing nodeid + first 200 chars of longrepr.

- [ ] **1.7 — Append untriaged findings to State Tracker**

For each unique `(provider, test_node_id, outcome)` tuple not already in the findings table, add a row:
```
| <provider> | <nodeid> | failed/xfailed/error/timeout | <one-line excerpt> | UNTRIAGED |
```

- [ ] **1.8 — Commit Phase 1**

```bash
git add artifacts/
git commit -m "chore(test-results): full Phase 1 run YYYY-MM-DD (<n> providers)"
```

- [ ] **1.9 — Update State Tracker**

Set `phase1_last_run = YYYY-MM-DD-HH:MM`, `phase1_due = false`, queue is now Phase 2 triage of UNTRIAGED rows.

---

## Phase 2 — Per-Finding Investigation

**Goal:** For each UNTRIAGED finding, classify as one of:
- **MOD-BUG** — module violates spec; record in `docs/module-issues.md`, mark test `pytest.xfail(reason="<spec-ref>; <module-ref>")`.
- **SPEC-NOTE** — module is within spec but exhibits implementation-defined behavior; use `compliance.note(...)` and `pytest.xfail` if the test was overly strict.
- **CHECK-BUG** — pkcs11-check itself has a bug (wrong CKR expectation, helper bug, fixture leak, vector parsing). Queue a Phase 5 fix task.
- **DATA-FLAKE** — vector regenerated upstream (Phase 0 caught it). Acceptable; record in State Tracker `data_decisions`.

**Files:**
- `docs/module-issues.md` — module bug catalogue (one section per provider+version)
- `src/pkcs11_check/compliance.py` — `note()` and ComplianceLevel enum
- `src/pkcs11_check/testcases/test_*.py` — where xfail markers may be added
- OASIS spec markdown: `/home/user/src/m/pkcs11-proxy/doc/oasis-tcs-pkcs11/working/doc/spec/*.md`

**Commit prefix:** `docs(module-issues):` for catalogue updates, `fix(test):` for xfail-with-spec-ref additions, `test:` for new regression tests.

### Phase 2 Per-Finding Loop (one task per finding row)

For each UNTRIAGED row in the State Tracker findings table:

- [ ] **2.N.a — Reproduce the failure in isolation**

```bash
bash docker/test.sh <provider> --timeout 60 -- <nodeid>
```
Or, for a local-builds run:
```bash
bash local-builds/test.sh <provider> -k "<nodeid suffix>" -v
```
Expected: same outcome as Phase 1.5 reported (failed/xfailed/error). If you cannot reproduce, mark the row `FLAKY` and create a follow-up task to investigate flakiness — do NOT silently dismiss.

- [ ] **2.N.b — Read the full longrepr + relevant test source**

```bash
jq -r '.longrepr' artifacts/<provider>/report.jsonl | head -200
```
Plus: open the test file at the relevant line, read the test logic, read any helper it calls.

- [ ] **2.N.c — Cross-check the OASIS PKCS#11 spec**

Locate the relevant section. Common mappings:
- C_Sign / C_Verify return codes → `function_return_values.md` + the per-mechanism file (`rsa.md`, `aes.md`, `ml_dsa.md`, `slh-dsa.md`, `elliptic_curves.md`)
- Session lifecycle → `session_mgmt_functions.md`
- Object attributes → `object_management_functions.md`, `attributes.md`
- Mechanism-specific behaviors → per-mechanism file

Quote the exact spec sentence that supports your classification (it goes into the xfail reason or compliance note).

- [ ] **2.N.d — Cross-check vendor extension behavior**

Look for vendor-specific behavior that overrides spec defaults:
- Kryoptic: check `src/kryoptic/...` for the relevant mechanism / attribute; check `mechanisms.toml` config.
- SoftHSM2: check `src/lib/SoftHSM.cpp`, `src/lib/crypto/*`.
- NSS: check `lib/softoken/pkcs11*.c`, `lib/freebl/*` for crypto, plus `lib/util/pkcs11n.h` for vendor mechanisms.
- OpenCryptoki: check `usr/lib/<token>/*.c`, particularly `tok_specific.c`.
- BouncyHSM: check `Src/BouncyHsm.Core/Services/Contracts/*` and the C# pkcs11 layer.
- tpm2-pkcs11: check `src/lib/*.c`, especially `mech.c`.

If the vendor implementation diverges from spec deliberately (documented in their tracker / changelog), that's a SPEC-NOTE. If it diverges silently, that's a MOD-BUG.

- [ ] **2.N.e — Classify and act**

| Classification | Action |
|---|---|
| MOD-BUG | Append to relevant section in `docs/module-issues.md` with: severity, exact CKR observed vs. expected, spec ref, test that catches it. Add `pytest.xfail(reason="<module> <version>: <one-line> — see docs/module-issues.md")` to the test. |
| SPEC-NOTE | Add `compliance.note("<module> behaves X — within spec because Y", ComplianceLevel.VENDOR)` near the assertion. Either expand the test to accept both behaviors with a list of acceptable CKRs, or `xfail` if the strict-spec interpretation is the test's contract. |
| CHECK-BUG | Add a row to the Phase 5 fix queue: file, line, what's wrong, proposed fix in one sentence. Do NOT fix it now — Phase 5 is TDD. |
| DATA-FLAKE | Note in State Tracker `data_decisions`. No code change. |

- [ ] **2.N.f — Mark the row TRIAGED**

Update the State Tracker findings table row: change `UNTRIAGED` → one of `MOD-BUG`, `SPEC-NOTE`, `CHECK-BUG`, `DATA-FLAKE`. Add a one-line summary column.

- [ ] **2.N.g — Commit**

```bash
git add <changed files>
git commit -m "docs(module-issues): triage <provider> <test> as <classification>"
```

(or `fix(test):` / `chore(state):` as appropriate)

---

## Phase 3 — pkcs11-check Functional Audit

**Goal:** Audit pkcs11-check's own code surface for correctness, consistency, dead code, missing defensive checks, and divergence between the documented architecture and reality.

**Audit slices** (each is one task; do them in order, one per /loop tick where the agent has slack — do NOT batch):

**Files:**
- `src/pkcs11_check/raw/` — raw ctypes bindings, recipes, type stubs
- `src/pkcs11_check/core/` — loader, file_runner, preflight, collection, isolation
- `src/pkcs11_check/cli/` — Typer commands
- `src/pkcs11_check/plugin.py`, `markers.py`, `fixtures.py`, `compliance.py`, `config.py`
- `src/pkcs11_check/testcases/conftest.py`, `_error_tuples.py`, `mechanism_*.py`
- `tests/` — meta-tests
- `docs/architecture.md` — must match reality after audit

**Commit prefix:** `refactor(audit):` for code cleanups, `docs(audit):` for doc fixups, `fix(audit):` for real bugs found.

### Phase 3 Audit Tasks

- [ ] **3.1 — Raw bindings completeness audit**

Compare `src/pkcs11_check/raw/api.py` (and `function_list.py` / equivalents) against `pkcs11_check/raw/types_std.py` (CK_FUNCTION_LIST_3_2 layout). Every function listed in the v3.2 function list MUST have a Python wrapper that:
- Uses the correct ctypes signature.
- Returns the raw CK_RV.
- Has a docstring referencing the spec section.

For each missing or wrong wrapper: record file/line + create a Phase 5 fix row.

- [ ] **3.2 — types_std.py vs OASIS pkcs11.h audit**

Compare CKR_*, CKM_*, CKA_*, CKO_*, CKK_*, CKF_* constants and CK_* struct definitions in `src/pkcs11_check/raw/types_std.py` against the OASIS `pkcs11.h` header. Ensure every constant added in v3.0 / v3.1 / v3.2 amendments is present with the correct value. Mismatches → Phase 5.

- [ ] **3.3 — Mechanism registry audit**

`src/pkcs11_check/testcases/mechanism_registry/` and `mechanism_catalog.py`: every entry should reference a CKM_* constant from types_std and have correct interface-version gating (`requires_v30` / `requires_v32` etc.). Cross-check vs. spec mechanism table.

- [ ] **3.4 — Fixture correctness audit**

`fixtures.py` and `raw_fixtures.py`: verify every fixture that opens a session also closes it on teardown; every fixture that logs in also logs out; every fixture marked session-scoped does not leak state across tests.

Look for:
- Leaked handles when a test raises mid-fixture.
- `C_Initialize` / `C_Finalize` ordering.
- Login state cleanup on failed setup.

- [ ] **3.5 — Marker plumbing audit**

`plugin.py` + `markers.py` + `core/collection.py` + `core/file_runner.py`: every documented marker (`@destructive`, `@slow`, `@requires_v30`, `@stress`, `@fuzz`, `@wycheproof`, `@acvp`, `@cctv`, etc.) is registered, deselectable from the CLI, and respected by the runner's isolation logic. Run:

```bash
uv run python -m pytest --collect-only -q -m "destructive" | head -20
uv run python -m pytest --collect-only -q -m "stress" | head -20
```

- [ ] **3.6 — CKR strict mode audit**

`src/pkcs11_check/testcases/ckr/` + `--ckr-strict` flag + `_error_tuples.py`: ensure every CKR test specifies acceptable codes via the predefined tuples (per CLAUDE.md), no bare `except: pass`, no permissive multi-CKR catch-alls used to dodge failures.

```bash
grep -rn "except Exception" src/pkcs11_check/testcases/ | grep -v "raise" | head
grep -rn "CKR_OK, CKR_" src/pkcs11_check/testcases/ | head
```

- [ ] **3.7 — Subprocess isolation audit**

Tests expecting crashes MUST run via `subprocess.run([sys.executable, "-c", script])` per CLAUDE.md. Find any test that triggers known-crash behavior (NULL deref, invalid params expected to segfault) but runs in-process:

```bash
grep -rn "C_GetAttributeValue\|C_DestroyObject\|seg" src/pkcs11_check/testcases/ | grep -v subprocess | head -50
```

- [ ] **3.8 — Helper API consistency**

`src/pkcs11_check/raw/recipes.py`: every helper (`gen_aes_key`, `gen_rsa_keypair`, `encrypt_single`, `destroy_quietly`, etc.) should have a consistent signature pattern, raise on hard failures (not return None silently), and be documented.

- [ ] **3.9 — CLI surface audit**

`src/pkcs11_check/cli/`: every command in `app.py` has typed parameters, --help works, and exits with non-zero on failure.

```bash
uv run pkcs11-check --help
for cmd in version test fetch-data fetch-disabled list-mechanisms; do
  uv run pkcs11-check $cmd --help 2>&1 | head -10 || echo "MISSING: $cmd"
done
```

- [ ] **3.10 — Architecture doc reconciliation**

`docs/architecture.md` claims a structure. Verify it: every directory mentioned exists; every "Core module" entry corresponds to an actual file; the test-vector data section matches `sources.toml`. Diffs → fix the doc.

- [ ] **3.11 — Lint / type / meta-test sweep**

```bash
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/
uv run mypy --strict src/
uv run python -m pytest tests/ -q
```
Expected: all green. Any failure → Phase 5 fix row.

- [ ] **3.12 — Commit Phase 3 findings**

```bash
git add -p   # selectively
git commit -m "refactor(audit): <slice> — <one-line>"
```
(One commit per audit slice that yielded changes.)

---

## Phase 4 — Deep Gap Analysis

**Goal:** Determine the gap between what pkcs11-check tests today and what it SHOULD test according to the PKCS#11 v2.40/v3.0/v3.1/v3.2 spec. Output: a prioritized list of missing tests / mechanisms / CKR codes / security scenarios. Each item becomes a Phase 5 task.

**Files:**
- All Phase 3 audit outputs.
- OASIS spec markdown directory.
- Latest CVE feeds for PKCS#11 modules.

**Commit prefix:** `docs(gap):` for the gap report itself.

### Phase 4 Tasks

- [ ] **4.1 — Mechanism coverage matrix**

Build a matrix: rows = every CKM_* in the v3.2 spec; columns = (has_test, has_wycheproof_vectors, has_acvp_vectors, has_known_answer_vectors, has_cross_verify, has_kat_negative). Source: parse `mechanism_registry/` + grep tests. Empty cells → gap.

- [ ] **4.2 — CKR coverage matrix**

Rows = every CKR_* code in `function_return_values.md`. Columns = (tested_in_ckr_strict, has_dedicated_test). Empty cells → gap.

- [ ] **4.3 — PKCS#11 function coverage**

Rows = every C_* function in v3.2 spec. Columns = (called_in_tests, has_dedicated_test, has_negative_path_test). Today (per `release-v0.1.0.md`): 64/104. Identify the 40 missing.

- [ ] **4.4 — Object class × attribute matrix**

Rows = (CKO_class, CKA_attribute) combinations from v3.2. Columns = (round-trips, default-checked, enforcement-checked). Find missing combinations.

- [ ] **4.5 — Security test gap analysis**

Cross-check `testcases/security/` against:
- Tookan attack vectors (see Tookan 2017 paper) — every variant present?
- Padding oracle (Bleichenbacher / Manger / Vaudenay) coverage.
- Key wrap / unwrap escalation.
- Attribute escalation (SENSITIVE False→True, EXTRACTABLE, COPYABLE — known NSS findings: are they generalized to other attrs?).
- Side-channel timing checks (where applicable).
- Known CVE list (`docs/cve-regression.md`) — does each CVE have a regression test?

- [ ] **4.6 — Multi-part / streaming API gap**

`release-v0.1.0.md` lists "Multi-part streaming API" as future work. Enumerate which streaming functions need tests: C_EncryptUpdate/Final, C_DecryptUpdate/Final, C_DigestUpdate/Final, C_SignUpdate/Final, C_VerifyUpdate/Final, plus the v3.0 message-based API (C_EncryptMessage, etc.).

- [ ] **4.7 — PIN management API gap**

Enumerate untested: C_InitToken, C_InitPIN, C_SetPIN. Note: must be `@destructive` due to lockout risk.

- [ ] **4.8 — Session-state matrix gap**

PKCS#11 session-state diagram (`session_mgmt_functions.md` figure 5) defines transitions. Verify each transition has a test (e.g., `RW Public Session → RW User Functions → RW Public via Logout`).

- [ ] **4.9 — Interface-version negotiation gap**

`core/loader.py` does v2.40 / v3.0 / v3.1 / v3.2 negotiation. Verify a test exists for each version with a module that supports it AND with a module that doesn't (forced-downgrade path).

- [ ] **4.10 — Compile gap report**

Write `docs/gap-analysis-YYYY-MM-DD.md` with each gap as a row: id, area, missing-item, priority (HIGH/MED/LOW), spec ref, sketch of the test to write.

- [ ] **4.11 — Translate gaps into Phase 5 tasks**

For each row in the gap report, add a row to the Phase 5 fix queue with `kind=GAP`, `gap_id=<id>`, `priority=<P>`.

- [ ] **4.12 — Commit gap report**

```bash
git add docs/gap-analysis-*.md
git commit -m "docs(gap): gap analysis YYYY-MM-DD (<n> items)"
```

---

## Phase 5 — Fixes and Improvements (TDD per task)

**Goal:** Drain the fix queue (Phase 2 CHECK-BUG rows + Phase 4 GAP rows + Phase 3 audit rows). One queue item per task. Strict TDD: failing test first, minimal fix, test passes, commit.

**Files:** vary per task — listed in each Phase 5.N row.

**Commit prefix:**
- `fix(<area>):` for CHECK-BUG fixes.
- `feat(<area>):` for new tests / new mechanism coverage from GAP.
- `test(<area>):` for purely new test files with no production-code change.

### Phase 5 Per-Task Recipe

For each row in the fix queue (Phase 2 CHECK-BUG and Phase 4 GAP):

- [ ] **5.N.a — Open the relevant test file (or create it)**

Pick path per the queue row. If new file, follow the template in `docs/architecture.md` "Writing new tests".

- [ ] **5.N.b — Write the failing test**

Express the bug or the missing scenario as an assertion. Show the full test code in the row notes. Mention exact CKR(s) acceptable per spec.

- [ ] **5.N.c — Run, verify it fails**

```bash
bash local-builds/test.sh <provider> -k "<test_name>" -v
```
Expected: FAIL with the gap-relevant assertion. **If it does NOT fail, the test is wrong** — rewrite before continuing.

- [ ] **5.N.d — Implement the minimal fix (CHECK-BUG) or supporting helper (GAP)**

For CHECK-BUG: change the production code in `src/pkcs11_check/`. For GAP: write only enough helper / fixture / vector-loader code to make the new test pass.

- [ ] **5.N.e — Run, verify it passes**

```bash
bash local-builds/test.sh <provider> -k "<test_name>" -v
```
Expected: PASS. Plus: run a broader scope to confirm no regression:
```bash
bash local-builds/test.sh <provider> -m "smoke or <relevant_marker>"
```

- [ ] **5.N.f — Lint + type-check**

```bash
uv run ruff check src/ tests/
uv run mypy --strict src/
```
Expected: green.

- [ ] **5.N.g — Commit**

```bash
git add <files>
git commit -m "<type>(<area>): <one-line>; closes <gap_id|finding_id>"
```

- [ ] **5.N.h — Mark queue row done in State Tracker**

---

## Phase 6 — Verify and Loop Back

**Goal:** Re-enter Phase 1 to confirm the fixes did not introduce regressions and that no new findings emerged. If the new run is clean (every finding has a triaged justification), the Exit Criteria are met.

### Phase 6 Tasks

- [ ] **6.1 — Snapshot the fix-queue tail**

When the Phase 5 queue empties, snapshot the count and IDs of all closed fixes since the previous Phase 1 run.

- [ ] **6.2 — Set `phase1_due = true`**

Update State Tracker. Next /loop tick will run Phase 1 again.

- [ ] **6.3 — After Phase 1 completes, diff vs. previous Phase 1 results**

If the new run has zero UNTRIAGED rows AND no row that was previously TRIAGED has flipped state (regression), goto 6.4. Otherwise, route new findings to Phase 2.

- [ ] **6.4 — Write iteration summary**

Append a row to the **Iteration Log** at the bottom of this plan: iteration number, date, fixes closed, findings triaged, current per-provider status. This is durable state.

- [ ] **6.5 — Decide: loop or exit**

Apply the Exit Criteria. If met, write `## Loop Exit — Met YYYY-MM-DD` and stop. If not met, set `phase1_due = false`; the loop will pick up the next Phase 5 / Phase 4 / Phase 3 task per priority.

---

## Loop Exit Criteria

**ALL** of the following must hold for the loop to exit:

1. Phase 5 fix queue is empty.
2. Phase 2 untriaged-findings table has zero UNTRIAGED rows after the most recent Phase 1 run.
3. Phase 1 was run within the last 24 hours, against the most recent `dev` HEAD AND with the most recent `sources.toml` data, AND its delta vs. the prior Phase 1 run is empty (no new failures, no flipped triages).
4. `uv run ruff check src/ tests/`, `uv run mypy --strict src/`, `uv run python -m pytest tests/ -q` all green.
5. `docs/architecture.md`, `docs/module-issues.md`, `docs/gap-analysis-*.md` are up to date (no `TODO`, no stale section, no contradiction with the State Tracker).
6. `docs/cve-regression.md` lists every CVE that has a regression test, with a one-line summary per CVE.

If 1–6 hold, the agent writes `## Loop Exit — Met <date>` with the final Phase 1 result table copied below it, then halts (no `ScheduleWakeup`).

---

## State Tracker

> **The /loop agent updates this section every tick.** Keep it terse. Append rows; do not rewrite history.

### Status

| Field | Value |
|---|---|
| current_iteration | 14 |
| phase0_last_run | 2026-04-28 (DONE) |
| phase1_last_run | (none yet) |
| phase1_due | true |
| phase3_audit_complete_for_iteration | (none) |
| phase4_gap_complete_for_iteration | (none) |
| last_action_at | 2026-04-28 |
| last_action | Phase 5 CHECK-002: widened `gen_keypair` / `gen_rsa_keypair` / `gen_ec_keypair` `public_attrs`+`private_attrs` to `Mapping[Any, Any] \| None`; widened `gen_keypair.pub_skip` to `set[Any] \| frozenset[Any]`; widened `xfail_if_known_ckr.known_ckrs` to `set[Any] \| tuple[Any, ...] \| frozenset[Any]`. mypy 312→255 (-57 this tick). **Cumulative: 516→255 (-261, -50.6%) — past halfway.** |

### Findings Table (Phase 1 → Phase 2)

| iter | provider | nodeid | outcome | excerpt | classification | linked_fix |
|---|---|---|---|---|---|---|
| (empty — populated by Phase 1.7) | | | | | | |

### Fix Queue (Phase 2 + Phase 4 → Phase 5)

| id | source | area | priority | description | status |
|---|---|---|---|---|---|
| UV-001 | side-finding (Phase 0.1) | tooling/docs | LOW | `uv run <cmd>` exits 120 silently in this shell; `/snap/bin/uv --version` also empty. Need to either (a) fix uv install / venv link, or (b) update CLAUDE.md to allow `.venv/bin/<cmd>` as fallback, or (c) wrap commands so failures aren't swallowed. Reproducer: `uv run python -c "print('hi')"` returns exit 120 with no output; `.venv/bin/python -c "print('hi')"` works. | OPEN |
| CHECK-001 | Phase 0.7 meta-tests | tests/test_cli.py | MED | 8 CLI test failures: `test_test_file_isolation_invokes_runner`, `test_test_restores_pin_env`, `test_test_auto_isolation_invokes_mixed_runner`, `test_test_defaults_to_auto_isolation`, `test_test_auto_resume_reuses_saved_units`, `test_test_isolation_builds_report_config[auto-json-...]`, `test_test_isolation_builds_report_config[file-junit-...]`, `test_test_file_isolation_resume_mismatch_is_reported`. Pre-existing (verified pre-Phase-0). Test the CLI `test` subcommand contract — likely runner/isolation refactor drift. Investigate test fixtures vs current `core/file_runner.py` API. | **CLOSED iter 7** — root cause: tests mocked `discover_pytest_units` / `run_isolated_pytest_units` / `run_preflight_subprocess` but NOT `collect_pytest_item_metadata`. With a baseline of ~0 entries, `disabled_nodeids` was empty so the unmocked path was skipped; with 19,684 entries the path fired and crashed (15 collection errors during a subprocess `pytest --collect-only` invoked with `--p11-manifest`). Fix: added `--ignore-disabled-tests` flag to each of the 7 invocations (test_test_test_isolation_invokes_runner with isolation=test never hit the path so didn't need the flag). 25/25 tests pass. |
| CHECK-002 | Phase 0.7 mypy | src/ (broad) | MED | 516 mypy --strict errors across 99 files. Sample: `core/file_runner.py:2776 Name "unit_records" already defined`, `cli/test_cmd.py:216 Argument "pin" expected SecretStr\|None`, multiple Mapping vs dict invariance issues. Need batch cleanup; cannot land Phase 5 fixes that touch these files cleanly until baseline is mypy-clean. | **IN PROGRESS** — 516→466 (-50) via pack.py __all__ fix in iter 9. Remaining categories (post-fix): 270 arg-type, 145→~95 attr-defined (after pack.py fix), 34 union-attr, 15 str-bytes-safe, 14 no-any-return, 6 operator, 6 no-untyped-def, 5 assignment, 4 unused-ignore, 3 each {type-arg, return-value, no-redef, import-untyped}, 2 misc, 1 each {var-annotated, index, call-overload}. Top files post-fix: recipes.py (likely ~30), test_misc_kdf.py, test_tls12.py, test_rsa_oaep.py. Plan: drain by category — quick wins (no-untyped-def, unused-ignore, type-arg, no-redef, return-value, import-untyped → ~22 errors), then medium chunks (no-any-return, operator, assignment, str-bytes-safe → ~40 errors), then arg-type/attr-defined/union-attr root-causes. |
| CHECK-003 | Phase 0.7 ruff | src/ | LOW | 4 ruff errors, all auto-fixable: "Remove default type arguments" (`Generator[X, None, None]` → `Generator[X]`). Single `ruff check --fix` should resolve. | **CLOSED iter 8** — `ruff check src/ tests/ --fix` resolved all 4 (UP043 in `fixtures.py` x2 and `raw_fixtures.py` x2). `ruff check src/ tests/` clean afterwards. |
| CHECK-004 | Phase 0.7 meta-tests | tests/test_raw_header_parity.py | HIGH | `test_function_count_not_regressed` and `test_all_reference_functions_present` both fail: `len(cur)=0 < len(ref)=104` — the live metadata source returns an empty set. Means `pkcs11_check.raw.metadata` (or whatever `cur` reads) is broken / missing the function inventory. This blocks any v3.x function-coverage gap analysis in Phase 4. Pre-existing (verified pre-Phase-0 via stash test). | **CLOSED iter 6** — root cause: `_extract_function_sigs` regex `r"'(C_\w+)':"` only matched single-quoted keys; ruff reformatted `metadata_std.py` to double quotes. Fix: regex `r"['\"](C_\w+)['\"]:"`. metadata_std.py actually has 208 functions vs 104 in reference, so no regression — current is a strict superset. |

### Data Decisions (Phase 0)

| date | source | decision | reason |
|---|---|---|---|
| 2026-04-28 | wycheproof | BUMP 78898104→4d535535 DONE (zip 26 MB, sha 9d326c66...; 341 files installed; 65,939 tests collected, +2,629 vs prior 63,310) | ~7 weeks of additive vectors; Google CI-tested corpus, no history rewrites |
| 2026-04-28 | cctv | BUMP d091f096→67c1397a DONE (zip 1.3 MB, sha 9380931c...; 53 files installed; 1,365 cctv tests collected cleanly) | ~7 weeks of additive C2SP vectors; additive-only by repo policy |
| 2026-04-28 | acvp | BUMP 3611942e→15c0f3de DONE (zip 490 MB, sha 12c1c795...; 838 files installed; 30,908 acvp tests collected cleanly) | ~5 weeks of additive NIST validation vectors; additive-only |
| 2026-04-28 | x509-limbo | BUMP 9d594748→086b0da8 DONE (zip 16 MB, sha a7d1a020...; 132 files installed; 1,686 x509/limbo tests collect cleanly) | ~8 weeks of additive C2SP x509 corpus; additive-only |

### Iteration Log (Phase 6.4)

| iter | date | fixes_closed | findings_triaged | per_provider_pass_count | notes |
|---|---|---|---|---|---|
| (empty — populated at end of each loop cycle) | | | | | |

---

## Self-Review (one-time, at plan creation)

- **Spec coverage:** all 7 user-supplied phases (0–6) have a section above. ✓
- **Placeholder scan:** no `TBD`, no `implement later`, no "similar to Task N", no `add error handling` waffle. Every command and step has concrete content. ✓
- **Type / name consistency:** classification values are the same set in Phase 2 and the findings table (MOD-BUG / SPEC-NOTE / CHECK-BUG / DATA-FLAKE). ✓
- **Loop semantics:** the protocol uses ScheduleWakeup-friendly delays and explicit halt on Exit Criteria. ✓
- **Project rules:** every per-phase rule references CLAUDE.md / project memory (no skipping crashes, no vector caps, no bare except, no main-branch touch). ✓
