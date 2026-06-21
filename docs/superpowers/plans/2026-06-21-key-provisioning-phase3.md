# Key-Provisioning Phase 3 — Visibility (Provisioning Report + Dedicated Finding) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make the currently-invisible provisioning outcomes explicit: a per-run **provisioning report** sidecar (counts of `ran_via_create` / `ran_via_unwrap` / `ran_via_external` / `skipped_no_path`, by object class) plus ONE dedicated conformance test that records per-class `C_CreateObject` absence/prohibition as a single `honest_deviation` xfail — so a no-create module's thousands of silent skips become one visible, well-classified record.

**Architecture:** A module-global event accumulator in `testcases/_provisioning.py` (mirroring `compliance._notes` / `classification._records`); `provision_*` record one event per resolution outcome. The pytest plugin drains events per-test in `pytest_runtest_teardown`, aggregates into a session `StashKey` counter, and emits a `ProvisioningReport` JSONL record in `pytest_sessionfinish` (exactly like the existing `CoverageReport`). `file_runner` merges those records across subprocess units and writes `provisioning.json` next to `coverage.json`. A dormant terminal banner fires only when `ran_via_external > 0` (wired now, exercised in Phase 6).

**Tech Stack:** Python 3.12+, pytest plugin hooks, pure-ctypes `pkcs11_check.raw`.

## Global Constraints

- **NEVER `int()`-wrap `CKR_`/`CKA_`/`CKM_`/`CKK_`/`CKO_` constants.**
- **The report is observability only — it must NEVER change a test verdict.** Recording an event must not raise, must not alter the create/unwrap/skip control flow, and a recording failure must be swallowed (best-effort), never propagated into a test.
- **Plugin/runner changes affect EVERY run** — additive only. Do not alter existing `CoverageReport`/teardown/sessionfinish behavior; add alongside it. Mirror the `CoverageReport` pattern exactly.
- **The dedicated test emits `honest_deviation` (xfail), never `fail`** — `C_CreateObject` absence is a base-spec conformance deviation, not a crypto/policy break.
- All four gates pass before each commit: `uv run ruff format --check .`, `uv run ruff check .`, `uv run --extra dev mypy --strict src`, `uv run pytest tests/`.

**Integration anchors (verified 2026-06-21):**
- `plugin.py`: StashKey decls ~61-70; `pytest_configure` ~198; `pytest_runtest_teardown` ~908 (clears `compliance`/`classification`); `pytest_sessionfinish` ~1139; `CoverageReport` emission ~1261-1269 (`report_log_plugin._write_json_data({"$report_type": "CoverageReport", **data})`).
- `core/file_runner.py`: `extract_coverage_from_jsonl` ~1584; `coverage.json` write in two `finally` blocks ~2790 and ~3686.
- `cli/test_cmd.py`: non-isolation `coverage.json` write ~477.
- `provision_*` outcome lines in `_provisioning.py`: secret (`provision_secret_key`), private (`provision_rsa_private_key`, `provision_ec_private_key`).

---

### Task 1: Provisioning-event accumulator + record at each outcome

**Files:**
- Modify: `src/pkcs11_check/testcases/_provisioning.py`
- Test: `tests/test_provisioning_events.py`

**Interfaces — Produces:**
```python
@dataclass(frozen=True)
class ProvisioningEvent:
    obj_class: str   # "secret" | "private" | "public" | "cert" | "data"
    method: str      # "ran_via_create" | "ran_via_unwrap" | "ran_via_external" | "skipped_no_path"

def record_provisioning_event(obj_class: str, method: str) -> None  # appends; never raises
def get_provisioning_events() -> list[ProvisioningEvent]            # copy
def clear_provisioning_events() -> None
```
Module-global `_provisioning_events: list[ProvisioningEvent] = []`. `record_provisioning_event` wraps its body so any error is swallowed (observability must never break a test).

**Wire into the three resolvers (record immediately BEFORE the return/skip):**
- `provision_secret_key`: before `return import_secret_key(...)` → `record_provisioning_event("secret", "ran_via_create")`; before the unwrap `return handle` → `("secret", "ran_via_unwrap")`; before EACH `pytest.skip(...)` → `("secret", "skipped_no_path")`.
- `provision_rsa_private_key` / `provision_ec_private_key`: same, with `obj_class="private"` (create → `ran_via_create`; unwrap → `ran_via_unwrap`; every skip → `skipped_no_path`).
- Do NOT record `ran_via_external` anywhere yet (Phase 6 adds the external path).

- [ ] **Step 1: Write failing tests** — `record`/`get`/`clear` round-trip; and (using the existing `tests/test_provision_secret_key.py` fakes) assert that a create-available secret provision records `("secret","ran_via_create")`, a force-unwrap records `("secret","ran_via_unwrap")`, and an off+absent records `("secret","skipped_no_path")`. Add an analogous private check.
- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** accumulator + wiring.
- [ ] **Step 4: Run → pass; all four gates.**
- [ ] **Step 5: Commit** `feat(provisioning): event accumulator + record create/unwrap/skip outcomes`.

---

### Task 2: Plugin aggregation → `ProvisioningReport` JSONL record

**Files:**
- Modify: `src/pkcs11_check/plugin.py`
- Test: `tests/test_provisioning_report_plugin.py`

**Behavior (mirror the `CoverageReport` path exactly — additive):**
1. Add a StashKey near line 70: `_PROVISIONING_COUNTS: pytest.StashKey[Counter[tuple[str, str]]] = pytest.StashKey()` (import `Counter` from `collections`).
2. In `pytest_configure` (~198): `config.stash[_PROVISIONING_COUNTS] = Counter()`.
3. In `pytest_runtest_teardown` (~908, alongside the existing `clear_notes()`/`clear_classifications()`): drain provisioning events into the stash counter then clear:
   ```python
   from pkcs11_check.testcases._provisioning import (
       get_provisioning_events, clear_provisioning_events,
   )
   counts = item.session.config.stash.get(_PROVISIONING_COUNTS, None)
   if counts is not None:
       for ev in get_provisioning_events():
           counts[(ev.obj_class, ev.method)] += 1
   clear_provisioning_events()
   ```
   Place this in the **ungated** part of teardown (events can come from any test file), and guard with `getattr`/`None` so a missing stash never raises.
4. In `pytest_sessionfinish` (~1139, after the `CoverageReport` emission ~1269): build and emit the report:
   ```python
   prov_counts = config.stash.get(_PROVISIONING_COUNTS, Counter())
   by_class: dict[str, dict[str, int]] = {}
   for (obj_class, method), n in prov_counts.items():
       by_class.setdefault(obj_class, {})[method] = n
   provisioning_data = {
       "by_class": by_class,
       "totals": {  # summed across classes
           m: sum(c.get(m, 0) for c in by_class.values())
           for m in ("ran_via_create", "ran_via_unwrap", "ran_via_external", "skipped_no_path")
       },
   }
   if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
       report_log_plugin._write_json_data({"$report_type": "ProvisioningReport", **provisioning_data})
   ```
   Emit ALWAYS (even all-zero) so the sidecar is consistently produced.

- [ ] **Step 1: Write failing test** — a plugin-level test that builds a fake `config` with the stash counter populated and asserts the `pytest_sessionfinish` helper (extract the report-building into a small pure helper `_build_provisioning_report(counts) -> dict` so it's unit-testable) returns the expected `by_class`/`totals` shape. Mirror any existing plugin unit test for `CoverageReport` (search `tests/` for one).
- [ ] **Step 2-4:** Implement the pure helper + wire the hooks; run → pass; gates.
- [ ] **Step 5: Commit** `feat(provisioning): aggregate provisioning events → ProvisioningReport JSONL`.

---

### Task 3: `provisioning.json` sidecar (isolation + non-isolation) + dormant external banner

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py`, `src/pkcs11_check/cli/test_cmd.py`
- Test: `tests/test_provisioning_sidecar.py`

**Behavior:**
1. `extract_provisioning_from_jsonl(jsonl_path: Path) -> dict[str, Any] | None` in `file_runner.py` — mirror `extract_coverage_from_jsonl` (~1584): stream the JSONL, filter `"$report_type" == "ProvisioningReport"`, **merge** across units (sum `by_class[class][method]` and `totals[method]`). Return `None` if no record found.
2. In BOTH `finally` blocks that write `coverage.json` (~2790, ~3686): also `extract_provisioning_from_jsonl(...)` and, if non-None, write `provisioning.json` next to `coverage.json` (`json.dumps(..., indent=2)`).
3. Non-isolation path in `cli/test_cmd.py` (~477, where `coverage.json` is written): same — extract + write `provisioning.json`.
4. **Dormant external banner:** after writing `provisioning.json` in each location, if `data["totals"]["ran_via_external"] > 0`, print a prominent `rich` banner (e.g. `console.print(Panel("⚠ EXTERNAL KEY PROVISIONING WAS ACTIVE — results are NOT a pure in-API run", style="bold yellow"))`). With Phase 3 alone `ran_via_external` is always 0, so the banner never fires yet; Phase 6 turns it on by recording external events. Use the `console` already in scope at those sites.

- [ ] **Step 1: Write failing test** — feed `extract_provisioning_from_jsonl` a temp JSONL with two `ProvisioningReport` records and assert the merge sums correctly; assert `None` when absent. (Sidecar file-writing is covered by Task 5's controller run.)
- [ ] **Step 2-4:** Implement; run → pass; gates.
- [ ] **Step 5: Commit** `feat(provisioning): provisioning.json sidecar + dormant external banner`.

---

### Task 4: Dedicated `test_provisioning_capability.py` conformance test

**Files:**
- Create: `src/pkcs11_check/testcases/test_provisioning_capability.py`
- (No module-free test — this is itself a testcase; its logic is exercised by Task 5's controller run. Keep it tiny and obviously correct.)

**Behavior:** One parametrized test over object classes `["secret", "private"]` (the two with a real probe; public/cert/data probes land in Phase 4 — do NOT include them here yet). For each: `verdict = profile_for(rs).create_verdict(obj_class)`; if `verdict in ("create_absent", "create_prohibited")` → `xfail_as("honest_deviation", kind="policy", label=f"C_CreateObject:{obj_class}", operation="C_CreateObject", summary=f"C_CreateObject not available for {obj_class} keys ({verdict})")`; else the test passes. Mirror the `xfail_as` shape in `testcases/test_attribute_invariants.py`. Use the `p11_raw_session` fixture (a fresh session; this is a small file). Import `profile_for` from `_provisioning`, `xfail_as` from `pkcs11_check.classification`.

- [ ] **Step 1:** Read `test_attribute_invariants.py` for the `xfail_as` pattern + a small-file fixture example.
- [ ] **Step 2:** Write the test file (one parametrized function over secret/private).
- [ ] **Step 3:** `uv run pytest --collect-only` includes it cleanly; all four gates.
- [ ] **Step 4: Commit** `feat(provisioning): dedicated per-class C_CreateObject-availability conformance test`.

---

### Task 5: Controller real-module validation (NOT a gate test)

**Executed by the controller.**
- [ ] Run a small slice (e.g. the migrated wycheproof secret + private files) against softhsm2 (`--key-inject=off`, default) and confirm `provisioning.json` is written next to the run artifacts with `totals.ran_via_create > 0` and well-formed `by_class`.
- [ ] Run the same against a **no-create scenario**: use `--key-inject=force-unwrap` on softhsm2 (forces unwrap) and confirm `totals.ran_via_unwrap > 0`; or point at a real no-create module (freehsm-c docker) with `--key-inject=off` and confirm `skipped_no_path > 0` + the dedicated `test_provisioning_capability.py` records the `honest_deviation` xfail.
- [ ] Confirm the dormant external banner does NOT fire (ran_via_external == 0).
- [ ] Record results in the ledger. Then final whole-branch review → merge to `dev`.

## Notes
- The `_build_provisioning_report` pure helper (Task 2) is what keeps the plugin change unit-testable without a module.
- `ran_via_external` is plumbed through report/sidecar/banner now but only RECORDED in Phase 6 — do not add an external code path here.
- Public/cert/data create-verdict probes and their inclusion in the capability test arrive in Phase 4.
