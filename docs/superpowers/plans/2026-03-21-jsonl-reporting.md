# JSONL-Based Test Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace pytest-json-report with pytest-reportlog JSONL for crash-safe per-test results with iterative deselect crash recovery.

**Architecture:** pytest-reportlog writes one JSON line per test event, flushed immediately. The runner reads JSONL files to extract per-test results (with outcome mapping for xfail), identify crash culprits, and iteratively retry with `--deselect`. Two artifacts: `report.jsonl` (raw) and `results.json` (aggregated).

**Tech Stack:** pytest-reportlog 1.0.0, Python 3.11+, pytest 9.x

**Spec:** `docs/superpowers/specs/2026-03-21-jsonl-reporting-design.md`

---

## Phase 1: JSONL Reading + Outcome Mapping

### Task 1: Promote pytest-reportlog to main dependency

**Files:**
- Modify: `pyproject.toml:33,96`

- [ ] **Step 1: Move pytest-reportlog from dev to main deps, keep json-report for now**

In `pyproject.toml`, add `"pytest-reportlog>=1.0.0"` to the main `dependencies` list (around line 33). Keep it in dev deps too (line 96) — no harm. Do NOT remove `pytest-json-report` yet.

- [ ] **Step 2: Run `uv sync` and verify both plugins are available**

Run: `uv sync && uv run python -c "import pytest_reportlog; import pytest_jsonreport"`
Expected: No import errors

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "deps: promote pytest-reportlog to main dependencies"
```

---

### Task 2: `_read_jsonl_results()` with outcome mapping and longrepr flattening

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (add new function near line 949)
- Test: `tests/test_file_runner.py`

- [ ] **Step 1: Write failing tests for outcome mapping**

Add to `tests/test_file_runner.py`:

```python
def test_read_jsonl_results_maps_outcomes(tmp_path: Path) -> None:
    """Outcome mapping: skipped+wasxfail→xfailed, passed+wasxfail→xpassed."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("\n".join([
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_pass",
                     "when": "call", "outcome": "passed", "duration": 0.1,
                     "start": 1000.0, "stop": 1000.1, "sections": [],
                     "location": ["t.py", 1, "test_pass"]}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_skip",
                     "when": "call", "outcome": "skipped", "duration": 0.0,
                     "sections": []}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_xfail",
                     "when": "call", "outcome": "skipped", "duration": 0.05,
                     "wasxfail": "known bug", "start": 1000.2, "stop": 1000.25,
                     "longrepr": "('t.py', 10, 'known bug')",
                     "location": ["t.py", 10, "test_xfail"], "sections": []}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_xpass",
                     "when": "call", "outcome": "passed", "duration": 0.03,
                     "wasxfail": "expected fail", "sections": []}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_fail",
                     "when": "call", "outcome": "failed", "duration": 0.2,
                     "longrepr": {"reprcrash": {"message": "assert False", "path": "t.py", "lineno": 20},
                                  "reprtraceback": {"reprentries": [{"lines": ["    assert False"], "reprfileloc": {"path": "t.py", "lineno": 20}}]},
                                  "sections": [], "chain": []},
                     "sections": [["Captured stdout call", "debug output\n"],
                                  ["Captured stderr call", "err msg\n"]],
                     "location": ["t.py", 20, "test_fail"]}),
    ]) + "\n")

    from pkcs11_check.core.file_runner import _read_jsonl_results
    detail = _read_jsonl_results(jsonl)

    assert detail is not None
    assert detail["counts"]["passed"] == 1
    assert detail["counts"]["skipped"] == 1
    assert detail["counts"]["xfailed"] == 1
    assert detail["counts"]["xpassed"] == 1
    assert detail["counts"]["failed"] == 1
    # Only non-passing in tests array
    tests = detail["tests"]
    assert len(tests) == 3  # xfailed, xpassed, failed (not passed, not skipped)
    xf = next(t for t in tests if t["outcome"] == "xfailed")
    assert xf["wasxfail"] == "known bug"
    assert xf["nodeid"] == "t.py::test_xfail"
    xp = next(t for t in tests if t["outcome"] == "xpassed")
    assert xp["wasxfail"] == "expected fail"
    fail = next(t for t in tests if t["outcome"] == "failed")
    assert "assert False" in fail["longrepr"]  # flattened from dict
    assert fail["stdout"] == "debug output\n"
    assert fail["stderr"] == "err msg\n"
```

- [ ] **Step 2: Write failing test for longrepr flattening edge cases**

```python
def test_read_jsonl_results_flattens_longrepr(tmp_path: Path) -> None:
    """longrepr can be dict, string, or None."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("\n".join([
        # dict longrepr (failure)
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_dict_lr",
                     "when": "call", "outcome": "failed", "duration": 0.1,
                     "longrepr": {"reprcrash": {"message": "KeyError: 'x'", "path": "t.py", "lineno": 5},
                                  "reprtraceback": {"reprentries": []}, "sections": [], "chain": []},
                     "sections": []}),
        # string longrepr (xfail)
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_str_lr",
                     "when": "call", "outcome": "skipped", "duration": 0.0,
                     "wasxfail": "reason", "longrepr": "('t.py', 10, 'Skipped: reason')",
                     "sections": []}),
        # null longrepr (pass — but we force it into tests for this test)
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_none_lr",
                     "when": "call", "outcome": "failed", "duration": 0.0,
                     "longrepr": None, "sections": []}),
    ]) + "\n")

    from pkcs11_check.core.file_runner import _read_jsonl_results
    detail = _read_jsonl_results(jsonl)
    tests = detail["tests"]
    dict_lr = next(t for t in tests if t["nodeid"] == "t.py::test_dict_lr")
    assert isinstance(dict_lr["longrepr"], str)
    assert "KeyError: 'x'" in dict_lr["longrepr"]
    str_lr = next(t for t in tests if t["nodeid"] == "t.py::test_str_lr")
    assert isinstance(str_lr["longrepr"], str)
    none_lr = next(t for t in tests if t["nodeid"] == "t.py::test_none_lr")
    assert "longrepr" not in none_lr
```

- [ ] **Step 3: Write failing test for setup-skip and fixture error**

```python
def test_read_jsonl_results_handles_setup_skip(tmp_path: Path) -> None:
    """Test skipped in setup (no when=call) counted as skipped, not crash."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("\n".join([
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_a",
                     "when": "setup", "outcome": "skipped", "duration": 0.0,
                     "longrepr": "('t.py', 1, 'no module')", "sections": []}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_b",
                     "when": "call", "outcome": "passed", "duration": 0.1,
                     "sections": []}),
    ]) + "\n")

    from pkcs11_check.core.file_runner import _read_jsonl_results
    detail = _read_jsonl_results(jsonl)
    assert detail["counts"]["skipped"] == 1
    assert detail["counts"]["passed"] == 1


def test_read_jsonl_results_handles_collect_error(tmp_path: Path) -> None:
    """CollectReport with error recorded, no TestReports."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text(
        json.dumps({"$report_type": "CollectReport", "nodeid": "t.py",
                     "outcome": "error",
                     "longrepr": "ImportError: No module named 'foo'",
                     "sections": []}) + "\n"
    )

    from pkcs11_check.core.file_runner import _read_jsonl_results
    detail = _read_jsonl_results(jsonl)
    assert detail["counts"]["error"] == 1
    assert any("ImportError" in t.get("longrepr", "") for t in detail["tests"])
```

- [ ] **Step 4: Write failing test for missing/truncated JSONL**

```python
def test_read_jsonl_results_returns_none_for_missing(tmp_path: Path) -> None:
    from pkcs11_check.core.file_runner import _read_jsonl_results
    assert _read_jsonl_results(tmp_path / "nope.jsonl") is None


def test_read_jsonl_results_skips_truncated_lines(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text(
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_ok",
                     "when": "call", "outcome": "passed", "duration": 0.1,
                     "sections": []}) + "\n"
        + '{"$report_type": "TestReport", "trunca'  # incomplete line
    )

    from pkcs11_check.core.file_runner import _read_jsonl_results
    detail = _read_jsonl_results(jsonl)
    assert detail is not None
    assert detail["counts"]["passed"] == 1
```

- [ ] **Step 5: Run tests — verify they all fail**

Run: `uv run python -m pytest tests/test_file_runner.py -k "read_jsonl" -v`
Expected: All new tests FAIL (function not defined)

- [ ] **Step 6: Implement `_read_jsonl_results()`**

Add to `src/pkcs11_check/core/file_runner.py` near line 949 (before or after `_extract_per_unit_test_detail`):

```python
def _flatten_longrepr(longrepr: Any) -> str | None:
    """Flatten pytest's longrepr from dict or string to plain string."""
    if longrepr is None:
        return None
    if isinstance(longrepr, str):
        return longrepr
    if isinstance(longrepr, dict):
        crash = longrepr.get("reprcrash", {})
        msg = crash.get("message", "")
        path = crash.get("path", "")
        lineno = crash.get("lineno", "")
        tb = longrepr.get("reprtraceback", {})
        entries = tb.get("reprentries", []) if isinstance(tb, dict) else []
        lines: list[str] = []
        for entry in entries:
            loc = entry.get("reprfileloc", {})
            if loc:
                lines.append(f"{loc.get('path', '')}:{loc.get('lineno', '')}")
            for line in entry.get("lines", []):
                lines.append(line)
        if lines:
            return "\n".join(lines) + f"\n{path}:{lineno}: {msg}"
        return f"{path}:{lineno}: {msg}" if msg else None
    return str(longrepr)


def _map_outcome(raw_outcome: str, wasxfail: str | None) -> str:
    """Map pytest's internal outcome to unified outcome."""
    if wasxfail is not None:
        if raw_outcome == "skipped":
            return "xfailed"
        if raw_outcome == "passed":
            return "xpassed"
    return raw_outcome


def _read_jsonl_results(jsonl_path: Path) -> dict[str, Any] | None:
    """Read a pytest-reportlog JSONL file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or empty.
    """
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None

    if not text.strip():
        return None

    counts: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    non_passing: list[dict[str, Any]] = []
    # Track per-nodeid state for setup-skip detection
    seen_call: set[str] = set()
    setup_skipped: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue  # truncated line

        rtype = record.get("$report_type")

        # Handle CollectReport errors (import/syntax errors)
        if rtype == "CollectReport" and record.get("outcome") == "error":
            counts["error"] = counts.get("error", 0) + 1
            lr = _flatten_longrepr(record.get("longrepr"))
            entry: dict[str, Any] = {
                "nodeid": record.get("nodeid", ""),
                "outcome": "error",
                "duration": 0.0,
            }
            if lr:
                entry["longrepr"] = lr
            non_passing.append(entry)
            continue

        if rtype != "TestReport":
            continue

        nodeid = record.get("nodeid", "")
        when = record.get("when", "")

        # Handle setup-phase skips (no call phase follows)
        if when == "setup" and record.get("outcome") == "skipped":
            setup_skipped.add(nodeid)
            continue

        if when == "setup" and record.get("outcome") == "error":
            # Fixture error — count as error
            if nodeid not in seen_call:
                counts["error"] = counts.get("error", 0) + 1
                # Only add detail for the first fixture error
                if not any(t.get("outcome") == "error" and "fixture" in t.get("longrepr", "")
                           for t in non_passing):
                    lr = _flatten_longrepr(record.get("longrepr"))
                    entry = {"nodeid": nodeid, "outcome": "error", "duration": 0.0}
                    if lr:
                        entry["longrepr"] = lr
                    non_passing.append(entry)
            continue

        if when != "call":
            continue

        seen_call.add(nodeid)
        raw_outcome = record.get("outcome", "passed")
        wasxfail = record.get("wasxfail")
        outcome = _map_outcome(raw_outcome, wasxfail)
        counts[outcome] = counts.get(outcome, 0) + 1

        if outcome in {"passed", "skipped"}:
            continue

        entry = {
            "nodeid": nodeid,
            "outcome": outcome,
            "duration": record.get("duration", 0.0),
        }
        if record.get("start"):
            entry["start"] = record["start"]
        if wasxfail is not None:
            entry["wasxfail"] = wasxfail
        lr = _flatten_longrepr(record.get("longrepr"))
        if lr:
            entry["longrepr"] = lr
        if record.get("location"):
            entry["location"] = record["location"]
        # Extract stdout/stderr from sections
        for section_name, section_content in record.get("sections", []):
            if "stdout" in section_name.lower():
                entry["stdout"] = section_content
            elif "stderr" in section_name.lower():
                entry["stderr"] = section_content
        non_passing.append(entry)

    # Count setup-skipped tests that never got a call phase
    for nodeid in setup_skipped:
        if nodeid not in seen_call:
            counts["skipped"] = counts.get("skipped", 0) + 1

    return {"counts": counts, "tests": non_passing}
```

- [ ] **Step 7: Run tests — verify they all pass**

Run: `uv run python -m pytest tests/test_file_runner.py -k "read_jsonl" -v`
Expected: All new tests PASS

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: add _read_jsonl_results with outcome mapping and longrepr flattening"
```

---

### Task 3: Inject `--report-log` into subprocess cmd alongside `--json-report`

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py:104-125` (`_collection_args`), lines `1378-1395` (subprocess cmd construction)

- [ ] **Step 1: Strip `--report-log` from `_collection_args()`**

In `_collection_args()` at line 104, add `--report-log` to the stripped args. Add `"--report-log"` to the set on line 112 and add a startswith check for `--report-log=`:

```python
if arg in {"-q", "-v", "--no-header", "--json-report", "--report-log"}:
    continue
if arg.startswith("--json-report-file=") or arg.startswith("--json-report-omit=") or arg.startswith("--report-log="):
    continue
```

Also update the value-consuming check:
```python
if arg in {"--tb", "--json-report-file", "--json-report-omit", "--junit-xml", "--report-log"}:
```

- [ ] **Step 2: Add `--report-log` to subprocess cmd for file-level units**

At lines 1378-1395 where the subprocess cmd is built for file-level units, add JSONL temp file creation alongside the existing json-report:

```python
if unit_granularity == "file":
    # JSON report (existing, kept during migration)
    unit_json_fd, unit_json_raw = tempfile.mkstemp(...)
    ...
    # JSONL report (new)
    unit_jsonl_fd, unit_jsonl_raw = tempfile.mkstemp(
        prefix="pkcs11-check-jsonl-", suffix=".jsonl"
    )
    os.close(unit_jsonl_fd)
    unit_jsonl_path = Path(unit_jsonl_raw)
    cmd = [
        sys.executable, "-m", "pytest", unit, *pytest_args,
        "--json-report", f"--json-report-file={unit_json_path}",
        "--json-report-omit=collectors",
        "--report-log", str(unit_jsonl_path),
    ]
```

- [ ] **Step 3: Read JSONL results alongside json-report, prefer JSONL**

After the subprocess completes, read JSONL and prefer it over json-report:

```python
detail: dict[str, Any] | None = None
if unit_jsonl_path is not None:
    detail = _read_jsonl_results(unit_jsonl_path)
    unit_jsonl_path.unlink(missing_ok=True)
if detail is None and unit_json_path is not None:
    detail = _extract_per_unit_test_detail(unit_json_path)
```

- [ ] **Step 4: Run all meta-tests**

Run: `uv run python -m pytest tests/ -v --timeout 60`
Expected: All 114+ tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py
git commit -m "feat: inject --report-log alongside --json-report, prefer JSONL results"
```

---

### Task 4: Add `_identify_crash_culprit()` from JSONL

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (add new function)
- Test: `tests/test_file_runner.py`

- [ ] **Step 1: Write failing tests**

```python
def test_identify_crash_culprit_from_jsonl(tmp_path: Path) -> None:
    """Crash culprit is the test with setup but no teardown."""
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("\n".join([
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_a",
                     "when": "setup", "outcome": "passed"}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_a",
                     "when": "call", "outcome": "passed"}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_a",
                     "when": "teardown", "outcome": "passed"}),
        json.dumps({"$report_type": "TestReport", "nodeid": "t.py::test_b",
                     "when": "setup", "outcome": "passed"}),
        # crash here — no call or teardown for test_b
    ]) + "\n")

    from pkcs11_check.core.file_runner import _identify_crash_culprit
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit == "t.py::test_b"
    assert completed == ["t.py::test_a"]


def test_identify_crash_culprit_empty_jsonl(tmp_path: Path) -> None:
    jsonl = tmp_path / "report.jsonl"
    jsonl.write_text("")
    from pkcs11_check.core.file_runner import _identify_crash_culprit
    culprit, completed = _identify_crash_culprit(jsonl)
    assert culprit is None
    assert completed == []
```

- [ ] **Step 2: Implement `_identify_crash_culprit()`**

```python
def _identify_crash_culprit(
    jsonl_path: Path,
) -> tuple[str | None, list[str]]:
    """Identify crash culprit and completed tests from partial JSONL.

    Returns (culprit_nodeid, list_of_completed_nodeids).
    culprit is None if no incomplete test is found.
    """
    try:
        text = jsonl_path.read_text()
    except (FileNotFoundError, OSError):
        return None, []

    # Track per-nodeid phases
    phases: dict[str, set[str]] = {}
    order: list[str] = []

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("$report_type") != "TestReport":
            continue
        nodeid = record.get("nodeid", "")
        when = record.get("when", "")
        if nodeid not in phases:
            phases[nodeid] = set()
            order.append(nodeid)
        phases[nodeid].add(when)

    completed = [nid for nid in order if "teardown" in phases.get(nid, set())]
    culprit = None
    for nid in order:
        p = phases.get(nid, set())
        if "setup" in p and "teardown" not in p:
            culprit = nid
            break

    return culprit, completed
```

- [ ] **Step 3: Run tests — verify pass**

Run: `uv run python -m pytest tests/test_file_runner.py -k "crash_culprit" -v`

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: add _identify_crash_culprit from JSONL event order"
```

---

## Phase 2: Iterative Deselect Crash Recovery

### Task 5: Rewrite crash handler to iterative deselect loop

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py:1472-1513` (crash handler in main loop)

This is the core change. Replace the single-retry + escalation with the iterative deselect loop. The loop:
1. Reads JSONL for completed tests + crash culprit
2. Runs culprit alone for confirmation
3. Retries file with `--deselect` for all completed + culprits
4. Repeats until file passes or exit conditions hit

Exit conditions: `max_crashes_per_file` reached, `max_deselect_iterations` (10) reached, deselect arg length > 100KB → escalate via `_escalate_current_file()`.

- [ ] **Step 1: Implement iterative deselect loop replacing current crash handler**

Replace the block at lines 1472-1513 (the `if status == "crashed":` block for `granularity == "mixed" and unit_granularity == "file"`) with the iterative deselect loop. This is a large code change — implement the full loop with all guards per the spec.

Key implementation details:
- Accumulate `deselect_set: set[str]` across iterations
- Track `crash_count` per file
- Check `sum(len(f"--deselect={nid}") for nid in deselect_set) > 100_000` for size guard
- Keep `_escalate_current_file` as final fallback
- Merge JSONL details from all iterations into `per_unit_details[unit]`

- [ ] **Step 2: Remove `_deselect_args_for_crash()` (replaced by JSONL-based approach)**

Delete the function at line 1161 and its stdout-parsing logic. The existing retry-with-deselect code in the crash handler (lines 1538-1618) is also removed — it's replaced by the iterative loop.

- [ ] **Step 3: Run all meta-tests**

Run: `uv run python -m pytest tests/ -v --timeout 60`
Expected: All tests pass (mocked tests don't exercise crash recovery — they pass through)

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py
git commit -m "feat: iterative deselect crash recovery using JSONL"
```

---

## Phase 3: `--isolation none` via plugin.py

### Task 6: Conditional `--report-log` in plugin.py for `--isolation none`

**Files:**
- Modify: `src/pkcs11_check/plugin.py`
- Modify: `src/pkcs11_check/cli/test_cmd.py:76-85,253`

- [ ] **Step 1: Add conditional `--report-log` injection in plugin.py**

In `plugin.py`, add a `pytest_configure` hook that injects `--report-log` when `--p11-module` is set and the user hasn't already passed `--report-log`:

```python
def pytest_configure(config: Any) -> None:
    """Inject --report-log for non-isolated runs when generating JSON output."""
    # Only inject if --p11-module is set (not meta-tests)
    if config.getoption("p11_module", default=None) is None:
        return
    # Don't inject if user already passed --report-log
    if config.getoption("report_log", default=None) is not None:
        return
    # Only inject for machine-readable output (env var set by test_cmd.py)
    if os.environ.get("PKCS11_CHECK_REPORT_LOG"):
        config.option.report_log = os.environ["PKCS11_CHECK_REPORT_LOG"]
```

- [ ] **Step 2: Update test_cmd.py to set JSONL path for `--isolation none`**

In `test_cmd.py`, when `isolation == "none"` and `output == "json"`, set `PKCS11_CHECK_REPORT_LOG` env var with a temp path before calling `pytest.main()`. After pytest completes, read the JSONL and build `results.json` using `_read_jsonl_results()` instead of `postprocess_json_report_to_unified()`.

- [ ] **Step 3: Run meta-tests**

Run: `uv run python -m pytest tests/ -v --timeout 60`

- [ ] **Step 4: Commit**

```bash
git add src/pkcs11_check/plugin.py src/pkcs11_check/cli/test_cmd.py
git commit -m "feat: activate --report-log for --isolation none via plugin.py"
```

---

## Phase 4: Remove pytest-json-report

### Task 7: Remove json-report injection and old extraction code

**Files:**
- Modify: `pyproject.toml` (remove `pytest-json-report`)
- Modify: `src/pkcs11_check/core/file_runner.py` (remove json-report cmd injection, `_extract_per_unit_test_detail`, `_extract_xfail_reason`, `postprocess_json_report_to_unified`)
- Modify: `src/pkcs11_check/cli/test_cmd.py` (remove json-report from `_build_pytest_args`)
- Modify: `tests/test_file_runner.py` (remove json-report mock tests, keep JSONL tests)

- [ ] **Step 1: Remove `pytest-json-report` from pyproject.toml**

Remove `"pytest-json-report>=1.5.0"` from main `dependencies`.

- [ ] **Step 2: Remove json-report injection from file_runner.py subprocess cmd**

Remove `--json-report`, `--json-report-file`, `--json-report-omit` from the subprocess command construction. Remove `unit_json_path` temp file creation. The JSONL path is now the only report file.

- [ ] **Step 3: Remove old functions**

Delete:
- `_extract_xfail_reason()` (~line 922)
- `_extract_per_unit_test_detail()` (~line 949)
- `postprocess_json_report_to_unified()` (~line 473)

- [ ] **Step 4: Remove json-report from `_build_pytest_args` in test_cmd.py**

Remove lines 81-83 (`--json-report`, `--json-report-file`, `--json-report-omit`) and the `postprocess_json_report_to_unified` call at line 253.

- [ ] **Step 5: Update test mocks**

Remove tests that mock json-report files (`test_extract_per_unit_test_detail_*`). Update any remaining tests that write fake json-report files to write JSONL instead.

- [ ] **Step 6: Run all tests**

Run: `uv run python -m pytest tests/ -v --timeout 60`

- [ ] **Step 7: Run `uv sync` to verify json-report is uninstalled**

Run: `uv sync && uv run python -c "import pytest_jsonreport"` → should fail with ImportError

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "refactor: remove pytest-json-report, JSONL is sole per-test result source"
```

---

## Phase 5: report.jsonl Artifact

### Task 8: Write `report.jsonl` artifact

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (accumulate per-unit JSONL paths)
- Modify: `src/pkcs11_check/cli/test_cmd.py` (concatenate into final artifact)

- [ ] **Step 1: Accumulate per-unit JSONL temp file paths in the runner**

Instead of deleting JSONL temp files immediately after reading, accumulate their paths. Return them from `run_isolated_pytest_units` (or store in a shared structure).

- [ ] **Step 2: Streaming concatenation into `report.jsonl`**

In `test_cmd.py`, after the runner completes, stream-concatenate all per-unit JSONL files into a temp file, then atomic-rename to the artifact path:

```python
import shutil

def _write_report_jsonl(jsonl_paths: list[Path], output_path: Path) -> None:
    tmp = output_path.with_suffix(".jsonl.tmp")
    with tmp.open("w") as out:
        for path in jsonl_paths:
            if path.exists():
                with path.open() as f:
                    shutil.copyfileobj(f, out)
                path.unlink()
    tmp.rename(output_path)
```

- [ ] **Step 3: Clean up temp files on error**

Wrap in try/finally to ensure temp JSONL files are deleted even if concatenation fails.

- [ ] **Step 4: Run full meta-test suite**

Run: `uv run python -m pytest tests/ -v --timeout 60`

- [ ] **Step 5: Integration test with real module**

Run: `bash local-builds/test.sh softhsm2 -m smoke`
Verify: `artifacts/softhsm2/report.jsonl` exists and contains valid JSONL lines.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: write report.jsonl artifact (streaming concat, atomic rename)"
```

---

## Validation

### Task 9: End-to-end validation on Docker

- [ ] **Step 1: Run smoke tests on SoftHSM2 Docker**

Run: `bash docker/test.sh softhsm2 --marker smoke`
Verify: `artifacts/softhsm2/results.json` has enriched per-test entries with `wasxfail`, `start`, `location` fields. `artifacts/softhsm2/report.jsonl` exists.

- [ ] **Step 2: Run on a module with xfailed tests (Kryoptic)**

Run: `bash docker/test.sh kryoptic-main --marker smoke`
Verify: xfailed tests appear with `outcome: "xfailed"` and `wasxfail` reason in `results.json`.

- [ ] **Step 3: Verify crash recovery (if applicable)**

Run a test file known to crash on a specific module. Verify iterative deselect produces correct results with crashed test identified.

- [ ] **Step 4: Final commit with any fixes**

```bash
git add -A
git commit -m "fix: end-to-end validation fixes for JSONL reporting"
```
