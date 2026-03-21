# Unified Test Results Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a single unified JSON results format from all isolation modes so every test run reports per-test outcomes regardless of `--isolation none|auto|file|test`.

**Architecture:** Each file-level isolated subprocess gets `--json-report` added to its command, producing a temp JSON with per-test detail. Test-level subprocesses skip this (performance guard per spec — 75K temp files is unacceptable). The runner reads/deletes the temp file, accumulates per-unit test details in memory, and writes them into the final `results.json` in a unified format with per-file grouping. The non-isolated path post-processes its pytest-json-report output into the same format. `compliance_report.py` gets a parsing branch for the unified format.

**Tech Stack:** pytest-json-report (already a dependency), Python dataclasses, tempfile, json

**Spec:** `docs/superpowers/specs/2026-03-21-unified-test-results-design-brief.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/pkcs11_check/core/file_runner.py` | Modify | Add `_extract_per_unit_test_detail()`, inject `--json-report` into file-level subprocess cmd, rewrite `write_isolated_json_report()` for unified format with per-file grouping, add `postprocess_json_report_to_unified()` |
| `src/pkcs11_check/cli/test_cmd.py` | Modify | Call `postprocess_json_report_to_unified()` after `pytest.main()` for `--isolation none` with JSON output |
| `src/pkcs11_check/compliance_report.py` | Modify | Add unified format branch to `_parse_test_results()` |
| `tests/test_file_runner.py` | Modify | Tests for extraction, unified format, grouping, post-processing |
| `tests/test_compliance_report.py` | Create | Test for unified format parsing |

---

### Task 1: Extract per-unit test detail from pytest-json-report

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (add after `_status_from_returncode` at line 744)
- Modify: `tests/test_file_runner.py` (add new tests at end)

This task adds a pure function that reads a pytest-json-report JSON file produced by a subprocess and returns structured per-test outcome data. This is the foundation that all later tasks build on.

- [ ] **Step 1: Write the failing test for normal extraction**

In `tests/test_file_runner.py`, add `import json` at the top (after the existing imports), and add this test:

```python
from pkcs11_check.core.file_runner import _extract_per_unit_test_detail


def test_extract_per_unit_test_detail_parses_json_report(tmp_path: Path) -> None:
    json_file = tmp_path / "report.json"
    json_file.write_text(json.dumps({
        "summary": {"passed": 1, "failed": 1, "skipped": 1},
        "tests": [
            {"nodeid": "test_a.py::test_ok", "outcome": "passed", "duration": 0.1},
            {"nodeid": "test_a.py::test_skip", "outcome": "skipped", "duration": 0.0},
            {
                "nodeid": "test_a.py::test_fail",
                "outcome": "failed",
                "duration": 0.2,
                "call": {"outcome": "failed", "longrepr": "assert 1 == 2"},
            },
            {
                "nodeid": "test_a.py::test_xf",
                "outcome": "xfailed",
                "duration": 0.05,
                "wasxfail": "known bug",
            },
        ],
    }))

    detail = _extract_per_unit_test_detail(json_file)

    assert detail is not None
    assert detail["counts"] == {
        "passed": 1, "failed": 1, "skipped": 1, "xfailed": 1, "xpassed": 0, "error": 0,
    }
    # Only non-passing tests (failed, xfailed, xpassed, error) in the tests array
    assert len(detail["tests"]) == 2
    assert detail["tests"][0]["nodeid"] == "test_a.py::test_fail"
    assert detail["tests"][0]["outcome"] == "failed"
    assert detail["tests"][0]["longrepr"] == "assert 1 == 2"
    assert detail["tests"][1]["nodeid"] == "test_a.py::test_xf"
    assert detail["tests"][1]["wasxfail"] == "known bug"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_file_runner.py::test_extract_per_unit_test_detail_parses_json_report -v`
Expected: FAIL — `_extract_per_unit_test_detail` not importable

- [ ] **Step 3: Write the implementation**

In `src/pkcs11_check/core/file_runner.py`:

1. Change the typing import from `from typing import Literal` to `from typing import Any, Literal`
2. Add this function after `_status_from_returncode` (after line 744):

```python
def _extract_per_unit_test_detail(json_path: Path) -> dict[str, Any] | None:
    """Read a pytest-json-report file and return per-test outcomes.

    Returns ``{"counts": {...}, "tests": [...]}`` where ``tests`` contains
    only non-passing entries (failed, xfailed, xpassed, error).
    Returns ``None`` if the file is missing or corrupt.
    """
    try:
        data = json.loads(json_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    tests_raw = data.get("tests", [])
    if not tests_raw:
        return None

    counts: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    non_passing: list[dict[str, Any]] = []

    for test in tests_raw:
        outcome = test.get("outcome", "passed")
        counts[outcome] = counts.get(outcome, 0) + 1
        if outcome not in {"failed", "xfailed", "xpassed", "error"}:
            continue
        entry: dict[str, Any] = {
            "nodeid": test["nodeid"],
            "outcome": outcome,
            "duration": test.get("duration", 0.0),
        }
        if outcome == "xfailed" and test.get("wasxfail"):
            entry["wasxfail"] = test["wasxfail"]
        if outcome in {"failed", "error"}:
            longrepr = test.get("call", {}).get("longrepr", "")
            if longrepr:
                entry["longrepr"] = longrepr
        non_passing.append(entry)

    return {"counts": counts, "tests": non_passing}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run python -m pytest tests/test_file_runner.py::test_extract_per_unit_test_detail_parses_json_report -v`
Expected: PASS

- [ ] **Step 5: Write tests for edge cases**

Add to `tests/test_file_runner.py`:

```python
def test_extract_per_unit_test_detail_returns_none_for_missing_file(tmp_path: Path) -> None:
    result = _extract_per_unit_test_detail(tmp_path / "nonexistent.json")
    assert result is None


def test_extract_per_unit_test_detail_returns_none_for_corrupt_json(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{truncated")
    result = _extract_per_unit_test_detail(bad_file)
    assert result is None


def test_extract_per_unit_test_detail_returns_none_for_empty_tests(tmp_path: Path) -> None:
    json_file = tmp_path / "report.json"
    json_file.write_text(json.dumps({"summary": {}, "tests": []}))
    result = _extract_per_unit_test_detail(json_file)
    assert result is None
```

- [ ] **Step 6: Run all extraction tests**

Run: `uv run python -m pytest tests/test_file_runner.py -k "extract_per_unit" -v`
Expected: all 4 tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: add _extract_per_unit_test_detail helper for subprocess JSON reports"
```

---

### Task 2: Inject --json-report into file-level subprocesses and accumulate details

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` — `run_isolated_pytest_units` (lines 1001-1256), `write_isolated_report` (line 493), `write_isolated_json_report` (line 365)
- Modify: `tests/test_file_runner.py` (add new test)

This task wires the extraction into the subprocess loop. **Performance guard:** only file-level units get `--json-report` (spec risk section: "75K test units → 75K temp files is unacceptable"). Test-level units skip JSON report injection.

- [ ] **Step 1: Write test for json-report injection and detail extraction**

Add to `tests/test_file_runner.py`:

```python
def test_run_isolated_pytest_units_extracts_per_unit_details(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Verify file-level subprocess gets --json-report and detail is extracted."""
    seen_cmds: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> SimpleNamespace:
        del check, env, timeout, stdout, stderr
        seen_cmds.append(list(cmd))
        # Write a fake pytest-json-report to the temp file
        for arg in cmd:
            if arg.startswith("--json-report-file="):
                json_path = Path(arg.split("=", 1)[1])
                json_path.write_text(json.dumps({
                    "summary": {"passed": 1},
                    "tests": [
                        {"nodeid": "test_a.py::test_ok", "outcome": "passed", "duration": 0.1},
                    ],
                }))
                break
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]
    report_path = tmp_path / "results.json"

    exit_code = run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig("json", report_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert exit_code == 0
    # Verify --json-report was injected into the subprocess command
    cmd = seen_cmds[0]
    assert "--json-report" in cmd
    json_report_file_args = [a for a in cmd if a.startswith("--json-report-file=")]
    assert len(json_report_file_args) == 1
    # Verify the temp file was cleaned up
    temp_path = Path(json_report_file_args[0].split("=", 1)[1])
    assert not temp_path.exists()
    # Verify the report has per-unit counts
    report = json.loads(report_path.read_text())
    assert report["units"][0].get("counts") is not None
    assert report["units"][0]["counts"]["passed"] == 1
```

- [ ] **Step 2: Write test that test-level units do NOT get --json-report**

```python
def test_run_isolated_pytest_units_skips_json_report_for_test_level(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Performance guard: test-level units must not create temp JSON files."""
    seen_cmds: list[list[str]] = []

    def fake_run(
        cmd: list[str],
        *,
        check: bool = False,
        env: dict[str, str] | None = None,
        timeout: int = 0,
        stdout: object = None,
        stderr: object = None,
    ) -> SimpleNamespace:
        del check, env, timeout, stdout, stderr
        seen_cmds.append(list(cmd))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)  # type: ignore[arg-type]

    exit_code = run_isolated_pytest_units(
        ["test_a.py::test_case"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="test",
    )

    assert exit_code == 0
    cmd = seen_cmds[0]
    assert "--json-report" not in cmd
    assert not any(a.startswith("--json-report-file=") for a in cmd)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_file_runner.py -k "extracts_per_unit_details or skips_json_report" -v`
Expected: FAIL — subprocess cmd won't have `--json-report` yet

- [ ] **Step 4: Implement subprocess injection with performance guard**

In `src/pkcs11_check/core/file_runner.py`, add `import tempfile` to the top-level imports.

In `run_isolated_pytest_units`, after line 1060 (`exit_code = 0`), add:
```python
    per_unit_details: dict[str, dict[str, Any]] = {}
```

Inside the main loop, replace the subprocess command construction and invocation block. The current code (lines 1072-1094) becomes:

```python
            # Inject --json-report for file-level units only (spec guard:
            # 75K temp files for test-level units is unacceptable).
            unit_granularity = _effective_granularity(unit, granularity)
            unit_json_path: Path | None = None
            if unit_granularity == "file":
                unit_json_fd, unit_json_raw = tempfile.mkstemp(
                    prefix="pkcs11-check-unit-", suffix=".json"
                )
                os.close(unit_json_fd)
                unit_json_path = Path(unit_json_raw)
                cmd = [
                    sys.executable, "-m", "pytest", unit, *pytest_args,
                    "--json-report",
                    f"--json-report-file={unit_json_path}",
                    "--json-report-omit=collectors",
                ]
            else:
                cmd = [sys.executable, "-m", "pytest", unit, *pytest_args]
```

Note: The `unit_granularity` assignment currently at line 1073 should be moved up into this block (before the `if`). Remove the duplicate line.

Then wrap the subprocess invocation + result recording in a `try/finally` that always cleans up the temp file. The structure becomes:

```python
            try:
                try:
                    completed = subprocess.run(
                        cmd,
                        check=False,
                        env=env,
                        timeout=_unit_timeout_seconds(timeout, unit_granularity),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    # ... existing returncode/stdout/stderr/tee/status handling ...
                except subprocess.TimeoutExpired:
                    # ... existing timeout handling (unchanged) ...
                    index += 1
                    continue

                # ... existing duration/result recording/status handling ...

                # Extract per-test detail from file-level subprocess json-report
                if unit_json_path is not None:
                    detail = _extract_per_unit_test_detail(unit_json_path)
                    if detail is not None:
                        per_unit_details[unit] = detail
            finally:
                if unit_json_path is not None:
                    unit_json_path.unlink(missing_ok=True)
```

The key points:
- `unit_json_path` is `None` for test-level units — the `finally` block is a no-op
- Detail extraction happens only on the normal (non-timeout) path, inside the outer `try`
- On timeout, `subprocess.TimeoutExpired` is caught by the inner `except`, execution `continue`s, and the outer `finally` cleans up the temp file
- On crash (negative returncode), execution continues through the normal path, detail is extracted (JSON may or may not exist), and `finally` cleans up

- [ ] **Step 5: Thread per_unit_details through to report writing**

Update `write_isolated_json_report` signature (line 365) — add the `per_unit_details` parameter:
```python
def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    state_file: Path,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
```

Update `write_isolated_report` (line 493) to pass it through:
```python
def write_isolated_report(
    config: IsolatedReportConfig,
    state: FileRunState,
    *,
    state_file: Path,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write the requested aggregated report format for an isolated run."""
    if config.output_format == "json":
        write_isolated_json_report(
            config.output_path, state, state_file=state_file,
            per_unit_details=per_unit_details,
        )
        return
    write_isolated_junit_report(config.output_path, state)
```

Update the call in `run_isolated_pytest_units` (in the `finally` block, line ~1254):
```python
        if report_config is not None:
            write_isolated_report(
                report_config, state, state_file=state_file,
                per_unit_details=per_unit_details,
            )
```

- [ ] **Step 6: Run new tests**

Run: `uv run python -m pytest tests/test_file_runner.py -k "extracts_per_unit_details or skips_json_report" -v`
Expected: both PASS (the report format test may need Task 3, but the injection/cleanup assertions should pass)

- [ ] **Step 7: Run all existing tests**

Run: `uv run python -m pytest tests/test_file_runner.py -v`
Expected: all PASS (existing tests use `fake_run` that doesn't write to the temp file, so `_extract_per_unit_test_detail` returns None — graceful degradation)

- [ ] **Step 8: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: inject --json-report into file-level isolated subprocesses"
```

---

### Task 3: Unified JSON report format with per-file grouping

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` — rewrite `write_isolated_json_report` (line 365), add `_group_results_by_file` helper
- Modify: `tests/test_file_runner.py` (update existing test, add new tests)

This task rewrites `write_isolated_json_report` to produce the unified output format from the design brief. It includes per-file grouping so that `--isolation test` results are aggregated back into file-level units.

- [ ] **Step 1: Write test for unified output format (file-level units)**

Add to `tests/test_file_runner.py`:

```python
from pkcs11_check.core.file_runner import write_isolated_json_report


def test_write_isolated_json_report_unified_format(tmp_path: Path) -> None:
    state = FileRunState(
        units=["test_a.py", "test_b.py"],
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py", "passed", 0, 1.0),
            FileRunResult("test_b.py", "failed", 1, 2.0, stdout="FAILED test", stderr=""),
        ],
    )
    per_unit_details = {
        "test_a.py": {
            "counts": {"passed": 3, "failed": 0, "skipped": 1, "xfailed": 0, "xpassed": 0, "error": 0},
            "tests": [],
        },
        "test_b.py": {
            "counts": {"passed": 1, "failed": 1, "skipped": 0, "xfailed": 1, "xpassed": 0, "error": 0},
            "tests": [
                {"nodeid": "test_b.py::test_bad", "outcome": "failed", "duration": 0.5, "longrepr": "assert False"},
                {"nodeid": "test_b.py::test_xf", "outcome": "xfailed", "duration": 0.1, "wasxfail": "known"},
            ],
        },
    }
    report_path = tmp_path / "results.json"
    write_isolated_json_report(
        report_path, state, state_file=tmp_path / "state.json",
        per_unit_details=per_unit_details,
    )

    report = json.loads(report_path.read_text())
    assert report["tool"] == "pkcs11-check"
    assert report["kind"] == "test-run"
    # Summary aggregated from per-unit counts: (3+1)=4 passed, 1 failed, 1 skipped, 1 xfailed
    assert report["summary"]["passed"] == 4
    assert report["summary"]["failed"] == 1
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["xfailed"] == 1
    assert report["summary"]["total"] == 7
    assert len(report["units"]) == 2
    unit_a = report["units"][0]
    assert unit_a["target"] == "test_a.py"
    assert unit_a["counts"]["passed"] == 3
    assert "tests" not in unit_a  # no non-passing tests
    unit_b = report["units"][1]
    assert unit_b["target"] == "test_b.py"
    assert len(unit_b["tests"]) == 2
    assert unit_b["stdout"] == "FAILED test"
```

- [ ] **Step 2: Write test for per-file grouping (test-level units)**

```python
def test_write_isolated_json_report_groups_test_units_by_file(tmp_path: Path) -> None:
    state = FileRunState(
        units=[
            "test_a.py::test_one",
            "test_a.py::test_two",
            "test_b.py::test_only",
        ],
        fingerprint="abc123",
        results=[
            FileRunResult("test_a.py::test_one", "passed", 0, 0.5),
            FileRunResult("test_a.py::test_two", "failed", 1, 0.3, stdout="fail output"),
            FileRunResult("test_b.py::test_only", "passed", 0, 0.2),
        ],
    )
    per_unit_details = {
        "test_a.py::test_one": {
            "counts": {"passed": 1, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
            "tests": [],
        },
        "test_a.py::test_two": {
            "counts": {"passed": 0, "failed": 1, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
            "tests": [{"nodeid": "test_a.py::test_two", "outcome": "failed", "duration": 0.3, "longrepr": "bad"}],
        },
        "test_b.py::test_only": {
            "counts": {"passed": 1, "failed": 0, "skipped": 0, "xfailed": 0, "xpassed": 0, "error": 0},
            "tests": [],
        },
    }
    report_path = tmp_path / "results.json"
    write_isolated_json_report(
        report_path, state, state_file=tmp_path / "state.json",
        per_unit_details=per_unit_details,
    )

    report = json.loads(report_path.read_text())
    # Should be grouped into 2 file-level units, not 3 test-level units
    assert len(report["units"]) == 2
    unit_a = next(u for u in report["units"] if u["target"] == "test_a.py")
    assert unit_a["counts"]["passed"] == 1
    assert unit_a["counts"]["failed"] == 1
    assert unit_a["status"] == "failed"
    assert len(unit_a["tests"]) == 1
    assert unit_a["stdout"] == "fail output"
    unit_b = next(u for u in report["units"] if u["target"] == "test_b.py")
    assert unit_b["counts"]["passed"] == 1
    assert unit_b["status"] == "passed"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run python -m pytest tests/test_file_runner.py -k "unified_format or groups_test_units" -v`
Expected: FAIL — current format doesn't match

- [ ] **Step 4: Implement _group_results_by_file helper**

Add to `src/pkcs11_check/core/file_runner.py`, before `write_isolated_json_report`:

```python
def _group_results_by_file(
    results: list[FileRunResult],
    details: dict[str, dict[str, Any]],
) -> list[tuple[str, list[FileRunResult], dict[str, Any]]]:
    """Group results into file-level aggregates for the unified report.

    If all results are already file-level (no ``::`` in targets), returns
    them ungrouped.  Otherwise, groups test-level results by their file
    prefix and merges counts/tests from *details*.
    """
    has_test_level = any("::" in r.target for r in results)
    if not has_test_level:
        return [
            (r.target, [r], details.get(r.target, {}))
            for r in results
        ]

    groups: dict[str, list[FileRunResult]] = {}
    order: list[str] = []
    for result in results:
        file_key = result.target.split("::", 1)[0]
        if file_key not in groups:
            groups[file_key] = []
            order.append(file_key)
        groups[file_key].append(result)

    out: list[tuple[str, list[FileRunResult], dict[str, Any]]] = []
    for file_target in order:
        file_results = groups[file_target]
        merged_counts: dict[str, int] = {
            "passed": 0, "failed": 0, "skipped": 0,
            "xfailed": 0, "xpassed": 0, "error": 0,
        }
        merged_tests: list[dict[str, Any]] = []
        for r in file_results:
            detail = details.get(r.target, {})
            for key in merged_counts:
                merged_counts[key] += detail.get("counts", {}).get(key, 0)
            merged_tests.extend(detail.get("tests", []))
        out.append((file_target, file_results, {"counts": merged_counts, "tests": merged_tests}))
    return out
```

- [ ] **Step 5: Rewrite write_isolated_json_report**

Replace the entire body of `write_isolated_json_report` with:

```python
def write_isolated_json_report(
    path: Path,
    state: FileRunState,
    *,
    state_file: Path,
    per_unit_details: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write an aggregated JSON report for an isolated run in unified format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    details = per_unit_details or {}

    summary: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }

    grouped = _group_results_by_file(state.results, details)
    units_out: list[dict[str, Any]] = []

    for file_target, file_results, merged_detail in grouped:
        has_failure = any(r.status in {"failed", "crashed", "timeout"} for r in file_results)
        duration = sum(r.duration_s for r in file_results)
        stdout_parts = [r.stdout for r in file_results if r.stdout]
        stderr_parts = [r.stderr for r in file_results if r.stderr]

        unit: dict[str, Any] = {
            "target": file_target,
            "status": "failed" if has_failure else file_results[0].status,
            "returncode": max(abs(r.returncode) for r in file_results) if has_failure else 0,
            "duration_s": round(duration, 3),
        }
        if stdout_parts:
            unit["stdout"] = "\n".join(stdout_parts)
        if stderr_parts:
            unit["stderr"] = "\n".join(stderr_parts)

        counts = merged_detail.get("counts")
        if counts and any(v > 0 for v in counts.values()):
            unit["counts"] = counts
            for key in summary:
                summary[key] += counts.get(key, 0)
        tests = merged_detail.get("tests")
        if tests:
            unit["tests"] = tests

        units_out.append(unit)

    summary["total"] = sum(summary.values())

    payload = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units_out,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")
```

- [ ] **Step 6: Update existing JSON report test**

The existing `test_run_isolated_pytest_units_writes_json_report` checks for `'"kind": "isolated-run"'`. Change it to:

```python
    assert '"kind": "test-run"' in payload
```

- [ ] **Step 7: Run all tests**

Run: `uv run python -m pytest tests/test_file_runner.py -v`
Expected: all PASS

- [ ] **Step 8: Run mypy**

Run: `uv run mypy src/pkcs11_check/core/file_runner.py`
Expected: no errors

- [ ] **Step 9: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py tests/test_file_runner.py
git commit -m "feat: unified JSON report format with per-file grouping"
```

---

### Task 4: Post-process non-isolated path to unified format

**Files:**
- Modify: `src/pkcs11_check/core/file_runner.py` (add `postprocess_json_report_to_unified`)
- Modify: `src/pkcs11_check/cli/test_cmd.py` (call post-processor after `pytest.main`)
- Modify: `tests/test_file_runner.py` (add conversion test)
- Modify: `tests/test_cli.py` (add CLI wiring test)

When `--isolation none --output json`, pytest-json-report writes its native format. This task converts it to the unified format for consistency.

- [ ] **Step 1: Write test for json-report-to-unified conversion**

Add to `tests/test_file_runner.py`:

```python
from pkcs11_check.core.file_runner import postprocess_json_report_to_unified


def test_postprocess_json_report_to_unified(tmp_path: Path) -> None:
    json_file = tmp_path / "results.json"
    json_file.write_text(json.dumps({
        "summary": {"passed": 1, "failed": 1, "xfailed": 1},
        "tests": [
            {"nodeid": "test_a.py::test_ok", "outcome": "passed", "duration": 0.1},
            {"nodeid": "test_a.py::test_skip", "outcome": "skipped", "duration": 0.0},
            {
                "nodeid": "test_b.py::test_fail",
                "outcome": "failed",
                "duration": 0.5,
                "call": {"outcome": "failed", "longrepr": "assert False"},
            },
            {
                "nodeid": "test_b.py::test_xf",
                "outcome": "xfailed",
                "duration": 0.1,
                "wasxfail": "known bug",
            },
        ],
    }))

    postprocess_json_report_to_unified(json_file)

    report = json.loads(json_file.read_text())
    assert report["tool"] == "pkcs11-check"
    assert report["kind"] == "test-run"
    assert report["summary"]["passed"] == 1
    assert report["summary"]["failed"] == 1
    assert report["summary"]["skipped"] == 1
    assert report["summary"]["xfailed"] == 1
    assert report["summary"]["total"] == 4
    assert len(report["units"]) == 2

    unit_a = next(u for u in report["units"] if u["target"] == "test_a.py")
    assert unit_a["counts"]["passed"] == 1
    assert unit_a["counts"]["skipped"] == 1
    assert unit_a["status"] == "passed"
    assert "tests" not in unit_a  # no non-passing tests in test_a.py

    unit_b = next(u for u in report["units"] if u["target"] == "test_b.py")
    assert unit_b["status"] == "failed"
    assert len(unit_b["tests"]) == 2
    assert unit_b["tests"][0]["longrepr"] == "assert False"
    assert unit_b["tests"][1]["wasxfail"] == "known bug"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_file_runner.py::test_postprocess_json_report_to_unified -v`
Expected: FAIL — function not importable

- [ ] **Step 3: Implement postprocess_json_report_to_unified**

Add to `src/pkcs11_check/core/file_runner.py` (after `write_isolated_report`):

```python
def postprocess_json_report_to_unified(json_path: Path) -> None:
    """Convert a pytest-json-report file to pkcs11-check unified format.

    Reads the native pytest-json-report JSON, groups tests by file,
    and overwrites the file with the unified format.  Used for
    ``--isolation none`` to produce consistent output.
    """
    try:
        data = json.loads(json_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return

    tests_raw = data.get("tests", [])
    if not tests_raw:
        return

    by_file: dict[str, list[dict[str, Any]]] = {}
    for test in tests_raw:
        file_part = test.get("nodeid", "").split("::")[0]
        by_file.setdefault(file_part, []).append(test)

    summary: dict[str, int] = {
        "passed": 0, "failed": 0, "skipped": 0,
        "xfailed": 0, "xpassed": 0, "error": 0,
    }
    units: list[dict[str, Any]] = []

    for target in sorted(by_file):
        file_tests = by_file[target]
        counts: dict[str, int] = {
            "passed": 0, "failed": 0, "skipped": 0,
            "xfailed": 0, "xpassed": 0, "error": 0,
        }
        non_passing: list[dict[str, Any]] = []
        duration = 0.0

        for test in file_tests:
            outcome = test.get("outcome", "passed")
            counts[outcome] = counts.get(outcome, 0) + 1
            summary[outcome] = summary.get(outcome, 0) + 1
            duration += test.get("duration", 0.0)
            if outcome not in {"failed", "xfailed", "xpassed", "error"}:
                continue
            entry: dict[str, Any] = {
                "nodeid": test["nodeid"],
                "outcome": outcome,
                "duration": test.get("duration", 0.0),
            }
            if outcome == "xfailed" and test.get("wasxfail"):
                entry["wasxfail"] = test["wasxfail"]
            if outcome in {"failed", "error"}:
                longrepr = test.get("call", {}).get("longrepr", "")
                if longrepr:
                    entry["longrepr"] = longrepr
            non_passing.append(entry)

        has_failure = counts["failed"] > 0 or counts["error"] > 0
        unit: dict[str, Any] = {
            "target": target,
            "status": "failed" if has_failure else "passed",
            "returncode": 1 if has_failure else 0,
            "duration_s": round(duration, 3),
            "counts": counts,
        }
        if non_passing:
            unit["tests"] = non_passing
        units.append(unit)

    summary["total"] = sum(summary.values())

    payload = {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": summary,
        "units": units,
    }
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
```

- [ ] **Step 4: Run conversion test**

Run: `uv run python -m pytest tests/test_file_runner.py::test_postprocess_json_report_to_unified -v`
Expected: PASS

- [ ] **Step 5: Wire into test_cmd.py**

In `src/pkcs11_check/cli/test_cmd.py`, add to the import block (line 14-21):
```python
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    discover_auto_isolation_units,
    discover_pytest_units,
    load_run_state,
    postprocess_json_report_to_unified,
    run_isolated_pytest_units,
)
```

After line 247 (`exit_code = pytest.main(args)`), before line 248 (`raise typer.Exit`), add:
```python
        # Post-process JSON report to unified format
        if output == "json":
            unified_path = Path(output_file or "pkcs11-check-results.json")
            if unified_path.exists():
                postprocess_json_report_to_unified(unified_path)
```

- [ ] **Step 6: Write CLI wiring test**

In `tests/test_cli.py`, add a test that verifies the non-isolated JSON path calls the post-processor. Find the existing test patterns that mock `pytest.main` and preflight. Add:

```python
def test_test_none_isolation_postprocesses_json_report(
    self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--isolation none with --output json should produce unified format."""
    module = tmp_path / "module.so"
    module.write_text("fake")

    monkeypatch.setattr(
        "pkcs11_check.cli.test_cmd.run_preflight_subprocess",
        lambda *a, **kw: SimpleNamespace(status="ok", error=None),
    )

    # Make pytest.main write a fake json-report file
    json_path = Path("pkcs11-check-results.json")

    def fake_pytest_main(args: list[str]) -> int:
        json_path.write_text(json.dumps({
            "summary": {"passed": 1},
            "tests": [{"nodeid": "test.py::test_ok", "outcome": "passed", "duration": 0.1}],
        }))
        return 0

    monkeypatch.setattr("pkcs11_check.cli.test_cmd.pytest.main", fake_pytest_main)
    monkeypatch.chdir(tmp_path)

    from typer.testing import CliRunner
    from pkcs11_check.cli.app import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "test", "--module", str(module), "--isolation", "none", "--output", "json",
    ])

    report_file = tmp_path / "pkcs11-check-results.json"
    if report_file.exists():
        report = json.loads(report_file.read_text())
        assert report.get("kind") == "test-run"
        assert "units" in report
```

Note: This test pattern should match the existing CLI test conventions in `tests/test_cli.py`. Adapt imports and fixture patterns to match what's already there.

- [ ] **Step 7: Run mypy on both files**

Run: `uv run mypy src/pkcs11_check/core/file_runner.py src/pkcs11_check/cli/test_cmd.py`
Expected: no errors

- [ ] **Step 8: Run all tests**

Run: `uv run python -m pytest tests/test_file_runner.py tests/test_cli.py -v`
Expected: all PASS

- [ ] **Step 9: Commit**

```bash
git add src/pkcs11_check/core/file_runner.py src/pkcs11_check/cli/test_cmd.py tests/test_file_runner.py tests/test_cli.py
git commit -m "feat: post-process non-isolated JSON reports to unified format"
```

---

### Task 5: Update compliance_report to parse unified format

**Files:**
- Modify: `src/pkcs11_check/compliance_report.py:406-450` (`_parse_test_results`)
- Create: `tests/test_compliance_report.py`

This task ensures the compliance report generator can read the new unified format alongside the existing pytest-json-report and isolated-run formats.

- [ ] **Step 1: Write test for parsing unified format**

Create `tests/test_compliance_report.py`:

```python
"""Tests for compliance report parsing."""
from __future__ import annotations

import json
from pathlib import Path

from pkcs11_check.compliance_report import _parse_test_results


def test_parse_test_results_unified_format(tmp_path: Path) -> None:
    results_file = tmp_path / "results.json"
    results_file.write_text(json.dumps({
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {"passed": 3, "failed": 1, "skipped": 1, "xfailed": 1, "total": 6},
        "units": [
            {
                "target": "src/pkcs11_check/testcases/test_sign.py",
                "status": "passed",
                "counts": {"passed": 2, "failed": 0, "skipped": 1, "xfailed": 1},
            },
            {
                "target": "src/pkcs11_check/testcases/test_encrypt.py",
                "status": "failed",
                "counts": {"passed": 1, "failed": 1, "skipped": 0, "xfailed": 0},
            },
        ],
    }))

    counts = _parse_test_results(results_file)

    assert "test_sign" in counts
    assert counts["test_sign"]["passed"] == 2
    assert counts["test_sign"]["failed"] == 0
    assert counts["test_sign"]["skipped"] == 1
    assert "test_encrypt" in counts
    assert counts["test_encrypt"]["passed"] == 1
    assert counts["test_encrypt"]["failed"] == 1


def test_parse_test_results_unified_format_without_counts(tmp_path: Path) -> None:
    """Units without counts (e.g., crashed) should be handled gracefully."""
    results_file = tmp_path / "results.json"
    results_file.write_text(json.dumps({
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": {},
        "units": [
            {"target": "test_crash.py", "status": "crashed"},
        ],
    }))

    counts = _parse_test_results(results_file)
    # Crashed unit has no counts → treated as skipped (0/0/0)
    assert counts == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run python -m pytest tests/test_compliance_report.py -v`
Expected: FAIL — current parser doesn't handle unified format

- [ ] **Step 3: Update _parse_test_results**

In `src/pkcs11_check/compliance_report.py`, replace lines 406-450 with:

```python
def _parse_test_results(
    results_path: Path,
) -> dict[str, dict[str, int]]:
    """Parse a pytest-json-report, pkcs11-check isolated, or unified results JSON.

    Returns a mapping of test file base name -> {passed, failed, skipped}.
    """
    data = json.loads(results_path.read_text())

    counts: dict[str, dict[str, int]] = {}

    # Unified format: {"kind": "test-run", "units": [{"target": ..., "counts": ...}]}
    if data.get("kind") == "test-run":
        for unit in data.get("units", []):
            target = unit.get("target", "")
            base = target.split("::")[0].split("/")[-1].replace(".py", "")
            if not base:
                continue
            unit_counts = unit.get("counts")
            if unit_counts is None:
                continue
            if base not in counts:
                counts[base] = {"passed": 0, "failed": 0, "skipped": 0}
            counts[base]["passed"] += unit_counts.get("passed", 0)
            counts[base]["failed"] += unit_counts.get("failed", 0)
            counts[base]["skipped"] += unit_counts.get("skipped", 0)
        return counts

    # pytest-json-report format: {"tests": [{"nodeid": "...", "outcome": "..."}]}
    tests = data.get("tests", [])
    if not tests:
        # pkcs11-check isolated run format: {"results": [...]}
        for r in data.get("results", []):
            target = r.get("target", "")
            status = r.get("status", "")
            base = target.split("::")[0].split("/")[-1].replace(".py", "")
            if base not in counts:
                counts[base] = {"passed": 0, "failed": 0, "skipped": 0}
            if status == "passed":
                counts[base]["passed"] += 1
            elif status == "failed":
                counts[base]["failed"] += 1
            else:
                counts[base]["skipped"] += 1
        return counts

    for test in tests:
        nodeid = test.get("nodeid", "")
        outcome = test.get("outcome", "")
        base = nodeid.split("::")[0].split("/")[-1].replace(".py", "")
        if base not in counts:
            counts[base] = {"passed": 0, "failed": 0, "skipped": 0}
        if outcome == "passed":
            counts[base]["passed"] += 1
        elif outcome == "failed":
            counts[base]["failed"] += 1
        else:
            counts[base]["skipped"] += 1

    return counts
```

- [ ] **Step 4: Run test**

Run: `uv run python -m pytest tests/test_compliance_report.py -v`
Expected: both tests PASS

- [ ] **Step 5: Run mypy**

Run: `uv run mypy src/pkcs11_check/compliance_report.py`
Expected: no errors

- [ ] **Step 6: Run full test suite**

Run: `uv run python -m pytest tests/ -v`
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add src/pkcs11_check/compliance_report.py tests/test_compliance_report.py
git commit -m "feat: compliance report parser supports unified test results format"
```

---

## Final Validation

After all tasks are complete:

- [ ] **Run full meta-test suite:** `uv run python -m pytest tests/ -v`
- [ ] **Run ruff:** `uv run ruff check src/ tests/`
- [ ] **Run ruff format:** `uv run ruff format src/ tests/`
- [ ] **Run mypy:** `uv run mypy src/`
- [ ] **Smoke test with real module (optional):** `bash local-builds/test.sh softhsm2 -m smoke` then inspect `pkcs11-check-results.json` for unified format
