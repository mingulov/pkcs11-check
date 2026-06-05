"""Regression tests for scripts/compare-results.py (review finding: weak verdict).

The release sign-off compares each provider's new results against the baseline.
The verdict must catch a regression even when no file crosses pass->fail:
- an INCREASE in the failure/crash count inside already-failing files, and
- a previously-exercised target that is now absent (lost coverage).
A decrease in failures (an improvement) must still read as NO REGRESSIONS.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compare-results.py"


def _results(units: list[tuple[str, str]], summary: dict[str, int]) -> dict[str, object]:
    full = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "error": 0,
        "crashed": 0,
        "timeout": 0,
    }
    full.update(summary)
    full["total"] = sum(full.values())
    return {
        "tool": "pkcs11-check",
        "kind": "test-run",
        "summary": full,
        "units": [{"target": t, "status": s} for t, s in units],
    }


def _run(
    tmp: Path, base: dict[str, object], curr: dict[str, object]
) -> subprocess.CompletedProcess[str]:
    bp, cp = tmp / "base.json", tmp / "curr.json"
    bp.write_text(json.dumps(base))
    cp.write_text(json.dumps(curr))
    return subprocess.run(
        [sys.executable, str(_SCRIPT), str(bp), str(cp)],
        capture_output=True,
        text=True,
    )


def test_failure_count_increase_in_red_file_is_a_regression(tmp_path: Path) -> None:
    # Same file stays "failed" but with many more failing tests inside it.
    base = _results([("test_x.py", "failed")], {"passed": 100, "failed": 3})
    curr = _results([("test_x.py", "failed")], {"passed": 53, "failed": 50})

    proc = _run(tmp_path, base, curr)

    assert proc.returncode == 1, proc.stdout
    assert "REGRESSIONS DETECTED" in proc.stdout
    assert "failures +47" in proc.stdout


def test_new_crash_is_a_regression_even_if_failures_drop(tmp_path: Path) -> None:
    base = _results([("test_x.py", "failed")], {"passed": 100, "failed": 10, "crashed": 0})
    # Total failures dropped, but a NEW crash appeared — still a regression.
    curr = _results([("test_x.py", "crashed")], {"passed": 105, "failed": 3, "crashed": 2})

    proc = _run(tmp_path, base, curr)

    assert proc.returncode == 1, proc.stdout
    assert "CRASH/TIMEOUT COUNT INCREASED" in proc.stdout


def test_lost_coverage_is_a_regression(tmp_path: Path) -> None:
    base = _results([("test_x.py", "passed"), ("test_y.py", "passed")], {"passed": 200})
    # test_y.py is gone from the current run (shard died / scope shrank).
    curr = _results([("test_x.py", "passed")], {"passed": 100})

    proc = _run(tmp_path, base, curr)

    assert proc.returncode == 1, proc.stdout
    assert "LOST COVERAGE" in proc.stdout
    assert "test_y.py" in proc.stdout


def test_fewer_failures_is_not_a_regression(tmp_path: Path) -> None:
    # The expected release direction: a file is fixed, failures drop.
    base = _results([("test_x.py", "failed")], {"passed": 100, "failed": 10})
    curr = _results([("test_x.py", "passed")], {"passed": 110, "failed": 0})

    proc = _run(tmp_path, base, curr)

    assert proc.returncode == 0, proc.stdout
    assert "NO REGRESSIONS" in proc.stdout
    assert "FIXED" in proc.stdout
