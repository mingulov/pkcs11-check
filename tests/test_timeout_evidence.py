"""Exit 124 is a timeout only with positive watchdog evidence (F-012).

The runner used to map ANY self-exit 124 to `timeout` with no evidence check,
so a provider calling exit(124) was misreported as a timeout. The per-test
watchdog now emits a harness-owned TimeoutExpired record before exiting; the
runner requires that record before calling 124 a timeout. Without it, 124 is
an abrupt self-termination like any other exit code.
"""

from __future__ import annotations

import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from pkcs11_check.core.file_runner import (
    _TIMEOUT_RETURN_CODE,
    FileRunState,
    IsolatedReportConfig,
    _run_outer_tee,
    _status_from_returncode,
    load_run_state,
    run_isolated_pytest_units,
)


def test_status_from_returncode_treats_bare_124_as_failed() -> None:
    """F-012: without watchdog evidence, 124 is a self-exit, not a timeout.

    (The previous expectation -- bare 124 implies timeout -- is exactly the
    F-012 defect: a provider that exits 124 was misreported. Genuine watchdog
    exits carry a TimeoutExpired record and take the TimeoutExpired path before
    this mapping is consulted.)
    """
    assert _status_from_returncode(_TIMEOUT_RETURN_CODE) == "failed"


def _fresh_state() -> FileRunState:
    return FileRunState(units=["t"], fingerprint="", results=[])


def test_outer_tee_upgrades_124_only_with_watchdog_evidence(tmp_path: Path) -> None:
    """F-012 gate logic: a self-exit 124 takes the timeout path only on evidence."""
    cmd = [sys.executable, "-c", "import os; os._exit(124)"]
    state_file = tmp_path / "state.json"

    with pytest.raises(subprocess.TimeoutExpired):
        _run_outer_tee(
            cmd,
            env={"PATH": "/usr/bin:/bin"},
            timeout=30,
            state=_fresh_state(),
            state_file=state_file,
            target="t",
            role="unit",
            timeout_evidence=lambda: True,
        )

    state = _fresh_state()
    rc, _, _ = _run_outer_tee(
        cmd,
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
        state=state,
        state_file=state_file,
        target="t",
        role="unit",
        timeout_evidence=lambda: False,
    )
    assert rc == _TIMEOUT_RETURN_CODE
    termination = state.process_observations[-1].get("termination")
    assert not (isinstance(termination, dict) and termination.get("kind") == "timeout")


def test_outer_tee_only_consults_evidence_for_124(tmp_path: Path) -> None:
    """The evidence predicate runs only when the child actually exited 124."""
    calls: list[None] = []

    def _evidence() -> bool:
        calls.append(None)
        return True

    rc, _, _ = _run_outer_tee(
        [sys.executable, "-c", "pass"],
        env={"PATH": "/usr/bin:/bin"},
        timeout=30,
        state=_fresh_state(),
        state_file=tmp_path / "state.json",
        target="t",
        role="unit",
        timeout_evidence=_evidence,
    )
    assert rc == 0
    assert calls == []


def _run_unit(
    unit: Path, pytest_args: list[str], tmp_path: Path, *, timeout: int
) -> tuple[str, str]:
    """Run one real file unit; return (status, merged report.jsonl text)."""
    state_file = tmp_path / "state.json"
    report_jsonl_path = tmp_path / "report.jsonl"
    run_isolated_pytest_units(
        [str(unit)],
        pytest_args,
        timeout=timeout,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json", tmp_path / "results.json", jsonl_path=report_jsonl_path
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )
    saved = load_run_state(state_file)
    assert saved is not None
    status = {r.target: r.status for r in saved.results}[str(unit)]
    return status, report_jsonl_path.read_text(encoding="utf-8")


def test_provider_self_exit_124_is_not_a_timeout(tmp_path: Path) -> None:
    """F-012 real child: os._exit(124) with no watchdog record is abrupt, kept."""
    unit = tmp_path / "test_exit124.py"
    unit.write_text(
        "import os\n\ndef test_ok():\n    pass\n\ndef test_boom():\n    os._exit(124)\n",
        encoding="utf-8",
    )
    status, merged = _run_unit(
        unit, ["--p11-module", "/tmp/module.so", "--timeout", "60"], tmp_path, timeout=12
    )

    assert status == "failed"
    assert '"$report_type": "HarnessError"' not in merged
    assert "[abrupt-exit]" in merged
    assert "test_exit124.py::test_ok" in merged  # completed test preserved


def test_genuine_watchdog_timeout_keeps_record_and_status(tmp_path: Path) -> None:
    """F-012 real child: a hung test yields TimeoutExpired evidence + timeout status."""
    unit = tmp_path / "test_hang.py"
    unit.write_text(
        "import time\n\ndef test_hang():\n    time.sleep(60)\n",
        encoding="utf-8",
    )
    status, merged = _run_unit(
        unit, ["--p11-module", "/tmp/module.so", "--timeout", "2"], tmp_path, timeout=12
    )

    assert status == "timeout"
    assert '"$report_type": "TimeoutExpired"' in merged
    assert "test_hang.py::test_hang" in merged
