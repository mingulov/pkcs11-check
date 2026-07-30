"""Regression test: a 0-collected run must not report success (review finding R6).

If the module/marker/match/path selection matches nothing, the isolated runner
used to hit ``if not pending_units: return 0`` and exit green — so a scoping
mistake (e.g. a renamed marker) would pass silently in CI. Now an empty unit set
is a "couldn't run" condition (exit code 2; CI gates on rc>=2).
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from pkcs11_check.core.file_runner import (
    _NO_TESTS_COLLECTED_EXIT,
    IsolatedReportConfig,
    run_isolated_pytest_units,
)


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False)


def test_empty_units_returns_couldnt_run_code(tmp_path: Path) -> None:
    exit_code = run_isolated_pytest_units(
        [],  # nothing collected
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=_console(),
        granularity="file",
    )
    assert exit_code == _NO_TESTS_COLLECTED_EXIT
    assert exit_code >= 2  # contract: rc>=2 == "couldn't run" -> CI fails the job


def test_empty_units_writes_zero_total_report(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    report_config = IsolatedReportConfig("json", results_path)

    exit_code = run_isolated_pytest_units(
        [],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=report_config,
        resume=False,
        stop_on_failure=False,
        console=_console(),
        granularity="file",
    )

    assert exit_code == _NO_TESTS_COLLECTED_EXIT
    # An empty but well-formed report is emitted so tooling sees total == 0
    # (rather than a stale/absent file masquerading as a pass).
    payload = json.loads(results_path.read_text(encoding="utf-8"))
    assert payload["summary"]["total"] == 0
    assert payload["units"] == []
