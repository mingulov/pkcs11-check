"""Teardown attribution: failed finalization must not invent a harness error.

F-044: a failed C_Finalize is recorded as a TeardownFinalize record and the
process exits 1, but reportlog already wrote SessionFinish(0) (it receives the
original exitstatus argument, so hook order cannot fix the mismatch --
validating assessment proved a tryfirst simulation still wrote 0). The strict
completion check then invents a HarnessError. The fix is a narrow completion
rule: SessionFinish(0) + exit 1 verifies ONLY with a failed TeardownFinalize
in the same attempt.

N-006: a process exit DURING finalization (before TeardownFinalize is written)
must be a provider crash, not a harness error. That needs finalization to run
before the SessionFinish bookend (tryfirst), so the death leaves SessionFinish
absent and the existing abrupt-exit path attributes it to the module.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from rich.console import Console

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    _completion_verified_for_attempt,
    load_run_state,
    run_isolated_pytest_units,
)

FAILED_FINALIZE_OUTCOMES = ("error", "timeout", "crashed")


def _stream(
    tmp_path: Path,
    name: str,
    *,
    finalize_outcome: str | None = "error",
    session_exitstatus: int | None = 0,
) -> Path:
    """Write a synthetic unit stream: start, one passed test, optional finalize, bookend."""
    records: list[dict[str, Any]] = [
        {"$report_type": "SessionStart"},
        {
            "$report_type": "TestReport",
            "nodeid": "test_a.py::test_ok",
            "when": "call",
            "outcome": "passed",
            "duration": 0.01,
        },
    ]
    if finalize_outcome is not None:
        records.append(
            {
                "$report_type": "TeardownFinalize",
                "outcome": finalize_outcome,
                "rv": 5,
                "rv_name": "CKR_GENERAL_ERROR",
                "reinit_count": 0,
                "error": "C_Finalize returned CKR_GENERAL_ERROR (0x00000005)",
            }
        )
    if session_exitstatus is not None:
        records.append({"$report_type": "SessionFinish", "exitstatus": session_exitstatus})
    path = tmp_path / name
    path.write_text("".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8")
    return path


@pytest.mark.parametrize("outcome", FAILED_FINALIZE_OUTCOMES)
def test_completion_rule_accepts_zero_to_one_with_failed_finalize(
    tmp_path: Path, outcome: str
) -> None:
    """F-044: SessionFinish(0) + exit 1 + failed TeardownFinalize verifies."""
    jsonl = _stream(tmp_path, "f044.jsonl", finalize_outcome=outcome)
    assert _completion_verified_for_attempt(jsonl, "failed", 1, 0) is True


def test_completion_rule_rejects_zero_to_one_without_finalize(tmp_path: Path) -> None:
    """F-044 narrowness: the same mismatch with NO finalize record stays unverified."""
    jsonl = _stream(tmp_path, "narrow.jsonl", finalize_outcome=None)
    assert _completion_verified_for_attempt(jsonl, "failed", 1, 0) is False


def test_completion_rule_rejects_zero_to_one_with_clean_finalize(tmp_path: Path) -> None:
    """F-044 narrowness: a clean (ok) finalize record does not verify the mismatch."""
    jsonl = _stream(tmp_path, "clean.jsonl", finalize_outcome="ok")
    assert _completion_verified_for_attempt(jsonl, "failed", 1, 0) is False


def test_completion_rule_ignores_malformed_finalize_tail(tmp_path: Path) -> None:
    """F-044 robustness: corrupt lines around the record cannot verify or crash."""
    jsonl = tmp_path / "corrupt.jsonl"
    jsonl.write_text(
        '{"$report_type": "SessionStart"}\n'
        "not-json{\n"
        '{"$report_type": "TeardownFinalize", "outcome": "error",\n'
        "[1, 2]\n"
        '{"$report_type": "SessionFinish", "exitstatus": 0}\n',
        encoding="utf-8",
    )
    assert _completion_verified_for_attempt(jsonl, "failed", 1, 0) is False


def test_failed_finalize_reaches_report_without_harness_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """F-044 full path: failed finalize + exit 1 yields a finding, not HarnessError."""

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        report_path = Path(cmd[cmd.index("--report-log") + 1])
        _stream(tmp_path, report_path.name, finalize_outcome="error")
        # _stream wrote to tmp_path; move the bytes to the runner-assigned path.
        report_path.write_text(
            (tmp_path / report_path.name).read_text(encoding="utf-8"), encoding="utf-8"
        )
        return (1, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_jsonl_path = tmp_path / "report.jsonl"
    run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json", tmp_path / "results.json", jsonl_path=report_jsonl_path
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    merged = report_jsonl_path.read_text(encoding="utf-8")
    assert '"$report_type": "HarnessError"' not in merged
    assert '"$report_type": "TeardownFinalize"' in merged
    saved = load_run_state(tmp_path / "state.json")
    assert saved is not None
    assert {r.target: r.status for r in saved.results}["test_a.py"] == "failed"


def test_abrupt_exit_without_bookend_is_provider_crash_not_harness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """N-006 landing zone: exit during finalization leaves no SessionFinish.

    With finalization ordered before the bookend, a death inside C_Finalize
    produces test records + abrupt rc + no SessionFinish -- the existing
    abrupt-exit path attributes it to the module. This pins that landing zone.
    """
    records = [
        {"$report_type": "SessionStart"},
        {
            "$report_type": "TestReport",
            "nodeid": "test_a.py::test_ok",
            "when": "call",
            "outcome": "passed",
            "duration": 0.01,
        },
    ]

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        report_path = Path(cmd[cmd.index("--report-log") + 1])
        report_path.write_text("".join(json.dumps(rec) + "\n" for rec in records), encoding="utf-8")
        return (7, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)
    report_jsonl_path = tmp_path / "report.jsonl"
    run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=IsolatedReportConfig(
            "json", tmp_path / "results.json", jsonl_path=report_jsonl_path
        ),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    merged = report_jsonl_path.read_text(encoding="utf-8")
    assert '"$report_type": "HarnessError"' not in merged
    assert "[abrupt-exit]" in merged


def test_sessionfinish_runs_before_reportlog_bookend() -> None:
    """N-006 ordering: our sessionfinish must precede reportlog's SessionFinish.

    Teardown records (and a death inside finalization) must land before the
    completion bookend is written. pluggy runs tryfirst hooks before default
    ones; this pins the marker the ordering depends on.
    """
    impl = getattr(plugin_mod.pytest_sessionfinish, "pytest_impl", None)
    assert isinstance(impl, dict), "pytest_sessionfinish must carry hookimpl opts"
    assert impl.get("tryfirst") is True
