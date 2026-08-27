"""A child that reports a timeout itself must reach the timeout recovery path.

The runner's timeout handling - culprit confirmation, deselect-and-retry, escalation
to per-test units - all lives inside `except subprocess.TimeoutExpired`, i.e. it is
keyed on the RUNNER's own wall-clock kill. A child process that detects its own
per-test timeout and exits with _TIMEOUT_RETURN_CODE never took that path, so it was
classified "failed" and the rest of its file was silently abandoned: no culprit, no
escalation, no `incomplete` marker.

That matters because the per-test timeout is the only layer that can stop a hang
inside native code (see tests/test_ffi_proof_timeout.py). Making it effective without
this routing would trade a long stall for silent truncation.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.file_runner import (
    _TIMEOUT_RETURN_CODE,
    IsolatedReportConfig,
    _load_cached_report_records_by_unit,
    load_run_state,
    run_isolated_pytest_units,
)


def test_child_exit_124_preserves_partial_report_records(
    monkeypatch: object, tmp_path: Path
) -> None:
    """Partial results must survive a child-reported timeout, as they do a runner kill.

    The runner caches a unit's partial JSONL records inside `except TimeoutExpired`.
    A child that exits _TIMEOUT_RETURN_CODE returns normally instead, so that caching
    never ran and every test the unit HAD completed before the hang was discarded.
    """
    units = ["test_a.py"]
    state_file = tmp_path / "state.json"
    results_path = tmp_path / "results.json"
    report_jsonl_path = tmp_path / "report.jsonl"

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del env, timeout
        # The child completed one test, then hit its own per-test timeout and exited.
        for i, arg in enumerate(cmd):
            if arg == "--report-log" and i + 1 < len(cmd):
                Path(cmd[i + 1]).write_text(
                    json.dumps(
                        {
                            "$report_type": "TestReport",
                            "nodeid": "test_a.py::test_done",
                            "when": "call",
                            "outcome": "passed",
                            "duration": 0.01,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                break
        return (_TIMEOUT_RETURN_CODE, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)  # type: ignore[attr-defined]

    run_isolated_pytest_units(
        units,
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=IsolatedReportConfig("json", results_path, jsonl_path=report_jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    saved = load_run_state(state_file)
    assert saved is not None
    assert {r.target: r.status for r in saved.results}["test_a.py"] == "timeout"

    records = _load_cached_report_records_by_unit(state_file, units)
    assert records.get("test_a.py"), (
        "the test the unit completed before hanging must be preserved; a child-reported "
        "timeout discarded it because the caching lives inside `except TimeoutExpired`"
    )


def test_child_units_are_marked_so_the_timeout_hook_arms(
    monkeypatch: object, tmp_path: Path
) -> None:
    """The owned timer only arms in isolated child units, keyed on an env marker.

    Without the runner setting it, the hook delegates to pytest-timeout everywhere and
    the FFI-proof timeout silently never engages in production - the exact class of
    "looks wired up, does nothing" bug this whole change exists to remove.
    """
    from pkcs11_check.plugin import UNIT_CHILD_ENV

    seen: list[dict[str, str]] = []

    def fake_run(
        cmd: list[str],
        *,
        env: dict[str, str] | None = None,
        timeout: int = 0,
    ) -> tuple[int, str, str]:
        del cmd, timeout
        seen.append(dict(env or {}))
        return (0, "", "")

    monkeypatch.setattr(file_runner_mod, "_run_subprocess_tee", fake_run)  # type: ignore[attr-defined]

    run_isolated_pytest_units(
        ["test_a.py"],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=tmp_path / "state.json",
        policy_file=None,
        report_config=None,
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="file",
    )

    assert seen, "the runner must have launched a child"
    assert seen[0].get(UNIT_CHILD_ENV) == "1"
