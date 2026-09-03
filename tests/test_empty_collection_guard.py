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

import pytest
from rich.console import Console

from pkcs11_check.core._report_records import _report_record_cache_dir
from pkcs11_check.core.collection_errors import collection_failure_sidecar_path
from pkcs11_check.core.file_runner import (
    _NO_TESTS_COLLECTED_EXIT,
    IsolatedReportConfig,
    _write_unit_report_record_cache,
    run_isolated_pytest_units,
)


def _console() -> Console:
    return Console(file=StringIO(), force_terminal=False)


def _write_collection_sidecar(state_file: Path, diagnostics: tuple[str, ...]) -> None:
    collection_failure_sidecar_path(state_file).write_text(
        "".join(
            json.dumps(
                {
                    "$report_type": "CollectReport",
                    "nodeid": "<collection>",
                    "when": "collect",
                    "outcome": "failed",
                    "longrepr": diagnostic,
                    "source": "runner-fallback",
                }
            )
            + "\n"
            for diagnostic in diagnostics
        ),
        encoding="utf-8",
    )


def _report_config(tmp_path: Path, output_format: str | None) -> IsolatedReportConfig | None:
    if output_format == "json":
        return IsolatedReportConfig(
            "json", tmp_path / "results.json", jsonl_path=tmp_path / "report.jsonl"
        )
    if output_format == "junit":
        return IsolatedReportConfig(
            "junit", tmp_path / "results.xml", jsonl_path=tmp_path / "report.jsonl"
        )
    return None


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


def test_fresh_empty_units_clear_stale_run_artifacts(tmp_path: Path) -> None:
    state_file = tmp_path / "state.json"
    state_file.write_text(
        json.dumps({"units": ["old.py"], "fingerprint": "old", "results": []}),
        encoding="utf-8",
    )
    state_file.with_name("state.json.recovery.jsonl").write_text("stale\n", encoding="utf-8")
    cache_dir = _report_record_cache_dir(state_file)
    cache_dir.mkdir()
    (cache_dir / "old.jsonl").write_text('{"stale": true}\n', encoding="utf-8")

    results_path = tmp_path / "results.json"
    jsonl_path = tmp_path / "report.jsonl"
    report_config = IsolatedReportConfig("json", results_path, jsonl_path)
    for path in (
        results_path,
        jsonl_path,
        tmp_path / "coverage.json",
        tmp_path / "provisioning.json",
        tmp_path / "quality.json",
    ):
        path.write_text("stale\n", encoding="utf-8")

    exit_code = run_isolated_pytest_units(
        [],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=report_config,
        resume=False,
        stop_on_failure=False,
        console=_console(),
        granularity="file",
    )

    assert exit_code == _NO_TESTS_COLLECTED_EXIT
    assert json.loads(state_file.read_text(encoding="utf-8"))["units"] == []
    assert not state_file.with_name("state.json.recovery.jsonl").exists()
    assert not cache_dir.exists()
    assert not jsonl_path.exists()
    assert not (tmp_path / "coverage.json").exists()
    assert not (tmp_path / "provisioning.json").exists()
    assert json.loads(results_path.read_text(encoding="utf-8"))["summary"]["total"] == 0
    assert (
        json.loads((tmp_path / "quality.json").read_text(encoding="utf-8"))["summary"]["total"] == 0
    )


@pytest.mark.parametrize("output_format", [None, "json", "junit"])
def test_resume_empty_units_replays_collection_failure_sidecar(
    tmp_path: Path, output_format: str | None
) -> None:
    state_file = tmp_path / "state.json"
    diagnostic = "previous global collection failure"
    _write_collection_sidecar(state_file, (diagnostic,))
    output_path = tmp_path / ("results.json" if output_format == "json" else "results.xml")
    report_config = _report_config(tmp_path, output_format)
    console_output = StringIO()

    exit_code = run_isolated_pytest_units(
        [],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=report_config,
        resume=True,
        stop_on_failure=False,
        console=Console(file=console_output, force_terminal=False),
        granularity="file",
    )

    assert exit_code == _NO_TESTS_COLLECTED_EXIT
    if output_format is None:
        assert diagnostic in console_output.getvalue()
        assert "INCOMPLETE" in console_output.getvalue()
    elif output_format == "json":
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] == 1
        assert payload["summary"]["incomplete"] is True
        assert payload["units"][0]["target"] == "<collection>"
        assert payload["units"][0]["completion_verified"] is False
        assert diagnostic in (tmp_path / "report.jsonl").read_text(encoding="utf-8")
    else:
        junit = output_path.read_text(encoding="utf-8")
        assert 'errors="1"' in junit
        assert 'type="collection"' in junit
        assert diagnostic in junit


@pytest.mark.parametrize("output_format", ["json", "junit"])
def test_collection_sidecar_is_authoritative_over_stale_collection_cache(
    tmp_path: Path, output_format: str
) -> None:
    state_file = tmp_path / "state.json"
    _write_collection_sidecar(state_file, ("sidecar diagnostic A", "sidecar diagnostic B"))
    old_record = {
        "$report_type": "CollectReport",
        "nodeid": "<collection>",
        "when": "collect",
        "outcome": "failed",
        "longrepr": "sidecar diagnostic A",
        "source": "runner-fallback",
    }
    (tmp_path / "report.jsonl").write_text(json.dumps(old_record) + "\n", encoding="utf-8")
    _write_unit_report_record_cache(
        state_file,
        "<collection>",
        [old_record],
    )
    output_path = tmp_path / ("results.json" if output_format == "json" else "results.xml")
    report_path = tmp_path / "report.jsonl"
    report_config = _report_config(tmp_path, output_format)

    exit_code = run_isolated_pytest_units(
        [],
        ["--p11-module", "/tmp/module.so"],
        timeout=12,
        state_file=state_file,
        policy_file=None,
        report_config=report_config,
        resume=True,
        stop_on_failure=False,
        console=_console(),
        granularity="file",
    )

    assert exit_code == _NO_TESTS_COLLECTED_EXIT
    if output_format == "json":
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["summary"]["error"] == 2
        report = report_path.read_text(encoding="utf-8")
        assert report.count('"$report_type": "CollectReport"') == 2
        assert report.count("sidecar diagnostic A") == 1
        assert report.count("sidecar diagnostic B") == 1
    else:
        junit = output_path.read_text(encoding="utf-8")
        assert 'tests="1"' in junit
        assert 'errors="1"' in junit
        assert junit.count("sidecar diagnostic A") == 1
        assert junit.count("sidecar diagnostic B") == 1
