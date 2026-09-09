"""Integrated release gate for classification, crash, and report integrity."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from rich.console import Console

from pkcs11_check.core import file_runner as file_runner_mod
from pkcs11_check.core.file_runner import (
    IsolatedReportConfig,
    _build_per_unit_details_from_record_sources,
    load_run_state,
    run_isolated_pytest_units,
    write_isolated_junit_report,
)
from pkcs11_check.report.extract import extract_groups

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.usefixtures("classification_report_plugin_enabled")


def _classifications(report: dict[str, object]) -> list[dict[str, object]]:
    properties = report.get("user_properties")
    if not isinstance(properties, list):
        return []
    for entry in properties:
        if (
            isinstance(entry, (list, tuple))
            and len(entry) == 2
            and entry[0] == "pkcs11_classification"
            and isinstance(entry[1], list)
        ):
            return [dict(item) for item in entry[1] if isinstance(item, dict)]
    return []


def test_reporting_integrity_release_gate(
    pytester: pytest.Pytester,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve phase evidence, hard failures, a real crash, and later tests."""
    marker = pytester.path / "crasher-ran"
    target = pytester.makepyfile(
        test_release_sequence=f"""
import ctypes
import os
import signal
import sys
from pathlib import Path

import pytest
from pkcs11_check import classification as C
from pkcs11_check.classification import Classification, record

@pytest.fixture
def setup_deviation(request):
    if request.node.name == "test_setup_xfail":
        C.xfail_as(
            "not_operational", kind="session", label="setup refusal",
            operation="C_OpenSession", summary="setup refusal",
        )

@pytest.fixture
def cleanup_failure():
    yield
    record(Classification(
        reason="harness_error", outcome="fail", severity="HIGH", kind="lifecycle",
        label="cleanup failure", operation="C_DestroyObject",
        summary="cleanup failed after provider measurement",
    ))

@pytest.fixture
def teardown_deviation():
    yield
    record(Classification(
        reason="honest_deviation", outcome="xfail", severity="LOW", kind="metadata",
        label="teardown deviation", operation="C_CloseSession",
        summary="teardown deviation",
    ))

def test_setup_xfail(setup_deviation):
    raise AssertionError("setup xfail must prevent this call")

def test_independent_after_setup():
    pass

def test_strict_raw_point_encoding():
    C.xfail_as(
        "honest_deviation", kind="metadata", label="strict raw EC point",
        operation="C_GetAttributeValue", summary="raw CKA_EC_POINT encoding",
    )

def test_operational_wrong_point():
    C.fail_as(
        "wrong_result", kind="crypto", label="operational wrong EC point",
        operation="C_DeriveKey", summary="point is not on expected curve",
    )

def test_measurement_then_cleanup(cleanup_failure):
    record(Classification(
        reason="accepted_invalid", outcome="fail", severity="CRITICAL", kind="crypto",
        label="provider measurement", operation="C_Verify",
        summary="provider accepted invalid signature",
    ))

def test_real_child_crash():
    marker = Path({str(marker)!r})
    if marker.exists():
        return
    marker.write_text("first attempt", encoding="utf-8")
    if sys.platform == "win32":
        kernel = ctypes.windll.kernel32
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
        kernel.TerminateProcess(kernel.GetCurrentProcess(), 0xC0000005)
    else:
        os.kill(os.getpid(), signal.SIGSEGV)

def test_independent_after_crash():
    pass

def test_teardown_finding(teardown_deviation):
    pass

def test_no_teardown_leak():
    pass
"""
    )
    state_path = pytester.path / "state.json"
    json_path = pytester.path / "results.json"
    jsonl_path = pytester.path / "report.jsonl"
    junit_path = pytester.path / "results.xml"
    monkeypatch.setattr(
        file_runner_mod,
        "_unit_plugin_addopts",
        lambda _path: "-p pkcs11-check -p pytest_reportlog -p timeout",
    )

    exit_code = run_isolated_pytest_units(
        [str(target)],
        [],
        timeout=15,
        state_file=state_path,
        policy_file=None,
        report_config=IsolatedReportConfig("json", json_path, jsonl_path=jsonl_path),
        resume=False,
        stop_on_failure=False,
        console=Console(file=StringIO(), force_terminal=False),
        granularity="mixed",
    )

    assert exit_code == 1
    records = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    phase_reports = {
        (str(record.get("nodeid")), str(record.get("when"))): record
        for record in records
        if record.get("$report_type") == "TestReport"
    }

    def phase(name: str, when: str) -> dict[str, object]:
        suffix = f"::test_{name}"
        return next(
            report
            for (nodeid, report_when), report in phase_reports.items()
            if nodeid.endswith(suffix) and report_when == when
        )

    setup = _classifications(phase("setup_xfail", "setup"))
    assert [(item["reason"], item["operation"]) for item in setup] == [
        ("not_operational", "C_OpenSession")
    ]
    assert phase("independent_after_setup", "call")["outcome"] == "passed"
    strict = _classifications(phase("strict_raw_point_encoding", "call"))
    assert [(item["reason"], item["operation"]) for item in strict] == [
        ("honest_deviation", "C_GetAttributeValue")
    ]
    operational = _classifications(phase("operational_wrong_point", "call"))
    assert [(item["reason"], item["outcome"]) for item in operational] == [("wrong_result", "fail")]
    assert [
        item["reason"] for item in _classifications(phase("measurement_then_cleanup", "call"))
    ] == ["accepted_invalid"]
    assert [
        item["reason"] for item in _classifications(phase("measurement_then_cleanup", "teardown"))
    ] == ["harness_error"]
    assert phase("independent_after_crash", "call")["outcome"] == "passed"
    assert [item["reason"] for item in _classifications(phase("teardown_finding", "teardown"))] == [
        "honest_deviation"
    ]
    assert _classifications(phase("no_teardown_leak", "call")) == []

    groups = extract_groups(jsonl_path, crashes=[])
    grouped_reasons: dict[str, int] = {}
    for group in groups:
        reason = str(group["reason"])
        grouped_reasons[reason] = grouped_reasons.get(reason, 0) + int(group["count"])
    assert grouped_reasons == {
        "accepted_invalid": 1,
        "harness_error": 1,
        "honest_deviation": 2,
        "not_operational": 1,
        "wrong_result": 1,
    }

    unified = json.loads(json_path.read_text(encoding="utf-8"))
    summary = unified["summary"]
    assert summary["crashed"] == 1
    assert summary["failed"] >= 1
    assert summary["error"] >= 1
    assert summary["xfailed"] >= 3
    assert summary["passed"] >= 2
    outcome_keys = (
        "passed",
        "failed",
        "skipped",
        "xfailed",
        "xpassed",
        "error",
        "crashed",
        "timeout",
        "crash_limited",
    )
    for key in outcome_keys:
        assert summary[key] == sum(int(unit["counts"].get(key, 0)) for unit in unified["units"])
    assert summary["total"] == sum(int(summary[key]) for key in outcome_keys)

    state = load_run_state(state_path)
    assert state is not None
    details = _build_per_unit_details_from_record_sources(
        state_path,
        units=state.units,
        inline_records_by_unit=state.report_records_by_unit,
    )
    write_isolated_junit_report(junit_path, state, per_unit_details=details)
    junit = junit_path.read_text(encoding="utf-8")
    assert 'type="crashed"' in junit
    assert "isolated unit crashed" in junit
    assert "provider accepted invalid signature" in junit
    assert "cleanup failed after provider measurement" in junit
    assert "raw CKA_EC_POINT encoding" in junit
