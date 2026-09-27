"""Tests for pkcs11_check.report.extract — grouping at-source classification findings."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.report.extract import extract_groups


def _classification(**over: object) -> dict[str, object]:
    """Build a serialized Classification dict (schema mirrors classification.py)."""
    rec: dict[str, object] = {
        "reason": "accepted_invalid",
        "outcome": "fail",
        "severity": "CRITICAL",
        "kind": "crypto",
        "label": "RSA:decrypt",
        "summary": "RSA:decrypt: expected reject, got CKR_OK",
        "operation": "C_Decrypt",
        "mechanism": "CKM_RSA_PKCS",
        "expected_ckr": ["CKR_ENCRYPTED_DATA_INVALID"],
        "actual_ckr": "CKR_OK",
        "spec_ref": "PKCS#11 v3.2 §6.13",
        "source": "wycheproof",
        "vector_id": None,
        "detail": None,
        "schema": 1,
    }
    rec.update(over)
    return rec


def _test_report(
    nodeid: str, records: list[dict[str, object]], *, when: str = "call"
) -> dict[str, object]:
    """A pytest-reportlog phase-scoped TestReport line."""
    return {
        "$report_type": "TestReport",
        "when": when,
        "nodeid": nodeid,
        "outcome": "failed",
        "user_properties": [["pkcs11_classification", records]],
    }


def test_two_records_same_key_merge_into_one_group(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    r1 = _classification(vector_id="tc101")
    r2 = _classification(vector_id="tc202")
    lines = [
        _test_report("tests/test_rsa.py::test_a", [r1]),
        _test_report("tests/test_rsa.py::test_b", [r2]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    grp = groups[0]
    assert grp["count"] == 2
    assert grp["test_file"] == "tests/test_rsa.py"
    assert "tc101" in grp["vector_ids"]
    assert "tc202" in grp["vector_ids"]
    assert grp["severity"] == "CRITICAL"
    assert grp["reason"] == "accepted_invalid"
    assert grp["kind"] == "crypto"
    assert grp["mechanism"] == "CKM_RSA_PKCS"
    assert grp["operation"] == "C_Decrypt"
    assert grp["expected_ckr"] == ["CKR_ENCRYPTED_DATA_INVALID"]
    assert grp["actual_ckr"] == "CKR_OK"
    assert grp["outcome"] == "fail"
    assert "wycheproof" in grp["sources"]
    assert len(grp["nodeids"]) == 2


def test_count_remains_classification_occurrences_across_attempts(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    nodeid = "tests/test_rsa.py::test_case"
    classification = _classification(vector_id="tc101")
    lines = [
        {"$report_type": "IsolatedUnitReport", "target": "tests/test_rsa.py", "attempt": 0},
        _test_report(nodeid, [classification]),
        {"$report_type": "IsolatedUnitReport", "target": nodeid, "attempt": 0},
        _test_report(nodeid, [classification]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert groups[0]["nodeids"] == [nodeid]


def test_distinct_keys_make_distinct_groups(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    a = _classification(mechanism="CKM_RSA_PKCS")
    b = _classification(mechanism="CKM_AES_GCM", actual_ckr="CKR_OK")
    lines = [
        _test_report("tests/test_x.py::t1", [a]),
        _test_report("tests/test_x.py::t2", [b]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])
    assert len(groups) == 2


def test_crashes_are_merged_as_findings(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    path.write_text(
        json.dumps(_test_report("tests/test_x.py::t1", [_classification()])) + "\n",
        encoding="utf-8",
    )
    crash = {
        "schema": 1,
        "reason": "crash",
        "outcome": "fail",
        "severity": "HIGH",
        "kind": None,
        "label": "tests/test_overflow.py",
        "summary": "tests/test_overflow.py: process crashed",
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": {"signal": "SIGSEGV", "returncode": -11},
    }
    groups = extract_groups(path, crashes=[crash])
    reasons = {g["reason"] for g in groups}
    assert "crash" in reasons
    crash_grp = next(g for g in groups if g["reason"] == "crash")
    assert crash_grp["count"] == 1
    assert crash_grp["test_file"] == "tests/test_overflow.py"


def _crash(label: str) -> dict[str, object]:
    return {
        "schema": 1,
        "reason": "crash",
        "outcome": "fail",
        "severity": "HIGH",
        "kind": None,
        "label": label,
        "summary": f"{label}: process crashed",
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": {"signal": "SIGSEGV", "returncode": -11},
    }


def test_crash_with_per_test_target_recovers_nodeid(tmp_path: Path) -> None:
    """F-037: a per-test crash target already names the culprit -- keep it."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    groups = extract_groups(path, crashes=[_crash("tests/test_overflow.py::test_boom")])
    (crash_grp,) = [g for g in groups if g["reason"] == "crash"]
    assert crash_grp["test_file"] == "tests/test_overflow.py"
    assert crash_grp["nodeids"] == ["tests/test_overflow.py::test_boom"]


def _runner_record(
    label: str,
    *,
    reason: str,
    summary: str,
    detail: dict[str, object] | None,
) -> dict[str, object]:
    """A runner/report-side finding shaped like crash_classification output."""
    return {
        "schema": 1,
        "reason": reason,
        "outcome": "fail",
        "severity": "HIGH",
        "kind": None,
        "label": label,
        "summary": summary,
        "operation": None,
        "mechanism": None,
        "expected_ckr": None,
        "actual_ckr": None,
        "spec_ref": "",
        "source": None,
        "vector_id": None,
        "detail": detail,
    }


def test_timeout_and_exit_records_do_not_merge(tmp_path: Path) -> None:
    """F14/P11C-0198-012: a timeout and an ordinary exit share every 7-tuple
    element (same file, same probe_incomplete reason) -- only the structured
    termination in the grouping key keeps them apart."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    timeout = _runner_record(
        "tests/test_overflow.py",
        reason="probe_incomplete",
        summary="tests/test_overflow.py: process timed out without completing",
        detail={"mode": "timeout"},
    )
    exited = _runner_record(
        "tests/test_overflow.py",
        reason="probe_incomplete",
        summary="tests/test_overflow.py: process exited without completing",
        detail={"signal": "exit code 1", "returncode": 1},
    )
    # The split must come from the termination element alone, never the reason.
    assert timeout["reason"] == exited["reason"]
    groups = extract_groups(path, crashes=[timeout, exited])
    assert len(groups) == 2
    assert {g["reason"] for g in groups} == {"probe_incomplete"}


def test_distinct_termination_kinds_split_crash_groups(tmp_path: Path) -> None:
    """F14/P11C-0198-012: SIGSEGV and SIGABRT in one file are different
    terminations and must not share a group."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    segv = _crash("tests/test_overflow.py")
    abrt = _crash("tests/test_overflow.py")
    abrt["detail"] = {"signal": "SIGABRT", "returncode": -6}
    groups = extract_groups(path, crashes=[segv, abrt])
    assert len(groups) == 2


def test_identical_terminations_still_merge(tmp_path: Path) -> None:
    """F14 loudness pin: the termination key only splits what differs -- two
    identical SIGSEGV observations still form one group with count 2."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    groups = extract_groups(
        path, crashes=[_crash("tests/test_overflow.py"), _crash("tests/test_overflow.py")]
    )
    assert len(groups) == 1
    assert groups[0]["count"] == 2


def test_observation_termination_splits_runner_groups(tmp_path: Path) -> None:
    """F14/P11C-0198-012: observation-carried terminations (signal vs Windows
    exception) group apart even when every other key element matches."""
    from pkcs11_check.core.process_observation import build_process_observation

    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    signal_obs = build_process_observation("t", "unit", 0, -11)
    exc_obs = build_process_observation("t", "unit", 0, 0xC0000005, platform="win32")
    segv = _runner_record(
        "tests/test_overflow.py",
        reason="crash",
        summary="tests/test_overflow.py: process crashed with SIGSEGV",
        detail={"observation": signal_obs},
    )
    exc = _runner_record(
        "tests/test_overflow.py",
        reason="crash",
        summary="tests/test_overflow.py: process crashed with Windows exception",
        detail={"observation": exc_obs},
    )
    groups = extract_groups(path, crashes=[segv, exc])
    assert len(groups) == 2


def test_in_test_termination_detail_splits_groups(tmp_path: Path) -> None:
    """F14/P11C-0198-012: in-test records carrying detail.termination (the
    assert_subprocess_completed shape) group by termination kind."""
    path = tmp_path / "report.jsonl"
    sigterm = _classification(
        reason="crash",
        kind=None,
        operation=None,
        mechanism=None,
        expected_ckr=None,
        actual_ckr=None,
        detail={
            "termination": {
                "kind": "signal",
                "raw_code": -11,
                "signal_name": "SIGSEGV",
                "windows_status": None,
            }
        },
    )
    timeoutterm = _classification(
        reason="crash",
        kind=None,
        operation=None,
        mechanism=None,
        expected_ckr=None,
        actual_ckr=None,
        detail={
            "termination": {
                "kind": "timeout",
                "raw_code": 124,
                "signal_name": None,
                "windows_status": None,
            }
        },
    )
    lines = [
        _test_report("tests/test_overflow.py::test_a", [sigterm]),
        _test_report("tests/test_overflow.py::test_b", [timeoutterm]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")
    groups = extract_groups(path, crashes=[])
    assert len(groups) == 2


def test_crash_with_file_target_retains_uncertainty(tmp_path: Path) -> None:
    """F-037: a file-level crash names no culprit -- do not invent one."""
    path = tmp_path / "report.jsonl"
    path.write_text("", encoding="utf-8")
    groups = extract_groups(path, crashes=[_crash("tests/test_overflow.py")])
    (crash_grp,) = [g for g in groups if g["reason"] == "crash"]
    assert crash_grp["test_file"] == "tests/test_overflow.py"
    assert crash_grp["nodeids"] == []


def test_non_test_phase_reports_ignored(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    custom = {
        "$report_type": "TestReport",
        "when": "custom",
        "nodeid": "tests/test_x.py::t1",
        "outcome": "passed",
        "user_properties": [["pkcs11_classification", [_classification()]]],
    }
    call = _test_report("tests/test_x.py::t1", [_classification()])
    path.write_text(json.dumps(custom) + "\n" + json.dumps(call) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])
    assert len(groups) == 1
    assert groups[0]["count"] == 1


def test_fixture_phase_crashes_are_grouped_and_ordinary_error_is_absent(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    crash = _classification(
        reason="crash",
        severity="HIGH",
        kind=None,
        operation=None,
        mechanism=None,
        expected_ckr=None,
        actual_ckr=None,
        detail={"windows_status": 0xC0000005},
    )
    records = [
        _test_report("tests/test_x.py::setup_av", [crash], when="setup"),
        _test_report("tests/test_x.py::teardown_av", [crash], when="teardown"),
        {
            "$report_type": "TestReport",
            "when": "setup",
            "nodeid": "tests/test_x.py::ordinary_error",
            "outcome": "failed",
            "user_properties": [],
        },
    ]
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    assert groups[0]["reason"] == "crash"
    assert groups[0]["count"] == 2
    assert groups[0]["nodeids"] == [
        "tests/test_x.py::setup_av",
        "tests/test_x.py::teardown_av",
    ]


def test_params_aggregate_into_param_breakdown(tmp_path: Path) -> None:
    # same group key, different curve params -> one group with a curve breakdown
    path = tmp_path / "report.jsonl"
    lines = [
        _test_report("tests/test_ec.py::a", [_classification(params={"curve": "brainpoolP224r1"})]),
        _test_report("tests/test_ec.py::b", [_classification(params={"curve": "brainpoolP224r1"})]),
        _test_report("tests/test_ec.py::c", [_classification(params={"curve": "secp256r1"})]),
    ]
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])
    assert len(groups) == 1
    assert groups[0]["param_breakdown"] == {"curve=brainpoolp224r1": 2, "curve=secp256r1": 1}


def test_no_params_yields_empty_param_breakdown(tmp_path: Path) -> None:
    path = tmp_path / "report.jsonl"
    path.write_text(
        json.dumps(_test_report("t.py::a", [_classification()])) + "\n", encoding="utf-8"
    )
    groups = extract_groups(path, crashes=[])
    assert groups[0]["param_breakdown"] == {}


@pytest.mark.parametrize(
    ("record", "reason"),
    [
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "error",
                "rv": 5,
                "rv_name": "CKR_GENERAL_ERROR",
            },
            "self_contradiction",
        ),
        (
            {
                "$report_type": "TeardownFinalize",
                "outcome": "crashed",
                "windows_status": 0xC0000005,
                "signal": "EXCEPTION_ACCESS_VIOLATION",
            },
            "crash",
        ),
        (
            {"$report_type": "TeardownFinalize", "outcome": "timeout"},
            "self_contradiction",
        ),
    ],
)
def test_extract_groups_includes_teardown_finalize_finding(
    tmp_path: Path, record: dict[str, object], reason: str
) -> None:
    path = tmp_path / "report.jsonl"
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    groups = extract_groups(path, crashes=[])

    assert len(groups) == 1
    assert groups[0]["test_file"] == "C_Finalize"
    assert groups[0]["operation"] == "C_Finalize"
    assert groups[0]["reason"] == reason
    assert groups[0]["count"] == 1
