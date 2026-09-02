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
