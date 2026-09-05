"""Regression checks for crash-reporting policy in provider tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pkcs11_check.core._report_records import _build_detail_from_report_records
from pkcs11_check.testcases.ckr.test_ckr_null_params import _check_null_result

ROOT = Path(__file__).resolve().parents[1]
TESTCASE_ROOT = ROOT / "src/pkcs11_check/testcases"

_CRASH_TERMS = ("crash", "crashed", "segfault", "signal")
_NON_CRASH_PHRASES = (
    "not a crash",
    "without crash",
    "does not crash",
    "doesn't crash",
    "protocol kdf",
)


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return f"{func.value.id}.{func.attr}"
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    return [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]


def _reports_crash(strings: list[str]) -> bool:
    text = " ".join(value.lower() for value in strings)
    if any(phrase in text for phrase in _NON_CRASH_PHRASES):
        return False
    return any(term in text for term in _CRASH_TERMS)


def test_provider_crashes_are_not_xfailed() -> None:
    offenders: list[str] = []
    for path in TESTCASE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.xfail":
                continue
            if _reports_crash(_literal_strings(node)):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_provider_crashes_are_not_skipped() -> None:
    offenders: list[str] = []
    for path in TESTCASE_ROOT.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or _call_name(node) != "pytest.skip":
                continue
            if _reports_crash(_literal_strings(node)):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    assert offenders == []


def test_null_param_subprocess_signal_is_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="C_GetInfo.*signal 11"):
        _check_null_result("C_GetInfo", -11, "", "segfault")


def test_setup_crash_survives_retry_pass() -> None:
    nodeid = "test_demo.py::test_case"
    records = [
        {"$report_type": "IsolatedUnitReport", "target": "test_demo.py", "attempt": 0},
        {
            "$report_type": "TestReport",
            "nodeid": nodeid,
            "when": "setup",
            "outcome": "failed",
            "longrepr": "access violation in setup",
            "user_properties": [
                [
                    "pkcs11_classification",
                    [{"reason": "crash", "detail": {"windows_status": 0xC0000005}}],
                ]
            ],
        },
        {"$report_type": "IsolatedUnitReport", "target": nodeid, "attempt": 0},
        {
            "$report_type": "TestReport",
            "nodeid": nodeid,
            "when": "call",
            "outcome": "passed",
        },
    ]
    original = [dict(record) for record in records]

    detail = _build_detail_from_report_records(records)

    assert detail is not None
    assert detail["counts"]["crashed"] == 1
    assert detail["counts"]["passed"] == 0
    assert sum(detail["counts"].values()) == 1
    assert detail["tests"][0]["outcome"] == "crashed"
    assert detail["tests"][0]["when"] == "setup"
    assert records == original


def test_call_crash_and_teardown_failure_remain_inspectable_without_double_counting() -> None:
    nodeid = "test_demo.py::test_case"
    records = [
        {"$report_type": "IsolatedUnitReport", "target": "test_demo.py", "attempt": 0},
        {
            "$report_type": "TestReport",
            "nodeid": nodeid,
            "when": "call",
            "outcome": "failed",
            "longrepr": "access violation in call",
            "user_properties": [
                [
                    "pkcs11_classification",
                    [{"reason": "crash", "detail": {"windows_status": 0xC0000005}}],
                ]
            ],
        },
        {
            "$report_type": "TestReport",
            "nodeid": nodeid,
            "when": "teardown",
            "outcome": "failed",
            "longrepr": "cleanup also failed",
        },
    ]

    detail = _build_detail_from_report_records(records)

    assert detail is not None
    assert detail["counts"]["crashed"] == 1
    assert detail["counts"]["error"] == 0
    assert sum(detail["counts"].values()) == 1
    assert [(test["outcome"], test.get("when"), test["longrepr"]) for test in detail["tests"]] == [
        ("crashed", None, "access violation in call"),
        ("error", "teardown", "cleanup also failed"),
    ]
