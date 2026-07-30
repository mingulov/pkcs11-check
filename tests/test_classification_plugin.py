"""Tests that classification records ride to user_properties via the plugin."""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]


def test_classification_lands_in_user_properties(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_x="""
        from pkcs11_check import classification as C
        def test_emits():
            try:
                C.classify("nonspec_reject", label="probe", actual="CKR_DEVICE_ERROR")
            except Exception:
                pass
        """
    )
    result = pytester.runpytest_inprocess()
    reports = result.reprec.getreports("pytest_runtest_logreport")
    call = [r for r in reports if r.when == "call"][0]
    props = dict((k, v) for k, v in call.user_properties)
    assert "pkcs11_classification" in props
    assert props["pkcs11_classification"][0]["reason"] == "nonspec_reject"


def test_no_cross_item_classification_leak(pytester: pytest.Pytester) -> None:
    """Classification records from test_first must NOT appear on test_second.

    This is a regression test for the teardown asymmetry where clear_classifications()
    was gated on _is_testcase_item(), allowing records to leak across consecutive
    non-testcase items.  The fix moves the clear outside the gate so it runs for every
    item unconditionally (matching the ungated _attach_classification_to_report).

    We use runpytest (subprocess) to avoid shared module state between the outer and
    inner sessions (runpytest_inprocess shares the _records global and the outer
    session's hooks can interfere with inprocess captures).
    """
    pytester.makepyfile(
        test_leak="""
        from pkcs11_check import classification as C

        def test_first():
            try:
                C.classify("nonspec_reject", label="a", actual="CKR_DEVICE_ERROR")
            except Exception:
                pass

        def test_second():
            pass  # emits nothing
        """
    )
    # Use runpytest_subprocess to get a clean process with no shared module state.
    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    # test_first xfails (nonspec_reject → xfail outcome), test_second passes
    result.assert_outcomes(xfailed=1, passed=1)
    import json

    report_log = pytester.path / "report.jsonl"
    lines = [
        json.loads(line)
        for line in report_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    call_lines = [ln for ln in lines if ln.get("when") == "call"]
    assert len(call_lines) == 2, f"expected 2 call records, got {len(call_lines)}"

    # test_first should carry classification
    first_props = dict(call_lines[0].get("user_properties", []))
    assert "pkcs11_classification" in first_props, "test_first should have pkcs11_classification"

    # test_second must NOT carry classification from test_first
    second_props = dict(call_lines[1].get("user_properties", []))
    assert "pkcs11_classification" not in second_props, (
        "test_second must not inherit classification records from test_first"
    )
