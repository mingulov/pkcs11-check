"""Tests that classification records ride to user_properties via the plugin."""

from __future__ import annotations

import pytest

from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified

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


def test_harness_failure_record_makes_report_non_green(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_harness="""
        from pkcs11_check.classification import Classification, record

        def test_measurement_then_cleanup_error():
            record(Classification(
                reason="accepted_invalid", outcome="fail", severity="CRITICAL",
                label="provider verdict", summary="invalid input accepted",
            ))
            record(Classification(
                reason="harness_error", outcome="fail", severity="HIGH",
                label="cleanup", summary="cleanup failed after measurement",
            ))
        """
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    result.assert_outcomes(failed=1)

    import json

    records = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    call = next(record for record in records if record.get("when") == "call")
    assert call["outcome"] == "failed"
    classifications = dict(call["user_properties"])["pkcs11_classification"]
    assert [entry["reason"] for entry in classifications] == [
        "accepted_invalid",
        "harness_error",
    ]


def test_harness_failure_record_cannot_be_hidden_by_skip(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_harness_skip="""
        import pytest
        from pkcs11_check.classification import Classification, record

        def test_cleanup_error_then_skip():
            record(Classification(
                reason="harness_error", outcome="fail", severity="HIGH",
                label="cleanup", summary="cleanup failed before skip",
            ))
            pytest.skip("later disposition must not hide harness failure")
        """
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    result.assert_outcomes(failed=1)

    import json

    records = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    call = next(record for record in records if record.get("when") == "call")
    assert call["outcome"] == "failed"
    assert dict(call["user_properties"])["pkcs11_classification"][0]["reason"] == "harness_error"


def test_fixture_access_violations_are_crashes_but_ordinary_oserror_is_not(
    pytester: pytest.Pytester,
) -> None:
    pytester.makeconftest(
        """
        def pytest_configure():
            import pkcs11_check._plugin_report_attach as attach
            attach._is_testcase_item = lambda _item: True
        """
    )
    pytester.makepyfile(
        test_fixture_crash="""
        import pytest

        @pytest.fixture
        def setup_av():
            raise OSError("exception: access violation reading 0x0")

        @pytest.fixture
        def teardown_av():
            yield
            raise OSError("exception: access violation reading 0x0")

        @pytest.fixture
        def ordinary_error():
            raise OSError("provider I/O error")

        def test_setup_av(setup_av):
            pass

        def test_teardown_av(teardown_av):
            pass

        def test_ordinary_error(ordinary_error):
            pass
        """
    )

    pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    import json

    records = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    failed_fixture_reports = [
        record
        for record in records
        if record.get("when") in {"setup", "teardown"} and record.get("outcome") == "failed"
    ]
    crash_reports = [
        record
        for record in failed_fixture_reports
        if dict(record.get("user_properties", []))
        .get("pkcs11_classification", [{}])[0]
        .get("reason")
        == "crash"
    ]
    assert len(crash_reports) == 2

    payload = postprocess_jsonl_to_unified(
        pytester.path / "report.jsonl", pytester.path / "results.json"
    )
    assert payload["summary"]["crashed"] == 2
    assert payload["summary"]["error"] == 1
    assert payload["summary"]["passed"] == 0


def test_call_access_violation_survives_an_earlier_classification(
    pytester: pytest.Pytester,
) -> None:
    pytester.makeconftest(
        """
        def pytest_configure():
            import pkcs11_check._plugin_report_attach as attach
            attach._is_testcase_item = lambda _item: True
        """
    )
    pytester.makepyfile(
        test_call_crash="""
        from pkcs11_check.classification import Classification, record

        def test_call_crash():
            record(Classification(
                reason="nonspec_reject", outcome="xfail", severity="MEDIUM",
                label="earlier provider finding", summary="clean provider deviation",
            ))
            raise OSError("exception: access violation reading 0x0")
        """
    )

    pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    import json

    records = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    call = next(record for record in records if record.get("when") == "call")
    classifications = dict(call["user_properties"])["pkcs11_classification"]
    assert [entry["reason"] for entry in classifications] == ["nonspec_reject", "crash"]

    payload = postprocess_jsonl_to_unified(
        pytester.path / "report.jsonl", pytester.path / "results.json"
    )
    assert payload["summary"]["crashed"] == 1
    assert payload["units"][0]["counts"]["crashed"] == 1
