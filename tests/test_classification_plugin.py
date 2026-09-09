"""Tests that classification records ride to user_properties via the plugin."""

from __future__ import annotations

import json

import pytest

from pkcs11_check.core.file_runner import postprocess_jsonl_to_unified

pytest_plugins = ["pytester"]
pytestmark = pytest.mark.usefixtures("classification_report_plugin_enabled")


def _report_lines(pytester: pytest.Pytester) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _phase_reports(pytester: pytest.Pytester) -> dict[str, dict[str, object]]:
    return {
        str(report["when"]): report
        for report in _report_lines(pytester)
        if report.get("$report_type") == "TestReport"
    }


def _phase_classifications(report: dict[str, object]) -> list[dict[str, object]]:
    properties = dict(report.get("user_properties", []))
    return list(properties.get("pkcs11_classification", []))


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


def test_setup_xfail_classification_is_serialized_once(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_setup_xfail="""
import pytest
from pkcs11_check import classification as C

@pytest.fixture(autouse=True)
def setup_finding():
    C.xfail_as("not_operational", label="setup deviation", summary="setup deviation")

def test_body():
    raise AssertionError("setup xfail must prevent the call")
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(xfailed=1)
    setup = next(report for report in _report_lines(pytester) if report.get("when") == "setup")
    classifications = _phase_classifications(setup)
    assert [entry["reason"] for entry in classifications] == ["not_operational"]
    assert len(classifications) == 1


def test_setup_xfail_does_not_leak_to_independent_next_test(pytester: pytest.Pytester) -> None:
    """A setup refusal belongs only to its item; the next item runs independently."""
    pytester.makepyfile(
        test_setup_xfail_leak="""
import pytest
from pkcs11_check import classification as C

@pytest.fixture
def setup_finding(request):
    if request.node.name == "test_first":
        C.xfail_as("not_operational", label="first setup", summary="first setup")

def test_first(setup_finding):
    raise AssertionError("the setup refusal must prevent only this call")

def test_second():
    pass
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(xfailed=1, passed=1)
    second_call = next(
        report
        for report in _report_lines(pytester)
        if report.get("$report_type") == "TestReport"
        and report.get("nodeid", "").endswith("test_second")
        and report.get("when") == "call"
    )
    assert _phase_classifications(second_call) == []
    setup = next(
        report
        for report in _report_lines(pytester)
        if report.get("$report_type") == "TestReport"
        and report.get("nodeid", "").endswith("test_first")
        and report.get("when") == "setup"
    )
    assert [entry["reason"] for entry in _phase_classifications(setup)] == ["not_operational"]


def test_setup_observation_does_not_prevent_call(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_setup_observation="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture(autouse=True)
def setup_finding():
    record(Classification(
        reason="sanctioned_refusal", outcome="pass", severity="INFO",
        label="setup observation", summary="setup observation",
    ))

def test_body():
    assert True
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(passed=1)
    reports = _phase_reports(pytester)
    assert reports["call"]["outcome"] == "passed"
    assert [entry["reason"] for entry in _phase_classifications(reports["setup"])] == [
        "sanctioned_refusal"
    ]
    assert _phase_classifications(reports["call"]) == []


def test_teardown_classification_is_serialized_once(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_teardown_finding="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture(autouse=True)
def teardown_finding():
    yield
    record(Classification(
        reason="sanctioned_refusal", outcome="pass", severity="INFO",
        label="teardown observation", summary="teardown observation",
    ))

def test_body():
    assert True
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(passed=1)
    reports = _phase_reports(pytester)
    assert _phase_classifications(reports["call"]) == []
    assert [entry["reason"] for entry in _phase_classifications(reports["teardown"])] == [
        "sanctioned_refusal"
    ]


def test_setup_call_teardown_occurrences_are_not_duplicated(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_all_phases="""
import pytest
from pkcs11_check.classification import Classification, record

def finding(label):
    record(Classification(
        reason="sanctioned_refusal", outcome="pass", severity="INFO",
        label=label, summary=label,
    ))

@pytest.fixture(autouse=True)
def setup_and_teardown():
    finding("setup")
    yield
    finding("teardown")

def test_body():
    finding("call")
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(passed=1)
    reports = _phase_reports(pytester)
    assert [entry["label"] for entry in _phase_classifications(reports["setup"])] == ["setup"]
    assert [entry["label"] for entry in _phase_classifications(reports["call"])] == ["call"]
    assert [entry["label"] for entry in _phase_classifications(reports["teardown"])] == ["teardown"]


def test_teardown_observation_does_not_leak_to_next_item(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_teardown_leak="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture
def teardown_finding():
    yield
    record(Classification(
        reason="sanctioned_refusal", outcome="pass", severity="INFO",
        label="first teardown", summary="first teardown",
    ))

def test_first(teardown_finding):
    pass

def test_second():
    pass
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(passed=2)
    reports = [
        report
        for report in _report_lines(pytester)
        if report.get("$report_type") == "TestReport" and report.get("when") == "teardown"
    ]
    assert len(reports) == 2
    assert [entry["label"] for entry in _phase_classifications(reports[0])] == ["first teardown"]
    assert _phase_classifications(reports[1]) == []


def test_raw_failure_after_recorded_xfail_is_retained(pytester: pytest.Pytester) -> None:
    pytester.makeconftest(
        """
        def pytest_configure():
            import pkcs11_check._plugin_report_attach as attach
            attach._is_testcase_item = lambda _item: True
        """
    )
    pytester.makepyfile(
        test_raw_failure="""
from pkcs11_check.classification import Classification, record

def test_body():
    record(Classification(
        reason="nonspec_reject", outcome="xfail", severity="LOW",
        label="provider deviation", summary="provider deviation",
    ))
    assert False, "raw failure"
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(failed=1)
    call = next(report for report in _report_lines(pytester) if report.get("when") == "call")
    assert [entry["reason"] for entry in _phase_classifications(call)] == [
        "nonspec_reject",
        "unclassified",
    ]


def test_classified_failure_does_not_gain_duplicate_unclassified(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_classified_failure="""
from pkcs11_check import classification as C

def test_body():
    C.fail_as("accepted_invalid", kind="crypto", label="provider failure")
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(failed=1)
    call = next(report for report in _report_lines(pytester) if report.get("when") == "call")
    assert [entry["reason"] for entry in _phase_classifications(call)] == ["accepted_invalid"]


def test_caught_terminating_classification_still_controls_public_result(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(
        test_caught_classification="""
from pkcs11_check import classification as C

def test_body():
    try:
        C.fail_as("accepted_invalid", kind="crypto", label="caught provider failure")
    except BaseException:
        pass
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(failed=1)
    call = next(report for report in _report_lines(pytester) if report.get("when") == "call")
    assert call["outcome"] == "failed"
    assert [entry["reason"] for entry in _phase_classifications(call)] == ["accepted_invalid"]


def test_call_failure_and_cleanup_failure_both_survive(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_call_cleanup="""
import pytest
from pkcs11_check import classification as C
from pkcs11_check.classification import Classification, record

@pytest.fixture
def cleanup_failure():
    yield
    record(Classification(
        reason="harness_error", outcome="fail", severity="HIGH",
        label="cleanup", summary="cleanup failed",
    ))

def test_body(cleanup_failure):
    C.fail_as("accepted_invalid", kind="crypto", label="provider failure")
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(failed=1, errors=1)
    reports = _phase_reports(pytester)
    assert [entry["reason"] for entry in _phase_classifications(reports["call"])] == [
        "accepted_invalid"
    ]
    assert [entry["reason"] for entry in _phase_classifications(reports["teardown"])] == [
        "harness_error"
    ]


def test_setup_only_recorded_xfail_controls_passing_call(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_setup_xfail_public="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture(autouse=True)
def setup_finding():
    record(Classification(
        reason="nonspec_reject", outcome="xfail", severity="LOW",
        label="setup deviation", summary="setup deviation",
    ))

def test_body():
    assert True
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(xfailed=1)
    reports = _phase_reports(pytester)
    assert reports["setup"]["outcome"] == "passed"
    assert reports["call"]["outcome"] == "skipped"
    assert reports["call"].get("wasxfail") == "setup deviation"


@pytest.mark.parametrize("terminal", ["xfail", "skip"])
def test_recorded_fail_then_xfail_or_skip_stays_failed(
    pytester: pytest.Pytester, terminal: str
) -> None:
    pytester.makepyfile(
        test_recorded_fail="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture(autouse=True)
def setup_finding():
    record(Classification(
        reason="accepted_invalid", outcome="fail", severity="CRITICAL",
        label="recorded failure", summary="recorded failure",
    ))
    pytest.{terminal}("later disposition")

def test_body():
    pass
""".replace("{terminal}", terminal)
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(errors=1)
    setup = next(report for report in _report_lines(pytester) if report.get("when") == "setup")
    assert setup["outcome"] == "failed"
    assert "recorded failure" in str(setup.get("longrepr", ""))
    assert [entry["reason"] for entry in _phase_classifications(setup)] == ["accepted_invalid"]


def test_nonterminating_teardown_fail_is_public_failure(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        test_teardown_failure="""
import pytest
from pkcs11_check.classification import Classification, record

@pytest.fixture(autouse=True)
def teardown_finding():
    yield
    record(Classification(
        reason="harness_error", outcome="fail", severity="HIGH",
        label="teardown failure", summary="teardown failure",
    ))

def test_body():
    assert True
"""
    )

    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")

    result.assert_outcomes(passed=1, errors=1)
    teardown = next(
        report for report in _report_lines(pytester) if report.get("when") == "teardown"
    )
    assert teardown["outcome"] == "failed"
    assert "teardown failure" in str(teardown.get("longrepr", ""))
    assert [entry["reason"] for entry in _phase_classifications(teardown)] == ["harness_error"]
