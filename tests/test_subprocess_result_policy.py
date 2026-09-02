"""Meta-tests for subprocess crash-survival result classification."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from pkcs11_check import classification, plugin
from pkcs11_check.core.process_observation import (
    build_process_observation,
    drain_process_observations,
    record_process_observation,
)
from pkcs11_check.core.subprocess_trace import drain_subprocess_rv_trace
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed


def test_process_observations_attach_to_call_report_once_and_in_order() -> None:
    drain_process_observations()
    first = build_process_observation("_echo", "probe", 0, -9, platform="linux")
    second = build_process_observation("_echo", "probe", 0, 0, platform="linux")
    record_process_observation(first)
    record_process_observation(second)
    item = SimpleNamespace(
        path=Path("/repo/src/pkcs11_check/testcases/test_nested.py"),
        nodeid="wrong-item-nodeid",
        user_properties=[],
    )
    report = SimpleNamespace(
        when="call",
        outcome="passed",
        nodeid="src/pkcs11_check/testcases/test_nested.py::test_nested",
        user_properties=[],
    )

    plugin._attach_rv_trace_to_report(item, report)

    expected = [dict(first), dict(second)]
    for observation in expected:
        observation["parent_nodeid"] = report.nodeid
    assert dict(report.user_properties)["pkcs11_process_observations"] == expected
    assert first["parent_nodeid"] is None
    assert second["parent_nodeid"] is None
    assert drain_process_observations() == []

    next_report = SimpleNamespace(
        when="call",
        outcome="passed",
        nodeid="src/pkcs11_check/testcases/test_nested.py::test_next",
        user_properties=[],
    )
    plugin._attach_rv_trace_to_report(item, next_report)
    assert next_report.user_properties == []


def test_subprocess_result_policy_reports_signal_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "linux")
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        assert_subprocess_completed(
            -11,
            "",
            "segmentation fault",
            context="C_Test boundary probe",
        )


def test_subprocess_result_policy_records_normalized_termination_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pkcs11_check.core.process_observation.sys.platform", "linux")
    classification.clear()
    try:
        with pytest.raises(pytest.fail.Exception):
            assert_subprocess_completed(
                -11,
                "",
                "segmentation fault",
                context="C_Test boundary probe",
            )

        record = classification.get_records()[-1]
        assert record.detail == {
            "termination": {
                "kind": "signal",
                "raw_code": -11,
                "signal_name": "SIGSEGV",
                "windows_status": None,
            }
        }
    finally:
        classification.clear()


def test_subprocess_result_policy_reports_positive_child_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_subprocess_completed(
            1,
            "",
            "SyntaxError: invalid syntax",
            context="generated child script",
        )


@pytest.mark.parametrize(
    ("rc", "stderr"),
    [
        (5, "AttributeError: C_Test not available in this module"),
        (
            1,
            "AttributeError: C_Test not available in this module\nRuntimeError: later failure",
        ),
        (1, "log: not available in this module"),
    ],
)
def test_capability_phrase_does_not_hide_child_failure(rc: int, stderr: str) -> None:
    try:
        with pytest.raises(pytest.fail.Exception, match="subprocess failed"):
            assert_subprocess_completed(rc, "", stderr, context="generated child script")
    except pytest.skip.Exception as exc:
        pytest.fail(f"incidental capability phrase hid child failure: {exc}")


def test_exact_dispatcher_capability_failure_skips() -> None:
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "child.py", line 1, in <module>\n'
        "AttributeError: C_Test not available in this module\n"
    )
    with pytest.raises(pytest.skip.Exception, match="not implemented"):
        assert_subprocess_completed(1, "", stderr, context="generated child script")


def test_subprocess_result_policy_preserves_rv_trace_marker_after_long_output() -> None:
    marker = 'P11_RV_TRACE_JSON:[{"fn":"C_Test","rv":0,"rv_name":"CKR_OK"}]'
    stdout = "noise" * 200 + "\n" + marker

    with pytest.raises(pytest.fail.Exception) as excinfo:
        assert_subprocess_completed(
            1,
            stdout,
            "",
            context="generated child script",
        )

    assert marker in str(excinfo.value)


def test_subprocess_result_policy_keeps_the_exception_line_of_a_long_traceback() -> None:
    """A traceback carries its exception on the LAST line; a head-only excerpt drops it.

    This is why GH #9 could not be diagnosed from the harness output: the reporter saw
    the traceback header and had to reproduce the BufferError independently.
    """
    frames = "".join(
        f'  File "/x/pkcs11_check/testcases/_probes/output_length.py", line {n}, in _run_oracle\n'
        f"    in_mm.close()\n"
        for n in range(200)
    )
    stderr = f"Traceback (most recent call last):\n{frames}BufferError: cannot close exported"

    with pytest.raises(pytest.fail.Exception) as excinfo:
        assert_subprocess_completed(1, "", stderr, context="generated child script")

    assert "BufferError: cannot close exported" in str(excinfo.value)


def test_subprocess_result_policy_records_rv_trace_for_later_report_attachment() -> None:
    marker = 'P11_RV_TRACE_JSON:[{"i":0,"fn":"C_Test","rv":0,"rv_name":"CKR_OK"}]'

    assert_subprocess_completed(0, marker, "", context="generated child script")

    assert drain_subprocess_rv_trace() == [{"i": 0, "fn": "C_Test", "rv": 0, "rv_name": "CKR_OK"}]
