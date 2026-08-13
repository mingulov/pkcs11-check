"""Meta-tests for subprocess crash-survival result classification."""

from __future__ import annotations

import pytest

from pkcs11_check.core.subprocess_trace import drain_subprocess_rv_trace
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed


def test_subprocess_result_policy_reports_signal_crash() -> None:
    with pytest.raises(pytest.fail.Exception, match="module crashed with signal 11"):
        assert_subprocess_completed(
            -11,
            "",
            "segmentation fault",
            context="C_Test boundary probe",
        )


def test_subprocess_result_policy_reports_positive_child_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_subprocess_completed(
            1,
            "",
            "SyntaxError: invalid syntax",
            context="generated child script",
        )


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
