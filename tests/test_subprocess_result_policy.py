"""Meta-tests for subprocess crash-survival result classification."""

from __future__ import annotations

import pytest

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
