"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pkcs11_check.testcases.ckr import test_ckr_v30_raw, test_ckr_v32_raw

RawCheck = Callable[[int, str, str, str], None]


@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_signal_as_crash(check: RawCheck) -> None:
    """Negative subprocess return codes are crash findings."""
    with pytest.raises(pytest.fail.Exception, match="subprocess crashed with signal 11"):
        check(-11, "", "segmentation fault", "C_Test")


@pytest.mark.parametrize(
    "check",
    [test_ckr_v30_raw._check, test_ckr_v32_raw._check],
)
def test_raw_check_reports_positive_exit_as_subprocess_failure(check: RawCheck) -> None:
    """Assertion failures inside the child process are not crash findings."""
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        check(1, "CKR:0x00000007", "AssertionError: unexpected CKR", "C_Test")
