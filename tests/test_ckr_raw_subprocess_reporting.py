"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from pkcs11_check.testcases.ckr import (
    test_ckr_dual,
    test_ckr_v30_raw,
    test_ckr_v32_raw,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

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


def test_ckr_subprocess_helper_reports_positive_exit_as_child_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        assert_ckr_subprocess_ok(
            1,
            "",
            "AssertionError: setup failed",
            context="CKR setup probe",
        )


def test_ckr_subprocess_helper_converts_setup_marker_to_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="AES key generation rejected"):
        assert_ckr_subprocess_ok(
            0,
            "SETUP_XFAIL:AES key generation rejected: CKR_FUNCTION_NOT_SUPPORTED\n",
            "",
            context="CKR setup probe",
        )


def test_ckr_subprocess_helper_requires_ok_marker() -> None:
    with pytest.raises(pytest.fail.Exception, match="did not emit an OK marker"):
        assert_ckr_subprocess_ok(0, "CKR:0x00000000\n", "", context="CKR setup probe")


def test_ckr_dual_reports_positive_subprocess_exit_as_child_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CKR operation-state child assertion exits must not be labelled crashes."""

    def run_child(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout="",
            stderr="AssertionError: setup failed",
        )

    monkeypatch.setattr(test_ckr_dual.subprocess, "run", run_child)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    with pytest.raises(pytest.fail.Exception, match="subprocess failed with exit code 1"):
        test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))


def test_encrypt_without_init_child_does_not_require_aes_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """C_Encrypt without C_EncryptInit should not fail during AES key setup."""

    def run_child(
        args: list[str],
        *unused_args: object,
        **unused_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        script = args[2]
        assert "gen_aes_key" not in script
        assert "raw.C_Encrypt(" in script
        assert "CKR_OPERATION_NOT_INITIALIZED" in script
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="OK:encrypt_without_init\n",
            stderr="",
        )

    monkeypatch.setattr(test_ckr_dual.subprocess, "run", run_child)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_encrypt_without_init(SimpleNamespace(module="/fake/p11.so", pin=None))


def test_double_digest_init_child_checks_operation_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The double-DigestInit subprocess should test the state violation directly."""

    def run_child(
        args: list[str],
        *unused_args: object,
        **unused_kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        script = args[2]
        assert "digest_single" not in script
        assert script.count("raw.C_DigestInit(") == 2
        assert "CKR_OPERATION_ACTIVE" in script
        return subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="OK:double_digest_init_active\n",
            stderr="",
        )

    monkeypatch.setattr(test_ckr_dual.subprocess, "run", run_child)

    test_case = test_ckr_dual.TestOperationStateSubprocess()
    test_case.test_double_digest_init_via_subprocess(
        SimpleNamespace(module="/fake/p11.so", pin=None)
    )
