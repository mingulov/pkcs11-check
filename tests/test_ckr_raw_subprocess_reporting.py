"""Meta-tests for raw CKR subprocess result reporting."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases.ckr import (
    test_ckr_dual,
    test_ckr_v30_raw,
    test_ckr_v32_raw,
)
from pkcs11_check.testcases.ckr._subprocess import assert_ckr_subprocess_ok

RawCheck = Callable[[int, str, str, str], None]


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


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


def test_ckr_dual_encrypt_wrapper_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES-128 key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_encrypt_twice_succeeds(rs)


def test_ckr_dual_sign_then_encrypt_xfails_advertised_aes_setup_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_ckr_dual,
        "gen_rsa_keypair",
        lambda *_args, **_kwargs: (10, 11),
        raising=False,
    )
    monkeypatch.setattr(raw_recipes, "gen_rsa_keypair", lambda *_args, **_kwargs: (10, 11))
    monkeypatch.setattr(test_ckr_dual, "sign_single", lambda *_args, **_kwargs: b"s" * 256)
    monkeypatch.setattr(test_ckr_dual, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("AES_KEY_GEN", "RSA_PKCS_KEY_PAIR_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES-128 key generation"):
        test_ckr_dual.TestOperationStateWrapper().test_sign_then_encrypt(rs)


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
