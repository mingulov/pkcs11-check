"""Regression tests for legacy resource/stress runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw import bootstrap as raw_bootstrap
from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_SESSION_COUNT,
)
from pkcs11_check.testcases import test_resource, test_stress


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        slot_id=1,
        has_mechanism=lambda name: name in names,
    )


def _raise_function_not_supported(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )


def _raise_mechanism_invalid(*_args: Any, **_kwargs: Any) -> bytes:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_INVALID",
        int(CKR_MECHANISM_INVALID),
    )


def _raise_session_count(*_args: Any, **_kwargs: Any) -> int:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_SESSION_COUNT",
        int(CKR_SESSION_COUNT),
    )


def test_resource_aes_setup_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", _raise_function_not_supported)
    monkeypatch.setattr(
        test_resource,
        "gen_aes_key",
        _raise_function_not_supported,
        raising=False,
    )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_resource.TestMemoryLeaks().test_key_generation_no_leak(rs)


def test_resource_missing_digest_mechanism_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_resource,
        "digest_single",
        lambda *_args: pytest.fail("SHA256 should have been capability-guarded"),
    )
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="SHA256 not supported"):
        test_resource.TestMemoryLeaks().test_digest_cycle_no_leak(rs)


def test_resource_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(raw_bootstrap, "open_session", _raise_session_count)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_resource.TestSessionChurn().test_rapid_session_cycles(
            rs,
            SimpleNamespace(pin=None),
        )


def test_stress_missing_aes_ecb_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_stress,
        "gen_aes_key",
        lambda *_args, **_kwargs: pytest.fail("AES setup should have been skipped"),
        raising=False,
    )
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_stress.TestRapidOperations().test_rapid_encrypt_decrypt_1000(rs)


def test_stress_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_stress,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kwargs: (1, 2),
    )
    monkeypatch.setattr(raw_recipes, "sign_single", _raise_mechanism_invalid)
    monkeypatch.setattr(test_stress, "sign_single", _raise_mechanism_invalid)
    monkeypatch.setattr(test_stress, "destroy_quietly", lambda *_args: None)
    rs = _session_with_mechanisms("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")

    with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS sign rejected"):
        test_stress.TestRapidOperations().test_rapid_sign_verify_100(rs)


def test_stress_extra_session_capacity_reject_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_stress, "_raw_open_session", _raise_session_count)
    rs = _session_with_mechanisms()

    with pytest.raises(pytest.skip.Exception, match="additional session"):
        test_stress.TestSessionStress().test_session_open_close_100(
            rs,
            SimpleNamespace(pin=None),
        )


def test_stress_random_duplicates_remain_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_stress, "generate_random", lambda *_args: b"\x01" * 32)
    rs = _session_with_mechanisms()

    with pytest.raises(AssertionError, match="Random generation produced duplicates"):
        test_stress.TestRapidOperations().test_rapid_random_1000(rs)
