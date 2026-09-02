"""ML-KEM key-usage setup must not hide non-CKR provider failures."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED
from pkcs11_check.testcases import test_key_usage_policy as policy


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ML_KEM",
    )


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_encapsulate_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    def _raise(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise exc

    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", _raise)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session())
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


@pytest.mark.parametrize(
    ("which", "exc"),
    [
        ("normal", OSError("exception: access violation")),
        ("normal", AssertionError("normal setup bug")),
        ("restricted", OSError("exception: access violation")),
        ("restricted", AssertionError("restricted setup bug")),
    ],
)
def test_decapsulate_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch,
    which: str,
    exc: BaseException,
) -> None:
    calls = 0

    def _raise(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if (which == "normal" and calls == 1) or (which == "restricted" and calls == 2):
            raise exc
        return (1, 2)

    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", _raise)
    monkeypatch.setattr(policy, "destroy_quietly", lambda *_args: None)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session())
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


@pytest.mark.parametrize("exc", [OSError("exception: access violation"), AssertionError("bug")])
def test_decapsulate_operation_setup_non_ckr_exception_propagates(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> None:
    def _raise(*_args: Any, **_kwargs: Any) -> tuple[int, bytes]:
        raise exc

    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(policy, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr("pkcs11_check.raw.recipes.encapsulate_key", _raise)

    with pytest.raises(type(exc), match=str(exc)):
        try:
            policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session())
        except pytest.skip.Exception as skipped:
            pytest.fail(f"non-CKR exception was swallowed as a skip: {skipped}")


def test_advertised_clean_setup_refusal_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )
    monkeypatch.setattr(
        policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (_ for _ in ()).throw(refusal)
    )

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM keypair generation"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session())


def test_unknown_setup_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = CkrAssertionError("Unexpected CK_RV", 0x7FFFFFFF)
    monkeypatch.setattr(
        policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (_ for _ in ()).throw(refusal)
    )

    with pytest.raises(CkrAssertionError, match="Unexpected CK_RV"):
        policy.TestKEMKeyUsagePolicy().test_encapsulate_flag_false_rejected(_session())


def test_encapsulate_setup_refusal_is_visible_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    refusal = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
        int(CKR_FUNCTION_NOT_SUPPORTED),
    )
    monkeypatch.setattr(policy, "_gen_ml_kem_keypair", lambda *_a, **_k: (1, 2))
    monkeypatch.setattr(policy, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        "pkcs11_check.raw.recipes.encapsulate_key", lambda *_a, **_k: (_ for _ in ()).throw(refusal)
    )

    with pytest.raises(pytest.xfail.Exception, match="ML-KEM encapsulation setup"):
        policy.TestKEMKeyUsagePolicy().test_decapsulate_flag_false_rejected(_session())
