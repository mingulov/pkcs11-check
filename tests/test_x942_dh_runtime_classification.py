"""Regression tests for X9.42 DH generated-parameter coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKR_GENERAL_ERROR,
)
from pkcs11_check.testcases import test_x942_dh


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _generated_param_attrs() -> dict[int, Any]:
    return {
        CKA_PRIME: b"\x80" + (b"\x00" * 255),
        CKA_BASE: b"\x02",
        CKA_SUBPRIME: b"\x80" + (b"\x00" * 31),
        CKA_PRIME_BITS: 2048,
        CKA_SUBPRIME_BITS: 256,
    }


def test_x942_parameter_gen_exercises_advertised_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def _param_gen_ok(*_args: Any, **_kwargs: Any) -> int:
        nonlocal called
        called = True
        return 77

    rs = _session_with_mechanisms("X9_42_DH_PARAMETER_GEN")
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", _param_gen_ok, raising=False)
    monkeypatch.setattr(test_x942_dh, "read_attributes", lambda *_args: _generated_param_attrs())
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHParameterGen().test_generate_parameters(rs)

    assert called


def test_x942_parameter_gen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _param_gen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("X9_42_DH_PARAMETER_GEN")
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", _param_gen_reject, raising=False)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    with pytest.raises(pytest.xfail.Exception, match="X9_42_DH_PARAMETER_GEN advertised"):
        test_x942_dh.TestX942DHParameterGen().test_generate_parameters(rs)


def test_x942_keypair_from_generated_params_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keypair_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms(
        "X9_42_DH_PARAMETER_GEN",
        "X9_42_DH_KEY_PAIR_GEN",
        "X9_42_DH_DERIVE",
    )
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(test_x942_dh, "read_attributes", lambda *_args: _generated_param_attrs())
    monkeypatch.setattr(test_x942_dh, "_generate_x942_keypair", _keypair_reject)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    with pytest.raises(pytest.xfail.Exception, match="X9_42_DH_KEY_PAIR_GEN advertised"):
        test_x942_dh.TestX942DHParameterGen().test_generated_params_produce_valid_derive(rs)
