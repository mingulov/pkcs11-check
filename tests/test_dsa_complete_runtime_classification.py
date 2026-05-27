"""Regression tests for complete DSA setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_dsa_complete


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_dsa_parameter_gen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _param_gen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("DSA_PARAMETER_GEN")
    monkeypatch.setattr(test_dsa_complete, "_generate_dsa_params", _param_gen_reject)
    monkeypatch.setattr(
        test_dsa_complete.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="DSA_PARAMETER_GEN advertised"):
        test_dsa_complete.TestDSAParameterGen().test_parameter_gen(rs)


def test_dsa_keypair_from_generated_params_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keypair_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("DSA_PARAMETER_GEN", "DSA_KEY_PAIR_GEN")
    monkeypatch.setattr(test_dsa_complete, "_generate_dsa_params", lambda *_args: 10)
    monkeypatch.setattr(test_dsa_complete, "_gen_dsa_keypair_from_params", _keypair_reject)
    monkeypatch.setattr(test_dsa_complete, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_dsa_complete.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="DSA_KEY_PAIR_GEN advertised"):
        test_dsa_complete.TestDSAParameterGen().test_parameter_gen_and_keypair(rs)
