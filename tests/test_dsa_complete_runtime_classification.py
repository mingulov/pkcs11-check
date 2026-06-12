"""Regression tests for complete DSA setup/runtime classification."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_DSA_PARAMETER_GEN_PARAM,
    CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
    CKM_SHA256,
    CKR_GENERAL_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases import test_dsa_complete


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_dsa_complete_module_preserves_sign_and_slow_marks() -> None:
    mark = test_dsa_complete.pytestmark
    marks = mark if isinstance(mark, list) else [mark]

    assert {item.mark.name for item in marks} == {"sign", "slow"}


def test_dsa_parameter_gen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _param_gen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("DSA_PARAMETER_GEN")
    module = cast(Any, test_dsa_complete)
    monkeypatch.setattr(test_dsa_complete, "_generate_dsa_params", _param_gen_reject)
    monkeypatch.setattr(
        module.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="DSA_PARAMETER_GEN advertised"):
        test_dsa_complete.TestDSAParameterGen().test_parameter_gen(rs)


def test_dsa_parameter_gen_param_mech_owns_seed_buffer() -> None:
    packed = test_dsa_complete._dsa_parameter_gen_param_mech(
        CKM_DSA_PROBABILISTIC_PARAMETER_GEN,
        seed_len=32,
    )

    assert packed.ck.mechanism == CKM_DSA_PROBABILISTIC_PARAMETER_GEN
    assert packed.ck.ulParameterLen == ctypes.sizeof(CK_DSA_PARAMETER_GEN_PARAM)
    assert isinstance(packed.params, CK_DSA_PARAMETER_GEN_PARAM)
    assert packed.params.hash == CKM_SHA256
    assert packed.params.pSeed is not None
    assert packed.params.ulSeedLen == 32
    assert packed.buffer_bytes("seed") == b"\x00" * 32


def test_dsa_keypair_from_generated_params_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keypair_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("DSA_PARAMETER_GEN", "DSA_KEY_PAIR_GEN")
    module = cast(Any, test_dsa_complete)
    monkeypatch.setattr(test_dsa_complete, "_generate_dsa_params", lambda *_args: 10)
    monkeypatch.setattr(test_dsa_complete, "_gen_dsa_keypair_from_params", _keypair_reject)
    monkeypatch.setattr(test_dsa_complete, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        module.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="DSA_KEY_PAIR_GEN advertised"):
        test_dsa_complete.TestDSAParameterGen().test_parameter_gen_and_keypair(rs)


def test_raw_dsa_wrong_length_digest_acceptance_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_init(*_args: Any) -> int:
        return int(CKR_OK)

    def _sign(*_args: Any) -> int:
        out_len = _args[4]
        out_len._obj.value = 40
        return int(CKR_OK)

    rs = SimpleNamespace(
        raw=SimpleNamespace(C_SignInit=_sign_init, C_Sign=_sign),
        sh=1,
        has_mechanism=lambda name: name == "DSA",
    )
    monkeypatch.setattr(test_dsa_complete, "_generate_dsa_keypair", lambda _rs: (10, 11, 12))
    monkeypatch.setattr(test_dsa_complete, "destroy_quietly", lambda *_args: None)

    with pytest.raises(BaseException) as excinfo:
        test_dsa_complete.TestDSARaw().test_raw_dsa_wrong_length_digest(rs)

    assert type(excinfo.value) is pytest.fail.Exception
    assert "CKM_DSA wrong-length digest: accepted invalid" in str(excinfo.value)
