"""Regression checks for provider findings that must not become green skips."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKF_RNG,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_RANDOM_NO_RNG,
)
from pkcs11_check.testcases import conftest, test_token_flags
from pkcs11_check.testcases.wycheproof import test_wycheproof_ecdsa


def _rng_session(flags: int) -> SimpleNamespace:
    return SimpleNamespace(raw=_RngRaw(flags, int(CKR_OK)), sh=1, slot_id=0)


def _run_rng_check(monkeypatch: pytest.MonkeyPatch, flags: int, result: Any) -> None:
    check = test_token_flags.TestTokenFlags()
    session = _rng_session(flags)
    if isinstance(result, BaseException):
        monkeypatch.setattr(
            test_token_flags,
            "generate_random",
            lambda *_a: (_ for _ in ()).throw(result),
        )
    else:
        monkeypatch.setattr(test_token_flags, "generate_random", lambda *_a: result)
    check.test_rng_flag_matches_capability(session)


def test_advertised_rng_refusal_is_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CkrAssertionError("C_GenerateRandom failed", int(CKR_FUNCTION_FAILED))
    with pytest.raises(pytest.xfail.Exception, match="CKF_RNG is set"):
        _run_rng_check(monkeypatch, int(CKF_RNG), error)


def test_rng_wrong_length_is_not_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AssertionError):
        _run_rng_check(monkeypatch, int(CKF_RNG), b"short")


def test_unadvertised_rng_clean_absence_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CkrAssertionError("no RNG", int(CKR_RANDOM_NO_RNG))
    _run_rng_check(monkeypatch, 0, error)


def test_unadvertised_rng_unexpected_failure_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CkrAssertionError("device failed", int(CKR_DEVICE_ERROR))
    with pytest.raises(CkrAssertionError, match="device failed"):
        _run_rng_check(monkeypatch, 0, error)


def test_rng_success_without_flag_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.fail.Exception, match="CKF_RNG is not set"):
        _run_rng_check(monkeypatch, 0, b"x" * 32)


class _RngRaw:
    def __init__(self, flags: int, rv: int) -> None:
        self.flags = flags
        self.rv = rv

    def C_GetTokenInfo(self, _slot_id: int, info: Any) -> int:  # noqa: N802
        info._obj.flags = self.flags
        return int(CKR_OK)

    def C_GenerateRandom(self, _sh: int, _buf: Any, _length: int) -> int:  # noqa: N802
        return self.rv


def test_rng_quality_gate_exposes_advertised_failure() -> None:
    session = SimpleNamespace(raw=_RngRaw(int(CKF_RNG), int(CKR_FUNCTION_FAILED)), sh=1, slot_id=0)
    with pytest.raises(pytest.xfail.Exception, match="CKF_RNG is set"):
        conftest.skip_unless_generate_random_supported(session)


def test_rng_quality_gate_skips_clean_unadvertised_absence() -> None:
    session = SimpleNamespace(raw=_RngRaw(0, int(CKR_RANDOM_NO_RNG)), sh=1, slot_id=0)
    with pytest.raises(pytest.skip.Exception, match="does not advertise"):
        conftest.skip_unless_generate_random_supported(session)


def _ecdsa_vec() -> dict[str, Any]:
    return {
        "tcId": 1,
        "msg": "deadbeef",
        "sig": "aa" * 64,
        "result": "valid",
        "_curve": "secp256r1",
        "_coord_size": 32,
        "_is_p1363": True,
        "_hash_fn": hashlib.sha256,
        "_group": {"publicKey": {"uncompressed": "04" + "11" * 64}},
    }


def _ecdsa_session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_first_ecdsa_binding_defect_fails_then_cached_vectors_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mod = test_wycheproof_ecdsa
    monkeypatch.setattr(mod, "_CURVE_BINDING_DEFECTS", {})
    monkeypatch.setattr(mod, "import_ec_public_key_negotiated", lambda *_a, **_k: 7)
    monkeypatch.setattr(mod, "ec_public_key_binding_defect", lambda *_a: "silently rebound")
    monkeypatch.setattr(mod, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception, match="self-contradiction"):
        mod.test_ecdsa_wycheproof(_ecdsa_session(), "tc1", _ecdsa_vec())
    with pytest.raises(pytest.skip.Exception, match="already reported"):
        mod.test_ecdsa_wycheproof(_ecdsa_session(), "tc2", _ecdsa_vec())


def test_coherent_ecdsa_import_reaches_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = test_wycheproof_ecdsa
    verified: list[bool] = []
    monkeypatch.setattr(mod, "_CURVE_BINDING_DEFECTS", {})
    monkeypatch.setattr(mod, "import_ec_public_key_negotiated", lambda *_a, **_k: 7)
    monkeypatch.setattr(mod, "ec_public_key_binding_defect", lambda *_a: None)
    monkeypatch.setattr(mod, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(mod, "generate_random", lambda *_a: b"x" * 64)
    monkeypatch.setattr(mod, "verify_single", lambda *_a: verified.append(True) or True)

    mod.test_ecdsa_wycheproof(_ecdsa_session(), "tc1", _ecdsa_vec())
    assert verified == [True]
