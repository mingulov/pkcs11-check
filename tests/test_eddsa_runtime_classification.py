"""Regression tests for EdDSA runtime rejection classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED
from pkcs11_check.testcases import test_eddsa
from pkcs11_check.testcases._ec_export import RawECPointFamily


def test_eddsa_sign_device_error_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _device_error(*_args: object, **_kwargs: object) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    rs = type("RawSession", (), {"raw": object(), "sh": 1})()
    monkeypatch.setattr(test_eddsa, "sign_single", _device_error)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_eddsa._sign_eddsa(rs, 1, b"message")


def test_eddsa_verify_device_error_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _device_error(*_args: object, **_kwargs: object) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    rs = type("RawSession", (), {"raw": object(), "sh": 1})()
    monkeypatch.setattr(test_eddsa, "verify_single", _device_error)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_eddsa._verify_eddsa(rs, 1, b"message", b"signature")


def test_eddsa_cross_verify_preserves_raw_point_starting_with_der_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_point = b"\x04" + bytes(range(1, 32))
    family_calls: list[tuple[int, RawECPointFamily]] = []
    verifier_inputs: list[bytes] = []

    def _read_raw_point(_rs: Any, handle: int, family: RawECPointFamily, **_kwargs: Any) -> bytes:
        family_calls.append((handle, family))
        return raw_point

    class _FakeEd25519PublicKey:
        @classmethod
        def from_public_bytes(cls, public_bytes: bytes) -> _FakeEd25519PublicKey:
            verifier_inputs.append(public_bytes)
            return cls()

        def verify(self, signature: bytes, data: bytes) -> None:
            assert signature == b"signature"
            assert data == b"Ed25519 cross-verify test"

    monkeypatch.setattr(test_eddsa, "_sign_eddsa", lambda *_args: b"signature")
    monkeypatch.setattr(test_eddsa, "read_attributes", lambda *_args: {CKA_EC_POINT: raw_point})
    monkeypatch.setattr(
        test_eddsa,
        "read_raw_ec_point_or_xfail",
        _read_raw_point,
        raising=False,
    )
    monkeypatch.setattr(
        "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey",
        _FakeEd25519PublicKey,
    )

    test_eddsa.TestEdDSACrossVerify().test_sign_p11_verify_crypto(
        SimpleNamespace(raw=object(), sh=1), (1, 2)
    )

    assert family_calls == [(1, RawECPointFamily.ED25519)]
    assert verifier_inputs == [raw_point]


def test_acvp_eddsa_sigver_import_runtime_failure_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pkcs11_check.testcases.acvp import test_acvp_eddsa

    def _function_failed(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

    rs = type(
        "RawSession",
        (),
        {
            "raw": object(),
            "sh": 1,
            "has_mechanism": lambda self, name: name == "EDDSA",
            "has_mechanism_flag": lambda self, _mech, _flag: True,
        },
    )()
    vec = {
        "curve": "ED-25519",
        "ec_params": b"\x06\x03\x2b\x65\x70",
        "ec_point": b"\x04\x20" + (b"\x01" * 32),
        "msg": b"message",
        "sig": b"\x00" * 64,
        "expected_pass": True,
    }
    monkeypatch.setattr(
        test_acvp_eddsa,
        "_select_eddsa_public_key_encoding_for_vector",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        test_acvp_eddsa,
        "import_eddsa_public_key_with_supported_encoding",
        _function_failed,
    )

    with pytest.raises(pytest.xfail.Exception, match="public-key import rejected"):
        test_acvp_eddsa.test_acvp_eddsa_sigver(rs, "EDDSA-SigVer-ED-25519-tc1", vec)
