"""Regression tests for EdDSA runtime rejection classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED
from pkcs11_check.testcases import test_eddsa
from pkcs11_check.testcases.acvp import test_acvp_eddsa


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


def test_acvp_eddsa_sigver_import_runtime_failure_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _function_failed(*_args: object, **_kwargs: object) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

    rs = type(
        "RawSession",
        (),
        {
            "raw": object(),
            "sh": 1,
            "has_mechanism": lambda self, name: name == "EDDSA",
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
