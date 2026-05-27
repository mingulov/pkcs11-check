"""Regression tests for CCTV Ed25519 reject classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID, CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_cctv_ed25519


class _EdDsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _vec(flags: list[str]) -> dict[str, Any]:
    return {
        "number": 999,
        "key": "00" * 32,
        "sig": "00" * 64,
        "msg": "cctv edge case",
        "flags": flags,
    }


def test_cctv_ed25519_verify_non_clean_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _verify_reject(*_args: Any, **_kwargs: Any) -> bool:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(test_cctv_ed25519, "import_ec_public_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cctv_ed25519, "verify_single", _verify_reject)
    monkeypatch.setattr(test_cctv_ed25519, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="signature verification rejected"):
        test_cctv_ed25519.test_ed25519_cctv(_vec(["low_order_R"]), _EdDsaSession())


def test_cctv_ed25519_invalid_key_non_clean_import_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(test_cctv_ed25519, "import_ec_public_key", _import_reject)

    with pytest.raises(pytest.xfail.Exception, match="invalid public key rejected"):
        test_cctv_ed25519.test_ed25519_cctv(_vec(["low_order_A"]), _EdDsaSession())


def test_cctv_ed25519_invalid_key_clean_import_reject_is_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_cctv_ed25519, "import_ec_public_key", _import_reject)

    test_cctv_ed25519.test_ed25519_cctv(_vec(["non_canonical_A"]), _EdDsaSession())
