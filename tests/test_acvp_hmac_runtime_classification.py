"""Regression tests for ACVP HMAC runtime-result classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKK_SHA256_HMAC, CKM_SHA256_HMAC, CKR_GENERAL_ERROR
from pkcs11_check.testcases.acvp import test_acvp_hmac as hmac


class _HmacSession:
    raw = object()
    sh = 1


def _hmac_vec() -> dict[str, Any]:
    return {
        "key_type": int(CKK_SHA256_HMAC),
        "mechanism": int(CKM_SHA256_HMAC),
        "mech_display": "SHA256_HMAC",
        "key": b"k",
        "msg": b"message",
    }


def test_advertised_hmac_runtime_general_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generic runtime rejection after advertised HMAC support is an xfail finding."""

    def _sign_general_error(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(hmac, "import_secret_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(hmac, "sign_single", _sign_general_error)
    monkeypatch.setattr(hmac, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="advertised but imported HMAC key"):
        hmac._sign_hmac_with_key_fallback(_HmacSession(), _hmac_vec())
