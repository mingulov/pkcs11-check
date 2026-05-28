"""Regression tests for DES runtime reject classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKM_DES_CFB64, CKR_KEY_TYPE_INCONSISTENT
from pkcs11_check.testcases import test_des


def test_des_encrypt_key_type_inconsistent_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _encrypt_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT",
            int(CKR_KEY_TYPE_INCONSISTENT),
        )

    monkeypatch.setattr(test_des, "encrypt_single", _encrypt_reject)

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        test_des._encrypt_or_xfail(object(), 1, 2, CKM_DES_CFB64, b"12345678")
