"""Regression tests for Salsa20 runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_salsa20


def test_salsa20_encrypt_general_error_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"SALSA20", "SALSA20_KEY_GEN"},
    )
    monkeypatch.setattr(test_salsa20, "_gen_stream_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(test_salsa20, "destroy_quietly", lambda *_args: None)

    def _encrypt_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_salsa20, "encrypt_single", _encrypt_reject)
    monkeypatch.setattr(
        test_salsa20,
        "decrypt_single",
        lambda *_args, **_kwargs: pytest.fail("decrypt should not run after encrypt reject"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKM_SALSA20 encrypt not operational"):
        test_salsa20.TestSalsa20().test_salsa20_encrypt_decrypt(rs)
