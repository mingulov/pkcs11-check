"""Regression tests for Wycheproof RSA-OAEP private-key import classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep


class _RsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _first_oaep_vector() -> tuple[str, dict[str, Any]]:
    return test_wycheproof_rsa_oaep._ALL_OAEP_VECTORS[0]


def test_rsa_oaep_private_import_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_wycheproof_rsa_oaep._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_oaep_vector()

    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_wycheproof_rsa_oaep, "import_rsa_private_key", _import_reject)
    monkeypatch.setattr(
        test_wycheproof_rsa_oaep.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA private-key import is not operational"):
        test_wycheproof_rsa_oaep.test_rsa_oaep(_RsaSession(), vec_id, vec)

    assert test_wycheproof_rsa_oaep._UNSUPPORTED_RSA_KEY_SIZES == set()


def test_rsa_oaep_private_import_unknown_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    test_wycheproof_rsa_oaep._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_oaep_vector()

    def _import_bug(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("ctypes packing bug")

    monkeypatch.setattr(test_wycheproof_rsa_oaep, "import_rsa_private_key", _import_bug)

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_wycheproof_rsa_oaep.test_rsa_oaep(_RsaSession(), vec_id, vec)
