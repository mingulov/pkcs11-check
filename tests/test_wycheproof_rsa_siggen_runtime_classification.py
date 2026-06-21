"""Regression tests for Wycheproof RSA PKCS#1 siggen import classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_siggen


class _RsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def _first_siggen_vector() -> tuple[str, dict[str, Any]]:
    return test_wycheproof_rsa_siggen._ALL_SIGGEN_VECTORS[0]


def test_rsa_siggen_private_import_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = _first_siggen_vector()

    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_wycheproof_rsa_siggen, "provision_rsa_private_key", _import_reject)
    monkeypatch.setattr(
        test_wycheproof_rsa_siggen.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="RSA private-key import is not operational"):
        test_wycheproof_rsa_siggen.test_rsa_pkcs1_siggen(_RsaSession(), None, vec_id, vec)


def test_rsa_siggen_private_import_unknown_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vec_id, vec = _first_siggen_vector()

    def _import_bug(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("ctypes packing bug")

    monkeypatch.setattr(test_wycheproof_rsa_siggen, "provision_rsa_private_key", _import_bug)

    with pytest.raises(AssertionError, match="ctypes packing bug"):
        test_wycheproof_rsa_siggen.test_rsa_pkcs1_siggen(_RsaSession(), None, vec_id, vec)
