"""Regression tests for CCTV RFC6979 setup and expected-mismatch classification."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_cctv_rfc6979


class _EcdsaSession:
    raw = object()
    sh = 1

    def has_mechanism(self, _name: str) -> bool:
        return True


def test_rfc6979_public_import_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    # Batch 3b: the public-key site now negotiates storage shapes via
    # import_ec_public_key_negotiated -- patch that name (stale-pin reconciliation).
    monkeypatch.setattr(test_cctv_rfc6979, "import_ec_public_key_negotiated", _import_reject)
    monkeypatch.setattr(
        test_cctv_rfc6979.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="P-256 public-key import is not operational"):
        test_cctv_rfc6979.test_rfc6979_ecdsa_verify(_EcdsaSession())


def test_rfc6979_private_import_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_cctv_rfc6979, "import_ec_private_key", _import_reject)
    monkeypatch.setattr(
        test_cctv_rfc6979.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="P-256 private-key import is not operational"):
        test_cctv_rfc6979.test_rfc6979_ecdsa_sign_deterministic(_EcdsaSession())


def test_rfc6979_signature_mismatch_is_explicit_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_cctv_rfc6979, "import_ec_private_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_cctv_rfc6979, "sign_single", lambda *_args, **_kwargs: b"wrong")
    monkeypatch.setattr(test_cctv_rfc6979, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="does not use RFC 6979 deterministic k"):
        test_cctv_rfc6979.test_rfc6979_ecdsa_sign_deterministic(_EcdsaSession())
