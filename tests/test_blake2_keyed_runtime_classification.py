"""Regression tests for keyed BLAKE2b coverage and classification."""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR
from pkcs11_check.testcases import test_blake2


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_blake2b_hmac_reference_matches_python_hmac() -> None:
    key = b"blake2 hmac key"
    data = b"blake2 hmac data"
    digest_size = 32

    def _digest(payload: bytes = b"") -> Any:
        return hashlib.blake2b(payload, digest_size=digest_size)

    expected = hmac.new(key, data, _digest).digest()

    assert test_blake2._blake2b_hmac_reference(key, data, digest_size) == expected


def test_blake2b_hmac_general_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_HMAC_GENERAL")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_HMAC_GENERAL advertised"):
        test_blake2.TestBlake2bKeyed().test_blake2b_256_hmac_general_truncates(rs)


def test_blake2b_key_derive_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("BLAKE2B_256_KEY_DERIVE")
    monkeypatch.setattr(test_blake2, "_import_blake2b_setup_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_blake2, "derive_key", _derive_reject)

    with pytest.raises(pytest.xfail.Exception, match="BLAKE2B_256_KEY_DERIVE advertised"):
        test_blake2.TestBlake2bKeyed().test_blake2b_256_key_derive_value(rs)
