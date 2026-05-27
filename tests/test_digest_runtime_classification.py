"""Regression tests for general digest capability/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_SHA224,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases import test_digest


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in names)


def test_general_digest_skips_when_mechanism_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """General digest length checks should skip missing digest mechanisms."""

    def _unexpected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise AssertionError("digest should have been capability-guarded")

    monkeypatch.setattr(test_digest, "digest_single", _unexpected_digest)
    rs = _session_with_mechanisms("SHA256")

    with pytest.raises(pytest.skip.Exception, match="SHA224 not supported"):
        test_digest.TestDigestLengths().test_digest_length(rs, CKM_SHA224, 28)


def test_general_digest_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised digest mechanisms that reject valid input are non-clean xfails."""

    def _rejected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(test_digest, "digest_single", _rejected_digest)
    rs = _session_with_mechanisms("SHA256")

    with pytest.raises(pytest.xfail.Exception, match="SHA256 advertised but digest"):
        test_digest.TestDigestProperties().test_sha256_empty_data(rs)


def test_digest_key_aes_setup_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DigestKey coverage should classify advertised-but-rejected AES setup."""

    def _rejected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(test_digest, "gen_aes_key", _rejected_keygen)
    rs = _session_with_mechanisms("SHA256", "AES_KEY_GEN")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_digest.TestDigestKey().test_digest_key_matches_hashlib(rs)


def test_digest_key_skips_when_sha256_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DigestKey should skip before AES setup if the digest mechanism is absent."""

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should not run without SHA256")

    monkeypatch.setattr(test_digest, "gen_aes_key", _unexpected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.skip.Exception, match="SHA256 not supported"):
        test_digest.TestDigestKey().test_digest_key_matches_hashlib(rs)
