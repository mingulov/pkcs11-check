"""Regression tests for legacy multipart smoke setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD, CKR_MECHANISM_INVALID
from pkcs11_check.testcases import test_multipart


def _session(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in names)


def test_multipart_smoke_missing_digest_mechanism_is_counted_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_multipart,
        "digest_single",
        lambda *_args, **_kwargs: pytest.fail("digest should not be called"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256 not supported"):
        test_multipart.TestMultiPartDigest().test_sha256_consistency(_session())


def test_multipart_smoke_digest_runtime_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _digest_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(test_multipart, "digest_single", _digest_reject)

    with pytest.raises(pytest.xfail.Exception, match="SHA256 digest rejected"):
        test_multipart.TestMultiPartDigest().test_sha256_consistency(_session("SHA256"))


def test_multipart_smoke_missing_aes_ecb_is_counted_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_multipart,
        "gen_aes_key_or_xfail",
        lambda *_args, **_kwargs: pytest.fail("AES keygen should not be called"),
    )

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        test_multipart.TestMultiPartEncrypt().test_encrypt_16kb(_session("AES_KEY_GEN"))


def test_multipart_smoke_encrypt_runtime_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encrypt_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(test_multipart, "gen_aes_key_or_xfail", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(test_multipart, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_multipart, "encrypt_single", _encrypt_reject)

    with pytest.raises(pytest.xfail.Exception, match="AES_ECB encrypt rejected"):
        test_multipart.TestMultiPartEncrypt().test_encrypt_16kb(_session("AES_KEY_GEN", "AES_ECB"))


def test_multipart_smoke_decrypt_runtime_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _decrypt_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(test_multipart, "gen_aes_key_or_xfail", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(test_multipart, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_multipart, "encrypt_single", lambda *_args, **_kwargs: b"ct")
    monkeypatch.setattr(test_multipart, "decrypt_single", _decrypt_reject)

    with pytest.raises(pytest.xfail.Exception, match="AES_ECB decrypt rejected"):
        test_multipart.TestMultiPartEncrypt().test_encrypt_16kb(_session("AES_KEY_GEN", "AES_ECB"))


def test_multipart_smoke_missing_rsa_sign_mechanism_is_counted_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_multipart,
        "gen_rsa_keypair_or_xfail",
        lambda *_args, **_kwargs: pytest.fail("RSA keygen should not be called"),
    )

    with pytest.raises(pytest.skip.Exception, match="SHA256_RSA_PKCS not supported"):
        test_multipart.TestMultiPartSign().test_rsa_sign_1byte(_session("RSA_PKCS_KEY_PAIR_GEN"))


def test_multipart_smoke_sign_runtime_reject_is_visible_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        )

    monkeypatch.setattr(test_multipart, "gen_rsa_keypair_or_xfail", lambda *_args: (1, 2))
    monkeypatch.setattr(test_multipart, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_multipart, "sign_single", _sign_reject)

    with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS sign rejected"):
        test_multipart.TestMultiPartSign().test_rsa_sign_1byte(
            _session("RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
        )
