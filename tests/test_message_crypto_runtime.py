"""Regression tests for message-based crypto result classification."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_message_crypto
from tests._skip_assert import assert_skips


class _MessageVerifyRaw:
    def C_VerifyMessage(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_DEVICE_ERROR)

    def C_VerifyMessageBegin(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_VerifyMessageNext(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageVerifyInit(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageVerifyFinal(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)


class _MessageSignInitRaw:
    def __init__(self, rv: int) -> None:
        self._rv = rv

    def C_MessageSignInit(self, *_args: object) -> int:  # noqa: N802
        return self._rv


class _MessageEncryptRaw:
    def C_MessageEncryptInit(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessage(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessageBegin(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_EncryptMessageNext(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)

    def C_MessageEncryptFinal(self, *_args: object) -> int:  # noqa: N802
        return int(CKR_OK)


def test_message_verify_bad_signature_device_error_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=_MessageVerifyRaw(),
        sh=1,
        has_mechanism=lambda name: name == "SHA256_RSA_PKCS",
    )
    monkeypatch.setattr(test_message_crypto, "gen_rsa_keypair", lambda *_args: (10, 11))
    monkeypatch.setattr(test_message_crypto, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKR_DEVICE_ERROR"):
        test_message_crypto.TestMessageSignVerify().test_message_verify_bad_signature(rs)


def test_message_sign_init_mechanism_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_message_crypto.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_MECHANISM_INVALID)), sh=1)

    with pytest.raises(pytest.xfail.Exception, match="CKR_MECHANISM_INVALID"):
        test_message_crypto._message_sign(rs, 1, 1, b"data")


def test_message_sign_init_function_not_supported_is_skip() -> None:
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_FUNCTION_NOT_SUPPORTED)), sh=1)

    with pytest.raises(pytest.skip.Exception, match="C_MessageSignInit not supported"):
        test_message_crypto._message_sign(rs, 1, 1, b"data")


def test_message_sign_init_unexpected_rv_is_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_message_crypto.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )
    rs = SimpleNamespace(raw=_MessageSignInitRaw(int(CKR_ARGUMENTS_BAD)), sh=1)

    with pytest.raises(pytest.fail.Exception, match="C_MessageSignInit returned unexpected"):
        test_message_crypto._message_sign(rs, 1, 1, b"data")


def test_message_encrypt_uses_aes_keygen_xfail_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_message_crypto,
        "gen_aes_key",
        lambda *_args, **_kwargs: pytest.fail("raw AES keygen helper used"),
        raising=False,
    )
    monkeypatch.setattr(
        test_message_crypto,
        "gen_aes_key_or_xfail",
        lambda *_args, **_kwargs: pytest.xfail("AES_KEY_GEN advertised but rejected"),
        raising=False,
    )
    rs = SimpleNamespace(
        raw=_MessageEncryptRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_CBC", "AES_KEY_GEN"},
    )

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        test_message_crypto.TestMessageEncryptDecrypt().test_message_encrypt_single(rs)


def test_skip_if_message_op_not_implemented_skips_on_fns() -> None:
    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    assert_skips(
        test_message_crypto._skip_if_message_op_not_implemented,
        exc,
        "message encrypt",
        match="message encrypt",
    )


def test_skip_if_message_op_not_implemented_ignores_other_ckr() -> None:
    exc = CkrAssertionError("CKR_MECHANISM_INVALID", int(CKR_MECHANISM_INVALID))
    # Must return quietly so the caller's own xfail_if_known_ckr path runs.
    test_message_crypto._skip_if_message_op_not_implemented(exc, "message encrypt")


def test_message_encrypt_single_fns_is_skip_not_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """C_MessageEncryptInit/C_EncryptMessage are optional v3.0 functions; FNS from
    message_encrypt() is capability absence, not a deviation (site: line ~262)."""
    rs = SimpleNamespace(
        raw=_MessageEncryptRaw(),
        sh=1,
        has_mechanism=lambda name: name in {"AES_CBC", "AES_KEY_GEN"},
    )
    monkeypatch.setattr(test_message_crypto, "gen_aes_key_or_xfail", lambda *_a, **_k: 42)
    monkeypatch.setattr(test_message_crypto, "destroy_quietly", lambda *_a, **_k: None)

    def _raise(*_a: object, **_k: object) -> bytes:
        raise CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))

    # test_message_encrypt_single() does `from pkcs11_check.raw.recipes import
    # message_encrypt` locally, so the patch target is the recipes module, not
    # the test_message_crypto module namespace.
    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "message_encrypt", _raise)

    assert_skips(
        test_message_crypto.TestMessageEncryptDecrypt().test_message_encrypt_single,
        rs,
        match="message encrypt",
    )
