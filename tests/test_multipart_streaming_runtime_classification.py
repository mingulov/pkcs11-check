"""Regression tests for standalone multipart streaming setup classification."""

from __future__ import annotations

import hashlib
import hmac
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_KEY_TYPE,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKM_AES_ECB,
    CKM_SHA256_HMAC,
    CKR_ARGUMENTS_BAD,
    CKR_BUFFER_TOO_SMALL,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_multipart_streaming as streaming


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name in names)


def test_streaming_aes_ecb_skips_when_mechanism_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Standalone AES streaming checks should skip missing mechanisms before setup."""

    def _unexpected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("AES keygen should have been capability-guarded")

    monkeypatch.setattr(streaming, "gen_aes_key", _unexpected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN")

    with pytest.raises(pytest.skip.Exception, match="AES_ECB not supported"):
        streaming.TestMultipartEncrypt().test_aes_ecb_multiblock_roundtrip(rs, 1)


def test_streaming_aes_keygen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised-but-rejected AES setup is visible xfail evidence."""

    def _rejected_keygen(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_NOT_SUPPORTED",
            int(CKR_FUNCTION_NOT_SUPPORTED),
        )

    monkeypatch.setattr(streaming, "gen_aes_key", _rejected_keygen)
    rs = _session_with_mechanisms("AES_KEY_GEN", "AES_ECB")

    with pytest.raises(pytest.xfail.Exception, match="AES_KEY_GEN advertised"):
        streaming.TestMultipartEncrypt().test_aes_ecb_multiblock_roundtrip(rs, 1)


def test_streaming_imported_aes_key_sets_allowed_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Imported AES setup keys should declare the operation mechanism for TPM2."""
    captured: dict[str, Any] = {}

    def _capture_import(*_args: Any, attrs: dict[int, Any], **_kwargs: Any) -> int:
        captured["attrs"] = attrs
        return 1

    monkeypatch.setattr(streaming, "import_secret_key", _capture_import)

    key = streaming._import_aes_key(_session_with_mechanisms("AES_ECB"), bytes(range(32)))

    assert key == 1
    assert captured["attrs"][CKA_ALLOWED_MECHANISMS] == [CKM_AES_ECB]


def test_streaming_digest_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Advertised digest mechanisms that reject valid input are non-clean xfails."""

    def _rejected_digest(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_ARGUMENTS_BAD", int(CKR_ARGUMENTS_BAD))

    monkeypatch.setattr(streaming, "digest_single", _rejected_digest)
    rs = _session_with_mechanisms("SHA256")

    with pytest.raises(pytest.xfail.Exception, match="SHA256 advertised but digest"):
        streaming.TestMultipartDigest().test_sha256_large_data_crossverify(rs, 0)


def test_streaming_hmac_key_sets_allowed_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Imported HMAC setup keys should declare the operation mechanism for TPM2."""
    captured: dict[str, Any] = {}
    key_bytes = bytes(range(32))
    data = b"\x77" * 65536
    expected = hmac.new(key_bytes, data, hashlib.sha256).digest()

    def _capture_create(*_args: Any, **_kwargs: Any) -> int:
        captured["attrs"] = _args[2]
        return 1

    monkeypatch.setattr(streaming, "create_object", _capture_create)
    monkeypatch.setattr(streaming, "sign_single", lambda *_args, **_kwargs: expected)
    monkeypatch.setattr(streaming, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    streaming.TestMultipartSign().test_hmac_large_data_crossverify(rs)

    assert captured["attrs"][CKA_ALLOWED_MECHANISMS] == [CKM_SHA256_HMAC]


def test_streaming_hmac_buffer_too_small_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid advertised HMAC path returning CKR_BUFFER_TOO_SMALL is non-clean evidence."""

    def _buffer_too_small(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_BUFFER_TOO_SMALL",
            int(CKR_BUFFER_TOO_SMALL),
        )

    monkeypatch.setattr(streaming, "create_object", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(streaming, "sign_single", _buffer_too_small)
    monkeypatch.setattr(streaming, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    with pytest.raises(pytest.xfail.Exception, match="SHA256_HMAC advertised but sign"):
        streaming.TestMultipartSign().test_hmac_large_data_crossverify(rs)


def test_streaming_hmac_key_import_falls_back_to_generic_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HMAC streaming should keep coverage when typed HMAC key import is rejected."""
    seen_key_types: list[int] = []
    key_bytes = bytes(range(32))
    data = b"\x77" * 65536
    expected = hmac.new(key_bytes, data, hashlib.sha256).digest()

    def _create_with_fallback(*_args: Any, **_kwargs: Any) -> int:
        attrs = _args[2]
        seen_key_types.append(int(attrs[CKA_KEY_TYPE]))
        if len(seen_key_types) == 1:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
                int(CKR_TEMPLATE_INCONSISTENT),
            )
        return 2

    monkeypatch.setattr(streaming, "create_object", _create_with_fallback)
    monkeypatch.setattr(streaming, "sign_single", lambda *_args, **_kwargs: expected)
    monkeypatch.setattr(streaming, "destroy_quietly", lambda *_args, **_kwargs: None)
    rs = _session_with_mechanisms("SHA256_HMAC")

    try:
        streaming.TestMultipartSign().test_hmac_large_data_crossverify(rs)
    except pytest.xfail.Exception as exc:
        pytest.fail(f"typed HMAC import reject should fall back to generic-secret key: {exc}")

    assert seen_key_types == [int(CKK_SHA256_HMAC), int(CKK_GENERIC_SECRET)]
