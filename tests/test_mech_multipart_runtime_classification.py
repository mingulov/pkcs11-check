"""Regression tests for multipart mechanism runtime-result classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_CMAC,
    CKM_AES_GCM,
    CKM_SHA256,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_mech_multipart as mech_multipart
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe


def _encrypt_entry(*, deterministic: bool = True, auth_tag_included: bool = False) -> MechEntry:
    mech_id = int(CKM_AES_GCM) if auth_tag_included else int(CKM_AES_CBC)
    mech_name = "AES_GCM" if auth_tag_included else "AES_CBC"
    param_style = "gcm" if auth_tag_included else "iv"
    return MechEntry(
        mech_id=mech_id,
        mech_name=mech_name,
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=MechConfig(
            key_type=int(CKK_AES),
            key_sizes=(128,),
            param_recipe=ParamRecipe(param_style),
            keygen_recipe=KeygenRecipe("symmetric"),
            deterministic=deterministic,
            auth_tag_included=auth_tag_included,
        ),
    )


def _digest_entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_SHA256),
        mech_name="SHA256",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(),
    )


def _sign_entry() -> MechEntry:
    return MechEntry(
        mech_id=int(CKM_AES_CMAC),
        mech_name="AES_CMAC",
        flags=0,
        min_key_size=16,
        max_key_size=32,
        config=MechConfig(
            key_type=int(CKK_AES),
            key_sizes=(128,),
            param_recipe=ParamRecipe("none"),
            keygen_recipe=KeygenRecipe("symmetric"),
        ),
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def test_multipart_encrypt_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _encrypt_multipart_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    monkeypatch.setattr(mech_multipart, "generate_key_for_encrypt", lambda *_args: (1, None))
    monkeypatch.setattr(mech_multipart, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(mech_multipart, "make_mech_param", lambda _entry: None)
    monkeypatch.setattr(mech_multipart, "encrypt_single", lambda *_args, **_kwargs: b"1" * 32)
    monkeypatch.setattr(mech_multipart, "encrypt_multipart", _encrypt_multipart_reject)
    monkeypatch.setattr(mech_multipart, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="multipart encrypt is not operational"):
        mech_multipart.TestMultipartEncrypt().test_streaming_equals_single(
            _session(),
            _encrypt_entry(),
        )


def test_multipart_decrypt_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _decrypt_multipart_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ENCRYPTED_DATA_LEN_RANGE",
            int(CKR_ENCRYPTED_DATA_LEN_RANGE),
        )

    monkeypatch.setattr(mech_multipart, "generate_key_for_encrypt", lambda *_args: (1, None))
    monkeypatch.setattr(mech_multipart, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(mech_multipart, "make_mech_param", lambda _entry: b"iv" * 8)
    monkeypatch.setattr(mech_multipart, "encrypt_single", lambda *_args, **_kwargs: b"1" * 32)
    monkeypatch.setattr(mech_multipart, "decrypt_multipart", _decrypt_multipart_reject)
    monkeypatch.setattr(mech_multipart, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="multipart decrypt is not operational"):
        mech_multipart.TestMultipartEncrypt().test_streaming_equals_single(
            _session(),
            _encrypt_entry(deterministic=False),
        )


def test_multipart_encrypt_aead_reference_retries_buffer_too_small(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encrypt_calls: list[dict[str, Any]] = []

    def _encrypt_single(*_args: Any, **kwargs: Any) -> bytes:
        encrypt_calls.append(kwargs)
        return b"1" * 48

    monkeypatch.setattr(mech_multipart, "generate_key_for_encrypt", lambda *_args: (1, None))
    monkeypatch.setattr(mech_multipart, "get_test_plaintext_bytes", lambda: b"0" * 32)
    monkeypatch.setattr(mech_multipart, "make_mech_param", lambda _entry: b"gcm")
    monkeypatch.setattr(mech_multipart, "encrypt_single", _encrypt_single)
    monkeypatch.setattr(mech_multipart, "decrypt_multipart", lambda *_args, **_kwargs: b"0" * 32)
    monkeypatch.setattr(mech_multipart, "destroy_quietly", lambda *_args: None)

    mech_multipart.TestMultipartEncrypt().test_streaming_equals_single(
        _session(),
        _encrypt_entry(deterministic=False, auth_tag_included=True),
    )

    assert encrypt_calls[-1]["output_overhead"] == 16
    assert encrypt_calls[-1]["retry_on_buffer_too_small"] is True


def test_multipart_digest_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _digest_multipart_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(mech_multipart, "digest_single", lambda *_args, **_kwargs: b"digest")
    monkeypatch.setattr(mech_multipart, "digest_multipart", _digest_multipart_reject)

    with pytest.raises(pytest.xfail.Exception, match="multipart digest is not operational"):
        mech_multipart.TestMultipartDigest().test_streaming_equals_single(
            _session(),
            _digest_entry(),
        )


def test_multipart_sign_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _sign_multipart_reject(*_args: Any, **_kwargs: Any) -> bytes:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(mech_multipart, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_multipart, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_multipart, "sign_multipart", _sign_multipart_reject)
    monkeypatch.setattr(mech_multipart, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="multipart sign is not operational"):
        mech_multipart.TestMultipartSign().test_multipart_sign_verify(
            _session(),
            _sign_entry(),
        )


def test_multipart_verify_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _verify_multipart_reject(*_args: Any, **_kwargs: Any) -> bool:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT",
            int(CKR_KEY_TYPE_INCONSISTENT),
        )

    monkeypatch.setattr(mech_multipart, "generate_key_for_sign", lambda *_args: (1, None))
    monkeypatch.setattr(mech_multipart, "make_mech_param_or_skip", lambda _entry: None)
    monkeypatch.setattr(mech_multipart, "sign_multipart", lambda *_args, **_kwargs: b"sig")
    monkeypatch.setattr(mech_multipart, "verify_multipart", _verify_multipart_reject)
    monkeypatch.setattr(mech_multipart, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="multipart verify is not operational"):
        mech_multipart.TestMultipartSign().test_multipart_sign_verify(
            _session(),
            _sign_entry(),
        )
