"""Reachability pins for registry-driven permission negatives.

``_gen_claimed_false_secret_key`` must set up its key with the registry's
keygen mechanism (``config.keygen_mech``), not the operation mechanism
(``entry.mech_id``): for AES-XTS that is the difference between
``C_GenerateKey(CKM_AES_XTS_KEY_GEN)`` and a setup-time self-xfail on
``C_GenerateKey(CKM_AES_XTS)`` that never reaches the permission check.

Each row drives a real ``test_registry_*_without_flag`` node against a fake
token, asserting the captured keygen mechanism id, the template key type and
permission flags, and that the operation Init call is actually reached.
"""

from __future__ import annotations

import ctypes
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_AES,
    CKK_AES_XTS,
    CKK_BLAKE2B_512_HMAC,
    CKM_AES_CBC,
    CKM_AES_KEY_GEN,
    CKM_AES_XTS,
    CKM_AES_XTS_KEY_GEN,
    CKM_BLAKE2B_512_HMAC,
    CKM_BLAKE2B_512_KEY_GEN,
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_negative as neg
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import get_config


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    """Decode a captured template to {attribute id: raw value bytes}."""
    arr = ctypes.cast(tmpl, ctypes.POINTER(CK_ATTRIBUTE))
    decoded: dict[int, bytes] = {}
    for idx in range(int(count)):
        attr = arr[idx]
        decoded[int(attr.type)] = bytes(ctypes.string_at(attr.pValue, attr.ulValueLen))
    return decoded


def _decode_mech_id(mech: Any) -> int:
    return int(ctypes.cast(mech, ctypes.POINTER(CK_MECHANISM)).contents.mechanism)


class _PermissionCaptureRaw:
    """Fake token capturing keygen and Init calls for permission legs."""

    def __init__(
        self,
        *,
        keygen_rc: int = CKR_OK,
        init_rc: int = CKR_KEY_FUNCTION_NOT_PERMITTED,
    ) -> None:
        self._keygen_rc = int(keygen_rc)
        self._init_rc = int(init_rc)
        self.keygen_calls: list[tuple[int, dict[int, bytes]]] = []
        self.init_calls: list[tuple[str, int, int]] = []

    def C_GenerateKey(  # noqa: N802
        self,
        _session: int,
        mech: Any,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        self.keygen_calls.append((_decode_mech_id(mech), _decode_template(tmpl, count)))
        ctypes.cast(out, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = 77
        return self._keygen_rc

    def C_EncryptInit(  # noqa: N802
        self, _session: int, mech: Any, key: int
    ) -> int:
        self.init_calls.append(("C_EncryptInit", _decode_mech_id(mech), int(key)))
        return self._init_rc

    def C_SignInit(  # noqa: N802
        self, _session: int, mech: Any, key: int
    ) -> int:
        self.init_calls.append(("C_SignInit", _decode_mech_id(mech), int(key)))
        return self._init_rc


def _entry(mech_id: int, mech_name: str) -> MechEntry:
    config = get_config(mech_id)
    assert config is not None, f"no registry config for {mech_name}"
    return MechEntry(
        mech_id=mech_id,
        mech_name=mech_name,
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=config,
    )


def _permission_rs(raw: _PermissionCaptureRaw) -> SimpleNamespace:
    return SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: True)


def test_encrypt_without_flag_uses_keygen_mech_and_reaches_init(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES-XTS encrypt permission setup must generate via CKM_AES_XTS_KEY_GEN
    and reach C_EncryptInit -- not self-xfail inside C_GenerateKey(CKM_AES_XTS)."""
    raw = _PermissionCaptureRaw()
    monkeypatch.setattr(neg, "read_attributes", lambda *_args, **_kwargs: {CKA_ENCRYPT: False})
    monkeypatch.setattr(neg, "destroy_quietly", lambda *_args, **_kwargs: None)

    neg.TestMissingPermission().test_registry_encrypt_without_flag(
        _permission_rs(raw), _entry(CKM_AES_XTS, "AES_XTS")
    )

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(raw.keygen_calls) == 1
    keygen_mech, attrs = raw.keygen_calls[0]
    assert keygen_mech == int(CKM_AES_XTS_KEY_GEN)
    assert int.from_bytes(attrs[int(CKA_KEY_TYPE)], "little") == int(CKK_AES_XTS)
    assert attrs[int(CKA_ENCRYPT)] == b"\x00"
    assert attrs[int(CKA_DECRYPT)] == b"\x01"
    assert attrs[int(CKA_TOKEN)] == b"\x00"
    assert raw.init_calls == [("C_EncryptInit", int(CKM_AES_XTS), 77)]


def test_encrypt_without_flag_resolves_aes_cbc_generator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AES-CBC encrypt permission setup must generate via CKM_AES_KEY_GEN
    and reach C_EncryptInit."""
    raw = _PermissionCaptureRaw()
    monkeypatch.setattr(neg, "read_attributes", lambda *_args, **_kwargs: {CKA_ENCRYPT: False})
    monkeypatch.setattr(neg, "destroy_quietly", lambda *_args, **_kwargs: None)

    neg.TestMissingPermission().test_registry_encrypt_without_flag(
        _permission_rs(raw), _entry(CKM_AES_CBC, "AES_CBC")
    )

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(raw.keygen_calls) == 1
    keygen_mech, attrs = raw.keygen_calls[0]
    assert keygen_mech == int(CKM_AES_KEY_GEN)
    assert int.from_bytes(attrs[int(CKA_KEY_TYPE)], "little") == int(CKK_AES)
    assert attrs[int(CKA_ENCRYPT)] == b"\x00"
    assert raw.init_calls == [("C_EncryptInit", int(CKM_AES_CBC), 77)]


def test_sign_without_flag_resolves_blake2_generator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BLAKE2b-512 sign permission setup must generate via the typed BLAKE2
    keygen with the typed key type, and reach C_SignInit."""
    raw = _PermissionCaptureRaw()
    monkeypatch.setattr(neg, "read_attributes", lambda *_args, **_kwargs: {CKA_SIGN: False})
    monkeypatch.setattr(neg, "destroy_quietly", lambda *_args, **_kwargs: None)

    neg.TestMissingPermission().test_registry_sign_without_flag(
        _permission_rs(raw), _entry(CKM_BLAKE2B_512_HMAC, "BLAKE2B_512_HMAC")
    )

    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []
    assert len(raw.keygen_calls) == 1
    keygen_mech, attrs = raw.keygen_calls[0]
    assert keygen_mech == int(CKM_BLAKE2B_512_KEY_GEN)
    assert int.from_bytes(attrs[int(CKA_KEY_TYPE)], "little") == int(CKK_BLAKE2B_512_HMAC)
    assert attrs[int(CKA_SIGN)] == b"\x00"
    assert attrs[int(CKA_VERIFY)] == b"\x01"
    assert raw.init_calls == [("C_SignInit", int(CKM_BLAKE2B_512_HMAC), 77)]


def test_permission_setup_skips_when_generator_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permission setup skips (without calling C_GenerateKey) when the
    registry keygen mechanism is not advertised."""
    raw = _PermissionCaptureRaw()
    rs = SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda _name: False)
    monkeypatch.setattr(neg, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.skip.Exception):
        neg.TestMissingPermission().test_registry_encrypt_without_flag(
            rs, _entry(CKM_AES_XTS, "AES_XTS")
        )

    assert raw.keygen_calls == []
    assert raw.init_calls == []


def test_permission_setup_xfails_when_generator_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permission setup xfails not_operational (without reaching Init) when
    the generator cleanly refuses."""
    raw = _PermissionCaptureRaw(keygen_rc=CKR_FUNCTION_FAILED)
    monkeypatch.setattr(neg, "destroy_quietly", lambda *_args, **_kwargs: None)

    with pytest.raises(pytest.xfail.Exception):
        neg.TestMissingPermission().test_registry_encrypt_without_flag(
            _permission_rs(raw), _entry(CKM_AES_CBC, "AES_CBC")
        )

    assert len(raw.keygen_calls) == 1
    assert raw.init_calls == []
    (rec,) = C.get_records()
    assert rec.reason == "not_operational"
    assert rec.operation == "C_GenerateKey"
