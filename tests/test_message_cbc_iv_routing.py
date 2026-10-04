"""fw#41/fw#34: message-CBC legs must carry IVs, gate on flags, route via Next.

Runs the real TestMessageEncryptDecrypt methods against a fake session:
single-shot legs must pass an explicit IV at Init and per-message (#41),
decrypt legs must reuse the encrypt IV, legs must skip when the mechanism
lacks the CKF_MESSAGE_* flags (#34), and multipart legs must send data
through Next with non-AEAD AAD NULL/0 (#34). A provider refusing Init with
CKR_ARGUMENTS_BAD must still fail loudly (provider signal preserved).
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CKF_END_OF_MESSAGE,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MULTI_MESSAGE,
    CKM_AES_CBC,
    CKR_ARGUMENTS_BAD,
    CKR_OK,
)
from pkcs11_check.testcases import test_message_crypto
from tests._skip_assert import assert_skips

_CT_FIXTURE = bytes((i + 1) % 256 for i in range(32))
_PT_32 = b"A" * 32
_PT_XVERIFY = b"cross-verify test data padding!!"


def _mech_params(mech_ptr: Any) -> bytes | None:
    """Read (pParameter, ulParameterLen) from a byref(CK_MECHANISM)."""
    ck = mech_ptr._obj
    assert isinstance(ck, CK_MECHANISM)
    assert int(ck.mechanism) == int(CKM_AES_CBC)
    if not ck.pParameter:
        return None
    return bytes(ctypes.string_at(ck.pParameter, int(ck.ulParameterLen)))


def _buf_bytes(buf: Any, length: int) -> bytes | None:
    if buf is None:
        return None
    return bytes(buf[:length])


def _fill(buf: Any, out_len: Any, data: bytes) -> None:
    n = min(len(data), len(buf))
    for i in range(n):
        buf[i] = data[i]
    out_len._obj.value = n


class _FakeMessageRaw:
    """Fake token recording IV placement across the message-CBC legs."""

    def __init__(self, *, init_rv: int = int(CKR_OK)) -> None:
        self._init_rv = init_rv
        self.init_mechs: list[bytes | None] = []
        self.msg_params: list[bytes | None] = []
        self.msg_aads: list[bytes | None] = []
        self.begins: list[tuple[bytes | None, bytes | None]] = []
        self.nexts: list[tuple[bytes | None, bytes]] = []
        self.next_flags: list[int] = []
        self.finals: list[str] = []

    def C_GenerateKey(self, _sh: int, _mech: Any, _tmpl: Any, _n: int, out: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        out._obj.value = 5
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, _h: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the helper calls.
        return int(CKR_OK)

    def _init(self, _sh: int, mech: Any, _key: int) -> int:
        self.init_mechs.append(_mech_params(mech))
        return self._init_rv

    def C_MessageEncryptInit(self, sh: int, mech: Any, key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return self._init(sh, mech, key)

    def C_MessageDecryptInit(self, sh: int, mech: Any, key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return self._init(sh, mech, key)

    def _message(self, out_fill: bytes, params: tuple[Any, ...]) -> int:
        (_sh, p, pl, aad, al, _data, _dl, out, out_len) = params
        self.msg_params.append(_buf_bytes(p, pl))
        self.msg_aads.append(_buf_bytes(aad, al))
        if out is None:
            out_len._obj.value = len(out_fill)
        else:
            _fill(out, out_len, out_fill)
        return int(CKR_OK)

    def C_EncryptMessage(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return self._message(_CT_FIXTURE, args)

    def C_DecryptMessage(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        return self._message(_PT_32, args)

    def _begin(self, _sh: int, p: Any, pl: int, aad: Any, al: int) -> int:
        self.begins.append((_buf_bytes(p, pl), _buf_bytes(aad, al)))
        return int(CKR_OK)

    def C_EncryptMessageBegin(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        return self._begin(*args)

    def C_DecryptMessageBegin(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        return self._begin(*args)

    def _next(self, out_fill: bytes, args: tuple[Any, ...]) -> int:
        (_sh, p, pl, data, dl, out, out_len, flags) = args
        self.nexts.append((_buf_bytes(p, pl), bytes(_buf_bytes(data, dl) or b"")))
        self.next_flags.append(int(flags))
        if out is None:
            out_len._obj.value = len(out_fill)
        else:
            _fill(out, out_len, out_fill)
        return int(CKR_OK)

    def C_EncryptMessageNext(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        return self._next(_CT_FIXTURE, args)

    def C_DecryptMessageNext(self, *args: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        return self._next(_PT_32, args)

    def C_MessageEncryptFinal(self, _sh: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        self.finals.append("enc")
        return int(CKR_OK)

    def C_MessageDecryptFinal(self, _sh: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the test calls.
        self.finals.append("dec")
        return int(CKR_OK)

    def C_DecryptInit(self, _sh: int, mech: Any, _key: int) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        self.init_mechs.append(_mech_params(mech))
        return int(CKR_OK)

    def C_Decrypt(self, _sh: int, _data: Any, _dl: int, out: Any, out_len: Any) -> int:  # noqa: N802
        # Must match the PKCS#11 entry-point name the recipe calls.
        if out is None:
            out_len._obj.value = len(_PT_XVERIFY)
        else:
            _fill(out, out_len, _PT_XVERIFY)
        return int(CKR_OK)


class _FakeRs:
    def __init__(self, raw: _FakeMessageRaw, flags: set[int] | None = None) -> None:
        self.raw = raw
        self.sh = 1
        self._flags = (
            flags
            if flags is not None
            else {int(CKF_MESSAGE_ENCRYPT), int(CKF_MESSAGE_DECRYPT), int(CKF_MULTI_MESSAGE)}
        )

    def has_mechanism(self, _name: str) -> bool:
        return True

    def has_mechanism_flag(self, _mechanism: str, flag: int) -> bool:
        return int(flag) in self._flags


def _run(method: str, rs: _FakeRs) -> None:
    cls = test_message_crypto.TestMessageEncryptDecrypt()
    getattr(cls, method)(rs)


def test_single_shot_carries_iv_at_init_and_per_message() -> None:
    """Encrypt Init mech and per-message params must both carry the IV (#41)."""
    raw = _FakeMessageRaw()
    _run("test_message_encrypt_single", _FakeRs(raw))
    assert len(raw.init_mechs) == 1
    iv = raw.init_mechs[0]
    assert iv is not None and len(iv) == 16
    assert raw.msg_params == [iv, iv]
    assert raw.msg_aads == [None, None]
    assert raw.finals == ["enc"]


def test_decrypt_reuses_encrypt_iv() -> None:
    """Decrypt legs must reuse the encrypt IV at both Inits (#41)."""
    raw = _FakeMessageRaw()
    _run("test_message_decrypt_single", _FakeRs(raw))
    assert len(raw.init_mechs) == 2
    iv = raw.init_mechs[0]
    assert iv is not None and len(iv) == 16
    assert raw.init_mechs[1] == iv
    assert raw.msg_params == [iv, iv, iv, iv]
    assert raw.finals == ["enc", "dec"]


def test_roundtrip_classic_decrypt_uses_message_iv() -> None:
    """Cross-verify classic decrypt must use the message IV (#41)."""
    raw = _FakeMessageRaw()
    _run("test_message_encrypt_decrypt_roundtrip", _FakeRs(raw))
    assert len(raw.init_mechs) == 2
    iv = raw.init_mechs[0]
    assert iv is not None and len(iv) == 16
    assert raw.init_mechs[1] == iv
    assert raw.finals == ["enc"]


def test_legs_skip_without_message_flags() -> None:
    """Legs must skip (naming the flag) when message flags are absent (#34)."""
    cases = [
        ("test_message_encrypt_single", set(), "CKF_MESSAGE_ENCRYPT"),
        ("test_message_decrypt_single", set(), "CKF_MESSAGE_ENCRYPT"),
        (
            "test_message_decrypt_single",
            {int(CKF_MESSAGE_ENCRYPT)},
            "CKF_MESSAGE_DECRYPT",
        ),
        (
            "test_message_encrypt_multipart",
            {int(CKF_MESSAGE_ENCRYPT)},
            "CKF_MULTI_MESSAGE",
        ),
        (
            "test_message_decrypt_multipart",
            {int(CKF_MESSAGE_ENCRYPT), int(CKF_MESSAGE_DECRYPT)},
            "CKF_MULTI_MESSAGE",
        ),
        ("test_message_encrypt_decrypt_roundtrip", set(), "CKF_MESSAGE_ENCRYPT"),
    ]
    for method, flags, flag_name in cases:
        raw = _FakeMessageRaw()
        cls = test_message_crypto.TestMessageEncryptDecrypt()
        assert_skips(getattr(cls, method), _FakeRs(raw, flags), match=flag_name)
        assert raw.init_mechs == [], method


def test_multipart_encrypt_routes_data_through_next() -> None:
    """Multipart encrypt: IV at Init/Begin, data via Next, AAD NULL/0 (#34)."""
    raw = _FakeMessageRaw()
    _run("test_message_encrypt_multipart", _FakeRs(raw))
    assert len(raw.init_mechs) == 1
    iv = raw.init_mechs[0]
    assert iv is not None and len(iv) == 16
    assert raw.begins == [(iv, None)]
    assert len(raw.nexts) == 2
    for _param, data in raw.nexts:
        assert data == _PT_32
    assert raw.finals == ["enc"]


def test_multipart_decrypt_routes_data_through_next() -> None:
    """Multipart decrypt: IV at Init/Begin, data via Next, AAD NULL/0 (#34)."""
    raw = _FakeMessageRaw()
    _run("test_message_decrypt_multipart", _FakeRs(raw))
    assert len(raw.init_mechs) == 2
    iv = raw.init_mechs[0]
    assert iv is not None and len(iv) == 16
    assert raw.init_mechs[1] == iv
    assert raw.begins == [(iv, None)]
    assert len(raw.nexts) == 2
    for _param, data in raw.nexts:
        assert data == _CT_FIXTURE
    assert raw.finals == ["enc", "dec"]


def test_multipart_next_carries_end_of_message_flag() -> None:
    """Multipart legs pass CKF_END_OF_MESSAGE on every Next call (#34)."""
    for method in ("test_message_encrypt_multipart", "test_message_decrypt_multipart"):
        raw = _FakeMessageRaw()
        _run(method, _FakeRs(raw))
        assert raw.next_flags == [int(CKF_END_OF_MESSAGE)] * len(raw.nexts), method
        assert len(raw.nexts) == 2, method


def test_init_refusal_still_fails_loudly() -> None:
    """A 0x7 Init refusal on valid input stays a failure, never hidden (#41)."""
    raw = _FakeMessageRaw(init_rv=int(CKR_ARGUMENTS_BAD))
    try:
        _run("test_message_encrypt_single", _FakeRs(raw))
    except AssertionError as exc:
        assert "CKR_ARGUMENTS_BAD" in str(exc)
    except pytest.skip.Exception as exc:
        pytest.fail(f"expected a loud failure, got skip instead: {exc}")
    else:
        pytest.fail("expected AssertionError, method returned normally")
