"""Contract tests for 1-byte recovery verdicts (#54.3)."""

from __future__ import annotations

import ctypes
import hashlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import test_misc_kdf as kdf


def test_recovery_refused_passes() -> None:
    kdf._judge_byte_recovery(
        derive_rv=int(CKR_TEMPLATE_INCONSISTENT),
        recovered=False,
        control_ok=True,
        label="sealed",
    )
    assert classification.get_records() == []


def test_recovery_capability_refused_passes() -> None:
    # Refusal needs no oracle: the chain is blocked either way.
    kdf._judge_byte_recovery(
        derive_rv=int(CKR_MECHANISM_INVALID),
        recovered=False,
        control_ok=False,
        label="sealed",
    )
    assert classification.get_records() == []


def test_recovery_recovered_fails() -> None:
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=True, control_ok=True, label="sealed"
        )


def test_recovery_recovered_control_less_fails() -> None:
    # A match is self-evident: no oracle needed to interpret it.
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=True, control_ok=False, label="sealed"
        )


def test_recovery_unproven_xfails_with_control() -> None:
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=False, control_ok=True, label="sealed"
        )


def test_recovery_unproven_skips_without_control() -> None:
    with pytest.raises(Skipped):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=False, control_ok=False, label="sealed"
        )


def test_recovery_blocked_xfails_with_control() -> None:
    with pytest.raises(XFailed):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=None, control_ok=True, label="sealed"
        )


def test_recovery_blocked_skips_without_control() -> None:
    with pytest.raises(Skipped):
        kdf._judge_byte_recovery(
            derive_rv=int(CKR_OK), recovered=None, control_ok=False, label="sealed"
        )


def test_recovery_undefined_rv_fails() -> None:
    with pytest.raises(Failed):
        kdf._judge_byte_recovery(derive_rv=0xDEAD, recovered=False, control_ok=True, label="sealed")


def _tval(tmpl: Any, count: int, attr: int) -> bytes:
    for i in range(int(count)):
        if int(tmpl[i].type) == int(attr):
            length = int(tmpl[i].ulValueLen)
            if tmpl[i].pValue is None or length == 0:
                return b""
            return bytes(ctypes.string_at(tmpl[i].pValue, length))
    return b""


class _FakeKdfRaw:
    """Byte-exact KDF fake: imports, scripted derives, SHA-256 digests."""

    def __init__(self, derive_fn: Callable[[bytes], bytes]) -> None:
        self._derive_fn = derive_fn
        self.objects: dict[int, bytes] = {}
        self.sealed: dict[int, bool] = {}
        self.refuse_sealed = False
        self._next = 0
        self._pending: bytes | None = None

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, handle_ptr: Any) -> int:  # noqa: N802
        self._next += 1
        self.objects[self._next] = _tval(tmpl, count, int(CKA_VALUE))
        self.sealed[self._next] = _tval(tmpl, count, int(CKA_SENSITIVE)) == b"\x01"
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, _mech: Any, base: int, _tmpl: Any, _count: int, handle_ptr: Any
    ) -> int:
        if self.refuse_sealed and self.sealed.get(int(base), False):
            return int(CKR_TEMPLATE_INCONSISTENT)
        self._next += 1
        self.objects[self._next] = self._derive_fn(self.objects[int(base)])
        self.sealed[self._next] = self.sealed.get(int(base), False)
        ctypes.cast(handle_ptr, ctypes.POINTER(CK_OBJECT_HANDLE)).contents.value = self._next
        return int(CKR_OK)

    def C_DigestInit(self, _sh: int, _mech: Any) -> int:  # noqa: N802
        self._pending = None
        return int(CKR_OK)

    def C_DigestKey(self, _sh: int, key: int) -> int:  # noqa: N802
        self._pending = self.objects[int(key)]
        return int(CKR_OK)

    def C_DigestFinal(self, _sh: int, buf: Any, len_ptr: Any) -> int:  # noqa: N802
        digest = hashlib.sha256(self._pending or b"").digest()
        out_len = ctypes.cast(len_ptr, ctypes.POINTER(CK_ULONG)).contents
        if buf is None:
            out_len.value = len(digest)
            return int(CKR_OK)
        ctypes.memmove(buf, digest, len(digest))
        out_len.value = len(digest)
        return int(CKR_OK)

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.objects.pop(int(handle), None)
        return int(CKR_OK)


def _kdf_rs(derive_fn: Callable[[bytes], bytes], *, refuse_sealed: bool = False) -> Any:
    fake = _FakeKdfRaw(derive_fn)
    fake.refuse_sealed = refuse_sealed
    return SimpleNamespace(raw=fake, sh=7)


def test_recovery_end_to_end_extract_finds_recovery() -> None:
    rs = _kdf_rs(lambda base: base[:1])
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )


def test_recovery_end_to_end_xor_full_finds_recovery() -> None:
    data = kdf._RECOVERY_XOR_FULL_DATA
    rs = _kdf_rs(lambda base: bytes([base[0] ^ data[0]]))
    with pytest.raises(Failed):
        kdf._run_byte_recovery_case(rs, shape="xor_full", label="t")
    assert any(
        "recovered through 1-byte child" in rec.summary for rec in classification.get_records()
    )


def test_recovery_end_to_end_refused_passes() -> None:
    rs = _kdf_rs(lambda base: base[:1], refuse_sealed=True)
    kdf._run_byte_recovery_case(rs, shape="extract", label="t")
    assert classification.get_records() == []
