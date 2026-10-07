"""Selector-argument guards for the C_AsyncGetID probes (fw#35).

The no-operation probe must pass a valid NUL-terminated function name with a
scalar operation-id output; the empty selector is a distinct
argument-validation case. A zero-filled 256-byte buffer is an empty string,
not ``C_Digest``.
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_OPERATION_NOT_INITIALIZED,
    CK_C_AsyncGetID,
)
from pkcs11_check.testcases._probes import ckr_v32_raw
from pkcs11_check.testcases._probes.session import ProbeContext


class _FakeRaw:
    """Refuse empty selectors; report no-job for valid ones (the fw#35 oracle).

    ``C_AsyncGetID`` is the real entry-point prototype, so a selector the
    declared ``CK_UTF8CHAR_PTR`` rejects fails here exactly as in production
    (fw#49: a plain-Python fake hid the ``create_string_buffer`` mismatch).
    """

    def __init__(self) -> None:
        self.names: list[bytes] = []
        self.id_objs: list[Any] = []
        # Must match the PKCS#11 entry-point name the probe calls.
        self.C_AsyncGetID = CK_C_AsyncGetID(self._get_id_impl)

    def _get_id_impl(self, sh: int, name: Any, pul_id: Any) -> int:
        del sh
        raw = ctypes.cast(name, ctypes.c_char_p).value or b""
        self.names.append(bytes(raw))
        self.id_objs.append(pul_id.contents)
        if not raw:
            return int(CKR_ARGUMENTS_BAD)
        return int(CKR_OPERATION_NOT_INITIALIZED)


def _ctx(raw: _FakeRaw) -> Any:
    return ProbeContext(raw=raw, sh=1, slot_id=0, cleanup=lambda: None, module_path="fake")


def test_no_operation_sends_valid_selector(capsys: Any) -> None:
    """The no-op probe must name a real function with scalar id output (fw#35)."""
    raw = _FakeRaw()
    ckr_v32_raw._async_get_id_no_operation(_ctx(raw))
    assert raw.names == [b"C_Digest"]
    assert len(raw.id_objs) == 1
    assert isinstance(raw.id_objs[0], ctypes.c_ulong)
    out = capsys.readouterr().out
    assert "RESULT:C_AsyncGetID:CKR:0x00000091" in out
    assert "OK:C_AsyncGetID" in out


def test_empty_selector_is_distinct_case(capsys: Any) -> None:
    """The empty selector keeps its own argument-validation probe (fw#35)."""
    raw = _FakeRaw()
    ckr_v32_raw._async_get_id_empty_selector(_ctx(raw))
    assert raw.names == [b""]
    assert len(raw.id_objs) == 1
    assert isinstance(raw.id_objs[0], ctypes.c_ulong)
    out = capsys.readouterr().out
    assert "RESULT:C_AsyncGetID.empty_selector:CKR:0x00000007" in out
    assert "OK:C_AsyncGetID_empty_selector" in out
