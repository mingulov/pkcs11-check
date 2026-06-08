"""Helpers for building malformed CK_ATTRIBUTE templates in CKR tests."""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.types_std import CK_ULONG


def make_bool_attr_overlong(tmpl: Any, index: int, value: int = 0) -> CK_ULONG:
    """Replace a CK_BBOOL template value with CK_ULONG-sized storage."""
    storage = CK_ULONG(value)
    tmpl.array[index].pValue = ctypes.cast(ctypes.pointer(storage), ctypes.c_void_p)
    tmpl.array[index].ulValueLen = ctypes.sizeof(storage)
    return storage


def make_ulong_attr_with_length(tmpl: Any, index: int, value: int, length: int) -> Any:
    """Replace a CK_ULONG template value with storage of an explicit byte length."""
    storage = (ctypes.c_ubyte * length)()
    source = CK_ULONG(value)
    copy_len = min(length, ctypes.sizeof(source))
    if copy_len:
        ctypes.memmove(storage, ctypes.byref(source), copy_len)
    tmpl.array[index].pValue = ctypes.cast(storage, ctypes.c_void_p)
    tmpl.array[index].ulValueLen = length
    return storage
