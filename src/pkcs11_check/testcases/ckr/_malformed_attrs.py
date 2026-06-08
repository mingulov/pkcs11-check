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
