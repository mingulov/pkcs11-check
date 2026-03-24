"""Helpers for building CK_MECHANISM values with owned parameter storage."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .core import CK_MECHANISM, CK_VOID_PTR


@dataclass(frozen=True)
class PackedMechanism:
    """A CK_MECHANISM with owned parameter storage."""

    ck: CK_MECHANISM
    storage: Any = None

    def byref(self) -> Any:
        return ctypes.byref(self.ck)


def mech_simple(mechanism_type: int) -> PackedMechanism:
    return PackedMechanism(CK_MECHANISM(mechanism_type, None, 0))


def mech_bytes(mechanism_type: int, value: bytes | bytearray | memoryview) -> PackedMechanism:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    return PackedMechanism(
        CK_MECHANISM(
            mechanism_type,
            ctypes.cast(storage, CK_VOID_PTR),
            len(data),
        ),
        storage=storage,
    )
