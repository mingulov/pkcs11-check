"""Helpers for building CK_ATTRIBUTE arrays without policy or defaults."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .core import CK_ATTRIBUTE, CK_BBOOL, CK_ULONG, CK_VOID_PTR


@dataclass(frozen=True)
class PackedAttribute:
    """A CK_ATTRIBUTE with owned backing storage."""

    attribute: CK_ATTRIBUTE
    storage: Any


class CKTemplate:
    """Own a CK_ATTRIBUTE array and the buffers backing it."""

    def __init__(self, *attributes: PackedAttribute) -> None:
        self._attributes = list(attributes)
        self._storages = [attribute.storage for attribute in attributes]
        attr_type = CK_ATTRIBUTE * len(attributes)
        self.array = attr_type(*(attribute.attribute for attribute in attributes))
        self.count = len(attributes)
        self.ptr = self.array


def attr_bool(attr_type: int, value: bool) -> PackedAttribute:
    storage = CK_BBOOL(1 if value else 0)
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR),
            ulValueLen=ctypes.sizeof(storage),
        ),
        storage=storage,
    )


def attr_ulong(attr_type: int, value: int) -> PackedAttribute:
    storage = CK_ULONG(value)
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR),
            ulValueLen=ctypes.sizeof(storage),
        ),
        storage=storage,
    )


def attr_bytes(attr_type: int, value: bytes | bytearray | memoryview) -> PackedAttribute:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=ctypes.cast(storage, CK_VOID_PTR),
            ulValueLen=len(data),
        ),
        storage=storage,
    )
