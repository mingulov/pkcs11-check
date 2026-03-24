"""Helpers for building exact raw PKCS#11 values with owned storage."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .core import CK_ATTRIBUTE, CK_BBOOL, CK_DATE, CK_MECHANISM, CK_ULONG, CK_VOID_PTR


@dataclass(frozen=True)
class LengthArg:
    """Explicit or native byte length for a packed value."""

    value: int
    explicit: bool = False

    @classmethod
    def native(cls, size: int) -> LengthArg:
        return cls(value=size, explicit=False)

    @classmethod
    def explicit_value(cls, size: int) -> LengthArg:
        return cls(value=size, explicit=True)


@dataclass(frozen=True)
class PointerArg:
    """Pointer plus owned storage that must stay alive for the call."""

    pointer: Any
    storage: Any = None

    @classmethod
    def null(cls) -> PointerArg:
        return cls(pointer=None)

    @classmethod
    def to_storage(cls, storage: Any) -> PointerArg:
        if storage is None:
            return cls.null()
        if isinstance(storage, ctypes.Structure):
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
        elif isinstance(storage, ctypes.Array):
            pointer = ctypes.cast(storage, CK_VOID_PTR)
        else:
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
        return cls(pointer=pointer, storage=storage)


@dataclass(frozen=True)
class PackedAttribute:
    """A CK_ATTRIBUTE with owned backing storage."""

    attribute: CK_ATTRIBUTE
    storage: Any


@dataclass(frozen=True)
class PackedMechanism:
    """A CK_MECHANISM with owned parameter storage."""

    ck: CK_MECHANISM
    storage: Any = None

    def byref(self) -> Any:
        return ctypes.byref(self.ck)


class TemplateArg:
    """Own a CK_ATTRIBUTE array and the buffers backing it."""

    def __init__(self, *attributes: PackedAttribute) -> None:
        self._attributes = list(attributes)
        self._storages = [attribute.storage for attribute in attributes]
        attr_type = CK_ATTRIBUTE * len(attributes)
        self.array = attr_type(*(attribute.attribute for attribute in attributes))
        self.count = len(attributes)
        self.ptr = self.array


MechanismArg = PackedMechanism
CKTemplate = TemplateArg


def explicit_length(size: int) -> LengthArg:
    return LengthArg.explicit_value(size)


def _native_length(storage: Any) -> LengthArg:
    return LengthArg.native(ctypes.sizeof(storage))


def _build_attribute(
    attr_type: int,
    pointer: PointerArg,
    length: LengthArg,
) -> PackedAttribute:
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=pointer.pointer,
            ulValueLen=length.value,
        ),
        storage=pointer.storage,
    )


def _coerce_length(length: LengthArg | None, storage: Any) -> LengthArg:
    if length is not None:
        return length
    return _native_length(storage)


def attr_bool(attr_type: int, value: bool, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_BBOOL(1 if value else 0)
    return _build_attribute(attr_type, PointerArg.to_storage(storage), _coerce_length(length, storage))


def attr_ulong(attr_type: int, value: int, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_ULONG(value)
    return _build_attribute(attr_type, PointerArg.to_storage(storage), _coerce_length(length, storage))


def attr_bytes(
    attr_type: int,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    return _build_attribute(attr_type, PointerArg.to_storage(storage), length or LengthArg(len(data)))


def attr_string(
    attr_type: int,
    value: str,
    *,
    encoding: str = "utf-8",
    length: LengthArg | None = None,
) -> PackedAttribute:
    return attr_bytes(attr_type, value.encode(encoding), length=length)


def attr_date(
    attr_type: int,
    year: str,
    month: str,
    day: str,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    storage = CK_DATE(year.encode("ascii"), month.encode("ascii"), day.encode("ascii"))
    return _build_attribute(attr_type, PointerArg.to_storage(storage), _coerce_length(length, storage))


def attr_array(
    attr_type: int,
    values: list[int] | tuple[int, ...],
    *,
    ctype: Any = CK_ULONG,
    length: LengthArg | None = None,
) -> PackedAttribute:
    storage = (ctype * len(values))(*values)
    return _build_attribute(attr_type, PointerArg.to_storage(storage), _coerce_length(length, storage))


def attr_template(
    attr_type: int,
    value: TemplateArg,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    native = LengthArg(value.count * ctypes.sizeof(CK_ATTRIBUTE))
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=ctypes.cast(value.array, CK_VOID_PTR),
            ulValueLen=(length or native).value,
        ),
        storage=value,
    )


def template(*attributes: PackedAttribute) -> TemplateArg:
    return TemplateArg(*attributes)


def mech_simple(mechanism_type: int) -> PackedMechanism:
    return PackedMechanism(CK_MECHANISM(mechanism_type, None, 0))


def mech_bytes(
    mechanism_type: int,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedMechanism:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    parameter_length = length.value if length is not None else len(data)
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, PointerArg.to_storage(storage).pointer, parameter_length),
        storage=storage,
    )
