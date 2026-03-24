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
    kind: str = "null"
    origin: str = "unknown"
    native_length: int | None = None
    element_count: int | None = None
    element_type: str | None = None

    @classmethod
    def null(cls, *, origin: str = "unknown") -> PointerArg:
        return cls(pointer=None, origin=origin)

    @classmethod
    def to_storage(
        cls,
        storage: Any,
        *,
        origin: str = "unknown",
        native_length: int | None = None,
    ) -> PointerArg:
        if storage is None:
            return cls.null(origin=origin)
        if isinstance(storage, ctypes.Structure):
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
            kind = "struct"
            resolved_native_length = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        elif isinstance(storage, ctypes.Array):
            pointer = ctypes.cast(storage, CK_VOID_PTR)
            item_type = getattr(type(storage), "_type_", None)
            kind = "bytes" if item_type in (ctypes.c_char, ctypes.c_byte, ctypes.c_ubyte) else "array"
            resolved_native_length = ctypes.sizeof(storage)
            element_count = len(storage)
            element_type = getattr(item_type, "__name__", type(item_type).__name__ if item_type else None)
        else:
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
            kind = "scalar"
            resolved_native_length = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        return cls(
            pointer=pointer,
            storage=storage,
            kind=kind,
            origin=origin,
            native_length=resolved_native_length if native_length is None else native_length,
            element_count=element_count,
            element_type=element_type,
        )


@dataclass(frozen=True)
class PackedAttribute:
    """A CK_ATTRIBUTE with owned backing storage."""

    attribute: CK_ATTRIBUTE
    storage: Any
    pointer_arg: PointerArg
    length_arg: LengthArg


@dataclass(frozen=True)
class PackedMechanism:
    """A CK_MECHANISM with owned parameter storage."""

    ck: CK_MECHANISM
    storage: Any = None
    pointer_arg: PointerArg = PointerArg.null()
    length_arg: LengthArg = LengthArg.explicit_value(0)

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
        self.actual_count = len(attributes)
        self.ptr = self.array

    @property
    def attributes(self) -> tuple[PackedAttribute, ...]:
        return tuple(self._attributes)


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
        pointer_arg=pointer,
        length_arg=length,
    )


def _coerce_length(length: LengthArg | None, storage: Any) -> LengthArg:
    if length is not None:
        return length
    return _native_length(storage)


def attr_bool(attr_type: int, value: bool, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_BBOOL(1 if value else 0)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bool"),
        _coerce_length(length, storage),
    )


def attr_ulong(attr_type: int, value: int, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_ULONG(value)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_ulong"),
        _coerce_length(length, storage),
    )


def attr_bytes(
    attr_type: int,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bytes", native_length=len(data)),
        length or LengthArg.native(len(data)),
    )


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
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_date"),
        _coerce_length(length, storage),
    )


def attr_array(
    attr_type: int,
    values: list[int] | tuple[int, ...],
    *,
    ctype: Any = CK_ULONG,
    length: LengthArg | None = None,
) -> PackedAttribute:
    storage = (ctype * len(values))(*values)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_array"),
        _coerce_length(length, storage),
    )


def attr_template(
    attr_type: int,
    value: TemplateArg,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    native = LengthArg(value.count * ctypes.sizeof(CK_ATTRIBUTE))
    pointer_arg = PointerArg(
        pointer=ctypes.cast(value.array, CK_VOID_PTR),
        storage=value,
        kind="array",
        origin="attr_template",
        native_length=value.actual_count * ctypes.sizeof(CK_ATTRIBUTE),
        element_count=value.actual_count,
        element_type="CK_ATTRIBUTE",
    )
    chosen_length = length or native
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=pointer_arg.pointer,
            ulValueLen=chosen_length.value,
        ),
        storage=value,
        pointer_arg=pointer_arg,
        length_arg=chosen_length,
    )


def template(*attributes: PackedAttribute) -> TemplateArg:
    return TemplateArg(*attributes)


def mech_simple(mechanism_type: int) -> PackedMechanism:
    pointer_arg = PointerArg.null(origin="mech_simple")
    length_arg = LengthArg.explicit_value(0)
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, None, 0),
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )


def mech_bytes(
    mechanism_type: int,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedMechanism:
    data = bytes(value)
    storage = ctypes.create_string_buffer(data)
    pointer_arg = PointerArg.to_storage(storage, origin="mech_bytes", native_length=len(data))
    length_arg = length if length is not None else LengthArg.native(len(data))
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=storage,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )
