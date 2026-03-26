"""Helpers for building exact raw PKCS#11 values with owned storage."""

from __future__ import annotations

import ctypes
import datetime
from dataclasses import dataclass
from typing import Any

from .types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_DATE,
    CK_MECHANISM,
    CK_ULONG,
    CK_VOID_PTR,
    CKA,
    CKM,
)


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
    storage_size: int | None = None
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
            storage_size = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        elif isinstance(storage, ctypes.Array):
            pointer = ctypes.cast(storage, CK_VOID_PTR)
            item_type = getattr(type(storage), "_type_", None)
            byte_types = (ctypes.c_char, ctypes.c_byte, ctypes.c_ubyte)
            kind = "bytes" if item_type in byte_types else "array"
            resolved_native_length = ctypes.sizeof(storage)
            storage_size = ctypes.sizeof(storage)
            element_count = len(storage)
            fallback = type(item_type).__name__ if item_type else None
            element_type = getattr(item_type, "__name__", fallback)
        else:
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
            kind = "scalar"
            resolved_native_length = ctypes.sizeof(storage)
            storage_size = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        return cls(
            pointer=pointer,
            storage=storage,
            kind=kind,
            origin=origin,
            native_length=resolved_native_length if native_length is None else native_length,
            storage_size=storage_size,
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


class PackedMechanism:
    """A CK_MECHANISM with owned parameter storage.

    The params attribute holds a typed reference to the mechanism parameter struct
    (e.g. CK_AES_GCM_PARAMS) for struct-based packers. For mech_simple/mech_bytes
    it is None. Dynamic attributes (e.g. _iv_buf) keep buffer lifetime.
    """

    def __init__(
        self,
        ck: CK_MECHANISM,
        storage: Any = None,
        pointer_arg: PointerArg | None = None,
        length_arg: LengthArg | None = None,
        params: Any = None,
    ) -> None:
        self.ck = ck
        self.storage = storage
        self.pointer_arg = pointer_arg or PointerArg.null()
        self.length_arg = length_arg or LengthArg.explicit_value(0)
        self.params = params
        self._keepalive: list[Any] = []

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


def template_ptr_count(tmpl: TemplateArg | None) -> tuple[Any, int]:
    """Return (ptr, count) for an optional template, (None, 0) if None."""
    if tmpl is None:
        return None, 0
    return tmpl.ptr, tmpl.count


def _exact_byte_storage(data: bytes) -> Any:
    return ctypes.create_string_buffer(data, len(data))


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


def attr_bool(attr_type: CKA, value: bool, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_BBOOL(1 if value else 0)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bool"),
        _coerce_length(length, storage),
    )


def attr_ulong(attr_type: CKA, value: int, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_ULONG(value)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_ulong"),
        _coerce_length(length, storage),
    )


def attr_bytes(
    attr_type: CKA,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    data = bytes(value)
    storage = _exact_byte_storage(data)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bytes", native_length=len(data)),
        length or LengthArg.native(len(data)),
    )


def attr_string(
    attr_type: CKA,
    value: str,
    *,
    encoding: str = "utf-8",
    length: LengthArg | None = None,
) -> PackedAttribute:
    return attr_bytes(attr_type, value.encode(encoding), length=length)


def attr_date(
    attr_type: CKA,
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
    attr_type: CKA,
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
    attr_type: CKA,
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


def attr_auto(attr_type: int, value: Any) -> PackedAttribute:
    """Pack an attribute using ATTR_VALUE_TYPES for spec-correct wire type.

    Supports all PKCS#11 attribute types:
    - 'bool': CK_BBOOL (accepts bool or int)
    - 'ulong': CK_ULONG (accepts int)
    - 'str': RFC2279 UTF-8 (accepts str or bytes)
    - 'bytes': raw byte array (accepts bytes, bytearray)
    - 'date': CK_DATE 8-byte YYYYMMDD (accepts datetime.date or str 'YYYYMMDD')
    - 'ulong_array': CK_ULONG[] (accepts list[int] or tuple[int, ...])
    - 'template': CK_ATTRIBUTE[] — not supported for auto-packing, use pack.template() directly

    For deliberate mispacking (fault tests), use attr_bool/attr_ulong/attr_bytes directly.
    """
    from .attr_metadata import ATTR_VALUE_TYPES

    vtype = ATTR_VALUE_TYPES.get(attr_type)

    if vtype == "bool":
        return attr_bool(attr_type, bool(value))
    elif vtype == "ulong":
        return attr_ulong(attr_type, int(value))
    elif vtype == "str":
        if isinstance(value, bytes):
            return attr_bytes(attr_type, value)
        return attr_bytes(attr_type, str(value).encode("utf-8"))
    elif vtype == "bytes":
        if isinstance(value, str):
            return attr_bytes(attr_type, value.encode("utf-8"))
        if isinstance(value, (bytes, bytearray, memoryview)):
            return attr_bytes(attr_type, bytes(value))
        raise TypeError(
            f"attr_auto: 'bytes' type expects bytes/bytearray, got {type(value).__name__} "
            f"for attr {attr_type:#x}"
        )
    elif vtype == "date":
        # CK_DATE is 8 bytes: YYYYMMDD in ASCII
        if isinstance(value, datetime.date):
            date_bytes = value.strftime("%Y%m%d").encode("ascii")
        elif isinstance(value, str):
            # Validate format
            if len(value) != 8 or not value.isdigit():
                raise ValueError(f"attr_auto: 'date' string must be 'YYYYMMDD', got {value!r}")
            date_bytes = value.encode("ascii")
        elif isinstance(value, bytes) and len(value) == 8:
            date_bytes = value
        else:
            raise TypeError(
                f"attr_auto: 'date' type expects datetime.date, 'YYYYMMDD' str, or 8 bytes, "
                f"got {type(value).__name__} for attr {attr_type:#x}"
            )
        return attr_bytes(attr_type, date_bytes)
    elif vtype == "ulong_array":
        # Pack list of ints as CK_ULONG array
        if not isinstance(value, (list, tuple)):
            raise TypeError(
                f"attr_auto: 'ulong_array' type expects list[int] or tuple[int, ...], "
                f"got {type(value).__name__} for attr {attr_type:#x}"
            )
        arr = (CK_ULONG * len(value))(*value)
        return attr_bytes(attr_type, bytes(arr))
    elif vtype == "template":
        raise TypeError(
            f"attr_auto: 'template' attributes (attr {attr_type:#x}) cannot be auto-packed. "
            f"Use pack.template() and pack.attr_template() directly."
        )
    elif vtype is None:
        # Unknown attribute not in ATTR_VALUE_TYPES — fall back to Python type inference
        # but only for vendor/unknown attrs
        if isinstance(value, bool):
            return attr_bool(attr_type, value)
        elif isinstance(value, int):
            return attr_ulong(attr_type, value)
        elif isinstance(value, str):
            return attr_bytes(attr_type, value.encode("utf-8"))
        elif isinstance(value, (bytes, bytearray)):
            return attr_bytes(attr_type, value)
        raise TypeError(
            f"attr_auto: unknown attr {attr_type:#x} not in ATTR_VALUE_TYPES, "
            f"and cannot infer type from {type(value).__name__}"
        )
    else:
        raise TypeError(f"attr_auto: unsupported value type {vtype!r} for attr {attr_type:#x}")


def template_from_dict(attrs: dict[int, Any]) -> TemplateArg:
    """Build a template from {CKA_*: value} dict with spec-correct type packing."""
    return template(*[attr_auto(k, v) for k, v in attrs.items()])


def mech_simple(mechanism_type: CKM) -> PackedMechanism:
    pointer_arg = PointerArg.null(origin="mech_simple")
    length_arg = LengthArg.explicit_value(0)
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, None, 0),
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )


def mech_bytes(
    mechanism_type: CKM,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedMechanism:
    data = bytes(value)
    storage = _exact_byte_storage(data)
    pointer_arg = PointerArg.to_storage(storage, origin="mech_bytes", native_length=len(data))
    length_arg = length if length is not None else LengthArg.native(len(data))
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=storage,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )


def _pack_bytes(
    data: bytes | None,
    keepalive: list[Any],
) -> tuple[Any, int]:
    """Pack optional bytes into a ctypes buffer with lifetime tracking.

    Returns (void_ptr_or_None, length). Appends buffer to keepalive.
    """
    if data is None:
        return None, 0
    buf = (ctypes.c_ubyte * len(data))(*data)
    keepalive.append(buf)
    return ctypes.cast(buf, CK_VOID_PTR), len(data)


def _mech_struct(
    mechanism_type: CKM,
    params: ctypes.Structure,
    origin: str,
    keepalive: list[Any] | None = None,
) -> PackedMechanism:
    """Build a PackedMechanism from a pre-populated ctypes struct."""
    pointer_arg = PointerArg.to_storage(params, origin=origin)
    length_arg = LengthArg.native(ctypes.sizeof(params))
    result = PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    if keepalive:
        result._keepalive.extend(keepalive)
    return result


# Re-export mechanism packers for backward compatibility.
# These are defined in pack_mechanisms.py but historically imported from pack.
from .pack_mechanisms import (  # noqa: E402, F401
    mech_cbc_pad,
    mech_ccm,
    mech_chacha20,
    mech_chacha20_poly1305,
    mech_ctr,
    mech_ecdh,
    mech_eddsa,
    mech_gcm,
    mech_hkdf,
    mech_oaep,
    mech_pbkdf2,
    mech_pss,
    mech_ssl3_key_mat,
    mech_ssl3_master_key_derive,
    mech_string_data,
    mech_tls12_extended_master_key_derive,
    mech_tls12_key_mat,
    mech_tls12_master_key_derive,
    mech_tls_kdf,
    mech_tls_mac,
    mech_tls_prf,
    mech_wtls_key_mat,
    mech_wtls_master_key_derive,
    mech_wtls_prf,
)

__all__ = [
    "LengthArg",
    "PointerArg",
    "PackedAttribute",
    "PackedMechanism",
    "TemplateArg",
    "attr_array",
    "attr_auto",
    "attr_bool",
    "attr_bytes",
    "attr_date",
    "attr_string",
    "attr_template",
    "attr_ulong",
    "mech_bytes",
    "mech_simple",
    "template",
    "template_from_dict",
    "template_ptr_count",
]
