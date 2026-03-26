"""Fault-oriented pointer and length helpers for raw PKCS#11 calls."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .pack import (
    LengthArg,
    PackedAttribute,
    PointerArg,
    TemplateArg,
    _exact_byte_storage,
)
from .types_std import CK_ATTRIBUTE, CK_ULONG


@dataclass(frozen=True)
class SizedFaultArg:
    """A malformed pointer/length pair with owned backing storage."""

    pointer_arg: PointerArg
    length_arg: LengthArg
    note: str

    @property
    def pointer(self) -> Any:
        return self.pointer_arg.pointer

    @property
    def storage(self) -> Any:
        return self.pointer_arg.storage

    @property
    def explicit_length(self) -> int:
        return self.length_arg.value


@dataclass(frozen=True)
class CountFaultArg:
    """A malformed pointer/count pair with owned backing storage."""

    pointer_arg: PointerArg
    claimed_count: int
    actual_count: int
    note: str

    @property
    def pointer(self) -> Any:
        return self.pointer_arg.pointer

    @property
    def storage(self) -> Any:
        return self.pointer_arg.storage


def null_pointer() -> PointerArg:
    """Return an explicit NULL pointer argument."""
    return PointerArg.null(origin="null_pointer")


def zero_length() -> LengthArg:
    """Return an explicit zero-length argument."""
    return LengthArg.explicit_value(0)


def _fault_from_storage(
    storage: Any,
    *,
    length: int,
    origin: str,
    note: str,
    native_length: int | None = None,
) -> SizedFaultArg:
    return SizedFaultArg(
        pointer_arg=PointerArg.to_storage(storage, origin=origin, native_length=native_length),
        length_arg=LengthArg.explicit_value(length),
        note=note,
    )


def nonnull_zero_length_bytes(value: bytes | bytearray | memoryview) -> SizedFaultArg:
    """Model a live non-NULL byte pointer passed with length zero."""
    data = bytes(value)
    return _fault_from_storage(
        _exact_byte_storage(data),
        length=0,
        origin="fault_nonnull_zero_length_bytes",
        note="nonnull pointer with zero length",
        native_length=len(data),
    )


def nonnull_zero_length_scalar(value: int) -> SizedFaultArg:
    """Model a live non-NULL scalar pointer passed with length zero."""
    return _fault_from_storage(
        CK_ULONG(value),
        length=0,
        origin="fault_nonnull_zero_length_scalar",
        note="nonnull scalar pointer with zero length",
    )


def nonnull_zero_length_struct(struct_type: type[ctypes.Structure]) -> SizedFaultArg:
    """Model a live non-NULL struct pointer passed with length zero."""
    return _fault_from_storage(
        struct_type(),
        length=0,
        origin="fault_nonnull_zero_length_struct",
        note="nonnull struct pointer with zero length",
    )


def nonnull_zero_length_array(
    values: list[int] | tuple[int, ...],
    *,
    ctype: Any = CK_ULONG,
) -> SizedFaultArg:
    """Model a live non-NULL array pointer passed with length zero."""
    return _fault_from_storage(
        (ctype * len(values))(*values),
        length=0,
        origin="fault_nonnull_zero_length_array",
        note="nonnull array pointer with zero length",
    )


def incorrect_explicit_length_bytes(
    value: bytes | bytearray | memoryview,
    *,
    claim: int,
) -> SizedFaultArg:
    """Model a live byte buffer passed with an incorrect explicit length."""
    data = bytes(value)
    return _fault_from_storage(
        _exact_byte_storage(data),
        length=claim,
        origin="fault_incorrect_explicit_length_bytes",
        note="nonnull byte pointer with incorrect explicit length",
        native_length=len(data),
    )


def incorrect_explicit_length_struct(
    struct_type: type[ctypes.Structure],
    *,
    claim: int,
) -> SizedFaultArg:
    """Model a live struct pointer passed with an incorrect explicit length."""
    return _fault_from_storage(
        struct_type(),
        length=claim,
        origin="fault_incorrect_explicit_length_struct",
        note="nonnull struct pointer with incorrect explicit length",
    )


def truncated_struct(struct_type: type[ctypes.Structure], *, keep: int) -> SizedFaultArg:
    """Return a struct-backed pointer with an explicitly truncated length."""
    return _fault_from_storage(
        struct_type(),
        length=keep,
        origin="fault_truncated_struct",
        note="truncated struct bytes",
    )


def mismatched_template_count(
    *attributes: PackedAttribute,
    claim_count: int,
) -> CountFaultArg:
    """Model a template pointer whose claimed element count differs from reality."""
    storage = TemplateArg(*attributes)
    return CountFaultArg(
        pointer_arg=PointerArg(
            pointer=ctypes.cast(storage.array, ctypes.c_void_p),
            storage=storage,
            kind="array",
            origin="fault_mismatched_template_count",
            native_length=storage.actual_count * ctypes.sizeof(CK_ATTRIBUTE),
            element_count=storage.actual_count,
            element_type="CK_ATTRIBUTE",
        ),
        claimed_count=claim_count,
        actual_count=storage.actual_count,
        note="mismatched template count",
    )


def wrong_buffer_shape_ulong_array_as_bytes(values: list[int] | tuple[int, ...]) -> SizedFaultArg:
    """Model a CK_ULONG array passed as though it were a byte buffer."""
    return _fault_from_storage(
        (CK_ULONG * len(values))(*values),
        length=len(values),
        origin="fault_wrong_buffer_shape_ulong_array_as_bytes",
        note="wrong buffer width/shape: ulong array passed as bytes",
    )
