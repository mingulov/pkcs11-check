"""Fault-oriented pointer and length helpers for raw PKCS#11 calls."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .pack import LengthArg, PointerArg, explicit_length as pack_explicit_length


@dataclass(frozen=True)
class TruncatedStructArg:
    """Own a struct instance while exposing an intentionally short length."""

    storage: Any
    pointer: Any
    explicit_length: int

    @property
    def length(self) -> LengthArg:
        return pack_explicit_length(self.explicit_length)


def null_pointer() -> PointerArg:
    """Return an explicit NULL pointer argument."""
    return PointerArg.null()


def explicit_length(size: int) -> LengthArg:
    """Return an explicit raw length override."""
    return pack_explicit_length(size)


def zero_length() -> LengthArg:
    """Return an explicit zero-length argument."""
    return explicit_length(0)


def truncated_struct(struct_type: type[ctypes.Structure], *, keep: int) -> TruncatedStructArg:
    """Return a struct-backed pointer with an explicitly truncated length."""
    storage = struct_type()
    pointer = PointerArg.to_storage(storage)
    return TruncatedStructArg(
        storage=storage,
        pointer=pointer.pointer,
        explicit_length=keep,
    )
