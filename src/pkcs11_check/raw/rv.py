"""Helpers for checking and describing raw CK_RV return values."""

from __future__ import annotations

from . import metadata_std
from .extensions import lookup_symbol_name
from .types_std import CKR

_RV_NAMES = dict(metadata_std.RV_NAMES)


def ckr_name(rv: int) -> str:
    """Return a symbolic CKR_* name for a CK_RV integer when known."""
    return lookup_symbol_name("rvs", rv) or _RV_NAMES.get(rv, f"0x{rv:08x}")


def expect_rv(rv: int, *allowed: CKR, context: str | None = None) -> int:
    """Return rv if allowed, otherwise raise an AssertionError."""
    if rv in allowed:
        return rv
    msg = f"Unexpected CK_RV {ckr_name(rv)}"
    if context:
        msg = f"{context}: {msg}"
    allowed_names = ", ".join(ckr_name(value) for value in allowed)
    raise AssertionError(f"{msg}; expected one of: {allowed_names}")


__all__ = [
    "ckr_name",
    "expect_rv",
]
