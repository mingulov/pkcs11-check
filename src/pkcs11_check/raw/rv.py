"""Helpers for checking and describing raw CK_RV return values."""

from __future__ import annotations

from . import metadata_std
from .extensions import lookup_symbol_name


_RV_NAMES = dict(metadata_std.RV_NAMES)


def rv_name(rv: int) -> str:
    """Return a symbolic name for a CK_RV integer when known."""
    return lookup_symbol_name("rvs", rv) or _RV_NAMES.get(rv, f"0x{rv:08x}")


def ckr_name(rv: int) -> str:
    """Return a symbolic CKR_* name for a CK_RV integer when known."""
    return rv_name(rv)


def expect_rv(rv: int, *allowed: int) -> int:
    """Return rv if allowed, otherwise raise an AssertionError."""
    if rv in allowed:
        return rv
    allowed_names = ", ".join(rv_name(value) for value in allowed)
    raise AssertionError(f"Unexpected CK_RV {rv_name(rv)}; expected one of: {allowed_names}")
