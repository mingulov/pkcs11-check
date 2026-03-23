"""Helpers for checking and describing raw CK_RV return values."""

from __future__ import annotations

from . import core


_RV_NAMES = {
    value: name
    for name, value in vars(core).items()
    if name.startswith("CKR_") and isinstance(value, int)
}


def rv_name(rv: int) -> str:
    """Return a symbolic name for a CK_RV integer when known."""
    return _RV_NAMES.get(rv, f"0x{rv:08x}")


def ckr_name(rv: int) -> str:
    """Return a symbolic CKR_* name for a CK_RV integer when known."""
    return rv_name(rv)


def expect_rv(rv: int, *allowed: int) -> int:
    """Return rv if allowed, otherwise raise an AssertionError."""
    if rv in allowed:
        return rv
    allowed_names = ", ".join(rv_name(value) for value in allowed)
    raise AssertionError(f"Unexpected CK_RV {rv_name(rv)}; expected one of: {allowed_names}")
