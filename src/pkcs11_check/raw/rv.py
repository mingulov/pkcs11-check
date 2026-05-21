"""Helpers for checking and describing raw CK_RV return values."""

from __future__ import annotations

from . import metadata_std
from .extensions import lookup_symbol_name
from .types_std import CKR

_RV_NAMES = dict(metadata_std.RV_NAMES)


class CkrAssertionError(AssertionError):
    """AssertionError raised by ``expect_rv`` carrying the offending CKR int.

    ``except AssertionError`` keeps working (CkrAssertionError is a subclass),
    but callers that want exact CKR equality — rather than substring matching
    on the message — can read ``exc.rv`` directly.  Useful because some CKR
    names are prefixes of others (``CKR_MECHANISM_INVALID`` vs.
    ``CKR_MECHANISM_PARAM_INVALID``).
    """

    rv: int

    def __init__(self, message: str, rv: int) -> None:
        super().__init__(message)
        self.rv = rv


def ckr_name(rv: int) -> str:
    """Return a symbolic CKR_* name for a CK_RV integer when known."""
    return lookup_symbol_name("rvs", rv) or _RV_NAMES.get(rv, f"0x{rv:08x}")


def expect_rv(rv: int, *allowed: CKR, context: str | None = None) -> int:
    """Return rv if allowed, otherwise raise ``CkrAssertionError`` (an AssertionError)."""
    if rv in allowed:
        return rv
    msg = f"Unexpected CK_RV {ckr_name(rv)}"
    if context:
        msg = f"{context}: {msg}"
    allowed_names = ", ".join(ckr_name(value) for value in allowed)
    raise CkrAssertionError(f"{msg}; expected one of: {allowed_names}", rv)


__all__ = [
    "CkrAssertionError",
    "ckr_name",
    "expect_rv",
]
