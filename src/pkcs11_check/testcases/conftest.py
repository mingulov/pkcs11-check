"""Shared fixtures and helpers for pkcs11-check PKCS#11 test cases.

Note: Static skips such as missing-module and destructive gating are handled in
plugin.py collection hooks. Dynamic version/mechanism skips are handled from the
collection-safe capability manifest before test setup.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

import pytest


def needs_mechanism(name: str) -> Callable[[Any], Any]:
    """Decorator that skips the test if the mechanism is not supported."""

    def decorator(func: Any) -> Any:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            rs = kwargs.get("p11_raw_session")
            if rs is not None and not rs.has_mechanism(name):
                pytest.skip(f"{name} not supported")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def skip_unless_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")


def get_pin_bytes(p11_config: Any) -> bytes | None:
    """Extract PIN as bytes from config, or None if no PIN configured."""
    if p11_config.pin is None:
        return None
    pin = p11_config.pin
    pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
    return pin_str.encode("utf-8")


def extract_ec_point(ec_point_der: Any) -> Any:
    """Extract raw uncompressed EC point from DER OCTET STRING wrapper.

    PKCS#11 EC_POINT attribute is DER-encoded: 0x04 <length> <point_bytes>.
    Returns the raw point bytes (starting with 0x04 uncompressed prefix).
    """
    from pkcs11_check.raw.der import decode_ec_point

    data = bytes(ec_point_der)
    if not data or data[0] != 0x04:
        return ec_point_der
    return decode_ec_point(data)


def skip_if_token_write_protected(raw: Any, slot_id: int) -> None:
    """Skip test if the token is write-protected (cannot create token objects)."""
    from ctypes import byref

    from pkcs11_check.raw.types_std import CK_TOKEN_INFO, CKF_WRITE_PROTECTED, CKR_OK

    info = CK_TOKEN_INFO()
    rv = raw.C_GetTokenInfo(slot_id, byref(info))
    if rv != CKR_OK:
        return  # Can't determine, let the test try
    if info.flags & CKF_WRITE_PROTECTED:
        pytest.skip("Token is write-protected -- cannot create token objects")


def xfail_if_known_ckr(
    exc: Exception,
    known_ckrs: set[Any] | tuple[Any, ...] | frozenset[Any],
    msg: str,
) -> None:
    """xfail if ``exc`` corresponds to a known CKR, otherwise re-raise.

    Prefers the exact ``CkrAssertionError.rv`` attribute when present
    (raised by ``expect_rv``).  Falls back to substring matching on the
    exception message for assertions raised by other call paths.

    Use this instead of ``except (AssertionError, Exception): pytest.xfail(...)``
    so that only specific CKR failures become expected failures, while
    Python coding bugs and wrong-output assertions propagate as real failures.

    Args:
        exc: The caught exception.
        known_ckrs: Iterable of CKR integer values to match against.
        msg: Message for pytest.xfail if a known CKR is matched.
    """
    from pkcs11_check.raw.rv import ckr_name

    rv = getattr(exc, "rv", None)
    if rv is not None and rv in known_ckrs:
        pytest.xfail(f"{msg}: {ckr_name(rv)}")
    elif rv is None:
        exc_str = str(exc)
        for ckr in known_ckrs:
            if ckr_name(ckr) in exc_str:
                pytest.xfail(f"{msg}: {ckr_name(ckr)}")
    raise  # Not a known CKR -- propagate as real failure


def is_known_error(
    exc: BaseException,
    error_rvs: set[Any] | frozenset[Any] | tuple[Any, ...],
) -> bool:
    """Return True if ``exc`` corresponds to one of ``error_rvs``.

    Prefers exact integer equality via ``CkrAssertionError.rv`` (set by
    ``expect_rv``).  Falls back to substring matching against the
    exception message for legacy AssertionError paths — that fallback can
    misfire when one CKR name is a prefix of another, so prefer raising
    via ``expect_rv`` where possible.
    """
    from pkcs11_check.raw.rv import ckr_name

    rv = getattr(exc, "rv", None)
    if rv is not None:
        return rv in error_rvs
    msg = str(exc)
    return any(ckr_name(r) in msg for r in error_rvs)


def destroy_returned_handles(rs: Any, *handles: int) -> None:
    """Destroy a sequence of object handles, silently skipping zeros and errors."""
    from pkcs11_check.raw.recipes import destroy_quietly

    for handle in handles:
        if handle:
            destroy_quietly(rs.raw, rs.sh, int(handle))


def skip_if_mech_param_unsupported(exc: BaseException, context: str) -> None:
    """pytest.skip if ``exc`` carries one of MECH_PARAM_UNSUPPORTED_ERRORS, else re-raise.

    Provider-generated IV / nonce / wrap-output parameter conventions are
    allowed to be rejected even when the base mechanism is advertised; this
    helper turns those rejections into a clean skip while letting other
    failures propagate as real findings.

    Prefers exact ``CkrAssertionError.rv`` matching when present (via
    ``is_known_error``).
    """
    from pkcs11_check.testcases._error_tuples import MECH_PARAM_UNSUPPORTED_ERRORS

    if is_known_error(exc, MECH_PARAM_UNSUPPORTED_ERRORS):
        pytest.skip(f"{context} not supported: {exc}")
    raise exc
