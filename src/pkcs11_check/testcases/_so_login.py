"""SO (Security Officer) login helpers: PIN resolution, lockout safety, session dance.

Design: ws docs/superpowers/specs/2026-07-17-so-login-cka-trusted-design.md (roadmap #11).

Lockout policy (two-tier):

- ANY SO login attempt is refused (skip) when CKF_SO_PIN_FINAL_TRY or
  CKF_SO_PIN_LOCKED is set in CK_TOKEN_INFO.flags.
- The user-PIN-as-SO-PIN *guess* is additionally refused when
  CKF_SO_PIN_COUNT_LOW is set; an explicitly configured SO PIN
  (--p11-so-pin / P11TEST_SO_PIN) still proceeds (the operator vouches for it).
- ``require_pristine=True`` (deliberate wrong-PIN probes) refuses on any of the
  three counter flags, even with an explicit SO PIN.
- After one CKR_PIN_INCORRECT the failure is cached for the rest of this
  subprocess, so a wrong PIN is attempted at most once per isolated test file
  (each wrong attempt burns one SO retry-counter step on a real token).

The SO PIN value itself never appears in any message (PIN-handling rule).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_TOKEN_INFO,
    CKF_SO_PIN_COUNT_LOW,
    CKF_SO_PIN_FINAL_TRY,
    CKF_SO_PIN_LOCKED,
    CKR_OK,
    CKR_PIN_INCORRECT,
)

# Per-subprocess cache: once the resolved SO PIN was rejected with
# CKR_PIN_INCORRECT, no further SO login is attempted in this process.
_SO_PIN_REJECTED = False


def resolve_so_pin(p11_config: Any) -> tuple[bytes | None, bool]:
    """Resolve the SO PIN as ``(pin_bytes, explicit)``.

    ``explicit=True``: ``so_pin`` was configured (--p11-so-pin / P11TEST_SO_PIN
    / TOML). ``explicit=False``: fallback guess reusing the user PIN
    (historical behavior). ``(None, False)``: no PIN of either kind.
    """
    so_pin = getattr(p11_config, "so_pin", None)
    if so_pin is not None:
        value = so_pin.get_secret_value() if hasattr(so_pin, "get_secret_value") else str(so_pin)
        return value.encode("utf-8"), True
    pin = getattr(p11_config, "pin", None)
    if pin is None:
        return None, False
    value = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
    return value.encode("utf-8"), False


def guard_so_lockout(
    raw: Any, slot_id: int, *, explicit: bool, require_pristine: bool = False
) -> None:
    """Refuse (skip) an SO login attempt that risks walking the token to SO lockout."""
    if _SO_PIN_REJECTED:
        pytest.skip(
            "SO PIN already rejected once in this process (CKR_PIN_INCORRECT); "
            "not retrying (lockout safety)"
        )
    token_info = CK_TOKEN_INFO()
    info_rv = raw.C_GetTokenInfo(slot_id, byref(token_info))
    if info_rv != CKR_OK:
        return  # the gate is a safety net, not a new failure surface
    flags = int(token_info.flags)
    if flags & CKF_SO_PIN_LOCKED:
        pytest.skip("SO PIN is locked (CKF_SO_PIN_LOCKED); refusing any SO login attempt")
    if flags & CKF_SO_PIN_FINAL_TRY:
        pytest.skip(
            "SO PIN retry counter at final try (CKF_SO_PIN_FINAL_TRY); "
            "refusing any SO login attempt"
        )
    if flags & CKF_SO_PIN_COUNT_LOW and (require_pristine or not explicit):
        pytest.skip(
            "SO PIN retry counter low (CKF_SO_PIN_COUNT_LOW); refusing to spend "
            "an attempt without an explicitly configured SO PIN"
        )


def skip_if_so_pin_rejected(rv: int, *, explicit: bool) -> None:
    """On CKR_PIN_INCORRECT: cache the rejection process-wide, then skip."""
    global _SO_PIN_REJECTED
    if rv == CKR_PIN_INCORRECT:
        _SO_PIN_REJECTED = True
        if explicit:
            pytest.skip(
                "configured SO PIN rejected (CKR_PIN_INCORRECT); "
                "check --p11-so-pin / P11TEST_SO_PIN"
            )
        pytest.skip("SO PIN differs from user PIN on this module")
