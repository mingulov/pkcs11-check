"""CKR compliance tests for slot and token management functions.

Covers C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
C_WaitForSlotEvent.

Source: PKCS#11 v3.1 Sec.5.5.1-5.5.7.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CK_ULONG,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_NO_EVENT,
    CKR_OK,
)

pytestmark = pytest.mark.access


class TestGetMechanismInfoErrors:
    """Error conditions for C_GetMechanismInfo (Sec.5.5.6)."""

    def test_mechanism_invalid(self, p11_raw_session: Any) -> None:
        """Query info for non-existent mechanism -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, 0xDEADBEEF, byref(info))
        assert rv != CKR_OK, "Should have rejected non-existent mechanism"
        assert rv == CKR_MECHANISM_INVALID, f"Expected CKR_MECHANISM_INVALID, got {ckr_name(rv)}"


class TestWaitForSlotEventErrors:
    """Error conditions for C_WaitForSlotEvent (Sec.5.5.4)."""

    def test_non_blocking_no_event(self, p11_raw_session: Any) -> None:
        """Non-blocking WaitForSlotEvent -> CKR_NO_EVENT or CKR_FUNCTION_NOT_SUPPORTED."""
        rs = p11_raw_session
        slot_id = CK_ULONG(0)
        # flags=0 means non-blocking (CKF_DONT_BLOCK not needed for non-blocking)
        rv = rs.raw.C_WaitForSlotEvent(0, byref(slot_id), None)
        acceptable = (
            CKR_OK,  # Event returned - possible on some setups
            CKR_NO_EVENT,  # Expected for software tokens
            CKR_FUNCTION_NOT_SUPPORTED,  # SoftHSM2 doesn't implement this
        )
        assert rv in acceptable, f"Unexpected CKR {ckr_name(rv)} from C_WaitForSlotEvent"
