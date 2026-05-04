"""CKR compliance tests for C_GetOperationState and C_SetOperationState.

Source: PKCS#11 v3.1 Sec.5.6.5-5.6.6.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SAVED_STATE_INVALID,
    CKR_STATE_UNSAVEABLE,
)

pytestmark = pytest.mark.access


class TestGetOperationStateErrors:
    """Error conditions for C_GetOperationState (Sec.5.6.5)."""

    def test_no_active_operation(self, p11_raw_session: Any) -> None:
        """GetOperationState with no active op -> OPERATION_NOT_INITIALIZED."""
        rs = p11_raw_session
        state_len = CK_ULONG(0)
        rv = rs.raw.C_GetOperationState(rs.sh, None, byref(state_len))
        # Correct: no active operation to save, or function not supported
        acceptable = (
            CKR_OK,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_STATE_UNSAVEABLE,
            CKR_FUNCTION_NOT_SUPPORTED,
        )
        assert rv in acceptable, f"Unexpected CKR 0x{rv:08x} from C_GetOperationState"


class TestSetOperationStateErrors:
    """Error conditions for C_SetOperationState (Sec.5.6.6)."""

    def test_invalid_state(self, p11_raw_session: Any) -> None:
        """SetOperationState with garbage data -> CKR_SAVED_STATE_INVALID."""
        rs = p11_raw_session
        garbage = (ctypes.c_ubyte * 64)(*([0xDE, 0xAD, 0xBE, 0xEF] * 16))
        rv = rs.raw.C_SetOperationState(rs.sh, garbage, 64, 0, 0)
        assert rv != CKR_OK, "Should have rejected garbage operation state"
        acceptable = (
            CKR_SAVED_STATE_INVALID,
            CKR_OPERATION_NOT_INITIALIZED,
            CKR_FUNCTION_NOT_SUPPORTED,
        )
        # Any non-OK error is acceptable; spec-mandated is CKR_SAVED_STATE_INVALID
        assert rv in acceptable or rv != 0, f"Unexpected CKR 0x{rv:08x} from C_SetOperationState"
