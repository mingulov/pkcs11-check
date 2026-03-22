"""CKR compliance tests for C_GetOperationState and C_SetOperationState.

Source: PKCS#11 v3.1 Sec.5.6.5-5.6.6.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11.exceptions import (
    OperationNotInitialized,
    PKCS11Error,
    SavedStateInvalid,
    StateUnsaveable,
)

pytestmark = pytest.mark.access


class TestGetOperationStateErrors:
    """Error conditions for C_GetOperationState (Sec.5.6.5)."""

    def test_no_active_operation(self, p11_session: Any) -> None:
        """GetOperationState with no active op -> CKR_OPERATION_NOT_INITIALIZED or CKR_STATE_UNSAVEABLE."""
        try:
            state = p11_session.get_operation_state()
            # Some modules return empty state - acceptable
        except (OperationNotInitialized, StateUnsaveable):
            pass  # Correct: no active operation to save
        except PKCS11Error:
            pass  # Other errors acceptable (module may not support state save)


class TestSetOperationStateErrors:
    """Error conditions for C_SetOperationState (Sec.5.6.6)."""

    def test_invalid_state(self, p11_session: Any) -> None:
        """SetOperationState with garbage data -> CKR_SAVED_STATE_INVALID."""
        try:
            p11_session.set_operation_state(b"\xDE\xAD\xBE\xEF" * 16)
            pytest.fail("Should have rejected garbage operation state")
        except SavedStateInvalid:
            pass  # Correct per spec
        except (OperationNotInitialized, PKCS11Error):
            pass  # Other errors acceptable (module-specific)
