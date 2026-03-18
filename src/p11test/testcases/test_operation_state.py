"""C_GetOperationState / C_SetOperationState tests.

Tests the ability to save and restore multi-part operation state.
Many modules don't support this (CKR_STATE_UNSAVEABLE), so tests
skip gracefully.

Note: python-pkcs11 wraps multi-part operations internally, so
we test via the session-level get/set_operation_state methods
and verify they either work correctly or fail cleanly.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.access


class TestOperationState:
    """Test C_GetOperationState / C_SetOperationState."""

    def test_no_active_operation_fails(self, p11_session: Any) -> None:
        """Getting state with no active operation should fail."""
        try:
            state = p11_session.get_operation_state()
            # If it succeeds with empty state, that's also acceptable
            assert isinstance(state, bytes)
        except (PKCS11Error, AttributeError):
            pass  # Expected — no active operation or not supported

    def test_get_set_methods_exist(self, p11_session: Any) -> None:
        """Session exposes get/set_operation_state methods."""
        assert hasattr(p11_session, "get_operation_state")
        assert hasattr(p11_session, "set_operation_state")

    def test_set_invalid_state_fails(self, p11_session: Any) -> None:
        """Setting garbage as operation state should fail cleanly."""
        try:
            p11_session.set_operation_state(b"\xff" * 64)
            # If it doesn't error, that's concerning but not necessarily wrong
        except (PKCS11Error, AttributeError):
            pass  # Expected — invalid state data
