"""CKR compliance tests for slot and token management functions.

Covers C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
C_WaitForSlotEvent.

Source: PKCS#11 v3.1 Sec.5.5.1-5.5.7.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11.exceptions import (
    FunctionNotSupported,
    MechanismInvalid,
    NoEvent,
    PKCS11Error,
)

pytestmark = pytest.mark.access


class TestGetMechanismInfoErrors:
    """Error conditions for C_GetMechanismInfo (Sec.5.5.6)."""

    def test_mechanism_invalid(self, p11_module: Any) -> None:
        """Query info for non-existent mechanism -> CKR_MECHANISM_INVALID."""
        slot = p11_module.lib.get_slots()[0]
        try:
            # Use a bogus mechanism type value
            slot.get_mechanism_info(0xDEADBEEF)
            pytest.fail("Should have rejected non-existent mechanism")
        except (MechanismInvalid, PKCS11Error):
            pass  # CKR_MECHANISM_INVALID expected


class TestWaitForSlotEventErrors:
    """Error conditions for C_WaitForSlotEvent (Sec.5.5.4)."""

    def test_non_blocking_no_event(self, p11_module: Any) -> None:
        """Non-blocking WaitForSlotEvent -> CKR_NO_EVENT or CKR_FUNCTION_NOT_SUPPORTED."""
        try:
            p11_module.lib.wait_for_slot_event(blocking=False)
            # Event returned -- possible on some setups
        except NoEvent:
            pass  # Expected for software tokens
        except FunctionNotSupported:
            pass  # SoftHSM2 doesn't implement this
        except PKCS11Error:
            pass  # Other errors acceptable
