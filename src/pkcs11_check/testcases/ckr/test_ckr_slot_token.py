"""CKR compliance tests for slot and token management functions.

Covers C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo,
C_WaitForSlotEvent.

Source: PKCS#11 v3.2-5.5.7.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.recipes import get_mechanism_list
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CK_ULONG,
    CKF_DONT_BLOCK,
    CKM_AES_GCM,
    CKM_AES_XTS,
    CKM_CHACHA20,
    CKM_CHACHA20_POLY1305,
    CKM_ECDSA_SHA3_512,
    CKM_RSA_AES_KEY_WRAP,
    CKM_SHA3_512,
    CKM_SHAKE_256_KEY_DERIVE,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_NO_EVENT,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.access


class TestGetMechanismInfoErrors:
    """Error conditions for C_GetMechanismInfo (Sec.5.5.6)."""

    def test_mechanism_invalid(self, p11_raw_session: Any) -> None:
        """Query info for non-existent mechanism -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, 0xDEADBEEF, byref(info))
        classify_negative_rv(
            rv,
            (CKR_MECHANISM_INVALID,),
            label="C_GetMechanismInfo for a non-existent mechanism",
        )

    def test_mechanism_info_rejects_standard_unadvertised_mechanism(
        self, p11_raw_session: Any
    ) -> None:
        """A standard CKM absent from C_GetMechanismList must not return info."""
        rs = p11_raw_session
        advertised = set(get_mechanism_list(rs.raw, rs.slot_id))
        candidates = (
            CKM_CHACHA20_POLY1305,
            CKM_CHACHA20,
            CKM_AES_XTS,
            CKM_RSA_AES_KEY_WRAP,
            CKM_ECDSA_SHA3_512,
            CKM_SHAKE_256_KEY_DERIVE,
            CKM_SHA3_512,
            CKM_AES_GCM,
        )
        mechanism = next(
            (candidate for candidate in candidates if candidate not in advertised),
            None,
        )
        if mechanism is None:
            pytest.skip("No standard absent mechanism available for C_GetMechanismInfo probe")

        info = CK_MECHANISM_INFO()
        rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mechanism, byref(info))
        classify_negative_rv(
            rv,
            (CKR_MECHANISM_INVALID,),
            label=f"C_GetMechanismInfo for unadvertised standard mechanism {mechanism}",
        )


class TestWaitForSlotEventErrors:
    """Error conditions for C_WaitForSlotEvent (Sec.5.5.4)."""

    def test_non_blocking_no_event(self, p11_raw_session: Any) -> None:
        """Non-blocking WaitForSlotEvent -> CKR_NO_EVENT or CKR_FUNCTION_NOT_SUPPORTED."""
        rs = p11_raw_session
        slot_id = CK_ULONG(0)
        # CKF_DONT_BLOCK is REQUIRED for a non-blocking probe. Per PKCS#11 v3.2 §5.5.4,
        # flags=0 BLOCKS until a slot event occurs — against a module that honors that
        # (e.g. NetHSM) flags=0 hangs forever, and a signal-based test timeout cannot
        # interrupt the blocked native call. CKF_DONT_BLOCK returns immediately.
        rv = rs.raw.C_WaitForSlotEvent(CKF_DONT_BLOCK, byref(slot_id), None)
        acceptable = (
            CKR_OK,  # Event returned - possible on some setups
            CKR_NO_EVENT,  # Expected for software tokens
            CKR_FUNCTION_NOT_SUPPORTED,  # SoftHSM2 doesn't implement this
        )
        assert rv in acceptable, f"Unexpected CKR {ckr_name(rv)} from C_WaitForSlotEvent"
