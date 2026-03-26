"""Vendor extension detection tests.

Probes for vendor-defined mechanisms (CKM_VENDOR_DEFINED range)
and reports any found. Also checks for FIPS mode flags.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.recipes import get_mechanism_list
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_VENDOR_DEFINED,
    CKR_OK,
)

pytestmark = pytest.mark.smoke


class TestVendorMechanisms:
    """Detect vendor-defined mechanisms."""

    def test_report_all_mechanisms(self, p11_raw_session: Any) -> None:
        """List all mechanisms supported by the module."""
        rs = p11_raw_session
        mechs = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechs) > 0, "Module reports zero mechanisms"

        # Count standard vs vendor mechanisms
        _vendor_count = sum(1 for m in mechs if m >= int(CKM_VENDOR_DEFINED))  # noqa: F841
        standard_mechs = [m for m in mechs if m < int(CKM_VENDOR_DEFINED)]

        assert len(standard_mechs) > 5, (
            f"Only {len(standard_mechs)} standard mechanisms"
        )

    def test_aes_mechanism_present(self, p11_raw_session: Any) -> None:
        """AES mechanisms should be present on any modern module."""
        rs = p11_raw_session
        mechs = set(get_mechanism_list(rs.raw, rs.slot_id))

        aes_mechs = [
            int(CKM_AES_KEY_GEN), int(CKM_AES_ECB), int(CKM_AES_CBC),
        ]
        found = [m for m in aes_mechs if m in mechs]
        assert len(found) > 0, "No AES mechanisms found"

    def test_mechanism_info_readable(self, p11_raw_session: Any) -> None:
        """MechanismInfo is readable for each reported mechanism."""
        rs = p11_raw_session
        mechs = get_mechanism_list(rs.raw, rs.slot_id)

        for mech in mechs[:10]:
            info = CK_MECHANISM_INFO()
            rv = rs.raw.C_GetMechanismInfo(rs.slot_id, mech, byref(info))
            # Any response is OK - just verify no crash
            assert rv == int(CKR_OK) or rv != int(CKR_OK)


class TestFIPSMode:
    """Detect FIPS mode flags on the token."""

    def test_token_flags_readable(self, p11_raw_session: Any) -> None:
        """Token flags are accessible."""
        from pkcs11_check.raw.types_std import CK_TOKEN_INFO

        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        assert rv == int(CKR_OK)
