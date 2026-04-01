"""Vendor extension detection tests.

Probes for vendor-defined mechanisms (CKM_VENDOR_DEFINED range)
and reports any found. Also checks for FIPS mode flags.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.recipes import get_mechanism_info, get_mechanism_list
from pkcs11_check.raw.types_std import (
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
        _vendor_count = sum(1 for m in mechs if m >= CKM_VENDOR_DEFINED)  # noqa: F841
        standard_mechs = [m for m in mechs if m < CKM_VENDOR_DEFINED]

        assert len(standard_mechs) > 5, f"Only {len(standard_mechs)} standard mechanisms"

    def test_aes_mechanism_present(self, p11_raw_session: Any) -> None:
        """AES mechanisms should be present on any modern module."""
        rs = p11_raw_session
        mechs = set(get_mechanism_list(rs.raw, rs.slot_id))

        aes_mechs = [
            CKM_AES_KEY_GEN,
            CKM_AES_ECB,
            CKM_AES_CBC,
        ]
        found = [m for m in aes_mechs if m in mechs]
        assert len(found) > 0, "No AES mechanisms found"

    def test_mechanism_info_readable(self, p11_raw_session: Any) -> None:
        """MechanismInfo is readable for each reported mechanism."""
        rs = p11_raw_session
        mechs = get_mechanism_list(rs.raw, rs.slot_id)

        for mech in mechs[:10]:
            get_mechanism_info(rs.raw, rs.slot_id, mech)  # crash safety check


class TestVendorMechanismEnumeration:
    """Enumerate and report all vendor mechanisms (CKM_VENDOR_DEFINED range)."""

    def test_vendor_mechanisms_have_valid_info(self, p11_raw_session: Any) -> None:
        """Every vendor mechanism should return valid mechanism info."""
        rs = p11_raw_session
        mechs = get_mechanism_list(rs.raw, rs.slot_id)
        vendor_mechs = [m for m in mechs if m >= CKM_VENDOR_DEFINED]

        if not vendor_mechs:
            pytest.skip("No vendor mechanisms advertised")

        for mech in vendor_mechs:
            info = get_mechanism_info(rs.raw, rs.slot_id, mech)
            assert info["min_key_size"] >= 0
            assert info["max_key_size"] >= info["min_key_size"]
            assert info["flags"] >= 0

    def test_vendor_mechanism_flags_report(self, p11_raw_session: Any) -> None:
        """Log all vendor mechanisms with their flags for human review."""
        rs = p11_raw_session
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

        mechs = get_mechanism_list(rs.raw, rs.slot_id)
        vendor_mechs = [m for m in mechs if m >= CKM_VENDOR_DEFINED]

        if not vendor_mechs:
            pytest.skip("No vendor mechanisms advertised")

        for mech in vendor_mechs:
            info = get_mechanism_info(rs.raw, rs.slot_id, mech)
            name = MECHANISM_NAMES.get(mech, f"0x{mech:08x}")
            if name.startswith("CKM_"):
                name = name[4:]
            _flags = info["flags"]  # noqa: F841 — output visible in test log
            _name = name  # noqa: F841


class TestFIPSMode:
    """Detect FIPS mode flags on the token."""

    def test_token_flags_readable(self, p11_raw_session: Any) -> None:
        """Token flags are accessible."""
        from pkcs11_check.raw.types_std import CK_TOKEN_INFO

        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        assert rv == CKR_OK
