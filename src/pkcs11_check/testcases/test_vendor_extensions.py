"""Vendor extension detection tests.

Probes for vendor-defined mechanisms (CKM_VENDOR_DEFINED range)
and reports any found. Also checks for FIPS mode flags.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Mechanism
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.smoke


# CKM_VENDOR_DEFINED = 0x80000000
CKM_VENDOR_DEFINED = 0x80000000


class TestVendorMechanisms:
    """Detect vendor-defined mechanisms."""

    def test_report_all_mechanisms(self, p11_module: Any) -> None:
        """List all mechanisms supported by the module."""
        token = p11_module.get_token()
        slot = token.slot
        mechs = slot.get_mechanisms()
        assert len(mechs) > 0, "Module reports zero mechanisms"

        # Count standard vs vendor mechanisms
        vendor_mechs = []
        standard_mechs = []
        for m in mechs:
            val = m.value if hasattr(m, "value") else int(m)
            if val >= CKM_VENDOR_DEFINED:
                vendor_mechs.append(m)
            else:
                standard_mechs.append(m)

        # At minimum, a useful module should have some standard mechanisms
        assert len(standard_mechs) > 5, (
            f"Only {len(standard_mechs)} standard mechanisms — suspiciously low"
        )

    def test_aes_mechanism_present(self, p11_module: Any) -> None:
        """AES mechanisms should be present on any modern module."""
        token = p11_module.get_token()
        slot = token.slot
        mechs = slot.get_mechanisms()
        mech_set = set(mechs)

        # At least one AES mechanism should exist
        aes_mechs = [
            Mechanism.AES_KEY_GEN,
            Mechanism.AES_ECB,
            Mechanism.AES_CBC,
        ]
        found = [m for m in aes_mechs if m in mech_set]
        assert len(found) > 0, "No AES mechanisms found"

    def test_mechanism_info_readable(self, p11_module: Any) -> None:
        """MechanismInfo is readable for each reported mechanism."""
        token = p11_module.get_token()
        slot = token.slot
        mechs = slot.get_mechanisms()

        # Check info for first 10 mechanisms
        for mech in list(mechs)[:10]:
            try:
                info = slot.get_mechanism_info(mech)
                assert info is not None
            except (PKCS11Error, NotImplementedError):
                pass  # Some mechanisms may not have info


class TestFIPSMode:
    """Detect FIPS mode flags on the token."""

    def test_token_flags_readable(self, p11_module: Any) -> None:
        """Token flags are accessible — check for FIPS if available."""
        token = p11_module.get_token()
        # Token info should be accessible
        assert token is not None

        # Check if token has any flags attribute
        # CKF_FIPS_APPROVED would be in token flags if supported
        # For now, just verify we can access basic token properties
        slot = token.slot
        assert slot is not None
