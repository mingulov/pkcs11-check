"""Signal X3DH (Extended Triple Diffie-Hellman) mechanism tests.

CKM_X3DH_INITIALIZE - initiator side of X3DH key exchange.
CKM_X3DH_RESPOND   - responder side of X3DH key exchange.

Both mechanisms operate on EC Montgomery keys (CKK_EC_MONTGOMERY, i.e. X25519/X448).
Almost no HSM supports X3DH yet - tests skip cleanly when unavailable.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.full


class TestX3DH:
    """X3DH mechanism availability and consistency tests."""

    def test_x3dh_initialize_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_INITIALIZE is listed as a supported mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")
        # Module claims support - mechanism is present in the slot's list.
        assert rs.has_mechanism("X3DH_INITIALIZE")

    def test_x3dh_respond_mechanism_check(self, p11_raw_session: Any) -> None:
        """CKM_X3DH_RESPOND is listed as a supported mechanism."""
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")
        assert rs.has_mechanism("X3DH_RESPOND")

    def test_x3dh_both_sides_available(self, p11_raw_session: Any) -> None:
        """If X3DH_INITIALIZE is available, X3DH_RESPOND must also be present.

        A module that exposes only one side of the X3DH exchange is incomplete
        per the PKCS#11 spec - both mechanisms are required together.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_INITIALIZE"):
            pytest.skip("CKM_X3DH_INITIALIZE not supported")
        assert rs.has_mechanism("X3DH_RESPOND"), (
            "Module supports CKM_X3DH_INITIALIZE but not CKM_X3DH_RESPOND"
        )

    def test_x3dh_respond_implies_initialize(self, p11_raw_session: Any) -> None:
        """If X3DH_RESPOND is available, X3DH_INITIALIZE must also be present.

        Symmetric counterpart to test_x3dh_both_sides_available.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("X3DH_RESPOND"):
            pytest.skip("CKM_X3DH_RESPOND not supported")
        assert rs.has_mechanism("X3DH_INITIALIZE"), (
            "Module supports CKM_X3DH_RESPOND but not CKM_X3DH_INITIALIZE"
        )
