"""C_GetSessionValidationFlags tests -- v3.0+ session validation bitmask."""

from __future__ import annotations

from ctypes import byref, c_ulong
from typing import Any

import pytest

from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import CKR_OK

pytestmark = [pytest.mark.requires_v30]


class TestSessionValidationFlags:
    def test_get_session_validation_flags_returns_flags(self, p11_raw_session: Any) -> None:
        """C_GetSessionValidationFlags should return a CK_FLAGS bitmask."""
        rs = p11_raw_session
        if not hasattr(rs.raw, "C_GetSessionValidationFlags"):
            pytest.skip("C_GetSessionValidationFlags not available")
        flags = c_ulong(0)
        rv = rs.raw.C_GetSessionValidationFlags(rs.sh, 0, byref(flags))
        expect_rv(rv, CKR_OK)
        assert flags.value >= 0
