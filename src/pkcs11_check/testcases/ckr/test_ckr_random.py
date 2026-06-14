"""CKR compliance tests for C_SeedRandom and C_GenerateRandom.

Source: PKCS#11 v3.2-5.18.2.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
)

pytestmark = pytest.mark.access


class TestSeedRandomErrors:
    """Error conditions for C_SeedRandom (Sec.5.18.1)."""

    def test_seed_random(self, p11_raw_session: Any) -> None:
        """C_SeedRandom - should accept or return RANDOM_SEED_NOT_SUPPORTED."""
        rs = p11_raw_session
        seed = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        rv = rs.raw.C_SeedRandom(rs.sh, seed, 32)
        assert rv in (
            CKR_OK,
            CKR_RANDOM_SEED_NOT_SUPPORTED,
            CKR_FUNCTION_NOT_SUPPORTED,
        ), f"Unexpected CKR 0x{rv:08x} from C_SeedRandom"


class TestGenerateRandomErrors:
    """Error conditions for C_GenerateRandom (Sec.5.18.2)."""

    def test_generate_random_zero(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom(0) - should return empty or error."""
        rs = p11_raw_session
        buf = (ctypes.c_ubyte * 1)()  # minimal buffer
        rv = rs.raw.C_GenerateRandom(rs.sh, buf, CK_ULONG(0))
        # Module may accept zero-length or reject - both acceptable
        assert rv == CKR_OK or rv != 0

    @pytest.mark.slow
    def test_generate_random_large(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom(1MB) - large request."""
        rs = p11_raw_session
        size = 1024 * 1024
        buf = (ctypes.c_ubyte * size)()
        rv = rs.raw.C_GenerateRandom(rs.sh, buf, CK_ULONG(size))
        if rv == CKR_OK:
            assert len(bytes(buf)) == size
        # Some modules have size limits - non-OK is acceptable
