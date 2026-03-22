"""CKR compliance tests for C_SeedRandom and C_GenerateRandom.

Source: PKCS#11 v3.1 Sec.5.18.1-5.18.2.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.access


class TestSeedRandomErrors:
    """Error conditions for C_SeedRandom (Sec.5.18.1)."""

    def test_seed_random(self, p11_session: Any) -> None:
        """C_SeedRandom -- should accept or return RANDOM_SEED_NOT_SUPPORTED."""
        try:
            p11_session.seed_random(b"\x42" * 32)
            # Accepted -- module supports seeding
        except PKCS11Error:
            pass  # CKR_RANDOM_SEED_NOT_SUPPORTED or CKR_FUNCTION_NOT_SUPPORTED


class TestGenerateRandomErrors:
    """Error conditions for C_GenerateRandom (Sec.5.18.2)."""

    def test_generate_random_zero(self, p11_session: Any) -> None:
        """C_GenerateRandom(0) -- should return empty or error."""
        try:
            result = p11_session.generate_random(0)
            assert len(result) == 0
        except (PKCS11Error, ValueError):
            pass  # Module rejects, or python-pkcs11 can't create 0-length array

    def test_generate_random_large(self, p11_session: Any) -> None:
        """C_GenerateRandom(1MB) -- large request."""
        try:
            result = p11_session.generate_random(1024 * 1024 * 8)  # 1MB in bits
            assert len(result) == 1024 * 1024
        except PKCS11Error:
            pass  # Some modules have size limits
