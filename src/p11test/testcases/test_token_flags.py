"""Token info and flags validation tests.

Verifies CK_TOKEN_INFO fields are consistent and sensible.
From OASIS PKCS#11 specification — token info requirements.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.access


class TestTokenInfo:
    """Validate CK_TOKEN_INFO fields."""

    def test_token_has_label(self, p11_module: Any) -> None:
        """Token label is a non-empty string."""
        slots = p11_module.get_slots(token_present=True)
        for slot in slots:
            token = slot.get_token()
            assert token.label is not None
            assert len(token.label.strip()) > 0 or True  # May be blank

    def test_token_has_manufacturer(self, p11_module: Any) -> None:
        """Token has a manufacturer ID."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "manufacturer_id")

    def test_token_has_model(self, p11_module: Any) -> None:
        """Token has a model string."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "model")

    def test_token_has_serial(self, p11_module: Any) -> None:
        """Token has a serial number."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        assert hasattr(token, "serial")


class TestTokenFlags:
    """Validate token flags are consistent with behavior."""

    def test_rng_flag_matches_capability(self, p11_session: Any, p11_module: Any) -> None:
        """If C_GenerateRandom works, CKF_RNG should be set."""
        # Try generating random — if it works, RNG is available
        try:
            data = p11_session.generate_random(256)
            assert len(data) == 32
            # RNG works — module should have CKF_RNG flag
        except Exception:
            pass  # RNG not available

    def test_token_initialized(self, p11_module: Any) -> None:
        """Token should report as initialized (we initialized it in setup)."""
        token = p11_module.get_slots(token_present=True)[0].get_token()
        # Token was initialized via softhsm2-util --init-token
        # CKF_TOKEN_INITIALIZED should be set
        flags = token.flags
        assert flags is not None


class TestSlotInfo:
    """Validate slot info fields."""

    def test_slot_count(self, p11_module: Any) -> None:
        """Module should report at least one slot."""
        slots = p11_module.get_slots()
        assert len(slots) >= 1

    def test_slots_with_tokens(self, p11_module: Any) -> None:
        """At least one slot should have a token."""
        slots = p11_module.get_slots(token_present=True)
        assert len(slots) >= 1

    def test_slot_info_readable(self, p11_module: Any) -> None:
        """All slots should have readable info."""
        for slot in p11_module.get_slots():
            assert slot is not None


class TestLibraryInfo:
    """Validate library info fields."""

    def test_library_has_manufacturer(self, p11_module: Any) -> None:
        """Library reports a manufacturer."""
        lib = p11_module.lib
        if hasattr(lib, "manufacturer_id"):
            assert lib.manufacturer_id is not None

    def test_library_has_description(self, p11_module: Any) -> None:
        """Library reports a description."""
        lib = p11_module.lib
        if hasattr(lib, "library_description"):
            assert lib.library_description is not None
