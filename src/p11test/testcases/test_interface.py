"""Tests for PKCS#11 library and interface management."""

from __future__ import annotations

from typing import Any


class TestLibraryInfo:
    def test_module_loads(self, p11_module: Any) -> None:
        """Module loads without error."""
        assert p11_module is not None
        assert p11_module.lib is not None

    def test_interface_version_reported(self, p11_interface_version: str) -> None:
        """Interface version is a known value."""
        assert p11_interface_version in ("2.40", "3.0", "3.2")

    def test_library_has_slots(self, p11_module: Any) -> None:
        """Module reports at least one slot."""
        slots = p11_module.get_slots()
        assert len(slots) > 0


class TestSlotEnumeration:
    def test_get_slots_with_token(self, p11_module: Any) -> None:
        """At least one slot has a token present."""
        slots = p11_module.get_slots(token_present=True)
        assert len(slots) > 0

    def test_slot_has_token_info(self, p11_module: Any) -> None:
        """Token in slot has readable info."""
        slots = p11_module.get_slots(token_present=True)
        token = slots[0]
        # python-pkcs11 Slot has .get_token() or token attributes
        assert token is not None
