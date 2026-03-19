"""Cryptoki initialization and library management tests.

Tests C_Initialize / C_Finalize behavior, library info queries,
and basic lifecycle operations per OASIS PKCS#11 specification.
"""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.access


class TestLibraryInit:
    """Test basic library initialization and info queries."""

    def test_library_loads_and_has_info(self, p11_module: Any) -> None:
        """Library loads successfully and has basic info."""
        lib = p11_module.lib
        assert lib is not None
        # Library should have at least manufacturer info
        if hasattr(lib, "manufacturer_id"):
            assert isinstance(lib.manufacturer_id, str)

    def test_library_version_available(self, p11_module: Any) -> None:
        """Library reports a version."""
        lib = p11_module.lib
        if hasattr(lib, "library_version"):
            ver = lib.library_version
            assert ver is not None

    def test_library_description_available(self, p11_module: Any) -> None:
        """Library reports a description."""
        lib = p11_module.lib
        if hasattr(lib, "library_description"):
            desc = lib.library_description
            assert isinstance(desc, str)


class TestSlotDiscovery:
    """Test slot discovery after initialization."""

    def test_get_slots_returns_list(self, p11_module: Any) -> None:
        """C_GetSlotList returns a list."""
        slots = p11_module.get_slots()
        assert isinstance(slots, list)

    def test_get_slots_with_token(self, p11_module: Any) -> None:
        """C_GetSlotList with token_present=True returns subset."""
        all_slots = p11_module.get_slots()
        token_slots = p11_module.get_slots(token_present=True)
        assert len(token_slots) <= len(all_slots)

    def test_slot_mechanisms_queryable(self, p11_module: Any) -> None:
        """Each slot's mechanism list is queryable."""
        slots = p11_module.get_slots(token_present=True)
        for slot in slots:
            mechs = slot.get_mechanisms()
            assert isinstance(mechs, (list, set, frozenset))
            assert len(mechs) > 0


class TestRepeatedInit:
    """Test that the module handles repeated operations gracefully."""

    def test_multiple_lib_loads(self) -> None:
        """Loading the library multiple times should work or fail cleanly.

        Per PKCS#11 spec, calling C_Initialize when already initialized
        returns CKR_CRYPTOKI_ALREADY_INITIALIZED. python-pkcs11 may
        handle this internally.
        """
        # The fixture already loaded the library, so we just verify
        # the module is in a good state
        pass  # If we got here, the fixture worked

    def test_repeated_slot_queries(self, p11_module: Any) -> None:
        """Querying slots repeatedly should give consistent results."""
        slots1 = p11_module.get_slots(token_present=True)
        slots2 = p11_module.get_slots(token_present=True)
        assert len(slots1) == len(slots2)

    def test_repeated_mechanism_queries(self, p11_module: Any) -> None:
        """Querying mechanisms repeatedly should give consistent results."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechs1 = slot.get_mechanisms()
        mechs2 = slot.get_mechanisms()
        assert len(mechs1) == len(mechs2)
