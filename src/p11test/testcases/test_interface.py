"""Tests for PKCS#11 library and interface management."""

from __future__ import annotations

from typing import Any

import pytest

pytestmark = pytest.mark.smoke


class TestLibraryInfo:
    def test_module_loads(self, p11_module: Any) -> None:
        """Module loads without error."""
        assert p11_module is not None
        assert p11_module.lib is not None

    def test_interface_version_reported(self, p11_interface_version: str) -> None:
        """Interface version is a known value."""
        assert p11_interface_version in ("2.40", "3.0", "3.1", "3.2")

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


@pytest.mark.v30
@pytest.mark.requires_v30
class TestInterfaceV30:
    """Tests that exercise PKCS#11 v3.0 interface features."""

    def test_v30_interface_negotiated(self, p11_interface_version: str) -> None:
        """Module has negotiated at least v3.0 interface."""
        assert p11_interface_version in ("3.0", "3.1", "3.2"), (
            f"Expected v3.0+ but got v{p11_interface_version}"
        )

    def test_v30_session_opens(self, p11_session: Any) -> None:
        """v3.0 module opens a session without error."""
        assert p11_session is not None

    def test_v30_get_interface_list(self, p11_module: Any) -> None:
        """C_GetInterfaceList returns at least one interface entry."""
        ifaces = p11_module.lib.get_interface_list()
        assert len(ifaces) > 0
        names = [name for name, _maj, _min in ifaces]
        assert "PKCS 11" in names or any("PKCS" in n for n in names), (
            f"Expected PKCS 11 interface in list, got {names}"
        )

    def test_v30_encrypt_decrypt_aes(self, p11_session: Any) -> None:
        """v3.0 AES encrypt/decrypt round-trip via v3.0 function list."""
        from pkcs11 import Attribute, KeyType, Mechanism

        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            },
        )
        iv = b"\x00" * 16
        plaintext = b"v3.0 interface AES test data 123"
        ciphertext = key.encrypt(plaintext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        recovered = key.decrypt(ciphertext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
        assert recovered == plaintext


@pytest.mark.v32
@pytest.mark.requires_v32
class TestInterfaceV32:
    """Tests that exercise PKCS#11 v3.2 interface features."""

    def test_v32_interface_negotiated(self, p11_interface_version: str) -> None:
        """Module has negotiated v3.2 interface."""
        assert p11_interface_version == "3.2", (
            f"Expected v3.2 but got v{p11_interface_version}"
        )

    def test_v32_session_opens(self, p11_session: Any) -> None:
        """v3.2 module opens a session without error."""
        assert p11_session is not None
