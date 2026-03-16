"""Tests for PKCS#11 slot, token, and session management."""

from __future__ import annotations

from typing import Any

from p11test.testcases.conftest import mech_name


class TestSessionManagement:
    def test_session_is_open(self, p11_session: Any) -> None:
        """Session is usable after fixture setup."""
        assert p11_session is not None

    def test_generate_random(self, p11_session: Any) -> None:
        """Generate random bytes via the session."""
        random_bytes = p11_session.generate_random(256)
        assert len(random_bytes) == 32
        # Should not be all zeros (astronomically unlikely)
        assert random_bytes != bytes(32)

    def test_generate_random_different_each_time(self, p11_session: Any) -> None:
        """Two random generations should differ."""
        r1 = p11_session.generate_random(256)
        r2 = p11_session.generate_random(256)
        assert r1 != r2


class TestMechanismDiscovery:
    def test_slot_has_mechanisms(self, p11_module: Any) -> None:
        """Slot reports available mechanisms."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        assert len(mechanisms) > 0

    def test_aes_mechanism_available(self, p11_module: Any) -> None:
        """AES should be available on any reasonable PKCS#11 module."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        aes_mechs = [m for m in mechanisms if "AES" in mech_name(m)]
        assert len(aes_mechs) > 0, "No AES mechanisms found"

    def test_rsa_mechanism_available(self, p11_module: Any) -> None:
        """RSA should be available on any reasonable PKCS#11 module."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        rsa_mechs = [m for m in mechanisms if "RSA" in mech_name(m)]
        assert len(rsa_mechs) > 0, "No RSA mechanisms found"
