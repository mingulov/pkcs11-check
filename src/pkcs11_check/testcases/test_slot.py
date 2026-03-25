"""Tests for PKCS#11 slot, token, and session management."""
from __future__ import annotations
from typing import Any
import pytest
from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.recipes import generate_random, get_mechanism_list

pytestmark = pytest.mark.smoke


class TestSessionManagement:
    def test_session_is_open(self, p11_raw_session: Any) -> None:
        """Session is usable after fixture setup."""
        rs = p11_raw_session
        assert rs.sh != 0

    def test_generate_random(self, p11_raw_session: Any) -> None:
        """Generate random bytes via the session."""
        rs = p11_raw_session
        random_bytes = generate_random(rs.raw, rs.sh, 32)
        assert len(random_bytes) == 32
        assert random_bytes != bytes(32)

    def test_generate_random_different_each_time(self, p11_raw_session: Any) -> None:
        """Two random generations should differ."""
        rs = p11_raw_session
        r1 = generate_random(rs.raw, rs.sh, 32)
        r2 = generate_random(rs.raw, rs.sh, 32)
        assert r1 != r2


class TestMechanismDiscovery:
    def test_slot_has_mechanisms(self, p11_raw_session: Any) -> None:
        """Slot reports available mechanisms."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechanisms) > 0

    def test_aes_mechanism_available(self, p11_raw_session: Any) -> None:
        """AES should be available on any reasonable PKCS#11 module."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        aes_mechs = [m for m in mechanisms if "AES" in MECHANISM_NAMES.get(m, "")]
        assert len(aes_mechs) > 0, "No AES mechanisms found"

    def test_rsa_mechanism_available(self, p11_raw_session: Any) -> None:
        """RSA should be available on any reasonable PKCS#11 module."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        rsa_mechs = [m for m in mechanisms if "RSA" in MECHANISM_NAMES.get(m, "")]
        assert len(rsa_mechs) > 0, "No RSA mechanisms found"
