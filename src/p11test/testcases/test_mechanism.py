"""Tests for PKCS#11 mechanism discovery and info retrieval."""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Mechanism


class TestMechanismInfo:
    def test_mechanism_info_has_key_sizes(self, p11_module: Any) -> None:
        """Mechanism info reports min/max key sizes."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        assert len(mechanisms) > 0
        for mech in mechanisms:
            info = slot.get_mechanism_info(mech)
            assert info.min_key_length >= 0
            assert info.max_key_length >= info.min_key_length
            break

    def test_all_mechanisms_have_info(self, p11_module: Any) -> None:
        """Every reported mechanism returns valid info."""
        slot = p11_module.get_slots(token_present=True)[0]
        for mech in slot.get_mechanisms():
            info = slot.get_mechanism_info(mech)
            assert info is not None

    def test_aes_key_sizes(self, p11_module: Any) -> None:
        """AES mechanism reports correct key size range."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        aes_cbc = [m for m in mechanisms if m == Mechanism.AES_CBC]
        if not aes_cbc:
            pytest.skip("AES_CBC not supported")
        info = slot.get_mechanism_info(aes_cbc[0])
        assert info.min_key_length <= 16  # 128 bits = 16 bytes
        assert info.max_key_length >= 32  # 256 bits = 32 bytes

    def test_rsa_key_sizes(self, p11_module: Any) -> None:
        """RSA mechanism reports reasonable key size range."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        rsa_pkcs = [m for m in mechanisms if m == Mechanism.RSA_PKCS]
        if not rsa_pkcs:
            pytest.skip("RSA_PKCS not supported")
        info = slot.get_mechanism_info(rsa_pkcs[0])
        assert info.min_key_length <= 2048
        assert info.max_key_length >= 2048


class TestMechanismCategories:
    def test_has_symmetric_mechanisms(self, p11_module: Any) -> None:
        """Module supports at least one symmetric cipher."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        symmetric = [m for m in mechanisms if "AES" in m.name or "DES" in m.name]
        assert len(symmetric) > 0

    def test_has_hash_mechanisms(self, p11_module: Any) -> None:
        """Module supports at least one hash mechanism."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        hashes = [m for m in mechanisms if "SHA" in m.name]
        assert len(hashes) > 0

    def test_has_asymmetric_mechanisms(self, p11_module: Any) -> None:
        """Module supports at least one asymmetric mechanism."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        asymmetric = [m for m in mechanisms if "RSA" in m.name or "EC" in m.name]
        assert len(asymmetric) > 0

    def test_mechanism_count_reasonable(self, p11_module: Any) -> None:
        """Module reports a reasonable number of mechanisms (>10)."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        assert len(mechanisms) > 10
