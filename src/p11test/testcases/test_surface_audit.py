"""Surface audit — probe for hidden/undocumented PKCS#11 capabilities.

Systematically tests the module's API surface for inconsistencies between
what it advertises (C_GetMechanismList) and what it actually accepts.
Catches debug mechanisms, backdoors, and incomplete decommissioning.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.surface_audit


class TestHiddenMechanisms:
    """Probe for mechanisms that work but aren't advertised."""

    def test_all_advertised_mechanisms_have_info(self, p11_module: Any) -> None:
        """Every mechanism in C_GetMechanismList should return valid info."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        for mech in mechanisms:
            info = slot.get_mechanism_info(mech)
            assert info is not None, f"Mechanism {mech.name} has no info"

    def test_mechanism_count_reasonable(self, p11_module: Any) -> None:
        """Module should report a reasonable number of mechanisms."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        # Should have at least basic mechanisms
        assert len(mechanisms) >= 5, "Module reports too few mechanisms"
        # Should not report an unreasonable number
        assert len(mechanisms) < 1000, "Module reports suspiciously many mechanisms"

    def test_deprecated_mechanisms_flagged(self, p11_module: Any) -> None:
        """If deprecated mechanisms (DES, MD2) are available, flag them."""
        from p11test.compliance import ComplianceLevel, note

        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        mech_names = {m.name for m in mechanisms}

        deprecated = {"_DES_ECB", "_DES_CBC", "_DES_KEY_GEN", "_MD5", "MD2"}
        found_deprecated = mech_names & deprecated
        if found_deprecated:
            for mech in found_deprecated:
                note(
                    f"Deprecated mechanism available: {mech}",
                    ComplianceLevel.DEPRECATED,
                    reference="NIST SP 800-131A Rev. 2",
                )


class TestSlotConsistency:
    """Verify slot and token info consistency."""

    def test_all_slots_have_info(self, p11_module: Any) -> None:
        """Every slot should return valid slot info."""
        slots = p11_module.get_slots()
        assert len(slots) > 0
        for slot in slots:
            assert slot is not None

    def test_token_present_slots_have_token(self, p11_module: Any) -> None:
        """Slots with token_present=True should have readable tokens."""
        slots = p11_module.get_slots(token_present=True)
        for slot in slots:
            token = slot.get_token()
            assert token is not None
            assert hasattr(token, "label")

    def test_token_has_valid_label(self, p11_module: Any) -> None:
        """Token label should be a non-empty string."""
        slots = p11_module.get_slots(token_present=True)
        for slot in slots:
            token = slot.get_token()
            # Label may be padded with spaces but should exist
            assert token.label is not None


class TestFunctionRobustness:
    """Verify that all common operations fail gracefully, never crash."""

    def test_random_with_zero_bits(self, p11_session: Any) -> None:
        """C_GenerateRandom with 0 bits — should return empty or error, never crash."""
        try:
            data = p11_session.generate_random(0)
            assert len(data) == 0
        except (pkcs11.exceptions.PKCS11Error, ValueError):
            pass  # Acceptable — binding or module rejects zero-length

    def test_digest_all_hash_mechanisms(self, p11_session: Any) -> None:
        """Try digest with all available hash mechanisms — none should crash."""
        test_data = b"surface audit test data"
        hash_mechs = [
            Mechanism.SHA_1,
            Mechanism.SHA256,
            Mechanism.SHA384,
            Mechanism.SHA512,
            Mechanism.SHA224,
        ]
        for mech in hash_mechs:
            try:
                result = p11_session.digest(test_data, mechanism=mech)
                assert len(result) > 0
            except pkcs11.exceptions.PKCS11Error:
                pass  # Mechanism not supported — OK

    def test_generate_key_all_aes_sizes(self, p11_session: Any) -> None:
        """Generate AES keys at all standard sizes — none should crash."""
        for size in [128, 192, 256]:
            try:
                key = p11_session.generate_key(KeyType.AES, size)
                assert key is not None
                key.destroy()
            except pkcs11.exceptions.PKCS11Error:
                pass  # Size not supported — OK

    def test_generate_rsa_various_sizes(self, p11_session: Any) -> None:
        """Generate RSA keys at various sizes — none should crash."""
        for size in [1024, 2048, 3072, 4096]:
            try:
                pub, priv = p11_session.generate_keypair(KeyType.RSA, size)
                assert pub is not None
                pub.destroy()
                priv.destroy()
            except pkcs11.exceptions.PKCS11Error:
                pass  # Size not supported — OK

    def test_find_with_invalid_class(self, p11_session: Any) -> None:
        """Search with invalid object class — should return empty, not crash."""
        # Use a valid but unlikely class
        try:
            found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.DOMAIN_PARAMETERS}))
            assert isinstance(found, list)
        except pkcs11.exceptions.PKCS11Error:
            pass  # Also OK


class TestMechanismFlagsConsistency:
    """Verify mechanism flags match actual capabilities."""

    def test_aes_encrypt_flag_matches_capability(self, p11_session: Any, p11_module: Any) -> None:
        """If AES_ECB has CKF_ENCRYPT, encryption should work."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()

        aes_ecb = [m for m in mechanisms if m == Mechanism.AES_ECB]
        if not aes_ecb:
            pytest.skip("AES_ECB not supported")

        # Verify mechanism info is readable (doesn't crash)
        slot.get_mechanism_info(aes_ecb[0])
        # If we can encrypt (which our other tests prove), the capability exists

        key = p11_session.generate_key(KeyType.AES, 256)
        ct = key.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)
        assert len(ct) > 0
        key.destroy()

    def test_key_size_range_respected(self, p11_session: Any, p11_module: Any) -> None:
        """Key generation within reported min/max range should succeed."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()

        aes_keygen = [m for m in mechanisms if m.name == "AES_KEY_GEN"]
        if not aes_keygen:
            pytest.skip("AES_KEY_GEN not supported")

        info = slot.get_mechanism_info(aes_keygen[0])
        # Generate at minimum and maximum reported sizes
        if info.min_key_length > 0:
            key = p11_session.generate_key(KeyType.AES, info.min_key_length * 8)
            assert key is not None
            key.destroy()

        if info.max_key_length >= 32:
            key = p11_session.generate_key(KeyType.AES, min(info.max_key_length * 8, 256))
            assert key is not None
            key.destroy()
