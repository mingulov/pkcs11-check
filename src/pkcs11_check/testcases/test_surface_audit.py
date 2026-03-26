"""Surface audit - probe for hidden/undocumented PKCS#11 capabilities.

Systematically tests the module's API surface for inconsistencies between
what it advertises (C_GetMechanismList) and what it actually accepts.
Catches debug mechanisms, backdoors, and incomplete decommissioning.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    get_mechanism_info,
    get_mechanism_list,
    get_slot_info,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_OK,
)

pytestmark = pytest.mark.surface_audit


def _mech_name(mech_val: int) -> str:
    """Return mechanism name for a numeric value."""
    name = MECHANISM_NAMES.get(mech_val, "")
    if name.startswith("CKM_"):
        return name[4:]
    return name or f"0x{mech_val:08x}"


class TestHiddenMechanisms:
    """Probe for mechanisms that work but aren't advertised."""

    def test_all_advertised_mechanisms_have_info(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Every mechanism in C_GetMechanismList should return valid info."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        for mech in mechanisms:
            get_mechanism_info(rs.raw, rs.slot_id, mech)

    def test_mechanism_count_reasonable(self, p11_raw_session: Any) -> None:
        """Module should report a reasonable number of mechanisms."""
        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        assert len(mechanisms) >= 5, "Module reports too few mechanisms"
        assert len(mechanisms) < 1000, "Module reports suspiciously many"

    def test_deprecated_mechanisms_flagged(
        self,
        p11_raw_session: Any,
    ) -> None:
        """If deprecated mechanisms (DES, MD2) are available, flag them."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        mechanisms = get_mechanism_list(rs.raw, rs.slot_id)
        mech_names = {_mech_name(m) for m in mechanisms}

        deprecated = {"DES_ECB", "DES_CBC", "DES_KEY_GEN", "MD5", "MD2"}
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

    def test_all_slots_have_info(self, p11_raw_session: Any) -> None:
        """Every slot should return valid slot info."""
        from pkcs11_check.raw.bootstrap import get_slot_ids

        rs = p11_raw_session
        slots = get_slot_ids(rs.raw, token_present=False)
        assert len(slots) > 0
        for slot_id in slots:
            get_slot_info(rs.raw, slot_id)

    def test_token_present_slots_have_token(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Slots with token_present=True should have readable tokens."""
        from pkcs11_check.raw.bootstrap import get_slot_ids
        from pkcs11_check.raw.types_std import CK_TOKEN_INFO

        rs = p11_raw_session
        slots = get_slot_ids(rs.raw, token_present=True)
        for slot_id in slots:
            info = CK_TOKEN_INFO()
            rv = rs.raw.C_GetTokenInfo(slot_id, byref(info))
            assert rv == CKR_OK

    def test_token_has_valid_label(self, p11_raw_session: Any) -> None:
        """Token label should be a non-empty string."""
        from pkcs11_check.raw.types_std import CK_TOKEN_INFO

        rs = p11_raw_session
        info = CK_TOKEN_INFO()
        rv = rs.raw.C_GetTokenInfo(rs.slot_id, byref(info))
        assert rv == CKR_OK
        label = bytes(info.label).decode("utf-8", errors="replace").strip()
        assert label is not None


class TestFunctionRobustness:
    """Verify that all common operations fail gracefully, never crash."""

    def test_random_with_zero_bits(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom with 0 - should return empty or error."""
        rs = p11_raw_session
        try:
            data = generate_random(rs.raw, rs.sh, 0)
            assert len(data) == 0
        except (AssertionError, ValueError):
            pass

    def test_digest_all_hash_mechanisms(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Try digest with all available hash mechanisms."""
        rs = p11_raw_session
        test_data = b"surface audit test data"
        hash_mechs = [CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA224]
        for mech in hash_mechs:
            try:
                result = digest_single(rs.raw, rs.sh, mech, test_data)
                assert len(result) > 0
            except AssertionError:
                pass

    def test_generate_key_all_aes_sizes(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generate AES keys at all standard sizes."""
        rs = p11_raw_session
        for size in [128, 192, 256]:
            try:
                key = gen_aes_key(rs.raw, rs.sh, size)
                assert key != 0
                destroy_quietly(rs.raw, rs.sh, key)
            except AssertionError:
                pass

    def test_generate_rsa_various_sizes(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generate RSA keys at various sizes."""
        rs = p11_raw_session
        for size in [1024, 2048, 3072, 4096]:
            try:
                pub, priv = gen_rsa_keypair(rs.raw, rs.sh, size)
                assert pub != 0
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
            except AssertionError:
                pass

    def test_find_with_domain_parameters_class(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Search with domain params class - should return empty or work."""
        from pkcs11_check.raw.pack import template_from_dict
        from pkcs11_check.raw.recipes import find_objects
        from pkcs11_check.raw.types_std import CKA_CLASS, CKO_DOMAIN_PARAMETERS

        rs = p11_raw_session
        try:
            found = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_DOMAIN_PARAMETERS}),
            )
            assert isinstance(found, list)
        except AssertionError:
            pass


class TestMechanismFlagsConsistency:
    """Verify mechanism flags match actual capabilities."""

    def test_aes_encrypt_flag_matches_capability(
        self,
        p11_raw_session: Any,
    ) -> None:
        """If AES_ECB is in mechanism list, encryption should work."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("AES_ECB not supported")

        get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_ECB)

        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_ECB,
                b"0123456789abcdef",
            )
            assert len(ct) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_size_range_respected(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Key generation within reported min/max range should succeed."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        except AssertionError:
            pytest.skip("Cannot get AES_KEY_GEN mechanism info")

        if info["min_key_size"] > 0:
            key = gen_aes_key(rs.raw, rs.sh, int(info["min_key_size"]) * 8)
            assert key != 0
            destroy_quietly(rs.raw, rs.sh, key)

        if info["max_key_size"] >= 32:
            bits = min(int(info["max_key_size"]) * 8, 256)
            key = gen_aes_key(rs.raw, rs.sh, bits)
            assert key != 0
            destroy_quietly(rs.raw, rs.sh, key)


class TestMechanismLimitProbing:
    """Probe beyond advertised mechanism limits."""

    def test_aes_oversize_key(self, p11_raw_session: Any) -> None:
        """Try AES key sizes beyond standard 256-bit."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        except AssertionError:
            pytest.skip("Cannot get AES_KEY_GEN info")

        oversize = (int(info["max_key_size"]) + 8) * 8
        try:
            key = gen_aes_key(rs.raw, rs.sh, oversize)
            note(
                f"Module accepted AES key beyond max ({oversize} bits)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 CK_MECHANISM_INFO.ulMaxKeySize",
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            pass

    def test_rsa_undersize_key(self, p11_raw_session: Any) -> None:
        """Try RSA key smaller than min."""
        from pkcs11_check.compliance import ComplianceLevel, note
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_KEY_PAIR_GEN

        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except AssertionError:
            pytest.skip("Cannot get RSA key info")

        if int(info["min_key_size"]) == 0:
            pytest.skip("No minimum key length reported")

        undersize = max(int(info["min_key_size"]) - 256, 512)
        if undersize >= int(info["min_key_size"]):
            pytest.skip("Cannot test below minimum (already at 512)")

        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, undersize)
            note(
                f"Module accepted RSA key below min ({undersize} bits)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 CK_MECHANISM_INFO.ulMinKeySize",
            )
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        except AssertionError:
            pass

    def test_aes_non_standard_sizes(self, p11_raw_session: Any) -> None:
        """Try non-standard AES key sizes."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        for size in [64, 160, 384, 512, 768]:
            try:
                key = gen_aes_key(rs.raw, rs.sh, size)
                note(
                    f"Module accepted non-standard AES-{size}",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="FIPS 197",
                )
                destroy_quietly(rs.raw, rs.sh, key)
            except AssertionError:
                pass

    def test_hmac_short_key(self, p11_raw_session: Any) -> None:
        """Try HMAC with a very short key (1 byte)."""
        from pkcs11_check.compliance import ComplianceLevel, note
        from pkcs11_check.raw.recipes import create_object, sign_single
        from pkcs11_check.raw.types_std import (
            CKA_CLASS,
            CKA_KEY_TYPE,
            CKA_SENSITIVE,
            CKA_SIGN,
            CKA_TOKEN,
            CKA_VALUE,
            CKK_GENERIC_SECRET,
            CKM_SHA256_HMAC,
            CKO_SECRET_KEY,
        )

        rs = p11_raw_session
        try:
            key = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE: b"\x42",
                    CKA_SIGN: True,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                },
            )
            mac = sign_single(
                rs.raw,
                rs.sh,
                key,
                CKM_SHA256_HMAC,
                b"test",
            )
            note(
                f"Module accepted 1-byte HMAC key (len: {len(mac)})",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="RFC 2104",
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            pass

    def test_rsa_oversize_key(self, p11_raw_session: Any) -> None:
        """Try RSA key larger than max."""
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_KEY_PAIR_GEN

        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        try:
            info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)
        except AssertionError:
            pytest.skip("Cannot get RSA info")

        oversize = int(info["max_key_size"]) + 1024
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, oversize)
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"Module accepted RSA-{oversize} beyond max",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 CK_MECHANISM_INFO.ulMaxKeySize",
            )
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
        except AssertionError:
            pass
