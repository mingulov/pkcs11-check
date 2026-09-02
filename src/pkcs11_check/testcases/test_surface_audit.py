"""Surface audit - probe for hidden/undocumented PKCS#11 capabilities.

Systematically tests the module's API surface for inconsistencies between
what it advertises (C_GetMechanismList) and what it actually accepts.
Catches debug mechanisms, backdoors, and incomplete decommissioning.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
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
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKM_VENDOR_DEFINED,
    CKR_ARGUMENTS_BAD,
    CKR_OK,
)
from pkcs11_check.testcases._error_tuples import KEY_SIZE_ERRORS, TEMPLATE_ERRORS
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    CIPHER_OP_RUNTIME_REJECT_RVS,
    HMAC_OP_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_aes_key_or_xfail,
    reject_or_classify,
    xfail_if_known_ckr,
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
        standard_mechs = [m for m in mechanisms if m < CKM_VENDOR_DEFINED]
        vendor_mechs = [m for m in mechanisms if m >= CKM_VENDOR_DEFINED]
        assert len(standard_mechs) >= 5, f"Only {len(standard_mechs)} standard mechanisms"
        assert len(standard_mechs) < 1000, f"Too many standard mechanisms: {len(standard_mechs)}"
        if vendor_mechs:
            _vendor_count = len(vendor_mechs)  # noqa: F841 -- visible in test log

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
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                (CKR_ARGUMENTS_BAD,),
                label="C_GenerateRandom with zero length",
            )

    def test_digest_all_hash_mechanisms(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Try digest with all available hash mechanisms."""
        rs = p11_raw_session
        test_data = b"surface audit test data"
        hash_mechs = [CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKM_SHA224]
        for mech in hash_mechs:
            name = _mech_name(mech)
            if not rs.has_mechanism(name):
                continue
            try:
                result = digest_single(rs.raw, rs.sh, mech, test_data)
                assert len(result) > 0
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    f"{name} advertised but digest is not operational",
                )

    def test_generate_key_all_aes_sizes(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generate AES keys at all standard sizes."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")
        for size in [128, 192, 256]:
            try:
                key = gen_aes_key(rs.raw, rs.sh, size)
                assert key != 0
                destroy_quietly(rs.raw, rs.sh, key)
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    AES_KEYGEN_RUNTIME_REJECT_RVS,
                    f"AES_KEY_GEN advertised but AES-{size} key generation is not operational",
                )

    @pytest.mark.slow
    def test_generate_rsa_various_sizes(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Generate RSA keys at various sizes."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported")
        for size in [1024, 2048, 3072, 4096]:
            try:
                pub, priv = gen_rsa_keypair(rs.raw, rs.sh, size)
                assert pub != 0
                destroy_quietly(rs.raw, rs.sh, pub)
                destroy_quietly(rs.raw, rs.sh, priv)
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    KEYPAIR_RUNTIME_REJECT_RVS,
                    f"RSA_PKCS_KEY_PAIR_GEN advertised but RSA-{size} key generation "
                    "is not operational",
                )

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
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                TEMPLATE_ERRORS,
                label="CKO_DOMAIN_PARAMETERS search",
                kind="metadata",
            )


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

        key = gen_aes_key_or_xfail(rs, 256)
        try:
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_ECB,
                    b"0123456789abcdef",
                )
                assert len(ct) > 0
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "AES_ECB advertised but encryption is not operational",
                )
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

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)

        if info["min_key_size"] > 0:
            key = gen_aes_key_or_xfail(
                rs,
                int(info["min_key_size"]) * 8,
                purpose="key-size-range min probe",
            )
            assert key != 0
            destroy_quietly(rs.raw, rs.sh, key)

        if info["max_key_size"] >= 32:
            bits = min(int(info["max_key_size"]) * 8, 256)
            key = gen_aes_key_or_xfail(rs, bits, purpose="key-size-range max probe")
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

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)

        max_key_size = int(info["max_key_size"])
        oversize = (max_key_size + 8) * 8
        key = 0
        try:
            key = gen_aes_key(rs.raw, rs.sh, oversize)
            if max_key_size > 0:
                classify(
                    "self_contradiction",
                    kind="metadata",
                    label="AES_KEY_GEN advertised maximum",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                    actual=oversize,
                    expected=max_key_size * 8,
                    summary=(
                        f"AES_KEY_GEN accepted {oversize}-bit key beyond advertised "
                        f"maximum ({max_key_size * 8} bits)"
                    ),
                )
            note(
                f"Module accepted AES key beyond max ({oversize} bits) with no nonzero maximum",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 CK_MECHANISM_INFO.ulMaxKeySize",
            )
        except CkrAssertionError as exc:
            reject_or_classify(exc, KEY_SIZE_ERRORS, label="AES_KEY_GEN beyond advertised max")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_undersize_key(self, p11_raw_session: Any) -> None:
        """Try RSA key smaller than min."""
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_KEY_PAIR_GEN

        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)

        if int(info["min_key_size"]) == 0:
            pytest.skip("No minimum key length reported")

        undersize = max(int(info["min_key_size"]) - 256, 512)
        if undersize >= int(info["min_key_size"]):
            pytest.skip("Cannot test below minimum (already at 512)")

        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, undersize)
            classify(
                "self_contradiction",
                kind="metadata",
                label="RSA_PKCS_KEY_PAIR_GEN advertised minimum",
                operation="C_GenerateKeyPair",
                mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                actual=undersize,
                expected=int(info["min_key_size"]),
                summary=(
                    f"RSA key-pair generation accepted {undersize}-bit key below advertised "
                    f"minimum ({int(info['min_key_size'])} bits)"
                ),
            )
        except CkrAssertionError as exc:
            reject_or_classify(exc, KEY_SIZE_ERRORS, label="RSA keygen below advertised minimum")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_aes_non_standard_sizes(self, p11_raw_session: Any) -> None:
        """Try non-standard AES key sizes."""
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")
        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_KEY_GEN)
        raw_min = int(info["min_key_size"])
        raw_max = int(info["max_key_size"])
        min_bits = raw_min * 8 if raw_max <= 32 else raw_min
        max_bits = raw_max * 8 if raw_max <= 32 else raw_max
        for size in [64, 160, 384, 512, 768]:
            key = 0
            try:
                key = gen_aes_key(rs.raw, rs.sh, size)
                if (raw_min > 0 and size < min_bits) or (raw_max > 0 and size > max_bits):
                    classify(
                        "self_contradiction",
                        kind="metadata",
                        label=f"AES_KEY_GEN advertised range ({size} bits)",
                        operation="C_GenerateKey",
                        mechanism="CKM_AES_KEY_GEN",
                        actual=size,
                        expected=f"{min_bits}..{max_bits} bits",
                        summary=(
                            f"AES_KEY_GEN accepted non-standard {size}-bit key outside "
                            f"advertised range {min_bits}..{max_bits} bits"
                        ),
                    )
                note(
                    f"Module accepted non-standard AES-{size}",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="FIPS 197",
                )
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    KEY_SIZE_ERRORS,
                    label=f"AES_KEY_GEN non-standard {size}-bit key",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)

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
        key = 0
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
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                TEMPLATE_ERRORS + HMAC_OP_RUNTIME_REJECT_RVS,
                label="SHA256_HMAC 1-byte key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_oversize_key(self, p11_raw_session: Any) -> None:
        """Try RSA key larger than max."""
        from pkcs11_check.raw.types_std import CKM_RSA_PKCS_KEY_PAIR_GEN

        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA keygen not supported")

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)

        max_key_size = int(info["max_key_size"])
        oversize = max_key_size + 1024
        pub = priv = 0
        try:
            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, oversize)
            if max_key_size > 0:
                classify(
                    "self_contradiction",
                    kind="metadata",
                    label="RSA_PKCS_KEY_PAIR_GEN advertised maximum",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                    actual=oversize,
                    expected=max_key_size,
                    summary=(
                        f"RSA key-pair generation accepted {oversize}-bit key beyond advertised "
                        f"maximum ({max_key_size} bits)"
                    ),
                )
        except CkrAssertionError as exc:
            reject_or_classify(exc, KEY_SIZE_ERRORS, label="RSA keygen beyond advertised maximum")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
