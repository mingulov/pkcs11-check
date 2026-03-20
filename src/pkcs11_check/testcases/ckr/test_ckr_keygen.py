"""CKR compliance tests for C_GenerateKey and C_GenerateKeyPair.

Source: PKCS#11 v3.1 §5.14.1 (C_GenerateKey), §5.14.2 (C_GenerateKeyPair).
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import PKCS11Error

from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEYGEN, assert_ckr
from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access


class TestGenerateKeyErrors:
    """Error conditions for C_GenerateKey (§5.14.1)."""

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for keygen -> CKR_MECHANISM_INVALID."""
        try:
            p11_session.generate_key(KeyType.AES, 256, mechanism=Mechanism.SHA256)
            pytest.fail("Should have rejected SHA256 as key generation mechanism")
        except PKCS11Error as e:
            # Broad catch intentional — assert_ckr validates the specific type
            assert_ckr(CKR_KEYGEN["genkey_mechanism_invalid"], e, ckr_strict)

    def test_bad_key_size_zero(self, p11_session: Any, ckr_strict: bool) -> None:
        """AES key size 0 -> CKR_ATTRIBUTE_VALUE_INVALID."""
        exp = CKR_KEYGEN["genkey_bad_size"]
        try:
            p11_session.generate_key(KeyType.AES, 0)
            # Module accepted invalid key size — compliance deviation
            if not exp.allow_success:
                pytest.fail("Should have rejected AES key size 0")
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "C_GenerateKey accepted AES key size 0",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

    def test_bad_key_size_non_standard(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """AES key size 100 (not 128/192/256) -> CKR_ATTRIBUTE_VALUE_INVALID."""
        exp = CKR_KEYGEN["genkey_bad_size"]
        try:
            p11_session.generate_key(KeyType.AES, 100)
            if not exp.allow_success:
                pytest.fail("Should have rejected AES key size 100")
            from pkcs11_check.compliance import ComplianceLevel, note
            note(
                "C_GenerateKey accepted AES key size 100 (non-standard)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

    def test_template_inconsistent(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """SENSITIVE=False + EXTRACTABLE=False -> CKR_TEMPLATE_INCONSISTENT.

        A key that is both non-sensitive and non-extractable is contradictory
        in some modules. Others may accept it.
        """
        exp = CKR_KEYGEN["genkey_template_inconsistent"]
        try:
            p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: False,
                    Attribute.PRIVATE: True,
                },
            )
            # Some modules accept this — it's a spec grey area
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)


class TestGenerateKeyPairErrors:
    """Error conditions for C_GenerateKeyPair (§5.14.2)."""

    def test_bad_rsa_size_zero(self, p11_session: Any, ckr_strict: bool) -> None:
        """RSA key size 0 -> CKR_ATTRIBUTE_VALUE_INVALID."""
        try:
            p11_session.generate_keypair(KeyType.RSA, 0)
            pytest.fail("Should have rejected RSA key size 0")
        except PKCS11Error as e:
            assert_ckr(CKR_KEYGEN["genkeypair_bad_size"], e, ckr_strict)

    def test_bad_rsa_size_tiny(self, p11_session: Any, ckr_strict: bool) -> None:
        """RSA key size 64 (too small) -> reject."""
        try:
            p11_session.generate_keypair(KeyType.RSA, 64)
            pytest.fail("Should have rejected RSA key size 64")
        except PKCS11Error as e:
            assert_ckr(CKR_KEYGEN["genkeypair_bad_size"], e, ckr_strict)

    def test_mechanism_invalid(self, p11_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for keypair gen -> CKR_MECHANISM_INVALID."""
        try:
            p11_session.generate_keypair(KeyType.RSA, 2048, mechanism=Mechanism.AES_ECB)
            pytest.fail("Should have rejected AES_ECB for RSA keypair generation")
        except PKCS11Error as e:
            assert_ckr(CKR_KEYGEN["genkeypair_mechanism_invalid"], e, ckr_strict)

    def test_ec_curve_not_supported(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """EC keygen with unsupported/invalid curve -> CKR_CURVE_NOT_SUPPORTED."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")

        # Use a bogus OID that no module should support
        bogus_oid = bytes([0x06, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: bogus_oid},
            local=True,
        )
        try:
            params.generate_keypair()
            pytest.fail("Should have rejected bogus EC curve OID")
        except PKCS11Error as e:
            assert_ckr(CKR_KEYGEN["genkeypair_curve_not_supported"], e, ckr_strict)

    def test_attribute_type_invalid(
        self, p11_session: Any, ckr_strict: bool
    ) -> None:
        """Keygen with bogus attribute type -> CKR_ATTRIBUTE_TYPE_INVALID.

        python-pkcs11 may reject at wrapper level (NotImplementedError).
        """
        exp = CKR_KEYGEN["genkey_attribute_type_invalid"]
        try:
            p11_session.generate_key(
                KeyType.AES, 256,
                template={0xFFFFFFFF: True},  # Bogus attribute type
            )
            if not exp.allow_success:
                pytest.fail("Should have rejected bogus attribute type")
        except NotImplementedError:
            pass  # python-pkcs11 rejects before reaching module — acceptable
        except PKCS11Error as e:
            assert_ckr(exp, e, ckr_strict)

    def test_domain_params_invalid(
        self, p11_session: Any, p11_module: Any, ckr_strict: bool
    ) -> None:
        """EC keygen with malformed EC params -> CKR_DOMAIN_PARAMS_INVALID."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")
        # Malformed: valid OID header but truncated/corrupt content
        bad_params = bytes([0x06, 0x03, 0x00, 0x00, 0x00])
        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: bad_params},
            local=True,
        )
        try:
            params.generate_keypair()
            pytest.fail("Should have rejected malformed EC params")
        except PKCS11Error as e:
            assert_ckr(CKR_KEYGEN["genkeypair_domain_params_invalid"], e, ckr_strict)
