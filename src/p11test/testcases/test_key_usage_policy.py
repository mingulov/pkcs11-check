"""Key usage policy enforcement tests.

Verifies that PKCS#11 modules enforce CKA_ENCRYPT, CKA_DECRYPT,
CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP capability flags.

python-pkcs11 enforces capabilities at the wrapper level: a key
generated without ENCRYPT capability won't have an encrypt() method.
These tests verify that enforcement and the flag consistency.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.security


class TestAESKeyUsagePolicy:
    """Test AES key capability enforcement."""

    def test_encrypt_only_key_has_no_decrypt(self, p11_session: Any) -> None:
        """AES key with ENCRYPT=True, DECRYPT=False has no decrypt method."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: False,
                Attribute.SIGN: False,
                Attribute.VERIFY: False,
            },
        )
        # encrypt method should exist
        assert hasattr(key, "encrypt")
        data = b"\x00" * 16
        ct = key.encrypt(data, mechanism=Mechanism.AES_ECB)
        assert len(ct) == 16

        # decrypt method should NOT exist
        assert not hasattr(key, "decrypt"), "Key with DECRYPT=False should not have decrypt method"

    def test_decrypt_only_key_has_no_encrypt(self, p11_session: Any) -> None:
        """AES key with DECRYPT=True, ENCRYPT=False has no encrypt method."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: False,
                Attribute.DECRYPT: True,
                Attribute.SIGN: False,
                Attribute.VERIFY: False,
            },
        )
        assert hasattr(key, "decrypt")
        assert not hasattr(key, "encrypt"), "Key with ENCRYPT=False should not have encrypt method"

    def test_sign_only_key_has_no_encrypt(self, p11_session: Any) -> None:
        """Key with SIGN=True but ENCRYPT=False has no encrypt."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.ENCRYPT: False,
                Attribute.DECRYPT: False,
            },
        )
        assert hasattr(key, "sign")
        assert not hasattr(key, "encrypt")

    def test_full_capabilities_key_has_all_methods(self, p11_session: Any) -> None:
        """Key with all capabilities has encrypt, decrypt, sign, verify."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
            },
        )
        assert hasattr(key, "encrypt")
        assert hasattr(key, "decrypt")
        assert hasattr(key, "sign")
        assert hasattr(key, "verify")
        assert hasattr(key, "wrap_key")
        assert hasattr(key, "unwrap_key")


class TestRSAKeyUsagePolicy:
    """Test RSA key capability enforcement."""

    def test_sign_only_rsa_has_no_encrypt(self, p11_session: Any, p11_module: Any) -> None:
        """RSA key pair generated for signing only has no encrypt."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={
                Attribute.ENCRYPT: False,
                Attribute.VERIFY: True,
                Attribute.WRAP: False,
            },
            private_template={
                Attribute.DECRYPT: False,
                Attribute.SIGN: True,
                Attribute.UNWRAP: False,
            },
        )

        # Sign should work
        assert hasattr(priv, "sign")
        assert hasattr(pub, "verify")

        # Encrypt should not be available
        assert not hasattr(pub, "encrypt"), "PublicKey with ENCRYPT=False should not have encrypt"
        assert not hasattr(priv, "decrypt"), "PrivateKey with DECRYPT=False should not have decrypt"

    def test_encrypt_only_rsa_has_no_sign(self, p11_session: Any, p11_module: Any) -> None:
        """RSA key pair generated for encryption only has no sign."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: False,
                Attribute.WRAP: False,
            },
            private_template={
                Attribute.DECRYPT: True,
                Attribute.SIGN: False,
                Attribute.UNWRAP: False,
            },
        )

        assert hasattr(pub, "encrypt")
        assert hasattr(priv, "decrypt")
        assert not hasattr(priv, "sign"), "PrivateKey with SIGN=False should not have sign"
        assert not hasattr(pub, "verify"), "PublicKey with VERIFY=False should not have verify"


class TestCapabilityReadback:
    """Verify capability flags are readable and consistent."""

    def test_aes_capabilities_match_template(self, p11_session: Any) -> None:
        """Generated key's capability flags match what was requested."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: False,
                Attribute.SIGN: False,
                Attribute.VERIFY: False,
                Attribute.WRAP: False,
                Attribute.UNWRAP: False,
            },
        )
        assert key[Attribute.ENCRYPT] is True
        assert key[Attribute.DECRYPT] is False
        assert key[Attribute.SIGN] is False

    def test_rsa_capabilities_match_template(self, p11_session: Any, p11_module: Any) -> None:
        """RSA keypair flags match what was requested."""
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={Attribute.ENCRYPT: True, Attribute.VERIFY: False},
            private_template={Attribute.DECRYPT: True, Attribute.SIGN: False},
        )
        assert pub[Attribute.ENCRYPT] is True
        assert pub[Attribute.VERIFY] is False
        assert priv[Attribute.DECRYPT] is True
        assert priv[Attribute.SIGN] is False
