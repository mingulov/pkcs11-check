"""Classic Diffie-Hellman key agreement tests.

Tests CKM_DH_PKCS_KEY_PAIR_GEN, CKM_DH_PKCS_DERIVE, and
CKM_DH_PKCS_PARAMETER_GEN where supported.

Uses RFC 3526 Group 14 (2048-bit MODP) for known-good parameters.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# RFC 3526 Group 14 (2048-bit MODP) — widely supported safe prime.
DH_PRIME_2048 = bytes.fromhex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_GEN = bytes([0x02])


def _skip_no_dh(p11_module: Any) -> None:
    """Skip if DH mechanisms are not available."""
    if not has_mechanism(p11_module, "DH_PKCS_KEY_PAIR_GEN"):
        pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
    if not has_mechanism(p11_module, "DH_PKCS_DERIVE"):
        pytest.skip("CKM_DH_PKCS_DERIVE not supported")


class TestDHKeyAgreement:
    """Test DH key pair generation and key derivation."""

    def test_dh_keypair_generation(self, p11_session: Any, p11_module: Any) -> None:
        """Generate a DH keypair from known parameters."""
        _skip_no_dh(p11_module)

        params = p11_session.create_domain_parameters(
            KeyType.DH,
            {Attribute.PRIME: DH_PRIME_2048, Attribute.BASE: DH_GEN},
            local=True,
        )
        pub, priv = params.generate_keypair()
        assert pub is not None
        assert priv is not None

        # Public key value should be non-empty
        pub_value = pub[Attribute.VALUE]
        assert isinstance(pub_value, bytes)
        assert len(pub_value) > 0

    def test_dh_derive_shared_secret(self, p11_session: Any, p11_module: Any) -> None:
        """Alice and Bob derive the same shared AES key."""
        _skip_no_dh(p11_module)

        params = p11_session.create_domain_parameters(
            KeyType.DH,
            {Attribute.PRIME: DH_PRIME_2048, Attribute.BASE: DH_GEN},
            local=True,
        )

        # Alice and Bob each generate a keypair
        alice_pub, alice_priv = params.generate_keypair()
        bob_pub, bob_priv = params.generate_keypair()

        alice_value = alice_pub[Attribute.VALUE]
        bob_value = bob_pub[Attribute.VALUE]
        assert alice_value != bob_value  # Different public keys

        # Each derives an AES-128 key using the other's public value
        alice_shared = alice_priv.derive_key(
            KeyType.AES,
            128,
            mechanism_param=bob_value,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        bob_shared = bob_priv.derive_key(
            KeyType.AES,
            128,
            mechanism_param=alice_value,
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )

        # Both should derive the same key material
        assert alice_shared[Attribute.VALUE] == bob_shared[Attribute.VALUE]

    def test_dh_derived_key_encrypts(self, p11_session: Any, p11_module: Any) -> None:
        """Derived AES key from DH can encrypt/decrypt data."""
        _skip_no_dh(p11_module)

        params = p11_session.create_domain_parameters(
            KeyType.DH,
            {Attribute.PRIME: DH_PRIME_2048, Attribute.BASE: DH_GEN},
            local=True,
        )

        alice_pub, alice_priv = params.generate_keypair()
        bob_pub, bob_priv = params.generate_keypair()

        # Alice derives shared key, encrypts
        shared_key = alice_priv.derive_key(
            KeyType.AES,
            128,
            mechanism_param=bob_pub[Attribute.VALUE],
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )

        plaintext = b"DH key agreement!" + b"\x00" * 15  # pad to 32 bytes
        plaintext = plaintext[:32]
        ct = shared_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct != plaintext

        # Bob derives the same shared key, decrypts
        bob_key = bob_priv.derive_key(
            KeyType.AES,
            128,
            mechanism_param=alice_pub[Attribute.VALUE],
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
            },
        )
        pt = bob_key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    def test_dh_different_keypairs_different_secrets(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Two independent DH exchanges produce different shared secrets."""
        _skip_no_dh(p11_module)

        params = p11_session.create_domain_parameters(
            KeyType.DH,
            {Attribute.PRIME: DH_PRIME_2048, Attribute.BASE: DH_GEN},
            local=True,
        )

        # Exchange 1
        _pub1, priv1 = params.generate_keypair()
        pub2, _priv2 = params.generate_keypair()
        key1 = priv1.derive_key(
            KeyType.AES,
            128,
            mechanism_param=pub2[Attribute.VALUE],
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )

        # Exchange 2 (fresh keypairs)
        _pub3, priv3 = params.generate_keypair()
        pub4, _priv4 = params.generate_keypair()
        key2 = priv3.derive_key(
            KeyType.AES,
            128,
            mechanism_param=pub4[Attribute.VALUE],
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )

        # Different exchanges should produce different keys
        assert key1[Attribute.VALUE] != key2[Attribute.VALUE]


class TestDHParameterGeneration:
    """Test CKM_DH_PKCS_PARAMETER_GEN (on-token DH parameter generation)."""

    def test_generate_dh_parameters(self, p11_session: Any, p11_module: Any) -> None:
        """Generate DH domain parameters on the token."""
        if not has_mechanism(p11_module, "DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")

        params = p11_session.generate_domain_parameters(KeyType.DH, 2048)
        assert params is not None

        prime = params[Attribute.PRIME]
        assert isinstance(prime, bytes)
        assert len(prime) * 8 >= 2048

    def test_generated_params_produce_valid_keypair(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Generated parameters can produce a keypair that does key agreement."""
        if not has_mechanism(p11_module, "DH_PKCS_PARAMETER_GEN"):
            pytest.skip("CKM_DH_PKCS_PARAMETER_GEN not supported")
        if not has_mechanism(p11_module, "DH_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_DH_PKCS_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "DH_PKCS_DERIVE"):
            pytest.skip("CKM_DH_PKCS_DERIVE not supported")

        params = p11_session.generate_domain_parameters(KeyType.DH, 2048)
        pub_a, priv_a = params.generate_keypair()
        pub_b, priv_b = params.generate_keypair()

        key_a = priv_a.derive_key(
            KeyType.AES,
            128,
            mechanism_param=pub_b[Attribute.VALUE],
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        key_b = priv_b.derive_key(
            KeyType.AES,
            128,
            mechanism_param=pub_a[Attribute.VALUE],
            template={Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True},
        )
        assert key_a[Attribute.VALUE] == key_b[Attribute.VALUE]
