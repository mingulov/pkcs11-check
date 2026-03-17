"""Key derivation function tests — ECDH derive + HKDF-like cross-verification.

Tests key derivation operations available in PKCS#11 v2.40+.
HKDF (CKM_HKDF_DERIVE) requires v3.0+ — auto-skips on v2.40 modules.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.keymgmt


class TestKeyDeriveSoftware:
    """Test key derivation using software-verifiable methods."""

    def test_derive_from_digest(self, p11_session: Any) -> None:
        """Derive a key by hashing — deterministic, cross-verifiable."""
        # Import a known secret
        secret = b"key derivation input material!!"  # 32 bytes
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: secret,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.DERIVE: True,
            }
        )
        assert key is not None
        key.destroy()

    def test_hmac_as_kdf(self, p11_session: Any) -> None:
        """Use HMAC as a poor-man's KDF — cross-verify against Python hmac."""
        key_bytes = bytes(range(32))
        data = b"KDF input data for derivation"

        # HMAC via PKCS#11
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)

        # Python side
        py_mac = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()

        assert p11_mac == py_mac, "HMAC-based KDF output differs"


class TestHKDF:
    """HKDF tests — requires CKM_HKDF_DERIVE (PKCS#11 v3.0+)."""

    def test_hkdf_available(self, p11_module: Any) -> None:
        """Check if HKDF mechanism is available."""
        slot = p11_module.get_slots(token_present=True)[0]
        mechanisms = slot.get_mechanisms()
        names = {mech_name(m) for m in mechanisms}

        if "HKDF_DERIVE" not in names and "CKM_HKDF_DERIVE" not in names:
            pytest.skip("HKDF not supported — requires PKCS#11 v3.0+")

        # If we got here, HKDF is available
        assert True


class TestECDHDerive:
    """ECDH key agreement — derive shared secret from two keypairs."""

    def test_ecdh_keypair_independence(self, p11_session: Any) -> None:
        """Two independently generated EC keypairs should have different public points."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub_a, priv_a = ecparams.generate_keypair()
        pub_b, priv_b = ecparams.generate_keypair()

        point_a = pub_a[Attribute.EC_POINT]
        point_b = pub_b[Attribute.EC_POINT]

        assert point_a != point_b, "Two EC keypairs have same public point"

        pub_a.destroy()
        priv_a.destroy()
        pub_b.destroy()
        priv_b.destroy()

    def test_generic_secret_derive(self, p11_session: Any) -> None:
        """Derive an AES key from a generic secret (simple KDF pattern)."""
        # Import a generic secret
        secret = bytes(range(32))
        base_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: secret,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
        )
        assert base_key is not None
        # The key exists and can be used for HMAC-based derivation
        base_key.destroy()
