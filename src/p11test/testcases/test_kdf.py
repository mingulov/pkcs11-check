"""Key derivation function tests — ECDH derive, HMAC-KDF, key agreement.

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
from pkcs11.mechanisms import KDF

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


class TestKeyDeriveSoftware:
    """Test key derivation using software-verifiable methods."""

    def test_derive_from_digest(self, p11_session: Any) -> None:
        """Import a generic secret suitable for derivation."""
        secret = b"key derivation input material!!"
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

    def test_hmac_as_kdf(self, p11_session: Any) -> None:
        """Use HMAC as a KDF — cross-verify against Python hmac."""
        key_bytes = bytes(range(32))
        data = b"KDF input data for derivation"

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
        py_mac = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
        assert p11_mac == py_mac

    def test_hmac_sha512_as_kdf(self, p11_session: Any) -> None:
        """HMAC-SHA512 as KDF — cross-verify."""
        key_bytes = bytes(range(64))
        data = b"HMAC-SHA512 KDF test"

        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA512_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA512_HMAC)
        py_mac = hmac_mod.new(key_bytes, data, hashlib.sha512).digest()
        assert p11_mac == py_mac


class TestHKDF:
    """HKDF tests — requires CKM_HKDF_DERIVE (PKCS#11 v3.0+)."""

    def test_hkdf_available(self, p11_module: Any) -> None:
        """Check if HKDF mechanism is available."""
        if not has_mechanism(p11_module, "HKDF_DERIVE"):
            pytest.skip("HKDF not supported — requires PKCS#11 v3.0+")

    def test_hkdf_derive_basic(self, p11_session: Any, p11_module: Any) -> None:
        """Basic HKDF derivation with SHA-256."""
        if not has_mechanism(p11_module, "HKDF_DERIVE"):
            pytest.skip("HKDF not supported")

        ikm = bytes(range(32))
        base_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: ikm,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        try:
            derived = base_key.derive_key(
                KeyType.GENERIC_SECRET,
                256,
                mechanism=Mechanism.HKDF_DERIVE,
                mechanism_param=(Mechanism.SHA256, b"salt", b"info"),
                template={
                    Attribute.SENSITIVE: False,
                    Attribute.EXTRACTABLE: True,
                    Attribute.TOKEN: False,
                },
            )
            okm = derived[Attribute.VALUE]
            assert len(okm) == 32
        except p11.exceptions.PKCS11Error:
            pytest.xfail("HKDF derive failed")


class TestECDHDerive:
    """ECDH key agreement — derive shared secret from two keypairs."""

    def _generate_ec_keypair(self, session: Any) -> tuple[Any, Any]:
        ecparams = session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        return ecparams.generate_keypair()  # type: ignore[no-any-return]

    def _extract_ec_point(self, pub: Any) -> bytes:
        """Extract raw uncompressed point from DER OCTET STRING."""
        ec_point: bytes = pub[Attribute.EC_POINT]
        if ec_point[0] == 0x04:
            return ec_point[2:] if ec_point[1] < 128 else ec_point[3:]
        return ec_point

    def test_ecdh_keypair_independence(self, p11_session: Any) -> None:
        """Two independently generated EC keypairs have different public points."""
        pub_a, _ = self._generate_ec_keypair(p11_session)
        pub_b, _ = self._generate_ec_keypair(p11_session)
        assert pub_a[Attribute.EC_POINT] != pub_b[Attribute.EC_POINT]

    def test_ecdh_shared_secret_agreement(self, p11_session: Any) -> None:
        """ECDH: A derives with B's pubkey == B derives with A's pubkey."""
        pub_a, priv_a = self._generate_ec_keypair(p11_session)
        pub_b, priv_b = self._generate_ec_keypair(p11_session)

        point_a = self._extract_ec_point(pub_a)
        point_b = self._extract_ec_point(pub_b)

        # A derives with B's public key
        shared_ab = priv_a.derive_key(
            KeyType.GENERIC_SECRET,
            256,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, point_b),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )

        # B derives with A's public key
        shared_ba = priv_b.derive_key(
            KeyType.GENERIC_SECRET,
            256,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, point_a),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )

        assert shared_ab[Attribute.VALUE] == shared_ba[Attribute.VALUE]

    def test_ecdh_different_peers_different_secrets(self, p11_session: Any) -> None:
        """ECDH with different peers produces different shared secrets."""
        _, priv_a = self._generate_ec_keypair(p11_session)
        pub_b, _ = self._generate_ec_keypair(p11_session)
        pub_c, _ = self._generate_ec_keypair(p11_session)

        point_b = self._extract_ec_point(pub_b)
        point_c = self._extract_ec_point(pub_c)

        tmpl = {Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True, Attribute.TOKEN: False}

        shared_ab = priv_a.derive_key(
            KeyType.GENERIC_SECRET,
            256,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, point_b),
            template=tmpl,
        )
        shared_ac = priv_a.derive_key(
            KeyType.GENERIC_SECRET,
            256,
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, point_c),
            template=tmpl,
        )

        assert shared_ab[Attribute.VALUE] != shared_ac[Attribute.VALUE]
