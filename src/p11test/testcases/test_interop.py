"""Interoperability tests — generate keys in PKCS#11, use in cryptography, and vice versa.

Tests the full round-trip: PKCS#11 → export → cryptography → verify back in PKCS#11.
Also tests: import from cryptography → use in PKCS#11.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11 as p11
import pytest
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import MGF

from p11test.testcases.conftest import import_aes_key

pytestmark = pytest.mark.interop


class TestRSAInterop:
    """RSA key interop between PKCS#11 and cryptography."""

    def test_sign_in_p11_verify_in_crypto(self, p11_session: Any) -> None:
        """Sign with PKCS#11, export pubkey, verify with cryptography."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)

        data = b"interop test data"
        sig = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Export and verify in cryptography
        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        pub_crypto.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())

    def test_rsa_pubkey_pem_roundtrip(self, p11_session: Any) -> None:
        """Export RSA public key to PEM, parse back, verify key size."""
        pub_p11, _ = p11_session.generate_keypair(KeyType.RSA, 2048)

        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()

        pem = pub_crypto.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert b"BEGIN PUBLIC KEY" in pem

        pub_parsed = serialization.load_pem_public_key(pem)
        assert pub_parsed.key_size == 2048  # type: ignore[union-attr]

    def test_rsa_pss_sign_p11_verify_crypto(self, p11_session: Any) -> None:
        """RSA-PSS sign in PKCS#11, verify with cryptography."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA-PSS interop data"
        pss_params = (Mechanism.SHA256, MGF.SHA256, 32)

        sig = priv_p11.sign(
            data,
            mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
            mechanism_param=pss_params,
        )

        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()

        pub_crypto.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )

    @pytest.mark.parametrize(
        "hash_mech,hash_class",
        [
            (Mechanism.SHA1_RSA_PKCS, hashes.SHA1()),
            (Mechanism.SHA256_RSA_PKCS, hashes.SHA256()),
            (Mechanism.SHA384_RSA_PKCS, hashes.SHA384()),
            (Mechanism.SHA512_RSA_PKCS, hashes.SHA512()),
        ],
        ids=["SHA1", "SHA256", "SHA384", "SHA512"],
    )
    def test_rsa_multi_hash_interop(
        self, p11_session: Any, hash_mech: Mechanism, hash_class: Any
    ) -> None:
        """RSA signature interop across all standard hash algorithms."""
        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"multi-hash interop test"

        sig = priv_p11.sign(data, mechanism=hash_mech)

        modulus = int.from_bytes(pub_p11[Attribute.MODULUS], "big")
        exponent = int.from_bytes(pub_p11[Attribute.PUBLIC_EXPONENT], "big")
        pub_crypto = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        pub_crypto.verify(sig, data, padding.PKCS1v15(), hash_class)


class TestECDSAInterop:
    """ECDSA key interop between PKCS#11 and cryptography."""

    def _extract_ec_point(self, pub_p11: Any) -> Any:
        """Extract raw uncompressed EC point from PKCS#11 object."""
        ec_point = pub_p11[Attribute.EC_POINT]
        # DER OCTET STRING wrapper: 0x04 <len> <point>
        if ec_point[0] == 0x04:
            if ec_point[1] < 128:
                return ec_point[2:]
            else:
                return ec_point[3:]
        return ec_point

    def _generate_ec_keypair(self, session: Any, curve: str = "secp256r1") -> tuple[Any, Any]:
        ecparams = session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters(curve)},
            local=True,
        )
        return ecparams.generate_keypair()  # type: ignore[no-any-return]

    def test_ecdsa_sign_p11_verify_crypto(self, p11_session: Any) -> None:
        """Full ECDSA round-trip: sign in P11, verify in crypto."""
        pub_p11, priv_p11 = self._generate_ec_keypair(p11_session)

        data = b"ECDSA interop round-trip"
        digest = hashlib.sha256(data).digest()
        sig_raw = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        # Export point and verify in cryptography
        point_bytes = self._extract_ec_point(pub_p11)
        pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)

        r = int.from_bytes(sig_raw[:32], "big")
        s = int.from_bytes(sig_raw[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))

    @pytest.mark.parametrize(
        "curve_name,curve_obj,coord_size",
        [
            ("secp256r1", ec.SECP256R1(), 32),
            ("secp384r1", ec.SECP384R1(), 48),
        ],
        ids=["P-256", "P-384"],
    )
    def test_ecdsa_multi_curve_interop(
        self,
        p11_session: Any,
        curve_name: str,
        curve_obj: ec.EllipticCurve,
        coord_size: int,
    ) -> None:
        """ECDSA sign/verify interop for P-256 and P-384."""
        pub_p11, priv_p11 = self._generate_ec_keypair(p11_session, curve_name)

        data = b"multi-curve interop test"
        digest = hashlib.sha256(data).digest()
        sig_raw = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        point_bytes = self._extract_ec_point(pub_p11)
        pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(curve_obj, point_bytes)

        r = int.from_bytes(sig_raw[:coord_size], "big")
        s = int.from_bytes(sig_raw[coord_size:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))


class TestAESInterop:
    """AES key interop — import key from raw bytes, use in both."""

    def test_aes_ecb_encrypt_p11_decrypt_crypto(self, p11_session: Any) -> None:
        """Import AES key, encrypt in P11, decrypt in crypto."""
        key_bytes = bytes(range(32))
        plaintext = b"AES interop test"  # 16 bytes

        p11_key = import_aes_key(p11_session, key_bytes)
        ct = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        dec = cipher.decryptor()
        pt = dec.update(ct) + dec.finalize()
        assert pt == plaintext

    def test_aes_ecb_encrypt_crypto_decrypt_p11(self, p11_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        key_bytes = bytes(range(32))
        plaintext = b"reverse interop!"  # 16 bytes

        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        p11_key = import_aes_key(p11_session, key_bytes)
        pt = p11_key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    def test_aes_gcm_encrypt_p11_decrypt_crypto(self, p11_session: Any) -> None:
        """AES-GCM: encrypt in PKCS#11, decrypt with cryptography."""
        from pkcs11.mechanisms import GCMParams

        key_bytes = bytes(range(32))
        plaintext = b"GCM interop test data!!"
        nonce = b"\x00" * 12

        p11_key = import_aes_key(p11_session, key_bytes)
        gcm = GCMParams(nonce)
        ct_tag = p11_key.encrypt(plaintext, mechanism=Mechanism.AES_GCM, mechanism_param=gcm)

        aesgcm = AESGCM(key_bytes)
        pt = aesgcm.decrypt(nonce, ct_tag, b"")
        assert pt == plaintext


class TestHMACInterop:
    """HMAC interop between PKCS#11 and cryptography."""

    def test_hmac_sha256_interop(self, p11_session: Any) -> None:
        """Compute HMAC-SHA256 in both, compare."""
        key_bytes = bytes(range(32))
        data = b"HMAC interop test data"

        # PKCS#11
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: p11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)

        # cryptography
        h = hmac.HMAC(key_bytes, hashes.SHA256())
        h.update(data)
        crypto_mac = h.finalize()

        assert p11_mac == crypto_mac

    def test_hmac_sha1_interop(self, p11_session: Any) -> None:
        """HMAC-SHA1 cross-verification."""
        key_bytes = b"secret key for hmac!!"  # >= 20 bytes for SHA-1 HMAC
        data = b"message to authenticate"

        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: p11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA_1_HMAC)

        h = hmac.HMAC(key_bytes, hashes.SHA1())
        h.update(data)
        crypto_mac = h.finalize()

        assert p11_mac == crypto_mac
