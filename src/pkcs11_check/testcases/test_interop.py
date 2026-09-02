"""Interoperability tests - generate keys in PKCS#11, use in cryptography, and vice versa.

Tests the full round-trip: PKCS#11 -> export -> cryptography -> verify back in PKCS#11.
Also tests: import from cryptography -> use in PKCS#11.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_gcm, mech_pss
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_ec_keypair,
    gen_rsa_keypair,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_DECRYPT,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_ECB,
    CKM_AES_GCM,
    CKM_ECDSA,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA_1_HMAC,
)
from pkcs11_check.testcases._interop_runtime import xfail_if_interop_operation_reject
from pkcs11_check.testcases._rsa_export import read_rsa_public_key_or_xfail
from pkcs11_check.testcases._signature_policy import xfail_if_op_not_operational
from pkcs11_check.testcases.conftest import (
    assert_correct,
    extract_ec_point,
    import_secret_key_negotiated,
    skip_unless_create_object_supported,
)

pytestmark = pytest.mark.interop


def _require_mechanisms(rs: Any, *names: str) -> None:
    for name in names:
        if not rs.has_mechanism(name):
            pytest.skip(f"{name} not supported")


class TestRSAInterop:
    """RSA key interop between PKCS#11 and cryptography."""

    def test_sign_in_p11_verify_in_crypto(self, p11_raw_session: Any) -> None:
        """Sign with PKCS#11, export pubkey, verify with cryptography."""
        rs = p11_raw_session
        _require_mechanisms(rs, "RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS")
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)

        data = b"interop test data"
        try:
            sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)

            # Export and verify in cryptography
            pub_crypto = read_rsa_public_key_or_xfail(rs, pub_h)
            pub_crypto.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)

    def test_rsa_pubkey_pem_roundtrip(self, p11_raw_session: Any) -> None:
        """Export RSA public key to PEM, parse back, verify key size."""
        rs = p11_raw_session
        _require_mechanisms(rs, "RSA_PKCS_KEY_PAIR_GEN")
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)

        try:
            pub_crypto = read_rsa_public_key_or_xfail(rs, pub_h)

            pem = pub_crypto.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            assert b"BEGIN PUBLIC KEY" in pem

            pub_parsed = serialization.load_pem_public_key(pem)
            assert pub_parsed.key_size == 2048  # type: ignore[union-attr]
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)

    def test_rsa_pss_sign_p11_verify_crypto(self, p11_raw_session: Any) -> None:
        """RSA-PSS sign in PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        _require_mechanisms(rs, "RSA_PKCS_KEY_PAIR_GEN", "SHA256_RSA_PKCS_PSS")
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"RSA-PSS interop data"
        pss_param = mech_pss(
            CKM_SHA256_RSA_PKCS_PSS,
            hash_mech=CKM_SHA256,
            mgf=CKG_MGF1_SHA256,
            salt_len=32,
        )

        try:
            sig = sign_single(
                rs.raw,
                rs.sh,
                priv_h,
                CKM_SHA256_RSA_PKCS_PSS,
                data,
                mech_param=pss_param,
            )

            pub_crypto = read_rsa_public_key_or_xfail(rs, pub_h)

            pub_crypto.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)

    @pytest.mark.parametrize(
        "hash_mech,hash_class",
        [
            # Intentional CKM_SHA1_RSA_PKCS compatibility coverage for legacy modules.
            (CKM_SHA1_RSA_PKCS, hashes.SHA1()),  # nosec B303
            (CKM_SHA256_RSA_PKCS, hashes.SHA256()),
            (CKM_SHA384_RSA_PKCS, hashes.SHA384()),
            (CKM_SHA512_RSA_PKCS, hashes.SHA512()),
        ],
        ids=["SHA1", "SHA256", "SHA384", "SHA512"],
    )
    def test_rsa_multi_hash_interop(
        self, p11_raw_session: Any, hash_mech: Any, hash_class: Any
    ) -> None:
        """RSA signature interop across all standard hash algorithms."""
        rs = p11_raw_session
        mech_names: dict[int, str] = {
            int(CKM_SHA1_RSA_PKCS): "SHA1_RSA_PKCS",
            int(CKM_SHA256_RSA_PKCS): "SHA256_RSA_PKCS",
            int(CKM_SHA384_RSA_PKCS): "SHA384_RSA_PKCS",
            int(CKM_SHA512_RSA_PKCS): "SHA512_RSA_PKCS",
        }
        _require_mechanisms(rs, "RSA_PKCS_KEY_PAIR_GEN", mech_names[int(hash_mech)])
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"multi-hash interop test"

        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv_h, hash_mech, data)
            except AssertionError as exc:
                # FIPS deprecates SHA-1 for signature generation -> DEVICE_ERROR:
                # advertised but not operational, not a break.
                xfail_if_op_not_operational(exc, mech_names[int(hash_mech)])

            pub_crypto = read_rsa_public_key_or_xfail(rs, pub_h)
            pub_crypto.verify(sig, data, padding.PKCS1v15(), hash_class)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestECDSAInterop:
    """ECDSA key interop between PKCS#11 and cryptography."""

    @staticmethod
    def _extract_ec_point_bytes(
        rs: Any,
        pub_h: int,
    ) -> bytes:
        attrs = read_attributes(rs.raw, rs.sh, pub_h, [CKA_EC_POINT])
        raw_point = attrs[CKA_EC_POINT]
        return bytes(extract_ec_point(raw_point))

    def test_ecdsa_sign_p11_verify_crypto(self, p11_raw_session: Any) -> None:
        """Full ECDSA round-trip: sign in P11, verify in crypto."""
        rs = p11_raw_session
        _require_mechanisms(rs, "EC_KEY_PAIR_GEN", "ECDSA")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub_h, priv_h = gen_ec_keypair(rs.raw, rs.sh, curve_oid)

        data = b"ECDSA interop round-trip"
        digest = hashlib.sha256(data).digest()
        try:
            sig_raw = sign_single(rs.raw, rs.sh, priv_h, CKM_ECDSA, digest)

            # Export point and verify in cryptography
            point_bytes = self._extract_ec_point_bytes(rs, pub_h)
            pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point_bytes)

            r = int.from_bytes(sig_raw[:32], "big")
            s = int.from_bytes(sig_raw[32:], "big")
            der_sig = utils.encode_dss_signature(r, s)
            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)

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
        p11_raw_session: Any,
        curve_name: str,
        curve_obj: ec.EllipticCurve,
        coord_size: int,
    ) -> None:
        """ECDSA sign/verify interop for P-256 and P-384."""
        rs = p11_raw_session
        _require_mechanisms(rs, "EC_KEY_PAIR_GEN", "ECDSA")
        curve_oid = encode_named_curve_parameters(curve_name)
        pub_h, priv_h = gen_ec_keypair(rs.raw, rs.sh, curve_oid)

        data = b"multi-curve interop test"
        digest = hashlib.sha256(data).digest()
        try:
            sig_raw = sign_single(rs.raw, rs.sh, priv_h, CKM_ECDSA, digest)

            point_bytes = self._extract_ec_point_bytes(rs, pub_h)
            pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(curve_obj, point_bytes)

            r = int.from_bytes(sig_raw[:coord_size], "big")
            s = int.from_bytes(sig_raw[coord_size:], "big")
            der_sig = utils.encode_dss_signature(r, s)
            pub_crypto.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestAESInterop:
    """AES key interop - import key from raw bytes, use in both."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_create_object(self, p11_raw_session: Any) -> None:
        skip_unless_create_object_supported(p11_raw_session)

    def test_aes_ecb_encrypt_p11_decrypt_crypto(self, p11_raw_session: Any) -> None:
        """Import AES key, encrypt in P11, decrypt in crypto."""
        rs = p11_raw_session
        _require_mechanisms(rs, "AES_ECB")
        key_bytes = bytes(range(32))
        plaintext = b"AES interop test"  # 16 bytes

        key_h = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ALLOWED_MECHANISMS: [CKM_AES_ECB],
            },
        )
        try:
            try:
                ct = encrypt_single(rs.raw, rs.sh, key_h, CKM_AES_ECB, plaintext)
            except AssertionError as exc:
                xfail_if_interop_operation_reject(exc, "AES_ECB encrypt")

            # Intentional CKM_AES_ECB reference vector for PKCS#11 interoperability.
            cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())  # nosec B305
            dec = cipher.decryptor()
            pt = dec.update(ct) + dec.finalize()
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_ECB:P11-encrypt cryptography-decrypt round-trip",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
                source="cryptography",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_aes_ecb_encrypt_crypto_decrypt_p11(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        _require_mechanisms(rs, "AES_ECB")
        key_bytes = bytes(range(32))
        plaintext = b"reverse interop!"  # 16 bytes

        # Intentional CKM_AES_ECB reference vector for PKCS#11 interoperability.
        cipher = Cipher(algorithms.AES(key_bytes), modes.ECB())  # nosec B305
        enc = cipher.encryptor()
        ct = enc.update(plaintext) + enc.finalize()

        key_h = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ALLOWED_MECHANISMS: [CKM_AES_ECB],
            },
        )
        try:
            try:
                pt = decrypt_single(rs.raw, rs.sh, key_h, CKM_AES_ECB, ct)
            except AssertionError as exc:
                xfail_if_interop_operation_reject(exc, "AES_ECB decrypt")
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_ECB:cryptography-encrypt P11-decrypt round-trip",
                operation="C_Decrypt",
                mechanism="CKM_AES_ECB",
                source="cryptography",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_aes_gcm_encrypt_p11_decrypt_crypto(self, p11_raw_session: Any) -> None:
        """AES-GCM: encrypt in PKCS#11, decrypt with cryptography."""
        rs = p11_raw_session
        _require_mechanisms(rs, "AES_GCM")
        key_bytes = bytes(range(32))
        plaintext = b"GCM interop test data!!"
        nonce = b"\x00" * 12

        key_h = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ALLOWED_MECHANISMS: [CKM_AES_GCM],
            },
        )
        try:
            gcm_param = mech_gcm(CKM_AES_GCM, nonce)
            ct_tag = encrypt_single(
                rs.raw,
                rs.sh,
                key_h,
                CKM_AES_GCM,
                plaintext,
                mech_param=gcm_param,
                output_overhead=16,  # GCM appends a 128-bit (16-byte) authentication tag
            )

            aesgcm = AESGCM(key_bytes)
            pt = aesgcm.decrypt(nonce, ct_tag, b"")
            assert_correct(
                actual=pt,
                expected=plaintext,
                label="AES_GCM:P11-encrypt cryptography-decrypt round-trip",
                operation="C_Encrypt",
                mechanism="CKM_AES_GCM",
                source="cryptography",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestHMACInterop:
    """HMAC interop between PKCS#11 and cryptography."""

    @pytest.fixture(autouse=True)
    def _skip_if_no_create_object(self, p11_raw_session: Any) -> None:
        skip_unless_create_object_supported(p11_raw_session)

    def test_hmac_sha256_interop(self, p11_raw_session: Any) -> None:
        """Compute HMAC-SHA256 in both, compare."""
        rs = p11_raw_session
        _require_mechanisms(rs, "SHA256_HMAC")
        key_bytes = bytes(range(32))
        data = b"HMAC interop test data"

        # PKCS#11
        key_h = import_secret_key_negotiated(
            rs,
            CKK_GENERIC_SECRET,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ALLOWED_MECHANISMS: [CKM_SHA256_HMAC],
            },
        )
        try:
            try:
                p11_mac = sign_single(rs.raw, rs.sh, key_h, CKM_SHA256_HMAC, data)
            except AssertionError as exc:
                xfail_if_interop_operation_reject(exc, "SHA256_HMAC sign")

            # cryptography
            h = hmac.HMAC(key_bytes, hashes.SHA256())
            h.update(data)
            crypto_mac = h.finalize()

            assert_correct(
                actual=p11_mac,
                expected=crypto_mac,
                label="SHA256_HMAC:MAC cross-verify vs cryptography",
                operation="C_Sign",
                mechanism="CKM_SHA256_HMAC",
                source="cryptography",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_hmac_sha1_interop(self, p11_raw_session: Any) -> None:
        """HMAC-SHA1 cross-verification."""
        rs = p11_raw_session
        _require_mechanisms(rs, "SHA_1_HMAC")
        key_bytes = b"secret key for hmac!!"  # >= 20 bytes for SHA-1 HMAC
        data = b"message to authenticate"

        key_h = import_secret_key_negotiated(
            rs,
            CKK_GENERIC_SECRET,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ALLOWED_MECHANISMS: [CKM_SHA_1_HMAC],
            },
        )
        try:
            try:
                p11_mac = sign_single(rs.raw, rs.sh, key_h, CKM_SHA_1_HMAC, data)
            except AssertionError as exc:
                xfail_if_interop_operation_reject(exc, "SHA_1_HMAC sign")

            # Intentional CKM_SHA_1_HMAC compatibility coverage for legacy modules.
            h = hmac.HMAC(key_bytes, hashes.SHA1())  # nosec B303
            h.update(data)
            crypto_mac = h.finalize()

            assert_correct(
                actual=p11_mac,
                expected=crypto_mac,
                label="SHA_1_HMAC:MAC cross-verify vs cryptography",
                operation="C_Sign",
                mechanism="CKM_SHA_1_HMAC",
                source="cryptography",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)
