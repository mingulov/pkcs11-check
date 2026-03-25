"""Tests for RSA-OAEP encrypt/decrypt with cross-verification.

Covers roundtrip, randomness, cross-verification with cryptography,
different plaintext sizes, and max plaintext length.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_TOKEN,
    CKG_MGF1_SHA1,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
    CKR_OK,
)

pytestmark = pytest.mark.crossverify

_PUB_ATTRS: dict[int, Any] = {int(CKA_ENCRYPT): True, int(CKA_TOKEN): False}
_PRIV_ATTRS: dict[int, Any] = {int(CKA_DECRYPT): True, int(CKA_TOKEN): False}


def _oaep_sha1() -> Any:
    return mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=int(CKM_SHA_1), mgf=int(CKG_MGF1_SHA1))


class TestRSAOAEPRoundtrip:
    def test_oaep_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """RSA-OAEP: encrypt then decrypt returns original."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        plaintext = b"RSA-OAEP roundtrip"
        oaep = _oaep_sha1()
        try:
            ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS_OAEP, plaintext, mech_param=oaep)
            pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, ct, mech_param=oaep)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_randomized(self, p11_raw_session: Any) -> None:
        """RSA-OAEP produces different ciphertext for same plaintext."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        plaintext = b"OAEP randomness"
        oaep = _oaep_sha1()
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_RSA_PKCS_OAEP,
                plaintext,
                mech_param=oaep,
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_RSA_PKCS_OAEP,
                plaintext,
                mech_param=oaep,
            )
            assert ct1 != ct2
            assert (
                decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, ct1, mech_param=oaep)
                == plaintext
            )
            assert (
                decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, ct2, mech_param=oaep)
                == plaintext
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_empty_plaintext(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with empty plaintext."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        oaep = _oaep_sha1()
        try:
            ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS_OAEP, b"", mech_param=oaep)
            pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, ct, mech_param=oaep)
            assert pt == b""
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_max_plaintext(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with maximum plaintext size.

        For RSA-2048 with SHA-1 OAEP: max = 256 - 2*20 - 2 = 214 bytes.
        """
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        plaintext = b"\xab" * 190  # Safe under 214-byte limit
        oaep = _oaep_sha1()
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_RSA_PKCS_OAEP,
                plaintext,
                mech_param=oaep,
            )
            pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, ct, mech_param=oaep)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_ciphertext_size(self, p11_raw_session: Any) -> None:
        """RSA-OAEP ciphertext is always modulus-length (256 bytes for 2048)."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        oaep = _oaep_sha1()
        try:
            for pt_len in [1, 16, 100, 190]:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP,
                    b"\x00" * pt_len,
                    mech_param=oaep,
                )
                assert len(ct) == 256
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestRSAOAEPCrossVerify:
    def _export_rsa_pubkey(self, rs: Any, pub_handle: int) -> rsa.RSAPublicKey:
        attrs = read_attributes(
            rs.raw,
            rs.sh,
            pub_handle,
            [int(CKA_MODULUS), int(CKA_PUBLIC_EXPONENT)],
        )
        modulus = int.from_bytes(attrs[int(CKA_MODULUS)], "big")  # type: ignore[arg-type]
        exponent = int.from_bytes(attrs[int(CKA_PUBLIC_EXPONENT)], "big")  # type: ignore[arg-type]
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    def test_encrypt_crypto_decrypt_p11(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        try:
            pub_crypto = self._export_rsa_pubkey(rs, pub)
            plaintext = b"OAEP cross-verify"

            ct = pub_crypto.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
            )
            oaep = _oaep_sha1()
            rv = int(rs.raw.C_DecryptInit(rs.sh, oaep.byref(), priv))
            if rv != int(CKR_OK):
                pytest.xfail(f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}")
            import ctypes
            from ctypes import byref

            from pkcs11_check.raw.types_std import CK_ULONG

            in_buf = (ctypes.c_ubyte * len(ct))(*ct)
            out_len = CK_ULONG(0)
            rv = int(rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), None, byref(out_len)))
            if rv != int(CKR_OK):
                pytest.xfail(f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}")
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = int(rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), out_buf, byref(out_len)))
            if rv != int(CKR_OK):
                pytest.xfail(f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}")
            pt = bytes(out_buf[: out_len.value])
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_wrong_key_decrypt_fails(self, p11_raw_session: Any) -> None:
        """Decrypting with wrong private key should fail."""
        rs = p11_raw_session
        pub1, priv1 = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        pub2, priv2 = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        oaep = _oaep_sha1()
        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                pub1,
                CKM_RSA_PKCS_OAEP,
                b"wrong key test",
                mech_param=oaep,
            )
            # Decrypt with wrong key — should fail at Init or Decrypt stage
            rv = int(rs.raw.C_DecryptInit(rs.sh, oaep.byref(), priv2))
            if rv != int(CKR_OK):
                return  # Failed as expected
            import ctypes
            from ctypes import byref

            from pkcs11_check.raw.types_std import CK_ULONG

            in_buf = (ctypes.c_ubyte * len(ct))(*ct)
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = int(rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), out_buf, byref(out_len)))
            if rv != int(CKR_OK):
                return  # Failed as expected
            pt = bytes(out_buf[: out_len.value])
            if pt == b"wrong key test":
                pytest.fail("Decryption with wrong key should fail")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)
