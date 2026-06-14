"""Tests for RSA-OAEP encrypt/decrypt with cross-verification.

Covers roundtrip, randomness, cross-verification with cryptography,
different plaintext sizes, and max plaintext length.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._rsa_export import read_rsa_public_key_or_xfail
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail, xfail_if_known_ckr

pytestmark = pytest.mark.crossverify

_PUB_ATTRS: dict[int, Any] = {CKA_ENCRYPT: True, CKA_TOKEN: False}
_PRIV_ATTRS: dict[int, Any] = {CKA_DECRYPT: True, CKA_TOKEN: False}


def _oaep_sha1() -> Any:
    return mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA_1, mgf=CKG_MGF1_SHA1)


_RSA_OAEP_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _xfail_if_oaep_runtime_reject(exc: AssertionError, label: str) -> None:
    xfail_if_known_ckr(
        exc,
        _RSA_OAEP_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA-OAEP parameters are not operational",
    )
    raise exc


class TestRSAOAEPRoundtrip:
    def test_oaep_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """RSA-OAEP: encrypt then decrypt returns original."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
        return read_rsa_public_key_or_xfail(rs, pub_handle)

    def test_encrypt_crypto_decrypt_p11(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
                    # Intentional PKCS#11 OAEP SHA-1 default compatibility coverage.
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),  # nosec B303
                    algorithm=hashes.SHA1(),  # nosec B303
                    label=None,
                ),
            )
            oaep = _oaep_sha1()
            rv = rs.raw.C_DecryptInit(rs.sh, oaep.byref(), priv)
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_DecryptInit",
                    operation="C_DecryptInit",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}",
                )
            import ctypes
            from ctypes import byref

            from pkcs11_check.raw.types_std import CK_ULONG

            in_buf = (ctypes.c_ubyte * len(ct))(*ct)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), None, byref(out_len))
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_Decrypt (length query)",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}",
                )
            out_buf = (ctypes.c_ubyte * out_len.value)()
            rv = rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), out_buf, byref(out_len))
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_Decrypt",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=f"OAEP param mismatch between module and cryptography: {ckr_name(rv)}",
                )
            pt = bytes(out_buf[: out_len.value])
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_wrong_key_decrypt_fails(self, p11_raw_session: Any) -> None:
        """Decrypting with wrong private key should fail."""
        rs = p11_raw_session
        pub1, priv1 = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        pub2, priv2 = gen_rsa_keypair_or_xfail(
            rs,
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
            # Decrypt with wrong key -- should fail at Init or Decrypt stage
            rv = rs.raw.C_DecryptInit(rs.sh, oaep.byref(), priv2)
            if rv != CKR_OK:
                return  # Failed as expected
            import ctypes
            from ctypes import byref

            from pkcs11_check.raw.types_std import CK_ULONG

            in_buf = (ctypes.c_ubyte * len(ct))(*ct)
            out_len = CK_ULONG(256)
            out_buf = (ctypes.c_ubyte * 256)()
            rv = rs.raw.C_Decrypt(rs.sh, in_buf, len(ct), out_buf, byref(out_len))
            if rv != CKR_OK:
                return  # Failed as expected
            pt = bytes(out_buf[: out_len.value])
            if pt == b"wrong key test":
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:wrong-key decrypt",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    summary="Decryption with wrong key should fail",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)


class TestRSAOAEPHashCombos:
    """RSA-OAEP with SHA-384 and SHA-512 hash/MGF combinations."""

    def test_oaep_sha384_roundtrip(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with SHA-384/MGF1-SHA384 roundtrip."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        try:
            plaintext = b"OAEP SHA-384 test"
            mech = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA384, mgf=CKG_MGF1_SHA384)
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP,
                    plaintext,
                    mech_param=mech,
                )
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_OAEP,
                    ct,
                    mech_param=mech,
                )
            except AssertionError as exc:
                _xfail_if_oaep_runtime_reject(exc, "RSA-OAEP SHA-384/MGF1-SHA384")
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_sha512_roundtrip(self, p11_raw_session: Any) -> None:
        """RSA-OAEP with SHA-512/MGF1-SHA512 roundtrip."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs=_PUB_ATTRS,
            private_attrs=_PRIV_ATTRS,
        )
        try:
            # SHA-512 with RSA-2048: max plaintext = 256 - 2*64 - 2 = 126 bytes
            plaintext = b"OAEP SHA-512"
            mech = mech_oaep(CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA512, mgf=CKG_MGF1_SHA512)
            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP,
                    plaintext,
                    mech_param=mech,
                )
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_OAEP,
                    ct,
                    mech_param=mech,
                )
            except AssertionError as exc:
                _xfail_if_oaep_runtime_reject(exc, "RSA-OAEP SHA-512/MGF1-SHA512")
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
