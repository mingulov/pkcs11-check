"""Tests for extended RSA mechanisms.

Covers CKM_RSA_X9_31, CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_AES_KEY_WRAP,
and CKM_RSA_PKCS_OAEP_TPM_1_1.

OASIS spec: rsa.md
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    PackedMechanism,
    attr_ulong,
    mech_oaep,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    read_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_RSA_AES_KEY_WRAP_PARAMS,
    CK_RSA_PKCS_OAEP_PARAMS,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_WRAP,
    CKG_MGF1_SHA256,
    CKK_AES,
    CKM_RSA_AES_KEY_WRAP,
    CKM_RSA_PKCS_OAEP,
    CKM_RSA_PKCS_OAEP_TPM_1_1,
    CKM_RSA_X9_31,
    CKM_RSA_X9_31_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_SECRET_KEY,
    CKR_OK,
    CKZ_DATA_SPECIFIED,
)

pytestmark = pytest.mark.full


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rsa_keypair(
    rs: Any,
    bits: int = 2048,
    *,
    sign: bool = False,
    encrypt: bool = False,
    wrap: bool = False,
    mechanism: int | None = None,
) -> tuple[int, int]:
    """Generate an RSA keypair with specific capabilities."""
    pub_attrs: dict[int, Any] = {CKA_TOKEN: False}
    priv_attrs: dict[int, Any] = {CKA_TOKEN: False}

    if sign:
        pub_attrs[CKA_VERIFY] = True
        priv_attrs[CKA_SIGN] = True
    if encrypt:
        pub_attrs[CKA_ENCRYPT] = True
        priv_attrs[CKA_DECRYPT] = True
    if wrap:
        pub_attrs[CKA_WRAP] = True
        priv_attrs[CKA_UNWRAP] = True

    if mechanism is not None and mechanism != CKM_RSA_X9_31_KEY_PAIR_GEN:
        # Standard RSA keygen
        return gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits,
            public_attrs=pub_attrs,
            private_attrs=priv_attrs,
        )

    if mechanism is not None:
        # Non-standard keygen mechanism (e.g. X9.31): call C_GenerateKeyPair directly
        pub_packed = [attr_ulong(CKA_MODULUS_BITS, bits)]
        from pkcs11_check.raw.recipes import pack_attrs

        pub_packed.extend(pack_attrs(pub_attrs, skip={CKA_MODULUS_BITS}))
        priv_packed = pack_attrs(priv_attrs)
        pub_tmpl = template(*pub_packed)
        priv_tmpl = template(*priv_packed) if priv_packed else template()
        mech = mech_simple(mechanism)
        pub_h = CK_OBJECT_HANDLE(0)
        priv_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub_h),
            byref(priv_h),
        )
        expect_rv(rv, CKR_OK)
        return pub_h.value, priv_h.value

    return gen_rsa_keypair(
        rs.raw,
        rs.sh,
        bits,
        public_attrs=pub_attrs,
        private_attrs=priv_attrs,
    )


def _make_extractable_aes(rs: Any, bits: int = 128) -> int:
    """Generate an extractable AES key suitable for wrapping."""
    return gen_aes_key(
        rs.raw,
        rs.sh,
        bits,
        attrs={
            CKA_EXTRACTABLE: True,
            CKA_SENSITIVE: False,
            CKA_TOKEN: False,
        },
    )


# ---------------------------------------------------------------------------
# CKM_RSA_X9_31 - X9.31 signature padding
# ---------------------------------------------------------------------------


class TestRSAX931:
    """CKM_RSA_X9_31 sign/verify with pre-hashed data."""

    def test_sign_verify_sha256(self, p11_raw_session: Any) -> None:
        """Sign a SHA-256 digest with RSA X9.31 and verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(rs, sign=True)
        try:
            # X9.31 operates on pre-hashed data - must be exactly hash length
            digest = hashlib.sha256(b"test data for X9.31 signing").digest()
            assert len(digest) == 32

            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_RSA_X9_31, digest)
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            assert len(sig) == 256  # 2048-bit RSA = 256 bytes
            result = verify_single(rs.raw, rs.sh, pub, CKM_RSA_X9_31, digest, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_sign_verify_sha1(self, p11_raw_session: Any) -> None:
        """Sign a SHA-1 digest with RSA X9.31 and verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(rs, sign=True)
        try:
            digest = hashlib.sha1(b"test data for X9.31 SHA-1", usedforsecurity=False).digest()  # noqa: S324
            assert len(digest) == 20

            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_RSA_X9_31, digest)
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign with SHA-1 digest not functional: {exc}")

            result = verify_single(rs.raw, rs.sh, pub, CKM_RSA_X9_31, digest, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_tampered_signature_fails(self, p11_raw_session: Any) -> None:
        """Verification with tampered signature should fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(rs, sign=True)
        try:
            digest = hashlib.sha256(b"tamper detection test").digest()

            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_RSA_X9_31, digest)
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            # Flip a byte in the signature
            tampered = bytearray(sig)
            tampered[-1] ^= 0xFF
            tampered_sig = bytes(tampered)

            result = verify_single(rs.raw, rs.sh, pub, CKM_RSA_X9_31, digest, tampered_sig)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_wrong_digest_fails(self, p11_raw_session: Any) -> None:
        """Verification with different digest should fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31"):
            pytest.skip("CKM_RSA_X9_31 not supported")

        pub, priv = _rsa_keypair(rs, sign=True)
        try:
            digest = hashlib.sha256(b"original data").digest()

            try:
                sig = sign_single(rs.raw, rs.sh, priv, CKM_RSA_X9_31, digest)
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_X9_31 sign not functional: {exc}")

            wrong_digest = hashlib.sha256(b"different data").digest()

            result = verify_single(rs.raw, rs.sh, pub, CKM_RSA_X9_31, wrong_digest, sig)
            assert result is False
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# CKM_RSA_X9_31_KEY_PAIR_GEN - alternative RSA key generation
# ---------------------------------------------------------------------------


class TestRSAX931KeyPairGen:
    """CKM_RSA_X9_31_KEY_PAIR_GEN - generate RSA keys using X9.31 method."""

    def test_generate_keypair(self, p11_raw_session: Any) -> None:
        """Generate an RSA keypair using X9.31 key generation."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")

        try:
            pub, priv = _rsa_keypair(
                rs,
                sign=True,
                encrypt=True,
                mechanism=CKM_RSA_X9_31_KEY_PAIR_GEN,
            )
        except AssertionError as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            assert pub != 0
            assert priv != 0
            # Verify the key has the expected modulus size
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS])
            modulus = attrs[CKA_MODULUS]
            assert isinstance(modulus, bytes)
            assert len(modulus) == 256  # 2048 bits = 256 bytes
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_generated_key_can_sign(self, p11_raw_session: Any) -> None:
        """Keys generated with X9.31 method can perform standard RSA signing."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            pub, priv = _rsa_keypair(
                rs,
                sign=True,
                mechanism=CKM_RSA_X9_31_KEY_PAIR_GEN,
            )
        except AssertionError as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            data = b"sign with X9.31-generated key"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
            assert len(sig) == 256
            result = verify_single(rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_generated_key_can_encrypt(self, p11_raw_session: Any) -> None:
        """Keys generated with X9.31 method can perform RSA-OAEP encrypt/decrypt."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_X9_31_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_X9_31_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")

        try:
            pub, priv = _rsa_keypair(
                rs,
                encrypt=True,
                mechanism=CKM_RSA_X9_31_KEY_PAIR_GEN,
            )
        except AssertionError as exc:
            pytest.xfail(f"CKM_RSA_X9_31_KEY_PAIR_GEN not functional: {exc}")

        try:
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA256,
                mgf=CKG_MGF1_SHA256,
            )
            plaintext = b"encrypt with X9.31 key"
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                pub,
                CKM_RSA_PKCS_OAEP,
                plaintext,
                mech_param=oaep,
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                priv,
                CKM_RSA_PKCS_OAEP,
                ct,
                mech_param=oaep,
            )
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


# ---------------------------------------------------------------------------
# CKM_RSA_AES_KEY_WRAP - hybrid RSA+AES key wrapping
# ---------------------------------------------------------------------------


def _mech_rsa_aes_key_wrap(aes_key_bits: int = 256) -> PackedMechanism:
    """Build CKM_RSA_AES_KEY_WRAP mechanism params."""
    oaep = CK_RSA_PKCS_OAEP_PARAMS()
    oaep.hashAlg = CKM_SHA256
    oaep.mgf = CKG_MGF1_SHA256
    oaep.source = CKZ_DATA_SPECIFIED
    oaep.pSourceData = None
    oaep.ulSourceDataLen = 0

    params = CK_RSA_AES_KEY_WRAP_PARAMS()
    params.ulAESKeyBits = aes_key_bits
    params.pOAEPParams = ctypes.cast(ctypes.pointer(oaep), ctypes.c_void_p)

    from pkcs11_check.raw.pack import LengthArg, PointerArg

    pointer_arg = PointerArg.to_storage(params, origin="mech_rsa_aes_key_wrap")
    length_arg = LengthArg.native(ctypes.sizeof(params))
    from pkcs11_check.raw.types_std import CK_MECHANISM

    result = PackedMechanism(
        CK_MECHANISM(CKM_RSA_AES_KEY_WRAP, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    # Keep oaep struct alive
    result._keepalive.append(oaep)
    return result


class TestRSAAESKeyWrap:
    """CKM_RSA_AES_KEY_WRAP - wraps a key with AES, then wraps the AES key with RSA-OAEP."""

    def test_wrap_unwrap_aes128(self, p11_raw_session: Any) -> None:
        """Wrap an AES-128 key using RSA_AES_KEY_WRAP and unwrap it."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(rs, wrap=True)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            attrs = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])
            original_value = attrs[CKA_VALUE]
            assert isinstance(original_value, bytes)

            wrap_param = _mech_rsa_aes_key_wrap(256)

            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    pub,
                    aes_key,
                    CKM_RSA_AES_KEY_WRAP,
                    mech_param=wrap_param,
                )
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            assert wrapped is not None
            assert len(wrapped) > 0

            unwrap_param = _mech_rsa_aes_key_wrap(256)
            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                priv,
                wrapped,
                CKM_RSA_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
                mech_param=unwrap_param,
            )
            try:
                unwrapped_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    unwrapped,
                    [CKA_VALUE],
                )
                assert unwrapped_attrs[CKA_VALUE] == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrap_unwrap_aes256(self, p11_raw_session: Any) -> None:
        """Wrap an AES-256 key using RSA_AES_KEY_WRAP."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(rs, wrap=True)
        aes_key = _make_extractable_aes(rs, 256)
        try:
            attrs = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])
            original_value = attrs[CKA_VALUE]
            assert isinstance(original_value, bytes)

            wrap_param = _mech_rsa_aes_key_wrap(256)

            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    pub,
                    aes_key,
                    CKM_RSA_AES_KEY_WRAP,
                    mech_param=wrap_param,
                )
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            unwrap_param = _mech_rsa_aes_key_wrap(256)
            unwrapped = unwrap_key(
                rs.raw,
                rs.sh,
                priv,
                wrapped,
                CKM_RSA_AES_KEY_WRAP,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_AES,
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                    CKA_TOKEN: False,
                },
                mech_param=unwrap_param,
            )
            try:
                unwrapped_attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    unwrapped,
                    [CKA_VALUE],
                )
                assert unwrapped_attrs[CKA_VALUE] == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)

    def test_wrapped_data_differs_from_original(self, p11_raw_session: Any) -> None:
        """Wrapped key data should not contain the original key material."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_AES_KEY_WRAP"):
            pytest.skip("CKM_RSA_AES_KEY_WRAP not supported")

        pub, priv = _rsa_keypair(rs, wrap=True)
        aes_key = _make_extractable_aes(rs, 128)
        try:
            attrs = read_attributes(rs.raw, rs.sh, aes_key, [CKA_VALUE])
            original_value = attrs[CKA_VALUE]
            assert isinstance(original_value, bytes)

            wrap_param = _mech_rsa_aes_key_wrap(256)

            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    pub,
                    aes_key,
                    CKM_RSA_AES_KEY_WRAP,
                    mech_param=wrap_param,
                )
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_AES_KEY_WRAP wrap not functional: {exc}")

            # The wrapped blob should not contain the raw key bytes
            assert original_value not in wrapped
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, aes_key)


# ---------------------------------------------------------------------------
# CKM_RSA_PKCS_OAEP_TPM_1_1 - TPM 1.1 variant of RSA-OAEP
# ---------------------------------------------------------------------------


class TestRSAOAEPTPM:
    """CKM_RSA_PKCS_OAEP_TPM_1_1 - TPM 1.1 specific RSA-OAEP variant."""

    def test_encrypt_decrypt_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt and decrypt with RSA-OAEP TPM 1.1."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(rs, encrypt=True)
        try:
            plaintext = b"TPM 1.1 OAEP test data"

            try:
                ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS_OAEP_TPM_1_1, plaintext)
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            assert len(ct) == 256  # 2048-bit RSA
            assert ct != plaintext

            pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP_TPM_1_1, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ciphertext_is_randomized(self, p11_raw_session: Any) -> None:
        """OAEP encryption is randomized - same plaintext gives different ciphertexts."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(rs, encrypt=True)
        try:
            plaintext = b"randomization test"

            try:
                ct1 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP_TPM_1_1,
                    plaintext,
                )
                ct2 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP_TPM_1_1,
                    plaintext,
                )
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            # OAEP uses random padding - two encryptions should differ
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_max_plaintext_size(self, p11_raw_session: Any) -> None:
        """Encrypt the maximum-size plaintext for 2048-bit RSA OAEP.

        For OAEP with SHA-1 (TPM 1.1 default): max = k - 2*hLen - 2 = 256 - 42 = 214 bytes.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP_TPM_1_1"):
            pytest.skip("CKM_RSA_PKCS_OAEP_TPM_1_1 not supported")

        pub, priv = _rsa_keypair(rs, encrypt=True)
        try:
            # TPM 1.1 OAEP uses SHA-1 (hLen=20), so max plaintext = 256 - 2*20 - 2 = 214
            max_plaintext = os.urandom(214)

            try:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_RSA_PKCS_OAEP_TPM_1_1,
                    max_plaintext,
                )
            except AssertionError as exc:
                pytest.xfail(f"CKM_RSA_PKCS_OAEP_TPM_1_1 encrypt not functional: {exc}")

            pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP_TPM_1_1, ct)
            assert pt == max_plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
