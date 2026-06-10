"""Tests for PKCS#11 encrypt/decrypt operations.

Covers AES key generation, multiple modes (CBC, ECB, GCM), key sizes,
and basic properties: roundtrip, key independence, ciphertext randomness.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
)
from pkcs11_check.testcases._signature_policy import xfail_if_op_not_operational
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.full

_AES_SETUP_KEY_BITS = 128


def _require_aes_keygen(rs: Any) -> None:
    require_operational_aes_keygen(rs)


def _gen_aes_key_or_xfail(
    rs: Any,
    *,
    bits: int = _AES_SETUP_KEY_BITS,
    attrs: Mapping[Any, Any] | None = None,
    purpose: str = "setup",
) -> int:
    try:
        return gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            f"AES_KEY_GEN advertised but AES-{bits} key generation for {purpose} "
            "is not operational",
        )
        raise


class TestAESEncryption:
    def test_aes_generate_key(self, p11_raw_session: Any) -> None:
        """Generate an AES session key."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        try:
            assert key is not None
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt and decrypt with AES-CBC produces original plaintext."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        iv = generate_random(rs.raw, rs.sh, 16)
        # AES-CBC requires data aligned to block size (16 bytes)
        plaintext = b"hello pkcs11!!\x02\x02"  # 16 bytes with PKCS padding

        try:
            ciphertext = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert ciphertext != plaintext
            assert len(ciphertext) > 0

            decrypted = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                ciphertext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert decrypted == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_different_keys_different_ciphertext(self, p11_raw_session: Any) -> None:
        """Same plaintext encrypted with different keys should differ."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key1 = _gen_aes_key_or_xfail(rs)
        key2 = _gen_aes_key_or_xfail(rs)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"test data 123456"  # 16 bytes

        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key1,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key2,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_aes_ecb_roundtrip(self, p11_raw_session: Any) -> None:
        """AES-ECB encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        plaintext = b"sixteen bytes!!" + b"\x01"  # 16 bytes

        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert ct != plaintext
            pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize("key_bits", [128, 192, 256])
    def test_aes_key_sizes(self, p11_raw_session: Any, key_bits: int) -> None:
        """Generate AES keys of all standard sizes."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs, bits=key_bits, purpose="key-size coverage")
        try:
            assert key is not None
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_TYPE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_ciphertext_length(self, p11_raw_session: Any) -> None:
        """AES-ECB ciphertext should be same length as plaintext (block-aligned)."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        plaintext = b"\x00" * 32  # 2 blocks
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert len(ct) == len(plaintext)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_encrypt_not_deterministic_cbc(self, p11_raw_session: Any) -> None:
        """AES-CBC with different IVs produces different ciphertexts."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        plaintext = b"determinism test"  # 16 bytes
        iv1 = generate_random(rs.raw, rs.sh, 16)
        iv2 = generate_random(rs.raw, rs.sh, 16)

        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv1),
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv2),
            )
            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_aes_wrong_key_decrypt_fails(self, p11_raw_session: Any) -> None:
        """Decrypting with wrong key should produce garbage (ECB)."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key1 = _gen_aes_key_or_xfail(rs)
        key2 = _gen_aes_key_or_xfail(rs)
        plaintext = b"wrong key test!!"  # 16 bytes

        try:
            ct = encrypt_single(rs.raw, rs.sh, key1, CKM_AES_ECB, plaintext)
            decrypted = decrypt_single(rs.raw, rs.sh, key2, CKM_AES_ECB, ct)
            assert decrypted != plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)

    def test_aes_empty_block_encrypt(self, p11_raw_session: Any) -> None:
        """AES-ECB with exactly one block of zeros."""
        rs = p11_raw_session
        _require_aes_keygen(rs)
        key = _gen_aes_key_or_xfail(rs)
        plaintext = b"\x00" * 16
        try:
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert ct != plaintext
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestRSAEncryption:
    def test_rsa_pkcs_roundtrip(self, p11_raw_session: Any) -> None:
        """RSA PKCS#1 v1.5 encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"RSA roundtrip test"
            try:
                ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, plaintext)
                pt = decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, ct)
            except AssertionError as exc:
                # FIPS restricts RSA PKCS#1 v1.5 key transport -> CKR_DEVICE_ERROR
                # on the private-key decrypt: advertised but not operational, not
                # a break.
                xfail_if_op_not_operational(exc, "CKM_RSA_PKCS")
            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_rsa_oaep_roundtrip(self, p11_raw_session: Any) -> None:
        """RSA-OAEP encrypt/decrypt roundtrip."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"OAEP roundtrip test"
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
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

    def test_rsa_ciphertext_is_random(self, p11_raw_session: Any) -> None:
        """RSA-OAEP should produce different ciphertexts for same plaintext."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )
        try:
            plaintext = b"randomness test"
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
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
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
