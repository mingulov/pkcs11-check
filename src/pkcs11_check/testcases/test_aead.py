"""Tests for AEAD (Authenticated Encryption) - AES-GCM cross-verification.

Verifies AES-GCM encrypt/decrypt via PKCS#11 against Python cryptography.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import mech_gcm, mech_gcm_generated_iv
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_GCM,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    skip_if_mech_param_unsupported,
)

pytestmark = pytest.mark.crossverify


def _import_aes(rs: Any, key_bytes: bytes) -> int:
    """Import an AES key with encrypt/decrypt for the raw session."""
    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs={
            CKA_ENCRYPT: True,
            CKA_DECRYPT: True,
            CKA_TOKEN: False,
        },
    )


def _encrypt_gcm_generated_iv(
    rs: Any,
    key: int,
    mech: Any,
    plaintext: bytes,
    *,
    convention: str,
) -> bytes:
    """Encrypt via the standard recipe, skipping cleanly on unsupported-CKR rejections.

    Wraps ``encrypt_single`` so the generated-IV convention probes share their
    two-call buffer logic (including the CKR_BUFFER_TOO_SMALL retry) with every
    other AEAD path instead of reimplementing it.
    """
    try:
        return encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_GCM,
            plaintext,
            mech_param=mech,
            output_overhead=16,
            retry_on_buffer_too_small=True,
        )
    except AssertionError as exc:
        skip_if_mech_param_unsupported(
            exc,
            f"CKM_AES_GCM provider-generated IV convention {convention!r}",
        )
        return b""  # unreachable — helper either skips or re-raises


class TestAESGCMCrossVerify:
    """Cross-verify AES-GCM against Python cryptography."""

    def test_gcm_256_encrypt_crossverify(self, p11_raw_session: Any) -> None:
        """AES-256-GCM: encrypt via PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        key_bytes = bytes(range(32))
        nonce = bytes(12)  # 96-bit recommended IV
        plaintext = b"GCM cross-verify test data!!"
        aad = b"additional authenticated data"

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_ct = encrypt_single(
                rs.raw,
                rs.sh,
                p11_key,
                CKM_AES_GCM,
                plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
                output_overhead=16,  # GCM appends a 128-bit (16-byte) authentication tag
            )

            # p11 returns ciphertext + tag concatenated
            # cryptography returns the same format
            aesgcm = AESGCM(key_bytes)
            crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_128_encrypt_crossverify(self, p11_raw_session: Any) -> None:
        """AES-128-GCM cross-verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        key_bytes = bytes(16)
        nonce = bytes(range(12))
        plaintext = b"GCM-128 test!!"

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_ct = encrypt_single(
                rs.raw,
                rs.sh,
                p11_key,
                CKM_AES_GCM,
                plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, tag_bits=128),
                output_overhead=16,  # GCM appends a 128-bit (16-byte) authentication tag
            )

            aesgcm = AESGCM(key_bytes)
            crypto_ct = aesgcm.encrypt(nonce, plaintext, None)

            assert p11_ct == crypto_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_decrypt_crossverify(self, p11_raw_session: Any) -> None:
        """Encrypt with cryptography, decrypt with PKCS#11."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"decrypt cross-verify"
        aad = b"aad data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        p11_key = _import_aes(rs, key_bytes)
        try:
            p11_pt = decrypt_single(
                rs.raw,
                rs.sh,
                p11_key,
                CKM_AES_GCM,
                crypto_ct,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            assert p11_pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_tampered_tag_rejected(self, p11_raw_session: Any) -> None:
        """Tampered GCM ciphertext must be rejected by PKCS#11."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"tamper detection"
        aad = b"auth data"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, aad)

        # Tamper with the tag (last 16 bytes)
        tampered = bytearray(crypto_ct)
        tampered[-1] ^= 0xFF

        p11_key = _import_aes(rs, key_bytes)
        try:
            with pytest.raises(AssertionError):
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    p11_key,
                    CKM_AES_GCM,
                    bytes(tampered),
                    mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_gcm_wrong_aad_rejected(self, p11_raw_session: Any) -> None:
        """Wrong AAD must cause decryption failure."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        nonce = bytes(12)
        plaintext = b"aad integrity"

        aesgcm = AESGCM(key_bytes)
        crypto_ct = aesgcm.encrypt(nonce, plaintext, b"correct aad")

        p11_key = _import_aes(rs, key_bytes)
        try:
            with pytest.raises(AssertionError):
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    p11_key,
                    CKM_AES_GCM,
                    crypto_ct,
                    mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=b"wrong aad", tag_bits=128),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestAESGCMProperties:
    """Test AES-GCM AEAD properties."""

    def test_gcm_different_nonces_different_ct(self, p11_raw_session: Any) -> None:
        """Same key+plaintext with different nonces must produce different ciphertext."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        plaintext = b"nonce uniqueness"

        nonce1 = generate_random(rs.raw, rs.sh, 12)
        nonce2 = generate_random(rs.raw, rs.sh, 12)

        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce1, tag_bits=128),
                output_overhead=16,  # GCM appends a 128-bit (16-byte) authentication tag
            )
            ct2 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce2, tag_bits=128),
                output_overhead=16,
            )

            assert ct1 != ct2
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_gcm_roundtrip(self, p11_raw_session: Any) -> None:
        """GCM encrypt then decrypt must return original plaintext."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 256)
        nonce = generate_random(rs.raw, rs.sh, 12)
        plaintext = b"GCM roundtrip test data"
        aad = b"authenticated but not encrypted"

        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                plaintext,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
                output_overhead=16,  # GCM appends a 128-bit (16-byte) authentication tag
            )

            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ct,
                mech_param=mech_gcm(CKM_AES_GCM, nonce, aad=aad, tag_bits=128),
            )

            assert pt == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.vendor
class TestAESGCMProviderGeneratedIV:
    """Provider-generated IV workflows exposed by HSM/vendor behavior."""

    def test_gcm_generated_iv_strict_writeback_two_call(self, p11_raw_session: Any) -> None:
        """CKM_AES_GCM strict generated-IV convention writes IV back to pIv.

        This covers the pkcs11-proxy/CloudHSM class of workflows where the caller
        supplies a writable pIv buffer but requests provider IV generation via
        ulIvLen=0 and ulIvBits=96. Unsupported modules may reject the parameter;
        accepting it but not writing an IV back is a behavioral finding.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        note(
            "CKM_AES_GCM provider-generated IV via ulIvLen=0/ulIvBits=N",
            ComplianceLevel.VENDOR,
            reference="AWS CloudHSM and Thales Luna/PTK generated-IV behavior",
        )

        key_bytes = bytes(range(32))
        plaintext = b"classic GCM generated IV strict"
        aad = b"generated-iv-aad"
        key = _import_aes(rs, key_bytes)
        try:
            mech = mech_gcm_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                aad=aad,
                tag_bits=128,
                convention="strict",
            )
            ciphertext = _encrypt_gcm_generated_iv(
                rs,
                key,
                mech,
                plaintext,
                convention="strict",
            )
            iv = mech.buffer_bytes("iv")
            if not any(iv):
                pytest.skip(
                    "module accepted strict generated-IV-shaped parameters, but no "
                    "provider-generated IV writeback was observed"
                )

            decrypted = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ciphertext,
                mech_param=mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=128),
                retry_on_buffer_too_small=True,
            )
            assert decrypted == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_gcm_generated_iv_aws_style_writeback_two_call(self, p11_raw_session: Any) -> None:
        """AWS CloudHSM-style CKM_AES_GCM generated IV writes IV back to pIv.

        AWS CloudHSM callers use a zeroized pIv with ulIvLen=12 and ulIvBits=0.
        Standard software modules may reasonably treat that as a caller-supplied
        all-zero IV; those are skipped because no generated-IV writeback occurred.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")
        note(
            "CKM_AES_GCM provider-generated IV via AWS CloudHSM zeroized pIv convention",
            ComplianceLevel.VENDOR,
            reference="AWS CloudHSM CK_GCM_PARAMS pIV writeback",
        )

        key_bytes = bytes(range(32))
        plaintext = b"classic GCM generated IV aws"
        aad = b"generated-iv-aad"
        key = _import_aes(rs, key_bytes)
        try:
            mech = mech_gcm_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                aad=aad,
                tag_bits=128,
                convention="aws",
            )
            ciphertext = _encrypt_gcm_generated_iv(
                rs,
                key,
                mech,
                plaintext,
                convention="aws",
            )
            iv = mech.buffer_bytes("iv")
            if not any(iv):
                pytest.skip(
                    "module treated AWS-style parameters as caller-supplied zero IV; "
                    "no provider-generated IV writeback observed"
                )

            decrypted = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_GCM,
                ciphertext,
                mech_param=mech_gcm(CKM_AES_GCM, iv, aad=aad, tag_bits=128),
                retry_on_buffer_too_small=True,
            )
            assert decrypted == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
