"""Padding oracle detection - Bleichenbacher/Vaudenay style.

Tests whether the module leaks information about padding validity through
different error codes or timing differences. A secure module should return
the same error code regardless of padding correctness.

Based on Bardou et al. "Efficient Padding Oracle Attacks on Cryptographic
Hardware" (CRYPTO 2012).
"""

from __future__ import annotations

import re
import time
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
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKG_MGF1_SHA1,
    CKM_AES_CBC_PAD,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
)

pytestmark = pytest.mark.security

# Regex to extract CKR error name from AssertionError messages
_CKR_RE = re.compile(r"CKR_\w+")


def _extract_ckr(exc: AssertionError) -> str:
    """Extract CKR error name from an AssertionError message."""
    m = _CKR_RE.search(str(exc))
    return m.group(0) if m else type(exc).__name__


class TestRSAPaddingOracle:
    """Check if RSA decryption leaks padding validity via error codes."""

    def test_pkcs1v15_error_uniformity(self, p11_raw_session: Any) -> None:
        """RSA PKCS#1 v1.5: invalid ciphertexts must all return same error code.

        A padding oracle exists if the module returns different errors for
        'valid padding but wrong content' vs 'invalid padding structure'.
        """
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            # Generate several types of invalid ciphertext
            error_types: set[str] = set()
            for _ in range(10):
                # Random garbage ciphertext
                bad_ct = generate_random(rs.raw, rs.sh, 256)  # 256 bytes = 2048 bits
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, bad_ct)
                    # Decryption succeeded with random data - very unlikely but possible
                except AssertionError as exc:
                    error_types.add(_extract_ckr(exc))

            # All errors should be the same type - if not, there's a potential oracle
            if len(error_types) > 1:
                pytest.fail(
                    f"SECURITY: RSA PKCS#1 v1.5 returns different error codes "
                    f"for invalid ciphertexts: {error_types}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_error_uniformity(self, p11_raw_session: Any) -> None:
        """RSA-OAEP: all invalid ciphertexts must return same error."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )
            error_types: set[str] = set()
            for _ in range(10):
                bad_ct = generate_random(rs.raw, rs.sh, 256)
                try:
                    decrypt_single(
                        rs.raw,
                        rs.sh,
                        priv,
                        CKM_RSA_PKCS_OAEP,
                        bad_ct,
                        mech_param=oaep,
                    )
                except AssertionError as exc:
                    error_types.add(_extract_ckr(exc))

            if len(error_types) > 1:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"SECURITY: NSS RSA-OAEP returns non-uniform error codes for invalid "
                    f"ciphertexts ({error_types}), enabling padding oracle attack "
                    f"(Manger 2001 / Bleichenbacher-style)",
                    ComplianceLevel.CRITICAL,
                    reference="Manger (2001); PKCS#11 v3.1 Sec.6.1.8: implementations "
                    "SHOULD return CKR_ENCRYPTED_DATA_INVALID uniformly",
                )
                pytest.xfail(
                    f"SECURITY: NSS RSA-OAEP padding oracle -- non-uniform error codes: "
                    f"{error_types} (Manger 2001 attack vector)"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestAESPaddingOracle:
    """Check if AES-CBC padding errors leak information."""

    def test_cbc_pad_error_uniformity(self, p11_raw_session: Any) -> None:
        """AES-CBC-PAD: corrupted ciphertext at different positions must
        return the same error code.

        Corrupting the last byte affects padding; corrupting a middle byte
        affects plaintext content. If these return different errors, there's
        a padding oracle.
        """
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        iv = generate_random(rs.raw, rs.sh, 16)
        plaintext = b"padding oracle!!"  # 16 bytes

        try:
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )

            error_last_byte: str | None = None
            error_middle_byte: str | None = None

            # Corrupt last byte (affects padding)
            ct_bad_pad = bytearray(ct)
            ct_bad_pad[-1] ^= 0xFF
            try:
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC_PAD,
                    bytes(ct_bad_pad),
                    mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                )
            except AssertionError as exc:
                error_last_byte = _extract_ckr(exc)

            # Corrupt middle byte (affects content, not padding)
            ct_bad_mid = bytearray(ct)
            ct_bad_mid[len(ct) // 2] ^= 0xFF
            try:
                decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC_PAD,
                    bytes(ct_bad_mid),
                    mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                )
            except AssertionError as exc:
                error_middle_byte = _extract_ckr(exc)

            if error_last_byte and error_middle_byte and error_last_byte != error_middle_byte:
                pytest.fail(
                    f"SECURITY: AES-CBC padding oracle - last byte error "
                    f"({error_last_byte}) differs from middle byte ({error_middle_byte})"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestTimingBasic:
    """Basic timing difference checks.

    NOTE: These are sanity checks, not lab-grade timing analysis.
    Proper timing analysis requires controlled environments.
    """

    def test_rsa_decrypt_timing_sanity(self, p11_raw_session: Any) -> None:
        """RSA decrypt: valid vs invalid ciphertext timing should be similar.

        We measure wall-clock time for 50 valid and 50 invalid decryptions.
        If the difference is >2x, there may be a timing oracle.
        """
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            # Valid ciphertext
            valid_ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"timing test")

            # Time valid decryptions
            valid_times = []
            for _ in range(50):
                start = time.perf_counter()
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, valid_ct)
                except AssertionError:
                    pass
                valid_times.append(time.perf_counter() - start)

            # Time invalid decryptions
            invalid_times = []
            for _ in range(50):
                bad_ct = generate_random(rs.raw, rs.sh, 256)
                start = time.perf_counter()
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, bad_ct)
                except AssertionError:
                    pass
                invalid_times.append(time.perf_counter() - start)

            valid_avg = sum(valid_times) / len(valid_times)
            invalid_avg = sum(invalid_times) / len(invalid_times)

            # If one is more than 3x the other, flag it
            if valid_avg > 0 and invalid_avg > 0:
                ratio = max(valid_avg, invalid_avg) / min(valid_avg, invalid_avg)
                if ratio > 3.0:
                    pytest.fail(
                        f"TIMING: RSA decrypt timing ratio {ratio:.1f}x "
                        f"(valid={valid_avg * 1000:.2f}ms, invalid={invalid_avg * 1000:.2f}ms)"
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
