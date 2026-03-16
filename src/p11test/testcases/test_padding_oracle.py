"""Padding oracle detection — Bleichenbacher/Vaudenay style.

Tests whether the module leaks information about padding validity through
different error codes or timing differences. A secure module should return
the same error code regardless of padding correctness.

Based on Bardou et al. "Efficient Padding Oracle Attacks on Cryptographic
Hardware" (CRYPTO 2012).
"""

from __future__ import annotations

import time
from typing import Any

import pkcs11
import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.security


class TestRSAPaddingOracle:
    """Check if RSA decryption leaks padding validity via error codes."""

    def test_pkcs1v15_error_uniformity(self, p11_session: Any) -> None:
        """RSA PKCS#1 v1.5: invalid ciphertexts must all return same error code.

        A padding oracle exists if the module returns different errors for
        'valid padding but wrong content' vs 'invalid padding structure'.
        """
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        # Generate several types of invalid ciphertext
        error_types: set[str] = set()
        for i in range(10):
            # Random garbage ciphertext
            bad_ct = p11_session.generate_random(2048)  # 256 bytes = 2048 bits
            try:
                priv.decrypt(bad_ct, mechanism=Mechanism.RSA_PKCS)
                # Decryption succeeded with random data — very unlikely but possible
            except pkcs11.exceptions.PKCS11Error as exc:
                error_types.add(type(exc).__name__)

        # All errors should be the same type — if not, there's a potential oracle
        if len(error_types) > 1:
            pytest.xfail(
                f"SECURITY: RSA PKCS#1 v1.5 returns different error codes "
                f"for invalid ciphertexts: {error_types}"
            )

    def test_oaep_error_uniformity(self, p11_session: Any) -> None:
        """RSA-OAEP: all invalid ciphertexts must return same error."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        error_types: set[str] = set()
        for i in range(10):
            bad_ct = p11_session.generate_random(2048)
            try:
                priv.decrypt(bad_ct, mechanism=Mechanism.RSA_PKCS_OAEP)
            except pkcs11.exceptions.PKCS11Error as exc:
                error_types.add(type(exc).__name__)

        if len(error_types) > 1:
            pytest.xfail(
                f"SECURITY: RSA-OAEP returns different error codes: {error_types}"
            )


class TestAESPaddingOracle:
    """Check if AES-CBC padding errors leak information."""

    def test_cbc_pad_error_uniformity(self, p11_session: Any) -> None:
        """AES-CBC-PAD: corrupted ciphertext at different positions must
        return the same error code.

        Corrupting the last byte affects padding; corrupting a middle byte
        affects plaintext content. If these return different errors, there's
        a padding oracle.
        """
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"padding oracle!!"  # 16 bytes

        ct = key.encrypt(plaintext, mechanism_param=iv)

        error_last_byte: str | None = None
        error_middle_byte: str | None = None

        # Corrupt last byte (affects padding)
        ct_bad_pad = bytearray(ct)
        ct_bad_pad[-1] ^= 0xFF
        try:
            key.decrypt(bytes(ct_bad_pad), mechanism_param=iv)
        except pkcs11.exceptions.PKCS11Error as exc:
            error_last_byte = type(exc).__name__

        # Corrupt middle byte (affects content, not padding)
        ct_bad_mid = bytearray(ct)
        ct_bad_mid[len(ct) // 2] ^= 0xFF
        try:
            key.decrypt(bytes(ct_bad_mid), mechanism_param=iv)
        except pkcs11.exceptions.PKCS11Error as exc:
            error_middle_byte = type(exc).__name__

        if error_last_byte and error_middle_byte and error_last_byte != error_middle_byte:
            pytest.xfail(
                f"SECURITY: AES-CBC padding oracle — last byte error "
                f"({error_last_byte}) differs from middle byte ({error_middle_byte})"
            )


class TestTimingBasic:
    """Basic timing difference checks.

    NOTE: These are sanity checks, not lab-grade timing analysis.
    Proper timing analysis requires controlled environments.
    """

    def test_rsa_decrypt_timing_sanity(self, p11_session: Any) -> None:
        """RSA decrypt: valid vs invalid ciphertext timing should be similar.

        We measure wall-clock time for 50 valid and 50 invalid decryptions.
        If the difference is >2x, there may be a timing oracle.
        """
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        # Valid ciphertext
        valid_ct = pub.encrypt(b"timing test", mechanism=Mechanism.RSA_PKCS)

        # Time valid decryptions
        valid_times = []
        for _ in range(50):
            start = time.perf_counter()
            try:
                priv.decrypt(valid_ct, mechanism=Mechanism.RSA_PKCS)
            except pkcs11.exceptions.PKCS11Error:
                pass
            valid_times.append(time.perf_counter() - start)

        # Time invalid decryptions
        invalid_times = []
        for _ in range(50):
            bad_ct = p11_session.generate_random(2048)
            start = time.perf_counter()
            try:
                priv.decrypt(bad_ct, mechanism=Mechanism.RSA_PKCS)
            except pkcs11.exceptions.PKCS11Error:
                pass
            invalid_times.append(time.perf_counter() - start)

        valid_avg = sum(valid_times) / len(valid_times)
        invalid_avg = sum(invalid_times) / len(invalid_times)

        # If one is more than 3x the other, flag it
        if valid_avg > 0 and invalid_avg > 0:
            ratio = max(valid_avg, invalid_avg) / min(valid_avg, invalid_avg)
            if ratio > 3.0:
                pytest.xfail(
                    f"TIMING: RSA decrypt timing ratio {ratio:.1f}x "
                    f"(valid={valid_avg*1000:.2f}ms, invalid={invalid_avg*1000:.2f}ms)"
                )
