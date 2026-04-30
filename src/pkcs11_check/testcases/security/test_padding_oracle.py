"""Padding oracle detection - Bleichenbacher/Vaudenay style.

Tests whether the module leaks information about padding validity through
different error codes or timing differences. A secure module should return
the same error code regardless of padding correctness.

Based on Bardou et al. "Efficient Padding Oracle Attacks on Cryptographic
Hardware" (CRYPTO 2012) and Manger (CRYPTO 2001).
"""

from __future__ import annotations

import re
import secrets
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
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
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
                    f"RSA-OAEP returns non-uniform error codes for invalid "
                    f"ciphertexts ({error_types}), enabling padding oracle attack "
                    f"(Manger 2001 / Bleichenbacher-style)",
                    ComplianceLevel.CRITICAL,
                    reference="Manger (2001); PKCS#11 v3.1 Sec.6.1.8: implementations "
                    "SHOULD return CKR_ENCRYPTED_DATA_INVALID uniformly",
                )
                pytest.fail(
                    f"SECURITY: RSA-OAEP padding oracle — non-uniform error codes: "
                    f"{error_types} (Manger 2001 attack vector). Distinct CKRs "
                    f"on invalid ciphertexts let an attacker partition decryption "
                    f"failures into categories — exactly the Manger leak channel."
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pkcs1v15_bleichenbacher_structured_oracle(
        self, p11_raw_session: Any
    ) -> None:
        """RSA PKCS#1 v1.5 Bleichenbacher 1998 structured-ciphertext oracle.

        Bleichenbacher's attack distinguishes ciphertexts whose decryption
        starts with the correct ``00 02`` PKCS#1 v1.5 prefix (cat-1, "valid
        padding format / bad content") from those that don't (cat-2,
        "invalid padding format"). A secure module returns identical
        errors for both categories — distinct CKRs are the leak channel.

        The pre-existing test_pkcs1v15_error_uniformity uses 10 random
        ciphertexts which overwhelmingly fall in cat-2 because random m
        almost never starts with ``00 02``. This test explicitly
        constructs cat-1 ciphertexts by choosing m with the ``00 02``
        prefix and short / no PS-separator, ensuring the per-category
        error sets are populated.

        Closes Phase 4.5 GAP-P2 (HIGH).
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
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT]
                )
            except AssertionError as exc:
                pytest.skip(
                    f"Module does not expose CKA_MODULUS / CKA_PUBLIC_EXPONENT: {exc}"
                )
                return

            n_bytes = attrs[CKA_MODULUS]
            e_bytes = attrs[CKA_PUBLIC_EXPONENT]
            if not isinstance(n_bytes, bytes) or not isinstance(e_bytes, bytes):
                pytest.skip("Modulus / exponent not returned as bytes")
                return
            n = int.from_bytes(n_bytes, "big")
            e = int.from_bytes(e_bytes, "big")
            k = (n.bit_length() + 7) // 8

            cat1_errors: set[str] = set()  # 00 02 prefix, missing PS-separator
            cat2_errors: set[str] = set()  # arbitrary, no 00 02 prefix

            samples_per_category = 50
            for _ in range(samples_per_category):
                # Cat-1: m starts with 0x00 0x02 followed by random non-zero
                # bytes through to the end (no 0x00 separator → garbled
                # plaintext but valid prefix). PS must be ≥ 8 bytes per
                # PKCS#1 v1.5; our cat-1 has ≥ k-2 bytes which is far over.
                ps_body = bytes(
                    [b if b != 0 else 0x01 for b in secrets.token_bytes(k - 2)]
                )
                m1_bytes = b"\x00\x02" + ps_body
                m1 = int.from_bytes(m1_bytes, "big")
                if m1 >= n:
                    # Force m < n by clearing the top bit of byte 2.
                    m1_bytes = bytes([0x00, 0x02, ps_body[0] & 0x7F]) + ps_body[1:]
                    m1 = int.from_bytes(m1_bytes, "big")
                c1 = pow(m1, e, n)
                c1_bytes = c1.to_bytes(k, "big")
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, c1_bytes)
                except AssertionError as exc:
                    cat1_errors.add(_extract_ckr(exc))

                # Cat-2: m has random non-{00,02} prefix → invalid padding
                # format. Force the top byte != 0 to ensure cat-2.
                while True:
                    m2_bytes = secrets.token_bytes(k)
                    if m2_bytes[0] != 0x00:  # any non-zero high byte → not cat-1
                        break
                m2 = int.from_bytes(m2_bytes, "big") % n
                c2 = pow(m2, e, n)
                c2_bytes = c2.to_bytes(k, "big")
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, c2_bytes)
                except AssertionError as exc:
                    cat2_errors.add(_extract_ckr(exc))

            if cat1_errors != cat2_errors:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"RSA PKCS#1 v1.5 returns category-distinguishable error "
                    f"codes — cat-1 (00 02 prefix, bad PS): {cat1_errors}, "
                    f"cat-2 (no 00 02 prefix): {cat2_errors}. This is the "
                    f"Bleichenbacher 1998 leak channel.",
                    ComplianceLevel.CRITICAL,
                    reference="Bleichenbacher 'Chosen Ciphertext Attacks "
                    "Against Protocols Based on the RSA Encryption Standard "
                    "PKCS #1' (CRYPTO 1998); RFC 3218",
                )
                pytest.fail(
                    f"SECURITY: RSA PKCS#1 v1.5 Bleichenbacher 1998 oracle — "
                    f"cat-1 errors {cat1_errors} != cat-2 errors {cat2_errors}. "
                    f"An attacker who can submit chosen ciphertexts can "
                    f"recover the plaintext via roughly 2^20 oracle queries."
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_manger_structured_oracle(self, p11_raw_session: Any) -> None:
        """RSA-OAEP Manger 2001 structured-ciphertext oracle.

        Manger's attack distinguishes ciphertexts whose decryption m falls
        below B = 2^(8*(k-1)) (top byte zero) from those at or above B
        (top byte non-zero). A secure RSA-OAEP implementation returns
        identical errors for both categories — the bug is otherwise the
        primary lever for the Manger chosen-ciphertext attack.

        This goes beyond the existing test_oaep_error_uniformity (which
        uses 10 random ciphertexts) by:
        - reading the actual public modulus n and computing B from it,
        - constructing 50 cat-1 ciphertexts (m < B, top byte zero) and
          50 cat-2 ciphertexts (m >= B, top byte non-zero) via raw
          modular exponentiation c = m^e mod n outside PKCS#11,
        - comparing the resulting error-code sets per category.

        Closes Phase 4.5 GAP-P1 (HIGH).
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
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT]
                )
            except AssertionError as exc:
                pytest.skip(f"Module does not expose CKA_MODULUS / CKA_PUBLIC_EXPONENT: {exc}")
                return

            n_bytes = attrs[CKA_MODULUS]
            e_bytes = attrs[CKA_PUBLIC_EXPONENT]
            if not isinstance(n_bytes, bytes) or not isinstance(e_bytes, bytes):
                pytest.skip("Modulus / exponent not returned as bytes")
                return
            n = int.from_bytes(n_bytes, "big")
            e = int.from_bytes(e_bytes, "big")
            k = (n.bit_length() + 7) // 8
            boundary = 1 << (8 * (k - 1))

            oaep = mech_oaep(
                CKM_RSA_PKCS_OAEP,
                hash_mech=CKM_SHA_1,
                mgf=CKG_MGF1_SHA1,
            )

            cat1_errors: set[str] = set()  # m < B (top byte == 0)
            cat2_errors: set[str] = set()  # m >= B (top byte != 0)

            samples_per_category = 50
            for _ in range(samples_per_category):
                # Cat-1: random m in [1, B). Top byte is 0.
                m1 = secrets.randbelow(boundary - 1) + 1
                c1 = pow(m1, e, n)
                c1_bytes = c1.to_bytes(k, "big")
                try:
                    decrypt_single(
                        rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, c1_bytes, mech_param=oaep
                    )
                except AssertionError as exc:
                    cat1_errors.add(_extract_ckr(exc))

                # Cat-2: random m in [B, n). Top byte is non-zero.
                m2 = boundary + secrets.randbelow(n - boundary)
                c2 = pow(m2, e, n)
                c2_bytes = c2.to_bytes(k, "big")
                try:
                    decrypt_single(
                        rs.raw, rs.sh, priv, CKM_RSA_PKCS_OAEP, c2_bytes, mech_param=oaep
                    )
                except AssertionError as exc:
                    cat2_errors.add(_extract_ckr(exc))

            # Manger leak: the two categories produce DIFFERENT error sets.
            if cat1_errors != cat2_errors:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"RSA-OAEP returns category-distinguishable error codes — "
                    f"cat-1 (m<B, top-byte=0): {cat1_errors}, "
                    f"cat-2 (m>=B, top-byte!=0): {cat2_errors}. This is the "
                    f"Manger 2001 leak channel.",
                    ComplianceLevel.CRITICAL,
                    reference="Manger 'A Chosen Ciphertext Attack on RSA "
                    "Optimal Asymmetric Encryption Padding (OAEP) as "
                    "Standardized in PKCS #1 v2.0' (CRYPTO 2001)",
                )
                pytest.fail(
                    f"SECURITY: RSA-OAEP Manger 2001 padding oracle — "
                    f"cat-1 errors {cat1_errors} != cat-2 errors {cat2_errors}. "
                    f"An attacker who can submit chosen ciphertexts can "
                    f"recover the plaintext via roughly k * log2(k) "
                    f"oracle queries."
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
