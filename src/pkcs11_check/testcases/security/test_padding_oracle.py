"""Padding oracle detection - Bleichenbacher/Vaudenay style.

Tests whether the module leaks information about padding validity through
different error codes or timing differences. A secure module should return
the same error code regardless of padding correctness.

Based on Bardou et al. "Efficient Padding Oracle Attacks on Cryptographic
Hardware" (CRYPTO 2012) and Manger (CRYPTO 2001).
"""

from __future__ import annotations

import ctypes
import re
import secrets
import time
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes, mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_TOKEN,
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKG_MGF1_SHA1,
    CKM_AES_CBC_PAD,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA_1,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    require_operational_aes_keygen,
    skip_unless_mechanism_flag,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

# Regex to extract CKR error name from AssertionError messages
_CKR_RE = re.compile(r"CKR_\w+")


def _extract_ckr(exc: AssertionError) -> str:
    """Extract CKR error name from an AssertionError message."""
    m = _CKR_RE.search(str(exc))
    return m.group(0) if m else type(exc).__name__


def _abort_decrypt_operation(raw: Any, session: int) -> None:
    """Best-effort cleanup after an expected decrypt error leaves state active."""
    try:
        out_buf = (ctypes.c_ubyte * 4096)()
        out_len = CK_ULONG(4096)
        raw.C_DecryptFinal(session, out_buf, ctypes.byref(out_len))
    except (AttributeError, OSError, ctypes.ArgumentError):
        pass


def _decrypt_result_or_error(
    raw: Any,
    session: int,
    key: int,
    mechanism: int,
    ciphertext: bytes,
    *,
    mech_param: Any | None = None,
) -> tuple[bytes | None, str | None]:
    try:
        result = decrypt_single(
            raw,
            session,
            key,
            mechanism,
            ciphertext,
            mech_param=mech_param,
        )
    except AssertionError as exc:
        error = _extract_ckr(exc)
        _abort_decrypt_operation(raw, session)
        return None, error
    return result, None


def _read_rsa_public_numbers_or_xfail(
    rs: Any,
    pub: int,
    *,
    min_modulus_bytes: int = 11,
) -> tuple[int, int, int]:
    """Read usable RSA public numbers for structured-oracle construction.

    A provider that successfully generates an RSA keypair but returns malformed
    public attributes is an advertised-but-not-operational finding. Report that
    as xfail evidence instead of allowing unrelated Python arithmetic errors.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT])
    except AssertionError as exc:
        pytest.skip(f"Module does not expose CKA_MODULUS / CKA_PUBLIC_EXPONENT: {exc}")

    n_bytes = attrs[CKA_MODULUS]
    e_bytes = attrs[CKA_PUBLIC_EXPONENT]
    if not isinstance(n_bytes, bytes) or not isinstance(e_bytes, bytes):
        classify(
            "not_operational",
            kind="crypto",
            label="RSA public-number readback",
            operation="C_GenerateKeyPair",
            summary="unusable RSA public modulus/exponent: attributes are not bytes",
        )

    n = int.from_bytes(n_bytes, "big")
    e = int.from_bytes(e_bytes, "big")
    k = (n.bit_length() + 7) // 8
    if n < 3 or e < 3 or k < min_modulus_bytes:
        classify(
            "not_operational",
            kind="crypto",
            label="RSA public-number readback",
            operation="C_GenerateKeyPair",
            summary="unusable RSA public modulus/exponent: generated key attributes "
            f"cannot support structured padding-oracle probes (n_bits={n.bit_length()}, e={e})",
        )

    return n, e, k


class TestRSAPaddingOracle:
    """Check if RSA decryption leaks padding validity via error codes."""

    def test_pkcs1v15_error_uniformity(self, p11_raw_session: Any) -> None:
        """RSA PKCS#1 v1.5: invalid ciphertexts must all return same error code.

        A padding oracle exists if the module returns different errors for
        'valid padding but wrong content' vs 'invalid padding structure'.
        """
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
                _, error = _decrypt_result_or_error(rs.raw, rs.sh, priv, CKM_RSA_PKCS, bad_ct)
                if error is not None:
                    error_types.add(error)

            # All errors should be the same type - if not, there's a potential oracle
            if len(error_types) > 1:
                classify(
                    "oracle",
                    kind="crypto",
                    label="RSA PKCS#1 v1.5 padding oracle",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS",
                    summary="SECURITY: RSA PKCS#1 v1.5 returns different error codes "
                    f"for invalid ciphertexts: {error_types}",
                    detail={"channel": "error_code", "codes": sorted(error_types)},
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_oaep_error_uniformity(self, p11_raw_session: Any) -> None:
        """RSA-OAEP: all invalid ciphertexts must return same error."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
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
                _, error = _decrypt_result_or_error(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_OAEP,
                    bad_ct,
                    mech_param=oaep,
                )
                if error is not None:
                    error_types.add(error)

            if len(error_types) > 1:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"RSA-OAEP returns non-uniform error codes for invalid "
                    f"ciphertexts ({error_types}), enabling padding oracle attack "
                    f"(Manger 2001 / Bleichenbacher-style)",
                    ComplianceLevel.CRITICAL,
                    reference="Manger (2001); PKCS#11 v3.2: implementations "
                    "SHOULD return CKR_ENCRYPTED_DATA_INVALID uniformly",
                )
                classify(
                    "oracle",
                    kind="crypto",
                    label="RSA-OAEP padding oracle (Manger 2001)",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    summary="SECURITY: RSA-OAEP padding oracle — non-uniform error codes: "
                    f"{error_types} (Manger 2001 attack vector). Distinct CKRs "
                    f"on invalid ciphertexts let an attacker partition decryption "
                    f"failures into categories — exactly the Manger leak channel.",
                    detail={"channel": "error_code", "codes": sorted(error_types)},
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_pkcs1v15_bleichenbacher_structured_oracle(self, p11_raw_session: Any) -> None:
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            n, e, k = _read_rsa_public_numbers_or_xfail(rs, pub)

            cat1_errors: set[str] = set()  # 00 02 prefix, missing PS-separator
            cat2_errors: set[str] = set()  # arbitrary, no 00 02 prefix

            samples_per_category = 50
            for _ in range(samples_per_category):
                # Cat-1: m starts with 0x00 0x02 followed by random non-zero
                # bytes through to the end (no 0x00 separator → garbled
                # plaintext but valid prefix). PS must be ≥ 8 bytes per
                # PKCS#1 v1.5; our cat-1 has ≥ k-2 bytes which is far over.
                ps_body = bytes([b if b != 0 else 0x01 for b in secrets.token_bytes(k - 2)])
                m1_bytes = b"\x00\x02" + ps_body
                m1 = int.from_bytes(m1_bytes, "big")
                if m1 >= n:
                    # Force m < n by clearing the top bit of byte 2.
                    m1_bytes = bytes([0x00, 0x02, ps_body[0] & 0x7F]) + ps_body[1:]
                    m1 = int.from_bytes(m1_bytes, "big")
                c1 = pow(m1, e, n)
                c1_bytes = c1.to_bytes(k, "big")
                _, error = _decrypt_result_or_error(rs.raw, rs.sh, priv, CKM_RSA_PKCS, c1_bytes)
                if error is not None:
                    cat1_errors.add(error)

                # Cat-2: m has random non-{00,02} prefix → invalid padding
                # format. Force the top byte != 0 to ensure cat-2.
                while True:
                    m2_bytes = secrets.token_bytes(k)
                    if m2_bytes[0] != 0x00:  # any non-zero high byte → not cat-1
                        break
                m2 = int.from_bytes(m2_bytes, "big") % n
                c2 = pow(m2, e, n)
                c2_bytes = c2.to_bytes(k, "big")
                _, error = _decrypt_result_or_error(rs.raw, rs.sh, priv, CKM_RSA_PKCS, c2_bytes)
                if error is not None:
                    cat2_errors.add(error)

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
                classify(
                    "oracle",
                    kind="crypto",
                    label="RSA PKCS#1 v1.5 Bleichenbacher 1998 oracle",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS",
                    summary="SECURITY: RSA PKCS#1 v1.5 Bleichenbacher 1998 oracle — "
                    f"cat-1 errors {cat1_errors} != cat-2 errors {cat2_errors}. "
                    f"An attacker who can submit chosen ciphertexts can "
                    f"recover the plaintext via roughly 2^20 oracle queries.",
                    detail={
                        "channel": "error_code",
                        "cat1": sorted(cat1_errors),
                        "cat2": sorted(cat2_errors),
                    },
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
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            n, e, k = _read_rsa_public_numbers_or_xfail(rs, pub)
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
                _, error = _decrypt_result_or_error(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_OAEP,
                    c1_bytes,
                    mech_param=oaep,
                )
                if error is not None:
                    cat1_errors.add(error)

                # Cat-2: random m in [B, n). Top byte is non-zero.
                m2 = boundary + secrets.randbelow(n - boundary)
                c2 = pow(m2, e, n)
                c2_bytes = c2.to_bytes(k, "big")
                _, error = _decrypt_result_or_error(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_RSA_PKCS_OAEP,
                    c2_bytes,
                    mech_param=oaep,
                )
                if error is not None:
                    cat2_errors.add(error)

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
                classify(
                    "oracle",
                    kind="crypto",
                    label="RSA-OAEP Manger 2001 padding oracle",
                    operation="C_Decrypt",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    summary="SECURITY: RSA-OAEP Manger 2001 padding oracle — "
                    f"cat-1 errors {cat1_errors} != cat-2 errors {cat2_errors}. "
                    f"An attacker who can submit chosen ciphertexts can "
                    f"recover the plaintext via roughly k * log2(k) "
                    f"oracle queries.",
                    detail={
                        "channel": "error_code",
                        "cat1": sorted(cat1_errors),
                        "cat2": sorted(cat2_errors),
                    },
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
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        require_operational_aes_keygen(rs)
        key = gen_aes_key_or_xfail(rs, purpose="AES-CBC-PAD oracle setup")
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
            _, error_last_byte = _decrypt_result_or_error(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                bytes(ct_bad_pad),
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )

            # Corrupt middle byte (affects content, not padding)
            ct_bad_mid = bytearray(ct)
            ct_bad_mid[len(ct) // 2] ^= 0xFF
            _, error_middle_byte = _decrypt_result_or_error(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                bytes(ct_bad_mid),
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )

            if error_last_byte and error_middle_byte and error_last_byte != error_middle_byte:
                classify(
                    "oracle",
                    kind="crypto",
                    label="AES-CBC-PAD padding oracle",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_CBC_PAD",
                    summary="SECURITY: AES-CBC padding oracle - last byte error "
                    f"({error_last_byte}) differs from middle byte ({error_middle_byte})",
                    detail={
                        "channel": "error_code",
                        "last_byte": error_last_byte,
                        "middle_byte": error_middle_byte,
                    },
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cbc_pad_all_last_block_positions(self, p11_raw_session: Any) -> None:
        """AES-CBC-PAD: corrupting each of the 16 byte positions of the last
        ciphertext block — sweep across many independent key+IV trials.

        Vaudenay 2002 / POODLE-style padding-oracle attacks exploit
        differences between "valid PKCS#7 padding, wrong content" and
        "invalid PKCS#7 padding". When an attacker bit-flips the last
        block of a CBC-PAD ciphertext, the resulting plaintext is
        randomly distributed — about 6/256 of corruptions produce
        accidentally-valid padding (0x01, 0x0202, 0x030303 … 16×0x10).
        A module that distinguishes the accidentally-valid path
        (CKR_OK) from the invalid-padding path
        (CKR_ENCRYPTED_DATA_INVALID) leaks the oracle bit on each
        chosen-ciphertext query.

        This is an INHERENT property of PKCS#7 padding without
        integrity — every conforming CBC-PAD implementation that
        responds with CKR_OK on accidentally-valid padding leaks the
        Vaudenay channel. The mitigation lives at the application
        layer (use AES-GCM or RFC 7366 encrypt-then-MAC), not the
        module layer. This test surfaces the channel by sweeping
        20 trials × 16 positions = 320 corruption probes; with
        ~6/256 ≈ 2.3% chance per probe of producing CKR_OK, the
        chance that all 320 land on CKR_ENCRYPTED_DATA_INVALID is
        about 0.05%. Effectively-deterministic detection.

        Closes Phase 4.5 GAP-P3 (MED).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        require_operational_aes_keygen(rs)
        plaintext = b"vaudenay POODLE all 16 positions"  # 32 bytes
        assert len(plaintext) == 32

        # Classification per probe:
        #   "CKR_<X>"            — module raised; recorded CKR
        #   "CKR_OK_MATCH"       — decrypt returned CKR_OK with bytes
        #                          matching the original plaintext (only
        #                          possible if the bit-flip happened to
        #                          produce a self-consistent plaintext;
        #                          extremely unlikely for AES-CBC, but
        #                          counted distinctly for completeness)
        #   "CKR_OK_DIFFERENT"   — decrypt returned CKR_OK with garbage
        #                          plaintext (the canonical Vaudenay
        #                          leak: padding validated, content
        #                          differs from original)
        # Distinguishing "_MATCH" / "_DIFFERENT" / CKR sets disambiguates
        # the M1 + M5 audit findings: a module that silently accepts ALL
        # corrupted CTs as CKR_OK with garbage plaintext is leaking CT
        # malleability (worse than Vaudenay), distinct from a module
        # that uniformly rejects (real mitigation).
        all_errors: dict[tuple[int, int], str] = {}

        keys: list[int] = []
        try:
            trials = 20
            for trial in range(trials):
                key = gen_aes_key_or_xfail(rs, purpose="AES-CBC-PAD oracle sweep setup")
                keys.append(key)
                iv = generate_random(rs.raw, rs.sh, 16)
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC_PAD,
                    plaintext,
                    mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                )
                assert len(ct) >= 32, f"Unexpectedly short CT: {len(ct)}"
                last_block_start = len(ct) - 16
                for pos in range(16):
                    corrupted = bytearray(ct)
                    corrupted[last_block_start + pos] ^= 0xFF
                    result, error = _decrypt_result_or_error(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM_AES_CBC_PAD,
                        bytes(corrupted),
                        mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                    )
                    if error is not None:
                        all_errors[(trial, pos)] = error
                    else:
                        assert result is not None
                        # Decrypt succeeded — disambiguate match vs
                        # different plaintext (M1 / M5 mitigation).
                        all_errors[(trial, pos)] = (
                            "CKR_OK_MATCH" if result == plaintext else "CKR_OK_DIFFERENT"
                        )

            distinct = set(all_errors.values())
            if len(distinct) > 1:
                # Tally for the failure message so triage can see
                # whether the leak is the canonical Vaudenay path
                # (CKR_OK_DIFFERENT vs CKR_ENCRYPTED_DATA_INVALID) or
                # a malleability finding (all CKR_OK_DIFFERENT).
                from collections import Counter

                tally = Counter(all_errors.values())
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"AES-CBC-PAD returns distinguishable outcomes across "
                    f"corruption positions over {trials} trials: "
                    f"{dict(tally)}. This is the Vaudenay 2002 / POODLE "
                    f"leak channel — a module that returns "
                    f"CKR_OK_DIFFERENT (accidentally valid padding) "
                    f"distinguishably from CKR_ENCRYPTED_DATA_INVALID "
                    f"leaks the padding-validity bit per chosen-CT query.",
                    ComplianceLevel.CRITICAL,
                    reference="Vaudenay 'Security Flaws Induced by CBC "
                    "Padding' (EUROCRYPT 2002); POODLE (CVE-2014-3566); "
                    "RFC 7366 (encrypt-then-MAC mitigation)",
                )
                classify(
                    "oracle",
                    kind="crypto",
                    label="AES-CBC-PAD padding oracle (Vaudenay 2002)",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_CBC_PAD",
                    summary="SECURITY: AES-CBC-PAD padding oracle (Vaudenay 2002) — "
                    f"distinct outcomes {dict(tally)} across {trials * 16} "
                    f"corruption probes. An attacker with chosen-ciphertext "
                    f"access can recover plaintext byte-by-byte via ~256 "
                    f"oracle queries per byte. Mitigation is application-"
                    f"level: use AES-GCM or encrypt-then-MAC instead of "
                    f"bare CBC-PAD.",
                    detail={"channel": "error_code", "outcomes": dict(tally)},
                )

            # Single-outcome path: surface the *kind* of single outcome.
            # All CKR_OK_DIFFERENT = malleability finding; all
            # CKR_ENCRYPTED_DATA_INVALID = real Vaudenay mitigation.
            single = next(iter(distinct))
            if single == "CKR_OK_DIFFERENT":
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"AES-CBC-PAD accepts ALL bit-flipped ciphertexts and "
                    f"returns CKR_OK with corrupted plaintext over "
                    f"{trials * 16} probes — ciphertext malleability is "
                    f"unchecked. This is strictly worse than the Vaudenay "
                    f"channel (the channel needs distinguishability; "
                    f"unchecked malleability allows direct plaintext "
                    f"manipulation).",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2: padding validation expected on padded mechanisms",
                )
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    label="AES-CBC-PAD unchecked malleability",
                    operation="C_Decrypt",
                    mechanism="CKM_AES_CBC_PAD",
                    summary="SECURITY: AES-CBC-PAD silently accepts every bit-"
                    "flipped ciphertext (CKR_OK with mismatched "
                    "plaintext) — no padding validation at all. CT "
                    "malleability is unchecked.",
                    detail={"outcome": "CKR_OK_DIFFERENT", "probes": trials * 16},
                )
        finally:
            for k in keys:
                destroy_quietly(rs.raw, rs.sh, k)


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
        # Needs BOTH directions: this encrypts a probe, then times decryptions.
        # CKM_RSA_PKCS signature and encryption are separately gated -- PKCS#1 v1.5
        # signature is FIPS-approved while v1.5 encryption is not -- so a FIPS-strict
        # module advertises the mechanism for signing only (GH #7). Gate on the
        # operation flags rather than mere presence: a module that DOES advertise
        # CKF_ENCRYPT/CKF_DECRYPT and then refuses is still a finding.
        skip_unless_mechanism_flag(rs, "RSA_PKCS", CKF_ENCRYPT)
        skip_unless_mechanism_flag(rs, "RSA_PKCS", CKF_DECRYPT)
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
        )

        try:
            # Valid ciphertext. The flag guard above means the module DID advertise
            # CKF_ENCRYPT, so a clean refusal here is advertised-but-not-operational
            # -- an xfail finding per the classification model, not a hard failure.
            try:
                valid_ct = encrypt_single(rs.raw, rs.sh, pub, CKM_RSA_PKCS, b"timing test")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "RSA-PKCS encrypt advertised (CKF_ENCRYPT) but not operational",
                )
                raise

            # Time valid decryptions
            valid_times = []
            for _ in range(50):
                start = time.perf_counter()
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, valid_ct)
                except AssertionError:
                    _abort_decrypt_operation(rs.raw, rs.sh)
                valid_times.append(time.perf_counter() - start)

            # Time invalid decryptions
            invalid_times = []
            for _ in range(50):
                bad_ct = generate_random(rs.raw, rs.sh, 256)
                start = time.perf_counter()
                try:
                    decrypt_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, bad_ct)
                except AssertionError:
                    _abort_decrypt_operation(rs.raw, rs.sh)
                invalid_times.append(time.perf_counter() - start)

            valid_avg = sum(valid_times) / len(valid_times)
            invalid_avg = sum(invalid_times) / len(invalid_times)

            # If one is more than 3x the other, flag it
            if valid_avg > 0 and invalid_avg > 0:
                ratio = max(valid_avg, invalid_avg) / min(valid_avg, invalid_avg)
                if ratio > 3.0:
                    classify(
                        "oracle",
                        kind="crypto",
                        label="RSA decrypt timing oracle",
                        operation="C_Decrypt",
                        mechanism="CKM_RSA_PKCS",
                        summary=f"TIMING: RSA decrypt timing ratio {ratio:.1f}x "
                        f"(valid={valid_avg * 1000:.2f}ms, invalid={invalid_avg * 1000:.2f}ms)",
                        detail={"channel": "timing", "ratio": round(ratio, 2)},
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_aes_cbc_pad_decrypt_timing_sanity(self, p11_raw_session: Any) -> None:
        """AES-CBC-PAD decrypt: valid vs invalid-padding timing should be similar.

        Lucky13 (CVE-2013-0169, Al Fardan & Paterson 2013) exploits
        sub-microsecond timing differences amplified across millions of
        samples. **This test does NOT detect Lucky13-class signals** —
        the 3x threshold + N=50 sample size only catch GROSS timing
        oracles (e.g. 100ms vs 5ms). Real Lucky13-resistance testing
        requires N ≥ 10⁶ samples + Welch's t-test in a controlled
        environment with cgroups CPU pinning, jitter calibration, and
        clock-source disambiguation — well beyond the scope of a unit
        test.

        Use this test as an "obvious-bug detector" only. A pass here
        does not mean the module is Lucky13-resistant; a fail means
        the gap is large enough to be visible without statistical
        machinery (likely a missing constant-time path).

        Phase 4.5 GAP-P4 status: gross-timing sanity covered here.
        Lab-grade Lucky13 detection remains future work (would belong
        in an offline timing-analysis tool, not a pytest unit).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        require_operational_aes_keygen(rs)

        key = gen_aes_key_or_xfail(rs, purpose="AES-CBC-PAD timing setup")
        try:
            iv = generate_random(rs.raw, rs.sh, 16)
            plaintext = b"lucky13 timing probe " * 5  # 105 bytes (7 blocks of 16)
            valid_ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert len(valid_ct) % 16 == 0

            # Valid decrypts: CT with intact PKCS#7 padding. The valid
            # path MUST NOT raise — if it does, that is itself a finding
            # (and timing measurement of failures is meaningless).
            valid_times: list[float] = []
            for _ in range(50):
                start = time.perf_counter()
                try:
                    decrypt_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM_AES_CBC_PAD,
                        valid_ct,
                        mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                    )
                except AssertionError as exc:
                    _abort_decrypt_operation(rs.raw, rs.sh)
                    classify(
                        "not_operational",
                        kind="crypto",
                        label="AES-CBC-PAD valid decrypt",
                        operation="C_Decrypt",
                        mechanism="CKM_AES_CBC_PAD",
                        summary=f"Valid CBC-PAD decrypt failed unexpectedly "
                        f"({exc}) — timing comparison invalid",
                    )
                valid_times.append(time.perf_counter() - start)

            # Invalid decrypts: corrupt the LAST block to invalidate
            # padding. Use a fresh corrupted ct each iteration so we
            # don't accidentally settle on a stable "accidentally valid"
            # padding pattern. We accept ONLY explicit padding-failure
            # CKRs as legitimate "invalid path" timing samples;
            # CKR_GENERAL_ERROR / CKR_FUNCTION_FAILED / unrelated
            # AssertionErrors fail the test (those would skew timing).
            invalid_times: list[float] = []
            last_block_start = len(valid_ct) - 16
            invalid_path_codes = (
                "CKR_ENCRYPTED_DATA_INVALID",
                "CKR_DATA_INVALID",
                "CKR_DATA_LEN_RANGE",
            )
            for i in range(50):
                bad_ct = bytearray(valid_ct)
                # Vary the corruption position so we sample the response
                # surface, not just one byte.
                bad_ct[last_block_start + (i % 16)] ^= 0xFF
                start = time.perf_counter()
                try:
                    decrypt_single(
                        rs.raw,
                        rs.sh,
                        key,
                        CKM_AES_CBC_PAD,
                        bytes(bad_ct),
                        mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
                    )
                except AssertionError as exc:
                    elapsed = time.perf_counter() - start
                    _abort_decrypt_operation(rs.raw, rs.sh)
                    msg = str(exc)
                    if not any(code in msg for code in invalid_path_codes):
                        # Some bit-flips happen to produce valid padding
                        # → CKR_OK + garbage plaintext, no exception. That
                        # is fine; timing is still on the rejection path
                        # the test is comparing. Other (non-padding) CKRs
                        # indicate broken decrypt and would skew timing.
                        if "CKR_OK" not in msg:
                            classify(
                                "nonspec_reject",
                                label="AES-CBC-PAD corrupted decrypt",
                                operation="C_Decrypt",
                                mechanism="CKM_AES_CBC_PAD",
                                expected=invalid_path_codes,
                                summary=f"Unexpected non-padding error on bit-"
                                f"flipped CBC-PAD decrypt: {exc} — timing "
                                f"comparison invalid",
                            )
                    invalid_times.append(elapsed)
                else:
                    invalid_times.append(time.perf_counter() - start)

            valid_avg = sum(valid_times) / len(valid_times)
            invalid_avg = sum(invalid_times) / len(invalid_times)

            if valid_avg > 0 and invalid_avg > 0:
                ratio = max(valid_avg, invalid_avg) / min(valid_avg, invalid_avg)
                if ratio > 3.0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        f"AES-CBC-PAD valid/invalid decrypt timing ratio "
                        f"{ratio:.1f}x — Lucky13-class timing oracle.",
                        ComplianceLevel.CRITICAL,
                        reference="Al Fardan & Paterson 'Lucky Thirteen' "
                        "(IEEE S&P 2013, CVE-2013-0169)",
                    )
                    classify(
                        "oracle",
                        kind="crypto",
                        label="AES-CBC-PAD Lucky13 timing oracle",
                        operation="C_Decrypt",
                        mechanism="CKM_AES_CBC_PAD",
                        summary=f"TIMING: AES-CBC-PAD valid vs invalid timing "
                        f"ratio {ratio:.1f}x "
                        f"(valid={valid_avg * 1000:.2f}ms, "
                        f"invalid={invalid_avg * 1000:.2f}ms) — "
                        f"Lucky13-class oracle.",
                        detail={"channel": "timing", "ratio": round(ratio, 2)},
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
