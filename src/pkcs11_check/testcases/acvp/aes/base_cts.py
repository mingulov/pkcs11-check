"""Shared helpers for AES-CBC-CS (Ciphertext Stealing) ACVP tests.

Contains CS variant auto-detection, vector loading, and test runners
shared across test_cts_cs1.py, test_cts_cs2.py, test_cts_cs3.py.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    get_mechanism_info,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKF_DECRYPT,
    CKF_ENCRYPT,
    CKM_AES_CBC,
    CKM_AES_CTS,
    CKR_DEVICE_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors
from pkcs11_check.testcases.conftest import is_known_error

# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------


def load_cbc_cs_vectors(
    cs_version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-CBC-CS1/CS2/CS3 ACVP vectors.

    Vectors with non-byte-aligned payloadLen are excluded: PKCS#11
    CKM_AES_CTS operates on whole bytes, but ACVP CBC-CS vectors may
    specify bit-level payloads.  The CTS "stealing" portion changes
    size when rounded to bytes, producing different ciphertext.
    """
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "pt": "pt",
        "ct_expected": "ct",
    }
    decrypt_fields = {
        "key": "key",
        "iv": "iv",
        "ct": "ct",
        "pt_expected": "pt",
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        f"ACVP-AES-CBC-CS{cs_version}-1.0",
        encrypt_fields,
        decrypt_fields,
        extra_group_fields={"payload_len_bits": "payloadLen"},
    )

    def _byte_aligned(v: dict[str, Any]) -> bool:
        pl = v.get("payload_len_bits")
        return pl is None or pl % 8 == 0

    encrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in encrypt_vecs if _byte_aligned(v)]
    decrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in decrypt_vecs if _byte_aligned(v)]

    return encrypt_vecs, decrypt_vecs


# ---------------------------------------------------------------------------
# CS variant auto-detection
# ---------------------------------------------------------------------------


def skip_unless_cts_encrypt_decrypt(rs: Any) -> None:
    """Skip CTS vector probes unless C_GetMechanismInfo advertises enc/dec."""
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("CKM_AES_CTS not supported by module")
    info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_CTS)
    required = int(CKF_ENCRYPT) | int(CKF_DECRYPT)
    if int(info["flags"]) & required != required:
        pytest.skip("CKM_AES_CTS does not advertise CKF_ENCRYPT|CKF_DECRYPT")


def _detect_cts_variant(rs: Any) -> str | None:
    """Detect which CBC-CS variant (CS1/CS2/CS3) the module implements.

    Uses structural comparison -- no pre-computed values needed.

    Probe 1 -- 33 bytes (2 full blocks + 1 byte): the module returns 33 bytes.
      CS3: output starts with CBC(block1) -- natural order.
      CS1/CS2: output starts differently -- swapped.

    Probe 2 -- 32 bytes (block-aligned): only needed if probe 1 says CS1/CS2.
      CS1: output == standard CBC output (no swap).
      CS2: last two 16-byte halves are swapped vs CBC.

    Returns "1", "2", "3", or None if detection fails.
    """
    if not rs.has_mechanism("AES_CTS"):
        return None

    from pkcs11_check.raw.recipes import gen_aes_key as _gen_key

    key = 0
    try:
        key = _gen_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
        )
    except (AssertionError, OSError):
        return None

    try:
        iv = bytes(16)  # zero IV

        # Probe 1: 33 bytes = 2 full blocks + 1 byte
        pt1 = bytes(range(33))
        try:
            ct1 = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                pt1,
                mech_param=mech_bytes(CKM_AES_CTS, iv),
            )
        except AssertionError:
            # CTS encrypt fails for non-aligned (e.g. CKR_DEVICE_ERROR).
            # Fallback: try block-aligned only.
            pt2 = bytes(range(32))
            try:
                ct2 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CTS,
                    pt2,
                    mech_param=mech_bytes(CKM_AES_CTS, iv),
                )
                cbc2 = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CBC,
                    pt2,
                    mech_param=mech_bytes(CKM_AES_CBC, iv),
                )
                if ct2 == cbc2:
                    return "1"  # CS1 or CS3 (no swap for aligned)
                if ct2[:16] == cbc2[16:] and ct2[16:] == cbc2[:16]:
                    return "2"
                return "1"
            except AssertionError:
                return None  # CTS completely broken

        if len(ct1) != 33:
            return None

        # Compare with standard AES-CBC to detect block order
        cbc_c1 = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CBC,
            pt1[:16],
            mech_param=mech_bytes(CKM_AES_CBC, iv),
        )

        if ct1[:16] == cbc_c1[:16]:
            # First block matches CBC(block1) -- candidate for CS3.
            pt1_padded = pt1 + b"\x00" * (48 - len(pt1))  # pad to 3 blocks
            cbc_full = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CBC,
                pt1_padded,
                mech_param=mech_bytes(CKM_AES_CBC, iv),
            )
            # In CS3, middle 16 bytes should be C3 (last full CBC block)
            if ct1[16:32] == cbc_full[32:48]:
                return "3"
            return None  # Non-standard variant

        # CS1 or CS2 -- need aligned probe to distinguish
        pt2 = bytes(range(32))
        ct2 = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CTS,
            pt2,
            mech_param=mech_bytes(CKM_AES_CTS, iv),
        )
        cbc_ct2 = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CBC,
            pt2,
            mech_param=mech_bytes(CKM_AES_CBC, iv),
        )

        if ct2 == cbc_ct2:
            return "1"  # CS1: no swap for aligned = same as CBC
        if ct2[:16] == cbc_ct2[16:] and ct2[16:] == cbc_ct2[:16]:
            return "2"  # CS2: always swaps, even when aligned
        return "1"  # Default to CS1 if inconclusive

    except (AssertionError, OSError):
        return None
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# Module-level cache for detected variant (set on first access)
_detected_variant: str | None | bool = False  # False = not yet detected


def get_detected_variant(rs: Any) -> str | None:
    """Get or detect the CTS variant for this module (cached)."""
    global _detected_variant  # noqa: PLW0603
    if _detected_variant is False:
        _detected_variant = _detect_cts_variant(rs)
    return _detected_variant  # type: ignore[return-value]


def skip_unless_cts_variant(rs: Any, expected_cs: str) -> None:
    """Skip test if module's CTS variant doesn't match expected_cs."""
    skip_unless_cts_encrypt_decrypt(rs)
    detected = get_detected_variant(rs)
    if detected is None:
        pytest.xfail("CKM_AES_CTS advertised but variant detection encrypt is not operational")
    if detected != expected_cs:
        pytest.skip(f"Module implements CS{detected}, skipping CS{expected_cs} vectors")


# ---------------------------------------------------------------------------
# Test runners
# ---------------------------------------------------------------------------


def _handle_cts_error(exc: AssertionError, vec_id: str, direction: str) -> None:
    """Handle CTS encrypt/decrypt errors with appropriate reporting."""
    if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID}):
        pytest.xfail(f"CKM_AES_CTS advertised but CBC-CS {direction} is not operational: {exc}")
    if is_known_error(exc, {CKR_DEVICE_ERROR}):
        note(
            f"CKM_AES_CTS {direction} returned CKR_DEVICE_ERROR for {vec_id}. "
            "Module advertises CTS but fails on valid input.",
            ComplianceLevel.CRITICAL,
            reference="PKCS#11 v3.1 CKM_AES_CTS",
        )
        pytest.xfail(f"CKM_AES_CTS advertised but CBC-CS {direction} failed: {exc}")
    raise exc


def run_cbc_cs_encrypt_test(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS encrypt test."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["pt"],
                mech_param=mech,
            )
        except AssertionError as exc:
            _handle_cts_error(exc, vec_id, "encrypt")

        assert ct == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch.\n"
            f"  got:      {ct.hex()}\n"
            f"  expected: {vec['ct_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def run_cbc_cs_decrypt_test(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS decrypt test."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["ct"],
                mech_param=mech,
            )
        except AssertionError as exc:
            _handle_cts_error(exc, vec_id, "decrypt")

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch.\n"
            f"  got:      {pt.hex()}\n"
            f"  expected: {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
