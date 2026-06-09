"""NIST ACVP AES key wrap tests - KW and KWP.

Tests AES key wrap modes using official NIST ACVP vectors:
- AES-KW - Key Wrap (RFC 3394)
- AES-KWP - Key Wrap with Padding (RFC 5649)

Per OASIS PKCS#11 v3.2 spec (aes_key_wrap.md), CKM_AES_KEY_WRAP and
CKM_AES_KEY_WRAP_KWP support both C_Encrypt/C_Decrypt (raw data) and
C_WrapKey/C_UnwrapKey (key objects).  ACVP vectors test raw byte-level
wrapping, so we use C_Encrypt/C_Decrypt which operate on raw data
without key-object metadata.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_WRAPPED_KEY_INVALID,
)
from pkcs11_check.testcases._operability import (
    Operability,
    OperabilityResult,
    classify_kat_clean_error,
    probe_operability,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors
from pkcs11_check.testcases.conftest import is_known_error

# CKR errors that indicate the module correctly rejected invalid ciphertext
# during unwrap integrity checking.  OpenSSL-backed modules often return
# CKR_GENERAL_ERROR instead of the more specific CKR codes.  Kryoptic
# returns CKR_DEVICE_ERROR for integrity check failures.
_UNWRAP_REJECT_RVS = {
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_WRAPPED_KEY_INVALID,
    CKR_DEVICE_ERROR,
}

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

# --- Canonical operability probe (triage H2) ---------------------------------
# One canonical RFC 3394/5649 known answer per (mechanism, direction) per
# process decides how clean vector errors classify (testcases/_operability.py).
# Expected outputs come from `cryptography.keywrap` (spec-derived truth).
PROBE_KEK = bytes(range(16))
PROBE_KW_PT = bytes(range(16))
PROBE_KWP_PT = bytes(range(20))


def _probe_expected_ct(mech_name: str) -> bytes:
    from cryptography.hazmat.primitives.keywrap import (
        aes_key_wrap,
        aes_key_wrap_with_padding,
    )

    if mech_name == "AES_KEY_WRAP":
        return aes_key_wrap(PROBE_KEK, PROBE_KW_PT)
    return aes_key_wrap_with_padding(PROBE_KEK, PROBE_KWP_PT)


def _canonical_wrap_probe(rs: Any, mech_name: str, direction: str) -> OperabilityResult:
    mech = CKM_AES_KEY_WRAP if mech_name == "AES_KEY_WRAP" else CKM_AES_KEY_WRAP_KWP
    pt = PROBE_KW_PT if mech_name == "AES_KEY_WRAP" else PROBE_KWP_PT
    expected_ct = _probe_expected_ct(mech_name)
    key = 0
    try:
        try:
            key = _import_aes_key(rs, PROBE_KEK, encrypt=True, decrypt=True)
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.INCONCLUSIVE, f"canonical {mech_name} key import failed: {exc}"
            )
        try:
            if direction == "encrypt":
                got = encrypt_single(
                    rs.raw, rs.sh, key, mech, pt,
                    mech_param=mech_simple(mech), output_overhead=16,
                )
                want = expected_ct
            else:
                got = decrypt_single(
                    rs.raw, rs.sh, key, mech, expected_ct, mech_param=mech_simple(mech)
                )
                want = pt
        except CkrAssertionError as exc:
            return OperabilityResult(
                Operability.NOT_OPERATIONAL,
                f"canonical {mech_name} {direction} rejected: {exc}",
            )
        if got != want:
            return OperabilityResult(
                Operability.WRONG_OUTPUT,
                f"canonical {mech_name} {direction} output mismatch: "
                f"got {got.hex()}, want {want.hex()}",
            )
        return OperabilityResult(
            Operability.OPERATIONAL, f"canonical {mech_name} {direction} OK"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def _wrap_operability(rs: Any, mech_name: str, direction: str) -> OperabilityResult:
    return probe_operability(
        f"{mech_name}:{direction}", lambda: _canonical_wrap_probe(rs, mech_name, direction)
    )


_MAX_HEX_BYTES = 128  # max bytes to show in mismatch messages


def _hex(data: bytes) -> str:
    """Hex-encode with truncation for readable assert messages."""
    if len(data) <= _MAX_HEX_BYTES:
        return data.hex()
    return data[:_MAX_HEX_BYTES].hex() + "..."


# =============================================================================
# AES-KW (RFC 3394)
# =============================================================================


def _is_cipher_variant(v: dict[str, Any]) -> bool:
    """True if the vector uses the standard (forward) cipher, not inverse."""
    return v.get("kw_cipher") != "inverse"


def _load_kw_vectors() -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-KW ACVP vectors.

    Inverse cipher variants (kwCipher=inverse, per SP 800-38F) are excluded:
    PKCS#11 CKM_AES_KEY_WRAP always uses the standard (forward) cipher.
    """
    encrypt_fields = {
        "key": "key",
        "pt": "pt",
        "ct_expected": "ct",
    }
    decrypt_fields = {
        "key": "key",
        "ct": "ct",
        "pt_expected": "pt",
    }
    enc, dec = _load_vectors(
        "ACVP-AES-KW-1.0",
        encrypt_fields,
        decrypt_fields,
        extra_group_fields={"kw_cipher": "kwCipher"},
    )
    return (
        [(vid, v) for vid, v in enc if _is_cipher_variant(v)],
        [(vid, v) for vid, v in dec if _is_cipher_variant(v)],
    )


_KW_ENCRYPT_VECTORS, _KW_DECRYPT_VECTORS = _load_kw_vectors()


@pytest.mark.parametrize("vec_id,vec", _KW_ENCRYPT_VECTORS, ids=[v[0] for v in _KW_ENCRYPT_VECTORS])
def test_acvp_aes_kw_wrap(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KW wrap via C_Encrypt from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        mech = mech_simple(CKM_AES_KEY_WRAP)
        ct = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_KEY_WRAP,
            vec["pt"],
            mech_param=mech,
            output_overhead=8,
        )

        assert ct == vec["ct_expected"], (
            f"{vec_id}: wrap mismatch:\n"
            f"  got:      {_hex(ct)}\n"
            f"  expected: {_hex(vec['ct_expected'])}"
        )
    except AssertionError as exc:
        classify_kat_clean_error(
            exc,
            result=_wrap_operability(rs, "AES_KEY_WRAP", "encrypt"),
            label="AES_KEY_WRAP C_Encrypt",
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize("vec_id,vec", _KW_DECRYPT_VECTORS, ids=[v[0] for v in _KW_DECRYPT_VECTORS])
def test_acvp_aes_kw_unwrap(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KW unwrap via C_Decrypt from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    test_passed = vec.get("test_passed", True)
    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        mech = mech_simple(CKM_AES_KEY_WRAP)
        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_KEY_WRAP,
                vec["ct"],
                mech_param=mech,
            )
        except AssertionError as exc:
            if isinstance(exc, CkrAssertionError) and is_known_error(exc, _UNWRAP_REJECT_RVS):
                if not test_passed:
                    return  # module correctly rejected invalid ciphertext
                result = _wrap_operability(rs, "AES_KEY_WRAP", "decrypt")
                if result.status is Operability.NOT_OPERATIONAL:
                    pytest.xfail(
                        f"AES_KEY_WRAP advertised but C_Decrypt is not operational "
                        f"({result.detail}); vector: {exc}"
                    )
                pytest.fail(f"{vec_id}: valid KW vector rejected: {exc}")
            classify_kat_clean_error(
                exc,
                result=_wrap_operability(rs, "AES_KEY_WRAP", "decrypt"),
                label="AES_KEY_WRAP C_Decrypt",
            )

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: unwrap mismatch:\n"
                f"  got:      {_hex(pt)}\n"
                f"  expected: {_hex(vec['pt_expected'])}"
            )
        else:
            pytest.fail(f"{vec_id}: module accepted KW ciphertext with invalid integrity check")
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# =============================================================================
# AES-KWP (RFC 5649)
# =============================================================================


def _load_kwp_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    """Load AES-KWP ACVP vectors (forward cipher only, see _load_kw_vectors)."""
    encrypt_fields = {
        "key": "key",
        "pt": "pt",
        "ct_expected": "ct",
    }
    decrypt_fields = {
        "key": "key",
        "ct": "ct",
        "pt_expected": "pt",
    }
    enc, dec = _load_vectors(
        "ACVP-AES-KWP-1.0",
        encrypt_fields,
        decrypt_fields,
        extra_group_fields={"kw_cipher": "kwCipher"},
    )
    return (
        [(vid, v) for vid, v in enc if _is_cipher_variant(v)],
        [(vid, v) for vid, v in dec if _is_cipher_variant(v)],
    )


_KWP_ENCRYPT_VECTORS, _KWP_DECRYPT_VECTORS = _load_kwp_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _KWP_ENCRYPT_VECTORS, ids=[v[0] for v in _KWP_ENCRYPT_VECTORS]
)
def test_acvp_aes_kwp_wrap(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KWP wrap via C_Encrypt from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
        # KWP pads to 8-byte boundary then adds 8-byte header; max overhead = 15.
        ct = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_KEY_WRAP_KWP,
            vec["pt"],
            mech_param=mech,
            output_overhead=16,
        )

        assert ct == vec["ct_expected"], (
            f"{vec_id}: KWP wrap mismatch:\n"
            f"  got:      {_hex(ct)}\n"
            f"  expected: {_hex(vec['ct_expected'])}"
        )
    except AssertionError as exc:
        classify_kat_clean_error(
            exc,
            result=_wrap_operability(rs, "AES_KEY_WRAP_KWP", "encrypt"),
            label="AES_KEY_WRAP_KWP C_Encrypt",
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize(
    "vec_id,vec", _KWP_DECRYPT_VECTORS, ids=[v[0] for v in _KWP_DECRYPT_VECTORS]
)
def test_acvp_aes_kwp_unwrap(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KWP unwrap via C_Decrypt from NIST ACVP vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    test_passed = vec.get("test_passed", True)
    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
        try:
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_KEY_WRAP_KWP,
                vec["ct"],
                mech_param=mech,
            )
        except AssertionError as exc:
            if isinstance(exc, CkrAssertionError) and is_known_error(exc, _UNWRAP_REJECT_RVS):
                if not test_passed:
                    return  # module correctly rejected invalid ciphertext
                result = _wrap_operability(rs, "AES_KEY_WRAP_KWP", "decrypt")
                if result.status is Operability.NOT_OPERATIONAL:
                    pytest.xfail(
                        f"AES_KEY_WRAP_KWP advertised but C_Decrypt is not operational "
                        f"({result.detail}); vector: {exc}"
                    )
                pytest.fail(f"{vec_id}: valid KWP vector rejected: {exc}")
            classify_kat_clean_error(
                exc,
                result=_wrap_operability(rs, "AES_KEY_WRAP_KWP", "decrypt"),
                label="AES_KEY_WRAP_KWP C_Decrypt",
            )

        if test_passed:
            assert pt == vec["pt_expected"], (
                f"{vec_id}: KWP unwrap mismatch:\n"
                f"  got:      {_hex(pt)}\n"
                f"  expected: {_hex(vec['pt_expected'])}"
            )
        else:
            pytest.fail(f"{vec_id}: module accepted KWP ciphertext with invalid integrity check")
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
