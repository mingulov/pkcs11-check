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
from pkcs11_check.raw.types_std import (
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]

_MAX_HEX_BYTES = 128  # max bytes to show in mismatch messages


def _hex(data: bytes) -> str:
    """Hex-encode with truncation for readable assert messages."""
    if len(data) <= _MAX_HEX_BYTES:
        return data.hex()
    return data[:_MAX_HEX_BYTES].hex() + "..."


# =============================================================================
# AES-KW (RFC 3394)
# =============================================================================


def _load_kw_vectors() -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-KW ACVP vectors."""
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
    return _load_vectors("ACVP-AES-KW-1.0", encrypt_fields, decrypt_fields)


_KW_ENCRYPT_VECTORS, _KW_DECRYPT_VECTORS = _load_kw_vectors()


@pytest.mark.parametrize("vec_id,vec", _KW_ENCRYPT_VECTORS, ids=[v[0] for v in _KW_ENCRYPT_VECTORS])
def test_acvp_aes_kw_wrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KW wrap via C_Encrypt from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        mech = mech_simple(CKM_AES_KEY_WRAP)
        ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_KEY_WRAP, vec["pt"], mech_param=mech)

        assert ct == vec["ct_expected"], (
            f"{vec_id}: wrap mismatch:\n"
            f"  got:      {_hex(ct)}\n"
            f"  expected: {_hex(vec['ct_expected'])}"
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
            pytest.skip(f"AES-KW encrypt not supported: {exc_msg}")
        raise
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize("vec_id,vec", _KW_DECRYPT_VECTORS, ids=[v[0] for v in _KW_DECRYPT_VECTORS])
def test_acvp_aes_kw_unwrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KW unwrap via C_Decrypt from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        mech = mech_simple(CKM_AES_KEY_WRAP)
        pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_KEY_WRAP, vec["ct"], mech_param=mech)

        assert pt == vec["pt_expected"], (
            f"{vec_id}: unwrap mismatch:\n"
            f"  got:      {_hex(pt)}\n"
            f"  expected: {_hex(vec['pt_expected'])}"
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
            pytest.skip(f"AES-KW decrypt not supported: {exc_msg}")
        raise
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# =============================================================================
# AES-KWP (RFC 5649)
# =============================================================================


def _load_kwp_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    """Load AES-KWP ACVP vectors."""
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
    return _load_vectors("ACVP-AES-KWP-1.0", encrypt_fields, decrypt_fields)


_KWP_ENCRYPT_VECTORS, _KWP_DECRYPT_VECTORS = _load_kwp_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _KWP_ENCRYPT_VECTORS, ids=[v[0] for v in _KWP_ENCRYPT_VECTORS]
)
def test_acvp_aes_kwp_wrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KWP wrap via C_Encrypt from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
        ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_KEY_WRAP_KWP, vec["pt"], mech_param=mech)

        assert ct == vec["ct_expected"], (
            f"{vec_id}: KWP wrap mismatch:\n"
            f"  got:      {_hex(ct)}\n"
            f"  expected: {_hex(vec['ct_expected'])}"
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
            pytest.skip(f"AES-KWP encrypt not supported: {exc_msg}")
        raise
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize(
    "vec_id,vec", _KWP_DECRYPT_VECTORS, ids=[v[0] for v in _KWP_DECRYPT_VECTORS]
)
def test_acvp_aes_kwp_unwrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KWP unwrap via C_Decrypt from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
        pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_KEY_WRAP_KWP, vec["ct"], mech_param=mech)

        assert pt == vec["pt_expected"], (
            f"{vec_id}: KWP unwrap mismatch:\n"
            f"  got:      {_hex(pt)}\n"
            f"  expected: {_hex(vec['pt_expected'])}"
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
            pytest.skip(f"AES-KWP decrypt not supported: {exc_msg}")
        raise
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
