"""NIST ACVP AES key wrap tests - KW and KWP.

Tests AES key wrap modes using official NIST ACVP vectors:
- AES-KW - Key Wrap (RFC 3394)
- AES-KWP - Key Wrap with Padding (RFC 5649)
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, import_secret_key, unwrap_key, wrap_key
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]


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
    """AES-KW key wrap from NIST ACVP vectors.

    Key Wrap uses C_WrapKey / C_UnwrapKey, not encrypt/decrypt.
    The plaintext is treated as a key to be wrapped.

    SoftHSM2: Known issue - KW may produce incorrect output in some versions.
    Kryoptic: Supports AES-KW well.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    wrapping_key = 0
    key_to_wrap = 0
    try:
        wrapping_key = _import_aes_key(rs, vec["key"], wrap=True, unwrap=True)
        key_to_wrap = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_GENERIC_SECRET,
            vec["pt"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )

        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                key_to_wrap,
                CKM_AES_KEY_WRAP,
                mech_param=mech,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"AES-KW wrap not supported: {exc_msg}")
            raise

        assert wrapped == vec["ct_expected"], (
            f"{vec_id}: wrap mismatch:\n"
            f"  got:      {wrapped.hex()}\n"
            f"  expected: {vec['ct_expected'].hex()}"
        )
    finally:
        if key_to_wrap:
            destroy_quietly(rs.raw, rs.sh, key_to_wrap)
        if wrapping_key:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)


@pytest.mark.parametrize("vec_id,vec", _KW_DECRYPT_VECTORS, ids=[v[0] for v in _KW_DECRYPT_VECTORS])
def test_acvp_aes_kw_unwrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KW key unwrap from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported by module")

    wrapping_key = 0
    unwrapped_key = 0
    try:
        wrapping_key = _import_aes_key(rs, vec["key"], wrap=True, unwrap=True)

        try:
            mech = mech_simple(CKM_AES_KEY_WRAP)
            template_attrs: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            }
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                vec["ct"],
                CKM_AES_KEY_WRAP,
                template_attrs,
                mech_param=mech,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"AES-KW unwrap not supported: {exc_msg}")
            raise
    finally:
        if unwrapped_key:
            destroy_quietly(rs.raw, rs.sh, unwrapped_key)
        if wrapping_key:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)


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
    """AES-KWP key wrap from NIST ACVP vectors.

    KWP is like KW but with padding support for non-8-byte-multiple inputs.

    SoftHSM2: Known issue - KWP may produce incorrect output.
    Kryoptic: Supports AES-KWP.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    wrapping_key = 0
    key_to_wrap = 0
    try:
        wrapping_key = _import_aes_key(rs, vec["key"], wrap=True, unwrap=True)
        key_to_wrap = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_GENERIC_SECRET,
            vec["pt"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )

        try:
            mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
            wrapped = wrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                key_to_wrap,
                CKM_AES_KEY_WRAP_KWP,
                mech_param=mech,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"AES-KWP wrap not supported: {exc_msg}")
            raise

        assert wrapped == vec["ct_expected"], (
            f"{vec_id}: KWP wrap mismatch:\n"
            f"  got:      {wrapped.hex()}\n"
            f"  expected: {vec['ct_expected'].hex()}"
        )
    finally:
        if key_to_wrap:
            destroy_quietly(rs.raw, rs.sh, key_to_wrap)
        if wrapping_key:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)


@pytest.mark.parametrize(
    "vec_id,vec", _KWP_DECRYPT_VECTORS, ids=[v[0] for v in _KWP_DECRYPT_VECTORS]
)
def test_acvp_aes_kwp_unwrap(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-KWP key unwrap from NIST ACVP vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported by module")

    wrapping_key = 0
    unwrapped_key = 0
    try:
        wrapping_key = _import_aes_key(rs, vec["key"], wrap=True, unwrap=True)

        try:
            mech = mech_simple(CKM_AES_KEY_WRAP_KWP)
            template_attrs: dict[Any, Any] = {
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            }
            unwrapped_key = unwrap_key(
                rs.raw,
                rs.sh,
                wrapping_key,
                vec["ct"],
                CKM_AES_KEY_WRAP_KWP,
                template_attrs,
                mech_param=mech,
            )
        except AssertionError as exc:
            exc_msg = str(exc)
            if any(c in exc_msg for c in ("CKR_MECHANISM_INVALID", "CKR_MECHANISM_PARAM_INVALID")):
                pytest.skip(f"AES-KWP unwrap not supported: {exc_msg}")
            raise
    finally:
        if unwrapped_key:
            destroy_quietly(rs.raw, rs.sh, unwrapped_key)
        if wrapping_key:
            destroy_quietly(rs.raw, rs.sh, wrapping_key)
