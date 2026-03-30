"""NIST ACVP AES-CFB and AES-OFB tests.

Tests AES-CFB and AES-OFB modes using official NIST ACVP vectors:
- AES-CFB1 - 1-bit cipher feedback mode
- AES-CFB8 - 8-bit cipher feedback mode
- AES-CFB128 - 128-bit cipher feedback mode
- AES-OFB - output feedback mode
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKM_AES_CFB1,
    CKM_AES_CFB8,
    CKM_AES_CFB128,
    CKM_AES_OFB,
)
from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    run_multiblock_decrypt_test,
    run_multiblock_encrypt_test,
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]


# =============================================================================
# AES-CFB128
# =============================================================================

_CFB128_ALL_ENCRYPT, _CFB128_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB128-1.0")
_CFB128_ENCRYPT_VECTORS = [(vid, v) for vid, v in _CFB128_ALL_ENCRYPT if not v.get("is_multiblock")]
_CFB128_DECRYPT_VECTORS = [(vid, v) for vid, v in _CFB128_ALL_DECRYPT if not v.get("is_multiblock")]
_CFB128_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _CFB128_ALL_ENCRYPT if v.get("is_multiblock")]
_CFB128_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _CFB128_ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_ENCRYPT_VECTORS, ids=[v[0] for v in _CFB128_ENCRYPT_VECTORS]
)
def test_acvp_aes_cfb128_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 encryption from NIST ACVP vectors."""
    run_simple_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_DECRYPT_VECTORS, ids=[v[0] for v in _CFB128_DECRYPT_VECTORS]
)
def test_acvp_aes_cfb128_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _CFB128_MULTIBLOCK_ENCRYPT]
)
def test_acvp_aes_cfb128_multiblock_encrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB128 multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB128_MULTIBLOCK_DECRYPT, ids=[v[0] for v in _CFB128_MULTIBLOCK_DECRYPT]
)
def test_acvp_aes_cfb128_multiblock_decrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB128 multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


# =============================================================================
# AES-CFB8
# =============================================================================

_CFB8_ALL_ENCRYPT, _CFB8_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB8-1.0")
_CFB8_ENCRYPT_VECTORS = [(vid, v) for vid, v in _CFB8_ALL_ENCRYPT if not v.get("is_multiblock")]
_CFB8_DECRYPT_VECTORS = [(vid, v) for vid, v in _CFB8_ALL_DECRYPT if not v.get("is_multiblock")]
_CFB8_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _CFB8_ALL_ENCRYPT if v.get("is_multiblock")]
_CFB8_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _CFB8_ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize(
    "vec_id,vec", _CFB8_ENCRYPT_VECTORS, ids=[v[0] for v in _CFB8_ENCRYPT_VECTORS]
)
def test_acvp_aes_cfb8_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB8 encryption from NIST ACVP vectors."""
    run_simple_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB8", CKM_AES_CFB8)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB8_DECRYPT_VECTORS, ids=[v[0] for v in _CFB8_DECRYPT_VECTORS]
)
def test_acvp_aes_cfb8_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB8 decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB8", CKM_AES_CFB8)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB8_MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _CFB8_MULTIBLOCK_ENCRYPT]
)
def test_acvp_aes_cfb8_multiblock_encrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB8 multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB8", CKM_AES_CFB8)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB8_MULTIBLOCK_DECRYPT, ids=[v[0] for v in _CFB8_MULTIBLOCK_DECRYPT]
)
def test_acvp_aes_cfb8_multiblock_decrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB8 multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB8", CKM_AES_CFB8)


# =============================================================================
# AES-CFB1
# =============================================================================

_CFB1_ALL_ENCRYPT, _CFB1_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB1-1.0")
_CFB1_ENCRYPT_VECTORS = [(vid, v) for vid, v in _CFB1_ALL_ENCRYPT if not v.get("is_multiblock")]
_CFB1_DECRYPT_VECTORS = [(vid, v) for vid, v in _CFB1_ALL_DECRYPT if not v.get("is_multiblock")]
_CFB1_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _CFB1_ALL_ENCRYPT if v.get("is_multiblock")]
_CFB1_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _CFB1_ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize(
    "vec_id,vec", _CFB1_ENCRYPT_VECTORS, ids=[v[0] for v in _CFB1_ENCRYPT_VECTORS]
)
def test_acvp_aes_cfb1_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB1 encryption from NIST ACVP vectors.

    CFB1 operates on single bits. Most modules don't support CFB1 well.
    """
    run_simple_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB1_DECRYPT_VECTORS, ids=[v[0] for v in _CFB1_DECRYPT_VECTORS]
)
def test_acvp_aes_cfb1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB1 decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB1_MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _CFB1_MULTIBLOCK_ENCRYPT]
)
def test_acvp_aes_cfb1_multiblock_encrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB1 multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)


@pytest.mark.parametrize(
    "vec_id,vec", _CFB1_MULTIBLOCK_DECRYPT, ids=[v[0] for v in _CFB1_MULTIBLOCK_DECRYPT]
)
def test_acvp_aes_cfb1_multiblock_decrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB1 multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)


# =============================================================================
# AES-OFB
# =============================================================================

_OFB_ALL_ENCRYPT, _OFB_ALL_DECRYPT = _load_simple_vectors("ACVP-AES-OFB-1.0")
_OFB_ENCRYPT_VECTORS = [(vid, v) for vid, v in _OFB_ALL_ENCRYPT if not v.get("is_multiblock")]
_OFB_DECRYPT_VECTORS = [(vid, v) for vid, v in _OFB_ALL_DECRYPT if not v.get("is_multiblock")]
_OFB_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _OFB_ALL_ENCRYPT if v.get("is_multiblock")]
_OFB_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _OFB_ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize(
    "vec_id,vec", _OFB_ENCRYPT_VECTORS, ids=[v[0] for v in _OFB_ENCRYPT_VECTORS]
)
def test_acvp_aes_ofb_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-OFB encryption from NIST ACVP vectors."""
    run_simple_encrypt_test(p11_raw_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.parametrize(
    "vec_id,vec", _OFB_DECRYPT_VECTORS, ids=[v[0] for v in _OFB_DECRYPT_VECTORS]
)
def test_acvp_aes_ofb_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-OFB decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_raw_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.parametrize(
    "vec_id,vec", _OFB_MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _OFB_MULTIBLOCK_ENCRYPT]
)
def test_acvp_aes_ofb_multiblock_encrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-OFB multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_raw_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.parametrize(
    "vec_id,vec", _OFB_MULTIBLOCK_DECRYPT, ids=[v[0] for v in _OFB_MULTIBLOCK_DECRYPT]
)
def test_acvp_aes_ofb_multiblock_decrypt(
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-OFB multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_raw_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)
