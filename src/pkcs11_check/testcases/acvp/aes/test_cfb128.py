"""NIST ACVP AES-CFB128 tests.

Tests AES-CFB128 (128-bit cipher feedback mode) using official NIST ACVP vectors.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_AES_CFB128
from pkcs11_check.testcases.acvp.acvp_loader import require_acvp_vectors
from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    run_multiblock_decrypt_test,
    run_multiblock_encrypt_test,
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CFB128"]

require_acvp_vectors()

_ALL_ENCRYPT, _ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB128-1.0")
_ENCRYPT_VECTORS = [(vid, v) for vid, v in _ALL_ENCRYPT if not v.get("is_multiblock")]
_DECRYPT_VECTORS = [(vid, v) for vid, v in _ALL_DECRYPT if not v.get("is_multiblock")]
_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _ALL_ENCRYPT if v.get("is_multiblock")]
_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize("vec_id,vec", _ENCRYPT_VECTORS, ids=[v[0] for v in _ENCRYPT_VECTORS])
def test_acvp_aes_cfb128_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 encryption from NIST ACVP vectors."""
    run_simple_encrypt_test(p11_module_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.parametrize("vec_id,vec", _DECRYPT_VECTORS, ids=[v[0] for v in _DECRYPT_VECTORS])
def test_acvp_aes_cfb128_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB128 decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_module_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.slow
@pytest.mark.parametrize("vec_id,vec", _MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _MULTIBLOCK_ENCRYPT])
def test_acvp_aes_cfb128_multiblock_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB128 multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_module_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)


@pytest.mark.slow
@pytest.mark.parametrize("vec_id,vec", _MULTIBLOCK_DECRYPT, ids=[v[0] for v in _MULTIBLOCK_DECRYPT])
def test_acvp_aes_cfb128_multiblock_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CFB128 multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_module_session, vec_id, vec, "AES_CFB128", CKM_AES_CFB128)
