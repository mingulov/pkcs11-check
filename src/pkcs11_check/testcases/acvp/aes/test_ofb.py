"""NIST ACVP AES-OFB tests.

Tests AES-OFB (output feedback mode) using official NIST ACVP vectors.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_AES_OFB
from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    run_multiblock_decrypt_test,
    run_multiblock_encrypt_test,
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_OFB"]

_ALL_ENCRYPT, _ALL_DECRYPT = _load_simple_vectors("ACVP-AES-OFB-1.0")
_ENCRYPT_VECTORS = [(vid, v) for vid, v in _ALL_ENCRYPT if not v.get("is_multiblock")]
_DECRYPT_VECTORS = [(vid, v) for vid, v in _ALL_DECRYPT if not v.get("is_multiblock")]
_MULTIBLOCK_ENCRYPT = [(vid, v) for vid, v in _ALL_ENCRYPT if v.get("is_multiblock")]
_MULTIBLOCK_DECRYPT = [(vid, v) for vid, v in _ALL_DECRYPT if v.get("is_multiblock")]


@pytest.mark.parametrize("vec_id,vec", _ENCRYPT_VECTORS, ids=[v[0] for v in _ENCRYPT_VECTORS])
def test_acvp_aes_ofb_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-OFB encryption from NIST ACVP vectors."""
    run_simple_encrypt_test(p11_module_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.parametrize("vec_id,vec", _DECRYPT_VECTORS, ids=[v[0] for v in _DECRYPT_VECTORS])
def test_acvp_aes_ofb_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-OFB decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_module_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.slow
@pytest.mark.parametrize("vec_id,vec", _MULTIBLOCK_ENCRYPT, ids=[v[0] for v in _MULTIBLOCK_ENCRYPT])
def test_acvp_aes_ofb_multiblock_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-OFB multi-block encryption with chaining."""
    run_multiblock_encrypt_test(p11_module_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)


@pytest.mark.slow
@pytest.mark.parametrize("vec_id,vec", _MULTIBLOCK_DECRYPT, ids=[v[0] for v in _MULTIBLOCK_DECRYPT])
def test_acvp_aes_ofb_multiblock_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-OFB multi-block decryption with chaining."""
    run_multiblock_decrypt_test(p11_module_session, vec_id, vec, "AES_OFB", CKM_AES_OFB)
