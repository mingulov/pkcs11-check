"""NIST ACVP AES-CFB1 tests.

Tests AES-CFB1 (1-bit cipher feedback mode) using official NIST ACVP vectors.

PKCS#11 CKM_AES_CFB1 processes full bytes (8 CFB1 bit-operations per byte).
MCT tests are excluded: each MCT iteration chains 1000 single-bit operations
with feedback-derived plaintext.  PKCS#11 CKM_AES_CFB1 processes full bytes
(8 bits per C_EncryptUpdate call), so the shift register advances 8x too fast
and diverges from the ACVP bit-level algorithm after the first byte.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKM_AES_CFB1
from pkcs11_check.testcases.acvp.aes.base_loader import _load_simple_vectors
from pkcs11_check.testcases.acvp.aes.base_runner_simple import (
    run_simple_decrypt_test,
    run_simple_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CFB1"]

_ALL_ENCRYPT, _ALL_DECRYPT = _load_simple_vectors("ACVP-AES-CFB1-1.0")
_ENCRYPT_VECTORS = [(vid, v) for vid, v in _ALL_ENCRYPT if not v.get("is_multiblock")]
_DECRYPT_VECTORS = [(vid, v) for vid, v in _ALL_DECRYPT if not v.get("is_multiblock")]


@pytest.mark.parametrize(
    "vec_id,vec", _ENCRYPT_VECTORS, ids=[v[0] for v in _ENCRYPT_VECTORS]
)
def test_acvp_aes_cfb1_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB1 encryption from NIST ACVP vectors.

    PKCS#11 CKM_AES_CFB1 processes full bytes (8 CFB1 bit-operations per byte).
    For vectors with payloadLen < 8, only the top payloadLen bits are compared.
    """
    run_simple_encrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)


@pytest.mark.parametrize(
    "vec_id,vec", _DECRYPT_VECTORS, ids=[v[0] for v in _DECRYPT_VECTORS]
)
def test_acvp_aes_cfb1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CFB1 decryption from NIST ACVP vectors."""
    run_simple_decrypt_test(p11_raw_session, vec_id, vec, "AES_CFB1", CKM_AES_CFB1)
