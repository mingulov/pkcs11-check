"""NIST ACVP AES-CCM tests - CCM and CCM-ECMA.

Tests AES-CCM authenticated encryption using official NIST ACVP vectors:
- AES-CCM - authenticated encryption with counter mode
- AES-CCM-ECMA - CCM variant for ECMA-368 standard (UWB)
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.acvp_loader import load_acvp_vectors
from pkcs11_check.testcases.acvp.aes.base import (
    _load_vectors,
    run_ccm_decrypt_test,
    run_ccm_encrypt_test,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CCM"]


# =============================================================================
# AES-CCM
# =============================================================================


def _load_ccm_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    """Load AES-CCM ACVP vectors."""
    encrypt_fields = {
        "key": "key",
        "nonce": "iv",
        "pt": "pt",
        "aad": "aad",
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "nonce": "iv",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "aad": "aad",
        "pt_expected": ("pt", lambda x: bytes.fromhex(x) if x else b""),
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        "ACVP-AES-CCM-1.0",
        encrypt_fields,  # type: ignore[arg-type]
        decrypt_fields,  # type: ignore[arg-type]
        extra_group_fields={
            "nonce_len": "ivLen",
            "tag_len": "tagLen",
        },
    )

    # Add test_passed to decrypt vectors and normalize lengths
    raw = load_acvp_vectors("ACVP-AES-CCM-1.0")
    for vec_id, vec in decrypt_vecs:
        tc_id = vec["tc_id"]
        for raw_vec in raw:
            if raw_vec["input"].get("tcId") == tc_id:
                vec["test_passed"] = raw_vec["expected"].get("testPassed", True)
                break

    # Normalize ivLen and tagLen to bytes
    for vec_id, vec in encrypt_vecs + decrypt_vecs:
        if "nonce_len" in vec:
            vec["nonce_len"] = vec["nonce_len"] // 8 if vec["nonce_len"] else 13
        if "tag_len" in vec:
            vec["tag_len"] = vec["tag_len"] // 8 if vec["tag_len"] else 16

    return encrypt_vecs, decrypt_vecs


_CCM_ENCRYPT_VECTORS, _CCM_DECRYPT_VECTORS = _load_ccm_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _CCM_ENCRYPT_VECTORS, ids=[v[0] for v in _CCM_ENCRYPT_VECTORS]
)
def test_acvp_aes_ccm_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CCM encryption from NIST ACVP vectors.

    Some modules may not support all nonce/tag sizes.
    """
    run_ccm_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CCM_DECRYPT_VECTORS, ids=[v[0] for v in _CCM_DECRYPT_VECTORS]
)
def test_acvp_aes_ccm_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CCM decryption from NIST ACVP vectors."""
    run_ccm_decrypt_test(p11_module_session, vec_id, vec)


# =============================================================================
# AES-CCM-ECMA
# =============================================================================


def _load_ccm_ecma_vectors() -> tuple[
    list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]
]:
    """Load AES-CCM-ECMA ACVP vectors (ECMA-368 variant of CCM)."""
    encrypt_fields = {
        "key": "key",
        "nonce": "iv",
        "pt": "pt",
        "aad": "aad",
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "nonce": "iv",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "aad": "aad",
        "pt_expected": ("pt", lambda x: bytes.fromhex(x) if x else b""),
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        "ACVP-AES-CCM-ECMA-1.0",
        encrypt_fields,  # type: ignore[arg-type]
        decrypt_fields,  # type: ignore[arg-type]
        extra_group_fields={
            "nonce_len": "ivLen",
            "tag_len": "tagLen",
        },
    )

    # Add test_passed to decrypt vectors and normalize lengths
    raw = load_acvp_vectors("ACVP-AES-CCM-ECMA-1.0")
    for vec_id, vec in decrypt_vecs:
        tc_id = vec["tc_id"]
        for raw_vec in raw:
            if raw_vec["input"].get("tcId") == tc_id:
                vec["test_passed"] = raw_vec["expected"].get("testPassed", True)
                break

    # Normalize ivLen and tagLen to bytes
    for vec_id, vec in encrypt_vecs + decrypt_vecs:
        if "nonce_len" in vec:
            vec["nonce_len"] = vec["nonce_len"] // 8 if vec["nonce_len"] else 13
        if "tag_len" in vec:
            vec["tag_len"] = vec["tag_len"] // 8 if vec["tag_len"] else 8

    return encrypt_vecs, decrypt_vecs


_CCM_ECMA_ENCRYPT_VECTORS, _CCM_ECMA_DECRYPT_VECTORS = _load_ccm_ecma_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _CCM_ECMA_ENCRYPT_VECTORS, ids=[v[0] for v in _CCM_ECMA_ENCRYPT_VECTORS]
)
def test_acvp_aes_ccm_ecma_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CCM-ECMA encryption from NIST ACVP vectors.

    CCM-ECMA is a variant of CCM used in the ECMA-368 standard (UWB).
    Uses standard CKM_AES_CCM mechanism with ECMA-specific test vectors.

    Some modules may not support all nonce/tag sizes.
    """
    run_ccm_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CCM_ECMA_DECRYPT_VECTORS, ids=[v[0] for v in _CCM_ECMA_DECRYPT_VECTORS]
)
def test_acvp_aes_ccm_ecma_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CCM-ECMA decryption from NIST ACVP vectors."""
    run_ccm_decrypt_test(p11_module_session, vec_id, vec)
