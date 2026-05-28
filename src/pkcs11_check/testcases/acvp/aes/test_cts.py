"""NIST ACVP AES-CBC-CS (Ciphertext Stealing) tests.

Tests AES-CBC-CS1/CS2/CS3 variants.  PKCS#11 defines a single CKM_AES_CTS
mechanism without specifying which variant is used.  This module auto-detects
the variant at runtime by probing the module, then runs only the matching
variant's ACVP vectors (skipping the other two).

Detection method (cached, runs once per session):
  Probe 1 -- 33-byte non-aligned encrypt: distinguishes CS3 from CS1/CS2.
  Probe 2 -- 32-byte aligned encrypt: distinguishes CS1 from CS2.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.aes.base_cts import (
    load_cbc_cs_vectors,
    run_cbc_cs_decrypt_test,
    run_cbc_cs_encrypt_test,
    skip_unless_cts_variant,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CTS"]


# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------

_CBC_CS1_ENCRYPT_VECTORS, _CBC_CS1_DECRYPT_VECTORS = load_cbc_cs_vectors("1")
_CBC_CS2_ENCRYPT_VECTORS, _CBC_CS2_DECRYPT_VECTORS = load_cbc_cs_vectors("2")
_CBC_CS3_ENCRYPT_VECTORS, _CBC_CS3_DECRYPT_VECTORS = load_cbc_cs_vectors("3")


# ---------------------------------------------------------------------------
# CS1 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "1")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "1")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)


# ---------------------------------------------------------------------------
# CS2 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "2")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "2")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)


# ---------------------------------------------------------------------------
# CS3 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_encrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS3 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "3")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS3 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "3")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)
