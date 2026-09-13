"""NIST ACVP AES-CBC-CS (Ciphertext Stealing) tests.

Tests AES-CBC-CS1/CS2/CS3 variants.  PKCS#11 defines a single CKM_AES_CTS
mechanism without specifying which variant is used.  This module auto-detects
the variant during collection and reuses that result at runtime, then runs
only the matching variant's ACVP vectors (skipping the other two).

Detection uses cached, independent fixed-key 32-byte aligned and 33-byte
unaligned known-answer encryptions for each supported AES key size (128, 192,
and 256 bits).  Collection pruning keeps one deterministic detector reporter
when the result is unavailable, so a file-isolated run does not repeat the
same provider outcome for every vector.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.acvp_loader import require_acvp_vectors
from pkcs11_check.testcases.acvp.aes.base_cts import (
    get_cts_detection,
    load_cbc_cs_vectors,
    report_cts_detection,
    run_cbc_cs_decrypt_test,
    run_cbc_cs_encrypt_test,
    skip_unless_cts_encrypt_decrypt,
    skip_unless_cts_variant,
)

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CTS"]

require_acvp_vectors()


# ---------------------------------------------------------------------------
# Vector loading
# ---------------------------------------------------------------------------

_CBC_CS1_ENCRYPT_VECTORS, _CBC_CS1_DECRYPT_VECTORS = load_cbc_cs_vectors("1")
_CBC_CS2_ENCRYPT_VECTORS, _CBC_CS2_DECRYPT_VECTORS = load_cbc_cs_vectors("2")
_CBC_CS3_ENCRYPT_VECTORS, _CBC_CS3_DECRYPT_VECTORS = load_cbc_cs_vectors("3")


def test_cts_variant_detected(p11_module_session: Any) -> None:
    """Report one authoritative result for the advertised AES-CTS probe."""
    rs = p11_module_session
    skip_unless_cts_encrypt_decrypt(rs)
    report_cts_detection(get_cts_detection(rs))


# ---------------------------------------------------------------------------
# CS1 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS1 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "1")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS1 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "1")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)


# ---------------------------------------------------------------------------
# CS2 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS2 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "2")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS2 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "2")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)


# ---------------------------------------------------------------------------
# CS3 Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_encrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS3 encryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "3")
    run_cbc_cs_encrypt_test(p11_module_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_decrypt(
    p11_module_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """AES-CBC-CS3 decryption from NIST ACVP vectors."""
    skip_unless_cts_variant(p11_module_session, "3")
    run_cbc_cs_decrypt_test(p11_module_session, vec_id, vec)
