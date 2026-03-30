"""NIST ACVP AES-XTS and AES-CBC-CS tests.

Tests AES-XTS and AES-CBC-CS modes using official NIST ACVP vectors:
- AES-XTS - XEX-based Tweaked Codebook with Ciphertext Stealing
- AES-CBC-CS1/CS2/CS3 - Ciphertext Stealing variants
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_AES_XTS,
    CKM_AES_CTS,
    CKM_AES_XTS,
)
from pkcs11_check.testcases.acvp.aes.base import _import_aes_key, _load_vectors

pytestmark = [pytest.mark.kat, pytest.mark.acvp]


# =============================================================================
# AES-XTS
# =============================================================================


def _load_xts_vectors(
    version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-XTS ACVP vectors for specified version (1.0 or 2.0)."""
    encrypt_fields = {
        "key": "key",
        "pt": ("pt", lambda x: bytes.fromhex(x) if x else b""),
        "tweak": "tweakValue",
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tweak": "tweakValue",
        "pt_expected": ("pt", lambda x: bytes.fromhex(x) if x else b""),
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        f"ACVP-AES-XTS-{version}",
        encrypt_fields,  # type: ignore[arg-type]
        decrypt_fields,  # type: ignore[arg-type]
    )

    # Add version prefix to vec_id for clarity
    encrypt_vecs = [(f"XTS-{version}-{vid}", v) for vid, v in encrypt_vecs]
    decrypt_vecs = [(f"XTS-{version}-{vid}", v) for vid, v in decrypt_vecs]

    return encrypt_vecs, decrypt_vecs


_XTS_1_0_ENCRYPT_VECTORS, _XTS_1_0_DECRYPT_VECTORS = _load_xts_vectors("1.0")
_XTS_2_0_ENCRYPT_VECTORS, _XTS_2_0_DECRYPT_VECTORS = _load_xts_vectors("2.0")


@pytest.mark.parametrize(
    "vec_id,vec",
    _XTS_1_0_ENCRYPT_VECTORS + _XTS_2_0_ENCRYPT_VECTORS,
    ids=[v[0] for v in _XTS_1_0_ENCRYPT_VECTORS + _XTS_2_0_ENCRYPT_VECTORS],
)
def test_acvp_aes_xts_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS encryption from NIST ACVP vectors (v1.0 and v2.0).

    XTS uses a double-length key (data key + tweak key) and a tweak value
    for sector-based disk encryption.

    SoftHSM2: Limited XTS support.
    Kryoptic: Supports AES-XTS via OpenSSL.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported by module")

    key = 0
    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES_XTS,
            vec["key"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_ENCRYPT: True,
            },
        )
        try:
            mech = mech_bytes(CKM_AES_XTS, vec["tweak"])
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_XTS,
                vec["pt"],
                mech_param=mech,
            )
        except AssertionError as exc:
            pytest.xfail(f"Module limitation: XTS encrypt failed ({exc})")

        assert ct == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct.hex()}, expected {vec['ct_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


@pytest.mark.parametrize(
    "vec_id,vec",
    _XTS_1_0_DECRYPT_VECTORS + _XTS_2_0_DECRYPT_VECTORS,
    ids=[v[0] for v in _XTS_1_0_DECRYPT_VECTORS + _XTS_2_0_DECRYPT_VECTORS],
)
def test_acvp_aes_xts_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS decryption from NIST ACVP vectors (v1.0 and v2.0)."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported by module")

    key = 0
    try:
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES_XTS,
            vec["key"],
            attrs={
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_DECRYPT: True,
            },
        )
        try:
            mech = mech_bytes(CKM_AES_XTS, vec["tweak"])
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_XTS,
                vec["ct"],
                mech_param=mech,
            )
        except AssertionError as exc:
            pytest.xfail(f"Module limitation: XTS decrypt failed ({exc})")
            return

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# =============================================================================
# AES-CBC-CS (Ciphertext Stealing)
# =============================================================================


def _load_cbc_cs_vectors(
    cs_version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-CBC-CS1/CS2/CS3 ACVP vectors."""
    encrypt_fields = {
        "key": "key",
        "iv": "iv",
        "pt": "pt",
        "ct_expected": "ct",
    }
    decrypt_fields = {
        "key": "key",
        "iv": "iv",
        "ct": "ct",
        "pt_expected": "pt",
    }

    encrypt_vecs, decrypt_vecs = _load_vectors(
        f"ACVP-AES-CBC-CS{cs_version}-1.0",
        encrypt_fields,
        decrypt_fields,
        extra_group_fields={"payload_len_bits": "payloadLen"},
    )

    # Add CS version prefix to vec_id
    encrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in encrypt_vecs]
    decrypt_vecs = [(f"CBC-CS{cs_version}-{vid}", v) for vid, v in decrypt_vecs]

    return encrypt_vecs, decrypt_vecs


_CBC_CS1_ENCRYPT_VECTORS, _CBC_CS1_DECRYPT_VECTORS = _load_cbc_cs_vectors("1")
_CBC_CS2_ENCRYPT_VECTORS, _CBC_CS2_DECRYPT_VECTORS = _load_cbc_cs_vectors("2")
_CBC_CS3_ENCRYPT_VECTORS, _CBC_CS3_DECRYPT_VECTORS = _load_cbc_cs_vectors("3")


def _run_cbc_cs_encrypt_test(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS encrypt test."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=True, decrypt=False)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["pt"],
                mech_param=mech,
            )
        except AssertionError as exc:
            pytest.xfail(f"Module limitation: CBC-CS encrypt failed ({exc})")

        assert ct == vec["ct_expected"], (
            f"{vec_id}: ciphertext mismatch: got {ct.hex()}, expected {vec['ct_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


def _run_cbc_cs_decrypt_test(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Run AES-CBC-CS decrypt test."""
    rs = p11_raw_session
    if not rs.has_mechanism("AES_CTS"):
        pytest.skip("AES_CTS not supported by module")

    key = 0
    try:
        key = _import_aes_key(rs, vec["key"], encrypt=False, decrypt=True)
        try:
            mech = mech_bytes(CKM_AES_CTS, vec["iv"])
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key,
                CKM_AES_CTS,
                vec["ct"],
                mech_param=mech,
            )
        except AssertionError as exc:
            pytest.xfail(f"Module limitation: CBC-CS decrypt failed ({exc})")
            return

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)


# CS1 Tests
@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 encryption from NIST ACVP vectors.

    SoftHSM2: Advertises CKM_AES_CTS but may not be operational - skip expected.
    Kryoptic: Supports CTS modes.
    """
    _run_cbc_cs_encrypt_test(p11_raw_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS1_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS1_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS1 decryption from NIST ACVP vectors."""
    _run_cbc_cs_decrypt_test(p11_raw_session, vec_id, vec)


# CS2 Tests
@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 encryption from NIST ACVP vectors."""
    _run_cbc_cs_encrypt_test(p11_raw_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS2_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS2_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs2_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS2 decryption from NIST ACVP vectors."""
    _run_cbc_cs_decrypt_test(p11_raw_session, vec_id, vec)


# CS3 Tests
@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_ENCRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_ENCRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_encrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS3 encryption from NIST ACVP vectors."""
    _run_cbc_cs_encrypt_test(p11_raw_session, vec_id, vec)


@pytest.mark.parametrize(
    "vec_id,vec", _CBC_CS3_DECRYPT_VECTORS, ids=[v[0] for v in _CBC_CS3_DECRYPT_VECTORS]
)
def test_acvp_aes_cbc_cs3_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CBC-CS3 decryption from NIST ACVP vectors."""
    _run_cbc_cs_decrypt_test(p11_raw_session, vec_id, vec)
