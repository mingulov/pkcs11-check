"""NIST ACVP AES-XTS tests.

XEX-based Tweaked Codebook with Ciphertext Stealing -- sector-based
disk encryption mode.  Uses double-length keys (data key + tweak key).
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
    CKM_AES_XTS,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases.acvp.aes.base import _load_vectors
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_XTS"]


def _load_xts_vectors(
    version: str,
) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, dict[str, Any]]]]:
    """Load AES-XTS ACVP vectors for specified version (1.0 or 2.0)."""
    encrypt_fields = {
        "key": "key",
        "pt": ("pt", lambda x: bytes.fromhex(x) if x else b""),
        "tweak": ("tweakValue", lambda x: bytes.fromhex(x) if x else b""),
        "ct_expected": ("ct", lambda x: bytes.fromhex(x) if x else b""),
    }
    decrypt_fields = {
        "key": "key",
        "ct": ("ct", lambda x: bytes.fromhex(x) if x else b""),
        "tweak": ("tweakValue", lambda x: bytes.fromhex(x) if x else b""),
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
    """AES-XTS encryption from NIST ACVP vectors (v1.0 and v2.0)."""
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
            if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID}):
                pytest.xfail(f"AES_XTS advertised but encrypt is not operational: {exc}")
            raise

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
            if is_known_error(exc, {CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID}):
                pytest.xfail(f"AES_XTS advertised but decrypt is not operational: {exc}")
            raise

        assert pt == vec["pt_expected"], (
            f"{vec_id}: plaintext mismatch: got {pt.hex()}, expected {vec['pt_expected'].hex()}"
        )
    finally:
        if key:
            destroy_quietly(rs.raw, rs.sh, key)
