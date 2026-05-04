"""NIST Known-Answer Test vectors - import key/data, compute, compare."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    import_secret_key,
)
from pkcs11_check.raw.types_std import (
    CKK_AES,
    CKM_AES_ECB,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
)
from pkcs11_check.testcases.data import KAT_DIR as VECTORS_DIR

pytestmark = pytest.mark.kat


def load_vectors(filename: str) -> list[dict[str, str]]:
    """Load test vectors from JSON file."""
    with open(VECTORS_DIR / filename) as f:
        data = json.load(f)
    return data["vectors"]  # type: ignore[no-any-return]


def _import_aes_key(rs: Any, key_bytes: bytes) -> int:
    """Import AES key bytes via raw API."""
    from pkcs11_check.raw.types_std import CKA_DECRYPT, CKA_ENCRYPT, CKA_TOKEN

    return import_secret_key(
        rs.raw,
        rs.sh,
        CKK_AES,
        key_bytes,
        attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False},
    )


class TestSHA256KAT:
    """SHA-256 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha256.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha256_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = digest_single(rs.raw, rs.sh, CKM_SHA256, msg)
        assert result == expected


class TestSHA512KAT:
    """SHA-512 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha512.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha512_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = digest_single(rs.raw, rs.sh, CKM_SHA512, msg)
        assert result == expected


class TestSHA1KAT:
    """SHA-1 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha1.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha1_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = digest_single(rs.raw, rs.sh, CKM_SHA_1, msg)
        assert result == expected


class TestSHA384KAT:
    """SHA-384 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha384.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha384_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = digest_single(rs.raw, rs.sh, CKM_SHA384, msg)
        assert result == expected


class TestSHA224KAT:
    """SHA-224 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha224.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha224_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = digest_single(rs.raw, rs.sh, CKM_SHA224, msg)
        assert result == expected


class TestAESECBKAT:
    """AES-256-ECB known-answer tests from NIST SP 800-38A."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_ecb.json"),
        ids=lambda v: v["ciphertext"][:16],
    )
    def test_aes_ecb_encrypt_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        key = _import_aes_key(rs, bytes.fromhex(vec["key"]))
        plaintext = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])
        try:
            result = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            assert result == expected_ct
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_ecb.json"),
        ids=lambda v: v["plaintext"][:16],
    )
    def test_aes_ecb_decrypt_kat(self, p11_raw_session: Any, vec: dict[str, str]) -> None:
        rs = p11_raw_session
        key = _import_aes_key(rs, bytes.fromhex(vec["key"]))
        ciphertext = bytes.fromhex(vec["ciphertext"])
        expected_pt = bytes.fromhex(vec["plaintext"])
        try:
            result = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ciphertext)
            assert result == expected_pt
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
