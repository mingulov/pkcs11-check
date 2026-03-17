"""NIST Known-Answer Test vectors — import key/data, compute, compare."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.kat

VECTORS_DIR = Path(__file__).parent / "vectors"


def load_vectors(filename: str) -> list[dict[str, str]]:
    """Load test vectors from JSON file."""
    with open(VECTORS_DIR / filename) as f:
        data = json.load(f)
    return data["vectors"]  # type: ignore[no-any-return]


class TestSHA256KAT:
    """SHA-256 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha256.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha256_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = p11_session.digest(msg, mechanism=Mechanism.SHA256)
        assert result == expected


class TestSHA512KAT:
    """SHA-512 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha512.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha512_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = p11_session.digest(msg, mechanism=Mechanism.SHA512)
        assert result == expected


class TestSHA1KAT:
    """SHA-1 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha1.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha1_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = p11_session.digest(msg, mechanism=Mechanism.SHA_1)
        assert result == expected


class TestSHA384KAT:
    """SHA-384 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha384.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha384_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = p11_session.digest(msg, mechanism=Mechanism.SHA384)
        assert result == expected


class TestSHA224KAT:
    """SHA-224 known-answer tests from NIST SHAVS."""

    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha224.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha224_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])
        result = p11_session.digest(msg, mechanism=Mechanism.SHA224)
        assert result == expected


class TestAESECBKAT:
    """AES-256-ECB known-answer tests from NIST SP 800-38A."""

    def _import_aes_key(self, session: Any, key_hex: str) -> Any:
        return session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: bytes.fromhex(key_hex),
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
            }
        )

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_ecb.json"),
        ids=lambda v: v["ciphertext"][:16],
    )
    def test_aes_ecb_encrypt_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        key = self._import_aes_key(p11_session, vec["key"])
        plaintext = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])
        result = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert result == expected_ct

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_ecb.json"),
        ids=lambda v: v["plaintext"][:16],
    )
    def test_aes_ecb_decrypt_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        key = self._import_aes_key(p11_session, vec["key"])
        ciphertext = bytes.fromhex(vec["ciphertext"])
        expected_pt = bytes.fromhex(vec["plaintext"])
        result = key.decrypt(ciphertext, mechanism=Mechanism.AES_ECB)
        assert result == expected_pt
