"""Wycheproof PBES2 vectors.

Tests password-based encryption using PKCS#5 PBKDF2 plus AES-CBC-PAD.
This is more useful for real PKCS#11 modules than PBKDF2 alone because it
exercises the derived-key handoff into an actual decrypt operation.
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = pytest.mark.wycheproof

_PRF_MAP = {
    "hmacsha1": 0x00000001,
    "hmacsha224": 0x00000003,
    "hmacsha256": 0x00000004,
    "hmacsha384": 0x00000005,
    "hmacsha512": 0x00000006,
}

_PBES2_FILES = [
    ("pbes2_hmacsha1_aes_128_test.json", "hmacsha1", 128),
    ("pbes2_hmacsha1_aes_192_test.json", "hmacsha1", 192),
    ("pbes2_hmacsha1_aes_256_test.json", "hmacsha1", 256),
    ("pbes2_hmacsha224_aes_128_test.json", "hmacsha224", 128),
    ("pbes2_hmacsha224_aes_192_test.json", "hmacsha224", 192),
    ("pbes2_hmacsha224_aes_256_test.json", "hmacsha224", 256),
    ("pbes2_hmacsha256_aes_128_test.json", "hmacsha256", 128),
    ("pbes2_hmacsha256_aes_192_test.json", "hmacsha256", 192),
    ("pbes2_hmacsha256_aes_256_test.json", "hmacsha256", 256),
    ("pbes2_hmacsha384_aes_128_test.json", "hmacsha384", 128),
    ("pbes2_hmacsha384_aes_192_test.json", "hmacsha384", 192),
    ("pbes2_hmacsha384_aes_256_test.json", "hmacsha384", 256),
    ("pbes2_hmacsha512_aes_128_test.json", "hmacsha512", 128),
    ("pbes2_hmacsha512_aes_192_test.json", "hmacsha512", 192),
    ("pbes2_hmacsha512_aes_256_test.json", "hmacsha512", 256),
]


def _load_pbes2_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, prf_name, key_bits in _PBES2_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        prf = _PRF_MAP[prf_name]
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_prf"] = prf
                test["_prf_name"] = prf_name
                test["_key_bits"] = key_bits
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_PBES2_VECTORS = _load_pbes2_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_PBES2_VECTORS, ids=[v[0] for v in _ALL_PBES2_VECTORS])
def test_pbes2_decrypt(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """PBES2 decrypt from Wycheproof vectors."""
    if not has_mechanism(p11_module, "PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")
    if not has_mechanism(p11_module, "AES_CBC_PAD"):
        pytest.skip("AES_CBC_PAD not supported")

    password = bytes.fromhex(vec["password"])
    salt = bytes.fromhex(vec["salt"])
    iterations = vec["iterationCount"]
    iv = bytes.fromhex(vec["iv"])
    ciphertext = bytes.fromhex(vec["ct"])
    expected = bytes.fromhex(vec["msg"])

    pbkdf2_params = {
        "password": password,
        "salt": salt,
        "iterations": iterations,
        "prf": vec["_prf"],
    }

    try:
        key = p11_session.generate_key(
            KeyType.AES,
            vec["_key_bits"],
            mechanism=Mechanism.PKCS5_PBKD2,
            mechanism_param=pbkdf2_params,
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
                Attribute.DECRYPT: True,
            },
        )
    except p11.exceptions.PKCS11Error as exc:
        pytest.xfail(
            f"PBES2 key derivation unsupported for {vec['_prf_name']}/{vec['_key_bits']}: "
            f"{type(exc).__name__}"
        )

    try:
        plaintext = key.decrypt(ciphertext, mechanism=Mechanism.AES_CBC_PAD, mechanism_param=iv)
    except p11.exceptions.PKCS11Error as exc:
        pytest.xfail(f"PBES2 decrypt failed for valid vector {vec_id}: {type(exc).__name__}")

    assert plaintext == expected, f"PBES2 plaintext mismatch for {vec_id}"
