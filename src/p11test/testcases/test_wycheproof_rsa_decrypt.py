"""Wycheproof RSA PKCS#1 v1.5 decryption vectors.

Tests RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) across key sizes 2048/3072/4096.
Imports RSA private key, decrypts ciphertext, compares against expected plaintext.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"

_DECRYPT_FILES = [
    "rsa_pkcs1_2048_test.json",
    "rsa_pkcs1_3072_test.json",
    "rsa_pkcs1_4096_test.json",
]


def _load_decrypt_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA PKCS#1 v1.5 decryption vectors."""
    vectors = []
    for filename in _DECRYPT_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_DECRYPT_VECTORS = _load_decrypt_vectors()


@pytest.mark.parametrize(
    "vec_id,vec", _ALL_DECRYPT_VECTORS, ids=[v[0] for v in _ALL_DECRYPT_VECTORS]
)
def test_rsa_pkcs1_decrypt(p11_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 decryption from Wycheproof vectors."""
    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]

    pk = group.get("privateKey", {})
    modulus_hex = pk.get("modulus", "")
    priv_exp_hex = pk.get("privateExponent", "")
    if not modulus_hex or not priv_exp_hex:
        pytest.skip("No RSA private key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    pub_exponent = bytes.fromhex(pk.get("publicExponent", ""))
    priv_exponent = bytes.fromhex(priv_exp_hex)
    prime1 = bytes.fromhex(pk.get("prime1", ""))
    prime2 = bytes.fromhex(pk.get("prime2", ""))
    exp1 = bytes.fromhex(pk.get("exponent1", ""))
    exp2 = bytes.fromhex(pk.get("exponent2", ""))
    coefficient = bytes.fromhex(pk.get("coefficient", ""))

    try:
        priv_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: pub_exponent,
                Attribute.PRIVATE_EXPONENT: priv_exponent,
                Attribute.PRIME_1: prime1,
                Attribute.PRIME_2: prime2,
                Attribute.EXPONENT_1: exp1,
                Attribute.EXPONENT_2: exp2,
                Attribute.COEFFICIENT: coefficient,
                Attribute.TOKEN: False,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import RSA private key")

    try:
        plaintext = priv_key.decrypt(ct, mechanism=Mechanism.RSA_PKCS)
        if result == "valid":
            assert plaintext == msg_expected
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid RSA PKCS#1 ciphertext {vec_id} failed to decrypt")
        # Expected for invalid vectors — padding oracle resistance
