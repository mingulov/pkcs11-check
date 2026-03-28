"""Wycheproof RSA PKCS#1 v1.5 decryption vectors.

Tests RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) across key sizes 2048/3072/4096.
Imports RSA private key, decrypts ciphertext, compares against expected plaintext.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKK_RSA,
    CKM_RSA_PKCS,
    CKO_PRIVATE_KEY,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

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
def test_rsa_pkcs1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 decryption from Wycheproof vectors."""
    rs = p11_raw_session
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
        priv_key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_RSA,
                CKA_MODULUS: modulus,
                CKA_PUBLIC_EXPONENT: pub_exponent,
                CKA_PRIVATE_EXPONENT: priv_exponent,
                CKA_PRIME_1: prime1,
                CKA_PRIME_2: prime2,
                CKA_EXPONENT_1: exp1,
                CKA_EXPONENT_2: exp2,
                CKA_COEFFICIENT: coefficient,
                CKA_TOKEN: False,
                CKA_DECRYPT: True,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        pytest.skip("Cannot import RSA private key")

    plaintext = None
    try:
        plaintext = decrypt_single(rs.raw, rs.sh, priv_key, CKM_RSA_PKCS, ct)
    except AssertionError:
        if result == "valid":
            pytest.fail(f"Valid RSA PKCS#1 ciphertext {vec_id} failed to decrypt")
        # acceptable/invalid: reject is fine (padding oracle resistance)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
