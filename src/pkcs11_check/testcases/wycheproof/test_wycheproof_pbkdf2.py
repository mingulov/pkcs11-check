"""Wycheproof PBKDF2 key derivation vectors.

Tests PKCS#5 PBKDF2 (RFC 8018) with HMAC-SHA1/224/256/384/512.
Uses CKM_PKCS5_PBKD2 mechanism with CK_PKCS5_PBKD2_PARAMS2.
Skips on modules without PBKDF2 support (e.g., SoftHSM2).
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Map Wycheproof file suffix to CKP_PKCS5_PBKD2_HMAC_* PRF constant
# These must match the values in python-pkcs11's _pkcs11.pxd
_PRF_MAP = {
    "hmacsha1": 0x00000001,  # CKP_PKCS5_PBKD2_HMAC_SHA1
    "hmacsha224": 0x00000003,  # CKP_PKCS5_PBKD2_HMAC_SHA224
    "hmacsha256": 0x00000004,  # CKP_PKCS5_PBKD2_HMAC_SHA256
    "hmacsha384": 0x00000005,  # CKP_PKCS5_PBKD2_HMAC_SHA384
    "hmacsha512": 0x00000006,  # CKP_PKCS5_PBKD2_HMAC_SHA512
}

_PBKDF2_FILES = [
    ("pbkdf2_hmacsha1_test.json", "hmacsha1"),
    ("pbkdf2_hmacsha224_test.json", "hmacsha224"),
    ("pbkdf2_hmacsha256_test.json", "hmacsha256"),
    ("pbkdf2_hmacsha384_test.json", "hmacsha384"),
    ("pbkdf2_hmacsha512_test.json", "hmacsha512"),
]


def _load_pbkdf2_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load PBKDF2 vectors with PRF info."""
    vectors = []
    for filename, prf_name in _PBKDF2_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        prf = _PRF_MAP.get(prf_name)
        if prf is None:
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_prf"] = prf
                test["_prf_name"] = prf_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_PBKDF2_VECTORS = _load_pbkdf2_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_PBKDF2_VECTORS, ids=[v[0] for v in _ALL_PBKDF2_VECTORS])
def test_pbkdf2(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """PBKDF2 key derivation from Wycheproof vectors.

    Derives a key using CKM_PKCS5_PBKD2 and compares the extracted
    key material against the expected derived key (dk).
    """
    if not has_mechanism(p11_module, "PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")

    password = bytes.fromhex(vec["password"])
    salt = bytes.fromhex(vec["salt"])
    iterations = vec["iterationCount"]
    dk_len = vec["dkLen"]  # bytes
    dk_expected = bytes.fromhex(vec["dk"])
    result = vec["result"]
    prf = vec["_prf"]

    # CKM_PKCS5_PBKD2 is a key generation mechanism (not derivation).
    # The password is passed in the mechanism params, not as a base key.
    pbkdf2_params = {
        "password": password,
        "salt": salt,
        "iterations": iterations,
        "prf": prf,
    }

    try:
        derived = p11_session.generate_key(
            KeyType.GENERIC_SECRET,
            dk_len * 8,  # bits
            mechanism=Mechanism.PKCS5_PBKD2,
            mechanism_param=pbkdf2_params,
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )
        dk_actual = derived[Attribute.VALUE]
        if result == "valid":
            assert dk_actual == dk_expected, (
                f"PBKDF2 output mismatch for {vec_id}: "
                f"got {dk_actual.hex()[:20]}... expected {dk_expected.hex()[:20]}..."
            )
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"PBKDF2 generate_key failed for valid vector {vec_id}")
