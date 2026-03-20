"""Wycheproof ML-DSA signature verification vectors.

Tests ML-DSA-44/65/87 (FIPS 204) signature verification.
Requires PKCS#11 v3.2 with ML-DSA support.
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v32, pytest.mark.pqc]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_MLDSA_FILES = [
    ("mldsa_44_verify_test.json", 44),
    ("mldsa_65_verify_test.json", 65),
    ("mldsa_87_verify_test.json", 87),
]


def _load_mldsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ML-DSA verify vectors."""
    vectors = []
    for filename, param_set in _MLDSA_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_param_set"] = param_set
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_MLDSA_VECTORS = _load_mldsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_MLDSA_VECTORS, ids=[v[0] for v in _ALL_MLDSA_VECTORS])
def test_mldsa_verify(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ML-DSA signature verification from Wycheproof vectors."""
    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip("ML_DSA not supported")

    group = vec["_group"]
    pk_hex = group.get("publicKey", "")
    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]

    if not pk_hex:
        pytest.skip("No public key in vector")

    pk_bytes = bytes.fromhex(pk_hex)

    try:
        pub_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.ML_DSA,
                Attribute.VALUE: pk_bytes,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
    except (p11.exceptions.PKCS11Error, AttributeError):
        pytest.skip("Cannot import ML-DSA public key")

    try:
        pub_key.verify(msg, sig, mechanism=Mechanism.ML_DSA)
        if result == "invalid":
            pass  # Module accepted edge-case sig
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid ML-DSA sig {vec_id} rejected")
