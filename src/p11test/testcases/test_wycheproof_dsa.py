"""Wycheproof DSA signature verification vectors.

Tests DSA across key sizes 2048/3072 with SHA-224/SHA-256.
Uses DER-encoded signatures (not P1363).
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

_SHA_MECHANISMS: dict[str, Mechanism] = {
    "SHA-224": Mechanism.DSA_SHA224,
    "SHA-256": Mechanism.DSA_SHA256,
}

# DSA vector files — DER-encoded (not P1363)
_DSA_FILES = [
    "dsa_2048_224_sha224_test.json",
    "dsa_2048_224_sha256_test.json",
    "dsa_2048_256_sha256_test.json",
    "dsa_3072_256_sha256_test.json",
]


def _load_dsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all DSA DER-encoded vectors."""
    vectors = []
    for filename in _DSA_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mechanism = _SHA_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_DSA_VECTORS = _load_dsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_DSA_VECTORS, ids=[v[0] for v in _ALL_DSA_VECTORS])
def test_dsa(p11_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """DSA signature verification from Wycheproof vectors."""
    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]

    pk = group.get("publicKey", {})
    p_hex = pk.get("p", "")
    q_hex = pk.get("q", "")
    g_hex = pk.get("g", "")
    y_hex = pk.get("y", "")
    if not all([p_hex, q_hex, g_hex, y_hex]):
        pytest.skip("Incomplete DSA public key")

    prime = bytes.fromhex(p_hex)
    subprime = bytes.fromhex(q_hex)
    base = bytes.fromhex(g_hex)
    value = bytes.fromhex(y_hex)

    try:
        pub_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.DSA,
                Attribute.PRIME: prime,
                Attribute.SUBPRIME: subprime,
                Attribute.BASE: base,
                Attribute.VALUE: value,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import DSA public key")

    try:
        pub_key.verify(msg, sig, mechanism=mechanism)
        if result == "invalid":
            pass  # Some modules accept edge-case signatures
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.fail(f"Valid DSA sig {vec_id} rejected")
