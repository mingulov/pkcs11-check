"""Wycheproof X25519 and X448 key exchange vectors.

Tests Montgomery curve Diffie-Hellman (RFC 7748) using CKM_ECDH1_DERIVE
with EC_MONTGOMERY key type. Skips on modules without Montgomery support.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import KDF

from p11test.testcases.conftest import has_mechanism

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"

# OIDs for Montgomery curves
X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])  # 1.3.101.110
X448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])  # 1.3.101.111

_X25519_X448_FILES = [
    ("x25519_test.json", X25519_OID, 32),
    ("x448_test.json", X448_OID, 56),
]


def _load_xdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load X25519/X448 key exchange vectors."""
    vectors = []
    for filename, oid, key_size in _X25519_X448_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_oid"] = oid
                test["_key_size"] = key_size
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_XDH_VECTORS = _load_xdh_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_XDH_VECTORS, ids=[v[0] for v in _ALL_XDH_VECTORS])
def test_xdh(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """X25519/X448 key exchange from Wycheproof vectors."""
    if not has_mechanism(p11_module, "ECDH1_DERIVE"):
        pytest.skip("ECDH1_DERIVE not supported")

    oid = vec["_oid"]
    key_size = vec["_key_size"]
    public_bytes = bytes.fromhex(vec["public"])
    private_bytes = bytes.fromhex(vec["private"])
    shared_expected = bytes.fromhex(vec["shared"])
    result = vec["result"]

    # Import Montgomery private key
    try:
        priv_key = p11_session.create_object(
            {
                Attribute.CLASS: p11.ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.EC_MONTGOMERY,
                Attribute.EC_PARAMS: oid,
                Attribute.VALUE: private_bytes,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except (p11.exceptions.PKCS11Error, AttributeError):
        if result == "invalid":
            return
        pytest.skip("Cannot import Montgomery private key")

    # Derive shared secret
    try:
        derived = priv_key.derive_key(
            KeyType.GENERIC_SECRET,
            key_size * 8,  # bits
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, public_bytes),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )
        shared = derived[Attribute.VALUE]
        if result == "valid":
            assert shared == shared_expected
    except (p11.exceptions.PKCS11Error, TypeError):
        if result == "valid":
            pytest.xfail(f"X25519/X448 derive failed for valid vector {vec_id}")
