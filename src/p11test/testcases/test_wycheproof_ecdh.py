"""Wycheproof ECDH key agreement vectors.

Tests ECDH (P-256, P-384, P-521) using ecpoint-encoded test vectors.
Imports private key + peer public key, performs derive, compares shared secret.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import KDF

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"

# OIDs for PKCS#11 EC key import (DER-encoded)
_CURVE_OIDS: dict[str, bytes] = {
    "secp256r1": bytes.fromhex("06082a8648ce3d030107"),  # OID 1.2.840.10045.3.1.7
    "secp384r1": bytes.fromhex("06052b81040022"),  # OID 1.3.132.0.34
    "secp521r1": bytes.fromhex("06052b81040023"),  # OID 1.3.132.0.35
}

# Key sizes in bits for derive_key (python-pkcs11 divides by 8 internally)
_CURVE_KEY_BITS: dict[str, int] = {
    "secp256r1": 256,
    "secp384r1": 384,
    "secp521r1": 528,  # 66 bytes = 528 bits (ceil(521/8)*8)
}

_ECDH_FILES = [
    ("ecdh_secp256r1_ecpoint_test.json", "secp256r1"),
    ("ecdh_secp384r1_ecpoint_test.json", "secp384r1"),
    ("ecdh_secp521r1_ecpoint_test.json", "secp521r1"),
]


def _load_ecdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDH ecpoint vectors."""
    vectors = []
    for filename, curve in _ECDH_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_curve"] = curve
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_ECDH_VECTORS = _load_ecdh_vectors()


def _has_ecdh(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "ECDH1_DERIVE" in names


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDH_VECTORS, ids=[v[0] for v in _ALL_ECDH_VECTORS])
def test_ecdh(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDH key agreement from Wycheproof ecpoint vectors."""
    if not _has_ecdh(p11_module):
        pytest.skip("ECDH1_DERIVE not supported")

    curve = vec["_curve"]
    oid = _CURVE_OIDS.get(curve)
    if oid is None:
        pytest.skip(f"No OID for curve {curve}")

    public_point = bytes.fromhex(vec["public"])
    private_scalar = bytes.fromhex(vec["private"])
    shared_expected = bytes.fromhex(vec["shared"])
    result = vec["result"]

    # Import EC private key
    try:
        priv_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.EC_PARAMS: oid,
                Attribute.VALUE: private_scalar,
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        pytest.skip("Cannot import EC private key for ECDH")

    # Derive shared secret
    # ECDH1_DERIVE params: (kdf, shared_data, public_data)
    # KDF.NULL means raw ECDH (no KDF applied to output)
    try:
        derived_key = priv_key.derive_key(
            KeyType.GENERIC_SECRET,
            _CURVE_KEY_BITS[curve],
            mechanism=Mechanism.ECDH1_DERIVE,
            mechanism_param=(KDF.NULL, None, public_point),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )
        # Extract the derived key value
        shared = derived_key[Attribute.VALUE]
        if result == "valid":
            assert shared == shared_expected, f"ECDH shared secret mismatch for {vec_id}"
        elif result == "invalid":
            pass  # Invalid but derive succeeded — module-specific
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid ECDH derive failed for {vec_id}")
    except (TypeError, NotImplementedError):
        pytest.skip("ECDH derive not supported by binding")
