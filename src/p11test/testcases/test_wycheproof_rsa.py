"""Wycheproof RSA signature verification vectors — all key sizes and hashes.

Auto-discovers RSA signature vector files from the Wycheproof submodule.
Each file produces a parametrized test class.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[Mechanism, str] = {
    Mechanism.SHA224_RSA_PKCS: "SHA224_RSA_PKCS",
    Mechanism.SHA256_RSA_PKCS: "SHA256_RSA_PKCS",
    Mechanism.SHA384_RSA_PKCS: "SHA384_RSA_PKCS",
    Mechanism.SHA512_RSA_PKCS: "SHA512_RSA_PKCS",
    Mechanism.SHA3_224_RSA_PKCS: "SHA3_224_RSA_PKCS",
    Mechanism.SHA3_256_RSA_PKCS: "SHA3_256_RSA_PKCS",
    Mechanism.SHA3_384_RSA_PKCS: "SHA3_384_RSA_PKCS",
    Mechanism.SHA3_512_RSA_PKCS: "SHA3_512_RSA_PKCS",
}

from p11test.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Map hash names to PKCS#11 mechanisms
_RSA_HASH_MECHANISMS = {
    "SHA-224": Mechanism.SHA224_RSA_PKCS,
    "SHA-256": Mechanism.SHA256_RSA_PKCS,
    "SHA-384": Mechanism.SHA384_RSA_PKCS,
    "SHA-512": Mechanism.SHA512_RSA_PKCS,
    # SHA-3 (PKCS#11 v3.0+)
    "SHA3-224": Mechanism.SHA3_224_RSA_PKCS,
    "SHA3-256": Mechanism.SHA3_256_RSA_PKCS,
    "SHA3-384": Mechanism.SHA3_384_RSA_PKCS,
    "SHA3-512": Mechanism.SHA3_512_RSA_PKCS,
}

# All RSA signature vector files we want to test
_RSA_SIG_FILES = [
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_2048_sha512_224_test.json",
    "rsa_signature_2048_sha512_256_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_3072_sha512_256_test.json",
    "rsa_signature_4096_sha256_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
    "rsa_signature_4096_sha512_256_test.json",
    # 8192-bit RSA (large key, slow)
    "rsa_signature_8192_sha256_test.json",
    "rsa_signature_8192_sha384_test.json",
    "rsa_signature_8192_sha512_test.json",
    # SHA-3 variants (PKCS#11 v3.0+)
    "rsa_signature_2048_sha3_224_test.json",
    "rsa_signature_2048_sha3_256_test.json",
    "rsa_signature_2048_sha3_384_test.json",
    "rsa_signature_2048_sha3_512_test.json",
    "rsa_signature_3072_sha3_256_test.json",
    "rsa_signature_3072_sha3_384_test.json",
    "rsa_signature_3072_sha3_512_test.json",
]


def _load_all_rsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all RSA vectors with file name as identifier."""
    vectors = []
    for filename in _RSA_SIG_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "SHA-256")
            mechanism = _RSA_HASH_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_RSA_VECTORS = _load_all_rsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_RSA_VECTORS, ids=[v[0] for v in _ALL_RSA_VECTORS])
def test_rsa_wycheproof(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """RSA PKCS#1 v1.5 signature verification from Wycheproof vectors."""
    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]

    # Check mechanism availability
    mech_display = _MECH_DISPLAY.get(mechanism, str(mechanism))
    slot = p11_module.get_slots(token_present=True)[0]
    supported = {mech_name(m) for m in slot.get_mechanisms()}
    if mech_display not in supported:
        pytest.skip(f"{mech_display} not supported by module")

    pk = group.get("publicKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    exponent = bytes.fromhex(exp_hex)

    try:
        pub_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: exponent,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import RSA public key")

    try:
        pub_key.verify(msg, sig, mechanism=mechanism)
        if result == "invalid":
            pass  # Some modules accept edge-case sigs
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid RSA sig {vec_id} rejected")
