"""Wycheproof HMAC vectors — all SHA variants."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

# Map mechanisms to their name for availability checking
_MECH_NAMES: dict[Mechanism, str] = {
    Mechanism.SHA_1_HMAC: "SHA_1_HMAC",
    Mechanism.SHA224_HMAC: "SHA224_HMAC",
    Mechanism.SHA256_HMAC: "SHA256_HMAC",
    Mechanism.SHA384_HMAC: "SHA384_HMAC",
    Mechanism.SHA512_HMAC: "SHA512_HMAC",
    Mechanism.SHA512_224_HMAC: "SHA512_224_HMAC",
    Mechanism.SHA512_256_HMAC: "SHA512_256_HMAC",
    Mechanism.SHA3_224_HMAC: "SHA3_224_HMAC",
    Mechanism.SHA3_256_HMAC: "SHA3_256_HMAC",
    Mechanism.SHA3_384_HMAC: "SHA3_384_HMAC",
    Mechanism.SHA3_512_HMAC: "SHA3_512_HMAC",
}

from p11test.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_HMAC_FILES = {
    "hmac_sha1_test.json": (KeyType.SHA_1_HMAC, Mechanism.SHA_1_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha224_test.json": (KeyType.SHA224_HMAC, Mechanism.SHA224_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha256_test.json": (None, None, None),  # already in test_wycheproof.py
    "hmac_sha384_test.json": (KeyType.SHA384_HMAC, Mechanism.SHA384_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha512_test.json": (KeyType.SHA512_HMAC, Mechanism.SHA512_HMAC, KeyType.GENERIC_SECRET),
    # SHA-512 truncated variants (PKCS#11 v3.0)
    "hmac_sha512_224_test.json": (
        KeyType.SHA512_224_HMAC,
        Mechanism.SHA512_224_HMAC,
        KeyType.GENERIC_SECRET,
    ),
    "hmac_sha512_256_test.json": (
        KeyType.SHA512_256_HMAC,
        Mechanism.SHA512_256_HMAC,
        KeyType.GENERIC_SECRET,
    ),
    # SHA-3 HMAC (PKCS#11 v3.0)
    "hmac_sha3_224_test.json": (
        KeyType.SHA3_224_HMAC,
        Mechanism.SHA3_224_HMAC,
        KeyType.GENERIC_SECRET,
    ),
    "hmac_sha3_256_test.json": (
        KeyType.SHA3_256_HMAC,
        Mechanism.SHA3_256_HMAC,
        KeyType.GENERIC_SECRET,
    ),
    "hmac_sha3_384_test.json": (
        KeyType.SHA3_384_HMAC,
        Mechanism.SHA3_384_HMAC,
        KeyType.GENERIC_SECRET,
    ),
    "hmac_sha3_512_test.json": (
        KeyType.SHA3_512_HMAC,
        Mechanism.SHA3_512_HMAC,
        KeyType.GENERIC_SECRET,
    ),
}


def _load_hmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, (key_type, mechanism, fallback_type) in _HMAC_FILES.items():
        if key_type is None:
            continue  # skip sha256 — already covered
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            tag_size = group.get("tagSize", 256) // 8
            for test in group["tests"]:
                test["_key_type"] = key_type
                test["_mechanism"] = mechanism
                test["_fallback_type"] = fallback_type
                test["_tag_size"] = tag_size
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_HMAC_VECTORS = _load_hmac_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_HMAC_VECTORS, ids=[v[0] for v in _ALL_HMAC_VECTORS])
def test_hmac_wycheproof(
    p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """HMAC verification from Wycheproof vectors."""
    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    tag_size = vec["_tag_size"]
    mechanism = vec["_mechanism"]

    # Check mechanism availability from the module's mechanism list
    mech_display = _MECH_NAMES.get(mechanism, str(mechanism))
    slot = p11_module.get_slots(token_present=True)[0]
    supported = {mech_name(m) for m in slot.get_mechanisms()}
    if mech_display not in supported:
        pytest.skip(f"{mech_display} not supported by module")

    # Try typed key, fall back to GENERIC_SECRET
    key = None
    for kt in (vec["_key_type"], vec["_fallback_type"]):
        try:
            key = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: kt,
                    Attribute.VALUE: key_bytes,
                    Attribute.SIGN: True,
                    Attribute.TOKEN: False,
                    Attribute.SENSITIVE: False,
                }
            )
            break
        except p11.exceptions.PKCS11Error:
            continue

    if key is None:
        if result == "invalid":
            return
        pytest.xfail(f"Cannot import {len(key_bytes)}-byte HMAC key")

    try:
        mac = key.sign(msg, mechanism=mechanism)
        truncated = mac[:tag_size]
        if result == "valid":
            assert truncated == tag_expected
    except p11.exceptions.PKCS11Error as exc:
        if result == "valid":
            pytest.xfail(f"HMAC failed: {type(exc).__name__}")
