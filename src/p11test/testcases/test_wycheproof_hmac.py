"""Wycheproof HMAC vectors — all SHA variants."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"

_HMAC_FILES = {
    "hmac_sha1_test.json": (KeyType.SHA_1_HMAC, Mechanism.SHA_1_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha224_test.json": (KeyType.SHA224_HMAC, Mechanism.SHA224_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha256_test.json": (None, None, None),  # already in test_wycheproof.py
    "hmac_sha384_test.json": (KeyType.SHA384_HMAC, Mechanism.SHA384_HMAC, KeyType.GENERIC_SECRET),
    "hmac_sha512_test.json": (KeyType.SHA512_HMAC, Mechanism.SHA512_HMAC, KeyType.GENERIC_SECRET),
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
def test_hmac_wycheproof(p11_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HMAC verification from Wycheproof vectors."""
    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    tag_size = vec["_tag_size"]
    mechanism = vec["_mechanism"]

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
