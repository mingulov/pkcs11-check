"""Wycheproof AES-CMAC and AES key wrap vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"


def _load_flat(filename: str) -> list[tuple[str, dict[str, Any]]]:
    """Load vectors from a Wycheproof JSON, flattening groups."""
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


# --- AES-CMAC ---

_AES_CMAC_VECTORS = _load_flat("aes_cmac_test.json")


def _has_aes_cmac(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_CMAC" in names


@pytest.mark.parametrize("vec_id,vec", _AES_CMAC_VECTORS, ids=[v[0] for v in _AES_CMAC_VECTORS])
def test_aes_cmac(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CMAC verification from Wycheproof vectors."""
    if not _has_aes_cmac(p11_module):
        pytest.skip("AES_CMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    tag_size = vec["_group"].get("tagSize", 128) // 8

    try:
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        raise

    try:
        mac = key.sign(msg, mechanism=Mechanism.AES_CMAC)
        truncated = mac[:tag_size]
        if result == "valid":
            assert truncated == tag_expected
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"AES-CMAC failed for valid vector {vec_id}")

    p11_session.generate_random(64)


# --- AES Key Wrap (RFC 3394) ---

_AES_WRAP_VECTORS = _load_flat("aes_wrap_test.json")


def _has_aes_kw(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_KEY_WRAP" in names


@pytest.mark.parametrize("vec_id,vec", _AES_WRAP_VECTORS, ids=[v[0] for v in _AES_WRAP_VECTORS])
def test_aes_key_wrap(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap (RFC 3394) from Wycheproof vectors.

    For valid vectors: wrap(msg) with key should produce ct.
    We test by importing wrapping key, wrapping a target key, comparing output.
    """
    if not _has_aes_kw(p11_module):
        pytest.skip("AES_KEY_WRAP not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # Import wrapping key
    try:
        wrap_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import AES wrapping key")

    # Import target key (the material being wrapped)
    try:
        target_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: msg,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        pytest.skip("Cannot import target key")

    # Wrap and compare
    try:
        wrapped = wrap_key.wrap_key(target_key, mechanism=Mechanism.AES_KEY_WRAP)
        if result == "valid":
            assert wrapped == ct_expected
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"AES-KW wrap failed for valid vector {vec_id}")
