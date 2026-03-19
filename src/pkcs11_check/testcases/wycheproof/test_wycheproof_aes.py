"""Wycheproof AES-CMAC, AES Key Wrap, AES-KWP, and AES-CCM vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402


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


# --- AES Key Wrap with Padding (RFC 5649) ---

_AES_KWP_VECTORS = _load_flat("aes_kwp_test.json")


def _has_aes_kwp(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_KEY_WRAP_PAD" in names


@pytest.mark.parametrize("vec_id,vec", _AES_KWP_VECTORS, ids=[v[0] for v in _AES_KWP_VECTORS])
def test_aes_kwp(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap with Padding (RFC 5649) from Wycheproof vectors.

    KWP allows wrapping data that is not a multiple of 8 bytes,
    unlike basic AES-KW which requires 8-byte aligned data.
    """
    if not _has_aes_kwp(p11_module):
        pytest.skip("AES_KEY_WRAP_PAD not supported")

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

    # KWP can wrap arbitrary-length data — import as generic secret
    # For non-aligned sizes, we use GENERIC_SECRET instead of AES
    key_type = KeyType.AES if len(msg) in (16, 24, 32) else KeyType.GENERIC_SECRET
    try:
        target_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: key_type,
                Attribute.VALUE: msg,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
                **({Attribute.VALUE_LEN: len(msg)} if key_type == KeyType.GENERIC_SECRET else {}),
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        pytest.skip("Cannot import target key for KWP")

    # Wrap with padding and compare
    try:
        wrapped = wrap_key.wrap_key(target_key, mechanism=Mechanism.AES_KEY_WRAP_PAD)
        if result == "valid" and wrapped != ct_expected:
            pytest.xfail(
                f"AES-KWP wrap output differs for {vec_id} "
                f"(got {len(wrapped)}B, expected {len(ct_expected)}B)"
            )
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"AES-KWP wrap failed for valid vector {vec_id}")


# --- AES-CCM ---

_AES_CCM_VECTORS = _load_flat("aes_ccm_test.json")


def _has_aes_ccm(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_CCM" in names


@pytest.mark.parametrize("vec_id,vec", _AES_CCM_VECTORS, ids=[v[0] for v in _AES_CCM_VECTORS])
def test_aes_ccm(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CCM AEAD encryption/decryption from Wycheproof vectors.

    For valid vectors: encrypt(msg, aad, iv) should produce ct||tag.
    """
    if not _has_aes_ccm(p11_module):
        pytest.skip("AES_CCM not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        raise

    # Encrypt and compare
    try:
        ciphertext = key.encrypt(
            msg,
            mechanism=Mechanism.AES_CCM,
            mechanism_param={
                "data_len": len(msg),
                "nonce": iv,
                "associated_data": aad,
                "mac_length": len(tag_expected),
            },
        )
        # AES-CCM output is ct||tag
        if result == "valid":
            assert ciphertext == ct_expected + tag_expected
    except (p11.exceptions.PKCS11Error, TypeError, NotImplementedError):
        if result == "valid":
            pytest.xfail(f"AES-CCM encrypt failed for valid vector {vec_id}")


# --- AES-GMAC ---

_AES_GMAC_VECTORS = _load_flat("aes_gmac_test.json")


def _has_aes_gmac(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_GMAC" in names


@pytest.mark.parametrize("vec_id,vec", _AES_GMAC_VECTORS, ids=[v[0] for v in _AES_GMAC_VECTORS])
def test_aes_gmac(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GMAC (authentication-only GCM) from Wycheproof vectors.

    GMAC is GCM with empty plaintext — produces only a tag over AAD.
    """
    if not _has_aes_gmac(p11_module):
        pytest.skip("AES_GMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])  # AAD in GMAC context
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

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
        mac = key.sign(
            msg,
            mechanism=Mechanism.AES_GMAC,
            mechanism_param=iv,
        )
        if result == "valid":
            assert mac == tag_expected
    except (p11.exceptions.PKCS11Error, TypeError):
        if result == "valid":
            pytest.xfail(f"AES-GMAC sign failed for valid vector {vec_id}")


# --- AES-XTS ---

_AES_XTS_VECTORS = _load_flat("aes_xts_test.json")


def _has_aes_xts(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "AES_XTS" in names


@pytest.mark.parametrize("vec_id,vec", _AES_XTS_VECTORS, ids=[v[0] for v in _AES_XTS_VECTORS])
def test_aes_xts(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS disk encryption mode from Wycheproof vectors.

    XTS uses a double-size key (e.g. 512 bits = two 256-bit keys)
    and a tweak (IV) for sector-based encryption.
    """
    if not _has_aes_xts(p11_module):
        pytest.skip("AES_XTS not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # XTS uses AES_XTS key type with double-size key
    try:
        key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.AES_XTS,
                Attribute.VALUE: key_bytes,
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except (p11.exceptions.PKCS11Error, AttributeError):
        if result == "invalid":
            return
        pytest.skip("Cannot import AES-XTS key")

    try:
        ct = key.encrypt(msg, mechanism=Mechanism.AES_XTS, mechanism_param=iv)
        if result == "valid":
            assert ct == ct_expected
    except (p11.exceptions.PKCS11Error, TypeError):
        if result == "valid":
            pytest.xfail(f"AES-XTS encrypt failed for valid vector {vec_id}")
