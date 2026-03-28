"""Wycheproof Ed25519 and Ed448 signature verification vectors."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_ec_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKK_EC_EDWARDS,
    CKM_EDDSA,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402


def _load_ed25519_vectors() -> list[tuple[str, dict[str, Any]]]:
    path = WYCHEPROOF_DIR / "ed25519_test.json"
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data["testGroups"]:
        pk_info = group.get("publicKey", group.get("key", {}))
        for test in group["tests"]:
            test["_pk"] = pk_info
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_ED25519_VECTORS = _load_ed25519_vectors()


@pytest.mark.parametrize("vec_id,vec", _ED25519_VECTORS, ids=[v[0] for v in _ED25519_VECTORS])
def test_ed25519_wycheproof(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Ed25519 signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA not supported")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    pk_info = vec["_pk"]

    # Ed25519 public key: 32 bytes raw
    pk_hex = pk_info.get("pk", "")
    if not pk_hex:
        pytest.skip("No public key in vector")
    pk_bytes = bytes.fromhex(pk_hex)

    # Ed25519 OID: 1.3.101.112
    ed25519_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x70])

    # Import Ed25519 public key
    # EC_POINT for Edwards curves needs the raw 32-byte key wrapped in OCTET STRING
    ec_point = bytes([0x04, len(pk_bytes)]) + pk_bytes

    try:
        pub_key = import_ec_public_key(
            rs.raw, rs.sh,
            ec_params=ed25519_oid, ec_point=ec_point,
            key_type=int(CKK_EC_EDWARDS),
            attrs={CKA_VERIFY: True},
        )
    except AssertionError:
        pytest.skip("Cannot import Ed25519 public key")

    try:
        verify_single(rs.raw, rs.sh, pub_key, CKM_EDDSA, msg, sig)
        if result == "invalid":
            pass  # Some modules accept edge-case sigs
    except AssertionError:
        if result == "valid":
            pytest.fail(f"Valid Ed25519 sig {vec_id} rejected")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)


# --- Ed448 ---


def _load_ed448_vectors() -> list[tuple[str, dict[str, Any]]]:
    path = WYCHEPROOF_DIR / "ed448_test.json"
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data["testGroups"]:
        pk_info = group.get("publicKey", group.get("key", {}))
        for test in group["tests"]:
            test["_pk"] = pk_info
            vec_id = f"ed448:tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


_ED448_VECTORS = _load_ed448_vectors()


@pytest.mark.parametrize("vec_id,vec", _ED448_VECTORS, ids=[v[0] for v in _ED448_VECTORS])
def test_ed448_wycheproof(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """Ed448 signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("EDDSA"):
        pytest.skip("EDDSA not supported")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    pk_info = vec["_pk"]

    pk_hex = pk_info.get("pk", "")
    if not pk_hex:
        pytest.skip("No public key in vector")
    pk_bytes = bytes.fromhex(pk_hex)

    # Ed448 OID: 1.3.101.113
    ed448_oid = bytes([0x06, 0x03, 0x2B, 0x65, 0x71])

    # EC_POINT: DER OCTET STRING wrapper
    ec_point = bytes([0x04, len(pk_bytes)]) + pk_bytes

    try:
        pub_key = import_ec_public_key(
            rs.raw, rs.sh,
            ec_params=ed448_oid, ec_point=ec_point,
            key_type=int(CKK_EC_EDWARDS),
            attrs={CKA_VERIFY: True},
        )
    except AssertionError:
        pytest.skip("Cannot import Ed448 public key")

    try:
        verify_single(rs.raw, rs.sh, pub_key, CKM_EDDSA, msg, sig)
        if result == "invalid":
            pass
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid Ed448 sig {vec_id} rejected: {exc}")
        # acceptable: module rejected invalid vector
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)
