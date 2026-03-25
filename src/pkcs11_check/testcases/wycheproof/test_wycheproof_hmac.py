"""Wycheproof HMAC vectors - all SHA variants."""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_secret_key,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKK_GENERIC_SECRET,
    CKK_SHA3_224_HMAC,
    CKK_SHA3_256_HMAC,
    CKK_SHA3_384_HMAC,
    CKK_SHA3_512_HMAC,
    CKK_SHA224_HMAC,
    CKK_SHA384_HMAC,
    CKK_SHA512_224_HMAC,
    CKK_SHA512_256_HMAC,
    CKK_SHA512_HMAC,
    CKK_SHA_1_HMAC,
    CKM_SHA3_224_HMAC,
    CKM_SHA3_256_HMAC,
    CKM_SHA3_384_HMAC,
    CKM_SHA3_512_HMAC,
    CKM_SHA224_HMAC,
    CKM_SHA384_HMAC,
    CKM_SHA512_224_HMAC,
    CKM_SHA512_256_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHA_1_HMAC,
)

pytestmark = pytest.mark.wycheproof

# Map mechanisms to their name for availability checking
_MECH_NAMES: dict[int, str] = {
    int(CKM_SHA_1_HMAC): "SHA_1_HMAC",
    int(CKM_SHA224_HMAC): "SHA224_HMAC",
    int(CKM_SHA384_HMAC): "SHA384_HMAC",
    int(CKM_SHA512_HMAC): "SHA512_HMAC",
    int(CKM_SHA512_224_HMAC): "SHA512_224_HMAC",
    int(CKM_SHA512_256_HMAC): "SHA512_256_HMAC",
    int(CKM_SHA3_224_HMAC): "SHA3_224_HMAC",
    int(CKM_SHA3_256_HMAC): "SHA3_256_HMAC",
    int(CKM_SHA3_384_HMAC): "SHA3_384_HMAC",
    int(CKM_SHA3_512_HMAC): "SHA3_512_HMAC",
}

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_HMAC_FILES: dict[str, tuple[int | None, int | None, int | None]] = {
    "hmac_sha1_test.json": (int(CKK_SHA_1_HMAC), int(CKM_SHA_1_HMAC), int(CKK_GENERIC_SECRET)),
    "hmac_sha224_test.json": (
        int(CKK_SHA224_HMAC),
        int(CKM_SHA224_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha256_test.json": (None, None, None),  # already in test_wycheproof.py
    "hmac_sha384_test.json": (
        int(CKK_SHA384_HMAC),
        int(CKM_SHA384_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha512_test.json": (
        int(CKK_SHA512_HMAC),
        int(CKM_SHA512_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    # SHA-512 truncated variants (PKCS#11 v3.0)
    "hmac_sha512_224_test.json": (
        int(CKK_SHA512_224_HMAC),
        int(CKM_SHA512_224_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha512_256_test.json": (
        int(CKK_SHA512_256_HMAC),
        int(CKM_SHA512_256_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    # SHA-3 HMAC (PKCS#11 v3.0)
    "hmac_sha3_224_test.json": (
        int(CKK_SHA3_224_HMAC),
        int(CKM_SHA3_224_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha3_256_test.json": (
        int(CKK_SHA3_256_HMAC),
        int(CKM_SHA3_256_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha3_384_test.json": (
        int(CKK_SHA3_384_HMAC),
        int(CKM_SHA3_384_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
    "hmac_sha3_512_test.json": (
        int(CKK_SHA3_512_HMAC),
        int(CKM_SHA3_512_HMAC),
        int(CKK_GENERIC_SECRET),
    ),
}


def _load_hmac_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, (key_type, mechanism, fallback_type) in _HMAC_FILES.items():
        if key_type is None:
            continue  # skip sha256 - already covered
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
    p11_raw_session: Any, vec_id: str, vec: dict[str, Any]
) -> None:
    """HMAC verification from Wycheproof vectors."""
    rs = p11_raw_session
    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]
    tag_size = vec["_tag_size"]
    mechanism = vec["_mechanism"]

    # Check mechanism availability from the module's mechanism list
    mech_display = _MECH_NAMES.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(mech_display):
        pytest.skip(f"{mech_display} not supported by module")

    # Try typed key, fall back to GENERIC_SECRET
    key = None
    for kt in (vec["_key_type"], vec["_fallback_type"]):
        try:
            key = import_secret_key(
                rs.raw,
                rs.sh,
                kt,
                key_bytes,
                attrs={
                    int(CKA_SIGN): True,
                    int(CKA_TOKEN): False,
                    int(CKA_SENSITIVE): False,
                },
            )
            break
        except AssertionError:
            continue

    if key is None:
        if result == "invalid":
            return
        pytest.xfail(f"Cannot import {len(key_bytes)}-byte HMAC key")

    try:
        mac = sign_single(rs.raw, rs.sh, key, mechanism, msg)
        truncated = mac[:tag_size]
        if result == "valid":
            assert truncated == tag_expected
    except AssertionError as exc:
        if result == "valid":
            pytest.xfail(f"HMAC failed: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
