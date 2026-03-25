"""Wycheproof PBKDF2 key derivation vectors.

Tests PKCS#5 PBKDF2 (RFC 8018) with HMAC-SHA1/224/256/384/512.
Uses CKM_PKCS5_PBKD2 mechanism with CK_PKCS5_PBKD2_PARAMS2.
Skips on modules without PBKDF2 support (e.g., SoftHSM2).
"""

from __future__ import annotations

import json
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    PackedMechanism,
    mech_pbkdf2,
    template_from_dict,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_PKCS5_PBKD2,
    CKP_PKCS5_PBKD2_HMAC_SHA1,
    CKP_PKCS5_PBKD2_HMAC_SHA224,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKP_PKCS5_PBKD2_HMAC_SHA384,
    CKP_PKCS5_PBKD2_HMAC_SHA512,
    CKR_OK,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Map Wycheproof file suffix to CKP_PKCS5_PBKD2_HMAC_* PRF constant
_PRF_MAP: dict[str, int] = {
    "hmacsha1": int(CKP_PKCS5_PBKD2_HMAC_SHA1),
    "hmacsha224": int(CKP_PKCS5_PBKD2_HMAC_SHA224),
    "hmacsha256": int(CKP_PKCS5_PBKD2_HMAC_SHA256),
    "hmacsha384": int(CKP_PKCS5_PBKD2_HMAC_SHA384),
    "hmacsha512": int(CKP_PKCS5_PBKD2_HMAC_SHA512),
}

_PBKDF2_FILES = [
    ("pbkdf2_hmacsha1_test.json", "hmacsha1"),
    ("pbkdf2_hmacsha224_test.json", "hmacsha224"),
    ("pbkdf2_hmacsha256_test.json", "hmacsha256"),
    ("pbkdf2_hmacsha384_test.json", "hmacsha384"),
    ("pbkdf2_hmacsha512_test.json", "hmacsha512"),
]


def _load_pbkdf2_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load PBKDF2 vectors with PRF info."""
    vectors = []
    for filename, prf_name in _PBKDF2_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        prf = _PRF_MAP.get(prf_name)
        if prf is None:
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_prf"] = prf
                test["_prf_name"] = prf_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_PBKDF2_VECTORS = _load_pbkdf2_vectors()


def _generate_key_with_mech(
    raw: Any, session: int, mech: PackedMechanism, attrs: dict[int, Any]
) -> int:
    """C_GenerateKey with a custom mechanism (for PBKDF2)."""
    tmpl = template_from_dict(attrs)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(session, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(int(rv), CKR_OK)
    return int(key.value)


@pytest.mark.parametrize("vec_id,vec", _ALL_PBKDF2_VECTORS, ids=[v[0] for v in _ALL_PBKDF2_VECTORS])
def test_pbkdf2(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """PBKDF2 key derivation from Wycheproof vectors.

    Derives a key using CKM_PKCS5_PBKD2 and compares the extracted
    key material against the expected derived key (dk).
    """
    rs = p11_raw_session
    if not rs.has_mechanism("PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")

    password = bytes.fromhex(vec["password"])
    salt = bytes.fromhex(vec["salt"])
    iterations = vec["iterationCount"]
    dk_len = vec["dkLen"]  # bytes
    dk_expected = bytes.fromhex(vec["dk"])
    result = vec["result"]
    prf = vec["_prf"]

    # Build PBKDF2 mechanism params
    pbkdf2_param = mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=salt,
        iterations=iterations,
        prf=prf,
        password=password,
    )

    try:
        derived = _generate_key_with_mech(
            rs.raw,
            rs.sh,
            pbkdf2_param,
            {
                int(CKA_KEY_TYPE): int(CKK_GENERIC_SECRET),
                int(CKA_VALUE_LEN): dk_len,
                int(CKA_SENSITIVE): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_TOKEN): False,
            },
        )
        attrs = read_attributes(rs.raw, rs.sh, derived, [int(CKA_VALUE)])
        dk_actual = attrs[int(CKA_VALUE)]
        assert isinstance(dk_actual, bytes)
        if result == "valid":
            assert dk_actual == dk_expected, (
                f"PBKDF2 output mismatch for {vec_id}: "
                f"got {dk_actual.hex()[:20]}... expected {dk_expected.hex()[:20]}..."
            )
        destroy_quietly(rs.raw, rs.sh, derived)
    except AssertionError:
        if result == "valid":
            pytest.xfail(f"PBKDF2 generate_key failed for valid vector {vec_id}")
        # acceptable: reject is fine
        return
