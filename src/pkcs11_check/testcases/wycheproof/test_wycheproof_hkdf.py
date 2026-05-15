"""Wycheproof HKDF vectors.

Tests HKDF (RFC 5869) with SHA-1/SHA-256/SHA-384/SHA-512.
Requires CKM_HKDF_DERIVE mechanism with CK_HKDF_PARAMS.
Skips on modules without HKDF support (e.g., SoftHSM2).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_hkdf
from pkcs11_check.raw.recipes import (
    create_object,
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_HKDF_DERIVE,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKO_SECRET_KEY,
)

pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v30]
REQUIRED_MECHANISMS = ["HKDF_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_HKDF_FILES = [
    ("hkdf_sha1_test.json", "SHA-1"),
    ("hkdf_sha256_test.json", "SHA-256"),
    ("hkdf_sha384_test.json", "SHA-384"),
    ("hkdf_sha512_test.json", "SHA-512"),
]

_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
}


def _load_hkdf_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load HKDF vectors."""
    vectors = []
    for filename, sha in _HKDF_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_sha"] = sha
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_HKDF_VECTORS = _load_hkdf_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_HKDF_VECTORS, ids=[v[0] for v in _ALL_HKDF_VECTORS])
def test_hkdf(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HKDF key derivation from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("HKDF_DERIVE"):
        pytest.skip("HKDF_DERIVE not supported")

    ikm = bytes.fromhex(vec["ikm"])
    salt = bytes.fromhex(vec["salt"])
    info = bytes.fromhex(vec["info"])
    okm_expected = bytes.fromhex(vec["okm"])
    okm_size = vec["size"]
    result = vec["result"]
    sha = vec["_sha"]

    hash_mech = _SHA_HASH_MECHS.get(sha)
    if hash_mech is None:
        pytest.skip(f"No hash mechanism mapping for {sha}")

    # Import IKM as a generic secret key
    try:
        ikm_key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE: ikm,
                CKA_VALUE_LEN: len(ikm),
                CKA_DERIVE: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        pytest.skip("Cannot import IKM key for HKDF")

    # CK_HKDF_PARAMS: (hash_mechanism, salt, info)
    # Uses extract+expand mode (standard HKDF)
    hkdf_param = mech_hkdf(
        CKM_HKDF_DERIVE,
        hash_mech=hash_mech,
        extract=True,
        expand=True,
        salt=salt if salt else None,
        info=info if info else None,
    )
    okm = None
    try:
        derived = derive_key(
            rs.raw,
            rs.sh,
            ikm_key,
            CKM_HKDF_DERIVE,
            attrs={
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: okm_size,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=hkdf_param,
        )
        attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
        okm = attrs[CKA_VALUE]
        assert isinstance(okm, bytes)
        destroy_quietly(rs.raw, rs.sh, derived)
    except (AssertionError, TypeError, NotImplementedError) as exc:
        if result == "valid":
            pytest.fail(f"HKDF derive failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, ikm_key)

    if result == "valid" and okm is not None:
        assert okm == okm_expected
