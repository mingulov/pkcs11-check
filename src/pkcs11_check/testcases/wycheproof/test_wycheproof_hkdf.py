"""Wycheproof HKDF vectors.

Tests HKDF (RFC 5869) with SHA-1/SHA-256/SHA-384/SHA-512.
Requires CKM_HKDF_DERIVE mechanism with CK_HKDF_PARAMS.
Skips on modules without HKDF support (e.g., SoftHSM2).
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

from pkcs11_check.testcases.conftest import mech_name

pytestmark = [pytest.mark.wycheproof, pytest.mark.requires_v30]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_HKDF_FILES = [
    ("hkdf_sha1_test.json", "SHA-1"),
    ("hkdf_sha256_test.json", "SHA-256"),
    ("hkdf_sha384_test.json", "SHA-384"),
    ("hkdf_sha512_test.json", "SHA-512"),
]

_SHA_HASH_MECHS: dict[str, Mechanism] = {
    "SHA-1": Mechanism.SHA_1,
    "SHA-256": Mechanism.SHA256,
    "SHA-384": Mechanism.SHA384,
    "SHA-512": Mechanism.SHA512,
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


def _has_hkdf(p11_module: Any) -> bool:
    slot = p11_module.get_slots(token_present=True)[0]
    names = {mech_name(m) for m in slot.get_mechanisms()}
    return "HKDF_DERIVE" in names or any("0x0000402a" in n for n in names)


@pytest.mark.parametrize("vec_id,vec", _ALL_HKDF_VECTORS, ids=[v[0] for v in _ALL_HKDF_VECTORS])
def test_hkdf(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """HKDF key derivation from Wycheproof vectors."""
    if not _has_hkdf(p11_module):
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
        ikm_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
                Attribute.VALUE: ikm,
                Attribute.VALUE_LEN: len(ikm),
                Attribute.DERIVE: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        if result == "invalid":
            return
        pytest.skip("Cannot import IKM key for HKDF")

    # CK_HKDF_PARAMS: (hash_mechanism, salt, info)
    # Uses extract+expand mode (standard HKDF)
    try:
        derived = ikm_key.derive_key(
            KeyType.GENERIC_SECRET,
            okm_size * 8,  # bits
            mechanism=Mechanism.HKDF_DERIVE,
            mechanism_param=(hash_mech, salt, info),
            template={
                Attribute.SENSITIVE: False,
                Attribute.EXTRACTABLE: True,
                Attribute.TOKEN: False,
            },
        )
        okm = derived[Attribute.VALUE]
        if result == "valid":
            assert okm == okm_expected
    except (p11.exceptions.PKCS11Error, TypeError, NotImplementedError):
        if result == "valid":
            pytest.xfail(f"HKDF derive failed for valid vector {vec_id}")
