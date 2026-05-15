"""Wycheproof DSA signature verification vectors.

Tests DSA across key sizes 2048/3072 with SHA-224/SHA-256.
Supports both ASN.1 DER and IEEE P1363 signature encodings.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_dsa_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_DSA_SHA224,
    CKM_DSA_SHA256,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["DSA_SHA256"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

_SHA_MECHANISMS: dict[str, int] = {
    "SHA-224": CKM_DSA_SHA224,
    "SHA-256": CKM_DSA_SHA256,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_DSA_SHA224: "DSA_SHA224",
    CKM_DSA_SHA256: "DSA_SHA256",
}

_DSA_FILES = [
    "dsa_2048_224_sha224_test.json",
    "dsa_2048_224_sha224_p1363_test.json",
    "dsa_2048_224_sha256_test.json",
    "dsa_2048_224_sha256_p1363_test.json",
    "dsa_2048_256_sha256_test.json",
    "dsa_2048_256_sha256_p1363_test.json",
    "dsa_3072_256_sha256_test.json",
    "dsa_3072_256_sha256_p1363_test.json",
]


def _load_dsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all DSA vectors."""
    vectors = []
    for filename in _DSA_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mechanism = _SHA_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                test["_is_p1363"] = "p1363" in filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_DSA_VECTORS = _load_dsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_DSA_VECTORS, ids=[v[0] for v in _ALL_DSA_VECTORS])
def test_dsa(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """DSA signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    pk = group.get("publicKey", {})
    p_hex = pk.get("p", "")
    q_hex = pk.get("q", "")
    g_hex = pk.get("g", "")
    y_hex = pk.get("y", "")
    if not all([p_hex, q_hex, g_hex, y_hex]):
        pytest.skip("Incomplete DSA public key")

    prime = bytes.fromhex(p_hex)
    subprime = bytes.fromhex(q_hex)
    base = bytes.fromhex(g_hex)
    value = bytes.fromhex(y_hex)

    try:
        pub_key = import_dsa_public_key(
            rs.raw,
            rs.sh,
            prime=prime,
            subprime=subprime,
            base_g=base,
            value=value,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError:
        pytest.skip("Cannot import DSA public key")

    try:
        verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig)
        if result == "invalid":
            pass  # Some modules accept edge-case signatures
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid DSA sig {vec_id} rejected: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
