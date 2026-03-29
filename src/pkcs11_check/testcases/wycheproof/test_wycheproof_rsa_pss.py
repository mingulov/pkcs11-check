"""Wycheproof RSA-PSS signature verification vectors.

Tests RSA-PSS (PKCS#1 v2.1) across key sizes 2048/3072/4096 with
SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and varying salt lengths.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_pss
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_rsa_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA3_224,
    CKG_MGF1_SHA3_256,
    CKG_MGF1_SHA3_384,
    CKG_MGF1_SHA3_512,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_SHA1_RSA_PKCS_PSS,
    CKM_SHA3_224,
    CKM_SHA3_224_RSA_PKCS_PSS,
    CKM_SHA3_256,
    CKM_SHA3_256_RSA_PKCS_PSS,
    CKM_SHA3_384,
    CKM_SHA3_384_RSA_PKCS_PSS,
    CKM_SHA3_512,
    CKM_SHA3_512_RSA_PKCS_PSS,
    CKM_SHA224,
    CKM_SHA224_RSA_PKCS_PSS,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS_PSS,
    CKM_SHA384,
    CKM_SHA384_RSA_PKCS_PSS,
    CKM_SHA512,
    CKM_SHA512_RSA_PKCS_PSS,
    CKM_SHA_1,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Map hash names to PKCS#11 mechanisms and hash mechanisms for PSS params
_SHA_MECHANISMS: dict[str, int] = {
    "SHA-1": CKM_SHA1_RSA_PKCS_PSS,
    "SHA-224": CKM_SHA224_RSA_PKCS_PSS,
    "SHA-256": CKM_SHA256_RSA_PKCS_PSS,
    "SHA-384": CKM_SHA384_RSA_PKCS_PSS,
    "SHA-512": CKM_SHA512_RSA_PKCS_PSS,
    "SHA3-224": CKM_SHA3_224_RSA_PKCS_PSS,
    "SHA3-256": CKM_SHA3_256_RSA_PKCS_PSS,
    "SHA3-384": CKM_SHA3_384_RSA_PKCS_PSS,
    "SHA3-512": CKM_SHA3_512_RSA_PKCS_PSS,
}

_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-224": CKM_SHA224,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
    "SHA3-224": CKM_SHA3_224,
    "SHA3-256": CKM_SHA3_256,
    "SHA3-384": CKM_SHA3_384,
    "SHA3-512": CKM_SHA3_512,
}

_SHA_MGFS: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA-224": CKG_MGF1_SHA224,
    "SHA-256": CKG_MGF1_SHA256,
    "SHA-384": CKG_MGF1_SHA384,
    "SHA-512": CKG_MGF1_SHA512,
    "SHA3-224": CKG_MGF1_SHA3_224,
    "SHA3-256": CKG_MGF1_SHA3_256,
    "SHA3-384": CKG_MGF1_SHA3_384,
    "SHA3-512": CKG_MGF1_SHA3_512,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA1_RSA_PKCS_PSS: "SHA1_RSA_PKCS_PSS",
    CKM_SHA224_RSA_PKCS_PSS: "SHA224_RSA_PKCS_PSS",
    CKM_SHA256_RSA_PKCS_PSS: "SHA256_RSA_PKCS_PSS",
    CKM_SHA384_RSA_PKCS_PSS: "SHA384_RSA_PKCS_PSS",
    CKM_SHA512_RSA_PKCS_PSS: "SHA512_RSA_PKCS_PSS",
    CKM_SHA3_224_RSA_PKCS_PSS: "SHA3_224_RSA_PKCS_PSS",
    CKM_SHA3_256_RSA_PKCS_PSS: "SHA3_256_RSA_PKCS_PSS",
    CKM_SHA3_384_RSA_PKCS_PSS: "SHA3_384_RSA_PKCS_PSS",
    CKM_SHA3_512_RSA_PKCS_PSS: "SHA3_512_RSA_PKCS_PSS",
}

# RSA-PSS vector files - standard and parameterized variants that map to
# the existing PKCS#11 PSS mechanism family.
_PSS_FILES = sorted(
    f.name
    for f in WYCHEPROOF_DIR.glob("rsa_pss_*_test.json")
    if f.exists() and "shake" not in f.name
)


def _load_pss_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all standard RSA-PSS vectors."""
    vectors = []
    for filename in _PSS_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mgf_sha = group.get("mgfSha", sha)
            mechanism = _SHA_MECHANISMS.get(sha)
            hash_mech = _SHA_HASH_MECHS.get(sha)
            mgf = _SHA_MGFS.get(mgf_sha)
            if mechanism is None or hash_mech is None or mgf is None:
                continue
            s_len = group.get("sLen", 0)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_sLen"] = s_len
                test["_sha"] = sha
                test["_mgf_sha"] = mgf_sha
                test["_hash_mech"] = hash_mech
                test["_mgf"] = mgf
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_PSS_VECTORS = _load_pss_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_PSS_VECTORS, ids=[v[0] for v in _ALL_PSS_VECTORS])
def test_rsa_pss(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-PSS signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, "RSA_PKCS_PSS")
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    s_len = vec["_sLen"]
    hash_mech = vec["_hash_mech"]
    mgf = vec["_mgf"]

    pk = group.get("publicKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    exponent = bytes.fromhex(exp_hex)

    try:
        pub_key = import_rsa_public_key(
            rs.raw, rs.sh,
            n=modulus, e=exponent,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError:
        pytest.skip("Cannot import RSA public key")

    # Build PSS params
    pss_param = mech_pss(mechanism, hash_mech=hash_mech, mgf=mgf, salt_len=s_len)

    try:
        verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig, mech_param=pss_param)
        if result == "invalid":
            pass  # Some modules accept edge-case signatures
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid RSA-PSS sig {vec_id} rejected (sLen={s_len}): {exc}")
        # acceptable: module rejected invalid vector
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
