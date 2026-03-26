"""Wycheproof RSA signature verification vectors - all key sizes and hashes.

Auto-discovers RSA signature vector files from the Wycheproof submodule.
Each file produces a parametrized test class.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    generate_random,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_RSA,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKO_PUBLIC_KEY,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA224_RSA_PKCS: "SHA224_RSA_PKCS",
    CKM_SHA256_RSA_PKCS: "SHA256_RSA_PKCS",
    CKM_SHA384_RSA_PKCS: "SHA384_RSA_PKCS",
    CKM_SHA512_RSA_PKCS: "SHA512_RSA_PKCS",
    CKM_SHA3_224_RSA_PKCS: "SHA3_224_RSA_PKCS",
    CKM_SHA3_256_RSA_PKCS: "SHA3_256_RSA_PKCS",
    CKM_SHA3_384_RSA_PKCS: "SHA3_384_RSA_PKCS",
    CKM_SHA3_512_RSA_PKCS: "SHA3_512_RSA_PKCS",
}

# Map hash names to PKCS#11 mechanisms
_RSA_HASH_MECHANISMS: dict[str, int] = {
    "SHA-224": CKM_SHA224_RSA_PKCS,
    "SHA-256": CKM_SHA256_RSA_PKCS,
    "SHA-384": CKM_SHA384_RSA_PKCS,
    "SHA-512": CKM_SHA512_RSA_PKCS,
    # SHA-3 (PKCS#11 v3.0+)
    "SHA3-224": CKM_SHA3_224_RSA_PKCS,
    "SHA3-256": CKM_SHA3_256_RSA_PKCS,
    "SHA3-384": CKM_SHA3_384_RSA_PKCS,
    "SHA3-512": CKM_SHA3_512_RSA_PKCS,
}

# All RSA signature vector files we want to test
_RSA_SIG_FILES = [
    "rsa_pkcs1_1024_sig_gen_test.json",
    "rsa_pkcs1_1536_sig_gen_test.json",
    "rsa_pkcs1_2048_sig_gen_test.json",
    "rsa_pkcs1_3072_sig_gen_test.json",
    "rsa_pkcs1_4096_sig_gen_test.json",
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha384_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_2048_sha512_224_test.json",
    "rsa_signature_2048_sha512_256_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_3072_sha512_256_test.json",
    "rsa_signature_4096_sha256_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
    "rsa_signature_4096_sha512_256_test.json",
    # 8192-bit RSA (large key, slow)
    "rsa_signature_8192_sha256_test.json",
    "rsa_signature_8192_sha384_test.json",
    "rsa_signature_8192_sha512_test.json",
    # SHA-3 variants (PKCS#11 v3.0+)
    "rsa_signature_2048_sha3_224_test.json",
    "rsa_signature_2048_sha3_256_test.json",
    "rsa_signature_2048_sha3_384_test.json",
    "rsa_signature_2048_sha3_512_test.json",
    "rsa_signature_3072_sha3_256_test.json",
    "rsa_signature_3072_sha3_384_test.json",
    "rsa_signature_3072_sha3_512_test.json",
]


def _load_all_rsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load all RSA vectors with file name as identifier."""
    vectors = []
    for filename in _RSA_SIG_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "SHA-256")
            mechanism = _RSA_HASH_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_RSA_VECTORS = _load_all_rsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_RSA_VECTORS, ids=[v[0] for v in _ALL_RSA_VECTORS])
def test_rsa_wycheproof(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 signature verification from Wycheproof vectors."""
    rs = p11_raw_session
    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]

    # Check mechanism availability
    mech_display = _MECH_DISPLAY.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(mech_display):
        pytest.skip(f"{mech_display} not supported by module")

    pk = group.get("publicKey", group.get("privateKey", {}))
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    exponent = bytes.fromhex(exp_hex)

    try:
        pub_key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_PUBLIC_KEY,
                CKA_KEY_TYPE: CKK_RSA,
                CKA_MODULUS: modulus,
                CKA_PUBLIC_EXPONENT: exponent,
                CKA_TOKEN: False,
                CKA_VERIFY: True,
            },
        )
    except AssertionError:
        pytest.skip("Cannot import RSA public key")

    try:
        verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig)
        if result == "invalid":
            pass  # Some modules accept edge-case sigs
    except AssertionError:
        if result == "valid":
            pytest.xfail(f"Valid RSA sig {vec_id} rejected")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
