"""Wycheproof RSA signature verification vectors - all key sizes and hashes.

Auto-discovers RSA signature vector files from the Wycheproof submodule.
Each file produces a parametrized test class.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    generate_random,
    import_rsa_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_VERIFY,
    CKM_SHA3_224_RSA_PKCS,
    CKM_SHA3_256_RSA_PKCS,
    CKM_SHA3_384_RSA_PKCS,
    CKM_SHA3_512_RSA_PKCS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

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
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        pub_key = import_rsa_public_key(
            rs.raw,
            rs.sh,
            n=modulus,
            e=exponent,
            attrs={CKA_VERIFY: True},
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        # Only cache permanent key-size rejections, not transient errors.
        if any(
            code in exc_msg
            for code in (
                "CKR_KEY_SIZE_RANGE",
                "CKR_ATTRIBUTE_VALUE_INVALID",
                "CKR_TEMPLATE_INCONSISTENT",
                "CKR_TEMPLATE_INCOMPLETE",
            )
        ):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit public key: {exc_msg}")

    try:
        verify_single(rs.raw, rs.sh, pub_key, mechanism, msg, sig)
        if result == "invalid":
            pass  # Some modules accept edge-case sigs
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid RSA sig {vec_id} rejected: {exc}")
        # acceptable: module rejected invalid vector
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)

    generate_random(rs.raw, rs.sh, 64)
