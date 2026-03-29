"""Wycheproof RSA-OAEP decryption vectors.

Tests RSA-OAEP across key sizes 2048/3072/4096 with various hash
and MGF combinations. Imports RSA private key, decrypts ciphertext,
compares against expected plaintext.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_oaep
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    import_rsa_private_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

# Map Wycheproof sha names to PKCS#11 hash mechanisms and MGFs for OAEP params
_SHA_HASH_MECHS: dict[str, int] = {
    "SHA-1": CKM_SHA_1,
    "SHA-224": CKM_SHA224,
    "SHA-256": CKM_SHA256,
    "SHA-384": CKM_SHA384,
    "SHA-512": CKM_SHA512,
}

_SHA_MGFS: dict[str, int] = {
    "SHA-1": CKG_MGF1_SHA1,
    "SHA-224": CKG_MGF1_SHA224,
    "SHA-256": CKG_MGF1_SHA256,
    "SHA-384": CKG_MGF1_SHA384,
    "SHA-512": CKG_MGF1_SHA512,
}

# RSA-OAEP files - same hash and mixed hash/MGF combinations
_OAEP_FILES = [
    # Same hash/MGF
    "rsa_oaep_2048_sha1_mgf1sha1_test.json",
    "rsa_oaep_2048_sha224_mgf1sha224_test.json",
    "rsa_oaep_2048_sha256_mgf1sha256_test.json",
    "rsa_oaep_2048_sha384_mgf1sha384_test.json",
    "rsa_oaep_2048_sha512_mgf1sha512_test.json",
    "rsa_oaep_3072_sha256_mgf1sha256_test.json",
    "rsa_oaep_3072_sha512_mgf1sha512_test.json",
    "rsa_oaep_4096_sha256_mgf1sha256_test.json",
    "rsa_oaep_4096_sha512_mgf1sha512_test.json",
    # Mixed hash/MGF (hash != mgfSha)
    "rsa_oaep_2048_sha224_mgf1sha1_test.json",
    "rsa_oaep_2048_sha256_mgf1sha1_test.json",
    "rsa_oaep_2048_sha384_mgf1sha1_test.json",
    "rsa_oaep_2048_sha512_mgf1sha1_test.json",
    "rsa_oaep_3072_sha256_mgf1sha1_test.json",
    "rsa_oaep_3072_sha512_mgf1sha1_test.json",
    "rsa_oaep_4096_sha256_mgf1sha1_test.json",
    "rsa_oaep_4096_sha512_mgf1sha1_test.json",
    "rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json",
    "rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json",
    "rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json",
    # Misc - various parameter combinations in one file
    "rsa_oaep_misc_test.json",
]


def _load_oaep_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-OAEP vectors - decryption tests with private key."""
    vectors = []
    for filename in _OAEP_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "SHA-1")
            mgf_sha = group.get("mgfSha", sha)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_file"] = filename
                test["_sha"] = sha
                test["_mgfSha"] = mgf_sha
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_OAEP_VECTORS = _load_oaep_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_OAEP_VECTORS, ids=[v[0] for v in _ALL_OAEP_VECTORS])
def test_rsa_oaep(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-OAEP decryption from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("RSA_PKCS_OAEP"):
        pytest.skip("RSA_PKCS_OAEP not supported")

    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]
    sha = vec["_sha"]
    mgf_sha = vec["_mgfSha"]
    label = bytes.fromhex(vec.get("label", ""))

    # Build OAEP params
    hash_mech = _SHA_HASH_MECHS.get(sha)
    mgf = _SHA_MGFS.get(mgf_sha)
    if hash_mech is None or mgf is None:
        pytest.skip(f"No OAEP param mapping for sha={sha} mgfSha={mgf_sha}")

    oaep_param = mech_oaep(
        CKM_RSA_PKCS_OAEP,
        hash_mech=hash_mech,
        mgf=mgf,
        source_data=label if label else None,
    )

    pk = group.get("privateKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    priv_exp_hex = pk.get("privateExponent", "")
    if not modulus_hex or not priv_exp_hex:
        pytest.skip("No RSA private key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    pub_exponent = bytes.fromhex(exp_hex)
    priv_exponent = bytes.fromhex(priv_exp_hex)
    prime1 = bytes.fromhex(pk.get("prime1", ""))
    prime2 = bytes.fromhex(pk.get("prime2", ""))
    exp1 = bytes.fromhex(pk.get("exponent1", ""))
    exp2 = bytes.fromhex(pk.get("exponent2", ""))
    coefficient = bytes.fromhex(pk.get("coefficient", ""))
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        priv_key = import_rsa_private_key(
            rs.raw, rs.sh,
            n=modulus, e=pub_exponent, d=priv_exponent,
            p=prime1, q=prime2,
            dmp1=exp1, dmq1=exp2, iqmp=coefficient,
            attrs={CKA_DECRYPT: True},
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        # Only cache permanent key-size rejections, not transient errors.
        if any(code in exc_msg for code in (
            "CKR_KEY_SIZE_RANGE", "CKR_ATTRIBUTE_VALUE_INVALID",
            "CKR_TEMPLATE_INCONSISTENT", "CKR_TEMPLATE_INCOMPLETE",
        )):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit private key for OAEP: {exc_msg}")

    plaintext = None
    try:
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            priv_key,
            CKM_RSA_PKCS_OAEP,
            ct,
            mech_param=oaep_param,
        )
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid RSA-OAEP ciphertext {vec_id} failed to decrypt: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
