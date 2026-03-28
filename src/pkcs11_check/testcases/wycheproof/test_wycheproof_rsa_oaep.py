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
    create_object,
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKG_MGF1_SHA1,
    CKG_MGF1_SHA224,
    CKG_MGF1_SHA256,
    CKG_MGF1_SHA384,
    CKG_MGF1_SHA512,
    CKK_RSA,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1,
    CKO_PRIVATE_KEY,
)

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

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

    try:
        priv_key = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_RSA,
                CKA_MODULUS: modulus,
                CKA_PUBLIC_EXPONENT: pub_exponent,
                CKA_PRIVATE_EXPONENT: priv_exponent,
                CKA_PRIME_1: prime1,
                CKA_PRIME_2: prime2,
                CKA_EXPONENT_1: exp1,
                CKA_EXPONENT_2: exp2,
                CKA_COEFFICIENT: coefficient,
                CKA_TOKEN: False,
                CKA_DECRYPT: True,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        pytest.skip("Cannot import RSA private key for OAEP")

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
    except AssertionError:
        if result == "valid":
            pytest.fail(f"Valid RSA-OAEP ciphertext {vec_id} failed to decrypt")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
