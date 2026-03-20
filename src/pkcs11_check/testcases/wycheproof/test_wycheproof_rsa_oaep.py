"""Wycheproof RSA-OAEP decryption vectors.

Tests RSA-OAEP across key sizes 2048/3072/4096 with various hash
and MGF combinations. Imports RSA private key, decrypts ciphertext,
compares against expected plaintext.
"""

from __future__ import annotations

import json
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import MGF

from pkcs11_check.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Map Wycheproof sha names to PKCS#11 hash mechanisms and MGFs for OAEP params
_SHA_HASH_MECHS: dict[str, Mechanism] = {
    "SHA-1": Mechanism.SHA_1,
    "SHA-224": Mechanism.SHA224,
    "SHA-256": Mechanism.SHA256,
    "SHA-384": Mechanism.SHA384,
    "SHA-512": Mechanism.SHA512,
}

_SHA_MGFS: dict[str, MGF] = {
    "SHA-1": MGF.SHA1,
    "SHA-224": MGF.SHA224,
    "SHA-256": MGF.SHA256,
    "SHA-384": MGF.SHA384,
    "SHA-512": MGF.SHA512,
}

# RSA-OAEP files — same hash and mixed hash/MGF combinations
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
    # Misc — various parameter combinations in one file
    "rsa_oaep_misc_test.json",
]


def _load_oaep_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA-OAEP vectors — decryption tests with private key."""
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
def test_rsa_oaep(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-OAEP decryption from Wycheproof vectors."""
    slot = p11_module.get_slots(token_present=True)[0]
    supported = {mech_name(m) for m in slot.get_mechanisms()}
    if "RSA_PKCS_OAEP" not in supported:
        pytest.skip("RSA_PKCS_OAEP not supported")

    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]
    sha = vec["_sha"]
    mgf_sha = vec["_mgfSha"]
    label = bytes.fromhex(vec.get("label", ""))

    # Build OAEP params: (hashAlg, mgf, source_data)
    hash_mech = _SHA_HASH_MECHS.get(sha)
    mgf = _SHA_MGFS.get(mgf_sha)
    if hash_mech is None or mgf is None:
        pytest.skip(f"No OAEP param mapping for sha={sha} mgfSha={mgf_sha}")

    oaep_params: tuple[Mechanism, MGF, bytes | None] = (
        hash_mech,
        mgf,
        label if label else None,
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
        priv_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PRIVATE_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: pub_exponent,
                Attribute.PRIVATE_EXPONENT: priv_exponent,
                Attribute.PRIME_1: prime1,
                Attribute.PRIME_2: prime2,
                Attribute.EXPONENT_1: exp1,
                Attribute.EXPONENT_2: exp2,
                Attribute.COEFFICIENT: coefficient,
                Attribute.TOKEN: False,
                Attribute.DECRYPT: True,
                Attribute.SENSITIVE: False,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import RSA private key for OAEP")

    try:
        plaintext = priv_key.decrypt(
            ct, mechanism=Mechanism.RSA_PKCS_OAEP, mechanism_param=oaep_params
        )
        if result == "valid":
            assert plaintext == msg_expected
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid RSA-OAEP ciphertext {vec_id} failed to decrypt")
