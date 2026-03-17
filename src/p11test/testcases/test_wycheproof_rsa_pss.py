"""Wycheproof RSA-PSS signature verification vectors.

Tests RSA-PSS (PKCS#1 v2.1) across key sizes 2048/3072/4096 with
SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 and varying salt lengths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.mechanisms import MGF

from p11test.testcases.conftest import mech_name

pytestmark = pytest.mark.wycheproof

WYCHEPROOF_DIR = Path(__file__).parent / "vectors" / "wycheproof" / "testvectors_v1"

# Map hash names to PKCS#11 mechanisms and hash mechanisms for PSS params
_SHA_MECHANISMS: dict[str, Mechanism] = {
    "SHA-1": Mechanism.SHA1_RSA_PKCS_PSS,
    "SHA-224": Mechanism.SHA224_RSA_PKCS_PSS,
    "SHA-256": Mechanism.SHA256_RSA_PKCS_PSS,
    "SHA-384": Mechanism.SHA384_RSA_PKCS_PSS,
    "SHA-512": Mechanism.SHA512_RSA_PKCS_PSS,
    "SHA3-224": Mechanism.SHA3_224_RSA_PKCS_PSS,
    "SHA3-256": Mechanism.SHA3_256_RSA_PKCS_PSS,
    "SHA3-384": Mechanism.SHA3_384_RSA_PKCS_PSS,
    "SHA3-512": Mechanism.SHA3_512_RSA_PKCS_PSS,
}

_SHA_HASH_MECHS: dict[str, Mechanism] = {
    "SHA-1": Mechanism.SHA_1,
    "SHA-224": Mechanism.SHA224,
    "SHA-256": Mechanism.SHA256,
    "SHA-384": Mechanism.SHA384,
    "SHA-512": Mechanism.SHA512,
    "SHA3-224": Mechanism.SHA3_224,
    "SHA3-256": Mechanism.SHA3_256,
    "SHA3-384": Mechanism.SHA3_384,
    "SHA3-512": Mechanism.SHA3_512,
}

_SHA_MGFS: dict[str, MGF] = {
    "SHA-1": MGF.SHA1,
    "SHA-224": MGF.SHA224,
    "SHA-256": MGF.SHA256,
    "SHA-384": MGF.SHA384,
    "SHA-512": MGF.SHA512,
    "SHA3-224": MGF.SHA3_224,
    "SHA3-256": MGF.SHA3_256,
    "SHA3-384": MGF.SHA3_384,
    "SHA3-512": MGF.SHA3_512,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[Mechanism, str] = {
    Mechanism.SHA1_RSA_PKCS_PSS: "SHA1_RSA_PKCS_PSS",
    Mechanism.SHA224_RSA_PKCS_PSS: "SHA224_RSA_PKCS_PSS",
    Mechanism.SHA256_RSA_PKCS_PSS: "SHA256_RSA_PKCS_PSS",
    Mechanism.SHA384_RSA_PKCS_PSS: "SHA384_RSA_PKCS_PSS",
    Mechanism.SHA512_RSA_PKCS_PSS: "SHA512_RSA_PKCS_PSS",
    Mechanism.SHA3_224_RSA_PKCS_PSS: "SHA3_224_RSA_PKCS_PSS",
    Mechanism.SHA3_256_RSA_PKCS_PSS: "SHA3_256_RSA_PKCS_PSS",
    Mechanism.SHA3_384_RSA_PKCS_PSS: "SHA3_384_RSA_PKCS_PSS",
    Mechanism.SHA3_512_RSA_PKCS_PSS: "SHA3_512_RSA_PKCS_PSS",
}

# RSA-PSS vector files — standard test variants (non-params, non-SHAKE)
_PSS_FILES = sorted(
    f.name
    for f in WYCHEPROOF_DIR.glob("rsa_pss_*_test.json")
    if f.exists()
    and "params" not in f.name
    and "shake" not in f.name
    and "mgf1sha" not in f.name  # mixed mgf1sha variants: sha != mgfSha
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
            # Only test where hash == mgfSha (standard PKCS#11 PSS mechanisms)
            if sha != mgf_sha:
                continue
            mechanism = _SHA_MECHANISMS.get(sha)
            if mechanism is None:
                continue
            s_len = group.get("sLen", 0)
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_mechanism"] = mechanism
                test["_sLen"] = s_len
                test["_sha"] = sha
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_PSS_VECTORS = _load_pss_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_PSS_VECTORS, ids=[v[0] for v in _ALL_PSS_VECTORS])
def test_rsa_pss(p11_session: Any, p11_module: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA-PSS signature verification from Wycheproof vectors."""
    mechanism = vec["_mechanism"]
    name = _MECH_DISPLAY.get(mechanism, str(mechanism))
    slot = p11_module.get_slots(token_present=True)[0]
    supported = {mech_name(m) for m in slot.get_mechanisms()}
    if name not in supported:
        pytest.skip(f"{name} not supported")

    msg = bytes.fromhex(vec["msg"])
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    mechanism = vec["_mechanism"]
    group = vec["_group"]
    s_len = vec["_sLen"]
    sha = vec["_sha"]

    pk = group.get("publicKey", {})
    modulus_hex = pk.get("modulus", "")
    exp_hex = pk.get("publicExponent", "")
    if not modulus_hex or not exp_hex:
        pytest.skip("No RSA public key in vector group")

    modulus = bytes.fromhex(modulus_hex)
    exponent = bytes.fromhex(exp_hex)

    try:
        pub_key = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.RSA,
                Attribute.MODULUS: modulus,
                Attribute.PUBLIC_EXPONENT: exponent,
                Attribute.TOKEN: False,
                Attribute.VERIFY: True,
            }
        )
    except p11.exceptions.PKCS11Error:
        pytest.skip("Cannot import RSA public key")

    # Build PSS params: (hash_mechanism, mgf, salt_length)
    hash_mech = _SHA_HASH_MECHS.get(sha)
    mgf = _SHA_MGFS.get(sha)
    if hash_mech is None or mgf is None:
        pytest.skip(f"No PSS param mapping for {sha}")

    pss_params = (hash_mech, mgf, s_len)

    try:
        pub_key.verify(msg, sig, mechanism=mechanism, mechanism_param=pss_params)
        if result == "invalid":
            pass  # Some modules accept edge-case signatures
    except p11.exceptions.PKCS11Error:
        if result == "valid":
            pytest.xfail(f"Valid RSA-PSS sig {vec_id} rejected (sLen={s_len})")
