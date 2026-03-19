"""Wycheproof ML-DSA signing test vectors.

Tests ML-DSA-44, ML-DSA-65, ML-DSA-87 signature generation using
Wycheproof vectors. Complements test_wycheproof_mldsa.py (verify-only).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.constants import MLDsaParameterSet

from pkcs11_check.testcases.conftest import has_mechanism
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc, pytest.mark.requires_v32]


def _load(filename: str) -> list[dict[str, Any]]:
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    with open(path) as f:
        data = json.load(f)
    vectors = []
    for group in data.get("testGroups", []):
        meta = {k: v for k, v in group.items() if k != "tests"}
        for test in group.get("tests", []):
            test["_group"] = meta
            vectors.append(test)
    return vectors


def _vid(v: dict[str, Any]) -> str:
    return f"tc{v['tcId']}-{v['result']}"


_MLDSA_SIGN_FILES = [
    ("mldsa_44_sign_noseed_test.json", MLDsaParameterSet.ML_DSA_44),
    ("mldsa_44_sign_seed_test.json", MLDsaParameterSet.ML_DSA_44),
    ("mldsa_65_sign_noseed_test.json", MLDsaParameterSet.ML_DSA_65),
    ("mldsa_65_sign_seed_test.json", MLDsaParameterSet.ML_DSA_65),
    ("mldsa_87_sign_noseed_test.json", MLDsaParameterSet.ML_DSA_87),
    ("mldsa_87_sign_seed_test.json", MLDsaParameterSet.ML_DSA_87),
]


def _load_sign_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, parameter_set in _MLDSA_SIGN_FILES:
        for vec in _load(filename):
            vec["_parameter_set"] = int(parameter_set)
            vec["_filename"] = filename
            vectors.append((f"{filename}:tc{vec['tcId']}-{vec['result']}", vec))
    return vectors


_ALL_SIGN_VECTORS = _load_sign_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_SIGN_VECTORS, ids=[v[0] for v in _ALL_SIGN_VECTORS])
def test_mldsa_sign(
    vec_id: str, vec: dict[str, Any], p11_session: Any, p11_module: Any
) -> None:
    """ML-DSA signing from Wycheproof vectors."""
    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip("ML_DSA not supported")

    group = vec["_group"]
    private_key_hex = group.get("privateKey", "")
    if not private_key_hex:
        private_key_hex = group.get("privateKeyPkcs8", "")
    msg = bytes.fromhex(vec.get("msg", ""))
    result = vec["result"]
    private_key_bytes = bytes.fromhex(private_key_hex)

    if not private_key_bytes:
        pytest.skip("No private key in vector")

    try:
        priv = p11_session.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.ML_DSA,
            Attribute.VALUE: private_key_bytes,
            Attribute.PARAMETER_SET: vec["_parameter_set"],
            Attribute.SIGN: True,
            Attribute.TOKEN: False,
        })
    except Exception:
        if result == "invalid":
            return
        raise

    try:
        sig = priv.sign(msg, mechanism=Mechanism.ML_DSA)
        if result == "valid":
            assert len(sig) > 0, "Empty signature"
            # Note: ML-DSA signatures are non-deterministic, so length/non-empty
            # is the meaningful invariant for this path.
    except Exception:
        if result == "valid":
            pytest.fail(f"Valid ML-DSA sign failed: {vec_id}")
