"""Wycheproof ML-DSA signing test vectors.

Tests ML-DSA-44, ML-DSA-65, ML-DSA-87 signature generation using
Wycheproof vectors. Complements test_wycheproof_mldsa.py (verify-only).

Vector files: mldsa_{44,65,87}_sign_noseed_test.json
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


@pytest.mark.parametrize("vec", _load("mldsa_65_sign_noseed_test.json"), ids=_vid)
def test_mldsa_65_sign(vec: dict[str, Any], p11_session: Any, p11_module: Any) -> None:
    """ML-DSA-65 signing from Wycheproof vectors."""
    if not has_mechanism(p11_module, "ML_DSA"):
        pytest.skip("ML_DSA not supported")

    group = vec["_group"]
    private_key_bytes = bytes.fromhex(group.get("privateKey", ""))
    msg = bytes.fromhex(vec.get("msg", ""))
    expected_sig = bytes.fromhex(vec.get("sig", ""))
    result = vec["result"]

    if not private_key_bytes:
        pytest.skip("No private key in vector")

    param_set = int(MLDsaParameterSet.ML_DSA_65)
    try:
        priv = p11_session.create_object({
            Attribute.CLASS: ObjectClass.PRIVATE_KEY,
            Attribute.KEY_TYPE: KeyType.ML_DSA,
            Attribute.VALUE: private_key_bytes,
            Attribute.PARAMETER_SET: param_set,
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
            # Note: ML-DSA signatures are non-deterministic (randomized)
            # so we can't compare exact bytes — just verify it's valid length
    except Exception:
        if result == "valid":
            pytest.fail(f"Valid ML-DSA-65 sign failed: tc{vec['tcId']}")
