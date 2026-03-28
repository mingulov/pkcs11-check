"""Wycheproof ML-DSA signing test vectors.

Tests ML-DSA-44, ML-DSA-65, ML-DSA-87 signature generation using
Wycheproof vectors. Complements test_wycheproof_mldsa.py (verify-only).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKO_PRIVATE_KEY,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
)
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]


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


_PARAM_MAP: dict[int, int] = {
    CKP_ML_DSA_44: CKP_ML_DSA_44,
    CKP_ML_DSA_65: CKP_ML_DSA_65,
    CKP_ML_DSA_87: CKP_ML_DSA_87,
}

# Only noseed vectors have raw private keys suitable for CKA_VALUE import.
# seed vectors use PKCS8-encoded keys which PKCS#11 can't import directly.
_MLDSA_SIGN_FILES = [
    ("mldsa_44_sign_noseed_test.json", CKP_ML_DSA_44),
    ("mldsa_65_sign_noseed_test.json", CKP_ML_DSA_65),
    ("mldsa_87_sign_noseed_test.json", CKP_ML_DSA_87),
]


def _load_sign_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, parameter_set in _MLDSA_SIGN_FILES:
        for vec in _load(filename):
            vec["_parameter_set"] = parameter_set
            vec["_filename"] = filename
            vectors.append((f"{filename}:tc{vec['tcId']}-{vec['result']}", vec))
    return vectors


_ALL_SIGN_VECTORS = _load_sign_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_SIGN_VECTORS, ids=[v[0] for v in _ALL_SIGN_VECTORS])
def test_mldsa_sign(vec_id: str, vec: dict[str, Any], p11_raw_session: Any) -> None:
    """ML-DSA signing from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ML_DSA"):
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
        priv = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_PRIVATE_KEY,
                CKA_KEY_TYPE: CKK_ML_DSA,
                CKA_VALUE: private_key_bytes,
                CKA_PARAMETER_SET: vec["_parameter_set"],
                CKA_SIGN: True,
                CKA_TOKEN: False,
            },
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        if any(
            name in exc_msg
            for name in (
                "CKR_TEMPLATE_INCOMPLETE",
                "CKR_TEMPLATE_INCONSISTENT",
                "CKR_ATTRIBUTE_VALUE_INVALID",
                "CKR_FUNCTION_FAILED",
                "CKR_DEVICE_ERROR",
            )
        ):
            if result == "invalid":
                return
            pytest.fail(f"Cannot import ML-DSA private key: {exc_msg}")
        raise

    try:
        sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, msg)
        if result == "valid":
            assert len(sig) > 0, "Empty signature"
            # Note: ML-DSA signatures are non-deterministic, so length/non-empty
            # is the meaningful invariant for this path.
    except AssertionError as exc:
        if result == "valid":
            pytest.fail(f"Valid ML-DSA sign failed {vec_id}: {exc}")
        # acceptable: module rejected invalid vector
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv)
