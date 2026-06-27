"""Wycheproof ML-DSA signing test vectors.

Tests ML-DSA-44, ML-DSA-65, ML-DSA-87 signature generation using
Wycheproof vectors. Complements test_wycheproof_mldsa.py (verify-only).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_pqc_private_key,
    sign_single,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, reject_or_classify
from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached

pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]
REQUIRED_MECHANISMS = ["ML_DSA"]


def _load(filename: str) -> list[dict[str, Any]]:
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    data = load_json_cached(path)
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

# Spec-correct CKRs for a malformed-key import rejection at C_CreateObject.
# CKR_ATTRIBUTE_VALUE_INVALID: the key value attribute is invalid (spec §5.2).
# CKR_TEMPLATE_INCOMPLETE / _INCONSISTENT: template shape errors (spec §11.7).
# CKR_KEY_SIZE_RANGE: key material is the wrong size (covers IncorrectPrivateKeyLength).
# CKR_DATA_INVALID: data is structurally invalid (some modules use this for decode failures).
# Any OTHER clean code (e.g. CKR_DEVICE_ERROR from some modules) is a recorded deviation (xfail).
_MLDSA_PRIVATE_IMPORT_REJECT_CKRS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_DATA_INVALID,
)

_MLDSA_INVALID_PRIVATE_KEY_FLAGS = frozenset(
    {
        "IncorrectPrivateKeyLength",
        "InvalidPrivateKey",
    }
)


def _has_flag(vec: dict[str, Any], flags: frozenset[str]) -> bool:
    return bool(flags.intersection(vec.get("flags", [])))


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
def test_mldsa_sign(vec_id: str, vec: dict[str, Any], p11_module_session: Any) -> None:
    """ML-DSA signing from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("ML_DSA"):
        pytest.skip("ML_DSA not supported")

    group = vec["_group"]
    private_key_hex = group.get("privateKey", "")
    if not private_key_hex:
        private_key_hex = group.get("privateKeyPkcs8", "")
    msg = bytes.fromhex(vec.get("msg", ""))
    result = vec["result"]
    private_key_bytes = bytes.fromhex(private_key_hex)

    if vec.get("ctx", ""):
        # This suite signs without transmitting the vector's context, so the
        # PKCS#11-visible operation differs from the vector: an InvalidContext
        # vector ("context too long") reaches the module as a valid empty-ctx
        # sign and "accepted" would be a false finding. Context vectors --
        # including the over-long reject -- are exercised faithfully via
        # CK_SIGN_ADDITIONAL_CONTEXT in test_wycheproof_mldsa_context.
        pytest.skip("ctx vector not transmitted here; covered by test_wycheproof_mldsa_context")

    if not private_key_bytes:
        pytest.skip("No private key in vector")

    try:
        priv = import_pqc_private_key(
            rs.raw,
            rs.sh,
            key_type=int(CKK_ML_DSA),
            value=private_key_bytes,
            parameter_set=vec["_parameter_set"],
            attrs={CKA_SIGN: True},
        )
    except CkrAssertionError as exc:
        exc_msg = str(exc)
        # A vector whose invalidity IS the private key (out-of-range s1/s2,
        # wrong length) is correctly rejected at import.  Per the classification
        # model (CLAUDE.md table): rejection with the expected spec CKR = pass;
        # rejection with SOME OTHER clean code = xfail (recorded deviation).
        # some modules reject these with CKR_DEVICE_ERROR (a crypto-layer decode
        # failure code); others instead accept the bytes and
        # sign (lenient, handled in the sign branch).  Both are honest; neither
        # is a fail.  reject_or_classify enforces the 3-way model here.
        if result == "invalid" and _has_flag(vec, _MLDSA_INVALID_PRIVATE_KEY_FLAGS):
            reject_or_classify(
                exc,
                _MLDSA_PRIVATE_IMPORT_REJECT_CKRS,
                label=f"{vec_id}: InvalidPrivateKey import reject",
            )
            return
        if is_known_error(exc, _MLDSA_PRIVATE_IMPORT_REJECT_CKRS):
            classify(
                "not_operational",
                label="ML_DSA:private-key-import",
                summary=f"ML_DSA advertised but private-key import is not operational: {exc_msg}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        raise

    try:
        sig = sign_single(rs.raw, rs.sh, priv, CKM_ML_DSA, msg)
        if result == "valid":
            assert len(sig) > 0, "Empty signature"
            # Note: ML-DSA signatures are non-deterministic, so length/non-empty
            # is the meaningful invariant for this path.
        elif _has_flag(vec, _MLDSA_INVALID_PRIVATE_KEY_FLAGS):
            # The module imported malformed key material AND produced a
            # signature: lenient key validation. No forgery and no
            # self-contradiction is provable from this alone (only the key
            # holder shape is wrong), so per the classification model it is a
            # recorded deviation, not a hard fail.
            classify(
                "honest_deviation",
                summary=(
                    f"{vec_id}: lenient private-key validation -- module accepted malformed "
                    f"ML-DSA key material (flags={vec.get('flags', [])}) and signed"
                ),
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        else:
            classify(
                "accepted_invalid",
                kind="crypto",
                summary=f"Invalid ML-DSA sign vector {vec_id} accepted by module",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    except AssertionError as exc:
        if result == "valid":
            classify(
                "not_operational",
                label=f"ML_DSA:sign:{vec_id}",
                summary=f"Valid ML-DSA sign failed {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: module rejected invalid vector
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv)
