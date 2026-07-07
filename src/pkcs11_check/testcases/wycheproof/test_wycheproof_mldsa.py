"""Wycheproof ML-DSA signature verification vectors.

Tests ML-DSA-44/65/87 (FIPS 204) signature verification.
Requires PKCS#11 v3.2 with ML-DSA support.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, set_params
from pkcs11_check.raw.pack_mechanisms import mech_sign_context
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    import_pqc_public_key,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_ML_DSA,
    CKM_ML_DSA,
    CKO_PUBLIC_KEY,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._signature_policy import signature_rejected_or_xfail
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = [pytest.mark.wycheproof, pytest.mark.pqc]
REQUIRED_MECHANISMS = ["ML_DSA"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

_MLDSA_FILES = [
    ("mldsa_44_verify_test.json", 44),
    ("mldsa_65_verify_test.json", 65),
    ("mldsa_87_verify_test.json", 87),
]

_PARAM_MAP: dict[int, int] = {
    44: CKP_ML_DSA_44,
    65: CKP_ML_DSA_65,
    87: CKP_ML_DSA_87,
}

_MLDSA_PUBLIC_IMPORT_REJECT_CKRS = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_VALUE_INVALID,
)

_MLDSA_INVALID_PUBLIC_KEY_FLAGS = frozenset(
    {
        "IncorrectPublicKeyLength",
        "ZeroPublicKey",
    }
)


def _has_flag(vec: dict[str, Any], flags: frozenset[str]) -> bool:
    return bool(flags.intersection(vec.get("flags", [])))


def _load_mldsa_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ML-DSA verify vectors."""
    vectors = []
    for filename, param_set in _MLDSA_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_param_set"] = param_set
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_MLDSA_VECTORS = _load_mldsa_vectors()


@pytest.mark.parametrize("vec_id,vec", _ALL_MLDSA_VECTORS, ids=[v[0] for v in _ALL_MLDSA_VECTORS])
def test_mldsa_verify(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ML-DSA signature verification from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("ML_DSA"):
        pytest.skip("ML_DSA not supported")

    group = vec["_group"]
    pk_hex = group.get("publicKey", "")
    msg = bytes.fromhex(vec["msg"])
    ctx = bytes.fromhex(vec.get("ctx", ""))
    sig = bytes.fromhex(vec["sig"])
    result = vec["result"]
    set_params({"mldsa": str(vec.get("_param_set", ""))})

    if not pk_hex:
        pytest.skip("No public key in vector")

    pk_bytes = bytes.fromhex(pk_hex)

    param_set = _PARAM_MAP.get(vec["_param_set"])

    try:
        if param_set is not None:
            pub_key = import_pqc_public_key(
                rs.raw,
                rs.sh,
                key_type=int(CKK_ML_DSA),
                value=pk_bytes,
                parameter_set=param_set,
                attrs={CKA_VERIFY: True},
            )
        else:
            pub_key = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_ML_DSA,
                    CKA_VALUE: pk_bytes,
                    CKA_TOKEN: False,
                    CKA_VERIFY: True,
                },
            )
    except AssertionError as exc:
        exc_msg = str(exc)
        if is_known_error(exc, _MLDSA_PUBLIC_IMPORT_REJECT_CKRS):
            if result == "invalid" and _has_flag(vec, _MLDSA_INVALID_PUBLIC_KEY_FLAGS):
                return  # Module correctly rejected invalid key - pass
            classify(
                "not_operational",
                label="ML_DSA:key-import",
                summary=f"ML_DSA advertised but public-key import is not operational: {exc_msg}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        raise

    try:
        mech_param = mech_sign_context(CKM_ML_DSA, context=ctx) if ctx else None
        verified = verify_single(
            rs.raw,
            rs.sh,
            pub_key,
            CKM_ML_DSA,
            msg,
            sig,
            mech_param=mech_param,
        )
        if result == "invalid":
            if verified:
                classify(
                    "accepted_invalid",
                    kind="crypto",
                    summary=f"Invalid ML-DSA sig {vec_id} accepted by module",
                    source=vec.get("_source"),
                    vector_id=vec.get("_vector_id"),
                )
            return
        if result == "valid" and not verified:
            classify(
                "wrong_result",
                kind="crypto",
                summary=f"Valid ML-DSA sig {vec_id} rejected by module",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
    except AssertionError as exc:
        if result == "valid":
            classify(
                "not_operational",
                label=f"ML_DSA:{vec_id}",
                summary=f"Valid ML-DSA sig {vec_id} rejected: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        signature_rejected_or_xfail(exc, vec_id)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, pub_key)
