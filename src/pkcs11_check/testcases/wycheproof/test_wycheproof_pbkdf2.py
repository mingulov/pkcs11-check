"""Wycheproof PBKDF2 key derivation vectors.

Tests PKCS#5 PBKDF2 (RFC 8018) with HMAC-SHA1/224/256/384/512.
Uses CKM_PKCS5_PBKD2 mechanism with CK_PKCS5_PBKD2_PARAMS2.
Skips on modules without PBKDF2 support (e.g., SoftHSM2).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import (
    PackedMechanism,
    mech_pbkdf2,
    template_from_dict,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA1,
    CKP_PKCS5_PBKD2_HMAC_SHA224,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKP_PKCS5_PBKD2_HMAC_SHA384,
    CKP_PKCS5_PBKD2_HMAC_SHA512,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import assert_correct, reject_or_classify, xfail_if_known_ckr

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["PKCS5_PBKD2"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

_PBKDF2_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
_PBKDF2_INVALID_PRF_REJECT_CKRS = (CKR_MECHANISM_PARAM_INVALID,)

# Map Wycheproof file suffix to CKP_PKCS5_PBKD2_HMAC_* PRF constant
_PRF_MAP: dict[str, int] = {
    "hmacsha1": CKP_PKCS5_PBKD2_HMAC_SHA1,
    "hmacsha224": CKP_PKCS5_PBKD2_HMAC_SHA224,
    "hmacsha256": CKP_PKCS5_PBKD2_HMAC_SHA256,
    "hmacsha384": CKP_PKCS5_PBKD2_HMAC_SHA384,
    "hmacsha512": CKP_PKCS5_PBKD2_HMAC_SHA512,
}

_PBKDF2_FILES = [
    ("pbkdf2_hmacsha1_test.json", "hmacsha1"),
    ("pbkdf2_hmacsha224_test.json", "hmacsha224"),
    ("pbkdf2_hmacsha256_test.json", "hmacsha256"),
    ("pbkdf2_hmacsha384_test.json", "hmacsha384"),
    ("pbkdf2_hmacsha512_test.json", "hmacsha512"),
]


def _load_pbkdf2_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load PBKDF2 vectors with PRF info."""
    vectors = []
    for filename, prf_name in _PBKDF2_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        prf = _PRF_MAP.get(prf_name)
        if prf is None:
            continue
        data = load_json_cached(path)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_prf"] = prf
                test["_prf_name"] = prf_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_PBKDF2_VECTORS = _load_pbkdf2_vectors()


def _generate_key_with_mech(
    raw: Any, session: int, mech: PackedMechanism, attrs: dict[int, Any]
) -> int:
    """C_GenerateKey with a custom mechanism (for PBKDF2)."""
    tmpl = template_from_dict(attrs)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(session, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def _xfail_if_pbkdf2_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised PBKDF2 valid-vector rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _PBKDF2_RUNTIME_REJECT_CKRS,
        f"{label}: advertised PBKDF2 key derivation is not operational",
    )
    raise exc


def test_pbkdf2_rejects_invalid_prf(p11_module_session: Any) -> None:
    """CKM_PKCS5_PBKD2 rejects a PRF selector outside the CKP_* table."""
    rs = p11_module_session
    if not rs.has_mechanism("PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")

    pbkdf2_param = mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=b"pbkcs11-check salt",
        iterations=2,
        prf=0,
        password=b"pkcs11-check password",
    )
    derived = 0
    exc: AssertionError | None = None
    try:
        try:
            derived = _generate_key_with_mech(
                rs.raw,
                rs.sh,
                pbkdf2_param,
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_VALUE_LEN: 32,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as caught:
            exc = caught
        reject_or_classify(
            exc,
            _PBKDF2_INVALID_PRF_REJECT_CKRS,
            label="PKCS5_PBKD2 invalid PRF selector",
        )
    finally:
        if derived:
            destroy_quietly(rs.raw, rs.sh, derived)


@pytest.mark.parametrize("vec_id,vec", _ALL_PBKDF2_VECTORS, ids=[v[0] for v in _ALL_PBKDF2_VECTORS])
def test_pbkdf2(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """PBKDF2 key derivation from Wycheproof vectors.

    Derives a key using CKM_PKCS5_PBKD2 and compares the extracted
    key material against the expected derived key (dk).
    """
    rs = p11_module_session
    if not rs.has_mechanism("PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")

    password = bytes.fromhex(vec["password"])
    salt = bytes.fromhex(vec["salt"])
    iterations = vec["iterationCount"]
    dk_len = vec["dkLen"]  # bytes
    dk_expected = bytes.fromhex(vec["dk"])
    result = vec["result"]
    prf = vec["_prf"]

    # Build PBKDF2 mechanism params
    pbkdf2_param = mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=salt,
        iterations=iterations,
        prf=prf,
        password=password,
    )

    try:
        derived = _generate_key_with_mech(
            rs.raw,
            rs.sh,
            pbkdf2_param,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: dk_len,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
        )
        attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
        dk_actual = attrs[CKA_VALUE]
        assert isinstance(dk_actual, bytes)
        destroy_quietly(rs.raw, rs.sh, derived)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_pbkdf2_runtime_reject(exc, vec_id)
        # acceptable: reject is fine
        return

    if result == "valid":
        assert_correct(
            actual=dk_actual,
            expected=dk_expected,
            label=f"PBKDF2:C_DeriveKey KAT {vec_id}",
            operation="C_DeriveKey",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
