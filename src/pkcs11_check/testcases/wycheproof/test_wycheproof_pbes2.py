"""Wycheproof PBES2 vectors.

Tests password-based encryption using PKCS#5 PBKDF2 plus AES-CBC-PAD.
This is more useful for real PKCS#11 modules than PBKDF2 alone because it
exercises the derived-key handoff into an actual decrypt operation.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import (
    PackedMechanism,
    mech_bytes,
    mech_pbkdf2,
    template_from_dict,
)
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_PKCS5_PBKD2,
    CKO_SECRET_KEY,
    CKP_PKCS5_PBKD2_HMAC_SHA1,
    CKP_PKCS5_PBKD2_HMAC_SHA224,
    CKP_PKCS5_PBKD2_HMAC_SHA256,
    CKP_PKCS5_PBKD2_HMAC_SHA384,
    CKP_PKCS5_PBKD2_HMAC_SHA512,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
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
from pkcs11_check.testcases.conftest import assert_correct, xfail_if_known_ckr
from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["PKCS5_PBKD2"]

_PBES2_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
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

_PRF_MAP: dict[str, int] = {
    "hmacsha1": CKP_PKCS5_PBKD2_HMAC_SHA1,
    "hmacsha224": CKP_PKCS5_PBKD2_HMAC_SHA224,
    "hmacsha256": CKP_PKCS5_PBKD2_HMAC_SHA256,
    "hmacsha384": CKP_PKCS5_PBKD2_HMAC_SHA384,
    "hmacsha512": CKP_PKCS5_PBKD2_HMAC_SHA512,
}

_PBES2_FILES = [
    ("pbes2_hmacsha1_aes_128_test.json", "hmacsha1", 128),
    ("pbes2_hmacsha1_aes_192_test.json", "hmacsha1", 192),
    ("pbes2_hmacsha1_aes_256_test.json", "hmacsha1", 256),
    ("pbes2_hmacsha224_aes_128_test.json", "hmacsha224", 128),
    ("pbes2_hmacsha224_aes_192_test.json", "hmacsha224", 192),
    ("pbes2_hmacsha224_aes_256_test.json", "hmacsha224", 256),
    ("pbes2_hmacsha256_aes_128_test.json", "hmacsha256", 128),
    ("pbes2_hmacsha256_aes_192_test.json", "hmacsha256", 192),
    ("pbes2_hmacsha256_aes_256_test.json", "hmacsha256", 256),
    ("pbes2_hmacsha384_aes_128_test.json", "hmacsha384", 128),
    ("pbes2_hmacsha384_aes_192_test.json", "hmacsha384", 192),
    ("pbes2_hmacsha384_aes_256_test.json", "hmacsha384", 256),
    ("pbes2_hmacsha512_aes_128_test.json", "hmacsha512", 128),
    ("pbes2_hmacsha512_aes_192_test.json", "hmacsha512", 192),
    ("pbes2_hmacsha512_aes_256_test.json", "hmacsha512", 256),
]


def _load_pbes2_vectors() -> list[tuple[str, dict[str, Any]]]:
    vectors = []
    for filename, prf_name, key_bits in _PBES2_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        data = load_json_cached(path)
        prf = _PRF_MAP[prf_name]
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_prf"] = prf
                test["_prf_name"] = prf_name
                test["_key_bits"] = key_bits
                test["_file"] = filename
                vectors.append((f"{filename}:tc{test['tcId']}-{test['result']}", test))
    return vectors


_ALL_PBES2_VECTORS = _load_pbes2_vectors()


def _xfail_if_pbes2_runtime_reject(
    exc: AssertionError,
    label: str,
    operation: str,
) -> NoReturn:
    """Classify advertised PBES2 setup/use rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _PBES2_RUNTIME_REJECT_CKRS,
        f"{label}: advertised PBES2 {operation} is not operational",
    )
    raise exc


def _generate_key_with_mech(
    raw: Any, session: int, mech: PackedMechanism, attrs: dict[int, Any]
) -> int:
    """C_GenerateKey with a custom mechanism (for PBKDF2)."""
    tmpl = template_from_dict(attrs)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(session, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


@pytest.mark.parametrize("vec_id,vec", _ALL_PBES2_VECTORS, ids=[v[0] for v in _ALL_PBES2_VECTORS])
def test_pbes2_decrypt(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """PBES2 decrypt from Wycheproof vectors."""
    rs = p11_module_session
    if not rs.has_mechanism("PKCS5_PBKD2"):
        pytest.skip("PKCS5_PBKD2 not supported")
    if not rs.has_mechanism("AES_CBC_PAD"):
        pytest.skip("AES_CBC_PAD not supported")

    result = vec["result"]
    password = bytes.fromhex(vec["password"])
    salt = bytes.fromhex(vec["salt"])
    iterations = vec["iterationCount"]
    iv = bytes.fromhex(vec["iv"])
    ciphertext = bytes.fromhex(vec["ct"])
    expected = bytes.fromhex(vec["msg"])

    pbkdf2_param = mech_pbkdf2(
        CKM_PKCS5_PBKD2,
        salt=salt,
        iterations=iterations,
        prf=vec["_prf"],
        password=password,
    )

    try:
        key = _generate_key_with_mech(
            rs.raw,
            rs.sh,
            pbkdf2_param,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_VALUE_LEN: vec["_key_bits"] // 8,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
                CKA_DECRYPT: True,
            },
        )
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_pbes2_runtime_reject(exc, vec_id, "key derivation")
        return

    try:
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CBC_PAD,
            ciphertext,
            mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
        )
    except AssertionError as exc:
        destroy_quietly(rs.raw, rs.sh, key)
        if result == "valid":
            _xfail_if_pbes2_runtime_reject(exc, vec_id, "decrypt")
        return

    destroy_quietly(rs.raw, rs.sh, key)
    if result == "invalid":
        classify(
            "accepted_invalid",
            kind="crypto",
            summary=f"PBES2 decrypt {vec_id}: accepted invalid ciphertext",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    assert_correct(
        actual=plaintext,
        expected=expected,
        label=f"PBES2:C_Decrypt KAT {vec_id}",
        operation="C_Decrypt",
        source=vec.get("_source"),
        vector_id=vec.get("_vector_id"),
    )
