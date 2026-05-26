"""Wycheproof RSA PKCS#1 v1.5 decryption vectors.

Tests RSA PKCS#1 v1.5 decryption (CKM_RSA_PKCS) across key sizes 2048/3072/4096.
Imports RSA private key, decrypts ciphertext, compares against expected plaintext.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    import_rsa_private_key,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKM_RSA_PKCS,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.wycheproof._key_decoders import pkcs11_bigint_from_hex

pytestmark = pytest.mark.wycheproof

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Cache of RSA key sizes (in bits) that the module rejected on import.
# Populated on first failure; subsequent tests with the same key size skip
# immediately without attempting another C_CreateObject probe.
_UNSUPPORTED_RSA_KEY_SIZES: set[int] = set()

_RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
)

_RSA_PKCS1_DECRYPT_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

_DECRYPT_FILES = [
    "rsa_pkcs1_2048_test.json",
    "rsa_pkcs1_3072_test.json",
    "rsa_pkcs1_4096_test.json",
]


def _load_decrypt_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA PKCS#1 v1.5 decryption vectors."""
    vectors = []
    for filename in _DECRYPT_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_DECRYPT_VECTORS = _load_decrypt_vectors()


def _xfail_if_rsa_pkcs1_decrypt_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised RSA PKCS#1 decrypt runtime rejects as findings."""
    xfail_if_known_ckr(
        exc,
        _RSA_PKCS1_DECRYPT_RUNTIME_REJECT_CKRS,
        f"{label}: advertised RSA PKCS#1 decrypt is not operational",
    )
    raise exc


@pytest.mark.parametrize(
    "vec_id,vec", _ALL_DECRYPT_VECTORS, ids=[v[0] for v in _ALL_DECRYPT_VECTORS]
)
def test_rsa_pkcs1_decrypt(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 decryption from Wycheproof vectors."""
    rs = p11_raw_session
    ct = bytes.fromhex(vec["ct"])
    msg_expected = bytes.fromhex(vec["msg"])
    result = vec["result"]
    group = vec["_group"]

    pk = group.get("privateKey", {})
    modulus_hex = pk.get("modulus", "")
    priv_exp_hex = pk.get("privateExponent", "")
    if not modulus_hex or not priv_exp_hex:
        pytest.skip("No RSA private key in vector group")

    modulus = pkcs11_bigint_from_hex(modulus_hex)
    pub_exponent = pkcs11_bigint_from_hex(pk.get("publicExponent", ""))
    priv_exponent = pkcs11_bigint_from_hex(priv_exp_hex)
    prime1 = pkcs11_bigint_from_hex(pk.get("prime1", ""))
    prime2 = pkcs11_bigint_from_hex(pk.get("prime2", ""))
    exp1 = pkcs11_bigint_from_hex(pk.get("exponent1", ""))
    exp2 = pkcs11_bigint_from_hex(pk.get("exponent2", ""))
    coefficient = pkcs11_bigint_from_hex(pk.get("coefficient", ""))
    key_bits = len(modulus) * 8

    if key_bits in _UNSUPPORTED_RSA_KEY_SIZES:
        pytest.skip(f"RSA {key_bits}-bit keys not supported (cached)")

    try:
        priv_key = import_rsa_private_key(
            rs.raw,
            rs.sh,
            n=modulus,
            e=pub_exponent,
            d=priv_exponent,
            p=prime1,
            q=prime2,
            dmp1=exp1,
            dmq1=exp2,
            iqmp=coefficient,
            attrs={CKA_DECRYPT: True},
        )
    except AssertionError as exc:
        exc_msg = str(exc)
        # Only cache permanent key-size rejections, not transient errors.
        if is_known_error(exc, _RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            _UNSUPPORTED_RSA_KEY_SIZES.add(key_bits)
        pytest.skip(f"Cannot import RSA {key_bits}-bit private key: {exc_msg}")

    plaintext = None
    try:
        plaintext = decrypt_single(rs.raw, rs.sh, priv_key, CKM_RSA_PKCS, ct)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_rsa_pkcs1_decrypt_runtime_reject(exc, vec_id)
            pytest.fail(f"Valid RSA PKCS#1 ciphertext {vec_id} failed to decrypt: {exc}")
        # acceptable/invalid: reject is fine (padding oracle resistance)
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and plaintext is not None:
        assert plaintext == msg_expected
    if result == "invalid" and plaintext is not None:
        pytest.fail(f"RSA PKCS#1 decrypt {vec_id} accepted invalid ciphertext")
