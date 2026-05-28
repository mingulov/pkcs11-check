"""Wycheproof RSA PKCS#1 v1.5 signature generation vectors (C_Sign path).

Tests RSA PKCS#1 v1.5 signing across key sizes 2048/3072/4096 with SHA-1
through SHA-512.  Each test imports the full RSA private key (via PKCS#8 DER
parsed with the cryptography library) and calls C_Sign, then compares the
resulting signature byte-for-byte against the expected value.

PKCS#1 v1.5 signatures are fully deterministic, so exact output matching is
mandatory.  Only "valid" result vectors are tested; "acceptable" vectors
(WeakHash etc.) are skipped.  1024-bit and 1536-bit files are also skipped
because many modules reject those key sizes.
"""

from __future__ import annotations

import json
from typing import Any, NoReturn

import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    import_rsa_private_key,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKM_SHA1_RSA_PKCS,
    CKM_SHA224_RSA_PKCS,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
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
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.data import WYCHEPROOF_DIR

pytestmark = pytest.mark.wycheproof

# Hash algorithm names -> PKCS#11 mechanisms
_SHA_TO_MECH: dict[str, int] = {
    "SHA-1": CKM_SHA1_RSA_PKCS,
    "SHA-224": CKM_SHA224_RSA_PKCS,
    "SHA-256": CKM_SHA256_RSA_PKCS,
    "SHA-384": CKM_SHA384_RSA_PKCS,
    "SHA-512": CKM_SHA512_RSA_PKCS,
}

# Mechanism display names for availability checking
_MECH_DISPLAY: dict[int, str] = {
    CKM_SHA1_RSA_PKCS: "SHA1_RSA_PKCS",
    CKM_SHA224_RSA_PKCS: "SHA224_RSA_PKCS",
    CKM_SHA256_RSA_PKCS: "SHA256_RSA_PKCS",
    CKM_SHA384_RSA_PKCS: "SHA384_RSA_PKCS",
    CKM_SHA512_RSA_PKCS: "SHA512_RSA_PKCS",
}

_RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_KEY_SIZE_RANGE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_RSA_PRIVATE_IMPORT_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)

# Only test key sizes >=2048; 1024 and 1536 are rejected by many modules
_SIGGEN_FILES = [
    "rsa_pkcs1_2048_sig_gen_test.json",
    "rsa_pkcs1_3072_sig_gen_test.json",
    "rsa_pkcs1_4096_sig_gen_test.json",
]


def _i2b(n: int) -> bytes:
    """Convert a positive integer to big-endian bytes with no leading zeros."""
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def _load_siggen_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load RSA PKCS#1 sig-gen vectors, keeping only 'valid' results."""
    vectors: list[tuple[str, dict[str, Any]]] = []
    for filename in _SIGGEN_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            sha = group.get("sha", "")
            mechanism = _SHA_TO_MECH.get(sha)
            if mechanism is None:
                continue
            pkcs8_hex = group.get("privateKeyPkcs8", "")
            if not pkcs8_hex:
                continue
            key_size = group.get("keySize", 0)
            for test in group["tests"]:
                if test["result"] != "valid":
                    continue
                test["_mechanism"] = mechanism
                test["_pkcs8_hex"] = pkcs8_hex
                test["_key_size"] = key_size
                test["_sha"] = sha
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}"
                vectors.append((vec_id, test))
    return vectors


_ALL_SIGGEN_VECTORS = _load_siggen_vectors()


def _skip_or_xfail_rsa_private_import_reject(
    exc: AssertionError,
    key_size: int,
    sha: str,
) -> NoReturn:
    """Classify RSA private-key import rejects before Wycheproof siggen."""
    if is_known_error(exc, _RSA_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
        pytest.skip(f"Cannot import RSA private key ({key_size}-bit, {sha}): {exc}")
    xfail_if_known_ckr(
        exc,
        _RSA_PRIVATE_IMPORT_RUNTIME_REJECT_CKRS,
        f"RSA private-key import is not operational ({key_size}-bit, {sha})",
    )
    raise exc


@pytest.mark.parametrize(
    "vec_id,vec",
    _ALL_SIGGEN_VECTORS,
    ids=[v[0] for v in _ALL_SIGGEN_VECTORS],
)
def test_rsa_pkcs1_siggen(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """RSA PKCS#1 v1.5 signature generation from Wycheproof vectors."""
    rs = p11_module_session
    mechanism: int = vec["_mechanism"]
    key_size: int = vec["_key_size"]
    sha: str = vec["_sha"]

    # Check mechanism availability before importing the key
    mech_display = _MECH_DISPLAY.get(mechanism, f"0x{mechanism:08x}")
    if not rs.has_mechanism(mech_display):
        pytest.skip(f"{mech_display} not supported by module")

    msg = bytes.fromhex(vec["msg"])
    expected_sig = bytes.fromhex(vec["sig"])

    # Parse PKCS#8 DER to extract full CRT private key components
    priv_der = bytes.fromhex(vec["_pkcs8_hex"])
    priv_key_raw = load_der_private_key(priv_der, password=None)
    assert isinstance(priv_key_raw, RSAPrivateKey), "Expected RSA private key in sig_gen vector"
    nums = priv_key_raw.private_numbers()
    pub_nums = nums.public_numbers

    key_obj = None
    try:
        try:
            key_obj = import_rsa_private_key(
                rs.raw,
                rs.sh,
                n=_i2b(pub_nums.n),
                e=_i2b(pub_nums.e),
                d=_i2b(nums.d),
                p=_i2b(nums.p),
                q=_i2b(nums.q),
                dmp1=_i2b(nums.dmp1),
                dmq1=_i2b(nums.dmq1),
                iqmp=_i2b(nums.iqmp),
                attrs={CKA_SIGN: True},
            )
        except AssertionError as e:
            _skip_or_xfail_rsa_private_import_reject(e, key_size, sha)

        sig = sign_single(rs.raw, rs.sh, key_obj, mechanism, msg)
        assert sig == expected_sig, (
            f"Signature mismatch for {vec_id} ({key_size}-bit {sha}): "
            f"got {sig.hex()[:32]}... expected {expected_sig.hex()[:32]}..."
        )
    finally:
        if key_obj is not None:
            destroy_quietly(rs.raw, rs.sh, key_obj)
