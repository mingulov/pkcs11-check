"""Wycheproof ECDH key agreement vectors.

Exercises raw-point, ASN.1, PEM, and WebCrypto encodings across the
curve families that can be fed into the existing PKCS#11 derive path.
"""

from __future__ import annotations

import json
from binascii import Error as BinasciiError
from typing import Any, NoReturn

import pytest

from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_ec_private_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr
from pkcs11_check.testcases.wycheproof._key_decoders import (
    decode_ec_private_scalar,
    decode_ec_public_point,
    ec_key_bits,
    ec_params_for_curve,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDH1_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Module-level cache of curves that failed C_CreateObject with a domain/curve error.
# Avoids thousands of redundant probe calls when a module does not support a curve.
_UNSUPPORTED_CURVES: set[str] = set()

_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
)

_ECDH_RUNTIME_REJECT_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

_ECDH_DECODE_ERRORS = (
    BinasciiError,
    KeyError,
    TypeError,
    ValueError,
)

_ECDH_FILES = [
    ("ecdh_brainpoolP224r1_test.json", "brainpoolP224r1", "asn"),
    ("ecdh_brainpoolP256r1_test.json", "brainpoolP256r1", "asn"),
    ("ecdh_brainpoolP320r1_test.json", "brainpoolP320r1", "asn"),
    ("ecdh_brainpoolP384r1_test.json", "brainpoolP384r1", "asn"),
    ("ecdh_brainpoolP512r1_test.json", "brainpoolP512r1", "asn"),
    ("ecdh_secp224r1_ecpoint_test.json", "secp224r1", "ecpoint"),
    ("ecdh_secp224r1_pem_test.json", "secp224r1", "pem"),
    ("ecdh_secp224r1_test.json", "secp224r1", "asn"),
    ("ecdh_secp256k1_test.json", "secp256k1", "asn"),
    ("ecdh_secp256k1_webcrypto_test.json", "P-256K", "webcrypto"),
    ("ecdh_secp256r1_ecpoint_test.json", "secp256r1", "ecpoint"),
    ("ecdh_secp256r1_pem_test.json", "secp256r1", "pem"),
    ("ecdh_secp256r1_test.json", "secp256r1", "asn"),
    ("ecdh_secp256r1_webcrypto_test.json", "P-256", "webcrypto"),
    ("ecdh_secp384r1_ecpoint_test.json", "secp384r1", "ecpoint"),
    ("ecdh_secp384r1_pem_test.json", "secp384r1", "pem"),
    ("ecdh_secp384r1_test.json", "secp384r1", "asn"),
    ("ecdh_secp384r1_webcrypto_test.json", "P-384", "webcrypto"),
    ("ecdh_secp521r1_ecpoint_test.json", "secp521r1", "ecpoint"),
    ("ecdh_secp521r1_pem_test.json", "secp521r1", "pem"),
    ("ecdh_secp521r1_test.json", "secp521r1", "asn"),
    ("ecdh_secp521r1_webcrypto_test.json", "P-521", "webcrypto"),
    ("ecdh_sect283k1_test.json", "sect283k1", "asn"),
    ("ecdh_sect283r1_test.json", "sect283r1", "asn"),
    ("ecdh_sect409k1_test.json", "sect409k1", "asn"),
    ("ecdh_sect409r1_test.json", "sect409r1", "asn"),
    ("ecdh_sect571k1_test.json", "sect571k1", "asn"),
    ("ecdh_sect571r1_test.json", "sect571r1", "asn"),
]


# Flags for vectors that test ASN.1/PEM container parsing, not the
# cryptographic operation. These are not testable through PKCS#11
# because C_CreateObject takes pre-extracted EC points and scalars,
# not SubjectPublicKeyInfo containers.
_UNTESTABLE_FLAGS = {"InvalidAsn", "InvalidPem"}


def _pkcs11_ecdh_fingerprint(test: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, str] | None:
    """Return the PKCS#11-visible ECDH operation inputs for duplicate detection."""
    try:
        return (
            ec_params_for_curve(test["_curve"]),
            decode_ec_public_point(test["public"], test["_encoding"], test["_curve"]),
            decode_ec_private_scalar(test["private"], test["_encoding"], test["_curve"]),
            bytes.fromhex(test["shared"]),
            str(test["result"]),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _load_ecdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load ECDH vectors across multiple input encodings."""
    vectors = []
    seen_pkcs11_inputs: dict[tuple[bytes, bytes, bytes, bytes, str], str] = {}
    for filename, curve, encoding_name in _ECDH_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                if _UNTESTABLE_FLAGS & set(test.get("flags", [])):
                    continue
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_curve"] = curve
                test["_encoding"] = encoding_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                fingerprint = _pkcs11_ecdh_fingerprint(test)
                if fingerprint is not None:
                    duplicate_of = seen_pkcs11_inputs.setdefault(fingerprint, vec_id)
                    if duplicate_of != vec_id:
                        test["_pkcs11_duplicate_of"] = duplicate_of
                vectors.append((vec_id, test))
    return vectors


_ALL_ECDH_VECTORS = _load_ecdh_vectors()


def _xfail_if_ecdh_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised ECDH derive rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _ECDH_RUNTIME_REJECT_CKRS,
        f"{label}: advertised ECDH derive is not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDH_VECTORS, ids=[v[0] for v in _ALL_ECDH_VECTORS])
def test_ecdh(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDH key agreement from Wycheproof ecpoint vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDH1_DERIVE"):
        pytest.skip("ECDH1_DERIVE not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 ECDH operation input; covered by {duplicate_of}")

    curve = vec["_curve"]
    encoding_name = vec["_encoding"]
    try:
        oid = ec_params_for_curve(curve)
    except _ECDH_DECODE_ERRORS:
        pytest.skip(f"No EC params mapping for curve {curve}")

    if curve in _UNSUPPORTED_CURVES:
        pytest.skip(f"Curve {curve} not supported (cached)")

    try:
        public_point = decode_ec_public_point(vec["public"], encoding_name, curve)
        private_scalar = decode_ec_private_scalar(vec["private"], encoding_name, curve)
    except _ECDH_DECODE_ERRORS as exc:
        pytest.skip(f"Cannot decode {encoding_name} ECDH vector: {type(exc).__name__}")
    shared_expected = bytes.fromhex(vec["shared"])
    result = vec["result"]

    key_bits = ec_key_bits(curve)

    # Import EC private key
    try:
        priv_key = import_ec_private_key(
            rs.raw,
            rs.sh,
            ec_params=oid,
            value=private_scalar,
            attrs={CKA_DERIVE: True},
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            _UNSUPPORTED_CURVES.add(curve)
            if result == "invalid":
                return
            pytest.skip(f"Cannot import EC private key for ECDH: {exc}")
        if result == "invalid" and is_known_error(exc, _EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            return
        if is_known_error(exc, _EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            pytest.skip(f"Cannot import EC private key for ECDH: {exc}")
        raise

    # Derive shared secret
    # ECDH1_DERIVE params: (kdf, shared_data, public_data)
    # KDF.NULL means raw ECDH (no KDF applied to output)
    ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=public_point)
    invalid_without_shared_derived = False
    try:
        derived_key = derive_key(
            rs.raw,
            rs.sh,
            priv_key,
            CKM_ECDH1_DERIVE,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: key_bits // 8,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=ecdh_param,
        )
        # Extract the derived key value
        attrs = read_attributes(rs.raw, rs.sh, derived_key, [CKA_VALUE])
        shared = attrs[CKA_VALUE]
        assert isinstance(shared, bytes)
        if result == "valid":
            assert shared == shared_expected, f"ECDH shared secret mismatch for {vec_id}"
        elif result == "invalid" and not shared_expected:
            invalid_without_shared_derived = True
        destroy_quietly(rs.raw, rs.sh, derived_key)
    except AssertionError as exc:
        exc_msg = str(exc)
        if "mismatch" in exc_msg:
            raise
        if result == "valid":
            _xfail_if_ecdh_runtime_reject(exc, vec_id)
            pytest.fail(f"Valid ECDH derive failed for {vec_id}: {exc_msg}")
        # acceptable: reject is fine
        return
    except (TypeError, NotImplementedError):
        pytest.skip("ECDH derive not supported by binding")
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if invalid_without_shared_derived:
        pytest.fail(f"Invalid ECDH vector {vec_id} derived without an expected shared secret")
