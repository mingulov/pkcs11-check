"""Wycheproof X25519 and X448 key exchange vectors.

Tests Montgomery curve Diffie-Hellman (RFC 7748) using CKM_ECDH1_DERIVE
with EC_MONTGOMERY key type across raw, ASN.1, PEM, and JWK encodings.
"""

from __future__ import annotations

import json
from binascii import Error as BinasciiError
from typing import Any, NoReturn

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

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
    CKK_EC_MONTGOMERY,
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
    decode_xdh_private_bytes,
    decode_xdh_public_bytes,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDH1_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR  # noqa: E402

# Module-level cache of curve OIDs that failed C_CreateObject with a domain/curve error.
# Keyed by OID bytes; avoids redundant probe calls for unsupported Montgomery curves.
_UNSUPPORTED_CURVE_OIDS: set[bytes] = set()

_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
)

_XDH_RUNTIME_REJECT_CKRS = (
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

_XDH_DECODE_ERRORS = (
    BinasciiError,
    KeyError,
    TypeError,
    UnsupportedAlgorithm,
    ValueError,
)

# OIDs for Montgomery curves
X25519_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6E])  # 1.3.101.110
X448_OID = bytes([0x06, 0x03, 0x2B, 0x65, 0x6F])  # 1.3.101.111

_X25519_X448_FILES = [
    ("x25519_test.json", X25519_OID, 32, "raw"),
    ("x25519_asn_test.json", X25519_OID, 32, "asn"),
    ("x25519_jwk_test.json", X25519_OID, 32, "jwk"),
    ("x25519_pem_test.json", X25519_OID, 32, "pem"),
    ("x448_test.json", X448_OID, 56, "raw"),
    ("x448_asn_test.json", X448_OID, 56, "asn"),
    ("x448_jwk_test.json", X448_OID, 56, "jwk"),
    ("x448_pem_test.json", X448_OID, 56, "pem"),
]


def _pkcs11_xdh_fingerprint(test: dict[str, Any]) -> tuple[bytes, bytes, bytes, bytes, str] | None:
    """Return the PKCS#11-visible XDH operation inputs for duplicate detection."""
    try:
        return (
            test["_oid"],
            decode_xdh_public_bytes(test["public"], test["_encoding"]),
            decode_xdh_private_bytes(test["private"], test["_encoding"]),
            bytes.fromhex(test["shared"]),
            str(test["result"]),
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return None


def _load_xdh_vectors() -> list[tuple[str, dict[str, Any]]]:
    """Load X25519/X448 key exchange vectors."""
    vectors = []
    seen_pkcs11_inputs: dict[tuple[bytes, bytes, bytes, bytes, str], str] = {}
    for filename, oid, key_size, encoding_name in _X25519_X448_FILES:
        path = WYCHEPROOF_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_oid"] = oid
                test["_key_size"] = key_size
                test["_encoding"] = encoding_name
                test["_file"] = filename
                vec_id = f"{filename}:tc{test['tcId']}-{test['result']}"
                fingerprint = _pkcs11_xdh_fingerprint(test)
                if fingerprint is not None:
                    duplicate_of = seen_pkcs11_inputs.setdefault(fingerprint, vec_id)
                    if duplicate_of != vec_id:
                        test["_pkcs11_duplicate_of"] = duplicate_of
                vectors.append((vec_id, test))
    return vectors


_ALL_XDH_VECTORS = _load_xdh_vectors()


def _xfail_if_xdh_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised XDH derive rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _XDH_RUNTIME_REJECT_CKRS,
        f"{label}: advertised XDH derive is not operational",
    )
    raise exc


@pytest.mark.parametrize("vec_id,vec", _ALL_XDH_VECTORS, ids=[v[0] for v in _ALL_XDH_VECTORS])
def test_xdh(p11_raw_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """X25519/X448 key exchange from Wycheproof vectors."""
    rs = p11_raw_session
    if not rs.has_mechanism("ECDH1_DERIVE"):
        pytest.skip("ECDH1_DERIVE not supported")

    if duplicate_of := vec.get("_pkcs11_duplicate_of"):
        pytest.skip(f"Duplicate PKCS#11 XDH operation input; covered by {duplicate_of}")

    oid = vec["_oid"]
    key_size = vec["_key_size"]
    encoding_name = vec["_encoding"]
    result = vec["result"]
    try:
        private_bytes = decode_xdh_private_bytes(vec["private"], encoding_name)
    except _XDH_DECODE_ERRORS as exc:
        if result == "invalid":
            return  # Can't import a private key on our side; invalid vector passes
        pytest.skip(f"Cannot decode {encoding_name} XDH private key: {type(exc).__name__}")
    try:
        public_bytes = decode_xdh_public_bytes(vec["public"], encoding_name)
    except _XDH_DECODE_ERRORS as exc:
        if result == "invalid":
            return
        pytest.skip(f"Cannot decode {encoding_name} XDH public key: {type(exc).__name__}")
    shared_expected = bytes.fromhex(vec["shared"])

    if oid in _UNSUPPORTED_CURVE_OIDS:
        pytest.skip(f"Montgomery curve OID {oid.hex()} not supported (cached)")

    # Import Montgomery private key
    try:
        priv_key = import_ec_private_key(
            rs.raw,
            rs.sh,
            ec_params=oid,
            value=private_bytes,
            key_type=int(CKK_EC_MONTGOMERY),
            attrs={CKA_DERIVE: True},
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            _UNSUPPORTED_CURVE_OIDS.add(oid)
            if result == "invalid":
                return
            pytest.skip(f"Cannot import Montgomery private key: {exc}")
        if result == "invalid" and is_known_error(exc, _MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            return
        if is_known_error(exc, _MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            pytest.skip(f"Cannot import Montgomery private key: {exc}")
        raise

    # Derive shared secret
    ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=public_bytes)
    shared = None
    try:
        derived = derive_key(
            rs.raw,
            rs.sh,
            priv_key,
            CKM_ECDH1_DERIVE,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: key_size,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=ecdh_param,
        )
        attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
        shared = attrs[CKA_VALUE]
        assert isinstance(shared, bytes)
        destroy_quietly(rs.raw, rs.sh, derived)
    except (AssertionError, TypeError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_xdh_runtime_reject(exc, vec_id)
            pytest.fail(f"X25519/X448 derive failed for valid vector {vec_id}: {exc}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and shared is not None:
        assert shared == shared_expected
    if result == "invalid" and shared is not None and len(public_bytes) != key_size:
        pytest.fail(
            f"Invalid X25519/X448 vector {vec_id} derived with {len(public_bytes)}-byte public key"
        )
