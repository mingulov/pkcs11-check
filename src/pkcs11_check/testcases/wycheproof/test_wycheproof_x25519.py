"""Wycheproof X25519 and X448 key exchange vectors.

Tests Montgomery curve Diffie-Hellman (RFC 7748) using CKM_ECDH1_DERIVE
with EC_MONTGOMERY key type across raw, ASN.1, PEM, and JWK encodings.
"""

from __future__ import annotations

from binascii import Error as BinasciiError
from typing import Any, NoReturn

import pytest
from cryptography.exceptions import UnsupportedAlgorithm

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
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
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._provisioning import provision_ec_private_key
from pkcs11_check.testcases.conftest import (
    assert_correct,
    is_known_error,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.wycheproof._key_decoders import (
    decode_xdh_private_bytes,
    decode_xdh_public_bytes,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDH1_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

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


def _xdh_jwk_invalidity_not_representable(test: dict[str, Any], key_size: int) -> bool:
    """Whether a JWK ``InvalidPublic`` vector's invalidity is invisible to PKCS#11.

    Wycheproof's JWK ``InvalidPublic`` vectors carry the invalidity entirely in
    the JWK wrapper -- a wrong ``crv``/``kty`` (e.g. a P-256 public key, or a
    malformed/missing ``kty``) while the ``x`` member is a canonical-length
    Montgomery coordinate.  ``decode_xdh_public_bytes`` extracts only that raw
    ``x``; per RFC 7748 sec 5 every 32-byte (X25519) / 56-byte (X448) string is a
    valid public key, so the module sees a fully valid raw point and deriving a
    secret is correct -- there is no invalid-curve / invalid-point attack class
    on Montgomery curves (RFC 7748 clamps the scalar; all inputs are valid
    points).  This is the direct analog of the ECDH ``InvalidAsn``/``InvalidPem``
    untestable-flag class: the invalidity is not representable once the wrapper
    is stripped, so the vector must be dropped at load rather than hard-failed.

    The wrong-length / missing-``x`` JWK invalid vectors are NOT swept: their
    ``x`` decodes to a non-canonical length (or is absent), which a careful
    module rejects at import, so they remain a genuine raw-point signal.
    """
    if test.get("_encoding") != "jwk" or test.get("result") != "invalid":
        return False
    if "InvalidPublic" not in test.get("flags", []):
        return False
    public = test.get("public")
    if not isinstance(public, dict):
        return False
    x_field = public.get("x")
    if not isinstance(x_field, str):
        return False
    try:
        raw = decode_xdh_public_bytes(public, "jwk")
    except _XDH_DECODE_ERRORS:
        return False
    # Only the canonical-length container-mismatch class is untestable; a
    # wrong-length coordinate is a real import-validation signal and stays.
    return len(raw) == key_size


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
        data = load_json_cached(path)
        for group in data["testGroups"]:
            for test in group["tests"]:
                test["_group"] = {k: v for k, v in group.items() if k != "tests"}
                test["_oid"] = oid
                test["_key_size"] = key_size
                test["_encoding"] = encoding_name
                test["_file"] = filename
                if _xdh_jwk_invalidity_not_representable(test, key_size):
                    # JWK wrapper-only invalidity (wrong crv/kty, canonical-length
                    # x): not representable through the raw-point path -- drop it,
                    # like the ECDH InvalidAsn/InvalidPem untestable class.
                    continue
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
def test_xdh(p11_module_session: Any, p11_config: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """X25519/X448 key exchange from Wycheproof vectors."""
    rs = p11_module_session
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
        priv_key = provision_ec_private_key(
            rs,
            p11_config,
            ec_params=oid,
            value=private_bytes,
            key_type=CKK_EC_MONTGOMERY,
            attrs={CKA_DERIVE: True},
            label="wycheproof X25519/X448 KAT",
        )
    except AssertionError as exc:
        if is_known_error(exc, _CURVE_UNSUPPORTED_CKRS):
            _UNSUPPORTED_CURVE_OIDS.add(oid)
            if result == "invalid":
                return
            pytest.skip(f"Cannot import Montgomery private key: {exc}")
        if result == "invalid" and is_known_error(exc, _MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS):
            return
        if isinstance(exc, CkrAssertionError) and is_known_error(
            exc, _MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS
        ):
            # ECDH1_DERIVE is advertised (gate passed above) and modules that
            # hit this branch operationally derive XDH/ECDH -- the canonical
            # private-key import of a VALID vector is the only gap. That is
            # "advertised but not operational" -> xfail per the classification
            # model, not skip. The CKR_CURVE_NOT_SUPPORTED/DOMAIN branch above
            # keeps the genuine-absence skip; the result=="invalid" return above
            # keeps the vacuous pass.
            classify(
                "not_operational",
                summary=not_operational_reason("ECDH:Montgomery-private-import", ckr_name(exc.rv)),
            )
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
            classify(
                "not_operational",
                label=vec_id,
                summary=f"X25519/X448 derive failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)

    if result == "valid" and shared is not None:
        assert_correct(
            actual=shared,
            expected=shared_expected,
            label=f"X25519/X448:C_DeriveKey KAT {vec_id}",
            operation="C_DeriveKey",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and shared is not None:
        classify(
            "accepted_invalid",
            kind="crypto",
            label=vec_id,
            summary=(
                f"X25519/X448 derived a secret for an invalid vector {vec_id} "
                "(invalid-point accepted)"
            ),
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
