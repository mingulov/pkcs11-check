"""Wycheproof ECDH key agreement vectors.

Exercises raw-point, ASN.1, PEM, and WebCrypto encodings across the
curve families that can be fed into the existing PKCS#11 derive path.
"""

from __future__ import annotations

from binascii import Error as BinasciiError
from typing import Any, NoReturn

import pytest

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
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_ec_private_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.wycheproof._key_decoders import (
    decode_ec_private_scalar,
    decode_ec_public_point,
    ec_key_bits,
    ec_params_for_curve,
    ecdh_cofactor1_shared_x,
)

pytestmark = pytest.mark.wycheproof
REQUIRED_MECHANISMS = ["ECDH1_DERIVE"]

from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached  # noqa: E402

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
        data = load_json_cached(path)
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


def _point_on_base_curve(point: bytes, curve_name: str) -> bool | None:
    """Whether ``point`` is a valid point on ``curve_name``.

    PKCS#11 CKM_ECDH1_DERIVE receives only the raw peer-point bytes plus the
    base key's curve -- it never sees the X.509 curve encoding. So a Wycheproof
    "invalid" vector whose invalidity is at the encoding layer
    (UnnamedCurve / ModifiedPrime / ModifiedGroup / WrongCurve where the point
    still lands on the base curve) is NOT an invalid-curve attack against the
    PKCS#11 path: the module derived correctly on an on-curve point. The genuine
    invalid-curve attack is only when the point is OFF the base curve.

    Returns True (on curve), False (off curve / unparseable -> a finding), or
    None when ``cryptography`` cannot represent the curve (cannot determine;
    the caller keeps the conservative finding). Uses cryptography's
    ``from_encoded_point``, which validates curve membership and never accepts
    an off-curve point -- so a real off-curve derive is never masked.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    curve_cls = getattr(ec, curve_name.upper(), None)
    if curve_cls is None or not isinstance(curve_cls, type):
        return None
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(curve_cls(), point)
        return True
    except (ValueError, TypeError):
        return False


@pytest.mark.parametrize("vec_id,vec", _ALL_ECDH_VECTORS, ids=[v[0] for v in _ALL_ECDH_VECTORS])
def test_ecdh(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """ECDH key agreement from Wycheproof ecpoint vectors."""
    rs = p11_module_session
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

    label = vec_id
    if result == "invalid" and shared_expected:
        # Parameter-level invalidity (WrongCurve / UnnamedCurve with WrongOrder
        # or ModifiedPrime) lives in the vector's ASN.1 curve parameters.
        # CK_ECDH1_DERIVE_PARAMS carries only the raw public point -- the curve
        # comes from the private key -- so when that point is ON the private
        # key's (cofactor-1) curve, the module sees a fully valid derive and
        # deriving is correct, not an accepted invalid point. Reduce to a
        # positive check against the vector's shared secret: a module that
        # honored the attacker-declared parameters yields a different
        # x-coordinate and still fails the comparison below.
        if ecdh_cofactor1_shared_x(curve, public_point, private_scalar) == shared_expected:
            result = "valid"
            label = f"{vec_id} (reduced: invalidity not representable in CK_ECDH1_DERIVE_PARAMS)"

    key_bits = ec_key_bits(curve)

    # Import EC private key
    try:
        priv_key = import_ec_private_key_negotiated(
            rs,
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
        if isinstance(exc, CkrAssertionError) and is_known_error(
            exc, _EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS
        ):
            # ECDH1_DERIVE is advertised (gate passed above) and providers that
            # hit this branch (tpm2/wolfpkcs11/kryoptic per the D2 cross-check)
            # operationally derive named-curve ECDH -- the canonical private-key
            # import of a VALID vector is the only gap. "Advertised but not
            # operational" -> xfail, not skip. The CKR_CURVE_NOT_SUPPORTED/DOMAIN
            # branch above keeps the genuine-absence skip; the result=="invalid"
            # return above keeps the vacuous pass.
            classify(
                "not_operational",
                label="ECDH:EC-private-import",
                summary=not_operational_reason("ECDH:EC-private-import", ckr_name(exc.rv)),
            )
        raise

    # Derive shared secret
    # ECDH1_DERIVE params: (kdf, shared_data, public_data)
    # KDF.NULL means raw ECDH (no KDF applied to output)
    ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=public_point)
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
            assert_correct(
                actual=shared,
                expected=shared_expected,
                label=f"ECDH:C_DeriveKey KAT {vec_id}",
                operation="C_DeriveKey",
                mechanism="CKM_ECDH1_DERIVE",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        elif result == "invalid":
            destroy_quietly(rs.raw, rs.sh, derived_key)
            # Only an OFF-base-curve derive is the genuine invalid-curve attack.
            # If the peer point is on the base curve, the vector's invalidity is
            # at the X.509 encoding layer the raw PKCS#11 ECDH path never sees,
            # so a correct derive is not a finding (every careful provider does
            # this for those vectors).
            if _point_on_base_curve(public_point, curve) is True:
                return
            classify(
                "accepted_invalid",
                kind="crypto",
                label="ECDH",
                summary=(
                    f"ECDH derived a secret for {vec_id} from a peer point that is not on the "
                    f"base curve {curve} (invalid-curve attack: module skipped point validation)"
                ),
            )
        destroy_quietly(rs.raw, rs.sh, derived_key)
    except AssertionError as exc:
        exc_msg = str(exc)
        if "mismatch" in exc_msg:
            raise
        if result == "valid":
            _xfail_if_ecdh_runtime_reject(exc, label)
        # acceptable: reject is fine
        return
    except (TypeError, NotImplementedError):
        pytest.skip("ECDH derive not supported by binding")
    finally:
        destroy_quietly(rs.raw, rs.sh, priv_key)
