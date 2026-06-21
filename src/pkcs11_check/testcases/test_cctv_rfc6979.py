"""CCTV RFC 6979 rejection-sampling test vector.

The CCTV RFC6979 directory contains a single P-256/SHA-256 test vector that
exercises the rejection-sampling path of RFC 6979 deterministic nonce
derivation.  With P-256 the first k candidate has a 2^-32 chance of landing
in the rejection zone; this vector was constructed to trigger exactly that.

Most PKCS#11 modules use hardware or OS RNG nonces rather than RFC 6979, so
the sign output is non-deterministic.  The signature mismatch is classified as
xfail at the comparison point.  The PUBLIC KEY IMPORT + VERIFY path IS tested
unconditionally and must succeed when ECDSA_SHA256 is available.

Vector source: src/pkcs11_check/testcases/data/cctv/RFC6979/README.md
Verified against: OpenSSL 3.2.0, python-ecdsa, github.com/codahale/rfc6979
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import not_operational_reason
from pkcs11_check.testcases._provisioning import provision_ec_private_key
from pkcs11_check.testcases.conftest import (
    import_ec_public_key_negotiated,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.kat, pytest.mark.cctv]

# --- RFC 6979 / CCTV P-256 rejection-sampling vector ---
# Private key integer d (big-endian, 32 bytes)
_PRIV_D = bytes.fromhex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721")

# Public key coordinates
_PUB_QX = bytes.fromhex("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")
_PUB_QY = bytes.fromhex("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")

# Message bytes (ASCII)
_MSG = b"wv[vnX"

# Expected signature (raw r||s, each 32 bytes) - only produced by RFC 6979 implementations
_EXPECTED_R = bytes.fromhex("EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234")
_EXPECTED_S = bytes.fromhex("3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33")
_EXPECTED_SIG = _EXPECTED_R + _EXPECTED_S

_EC_PARAMS = encode_named_curve_parameters("secp256r1")

# DER-encode the uncompressed EC point: OCTET STRING(04 || qx || qy)
_RAW_POINT = bytes([0x04]) + _PUB_QX + _PUB_QY
_EC_POINT_DER = bytes([0x04, len(_RAW_POINT)]) + _RAW_POINT  # len=65, fits in 1-byte DER length

# EC import reject classification (import-skip audit A15). The reject is split: a
# genuine-capability-absence branch (the P-256 curve is not supported) stays a
# skip; a broad import-failure branch on a module that ADVERTISES ECDSA_SHA256 is
# "advertised but not operational" -> xfail. The public-key site negotiates
# storage shapes via import_ec_public_key_negotiated; the private-key site routes
# through provision_ec_private_key (create or unwrap depending on module).
_CCTV_EC_CURVE_UNSUPPORTED_CKRS = (
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
)

_CCTV_EC_IMPORT_UNSUPPORTED_CKRS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_CCTV_ECDSA_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    # Module-verify-unusable codes (a module that advertises ECDSA verify but
    # cannot use the imported key handle / size for C_Verify) -> not_operational,
    # matching the shared sigver classification (signature_rejected_or_xfail).
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


def _skip_or_xfail_cctv_ec_import_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify EC import rejects before CCTV RFC6979 operations (import-skip audit A15).

    Curve-genuine-absence CKRs (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID)
    keep the capability skip. A broad import-failure CKR on a module that
    ADVERTISES ECDSA_SHA256 (the ``has_mechanism("ECDSA_SHA256")`` gate passed
    upstream) is "advertised but not operational" -> xfail per the classification
    model -- for both the negotiated public-key site and the private-key site
    (routed through ``provision_ec_private_key``).
    The existing runtime-reject branch is preserved. Non-CKR AssertionErrors
    propagate (harness/coding bug).
    """
    if is_known_error(exc, _CCTV_EC_CURVE_UNSUPPORTED_CKRS):
        # Genuine capability absence: the curve is not supported
        # (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID). Skip stays.
        pytest.skip(f"Cannot import {label}: {exc}")
    if isinstance(exc, CkrAssertionError) and is_known_error(exc, _CCTV_EC_IMPORT_UNSUPPORTED_CKRS):
        # ECDSA_SHA256 is advertised (has_mechanism gate passed above) and the
        # import is exhausted -> "advertised but not operational" -> xfail per
        # the classification model (not skip).
        # May include curve-capability rejects expressed as generic CKRs --
        # recorded as xfail, not hidden.
        xfail_as(
            "not_operational",
            kind="crypto",
            label="ECDSA_SHA256:key-import",
            operation="C_CreateObject",
            mechanism="CKM_ECDSA_SHA256",
            actual=exc.rv,
            summary=not_operational_reason(
                "ECDSA_SHA256:key-import", f"{label}: {ckr_name(exc.rv)}"
            ),
        )
    xfail_if_known_ckr(
        exc,
        _CCTV_ECDSA_RUNTIME_REJECT_CKRS,
        f"{label} import is not operational",
    )
    raise exc


def test_rfc6979_ecdsa_verify(p11_raw_session: Any) -> None:
    """Verify the RFC 6979 CCTV vector signature with the imported public key.

    This test confirms that the expected r||s signature (produced by an
    RFC 6979 implementation) is a VALID signature for the given (message, key)
    pair.  Any module that supports ECDSA_SHA256 must accept it.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("ECDSA_SHA256"):
        pytest.skip("ECDSA_SHA256 not supported by module")

    pub_key = 0
    try:
        try:
            pub_key = import_ec_public_key_negotiated(
                rs,
                ec_params=_EC_PARAMS,
                ec_point=_EC_POINT_DER,
                attrs={CKA_VERIFY: True},
                purpose="CCTV RFC6979 P-256 public key import",
            )
        except AssertionError as e:
            _skip_or_xfail_cctv_ec_import_reject(e, "P-256 public-key")

        try:
            verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA_SHA256, _MSG, _EXPECTED_SIG)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _CCTV_ECDSA_RUNTIME_REJECT_CKRS,
                "ECDSA_SHA256 verify is not operational for CCTV RFC6979",
            )
            raise
        if not verified:
            fail_as(
                "wrong_result",
                kind="crypto",
                label="ECDSA_SHA256:verify (RFC6979 CCTV vector)",
                operation="C_Verify",
                mechanism="CKM_ECDSA_SHA256",
                summary=(
                    "Module rejected a VALID ECDSA-SHA256 signature - "
                    "the RFC 6979 CCTV vector should verify correctly"
                ),
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


def test_rfc6979_ecdsa_sign_deterministic(p11_raw_session: Any, p11_config: Any) -> None:
    """Sign with the RFC 6979 private key and compare to the expected signature.

    The CCTV vector exercises the P-256 rejection-sampling path (first k
    candidate is in the rejection zone).  Only RFC 6979 implementations will
    produce the expected r||s bytes.  All others will produce a different but
    mathematically valid signature - those runs are marked xfail.
    """
    rs = p11_raw_session
    if not rs.has_mechanism("ECDSA_SHA256"):
        pytest.skip("ECDSA_SHA256 not supported by module")

    priv_key = 0
    try:
        try:
            # Routes through provision_ec_private_key (create or unwrap depending on module).
            priv_key = provision_ec_private_key(
                rs,
                p11_config,
                ec_params=_EC_PARAMS,
                value=_PRIV_D,
                key_type=CKK_EC,
                attrs={CKA_SIGN: True},
                label="cctv RFC6979 ECDSA KAT",
            )
        except AssertionError as e:
            _skip_or_xfail_cctv_ec_import_reject(e, "P-256 private-key")

        try:
            sig = sign_single(rs.raw, rs.sh, priv_key, CKM_ECDSA_SHA256, _MSG)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _CCTV_ECDSA_RUNTIME_REJECT_CKRS,
                "ECDSA_SHA256 signing is not operational for CCTV RFC6979",
            )
            raise
        if sig != _EXPECTED_SIG:
            classify(
                "honest_deviation",
                kind="crypto",
                label="ECDSA_SHA256:sign (RFC6979 deterministic k)",
                operation="C_Sign",
                mechanism="CKM_ECDSA_SHA256",
                summary=(
                    "Module does not use RFC 6979 deterministic k "
                    f"(got {sig.hex()[:32]}..., expected {_EXPECTED_SIG.hex()[:32]}...)"
                ),
            )
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
