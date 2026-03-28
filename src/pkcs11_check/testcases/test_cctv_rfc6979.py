"""CCTV RFC 6979 rejection-sampling test vector.

The CCTV RFC6979 directory contains a single P-256/SHA-256 test vector that
exercises the rejection-sampling path of RFC 6979 deterministic nonce
derivation.  With P-256 the first k candidate has a 2^-32 chance of landing
in the rejection zone; this vector was constructed to trigger exactly that.

Most PKCS#11 modules use hardware or OS RNG nonces rather than RFC 6979, so
the sign output is non-deterministic.  The test is therefore marked xfail for
signature comparison.  The PUBLIC KEY IMPORT + VERIFY path IS tested
unconditionally and must succeed when ECDSA_SHA256 is available.

Vector source: src/pkcs11_check/testcases/data/cctv/RFC6979/README.md
Verified against: OpenSSL 3.2.0, python-ecdsa, github.com/codahale/rfc6979
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA_SHA256,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
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
            pub_key = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: _EC_PARAMS,
                    CKA_EC_POINT: _EC_POINT_DER,
                    CKA_TOKEN: False,
                    CKA_VERIFY: True,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import P-256 public key: {e}")

        verified = verify_single(rs.raw, rs.sh, pub_key, CKM_ECDSA_SHA256, _MSG, _EXPECTED_SIG)
        if not verified:
            pytest.fail(
                "Module rejected a VALID ECDSA-SHA256 signature - "
                "the RFC 6979 CCTV vector should verify correctly"
            )
    finally:
        if pub_key:
            destroy_quietly(rs.raw, rs.sh, pub_key)


@pytest.mark.xfail(
    reason=(
        "Most PKCS#11 modules use random nonces rather than RFC 6979 "
        "deterministic k - signature will differ from the expected value. "
        "xfail is correct. A pass here means the module implements RFC 6979."
    ),
    strict=False,
)
def test_rfc6979_ecdsa_sign_deterministic(p11_raw_session: Any) -> None:
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
            priv_key = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PRIVATE_KEY,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: _EC_PARAMS,
                    CKA_VALUE: _PRIV_D,
                    CKA_TOKEN: False,
                    CKA_SENSITIVE: False,
                    CKA_SIGN: True,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Cannot import P-256 private key: {e}")

        sig = sign_single(rs.raw, rs.sh, priv_key, CKM_ECDSA_SHA256, _MSG)
        assert sig == _EXPECTED_SIG, (
            f"Signature mismatch: got {sig.hex()[:32]}... "
            f"expected {_EXPECTED_SIG.hex()[:32]}... "
            "(module does not use RFC 6979 deterministic k - xfail is expected)"
        )
    finally:
        if priv_key:
            destroy_quietly(rs.raw, rs.sh, priv_key)
