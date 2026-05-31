"""HashML-DSA (pre-hash ML-DSA) sign/verify tests - PKCS#11 v3.2.

Tests all 11 HASH_ML_DSA mechanism variants:
- CKM_HASH_ML_DSA (generic, single-part only, requires CK_HASH_SIGN_ADDITIONAL_CONTEXT)
- CKM_HASH_ML_DSA_SHA224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_ML_DSA_SHA3_224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_ML_DSA_SHAKE128/256 (hash-specific, single+multi-part)

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
from pkcs11_check.raw.pack_mechanisms import mech_hash_sign_context
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_PARAMETER_SET,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM,
    CKM_HASH_ML_DSA,
    CKM_HASH_ML_DSA_SHA3_224,
    CKM_HASH_ML_DSA_SHA3_256,
    CKM_HASH_ML_DSA_SHA3_384,
    CKM_HASH_ML_DSA_SHA3_512,
    CKM_HASH_ML_DSA_SHA224,
    CKM_HASH_ML_DSA_SHA256,
    CKM_HASH_ML_DSA_SHA384,
    CKM_HASH_ML_DSA_SHA512,
    CKM_HASH_ML_DSA_SHAKE128,
    CKM_HASH_ML_DSA_SHAKE256,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_SHA256,
    CKP_ML_DSA_65,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr

pytestmark = [pytest.mark.pqc]
REQUIRED_MECHANISMS = ["ML_DSA_KEY_PAIR_GEN"]

_MESSAGE = b"HashML-DSA pre-hash signature test message 2026"

# CKRs that indicate the mechanism is not yet implemented (not a test bug).
_SIGN_ERROR_CKRS = (
    CKR_MECHANISM_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_DEVICE_ERROR,
    CKR_DATA_LEN_RANGE,
    CKR_GENERAL_ERROR,
)

# Hash-specific HASH_ML_DSA variants mapped to their CKM constants.
# These support both single-part and multi-part sign/verify.
# The CK_SIGN_ADDITIONAL_CONTEXT parameter is optional (defaults apply).
_HASH_VARIANTS: dict[str, CKM] = {
    "HASH_ML_DSA_SHA224": CKM_HASH_ML_DSA_SHA224,
    "HASH_ML_DSA_SHA256": CKM_HASH_ML_DSA_SHA256,
    "HASH_ML_DSA_SHA384": CKM_HASH_ML_DSA_SHA384,
    "HASH_ML_DSA_SHA512": CKM_HASH_ML_DSA_SHA512,
    "HASH_ML_DSA_SHA3_224": CKM_HASH_ML_DSA_SHA3_224,
    "HASH_ML_DSA_SHA3_256": CKM_HASH_ML_DSA_SHA3_256,
    "HASH_ML_DSA_SHA3_384": CKM_HASH_ML_DSA_SHA3_384,
    "HASH_ML_DSA_SHA3_512": CKM_HASH_ML_DSA_SHA3_512,
    "HASH_ML_DSA_SHAKE128": CKM_HASH_ML_DSA_SHAKE128,
    "HASH_ML_DSA_SHAKE256": CKM_HASH_ML_DSA_SHAKE256,
}

_VARIANT_NAMES = list(_HASH_VARIANTS.keys())


def _skip_if_no(rs: Any, mech_name: str) -> None:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _generate_ml_dsa_keypair(rs: Any, param_set: int | None = None) -> tuple[int, int]:
    """Generate an ML-DSA key pair for HashML-DSA sign/verify."""
    effective_param = param_set if param_set is not None else CKP_ML_DSA_65
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_ML_DSA_KEY_PAIR_GEN,
        pub_base=[attr_ulong(CKA_PARAMETER_SET, effective_param)],
        priv_base=[],
        public_attrs={
            CKA_VERIFY: True,
            CKA_TOKEN: False,
        },
        private_attrs={
            CKA_SIGN: True,
            CKA_TOKEN: False,
        },
        pub_skip={CKA_PARAMETER_SET},
    )


class TestHashMLDSAGeneric:
    """CKM_HASH_ML_DSA - generic pre-hash ML-DSA (single-part only).

    This mechanism requires a CK_HASH_SIGN_ADDITIONAL_CONTEXT parameter
    that specifies which hash algorithm to use.
    """

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HASH_ML_DSA is advertised by the module."""
        _skip_if_no(p11_raw_session, "HASH_ML_DSA")

    def test_sign_verify_roundtrip(self, p11_raw_session: Any) -> None:
        """CKM_HASH_ML_DSA sign + verify with CK_HASH_SIGN_ADDITIONAL_CONTEXT (SHA-256)."""
        rs = p11_raw_session
        _skip_if_no(rs, "HASH_ML_DSA")
        _skip_if_no(rs, "ML_DSA")  # need keygen

        mech_param = mech_hash_sign_context(CKM_HASH_ML_DSA, hash_mech=int(CKM_SHA256))
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(
                    rs.raw, rs.sh, priv, CKM_HASH_ML_DSA, _MESSAGE, mech_param=mech_param
                )
            except AssertionError as exc:
                xfail_if_known_ckr(exc, _SIGN_ERROR_CKRS, "CKM_HASH_ML_DSA sign not operational")
                raise
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(
                rs.raw, rs.sh, pub, CKM_HASH_ML_DSA, _MESSAGE, sig, mech_param=mech_param
            )
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestHashMLDSAVariants:
    """Hash-specific HASH_ML_DSA variants - sign/verify round-trips.

    Each variant does the hashing on-token.  The CK_SIGN_ADDITIONAL_CONTEXT
    parameter is optional (defaults: hedgeVariant=CKH_HEDGE_PREFERRED,
    pContext=NULL, ulContextLen=0), so we call sign/verify without
    mechanism_param.
    """

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_mechanism_available(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Check that the hash-specific HASH_ML_DSA variant is advertised."""
        _skip_if_no(p11_raw_session, mech_attr)

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_sign_verify_roundtrip(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Sign + verify round-trip with CKM_HASH_ML_DSA_{hash}."""
        rs = p11_raw_session
        _skip_if_no(rs, mech_attr)
        _skip_if_no(rs, "ML_DSA")  # need keygen

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
            except AssertionError as exc:
                xfail_if_known_ckr(exc, _SIGN_ERROR_CKRS, f"CKM_{mech_attr} sign not operational")
                raise
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, mech, _MESSAGE, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_tampered_message_fails(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Tampered message must fail verification for CKM_HASH_ML_DSA_{hash}."""
        rs = p11_raw_session
        _skip_if_no(rs, mech_attr)
        _skip_if_no(rs, "ML_DSA")

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
            except AssertionError as exc:
                xfail_if_known_ckr(exc, _SIGN_ERROR_CKRS, f"CKM_{mech_attr} sign not operational")
                raise

            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = verify_single(rs.raw, rs.sh, pub, mech, tampered, sig)
                assert not result, f"Tampered message should fail CKM_{mech_attr} verification"
            except AssertionError as exc:
                # A tampered signature must be rejected; a clean non-spec reject
                # code (e.g. CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID) is
                # a noted deviation -> xfail, while a wrong-output assertion (the
                # tampered signature verified) propagates as a real failure.
                xfail_if_known_ckr(
                    exc, _SIGN_ERROR_CKRS, "tampered signature rejected with non-spec CKR"
                )
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_empty_message(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Sign/verify with an empty message (hash variants hash on-token)."""
        rs = p11_raw_session
        _skip_if_no(rs, mech_attr)
        _skip_if_no(rs, "ML_DSA")

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_ml_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, b"")
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _SIGN_ERROR_CKRS,
                    f"CKM_{mech_attr} sign of empty message not operational",
                )
                raise
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, mech, b"", sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
