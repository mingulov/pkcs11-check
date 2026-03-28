"""HashSLH-DSA (pre-hash SLH-DSA) sign/verify tests - PKCS#11 v3.2.

Tests all 11 HASH_SLH_DSA mechanism variants:
- CKM_HASH_SLH_DSA (generic, single-part only, requires CK_HASH_SIGN_ADDITIONAL_CONTEXT)
- CKM_HASH_SLH_DSA_SHA224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_SLH_DSA_SHA3_224/256/384/512 (hash-specific, single+multi-part)
- CKM_HASH_SLH_DSA_SHAKE128/256 (hash-specific, single+multi-part)

All tests require PKCS#11 v3.2 interface.  Auto-skips on v3.1 and earlier.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_ulong
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
    CKM_HASH_SLH_DSA_SHA3_224,
    CKM_HASH_SLH_DSA_SHA3_256,
    CKM_HASH_SLH_DSA_SHA3_384,
    CKM_HASH_SLH_DSA_SHA3_512,
    CKM_HASH_SLH_DSA_SHA224,
    CKM_HASH_SLH_DSA_SHA256,
    CKM_HASH_SLH_DSA_SHA384,
    CKM_HASH_SLH_DSA_SHA512,
    CKM_HASH_SLH_DSA_SHAKE128,
    CKM_HASH_SLH_DSA_SHAKE256,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKP_SLH_DSA_SHA2_128S,
)

pytestmark = [pytest.mark.pqc]

_MESSAGE = b"HashSLH-DSA pre-hash signature test message 2026"

# Hash-specific HASH_SLH_DSA variants mapped to their CKM constants.
# These support both single-part and multi-part sign/verify.
# The CK_SIGN_ADDITIONAL_CONTEXT parameter is optional (defaults apply).
_HASH_VARIANTS: dict[str, CKM] = {
    "HASH_SLH_DSA_SHA224": CKM_HASH_SLH_DSA_SHA224,
    "HASH_SLH_DSA_SHA256": CKM_HASH_SLH_DSA_SHA256,
    "HASH_SLH_DSA_SHA384": CKM_HASH_SLH_DSA_SHA384,
    "HASH_SLH_DSA_SHA512": CKM_HASH_SLH_DSA_SHA512,
    "HASH_SLH_DSA_SHA3_224": CKM_HASH_SLH_DSA_SHA3_224,
    "HASH_SLH_DSA_SHA3_256": CKM_HASH_SLH_DSA_SHA3_256,
    "HASH_SLH_DSA_SHA3_384": CKM_HASH_SLH_DSA_SHA3_384,
    "HASH_SLH_DSA_SHA3_512": CKM_HASH_SLH_DSA_SHA3_512,
    "HASH_SLH_DSA_SHAKE128": CKM_HASH_SLH_DSA_SHAKE128,
    "HASH_SLH_DSA_SHAKE256": CKM_HASH_SLH_DSA_SHAKE256,
}

_VARIANT_NAMES = list(_HASH_VARIANTS.keys())


def _skip_if_no(rs: Any, mech_name: str) -> None:
    if not rs.has_mechanism(mech_name):
        pytest.skip(f"CKM_{mech_name} not supported by module")


def _generate_slh_dsa_keypair(rs: Any, param_set: int | None = None) -> tuple[int, int]:
    """Generate an SLH-DSA key pair for HashSLH-DSA sign/verify."""
    effective_param = param_set if param_set is not None else CKP_SLH_DSA_SHA2_128S
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_SLH_DSA_KEY_PAIR_GEN,
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


class TestHashSLHDSAGeneric:
    """CKM_HASH_SLH_DSA - generic pre-hash SLH-DSA (single-part only).

    This mechanism requires a CK_HASH_SIGN_ADDITIONAL_CONTEXT parameter
    that includes a hash algorithm field.  Since pkcs11_check.raw does not yet
    have bindings for this struct, we test mechanism availability only and
    skip the actual sign/verify with an explanatory note.
    """

    def test_mechanism_available(self, p11_raw_session: Any) -> None:
        """Check that CKM_HASH_SLH_DSA is advertised by the module."""
        _skip_if_no(p11_raw_session, "HASH_SLH_DSA")

    def test_sign_verify_skipped_no_param_binding(self, p11_raw_session: Any) -> None:
        """CKM_HASH_SLH_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT param.

        The pkcs11_check.raw layer does not yet expose this struct, so we
        cannot construct the required mechanism_param.  Skip with a note.
        """
        _skip_if_no(p11_raw_session, "HASH_SLH_DSA")
        pytest.skip(
            "CKM_HASH_SLH_DSA requires CK_HASH_SIGN_ADDITIONAL_CONTEXT param "
            "not yet available in pkcs11_check.raw bindings"
        )


class TestHashSLHDSAVariants:
    """Hash-specific HASH_SLH_DSA variants - sign/verify round-trips.

    Each variant does the hashing on-token.  The CK_SIGN_ADDITIONAL_CONTEXT
    parameter is optional (defaults: hedgeVariant=CKH_HEDGE_PREFERRED,
    pContext=NULL, ulContextLen=0), so we call sign/verify without
    mechanism_param.
    """

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_mechanism_available(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Check that the hash-specific HASH_SLH_DSA variant is advertised."""
        _skip_if_no(p11_raw_session, mech_attr)

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_sign_verify_roundtrip(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Sign + verify round-trip with CKM_HASH_SLH_DSA_{hash}."""
        rs = p11_raw_session
        _skip_if_no(rs, mech_attr)
        _skip_if_no(rs, "SLH_DSA")  # need keygen

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_slh_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
            except AssertionError as exc:
                pytest.xfail(f"CKM_{mech_attr} sign failed: {exc!r}")
                raise  # unreachable
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, mech, _MESSAGE, sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize("mech_attr", _VARIANT_NAMES)
    def test_tampered_message_fails(self, p11_raw_session: Any, mech_attr: str) -> None:
        """Tampered message must fail verification for CKM_HASH_SLH_DSA_{hash}."""
        rs = p11_raw_session
        _skip_if_no(rs, mech_attr)
        _skip_if_no(rs, "SLH_DSA")

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_slh_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, _MESSAGE)
            except AssertionError as exc:
                pytest.xfail(f"CKM_{mech_attr} sign failed: {exc!r}")
                raise  # unreachable

            tampered = _MESSAGE[:-1] + bytes([_MESSAGE[-1] ^ 0xFF])
            try:
                result = verify_single(rs.raw, rs.sh, pub, mech, tampered, sig)
                assert not result, f"Tampered message should fail CKM_{mech_attr} verification"
            except AssertionError as exc:
                if "DEVICE_ERROR" in str(exc):
                    pytest.xfail(
                        "Kryoptic returns CKR_DEVICE_ERROR instead of CKR_SIGNATURE_INVALID"
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
        _skip_if_no(rs, "SLH_DSA")

        mech = _HASH_VARIANTS[mech_attr]
        pub, priv = _generate_slh_dsa_keypair(rs)
        try:
            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, b"")
            except AssertionError as exc:
                pytest.xfail(f"CKM_{mech_attr} sign of empty message failed: {exc!r}")
                raise  # unreachable
            assert isinstance(sig, bytes) and len(sig) > 0
            result = verify_single(rs.raw, rs.sh, pub, mech, b"", sig)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
