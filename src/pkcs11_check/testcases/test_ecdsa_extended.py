"""Tests for ECDSA prehash sign/verify variants.

Covers CKM_ECDSA_SHA1, CKM_ECDSA_SHA224, and CKM_ECDSA_SHA3_* mechanisms.
Basic CKM_ECDSA (raw) is tested in test_sign.py.
Uses the raw PKCS#11 API via pkcs11_check.raw.

OASIS PKCS#11 v3.2 spec: elliptic curves.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA3_224,
    CKM_ECDSA_SHA3_256,
    CKM_ECDSA_SHA3_384,
    CKM_ECDSA_SHA3_512,
    CKM_ECDSA_SHA224,
)
from pkcs11_check.testcases._ec_export import SECP256R1_ORDER, parse_raw_dss_or_classify
from pkcs11_check.testcases._signature_policy import (
    signature_rejected_or_xfail,
    xfail_if_op_not_operational,
)

pytestmark = pytest.mark.sign

# Distinct-message sample size for the repeated-r invariant below.
_DISTINCT_MESSAGE_SAMPLES = 20

_ECDSA_HASH_MECHS = [
    pytest.param("ECDSA_SHA1", CKM_ECDSA_SHA1, id="SHA1"),
    pytest.param("ECDSA_SHA224", CKM_ECDSA_SHA224, id="SHA224"),
    pytest.param("ECDSA_SHA3_224", CKM_ECDSA_SHA3_224, id="SHA3-224"),
    pytest.param("ECDSA_SHA3_256", CKM_ECDSA_SHA3_256, id="SHA3-256"),
    pytest.param("ECDSA_SHA3_384", CKM_ECDSA_SHA3_384, id="SHA3-384"),
    pytest.param("ECDSA_SHA3_512", CKM_ECDSA_SHA3_512, id="SHA3-512"),
]


class TestECDSAPrehash:
    """ECDSA prehash sign/verify - mechanism handles hashing internally."""

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_sign_verify_roundtrip(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Sign raw message data and verify succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            data = b"ECDSA prehash roundtrip test data"
            try:
                signature = sign_single(rs.raw, rs.sh, priv, mech, data)
            except AssertionError as exc:
                # Advertised but the sign refused at runtime (e.g. FIPS-deprecated
                # SHA-1 -> CKR_DEVICE_ERROR): not operational, not a break.
                xfail_if_op_not_operational(exc, f"CKM_{mech_name}")
            assert len(signature) > 0

            result = verify_single(rs.raw, rs.sh, pub, mech, data, signature)
            assert result is True
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_tampered_data_fails(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Verify with wrong data must fail."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            original = b"original message for ECDSA"
            tampered = b"tampered message for ECDSA"

            try:
                sig = sign_single(rs.raw, rs.sh, priv, mech, original)
            except AssertionError as exc:
                xfail_if_op_not_operational(exc, f"CKM_{mech_name}")
            try:
                result = verify_single(rs.raw, rs.sh, pub, mech, tampered, sig)
            except AssertionError as exc:
                if signature_rejected_or_xfail(exc, f"CKM_{mech_name}") is False:
                    return
                raise
            assert result is False, f"CKM_{mech_name}: verify with tampered data should fail"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(("mech_name", "mech"), _ECDSA_HASH_MECHS)
    def test_deterministic_signing_distinct_r(
        self,
        p11_raw_session: Any,
        mech_name: str,
        mech: Any,
    ) -> None:
        """Same-message resignature passes (deterministic signing is valid).

        Identical signatures for the same message are valid deterministic DSS
        behavior (RFC 6979 / FIPS 186-5), not nonce reuse. The adverse
        invariant is a repeated valid ``r`` across distinct messages, which
        signals equivalent-nonce reuse.
        """
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"CKM_{mech_name} not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            label = f"CKM_{mech_name}:sign deterministic signing"
            data = b"nonce uniqueness test for ECDSA prehash"
            try:
                sig1 = sign_single(rs.raw, rs.sh, priv, mech, data)
            except AssertionError as exc:
                xfail_if_op_not_operational(exc, f"CKM_{mech_name}")
            parse_raw_dss_or_classify(
                sig1,
                half_len=32,
                order=SECP256R1_ORDER,
                label=label,
                operation="C_Sign",
                mechanism=f"CKM_{mech_name}",
            )
            sig2 = sign_single(rs.raw, rs.sh, priv, mech, data)
            parse_raw_dss_or_classify(
                sig2,
                half_len=32,
                order=SECP256R1_ORDER,
                label=label,
                operation="C_Sign",
                mechanism=f"CKM_{mech_name}",
            )
            if sig1 == sig2:
                note(
                    f"CKM_{mech_name}: identical signatures for the same message "
                    "(deterministic signing; valid per RFC 6979 / FIPS 186-5)",
                    ComplianceLevel.STANDARD,
                    reference="RFC 6979; FIPS 186-5",
                )
            else:
                note(
                    f"CKM_{mech_name}: varying signatures for the same message "
                    "(randomized signing)",
                    ComplianceLevel.EXTENDED,
                    reference="RFC 6979; FIPS 186-5",
                )
            seen_r: dict[int, int] = {}
            for i in range(_DISTINCT_MESSAGE_SAMPLES):
                message = f"ECDSA prehash distinct message {i}".encode()
                sig = sign_single(rs.raw, rs.sh, priv, mech, message)
                r, _ = parse_raw_dss_or_classify(
                    sig,
                    half_len=32,
                    order=SECP256R1_ORDER,
                    label=f"CKM_{mech_name}:sign distinct-message r",
                    operation="C_Sign",
                    mechanism=f"CKM_{mech_name}",
                )
                if r in seen_r:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label=f"CKM_{mech_name}:sign distinct-message r",
                        operation="C_Sign",
                        mechanism=f"CKM_{mech_name}",
                        summary=(
                            f"CKM_{mech_name}: repeated valid r across distinct messages "
                            f"(samples {seen_r[r]} and {i}); dangerous "
                            "equivalent-nonce reuse signal"
                        ),
                        detail={
                            "first_index": seen_r[r],
                            "repeat_index": i,
                            "samples": _DISTINCT_MESSAGE_SAMPLES,
                            "r_bit_length": r.bit_length(),
                        },
                    )
                seen_r[r] = i
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
