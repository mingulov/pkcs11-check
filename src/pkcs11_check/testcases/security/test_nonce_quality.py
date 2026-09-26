"""ECDSA signing-behavior analysis.

Same-message deterministic ECDSA (RFC 6979 / FIPS 186-5) is valid and is not
nonce reuse. The adverse invariant is a repeated valid public ``r`` across
distinct messages/digests -- an equivalent-nonce reuse signal. Public ``r``
is ``x(kG) mod n``, not the secret nonce ``k``: its distribution is a
non-normative diagnostic that cannot support secret-value bias or
key-recovery claims.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
    CKM_ECDSA,
)
from pkcs11_check.testcases._ec_export import SECP256R1_ORDER, parse_raw_dss_or_classify
from pkcs11_check.testcases.conftest import gen_ec_keypair_or_xfail

pytestmark = pytest.mark.security

# Distinct-digest sample size for the repeated-r invariant below.
_NONCE_REUSE_SAMPLES = 50

# Public-r sample size for the distribution diagnostic below.
_DISTRIBUTION_SAMPLES = 200


class TestECDSANonceReuse:
    """Repeated valid r across distinct digests signals equivalent-nonce reuse."""

    def test_nonce_reuse_p256(self, p11_raw_session: Any) -> None:
        """Sign 50 distinct digests - all valid r values must be unique.

        A repeated valid ``r`` across distinct digests is a dangerous
        equivalent-nonce reuse signal. Same-digest repetition is valid
        deterministic signing, not reuse; key recovery is not claimed without
        performing it.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )

        try:
            seen_r: dict[int, int] = {}
            for i in range(_NONCE_REUSE_SAMPLES):
                digest = hashlib.sha256(f"nonce-reuse distinct digest {i}".encode()).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r, _ = parse_raw_dss_or_classify(
                    sig,
                    half_len=32,
                    order=SECP256R1_ORDER,
                    label="CKM_ECDSA:sign distinct-digest r",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                )
                if r in seen_r:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="CKM_ECDSA:sign distinct-digest r",
                        operation="C_Sign",
                        mechanism="CKM_ECDSA",
                        summary=(
                            "CKM_ECDSA: repeated valid r across distinct digests "
                            f"(samples {seen_r[r]} and {i} of {_NONCE_REUSE_SAMPLES}); "
                            "dangerous equivalent-nonce reuse signal"
                        ),
                        detail={
                            "first_index": seen_r[r],
                            "repeat_index": i,
                            "samples": _NONCE_REUSE_SAMPLES,
                            "r_bit_length": r.bit_length(),
                        },
                    )
                seen_r[r] = i
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_different_messages_different_r(self, p11_raw_session: Any) -> None:
        """Different messages must produce different valid r values."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )

        try:
            seen_r: dict[int, int] = {}
            for i in range(20):
                digest = hashlib.sha256(f"message {i}".encode()).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r, _ = parse_raw_dss_or_classify(
                    sig,
                    half_len=32,
                    order=SECP256R1_ORDER,
                    label="CKM_ECDSA:sign distinct-digest r",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                )
                if r in seen_r:
                    fail_as(
                        "wrong_result",
                        kind="crypto",
                        label="CKM_ECDSA:sign distinct-digest r",
                        operation="C_Sign",
                        mechanism="CKM_ECDSA",
                        summary=(
                            "CKM_ECDSA: repeated valid r across distinct digests "
                            f"(samples {seen_r[r]} and {i} of 20); "
                            "dangerous equivalent-nonce reuse signal"
                        ),
                        detail={
                            "first_index": seen_r[r],
                            "repeat_index": i,
                            "samples": 20,
                            "r_bit_length": r.bit_length(),
                        },
                    )
                seen_r[r] = i
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSADeterminism:
    """Check if module uses deterministic ECDSA (RFC 6979)."""

    def test_deterministic_check(self, p11_raw_session: Any) -> None:
        """Sign same message twice - record whether signatures are deterministic.

        Deterministic ECDSA (RFC 6979) is preferred for security.
        Random ECDSA is acceptable if RNG quality is good.
        This test is informational - both outcomes are acceptable.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )

        try:
            digest = hashlib.sha256(b"determinism check").digest()
            sig1 = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            sig2 = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)

            if sig1 == sig2:
                note(
                    "CKM_ECDSA: identical signatures for the same digest "
                    "(deterministic signing; valid per RFC 6979 / FIPS 186-5)",
                    ComplianceLevel.STANDARD,
                    reference="RFC 6979; FIPS 186-5",
                )
            else:
                note(
                    "CKM_ECDSA: varying signatures for the same digest (randomized signing)",
                    ComplianceLevel.EXTENDED,
                    reference="RFC 6979; FIPS 186-5",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSAPublicRDistribution:
    """Public-r distribution diagnostic (non-normative)."""

    def test_public_r_distribution(self, p11_raw_session: Any) -> None:
        """Collect 200 public r values and record their distribution.

        Public-``r`` MSB/small-value counts are a serialized diagnostic only:
        ``r`` is public output, not the secret signing value, so no bias or
        key-recovery conclusion is drawn. This test never fails on
        distribution; malformed signature shape still fails at parse time.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
        )

        try:
            r_values: list[int] = []
            for i in range(_DISTRIBUTION_SAMPLES):
                digest = hashlib.sha256(f"r-distribution diagnostic {i}".encode()).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r, _ = parse_raw_dss_or_classify(
                    sig,
                    half_len=32,
                    order=SECP256R1_ORDER,
                    label="CKM_ECDSA:sign public r sample",
                    operation="C_Sign",
                    mechanism="CKM_ECDSA",
                )
                r_values.append(r)

            msb_set = sum(1 for r in r_values if r >> 255)
            ratio = msb_set / len(r_values)
            small_r = sum(1 for r in r_values if r < (1 << 240))
            note(
                f"CKM_ECDSA public r distribution over {len(r_values)} signatures (P-256): "
                f"{msb_set}/{len(r_values)} with MSB set ({ratio:.1%}), "
                f"{small_r} with r < 2^240; public-output diagnostic only",
                ComplianceLevel.EXTENDED,
                reference="FIPS 186-5",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
