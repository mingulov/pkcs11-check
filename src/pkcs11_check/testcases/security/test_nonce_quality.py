"""ECDSA nonce quality analysis.

Tests for nonce reuse, bias, and deterministic signature generation.
A weak nonce leads to private key recovery.

Based on Trail of Bits "ECDSA: Handle with Care" and PuTTY CVE-2024-31497.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

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
from pkcs11_check.testcases.conftest import gen_ec_keypair_or_xfail

pytestmark = pytest.mark.security


class TestECDSANonceReuse:
    """Check if ECDSA nonce (k) is ever reused - instant key recovery if so."""

    def test_nonce_reuse_p256(self, p11_raw_session: Any) -> None:
        """Sign same message 50 times - all r values must be unique.

        If r repeats, the nonce was reused and the private key is recoverable.
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
            message = b"nonce reuse test message"
            digest = hashlib.sha256(message).digest()

            r_values: list[int] = []
            for _ in range(50):
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r = int.from_bytes(sig[:32], "big")
                r_values.append(r)

            unique_r = set(r_values)
            if len(unique_r) < len(r_values):
                # Count how many are duplicated
                dupes = len(r_values) - len(unique_r)
                pytest.fail(
                    f"CRITICAL: ECDSA nonce reuse detected! "
                    f"{dupes} duplicate r values in {len(r_values)} signatures. "
                    f"Private key is recoverable."
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_different_messages_different_r(self, p11_raw_session: Any) -> None:
        """Different messages should produce different r values."""
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
            r_values = []
            for i in range(20):
                digest = hashlib.sha256(f"message {i}".encode()).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r = int.from_bytes(sig[:32], "big")
                r_values.append(r)

            unique_r = set(r_values)
            assert len(unique_r) == len(r_values), "r values should all be unique"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSADeterminism:
    """Check if module uses deterministic ECDSA (RFC 6979)."""

    def test_deterministic_check(self, p11_raw_session: Any) -> None:
        """Sign same message twice - if r,s are identical, nonces are deterministic.

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
                pass  # Deterministic ECDSA (RFC 6979) - good
            else:
                pass  # Random ECDSA - acceptable, but check nonce quality
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSANonceBias:
    """Check for nonce bias - biased nonces enable lattice-based key recovery."""

    def test_r_value_distribution(self, p11_raw_session: Any) -> None:
        """Generate 200 signatures and check r values aren't biased.

        Specifically checks for the PuTTY-style bias (CVE-2024-31497)
        where upper bits of the nonce are zero.
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
            # Collect r values
            r_values = []
            for i in range(200):
                digest = hashlib.sha256(f"bias test {i}".encode()).digest()
                sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
                r = int.from_bytes(sig[:32], "big")
                r_values.append(r)

            # Check upper bit bias: count how many r values have the MSB as 0
            # For a 256-bit curve, ~50% should have bit 255 set
            msb_set = sum(1 for r in r_values if r >> 255)
            ratio = msb_set / len(r_values)

            # Allow 30%-70% range (very generous - real bias would show <10% or >90%)
            if ratio < 0.30 or ratio > 0.70:
                pytest.fail(
                    f"SECURITY: ECDSA nonce MSB bias detected - "
                    f"{msb_set}/{len(r_values)} ({ratio:.1%}) have MSB set "
                    f"(expected ~50%)"
                )

            # Check for short nonces (upper bytes all zero)
            short_nonces = sum(1 for r in r_values if r < (1 << 240))
            if short_nonces > 5:
                pytest.fail(
                    f"SECURITY: {short_nonces}/{len(r_values)} signatures have "
                    f"short nonces (<240 bits) - lattice attack may be feasible"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
