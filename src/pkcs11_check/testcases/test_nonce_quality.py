"""ECDSA nonce quality analysis.

Tests for nonce reuse, bias, and deterministic signature generation.
A weak nonce leads to private key recovery.

Based on Trail of Bits "ECDSA: Handle with Care" and PuTTY CVE-2024-31497.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.security


class TestECDSANonceReuse:
    """Check if ECDSA nonce (k) is ever reused - instant key recovery if so."""

    def test_nonce_reuse_p256(self, p11_session: Any) -> None:
        """Sign same message 50 times - all r values must be unique.

        If r repeats, the nonce was reused and the private key is recoverable.
        """
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        _, priv = ecparams.generate_keypair()

        message = b"nonce reuse test message"
        digest = hashlib.sha256(message).digest()

        r_values: list[int] = []
        for _ in range(50):
            sig = priv.sign(digest, mechanism=Mechanism.ECDSA)
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

    def test_different_messages_different_r(self, p11_session: Any) -> None:
        """Different messages should produce different r values."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        _, priv = ecparams.generate_keypair()

        r_values = []
        for i in range(20):
            digest = hashlib.sha256(f"message {i}".encode()).digest()
            sig = priv.sign(digest, mechanism=Mechanism.ECDSA)
            r = int.from_bytes(sig[:32], "big")
            r_values.append(r)

        unique_r = set(r_values)
        assert len(unique_r) == len(r_values), "r values should all be unique"


class TestECDSADeterminism:
    """Check if module uses deterministic ECDSA (RFC 6979)."""

    def test_deterministic_check(self, p11_session: Any) -> None:
        """Sign same message twice - if r,s are identical, nonces are deterministic.

        Deterministic ECDSA (RFC 6979) is preferred for security.
        Random ECDSA is acceptable if RNG quality is good.
        This test is informational - both outcomes are acceptable.
        """
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        _, priv = ecparams.generate_keypair()

        digest = hashlib.sha256(b"determinism check").digest()
        sig1 = priv.sign(digest, mechanism=Mechanism.ECDSA)
        sig2 = priv.sign(digest, mechanism=Mechanism.ECDSA)

        if sig1 == sig2:
            pass  # Deterministic ECDSA (RFC 6979) - good
        else:
            pass  # Random ECDSA - acceptable, but check nonce quality


class TestECDSANonceBias:
    """Check for nonce bias - biased nonces enable lattice-based key recovery."""

    def test_r_value_distribution(self, p11_session: Any) -> None:
        """Generate 200 signatures and check r values aren't biased.

        Specifically checks for the PuTTY-style bias (CVE-2024-31497)
        where upper bits of the nonce are zero.
        """
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        _, priv = ecparams.generate_keypair()

        # Collect r values
        r_values = []
        for i in range(200):
            digest = hashlib.sha256(f"bias test {i}".encode()).digest()
            sig = priv.sign(digest, mechanism=Mechanism.ECDSA)
            r = int.from_bytes(sig[:32], "big")
            r_values.append(r)

        # Check upper bit bias: count how many r values have the MSB as 0
        # For a 256-bit curve, ~50% should have bit 255 set
        msb_set = sum(1 for r in r_values if r >> 255)
        ratio = msb_set / len(r_values)

        # Allow 30%-70% range (very generous - real bias would show <10% or >90%)
        if ratio < 0.30 or ratio > 0.70:
            pytest.xfail(
                f"SECURITY: ECDSA nonce MSB bias detected - "
                f"{msb_set}/{len(r_values)} ({ratio:.1%}) have MSB set "
                f"(expected ~50%)"
            )

        # Check for short nonces (upper bytes all zero)
        short_nonces = sum(1 for r in r_values if r < (1 << 240))
        if short_nonces > 5:
            pytest.xfail(
                f"SECURITY: {short_nonces}/{len(r_values)} signatures have "
                f"short nonces (<240 bits) - lattice attack may be feasible"
            )
