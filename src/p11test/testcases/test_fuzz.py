"""Hypothesis-based property tests for PKCS#11 operations.

Tests invariants that must hold for ALL inputs:
- encrypt(decrypt(ct)) == ct (roundtrip)
- digest is deterministic
- sign/verify roundtrip always succeeds
- operations never crash regardless of input

Uses hypothesis for automatic input generation.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.fuzz


class TestAESFuzz:
    """Fuzz AES encrypt/decrypt with random inputs."""

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(
        max_examples=50, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_aes_ecb_roundtrip_fuzz(self, p11_session: Any, plaintext: bytes) -> None:
        """AES-ECB: decrypt(encrypt(pt)) == pt for any 16-byte input."""
        key = p11_session.generate_key(KeyType.AES, 256)
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext
        key.destroy()

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(
        max_examples=50, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_aes_ecb_deterministic_fuzz(self, p11_session: Any, plaintext: bytes) -> None:
        """AES-ECB with same key+pt always produces same ct."""
        key = p11_session.generate_key(KeyType.AES, 256)
        ct1 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct1 == ct2
        key.destroy()


class TestDigestFuzz:
    """Fuzz digest operations."""

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(
        max_examples=50, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_sha256_deterministic_fuzz(self, p11_session: Any, data: bytes) -> None:
        """SHA-256 of same data always produces same digest."""
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2
        assert len(d1) == 32

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(
        max_examples=50, deadline=5000, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_sha256_length_fuzz(self, p11_session: Any, data: bytes) -> None:
        """SHA-256 always produces 32-byte output regardless of input."""
        d = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert len(d) == 32


class TestRSAFuzz:
    """Fuzz RSA sign/verify."""

    @given(data=st.binary(min_size=1, max_size=1000))
    @settings(
        max_examples=20, deadline=10000, suppress_health_check=[HealthCheck.function_scoped_fixture]
    )
    def test_rsa_sign_verify_roundtrip_fuzz(self, p11_session: Any, data: bytes) -> None:
        """RSA: verify(sign(data)) always succeeds for any input."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)
        pub.destroy()
        priv.destroy()
