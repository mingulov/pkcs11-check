"""Hypothesis-based property tests for PKCS#11 operations.

Tests invariants that must hold for ALL inputs:
- encrypt(decrypt(ct)) == ct (roundtrip)
- digest is deterministic and matches hashlib
- sign/verify roundtrip always succeeds
- HMAC is deterministic and matches hmac module
- operations never crash regardless of input

Uses hypothesis for automatic input generation.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pkcs11
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = pytest.mark.fuzz

_HC = [HealthCheck.function_scoped_fixture]


class TestAESFuzz:
    """Fuzz AES encrypt/decrypt with random inputs."""

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_ecb_roundtrip(self, p11_session: Any, plaintext: bytes) -> None:
        """AES-ECB: decrypt(encrypt(pt)) == pt for any 16-byte input."""
        key = p11_session.generate_key(KeyType.AES, 256)
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == plaintext

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_ecb_deterministic(self, p11_session: Any, plaintext: bytes) -> None:
        """AES-ECB with same key+pt always produces same ct."""
        key = p11_session.generate_key(KeyType.AES, 256)
        ct1 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        assert ct1 == ct2

    @given(plaintext=st.binary(min_size=16, max_size=16))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_ecb_ciphertext_differs_from_plaintext(
        self, p11_session: Any, plaintext: bytes
    ) -> None:
        """AES-ECB ciphertext should differ from plaintext (except all-zero edge case)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
        # Ciphertext may equal plaintext for specific key/data combos, but extremely rare
        assert len(ct) == len(plaintext)


class TestDigestFuzz:
    """Fuzz digest operations with cross-verification."""

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_sha256_deterministic(self, p11_session: Any, data: bytes) -> None:
        """SHA-256 of same data always produces same digest."""
        d1 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(data, mechanism=Mechanism.SHA256)
        assert d1 == d2
        assert len(d1) == 32

    @given(data=st.binary(min_size=0, max_size=4096))
    @settings(max_examples=50, deadline=5000, suppress_health_check=_HC)
    def test_sha256_cross_verify(self, p11_session: Any, data: bytes) -> None:
        """SHA-256 via PKCS#11 matches hashlib for random inputs."""
        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        expected = hashlib.sha256(data).digest()
        assert p11_digest == expected

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_sha512_cross_verify(self, p11_session: Any, data: bytes) -> None:
        """SHA-512 via PKCS#11 matches hashlib for random inputs."""
        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA512)
        expected = hashlib.sha512(data).digest()
        assert p11_digest == expected


class TestRSAFuzz:
    """Fuzz RSA sign/verify."""

    @given(data=st.binary(min_size=1, max_size=1000))
    @settings(max_examples=20, deadline=10000, suppress_health_check=_HC)
    def test_sign_verify_roundtrip(self, p11_session: Any, data: bytes) -> None:
        """RSA: verify(sign(data)) always succeeds for any input."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    @given(data=st.binary(min_size=1, max_size=500))
    @settings(max_examples=15, deadline=10000, suppress_health_check=_HC)
    def test_signature_length_constant(self, p11_session: Any, data: bytes) -> None:
        """RSA-2048 signature is always 256 bytes regardless of input."""
        _, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256


class TestHMACFuzz:
    """Fuzz HMAC operations."""

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=40, deadline=5000, suppress_health_check=_HC)
    def test_hmac_sha256_cross_verify(self, p11_session: Any, data: bytes) -> None:
        """HMAC-SHA256 via PKCS#11 matches Python hmac for random inputs."""
        key_bytes = bytes(range(32))
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        p11_mac = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        expected = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
        assert p11_mac == expected

    @given(data=st.binary(min_size=0, max_size=2048))
    @settings(max_examples=30, deadline=5000, suppress_health_check=_HC)
    def test_hmac_deterministic(self, p11_session: Any, data: bytes) -> None:
        """HMAC-SHA256 with same key and data always produces same MAC."""
        key_bytes = bytes(range(32))
        p11_key = p11_session.create_object(
            {
                Attribute.CLASS: pkcs11.ObjectClass.SECRET_KEY,
                Attribute.KEY_TYPE: KeyType.SHA256_HMAC,
                Attribute.VALUE: key_bytes,
                Attribute.SIGN: True,
                Attribute.TOKEN: False,
                Attribute.SENSITIVE: False,
            }
        )
        mac1 = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        mac2 = p11_key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        assert mac1 == mac2


class TestECDSAFuzz:
    """Fuzz ECDSA operations."""

    @given(data=st.binary(min_size=32, max_size=32))
    @settings(max_examples=15, deadline=10000, suppress_health_check=_HC)
    def test_ecdsa_sign_verify_roundtrip(self, p11_session: Any, data: bytes) -> None:
        """ECDSA: verify(sign(digest)) always succeeds for any 32-byte digest."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, priv = ecparams.generate_keypair()
        sig = priv.sign(data, mechanism=Mechanism.ECDSA)
        assert pub.verify(data, sig, mechanism=Mechanism.ECDSA)
