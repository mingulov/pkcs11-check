"""Tests for PKCS#11 sign/verify operations."""

from __future__ import annotations

from typing import Any

import pkcs11
from pkcs11 import KeyType, Mechanism


class TestRSASignature:
    def test_rsa_generate_keypair(self, p11_session: Any) -> None:
        """Generate an RSA-2048 key pair."""
        public, private = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert public is not None
        assert private is not None

    def test_rsa_pkcs_sign_verify(self, p11_session: Any) -> None:
        """Sign data with RSA PKCS#1 v1.5 and verify."""
        public, private = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"test data for PKCS#11 signing"

        signature = private.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(signature) > 0
        assert len(signature) == 256  # 2048-bit RSA = 256 bytes

        # verify returns True or raises
        result = public.verify(data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert result is True

    def test_rsa_sign_wrong_data_fails_verify(self, p11_session: Any) -> None:
        """Verification with wrong data should fail."""
        public, private = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"original data"
        wrong_data = b"tampered data"

        signature = private.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        try:
            result = public.verify(wrong_data, signature, mechanism=Mechanism.SHA256_RSA_PKCS)
            # Some implementations return False, others raise
            assert result is False
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected — module rejected invalid signature


class TestECDSASignature:
    def test_ec_generate_keypair(self, p11_session: Any) -> None:
        """Generate an EC P-256 key pair."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        public, private = ecparams.generate_keypair()
        assert public is not None
        assert private is not None

    def test_ecdsa_sign_verify(self, p11_session: Any) -> None:
        """Sign and verify with ECDSA P-256."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        public, private = ecparams.generate_keypair()
        # ECDSA mechanism takes a pre-hashed digest (32 bytes for SHA-256)
        import hashlib

        data = b"ECDSA test data"
        digest = hashlib.sha256(data).digest()

        signature = private.sign(digest, mechanism=Mechanism.ECDSA)
        assert len(signature) > 0

        result = public.verify(digest, signature, mechanism=Mechanism.ECDSA)
        assert result is True
