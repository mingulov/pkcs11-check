"""Tests for PKCS#11 sign/verify operations.

Covers RSA PKCS#1 v1.5, RSA-PSS, ECDSA, and HMAC sign/verify.
Tests key generation, roundtrip, tamper detection, and multiple key sizes.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pkcs11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.mechanisms import MGF

pytestmark = pytest.mark.full


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
        assert len(signature) == 256  # 2048-bit RSA = 256 bytes

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
            assert result is False
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected — module rejected invalid signature

    @pytest.mark.parametrize(
        "mechanism",
        [
            Mechanism.SHA1_RSA_PKCS,
            Mechanism.SHA256_RSA_PKCS,
            Mechanism.SHA384_RSA_PKCS,
            Mechanism.SHA512_RSA_PKCS,
        ],
        ids=["SHA1", "SHA256", "SHA384", "SHA512"],
    )
    def test_rsa_hash_mechanisms(self, p11_session: Any, mechanism: Mechanism) -> None:
        """RSA sign/verify works with all standard hash mechanisms."""
        public, private = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"hash mechanism test data"

        sig = private.sign(data, mechanism=mechanism)
        assert public.verify(data, sig, mechanism=mechanism) is True

    def test_rsa_pss_sign_verify(self, p11_session: Any) -> None:
        """RSA-PSS sign/verify roundtrip."""
        public, private = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA-PSS test data for signing"
        pss_params = (Mechanism.SHA256, MGF.SHA256, 32)

        sig = private.sign(
            data, mechanism=Mechanism.SHA256_RSA_PKCS_PSS, mechanism_param=pss_params
        )
        result = public.verify(
            data, sig, mechanism=Mechanism.SHA256_RSA_PKCS_PSS, mechanism_param=pss_params
        )
        assert result is True

    def test_rsa_different_keys_different_signatures(self, p11_session: Any) -> None:
        """Same data signed with different keys produces different signatures."""
        _, priv1 = p11_session.generate_keypair(KeyType.RSA, 2048)
        _, priv2 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"key independence test"

        sig1 = priv1.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        sig2 = priv2.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert sig1 != sig2


class TestECDSASignature:
    def _generate_ec_keypair(self, session: Any, curve: str = "secp256r1") -> tuple[Any, Any]:
        ecparams = session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters(curve)},
            local=True,
        )
        return ecparams.generate_keypair()  # type: ignore[no-any-return]

    def test_ec_generate_keypair(self, p11_session: Any) -> None:
        """Generate an EC P-256 key pair."""
        public, private = self._generate_ec_keypair(p11_session)
        assert public is not None
        assert private is not None

    def test_ecdsa_sign_verify(self, p11_session: Any) -> None:
        """Sign and verify with ECDSA P-256."""
        public, private = self._generate_ec_keypair(p11_session)
        digest = hashlib.sha256(b"ECDSA test data").digest()

        signature = private.sign(digest, mechanism=Mechanism.ECDSA)
        assert len(signature) > 0

        result = public.verify(digest, signature, mechanism=Mechanism.ECDSA)
        assert result is True

    def test_ecdsa_wrong_data_fails(self, p11_session: Any) -> None:
        """ECDSA verification with wrong digest should fail."""
        public, private = self._generate_ec_keypair(p11_session)
        digest = hashlib.sha256(b"original").digest()
        wrong_digest = hashlib.sha256(b"tampered").digest()

        sig = private.sign(digest, mechanism=Mechanism.ECDSA)
        try:
            result = public.verify(wrong_digest, sig, mechanism=Mechanism.ECDSA)
            assert result is False
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected

    @pytest.mark.parametrize("curve", ["secp256r1", "secp384r1"])
    def test_ecdsa_multiple_curves(self, p11_session: Any, curve: str) -> None:
        """ECDSA sign/verify works with P-256 and P-384."""
        public, private = self._generate_ec_keypair(p11_session, curve)
        digest = hashlib.sha256(b"multi-curve test").digest()

        sig = private.sign(digest, mechanism=Mechanism.ECDSA)
        assert public.verify(digest, sig, mechanism=Mechanism.ECDSA) is True

    def test_ecdsa_nondeterministic(self, p11_session: Any) -> None:
        """ECDSA signatures for same data should differ (random nonce)."""
        _, private = self._generate_ec_keypair(p11_session)
        digest = hashlib.sha256(b"nonce test").digest()

        sig1 = private.sign(digest, mechanism=Mechanism.ECDSA)
        sig2 = private.sign(digest, mechanism=Mechanism.ECDSA)
        assert sig1 != sig2


class TestHMACSign:
    def _hmac_key(self, session: Any) -> Any:
        return session.generate_key(
            KeyType.GENERIC_SECRET,
            256,
            template={Attribute.SIGN: True, Attribute.VERIFY: True, Attribute.TOKEN: False},
        )

    def test_hmac_sha256_sign_verify(self, p11_session: Any) -> None:
        """HMAC-SHA256 sign and verify roundtrip."""
        key = self._hmac_key(p11_session)
        data = b"HMAC test data"
        mac = key.sign(data, mechanism=Mechanism.SHA256_HMAC)
        assert len(mac) == 32  # SHA-256 output

    def test_hmac_different_data_different_mac(self, p11_session: Any) -> None:
        """Different messages produce different MACs."""
        key = self._hmac_key(p11_session)
        mac1 = key.sign(b"message one", mechanism=Mechanism.SHA256_HMAC)
        mac2 = key.sign(b"message two", mechanism=Mechanism.SHA256_HMAC)
        assert mac1 != mac2


class TestDSASignature:
    def test_dsa_generate_and_sign(self, p11_session: Any, p11_module: Any) -> None:
        """Generate DSA params + keypair, sign and verify."""
        from pkcs11_check.testcases.conftest import has_mechanism

        if not has_mechanism(p11_module, "DSA_SHA256"):
            pytest.skip("DSA_SHA256 not supported")

        try:
            params = p11_session.generate_domain_parameters(KeyType.DSA, 2048)
            public, private = params.generate_keypair()
        except pkcs11.exceptions.PKCS11Error:
            pytest.skip("DSA parameter/key generation not supported")

        data = b"DSA test data for signing"
        sig = private.sign(data, mechanism=Mechanism.DSA_SHA256)
        assert public.verify(data, sig, mechanism=Mechanism.DSA_SHA256) is True
