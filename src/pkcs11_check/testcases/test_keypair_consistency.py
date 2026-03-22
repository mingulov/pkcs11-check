"""Keypair attribute consistency tests.

Verifies that public and private keys in a generated keypair have
consistent attributes - modulus matches for RSA, EC params match for EC.
Catches bugs where modules produce mathematically inconsistent keypairs.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt


class TestRSAKeypairConsistency:
    """Verify RSA keypair attribute consistency."""

    def test_modulus_matches(self, p11_session: Any, p11_module: Any) -> None:
        """Public and private RSA key have the same modulus."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        pub_modulus = pub[Attribute.MODULUS]
        priv_modulus = priv[Attribute.MODULUS]
        assert pub_modulus == priv_modulus, "RSA modulus mismatch between pub and priv"

    def test_public_exponent_matches(self, p11_session: Any, p11_module: Any) -> None:
        """Public exponent is the same on both keys."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)

        pub_exp = pub[Attribute.PUBLIC_EXPONENT]
        priv_exp = priv[Attribute.PUBLIC_EXPONENT]
        assert pub_exp == priv_exp, "RSA public exponent mismatch"

    def test_modulus_correct_size(self, p11_session: Any, p11_module: Any) -> None:
        """RSA-2048 modulus is 256 bytes (2048 bits)."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, _priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        modulus = pub[Attribute.MODULUS]
        assert len(modulus) == 256, f"Expected 256-byte modulus, got {len(modulus)}"


class TestECKeypairConsistency:
    """Verify EC keypair attribute consistency."""

    def test_ec_params_match(self, p11_session: Any, p11_module: Any) -> None:
        """Public and private EC key have the same CKA_EC_PARAMS."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub, priv = params.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip("secp256r1 not supported")
            return

        pub_params = pub[Attribute.EC_PARAMS]
        priv_params = priv[Attribute.EC_PARAMS]
        assert pub_params == priv_params, "EC params mismatch between pub and priv"

    def test_ec_point_on_pub_only(self, p11_session: Any, p11_module: Any) -> None:
        """CKA_EC_POINT is available on the public key and is non-empty."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub, _priv = params.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip("secp256r1 not supported")
            return

        ec_point = pub[Attribute.EC_POINT]
        assert isinstance(ec_point, bytes)
        assert len(ec_point) > 0

    def test_key_type_consistent(self, p11_session: Any, p11_module: Any) -> None:
        """Both keys report KeyType.EC."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        params = p11_session.create_domain_parameters(
            KeyType.EC,
            {Attribute.EC_PARAMS: encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        try:
            pub, priv = params.generate_keypair()
        except p11.exceptions.PKCS11Error:
            pytest.skip("secp256r1 not supported")
            return

        assert pub.key_type == KeyType.EC
        assert priv.key_type == KeyType.EC
