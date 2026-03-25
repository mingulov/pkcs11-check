"""Keypair attribute consistency tests.

Verifies that public and private keys in a generated keypair have
consistent attributes - modulus matches for RSA, EC params match for EC.
Catches bugs where modules produce mathematically inconsistent keypairs.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    gen_rsa_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKK_EC,
)

pytestmark = pytest.mark.keymgmt


class TestRSAKeypairConsistency:
    """Verify RSA keypair attribute consistency."""

    def test_modulus_matches(self, p11_raw_session: Any) -> None:
        """Public and private RSA key have the same modulus."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            pub_modulus = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_MODULUS)]
            )[int(CKA_MODULUS)]
            priv_modulus = read_attributes(
                rs.raw, rs.sh, priv, [int(CKA_MODULUS)]
            )[int(CKA_MODULUS)]
            assert pub_modulus == priv_modulus, "RSA modulus mismatch between pub and priv"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_public_exponent_matches(self, p11_raw_session: Any) -> None:
        """Public exponent is the same on both keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            pub_exp = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_PUBLIC_EXPONENT)]
            )[int(CKA_PUBLIC_EXPONENT)]
            priv_exp = read_attributes(
                rs.raw, rs.sh, priv, [int(CKA_PUBLIC_EXPONENT)]
            )[int(CKA_PUBLIC_EXPONENT)]
            assert pub_exp == priv_exp, "RSA public exponent mismatch"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_modulus_correct_size(self, p11_raw_session: Any) -> None:
        """RSA-2048 modulus is 256 bytes (2048 bits)."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA key generation not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            modulus = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_MODULUS)]
            )[int(CKA_MODULUS)]
            assert len(modulus) == 256, f"Expected 256-byte modulus, got {len(modulus)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECKeypairConsistency:
    """Verify EC keypair attribute consistency."""

    def test_ec_params_match(self, p11_raw_session: Any) -> None:
        """Public and private EC key have the same CKA_EC_PARAMS."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            pub_params = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_EC_PARAMS)]
            )[int(CKA_EC_PARAMS)]
            priv_params = read_attributes(
                rs.raw, rs.sh, priv, [int(CKA_EC_PARAMS)]
            )[int(CKA_EC_PARAMS)]
            assert pub_params == priv_params, "EC params mismatch between pub and priv"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_on_pub_only(self, p11_raw_session: Any) -> None:
        """CKA_EC_POINT is available on the public key and is non-empty."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            ec_point = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_EC_POINT)]
            )[int(CKA_EC_POINT)]
            assert isinstance(ec_point, bytes)
            assert len(ec_point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_key_type_consistent(self, p11_raw_session: Any) -> None:
        """Both keys report CKK_EC."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        pub, priv = gen_ec_keypair(rs.raw, rs.sh, curve_oid)
        try:
            pub_kt = read_attributes(
                rs.raw, rs.sh, pub, [int(CKA_KEY_TYPE)]
            )[int(CKA_KEY_TYPE)]
            priv_kt = read_attributes(
                rs.raw, rs.sh, priv, [int(CKA_KEY_TYPE)]
            )[int(CKA_KEY_TYPE)]
            assert pub_kt == int(CKK_EC)
            assert priv_kt == int(CKK_EC)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
