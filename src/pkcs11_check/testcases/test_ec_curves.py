"""Tests for EC key generation and ECDSA across multiple curves.

Parametrized tests for P-224, P-256, P-384, P-521.
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_ec_keypair,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKK_EC,
    CKM_ECDSA,
)

pytestmark = pytest.mark.crossverify

_EC_CURVES = [
    ("secp224r1", 28, ec.SECP224R1(), hashes.SHA224()),
    ("secp256r1", 32, ec.SECP256R1(), hashes.SHA256()),
    ("secp256k1", 32, ec.SECP256K1(), hashes.SHA256()),
    ("secp384r1", 48, ec.SECP384R1(), hashes.SHA384()),
    ("secp521r1", 66, ec.SECP521R1(), hashes.SHA512()),
]


def _try_gen_ec(rs: Any, curve_name: str) -> tuple[int, int]:
    """Generate EC keypair, skip if curve unsupported."""
    curve_oid = encode_named_curve_parameters(curve_name)
    try:
        return gen_ec_keypair(rs.raw, rs.sh, curve_oid)
    except (AssertionError, OSError):
        pytest.skip(f"Curve {curve_name} not supported by module")
        raise  # unreachable, satisfies mypy


class TestECKeygen:
    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ec_keygen(
        self, p11_raw_session: Any, curve_name: str, _: int, __: Any, ___: Any
    ) -> None:
        """Generate EC key pair on the given curve."""
        rs = p11_raw_session
        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    @pytest.mark.parametrize(
        "curve_name,_,__,___",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ec_key_type(
        self, p11_raw_session: Any, curve_name: str, _: int, __: Any, ___: Any
    ) -> None:
        """EC key pair should have EC key type."""
        rs = p11_raw_session
        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            attrs_pub = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE])
            attrs_priv = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_TYPE])
            assert attrs_pub[CKA_KEY_TYPE] == CKK_EC
            assert attrs_priv[CKA_KEY_TYPE] == CKK_EC
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECDSACrossVerify:
    @pytest.mark.parametrize(
        "curve_name,coord_size,crypto_curve,hash_algo",
        _EC_CURVES,
        ids=["P-224", "P-256", "P-384", "P-521"],
    )
    def test_ecdsa_sign_p11_verify_crypto(
        self,
        p11_raw_session: Any,
        curve_name: str,
        coord_size: int,
        crypto_curve: ec.EllipticCurve,
        hash_algo: hashes.HashAlgorithm,
    ) -> None:
        """ECDSA sign with PKCS#11, verify with cryptography."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        hash_fns = {28: hashlib.sha224, 32: hashlib.sha256, 48: hashlib.sha384, 66: hashlib.sha512}

        pub, priv = _try_gen_ec(rs, curve_name)
        try:
            data = f"ECDSA {curve_name} cross-verify".encode()
            digest = hash_fns[coord_size](data).digest()

            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)

            ec_point_der = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])[CKA_EC_POINT]
            point_bytes = decode_ec_point(ec_point_der)  # type: ignore[arg-type]
            pub_crypto = ec.EllipticCurvePublicKey.from_encoded_point(crypto_curve, point_bytes)

            half = len(sig) // 2
            r = int.from_bytes(sig[:half], "big")
            s = int.from_bytes(sig[half:], "big")
            der_sig = encode_dss_signature(r, s)

            pub_crypto.verify(der_sig, data, ec.ECDSA(hash_algo))
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
