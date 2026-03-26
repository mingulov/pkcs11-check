"""EC key import/export round-trip tests.

Tests importing raw EC public keys (CKA_EC_POINT + CKA_EC_PARAMS),
exporting EC points from generated keys, and verifying round-trip
functionality (generate -> export -> import -> use).
Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_ec_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_TOKEN,
    CKA_VERIFY,
    CKK_EC,
    CKM_ECDSA,
    CKO_PUBLIC_KEY,
)

pytestmark = pytest.mark.keymgmt


def _make_ec_keypair(rs: Any, curve_name: str) -> tuple[int, int]:
    """Generate EC keypair, skip if curve unsupported."""
    curve_oid = encode_named_curve_parameters(curve_name)
    try:
        return gen_ec_keypair(rs.raw, rs.sh, curve_oid)
    except (AssertionError, OSError):
        pytest.skip(f"Curve {curve_name} not supported")
        raise  # unreachable, satisfies mypy


class TestECPublicKeyImport:
    """Test importing raw EC public keys."""

    @pytest.mark.parametrize("curve_name", ["secp256r1", "secp384r1", "secp521r1"])
    def test_generate_export_import_verify(self, p11_raw_session: Any, curve_name: str) -> None:
        """Generate EC key -> export public point -> import -> verify signature."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        pub, priv = _make_ec_keypair(rs, curve_name)
        imported_pub = 0
        try:
            # Export public point and params
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT, CKA_EC_PARAMS])
            ec_point_der = attrs[CKA_EC_POINT]
            ec_params = attrs[CKA_EC_PARAMS]
            assert isinstance(ec_point_der, bytes)
            assert len(ec_point_der) > 0

            # Sign with original private key
            data = b"round-trip test data for ECDSA"
            digest = hashlib.sha256(data).digest()
            sig = sign_single(rs.raw, rs.sh, priv, CKM_ECDSA, digest)
            assert len(sig) > 0

            # Import the exported public key as a new object
            imported_pub = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_PUBLIC_KEY,
                    CKA_KEY_TYPE: CKK_EC,
                    CKA_EC_PARAMS: ec_params,
                    CKA_EC_POINT: ec_point_der,
                    CKA_VERIFY: True,
                    CKA_TOKEN: False,
                },
            )

            # Verify signature with imported key
            assert verify_single(rs.raw, rs.sh, imported_pub, CKM_ECDSA, digest, sig) is True
        finally:
            if imported_pub:
                destroy_quietly(rs.raw, rs.sh, imported_pub)
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestECPointExport:
    """Test EC point export consistency."""

    def test_ec_point_is_uncompressed(self, p11_raw_session: Any) -> None:
        """Exported EC point starts with 0x04 (uncompressed)."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        pub, priv = _make_ec_keypair(rs, "secp256r1")
        try:
            ec_point_der = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])[CKA_EC_POINT]
            raw_point = decode_ec_point(ec_point_der)  # type: ignore[arg-type]
            assert raw_point[0] == 0x04, "EC point should be uncompressed (0x04 prefix)"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_ec_point_correct_length(self, p11_raw_session: Any) -> None:
        """P-256 uncompressed point is 65 bytes (1 + 32 + 32)."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        pub, priv = _make_ec_keypair(rs, "secp256r1")
        try:
            ec_point_der = read_attributes(rs.raw, rs.sh, pub, [CKA_EC_POINT])[CKA_EC_POINT]
            raw_point = decode_ec_point(ec_point_der)  # type: ignore[arg-type]
            assert len(raw_point) == 65, f"P-256 point should be 65 bytes, got {len(raw_point)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_two_keypairs_different_points(self, p11_raw_session: Any) -> None:
        """Two independently generated keypairs have different public points."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        pub1, priv1 = _make_ec_keypair(rs, "secp256r1")
        pub2, priv2 = _make_ec_keypair(rs, "secp256r1")
        try:
            point1 = read_attributes(rs.raw, rs.sh, pub1, [CKA_EC_POINT])[CKA_EC_POINT]
            point2 = read_attributes(rs.raw, rs.sh, pub2, [CKA_EC_POINT])[CKA_EC_POINT]
            assert point1 != point2, "Two keypairs should not have the same public point"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)
