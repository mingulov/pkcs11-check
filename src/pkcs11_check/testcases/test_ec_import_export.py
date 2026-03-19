"""EC key import/export round-trip tests.

Tests importing raw EC public keys (CKA_EC_POINT + CKA_EC_PARAMS),
exporting EC points from generated keys, and verifying round-trip
functionality (generate -> export -> import -> use).
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.util.ec import encode_named_curve_parameters

from pkcs11_check.testcases.conftest import extract_ec_point, has_mechanism

pytestmark = pytest.mark.keymgmt


def _make_ec_keypair(session: Any, curve_name: str) -> tuple[Any, Any]:
    """Generate EC keypair using domain parameters."""
    params = session.create_domain_parameters(
        KeyType.EC,
        {Attribute.EC_PARAMS: encode_named_curve_parameters(curve_name)},
        local=True,
    )
    result: tuple[Any, Any] = params.generate_keypair()
    return result


class TestECPublicKeyImport:
    """Test importing raw EC public keys."""

    @pytest.mark.parametrize("curve_name", ["secp256r1", "secp384r1", "secp521r1"])
    def test_generate_export_import_verify(
        self, p11_session: Any, p11_module: Any, curve_name: str
    ) -> None:
        """Generate EC key -> export public point -> import -> verify signature."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "ECDSA"):
            pytest.skip("CKM_ECDSA not supported")

        try:
            pub, priv = _make_ec_keypair(p11_session, curve_name)
        except p11.exceptions.PKCS11Error:
            pytest.skip(f"Curve {curve_name} not supported")
            return

        # Export public point and params
        ec_point_der = pub[Attribute.EC_POINT]
        ec_params = pub[Attribute.EC_PARAMS]
        assert isinstance(ec_point_der, bytes)
        assert len(ec_point_der) > 0

        # Sign with original private key
        data = b"round-trip test data for ECDSA"
        sig = priv.sign(data, mechanism=Mechanism.ECDSA)
        assert len(sig) > 0

        # Import the exported public key as a new object
        imported_pub = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.PUBLIC_KEY,
                Attribute.KEY_TYPE: KeyType.EC,
                Attribute.EC_PARAMS: ec_params,
                Attribute.EC_POINT: ec_point_der,
                Attribute.VERIFY: True,
                Attribute.TOKEN: False,
            }
        )

        # Verify signature with imported key
        assert imported_pub.verify(data, sig, mechanism=Mechanism.ECDSA)


class TestECPointExport:
    """Test EC point export consistency."""

    def test_ec_point_is_uncompressed(self, p11_session: Any, p11_module: Any) -> None:
        """Exported EC point starts with 0x04 (uncompressed)."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")

        try:
            pub, _priv = _make_ec_keypair(p11_session, "secp256r1")
        except p11.exceptions.PKCS11Error:
            pytest.skip("P-256 not supported")
            return

        ec_point_der = pub[Attribute.EC_POINT]
        raw_point = extract_ec_point(ec_point_der)
        assert raw_point[0] == 0x04, "EC point should be uncompressed (0x04 prefix)"

    def test_ec_point_correct_length(self, p11_session: Any, p11_module: Any) -> None:
        """P-256 uncompressed point is 65 bytes (1 + 32 + 32)."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")

        try:
            pub, _priv = _make_ec_keypair(p11_session, "secp256r1")
        except p11.exceptions.PKCS11Error:
            pytest.skip("P-256 not supported")
            return

        ec_point_der = pub[Attribute.EC_POINT]
        raw_point = extract_ec_point(ec_point_der)
        assert len(raw_point) == 65, f"P-256 point should be 65 bytes, got {len(raw_point)}"

    def test_two_keypairs_different_points(self, p11_session: Any, p11_module: Any) -> None:
        """Two independently generated keypairs have different public points."""
        if not has_mechanism(p11_module, "EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")

        try:
            pub1, _priv1 = _make_ec_keypair(p11_session, "secp256r1")
            pub2, _priv2 = _make_ec_keypair(p11_session, "secp256r1")
        except p11.exceptions.PKCS11Error:
            pytest.skip("P-256 not supported")
            return

        point1 = pub1[Attribute.EC_POINT]
        point2 = pub2[Attribute.EC_POINT]
        assert point1 != point2, "Two keypairs should not have the same public point"
