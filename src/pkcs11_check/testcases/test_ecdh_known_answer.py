"""ECDH known-answer tests.

Verifies ECDH key agreement produces the correct shared secret
by deriving with known keys in both PKCS#11 and Python cryptography,
then comparing the raw shared secrets.
Uses the raw PKCS#11 API via pkcs11_check.raw.

This catches subtle ECDH implementation bugs that roundtrip tests miss.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.classification import classify
from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    gen_ec_keypair,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases.conftest import assert_correct

pytestmark = pytest.mark.crossverify

# Private key attrs: enable derive usage
_PRIV_DERIVE: dict[int, Any] = {CKA_DERIVE: True}

# Shared ECDH derive template: raw shared secret, extractable, session-only
_DERIVE_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
    CKA_VALUE_LEN: 32,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}


def _ec_point_from_handle(rs: Any, handle: int) -> bytes:
    """Read and decode EC_POINT from a public key handle."""
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    return decode_ec_point(attrs[CKA_EC_POINT])


class TestECDHKnownAnswer:
    """Verify ECDH produces correct shared secret using known keys."""

    def test_ecdh_p256_crossverify(self, p11_raw_session: Any) -> None:
        """ECDH P-256: derive in both PKCS#11 and cryptography, compare raw secrets."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        # Generate P-256 keypair in cryptography
        crypto_priv = ec.generate_private_key(ec.SECP256R1())
        crypto_pub = crypto_priv.public_key()
        pub_numbers = crypto_pub.public_numbers()
        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_bytes = pub_numbers.y.to_bytes(32, "big")
        crypto_point = b"\x04" + x_bytes + y_bytes

        # Generate P-256 keypair in PKCS#11
        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            p11_pub, p11_priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                private_attrs=_PRIV_DERIVE,
            )
        except (AssertionError, OSError):
            pytest.skip("P-256 not supported")
            raise  # unreachable

        derived_h = 0
        try:
            p11_point = _ec_point_from_handle(rs, p11_pub)

            # PKCS#11: p11_priv x crypto_pub (NULL KDF = raw shared secret)
            ecdh_param = mech_ecdh(
                CKM_ECDH1_DERIVE,
                kdf=CKD_NULL,
                public_data=crypto_point,
            )
            try:
                derived_h = derive_key(
                    rs.raw,
                    rs.sh,
                    p11_priv,
                    CKM_ECDH1_DERIVE,
                    attrs=_DERIVE_ATTRS,
                    mech_param=ecdh_param,
                )
            except AssertionError as exc:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_ECDH1_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_ECDH1_DERIVE",
                    summary=f"ECDH derivation failed -- mechanism advertised but rejected: {exc}",
                )

            p11_secret = read_attributes(rs.raw, rs.sh, derived_h, [CKA_VALUE])[CKA_VALUE]

            # cryptography: crypto_priv x p11_pub
            p11_x = int.from_bytes(p11_point[1:33], "big")
            p11_y = int.from_bytes(p11_point[33:65], "big")
            p11_pub_crypto = ec.EllipticCurvePublicNumbers(
                p11_x, p11_y, ec.SECP256R1()
            ).public_key()
            crypto_secret = crypto_priv.exchange(ec.ECDH(), p11_pub_crypto)

            # Both should produce the same raw shared secret
            assert_correct(
                actual=p11_secret,
                expected=crypto_secret,
                label="CKM_ECDH1_DERIVE:C_DeriveKey KAT (vs cryptography)",
                operation="C_DeriveKey",
                mechanism="CKM_ECDH1_DERIVE",
            )
        finally:
            if derived_h:
                destroy_quietly(rs.raw, rs.sh, derived_h)
            destroy_quietly(rs.raw, rs.sh, p11_pub)
            destroy_quietly(rs.raw, rs.sh, p11_priv)

    def test_ecdh_symmetric_agreement(self, p11_raw_session: Any) -> None:
        """Two PKCS#11 keypairs derive the same shared secret (symmetric)."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub_a, priv_a = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                private_attrs=_PRIV_DERIVE,
            )
            pub_b, priv_b = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                private_attrs=_PRIV_DERIVE,
            )
        except (AssertionError, OSError):
            pytest.skip("P-256 not supported")
            raise  # unreachable

        key_ab = 0
        key_ba = 0
        try:
            point_a = _ec_point_from_handle(rs, pub_a)
            point_b = _ec_point_from_handle(rs, pub_b)

            ecdh_ab = mech_ecdh(
                CKM_ECDH1_DERIVE,
                kdf=CKD_NULL,
                public_data=point_b,
            )
            ecdh_ba = mech_ecdh(
                CKM_ECDH1_DERIVE,
                kdf=CKD_NULL,
                public_data=point_a,
            )
            try:
                key_ab = derive_key(
                    rs.raw,
                    rs.sh,
                    priv_a,
                    CKM_ECDH1_DERIVE,
                    attrs=_DERIVE_ATTRS,
                    mech_param=ecdh_ab,
                )
                key_ba = derive_key(
                    rs.raw,
                    rs.sh,
                    priv_b,
                    CKM_ECDH1_DERIVE,
                    attrs=_DERIVE_ATTRS,
                    mech_param=ecdh_ba,
                )
            except AssertionError as exc:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_ECDH1_DERIVE:C_DeriveKey",
                    operation="C_DeriveKey",
                    mechanism="CKM_ECDH1_DERIVE",
                    summary=f"ECDH derivation failed -- mechanism advertised but rejected: {exc}",
                )

            secret_ab = read_attributes(rs.raw, rs.sh, key_ab, [CKA_VALUE])[CKA_VALUE]
            secret_ba = read_attributes(rs.raw, rs.sh, key_ba, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=secret_ab,
                expected=secret_ba,
                label="CKM_ECDH1_DERIVE:shared-secret symmetric agreement",
                operation="C_DeriveKey",
                mechanism="CKM_ECDH1_DERIVE",
            )
        finally:
            if key_ab:
                destroy_quietly(rs.raw, rs.sh, key_ab)
            if key_ba:
                destroy_quietly(rs.raw, rs.sh, key_ba)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)
