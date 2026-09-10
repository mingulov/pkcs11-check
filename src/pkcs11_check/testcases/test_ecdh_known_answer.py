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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    gen_ec_keypair,
    read_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKK_GENERIC_SECRET,
    CKM_ECDH1_DERIVE,
    CKO_SECRET_KEY,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._ec_export import (
    ConventionalECPoint,
    read_conventional_ec_point_or_xfail,
    select_ecdh_point_form,
)
from pkcs11_check.testcases.conftest import (
    CIPHER_OP_RUNTIME_REJECT_RVS,
    EC_CURVE_UNSUPPORTED_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    assert_correct,
    is_known_error,
    xfail_if_known_ckr,
)

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


def _ec_point_from_handle(rs: Any, handle: int) -> ConventionalECPoint:
    """Read and validate a provider-returned P-256 public point."""
    return read_conventional_ec_point_or_xfail(
        rs,
        handle,
        ec.SECP256R1(),
        label="ECDH P-256 public key",
    )


def _local_ec_point(public_key: ec.EllipticCurvePublicKey) -> ConventionalECPoint:
    """Represent a locally generated peer using the same operational boundary."""
    sec1_bytes = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return ConventionalECPoint(sec1_bytes, sec1_bytes, public_key)


def _select_ecdh_point_for_target(rs: Any, point: ConventionalECPoint) -> bytes:
    """Select the peer representation supported by the target ECDH mechanism."""
    return select_ecdh_point_form(
        point,
        supports_compressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_COMPRESS)),
        supports_uncompressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_UNCOMPRESS)),
    )


def _assert_kat_secret(
    actual: bytes,
    private_key: ec.EllipticCurvePrivateKey,
    provider_point: ConventionalECPoint,
) -> None:
    """Compare a provider-derived secret with the validated provider public key."""
    crypto_secret = private_key.exchange(ec.ECDH(), provider_point.public_key)
    assert_correct(
        actual=actual,
        expected=crypto_secret,
        label="CKM_ECDH1_DERIVE:C_DeriveKey KAT (vs cryptography)",
        operation="C_DeriveKey",
        mechanism="CKM_ECDH1_DERIVE",
    )


def _read_value_or_record(rs: Any, handle: int, *, label: str) -> Any:
    """Read CKA_VALUE while preserving an unavailable-value observation."""
    return attr_or_record(
        read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE]),
        CKA_VALUE,
        label=label,
        reason="not_operational",
    )


def _validate_derived_value(
    value: Any,
    *,
    leg: str,
    label: str,
) -> C.Classification | None:
    """Retain a hard finding for a present derived value with the wrong shape."""
    if value is MISSING_ATTRIBUTE:
        return None
    if type(value) is bytes and len(value) == 32:
        return None
    try:
        actual_length: int | None = len(value)
    except TypeError:
        actual_length = None
    return C.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        summary=f"{label}: provider returned a derived CKA_VALUE with the wrong shape",
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "leg": leg,
            "expected": {"type": "bytes", "length": 32},
            "actual": {"type": type(value).__name__, "length": actual_length},
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": "CKM_ECDH1_DERIVE",
        },
    )


def _gen_p256_or_skip(rs: Any) -> tuple[int, int]:
    """Skip an explicitly unsupported P-256 curve; expose other keygen failures."""
    try:
        return gen_ec_keypair(
            rs.raw,
            rs.sh,
            encode_named_curve_parameters("secp256r1"),
            private_attrs=_PRIV_DERIVE,
        )
    except CkrAssertionError as exc:
        if is_known_error(exc, EC_CURVE_UNSUPPORTED_RVS):
            pytest.skip("P-256 not supported")
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "EC key generation advertised but P-256 keygen is not operational",
        )
        raise


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

        # Generate P-256 keypair in PKCS#11
        p11_pub = p11_priv = 0
        derived_h = 0
        try:
            p11_pub, p11_priv = _gen_p256_or_skip(rs)
            p11_point = _ec_point_from_handle(rs, p11_pub)

            # PKCS#11: p11_priv x crypto_pub (NULL KDF = raw shared secret)
            crypto_peer = _local_ec_point(crypto_pub)
            crypto_point = _select_ecdh_point_for_target(rs, crypto_peer)
            ecdh_param = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=crypto_point)
            try:
                derived_h = derive_key(
                    rs.raw,
                    rs.sh,
                    p11_priv,
                    CKM_ECDH1_DERIVE,
                    attrs=_DERIVE_ATTRS,
                    mech_param=ecdh_param,
                )
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "CKM_ECDH1_DERIVE advertised but C_DeriveKey is not operational",
                )
                raise

            p11_secret = _read_value_or_record(
                rs,
                derived_h,
                label="CKM_ECDH1_DERIVE:known-answer derived CKA_VALUE",
            )
            if p11_secret is MISSING_ATTRIBUTE:
                return

            shape_record = _validate_derived_value(
                p11_secret,
                leg="crossverify",
                label="CKM_ECDH1_DERIVE:known-answer derived CKA_VALUE",
            )
            if shape_record is not None:
                C.raise_for_record(shape_record)

            # cryptography: crypto_priv x validated provider public key
            _assert_kat_secret(p11_secret, crypto_priv, p11_point)
        finally:
            if derived_h:
                destroy_quietly(rs.raw, rs.sh, derived_h)
            if p11_pub:
                destroy_quietly(rs.raw, rs.sh, p11_pub)
            if p11_priv:
                destroy_quietly(rs.raw, rs.sh, p11_priv)

    def test_ecdh_symmetric_agreement(self, p11_raw_session: Any) -> None:
        """Two PKCS#11 keypairs derive the same shared secret (symmetric)."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        pub_a = priv_a = 0
        pub_b = priv_b = 0
        key_ab = 0
        key_ba = 0
        try:
            pub_a, priv_a = _gen_p256_or_skip(rs)
            pub_b, priv_b = _gen_p256_or_skip(rs)

            point_a = _ec_point_from_handle(rs, pub_a)
            point_b = _ec_point_from_handle(rs, pub_b)

            point_b_wire = _select_ecdh_point_for_target(rs, point_b)
            ecdh_ab = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=point_b_wire)
            point_a_wire = _select_ecdh_point_for_target(rs, point_a)
            ecdh_ba = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=point_a_wire)
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
            except CkrAssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    CIPHER_OP_RUNTIME_REJECT_RVS,
                    "CKM_ECDH1_DERIVE advertised but C_DeriveKey is not operational",
                )
                raise

            secret_ab = _read_value_or_record(
                rs,
                key_ab,
                label="CKM_ECDH1_DERIVE:A-to-B derived CKA_VALUE",
            )
            secret_ba = _read_value_or_record(
                rs,
                key_ba,
                label="CKM_ECDH1_DERIVE:B-to-A derived CKA_VALUE",
            )

            shape_records = [
                record
                for record in (
                    _validate_derived_value(
                        secret_ab,
                        leg="A-to-B",
                        label="CKM_ECDH1_DERIVE:A-to-B derived CKA_VALUE",
                    ),
                    _validate_derived_value(
                        secret_ba,
                        leg="B-to-A",
                        label="CKM_ECDH1_DERIVE:B-to-A derived CKA_VALUE",
                    ),
                )
                if record is not None
            ]
            if shape_records:
                C.raise_for_record(shape_records[0])
            if secret_ab is MISSING_ATTRIBUTE or secret_ba is MISSING_ATTRIBUTE:
                return
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
            if pub_a:
                destroy_quietly(rs.raw, rs.sh, pub_a)
            if priv_a:
                destroy_quietly(rs.raw, rs.sh, priv_a)
            if pub_b:
                destroy_quietly(rs.raw, rs.sh, pub_b)
            if priv_b:
                destroy_quietly(rs.raw, rs.sh, priv_b)
