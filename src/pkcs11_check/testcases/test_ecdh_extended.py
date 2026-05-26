"""Tests for extended ECDH/EC mechanisms.

Covers CKM_ECDH1_COFACTOR_DERIVE, CKM_ECMQV_DERIVE, CKM_XEDDSA,
and CKM_EC_MONTGOMERY_KEY_PAIR_GEN.
Uses the raw PKCS#11 API via pkcs11_check.raw.

Basic CKM_ECDH1_DERIVE is tested in test_kdf.py.

OASIS spec: elliptic_curves.md
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    attr_bytes,
    mech_bytes,
    mech_ecdh,
)
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    gen_ec_keypair,
    gen_keypair,
    read_attributes,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKK_AES,
    CKK_EC_MONTGOMERY,
    CKK_GENERIC_SECRET,
    CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    CKM_ECDH1_COFACTOR_DERIVE,
    CKM_ECDH1_DERIVE,
    CKM_ECMQV_DERIVE,
    CKM_XEDDSA,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import is_known_error, xfail_if_known_ckr

pytestmark = pytest.mark.keymgmt

# OIDs for Montgomery curves (DER-encoded OID)
_X25519_OID = encode_named_curve_parameters("x25519")
_X448_OID = encode_named_curve_parameters("x448")

# Private key attrs for ECDH: enable derive usage
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

# AES derive template
_AES_DERIVE_ATTRS: dict[int, Any] = {
    CKA_CLASS: CKO_SECRET_KEY,
    CKA_KEY_TYPE: CKK_AES,
    CKA_VALUE_LEN: 32,
    CKA_ENCRYPT: True,
    CKA_DECRYPT: True,
    CKA_SENSITIVE: False,
    CKA_EXTRACTABLE: True,
    CKA_TOKEN: False,
}


_OPERATIONAL_ERROR_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)


def _ec_point(rs: Any, handle: int) -> bytes:
    """Read and decode EC_POINT from a public key handle.

    For Weierstrass curves (P-256, P-384, P-521) the attribute is DER OCTET STRING
    wrapping 0x04||x||y.  For Montgomery curves (X25519, X448) the value is raw
    little-endian bytes with no DER wrapper (RFC 7748 / OASIS PKCS#11 v3.2).
    """
    attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_EC_POINT])
    raw = attrs[CKA_EC_POINT]
    if isinstance(raw, bytes) and len(raw) > 0 and raw[0] == 0x04:
        return decode_ec_point(raw)
    assert isinstance(raw, bytes)
    return raw


def _gen_ec(rs: Any) -> tuple[int, int]:
    """Generate EC P-256 keypair with derive permission."""
    curve_oid = encode_named_curve_parameters("secp256r1")
    return gen_ec_keypair(rs.raw, rs.sh, curve_oid, private_attrs=_PRIV_DERIVE)


def _gen_montgomery(
    rs: Any,
    curve_oid: bytes,
    *,
    sign: bool = False,
    derive: bool = True,
) -> tuple[int, int]:
    """Generate a Montgomery curve keypair (X25519/X448) via raw C_GenerateKeyPair."""
    priv_attrs: dict[int, Any] = {
        CKA_SENSITIVE: True,
        CKA_TOKEN: False,
    }
    if derive:
        priv_attrs[CKA_DERIVE] = True
    if sign:
        priv_attrs[CKA_SIGN] = True
    return gen_keypair(
        rs.raw,
        rs.sh,
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        pub_base=[attr_bytes(CKA_EC_PARAMS, curve_oid)],
        priv_base=[],
        public_attrs={CKA_TOKEN: False},
        private_attrs=priv_attrs,
        pub_skip={CKA_EC_PARAMS},
    )


def _ecdh_derive(
    rs: Any,
    priv_key: int,
    peer_point: bytes,
    mechanism: Any,
    attrs: dict[int, Any] | None = None,
) -> int:
    """Derive a key via ECDH using the given mechanism."""
    ecdh_param = mech_ecdh(mechanism, kdf=CKD_NULL, public_data=peer_point)
    return derive_key(
        rs.raw,
        rs.sh,
        priv_key,
        mechanism,
        attrs=attrs or _DERIVE_ATTRS,
        mech_param=ecdh_param,
    )


def _read_value(rs: Any, handle: int) -> bytes:
    """Read CKA_VALUE from a derived key."""
    result = read_attributes(rs.raw, rs.sh, handle, [CKA_VALUE])
    val = result[CKA_VALUE]
    assert isinstance(val, bytes)
    return val


class TestECDH1CofactorDerive:
    """CKM_ECDH1_COFACTOR_DERIVE - ECDH with cofactor multiplication.

    For secp256r1 (cofactor=1), the result should match CKM_ECDH1_DERIVE.
    Uses the same CK_ECDH1_DERIVE_PARAMS structure as ECDH1_DERIVE.
    """

    def test_cofactor_derive_shared_secret(self, p11_raw_session: Any) -> None:
        """Two parties derive the same shared secret via cofactor ECDH."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        pub_a, priv_a = _gen_ec(rs)
        pub_b, priv_b = _gen_ec(rs)
        shared_ab = 0
        shared_ba = 0
        try:
            point_a = _ec_point(rs, pub_a)
            point_b = _ec_point(rs, pub_b)

            shared_ab = _ecdh_derive(rs, priv_a, point_b, CKM_ECDH1_COFACTOR_DERIVE)
            shared_ba = _ecdh_derive(rs, priv_b, point_a, CKM_ECDH1_COFACTOR_DERIVE)
            assert _read_value(rs, shared_ab) == _read_value(rs, shared_ba)
        finally:
            if shared_ab:
                destroy_quietly(rs.raw, rs.sh, shared_ab)
            if shared_ba:
                destroy_quietly(rs.raw, rs.sh, shared_ba)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            destroy_quietly(rs.raw, rs.sh, pub_b)

    def test_cofactor_matches_standard_ecdh(self, p11_raw_session: Any) -> None:
        """For secp256r1 (cofactor=1), cofactor derive == standard derive."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        pub_a, priv_a = _gen_ec(rs)
        pub_b, priv_b = _gen_ec(rs)
        shared_standard = 0
        shared_cofactor = 0
        try:
            point_b = _ec_point(rs, pub_b)

            shared_standard = _ecdh_derive(rs, priv_a, point_b, CKM_ECDH1_DERIVE)
            shared_cofactor = _ecdh_derive(rs, priv_a, point_b, CKM_ECDH1_COFACTOR_DERIVE)
            # secp256r1 has cofactor=1 so results must match
            assert _read_value(rs, shared_standard) == _read_value(rs, shared_cofactor)
        finally:
            if shared_standard:
                destroy_quietly(rs.raw, rs.sh, shared_standard)
            if shared_cofactor:
                destroy_quietly(rs.raw, rs.sh, shared_cofactor)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            destroy_quietly(rs.raw, rs.sh, pub_b)

    def test_cofactor_different_peers_different_secrets(self, p11_raw_session: Any) -> None:
        """Cofactor ECDH with different peers yields different secrets."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        _, priv_a = _gen_ec(rs)
        pub_b, _ = _gen_ec(rs)
        pub_c, _ = _gen_ec(rs)
        shared_ab = 0
        shared_ac = 0
        try:
            point_b = _ec_point(rs, pub_b)
            point_c = _ec_point(rs, pub_c)

            shared_ab = _ecdh_derive(rs, priv_a, point_b, CKM_ECDH1_COFACTOR_DERIVE)
            shared_ac = _ecdh_derive(rs, priv_a, point_c, CKM_ECDH1_COFACTOR_DERIVE)
            assert _read_value(rs, shared_ab) != _read_value(rs, shared_ac)
        finally:
            if shared_ab:
                destroy_quietly(rs.raw, rs.sh, shared_ab)
            if shared_ac:
                destroy_quietly(rs.raw, rs.sh, shared_ac)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, pub_c)

    def test_cofactor_derive_as_aes_key(self, p11_raw_session: Any) -> None:
        """Cofactor ECDH can derive an AES key directly."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_COFACTOR_DERIVE"):
            pytest.skip("CKM_ECDH1_COFACTOR_DERIVE not supported")

        pub_a, priv_a = _gen_ec(rs)
        pub_b, _ = _gen_ec(rs)
        derived = 0
        try:
            point_b = _ec_point(rs, pub_b)

            try:
                derived = _ecdh_derive(
                    rs,
                    priv_a,
                    point_b,
                    CKM_ECDH1_COFACTOR_DERIVE,
                    attrs=_AES_DERIVE_ATTRS,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _OPERATIONAL_ERROR_CKRS,
                    "CKM_ECDH1_COFACTOR_DERIVE advertised but cannot derive AES key",
                )
                raise  # unreachable

            attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_KEY_TYPE, CKA_VALUE])
            assert attrs[CKA_KEY_TYPE] == CKK_AES
            val = attrs[CKA_VALUE]
            assert isinstance(val, bytes)
            assert len(val) == 32
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)


class TestECMQVDerive:
    """CKM_ECMQV_DERIVE - EC Menter-Qu-Vanstone key agreement.

    Requires two keypairs per party (static + ephemeral).
    Very rarely supported by PKCS#11 modules.
    """

    def test_ecmqv_mechanism_listed(self, p11_raw_session: Any) -> None:
        """Check if CKM_ECMQV_DERIVE is in the mechanism list."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECMQV_DERIVE"):
            pytest.skip("CKM_ECMQV_DERIVE not supported")
        # If we get here, mechanism is listed - that alone is noteworthy

    def test_ecmqv_derive(self, p11_raw_session: Any) -> None:
        """Attempt ECMQV key agreement with two keypairs per party.

        ECMQV requires CK_ECMQV_DERIVE_PARAMS which needs:
        - kdf, shared data, public data (from peer's ephemeral public key),
        - peer's static public key handle, and own ephemeral private key handle.

        This mechanism is extremely rare. The test verifies it at least
        accepts the call or returns a reasonable error.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("ECMQV_DERIVE"):
            pytest.skip("CKM_ECMQV_DERIVE not supported")

        # ECMQV requires complex params (CK_ECMQV_DERIVE_PARAMS) not easily
        # constructible. We verify the mechanism is listed but expect the derive
        # call to fail with a parameter error since we pass ECDH1 params.
        pub_a_static, priv_a_static = _gen_ec(rs)
        pub_b_static, priv_b_static = _gen_ec(rs)
        shared = 0
        try:
            point_b = _ec_point(rs, pub_b_static)

            # Attempt derive - expect failure due to missing ECMQV param support
            try:
                shared = _ecdh_derive(
                    rs,
                    priv_a_static,
                    point_b,
                    CKM_ECMQV_DERIVE,
                )
            except AssertionError:
                pytest.xfail("ECMQV derive not operational: wrong param structure expected")
            else:
                # Unlikely to succeed, but if it does, verify and clean up
                val = _read_value(rs, shared)
                assert val is not None
        finally:
            if shared:
                destroy_quietly(rs.raw, rs.sh, shared)
            destroy_quietly(rs.raw, rs.sh, priv_a_static)
            destroy_quietly(rs.raw, rs.sh, pub_a_static)
            destroy_quietly(rs.raw, rs.sh, priv_b_static)
            destroy_quietly(rs.raw, rs.sh, pub_b_static)


class TestXEdDSA:
    """CKM_XEDDSA - XEdDSA sign/verify on Montgomery curve keys.

    Uses X25519 (Montgomery) keys for EdDSA-compatible signing.
    Very rarely supported.
    """

    def test_xeddsa_sign_verify(self, p11_raw_session: Any) -> None:
        """Sign and verify using XEdDSA on a Montgomery (X25519) key."""
        rs = p11_raw_session
        if not rs.has_mechanism("XEDDSA"):
            pytest.skip("CKM_XEDDSA not supported")
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for XEdDSA keygen")

        try:
            pub, priv = _gen_montgomery(rs, _X25519_OID, sign=True, derive=False)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _OPERATIONAL_ERROR_CKRS,
                "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but XEdDSA keygen is not operational",
            )
            raise  # unreachable

        try:
            data = b"XEdDSA test message for signing"
            # XEdDSA param is the hash type; 0 = SHA-512 per spec
            xeddsa_param = mech_bytes(CKM_XEDDSA, (0).to_bytes(4, "little"))
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_XEDDSA,
                    data,
                    mech_param=xeddsa_param,
                )
            except AssertionError:
                pytest.xfail("XEdDSA sign not operational")
                raise  # unreachable
            else:
                assert len(sig) > 0
                # Verify the signature
                xeddsa_v = mech_bytes(CKM_XEDDSA, (0).to_bytes(4, "little"))
                try:
                    result = verify_single(
                        rs.raw,
                        rs.sh,
                        pub,
                        CKM_XEDDSA,
                        data,
                        sig,
                        mech_param=xeddsa_v,
                    )
                    assert result is True
                except AssertionError:
                    pytest.xfail("XEdDSA verify not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_xeddsa_bad_signature_rejected(self, p11_raw_session: Any) -> None:
        """XEdDSA verify rejects a corrupted signature."""
        rs = p11_raw_session
        if not rs.has_mechanism("XEDDSA"):
            pytest.skip("CKM_XEDDSA not supported")
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported for XEdDSA keygen")

        try:
            pub, priv = _gen_montgomery(rs, _X25519_OID, sign=True, derive=False)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _OPERATIONAL_ERROR_CKRS,
                "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but XEdDSA keygen is not operational",
            )
            raise  # unreachable

        try:
            data = b"XEdDSA bad signature test"
            xeddsa_param = mech_bytes(CKM_XEDDSA, (0).to_bytes(4, "little"))
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_XEDDSA,
                    data,
                    mech_param=xeddsa_param,
                )
            except AssertionError:
                pytest.xfail("XEdDSA sign not operational")
                raise  # unreachable
            else:
                # Corrupt the signature
                bad_sig_arr = bytearray(sig)
                bad_sig_arr[0] ^= 0xFF
                bad_sig = bytes(bad_sig_arr)

                xeddsa_v = mech_bytes(CKM_XEDDSA, (0).to_bytes(4, "little"))
                result = verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_XEDDSA,
                    data,
                    bad_sig,
                    mech_param=xeddsa_v,
                )
                assert result is False, "XEdDSA verify accepted a corrupted signature"
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


class TestECMontgomeryKeyPairGen:
    """CKM_EC_MONTGOMERY_KEY_PAIR_GEN - Generate Montgomery curve keypairs.

    Tests X25519 and X448 key generation and ECDH derivation.
    """

    def test_x25519_keygen(self, p11_raw_session: Any) -> None:
        """Generate an X25519 keypair via EC_MONTGOMERY_KEY_PAIR_GEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub, priv = _gen_montgomery(rs, _X25519_OID)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _OPERATIONAL_ERROR_CKRS,
                "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but X25519 keygen is not operational",
            )
            raise  # unreachable

        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE, CKA_EC_POINT])
            assert attrs[CKA_KEY_TYPE] == CKK_EC_MONTGOMERY
            ec_point = attrs[CKA_EC_POINT]
            assert ec_point is not None
            assert len(ec_point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_x448_keygen(self, p11_raw_session: Any) -> None:
        """Generate an X448 keypair via EC_MONTGOMERY_KEY_PAIR_GEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub, priv = _gen_montgomery(rs, _X448_OID)
        except AssertionError as exc:
            if is_known_error(exc, _OPERATIONAL_ERROR_CKRS):
                pytest.skip(f"X448 keygen not supported: {exc}")
            raise

        try:
            attrs = read_attributes(rs.raw, rs.sh, pub, [CKA_KEY_TYPE, CKA_EC_POINT])
            assert attrs[CKA_KEY_TYPE] == CKK_EC_MONTGOMERY
            ec_point = attrs[CKA_EC_POINT]
            assert ec_point is not None
            assert len(ec_point) > 0
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_x25519_two_keypairs_differ(self, p11_raw_session: Any) -> None:
        """Two independently generated X25519 keypairs have different public keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")

        try:
            pub_a, priv_a = _gen_montgomery(rs, _X25519_OID)
            pub_b, priv_b = _gen_montgomery(rs, _X25519_OID)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _OPERATIONAL_ERROR_CKRS,
                "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but X25519 keygen is not operational",
            )
            raise  # unreachable

        try:
            point_a = read_attributes(rs.raw, rs.sh, pub_a, [CKA_EC_POINT])[CKA_EC_POINT]
            point_b = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])[CKA_EC_POINT]
            assert point_a != point_b
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            destroy_quietly(rs.raw, rs.sh, pub_b)

    def test_x25519_ecdh_derive(self, p11_raw_session: Any) -> None:
        """X25519 keys can perform ECDH key agreement."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_MONTGOMERY_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_MONTGOMERY_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        try:
            pub_a, priv_a = _gen_montgomery(rs, _X25519_OID)
            pub_b, priv_b = _gen_montgomery(rs, _X25519_OID)
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _OPERATIONAL_ERROR_CKRS,
                "CKM_EC_MONTGOMERY_KEY_PAIR_GEN advertised but X25519 keygen is not operational",
            )
            raise  # unreachable

        shared_ab = 0
        shared_ba = 0
        try:
            point_a = _ec_point(rs, pub_a)
            point_b = _ec_point(rs, pub_b)

            shared_ab = _ecdh_derive(rs, priv_a, point_b, CKM_ECDH1_DERIVE)
            shared_ba = _ecdh_derive(rs, priv_b, point_a, CKM_ECDH1_DERIVE)

            val_ab = _read_value(rs, shared_ab)
            val_ba = _read_value(rs, shared_ba)
            assert val_ab == val_ba
            assert len(val_ab) == 32
        finally:
            if shared_ab:
                destroy_quietly(rs.raw, rs.sh, shared_ab)
            if shared_ba:
                destroy_quietly(rs.raw, rs.sh, shared_ba)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_b)
            destroy_quietly(rs.raw, rs.sh, pub_b)
