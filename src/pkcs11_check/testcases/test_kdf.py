"""Key derivation function tests - ECDH derive, HMAC-KDF, key agreement.

Tests key derivation operations available in PKCS#11 v2.40+.
HKDF (CKM_HKDF_DERIVE) requires v3.0+ - auto-skips on v2.40 modules.

Uses the raw PKCS#11 API via pkcs11_check.raw.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh, mech_hkdf
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKK_GENERIC_SECRET,
    CKK_SHA256_HMAC,
    CKK_SHA512_HMAC,
    CKM_ECDH1_DERIVE,
    CKM_HKDF_DERIVE,
    CKM_SHA3_224_KEY_DERIVE,
    CKM_SHA3_256_KEY_DERIVE,
    CKM_SHA3_384_KEY_DERIVE,
    CKM_SHA3_512_KEY_DERIVE,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA512_HMAC,
    CKM_SHAKE_128_KEY_DERIVE,
    CKM_SHAKE_256_KEY_DERIVE,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._ec_export import (
    ConventionalECPoint,
    read_conventional_ec_point_or_xfail,
    select_ecdh_point_form,
)
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_ec_keypair_or_xfail,
    hmac_sign_or_xfail,
    import_secret_key_negotiated,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_DERIVE_ERROR_RVS = {
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
}


def _derived_value_length(value: Any) -> int | None:
    """Return a safe length summary for malformed derived-value readback."""
    try:
        return len(value)
    except TypeError:
        return None


def _record_derived_value_shape(
    value: Any,
    *,
    leg: str,
    expected_shape: str,
    expected_length: int | None,
    producer_mechanism: str,
) -> classification.Classification | None:
    """Record, without raising, malformed present derived-key value evidence."""
    if value is MISSING_ATTRIBUTE:
        return None
    valid = isinstance(value, bytes) and bool(value)
    if expected_length is not None:
        valid = valid and len(value) == expected_length
    if valid:
        return None
    return classification.record_as(
        "wrong_result",
        kind="metadata",
        label=f"{producer_mechanism}:{leg} CKA_VALUE",
        operation="C_GetAttributeValue",
        inherit_mechanism=False,
        mechanism=None,
        detail={
            "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
            "leg": leg,
            "expected_shape": expected_shape,
            "actual_type": type(value).__name__,
            "actual_length": _derived_value_length(value),
            "producer_operation": "C_DeriveKey",
            "producer_mechanism": producer_mechanism,
        },
        summary=f"{producer_mechanism}:{leg} CKA_VALUE: present value is not {expected_shape}",
    )


def _raise_derived_value_shape_failures(
    records: list[classification.Classification],
) -> None:
    """Raise the first malformed-present record after all paired reads validate."""
    if records:
        classification.raise_for_record(records[0])


def _select_ecdh_point_for_target(rs: Any, point: ConventionalECPoint) -> bytes:
    """Select the peer representation supported by the target ECDH mechanism."""
    return select_ecdh_point_form(
        point,
        supports_compressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_COMPRESS)),
        supports_uncompressed=rs.has_mechanism_flag(CKM_ECDH1_DERIVE, int(CKF_EC_UNCOMPRESS)),
    )


def _canonical_ec_point_bytes(point: ConventionalECPoint) -> bytes:
    """Serialize an EC public key canonically, independent of provider encoding."""
    return point.public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _import_generic_secret(rs: Any, value: bytes, derive: bool = True) -> int:
    """Import a GENERIC_SECRET key with DERIVE=True."""
    return import_secret_key_negotiated(
        rs,
        CKK_GENERIC_SECRET,
        value,
        attrs={
            CKA_TOKEN: False,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_DERIVE: derive,
        },
    )


class TestKeyDeriveSoftware:
    """Test key derivation using software-verifiable methods."""

    def test_derive_from_digest(self, p11_raw_session: Any) -> None:
        """Import a generic secret suitable for derivation."""
        rs = p11_raw_session
        secret = b"key derivation input material!!"
        key = _import_generic_secret(rs, secret)
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_hmac_as_kdf(self, p11_raw_session: Any) -> None:
        """Use HMAC as a KDF - cross-verify against Python hmac."""
        rs = p11_raw_session
        key_bytes = bytes(range(32))
        data = b"KDF input data for derivation"

        p11_key = import_secret_key_negotiated(
            rs,
            CKK_SHA256_HMAC,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            p11_mac = hmac_sign_or_xfail(rs, p11_key, CKM_SHA256_HMAC, data, label="SHA256_HMAC")
            py_mac = hmac_mod.new(key_bytes, data, hashlib.sha256).digest()
            assert_correct(
                actual=p11_mac,
                expected=py_mac,
                label="CKM_SHA256_HMAC:C_Sign KAT (HMAC-as-KDF)",
                operation="C_Sign",
                mechanism="CKM_SHA256_HMAC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)

    def test_hmac_sha512_as_kdf(self, p11_raw_session: Any) -> None:
        """HMAC-SHA512 as KDF - cross-verify."""
        rs = p11_raw_session
        key_bytes = bytes(range(64))
        data = b"HMAC-SHA512 KDF test"

        p11_key = import_secret_key_negotiated(
            rs,
            CKK_SHA512_HMAC,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            p11_mac = hmac_sign_or_xfail(rs, p11_key, CKM_SHA512_HMAC, data, label="SHA512_HMAC")
            py_mac = hmac_mod.new(key_bytes, data, hashlib.sha512).digest()
            assert_correct(
                actual=p11_mac,
                expected=py_mac,
                label="CKM_SHA512_HMAC:C_Sign KAT (HMAC-as-KDF)",
                operation="C_Sign",
                mechanism="CKM_SHA512_HMAC",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, p11_key)


class TestHKDF:
    """HKDF tests - requires CKM_HKDF_DERIVE (PKCS#11 v3.0+)."""

    def test_hkdf_available(self, p11_raw_session: Any) -> None:
        """Check if HKDF mechanism is available."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("HKDF not supported - requires PKCS#11 v3.0+")

    def test_hkdf_derive_basic(self, p11_raw_session: Any) -> None:
        """Basic HKDF derivation with SHA-256."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("HKDF not supported")

        ikm = bytes(range(32))
        base_key = _import_generic_secret(rs, ikm)
        derived = 0
        try:
            derived = derive_key(
                rs.raw,
                rs.sh,
                base_key,
                CKM_HKDF_DERIVE,
                attrs={
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                    CKA_SENSITIVE: False,
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                mech_param=mech_hkdf(
                    CKM_HKDF_DERIVE,
                    hash_mech=CKM_SHA256,
                    extract=True,
                    expand=True,
                    salt=b"salt",
                    info=b"info",
                ),
            )
            okm_attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
            okm = attr_or_record(
                okm_attrs,
                CKA_VALUE,
                label="CKM_HKDF_DERIVE:derived CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if okm is MISSING_ATTRIBUTE:
                return
            assert len(okm) == 32
        except AssertionError as exc:
            xfail_if_known_ckr(exc, _DERIVE_ERROR_RVS, "HKDF derivation not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)


class TestECDHDerive:
    """ECDH key agreement - derive shared secret from two keypairs."""

    def _generate_ec_keypair(self, rs: Any) -> tuple[int, int]:
        curve_oid = encode_named_curve_parameters("secp256r1")
        return gen_ec_keypair_or_xfail(
            rs,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )

    def _extract_ec_point(self, rs: Any, pub_handle: int) -> ConventionalECPoint:
        return read_conventional_ec_point_or_xfail(
            rs,
            pub_handle,
            ec.SECP256R1(),
            label="ECDH P-256 public key",
        )

    def _select_ecdh_point_for_target(self, rs: Any, point: ConventionalECPoint) -> bytes:
        """Select the peer representation supported by the target ECDH mechanism."""
        return _select_ecdh_point_for_target(rs, point)

    def _derive_shared(
        self,
        rs: Any,
        priv_handle: int,
        peer_point: ConventionalECPoint,
    ) -> int:
        peer_wire = self._select_ecdh_point_for_target(rs, peer_point)
        ecdh_param = mech_ecdh(
            CKM_ECDH1_DERIVE,
            kdf=CKD_NULL,
            public_data=peer_wire,
        )
        return derive_key(
            rs.raw,
            rs.sh,
            priv_handle,
            CKM_ECDH1_DERIVE,
            attrs={
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
            mech_param=ecdh_param,
        )

    def test_ecdh_keypair_independence(self, p11_raw_session: Any) -> None:
        """Two independently generated EC keypairs have different public points."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        pub_a = priv_a = pub_b = priv_b = 0
        try:
            pub_a, priv_a = self._generate_ec_keypair(rs)
            pub_b, priv_b = self._generate_ec_keypair(rs)
            point_a = self._extract_ec_point(rs, pub_a)
            point_b = self._extract_ec_point(rs, pub_b)
            canonical_a = _canonical_ec_point_bytes(point_a)
            canonical_b = _canonical_ec_point_bytes(point_b)
            if canonical_a == canonical_b:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_EC_KEY_PAIR_GEN:independent EC keypairs",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_EC_KEY_PAIR_GEN",
                    summary=(
                        "independently generated EC keypairs produced the same canonical "
                        "public point"
                    ),
                    detail={
                        "public_point": {
                            "canonical_a": canonical_a.hex(),
                            "canonical_b": canonical_b.hex(),
                        }
                    },
                )
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)

    def test_ecdh_shared_secret_agreement(self, p11_raw_session: Any) -> None:
        """ECDH: A derives with B's pubkey == B derives with A's pubkey."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        pub_a = priv_a = pub_b = priv_b = 0
        shared_ab = 0
        shared_ba = 0
        try:
            pub_a, priv_a = self._generate_ec_keypair(rs)
            pub_b, priv_b = self._generate_ec_keypair(rs)
            point_a = self._extract_ec_point(rs, pub_a)
            point_b = self._extract_ec_point(rs, pub_b)

            shared_ab = self._derive_shared(rs, priv_a, point_b)
            shared_ba = self._derive_shared(rs, priv_b, point_a)

            shape_failures: list[classification.Classification] = []
            val_ab_attrs = read_attributes(rs.raw, rs.sh, shared_ab, [CKA_VALUE])
            val_ab = attr_or_record(
                val_ab_attrs,
                CKA_VALUE,
                label="CKM_ECDH1_DERIVE:Alice shared CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            ab_shape = _record_derived_value_shape(
                val_ab,
                leg="ab",
                expected_shape="non-empty bytes",
                expected_length=None,
                producer_mechanism="CKM_ECDH1_DERIVE",
            )
            if ab_shape is not None:
                shape_failures.append(ab_shape)

            val_ba_attrs = read_attributes(rs.raw, rs.sh, shared_ba, [CKA_VALUE])
            val_ba = attr_or_record(
                val_ba_attrs,
                CKA_VALUE,
                label="CKM_ECDH1_DERIVE:Bob shared CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            ba_shape = _record_derived_value_shape(
                val_ba,
                leg="ba",
                expected_shape="non-empty bytes",
                expected_length=None,
                producer_mechanism="CKM_ECDH1_DERIVE",
            )
            if ba_shape is not None:
                shape_failures.append(ba_shape)
            _raise_derived_value_shape_failures(shape_failures)
            if val_ab is MISSING_ATTRIBUTE or val_ba is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=val_ab,
                expected=val_ba,
                label="CKM_ECDH1_DERIVE:shared-secret agreement (A*B == B*A)",
                operation="C_DeriveKey",
                mechanism="CKM_ECDH1_DERIVE",
            )
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            if shared_ab:
                destroy_quietly(rs.raw, rs.sh, shared_ab)
            if shared_ba:
                destroy_quietly(rs.raw, rs.sh, shared_ba)

    def test_ecdh_different_peers_different_secrets(self, p11_raw_session: Any) -> None:
        """ECDH with different peers produces different shared secrets."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        _pub_a = priv_a = pub_b = _priv_b = pub_c = _priv_c = 0
        shared_ab = 0
        shared_ac = 0
        try:
            _pub_a, priv_a = self._generate_ec_keypair(rs)
            pub_b, _priv_b = self._generate_ec_keypair(rs)
            pub_c, _priv_c = self._generate_ec_keypair(rs)
            point_b = self._extract_ec_point(rs, pub_b)
            point_c = self._extract_ec_point(rs, pub_c)

            shared_ab = self._derive_shared(rs, priv_a, point_b)
            shared_ac = self._derive_shared(rs, priv_a, point_c)

            shape_failures: list[classification.Classification] = []
            val_ab_attrs = read_attributes(rs.raw, rs.sh, shared_ab, [CKA_VALUE])
            val_ab = attr_or_record(
                val_ab_attrs,
                CKA_VALUE,
                label="CKM_ECDH1_DERIVE:shared AB CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            ab_shape = _record_derived_value_shape(
                val_ab,
                leg="ab",
                expected_shape="non-empty bytes",
                expected_length=None,
                producer_mechanism="CKM_ECDH1_DERIVE",
            )
            if ab_shape is not None:
                shape_failures.append(ab_shape)

            val_ac_attrs = read_attributes(rs.raw, rs.sh, shared_ac, [CKA_VALUE])
            val_ac = attr_or_record(
                val_ac_attrs,
                CKA_VALUE,
                label="CKM_ECDH1_DERIVE:shared AC CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            ac_shape = _record_derived_value_shape(
                val_ac,
                leg="ac",
                expected_shape="non-empty bytes",
                expected_length=None,
                producer_mechanism="CKM_ECDH1_DERIVE",
            )
            if ac_shape is not None:
                shape_failures.append(ac_shape)
            _raise_derived_value_shape_failures(shape_failures)
            if val_ab is MISSING_ATTRIBUTE or val_ac is MISSING_ATTRIBUTE:
                return
            peer_b_x = point_b.public_key.public_numbers().x
            peer_c_x = point_c.public_key.public_numbers().x
            if peer_b_x == peer_c_x:
                return
            if val_ab == val_ac:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="CKM_ECDH1_DERIVE:different peers produce different secrets",
                    operation="C_DeriveKey",
                    mechanism="CKM_ECDH1_DERIVE",
                    detail={"relation": "different_peer_outputs", "legs": ["ab", "ac"]},
                    summary="CKM_ECDH1_DERIVE:different peers produced the same shared secret",
                )
        finally:
            for h in (_pub_a, priv_a, pub_b, _priv_b, pub_c, _priv_c):
                if h:
                    destroy_quietly(rs.raw, rs.sh, h)
            if shared_ab:
                destroy_quietly(rs.raw, rs.sh, shared_ab)
            if shared_ac:
                destroy_quietly(rs.raw, rs.sh, shared_ac)


# ---------------------------------------------------------------------------
# SHA-3 / SHAKE hash-based key derivation
# ---------------------------------------------------------------------------

_SHA3_SHAKE_DERIVE_MECHS = [
    ("SHA3_224_KEY_DERIVE", CKM_SHA3_224_KEY_DERIVE),
    ("SHA3_256_KEY_DERIVE", CKM_SHA3_256_KEY_DERIVE),
    ("SHA3_384_KEY_DERIVE", CKM_SHA3_384_KEY_DERIVE),
    ("SHA3_512_KEY_DERIVE", CKM_SHA3_512_KEY_DERIVE),
    ("SHAKE_128_KEY_DERIVE", CKM_SHAKE_128_KEY_DERIVE),
    ("SHAKE_256_KEY_DERIVE", CKM_SHAKE_256_KEY_DERIVE),
]

_SHA3_SHAKE_OUTPUT_LENGTHS = {
    int(CKM_SHA3_224_KEY_DERIVE): 28,
    int(CKM_SHA3_256_KEY_DERIVE): 32,
    int(CKM_SHA3_384_KEY_DERIVE): 48,
    int(CKM_SHA3_512_KEY_DERIVE): 64,
    int(CKM_SHAKE_128_KEY_DERIVE): 32,
    int(CKM_SHAKE_256_KEY_DERIVE): 32,
}


class TestSHA3ShakeKeyDerive:
    """SHA3/SHAKE hash-based key derivation (CKM_SHA3_*_KEY_DERIVE, CKM_SHAKE_*_KEY_DERIVE)."""

    @pytest.mark.parametrize(
        "mech_name,ckm",
        _SHA3_SHAKE_DERIVE_MECHS,
        ids=[m[0] for m in _SHA3_SHAKE_DERIVE_MECHS],
    )
    def test_derive_produces_key(self, p11_raw_session: Any, mech_name: str, ckm: int) -> None:
        """Derive a key using hash-based derivation and verify it's usable."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        base_key = _import_generic_secret(rs, b"SHA3/SHAKE derive base key material!")
        derived = 0
        try:
            output_len = _SHA3_SHAKE_OUTPUT_LENGTHS[int(ckm)]
            try:
                derived = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    ckm,
                    attrs={
                        CKA_CLASS: int(CKO_SECRET_KEY),
                        CKA_KEY_TYPE: int(CKK_GENERIC_SECRET),
                        CKA_VALUE_LEN: output_len,
                        CKA_TOKEN: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                    mech_param=None,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _DERIVE_ERROR_RVS, f"{mech_name} derivation not operational"
                )
            assert derived != 0
            # Verify derived key has value
            val_attrs = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])
            val = attr_or_record(
                val_attrs,
                CKA_VALUE,
                label=f"{mech_name}:derived CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            if val is MISSING_ATTRIBUTE:
                return
            assert isinstance(val, bytes) and len(val) == output_len
        finally:
            if derived:
                destroy_quietly(rs.raw, rs.sh, derived)
            destroy_quietly(rs.raw, rs.sh, base_key)

    @pytest.mark.parametrize(
        "mech_name,ckm",
        _SHA3_SHAKE_DERIVE_MECHS,
        ids=[m[0] for m in _SHA3_SHAKE_DERIVE_MECHS],
    )
    def test_derive_deterministic(self, p11_raw_session: Any, mech_name: str, ckm: int) -> None:
        """Same base key and mechanism -> same derived key value."""
        rs = p11_raw_session
        if not rs.has_mechanism(mech_name):
            pytest.skip(f"{mech_name} not supported")

        base_key = _import_generic_secret(rs, b"determinism test key material!!")
        d1 = d2 = 0
        try:
            attrs = {
                CKA_CLASS: int(CKO_SECRET_KEY),
                CKA_KEY_TYPE: int(CKK_GENERIC_SECRET),
                CKA_VALUE_LEN: 16,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            }
            try:
                d1 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    ckm,
                    attrs=attrs,
                    mech_param=None,
                )
                d2 = derive_key(
                    rs.raw,
                    rs.sh,
                    base_key,
                    ckm,
                    attrs=attrs,
                    mech_param=None,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _DERIVE_ERROR_RVS, f"{mech_name} derivation not operational"
                )
            shape_failures: list[classification.Classification] = []
            v1_attrs = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])
            v1 = attr_or_record(
                v1_attrs,
                CKA_VALUE,
                label=f"{mech_name}:deterministic output 1 CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            v1_shape = _record_derived_value_shape(
                v1,
                leg="output_1",
                expected_shape="16-byte bytes",
                expected_length=16,
                producer_mechanism=f"CKM_{mech_name}",
            )
            if v1_shape is not None:
                shape_failures.append(v1_shape)

            v2_attrs = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])
            v2 = attr_or_record(
                v2_attrs,
                CKA_VALUE,
                label=f"{mech_name}:deterministic output 2 CKA_VALUE",
                reason="not_operational",
                inherit_mechanism=False,
            )
            v2_shape = _record_derived_value_shape(
                v2,
                leg="output_2",
                expected_shape="16-byte bytes",
                expected_length=16,
                producer_mechanism=f"CKM_{mech_name}",
            )
            if v2_shape is not None:
                shape_failures.append(v2_shape)
            producer_mechanism = f"CKM_{mech_name}"
            _raise_derived_value_shape_failures(shape_failures)
            if v1 is MISSING_ATTRIBUTE or v2 is MISSING_ATTRIBUTE:
                return
            assert_correct(
                actual=v1,
                expected=v2,
                label=f"{mech_name}:C_DeriveKey determinism",
                operation="C_DeriveKey",
                mechanism=producer_mechanism,
            )
        finally:
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)
            destroy_quietly(rs.raw, rs.sh, base_key)
