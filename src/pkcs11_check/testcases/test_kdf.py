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

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import mech_ecdh, mech_hkdf
from pkcs11_check.raw.recipes import (
    derive_key,
    destroy_quietly,
    import_secret_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
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
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_ec_keypair_or_xfail,
    hmac_sign_or_xfail,
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


def _import_generic_secret(rs: Any, value: bytes, derive: bool = True) -> int:
    """Import a GENERIC_SECRET key with DERIVE=True."""
    return import_secret_key(
        rs.raw,
        rs.sh,
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

        p11_key = import_secret_key(
            rs.raw,
            rs.sh,
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

        p11_key = import_secret_key(
            rs.raw,
            rs.sh,
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
            okm = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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

    def _extract_ec_point(self, rs: Any, pub_handle: int) -> bytes:
        ec_point_raw = read_attributes(rs.raw, rs.sh, pub_handle, [CKA_EC_POINT])[CKA_EC_POINT]
        return decode_ec_point(bytes(ec_point_raw))

    def _derive_shared(
        self,
        rs: Any,
        priv_handle: int,
        peer_point: bytes,
    ) -> int:
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
            mech_param=mech_ecdh(
                CKM_ECDH1_DERIVE,
                kdf=CKD_NULL,
                public_data=peer_point,
            ),
        )

    def test_ecdh_keypair_independence(self, p11_raw_session: Any) -> None:
        """Two independently generated EC keypairs have different public points."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")

        pub_a, priv_a = self._generate_ec_keypair(rs)
        pub_b, priv_b = self._generate_ec_keypair(rs)
        try:
            point_a = read_attributes(rs.raw, rs.sh, pub_a, [CKA_EC_POINT])[CKA_EC_POINT]
            point_b = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])[CKA_EC_POINT]
            assert point_a != point_b
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b):
                destroy_quietly(rs.raw, rs.sh, h)

    def test_ecdh_shared_secret_agreement(self, p11_raw_session: Any) -> None:
        """ECDH: A derives with B's pubkey == B derives with A's pubkey."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key generation not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        pub_a, priv_a = self._generate_ec_keypair(rs)
        pub_b, priv_b = self._generate_ec_keypair(rs)
        shared_ab = 0
        shared_ba = 0
        try:
            point_a = self._extract_ec_point(rs, pub_a)
            point_b = self._extract_ec_point(rs, pub_b)

            shared_ab = self._derive_shared(rs, priv_a, point_b)
            shared_ba = self._derive_shared(rs, priv_b, point_a)

            val_ab = read_attributes(rs.raw, rs.sh, shared_ab, [CKA_VALUE])[CKA_VALUE]
            val_ba = read_attributes(rs.raw, rs.sh, shared_ba, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=val_ab,
                expected=val_ba,
                label="CKM_ECDH1_DERIVE:shared-secret agreement (A*B == B*A)",
                operation="C_DeriveKey",
                mechanism="CKM_ECDH1_DERIVE",
            )
        finally:
            for h in (pub_a, priv_a, pub_b, priv_b):
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

        _pub_a, priv_a = self._generate_ec_keypair(rs)
        pub_b, _priv_b = self._generate_ec_keypair(rs)
        pub_c, _priv_c = self._generate_ec_keypair(rs)
        shared_ab = 0
        shared_ac = 0
        try:
            point_b = self._extract_ec_point(rs, pub_b)
            point_c = self._extract_ec_point(rs, pub_c)

            shared_ab = self._derive_shared(rs, priv_a, point_b)
            shared_ac = self._derive_shared(rs, priv_a, point_c)

            val_ab = read_attributes(rs.raw, rs.sh, shared_ab, [CKA_VALUE])[CKA_VALUE]
            val_ac = read_attributes(rs.raw, rs.sh, shared_ac, [CKA_VALUE])[CKA_VALUE]
            assert val_ab != val_ac
        finally:
            for h in (_pub_a, priv_a, pub_b, _priv_b, pub_c, _priv_c):
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
            val = read_attributes(rs.raw, rs.sh, derived, [CKA_VALUE])[CKA_VALUE]
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
            v1 = read_attributes(rs.raw, rs.sh, d1, [CKA_VALUE])[CKA_VALUE]
            v2 = read_attributes(rs.raw, rs.sh, d2, [CKA_VALUE])[CKA_VALUE]
            assert_correct(
                actual=v1,
                expected=v2,
                label=f"{mech_name}:C_DeriveKey determinism",
                operation="C_DeriveKey",
                mechanism=f"CKM_{mech_name}",
            )
        finally:
            if d1:
                destroy_quietly(rs.raw, rs.sh, d1)
            if d2:
                destroy_quietly(rs.raw, rs.sh, d2)
            destroy_quietly(rs.raw, rs.sh, base_key)
