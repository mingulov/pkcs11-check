"""CKR compliance tests for C_GenerateKey and C_GenerateKeyPair.

Source: PKCS#11 v3.1 Sec.5.14.1 (C_GenerateKey), Sec.5.14.2 (C_GenerateKeyPair).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_EC_PARAMS,
    CKA_EXTRACTABLE,
    CKA_MODULUS_BITS,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_VALUE_LEN,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEYGEN, assert_ckr

pytestmark = pytest.mark.access


class TestGenerateKeyErrors:
    """Error conditions for C_GenerateKey (Sec.5.14.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for keygen -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_SHA256)
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
        key = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(key.value))
            pytest.fail("Should have rejected SHA256 as key generation mechanism")
        assert_ckr(CKR_KEYGEN["genkey_mechanism_invalid"], rv, ckr_strict)

    def test_bad_key_size_zero(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key size 0 -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        exp = CKR_KEYGEN["genkey_bad_size"]
        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 0))
        key = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(key.value))
            if not exp.allow_success:
                pytest.fail("Should have rejected AES key size 0")
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_GenerateKey accepted AES key size 0",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        else:
            assert_ckr(exp, rv, ckr_strict)

    def test_bad_key_size_non_standard(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key size 100 bits (not 128/192/256) -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        exp = CKR_KEYGEN["genkey_bad_size"]
        mech = mech_simple(CKM_AES_KEY_GEN)
        # AES CKA_VALUE_LEN is in bytes; 100 bits ~= 12.5 bytes, use 13
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 13))
        key = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(key.value))
            if not exp.allow_success:
                pytest.fail("Should have rejected AES key size 13 bytes (non-standard)")
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_GenerateKey accepted AES key size 13 bytes (non-standard)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference=exp.spec_ref,
            )
        else:
            assert_ckr(exp, rv, ckr_strict)

    def test_template_inconsistent(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """SENSITIVE=False + EXTRACTABLE=False -> CKR_TEMPLATE_INCONSISTENT.

        A key that is both non-sensitive and non-extractable is contradictory
        in some modules. Others may accept it.
        """
        rs = p11_raw_session
        exp = CKR_KEYGEN["genkey_template_inconsistent"]
        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(
            attr_ulong(CKA_VALUE_LEN, 32),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, False),
            attr_bool(CKA_PRIVATE, True),
        )
        key = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(key.value))
            # Some modules accept this - it's a spec grey area
        else:
            assert_ckr(exp, rv, ckr_strict)


class TestGenerateKeyPairErrors:
    """Error conditions for C_GenerateKeyPair (Sec.5.14.2)."""

    def test_bad_rsa_size_zero(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA key size 0 -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(attr_ulong(CKA_MODULUS_BITS, 0))
        priv_tmpl = template()
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKeyPair(
                rs.sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub),
                byref(priv),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(pub.value))
            destroy_quietly(rs.raw, rs.sh, int(priv.value))
            pytest.fail("Should have rejected RSA key size 0")
        assert_ckr(CKR_KEYGEN["genkeypair_bad_size"], rv, ckr_strict)

    def test_bad_rsa_size_tiny(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """RSA key size 64 (too small) -> reject."""
        rs = p11_raw_session
        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(attr_ulong(CKA_MODULUS_BITS, 64))
        priv_tmpl = template()
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKeyPair(
                rs.sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub),
                byref(priv),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(pub.value))
            destroy_quietly(rs.raw, rs.sh, int(priv.value))
            pytest.fail("Should have rejected RSA key size 64")
        assert_ckr(CKR_KEYGEN["genkeypair_bad_size"], rv, ckr_strict)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using AES mechanism for keypair gen -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_AES_ECB)
        pub_tmpl = template(attr_ulong(CKA_MODULUS_BITS, 2048))
        priv_tmpl = template()
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKeyPair(
                rs.sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub),
                byref(priv),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(pub.value))
            destroy_quietly(rs.raw, rs.sh, int(priv.value))
            pytest.fail("Should have rejected AES_ECB for RSA keypair generation")
        assert_ckr(CKR_KEYGEN["genkeypair_mechanism_invalid"], rv, ckr_strict)

    def test_ec_curve_not_supported(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """EC keygen with unsupported/invalid curve -> CKR_CURVE_NOT_SUPPORTED."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")
        # Use a bogus OID that no module should support
        bogus_oid = bytes([0x06, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00])
        mech = mech_simple(CKM_EC_KEY_PAIR_GEN)
        pub_tmpl = template(attr_bytes(CKA_EC_PARAMS, bogus_oid))
        priv_tmpl = template()
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKeyPair(
                rs.sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub),
                byref(priv),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(pub.value))
            destroy_quietly(rs.raw, rs.sh, int(priv.value))
            pytest.fail("Should have rejected bogus EC curve OID")
        assert_ckr(CKR_KEYGEN["genkeypair_curve_not_supported"], rv, ckr_strict)

    def test_attribute_type_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Keygen with bogus attribute type -> CKR_ATTRIBUTE_TYPE_INVALID."""
        rs = p11_raw_session
        exp = CKR_KEYGEN["genkey_attribute_type_invalid"]
        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(
            attr_ulong(CKA_VALUE_LEN, 32),
            attr_bool(0xFFFFFFFF, True),  # Bogus attribute type
        )
        key = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKey(
                rs.sh,
                mech.byref(),
                tmpl.ptr,
                tmpl.count,
                byref(key),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(key.value))
            if not exp.allow_success:
                pytest.fail("Should have rejected bogus attribute type")
        else:
            assert_ckr(exp, rv, ckr_strict)

    def test_domain_params_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """EC keygen with malformed EC params -> CKR_DOMAIN_PARAMS_INVALID."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC key gen not supported")
        # Malformed: valid OID header but truncated/corrupt content
        bad_params = bytes([0x06, 0x03, 0x00, 0x00, 0x00])
        mech = mech_simple(CKM_EC_KEY_PAIR_GEN)
        pub_tmpl = template(attr_bytes(CKA_EC_PARAMS, bad_params))
        priv_tmpl = template()
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = int(
            rs.raw.C_GenerateKeyPair(
                rs.sh,
                mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub),
                byref(priv),
            )
        )
        if rv == int(CKR_OK):
            destroy_quietly(rs.raw, rs.sh, int(pub.value))
            destroy_quietly(rs.raw, rs.sh, int(priv.value))
            pytest.fail("Should have rejected malformed EC params")
        assert_ckr(CKR_KEYGEN["genkeypair_domain_params_invalid"], rv, ckr_strict)
