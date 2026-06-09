"""CKR compliance tests for C_GenerateKey and C_GenerateKeyPair.

Source: PKCS#11 v3.1 Sec.5.14.1 (C_GenerateKey), Sec.5.14.2 (C_GenerateKeyPair).
"""

from __future__ import annotations

from ctypes import byref, sizeof
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_DECAPSULATE,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_ENCAPSULATE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_DES,
    CKK_DES2,
    CKK_DES3,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_DES2_KEY_GEN,
    CKM_DES3_KEY_GEN,
    CKM_DES_KEY_GEN,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKO_SECRET_KEY,
    CKP_ML_DSA_65,
    CKP_ML_KEM_768,
    CKR_OK,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._ckr_spec import CKR_KEYGEN, assert_ckr
from pkcs11_check.testcases.ckr._malformed_attrs import (
    make_bool_attr_overlong,
    make_ulong_attr_with_length,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.access

_FIXED_LENGTH_SECRET_KEYGEN_CASES: tuple[tuple[str, int, int], ...] = (
    ("DES_KEY_GEN", CKM_DES_KEY_GEN, CKK_DES),
    ("DES2_KEY_GEN", CKM_DES2_KEY_GEN, CKK_DES2),
    ("DES3_KEY_GEN", CKM_DES3_KEY_GEN, CKK_DES3),
)


class TestGenerateKeyErrors:
    """Error conditions for C_GenerateKey (Sec.5.14.1)."""

    def test_fixed_length_generate_key_accepts_null_empty_template(
        self, p11_raw_session: Any
    ) -> None:
        """Fixed-length C_GenerateKey may use pTemplate=NULL when ulCount is zero."""
        rs = p11_raw_session
        selected = next(
            (
                (name, mechanism, expected_key_type)
                for name, mechanism, expected_key_type in _FIXED_LENGTH_SECRET_KEYGEN_CASES
                if rs.has_mechanism(name)
            ),
            None,
        )
        if selected is None:
            pytest.skip("No fixed-length secret key generation mechanism supported")

        name, mechanism, expected_key_type = selected
        mech = mech_simple(mechanism)
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(rs.sh, mech.byref(), None, 0, byref(key))
        if rv != CKR_OK:
            pytest.xfail(f"{name} advertised but C_GenerateKey(NULL, 0) returned {ckr_name(rv)}")

        try:
            if not key.value:
                pytest.fail("C_GenerateKey(NULL, 0) returned CKR_OK without a key handle")
            attrs = read_attributes(rs.raw, rs.sh, key.value, [CKA_CLASS, CKA_KEY_TYPE])
            assert attrs[CKA_CLASS] == CKO_SECRET_KEY
            assert attrs[CKA_KEY_TYPE] == expected_key_type
        finally:
            destroy_quietly(rs.raw, rs.sh, key.value)

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using hash mechanism for keygen -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_SHA256)
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 32))
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
            pytest.fail("Should have rejected SHA256 as key generation mechanism")
        assert_ckr(CKR_KEYGEN["genkey_mechanism_invalid"], rv, ckr_strict)

    def test_bad_key_size_zero(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """AES key size 0 -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        exp = CKR_KEYGEN["genkey_bad_size"]
        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(attr_ulong(CKA_VALUE_LEN, 0))
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
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
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
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
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
            # Some modules accept this - it's a spec grey area
        else:
            assert_ckr(exp, rv, ckr_strict)

    def test_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """C_GenerateKey must reject CK_ULONG-sized CKA_TOKEN template value."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")

        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_ENCRYPT, True),
            attr_bool(CKA_DECRYPT, True),
        )
        _storage = make_bool_attr_overlong(tmpl, 1)
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_GenerateKey with CK_ULONG-sized CKA_TOKEN boolean attribute",
        )

    @pytest.mark.parametrize(
        ("attr_len", "case_name"),
        [
            pytest.param(1, "underlong", id="underlong"),
            pytest.param(sizeof(CK_ULONG) + 1, "overlong", id="overlong"),
        ],
    )
    def test_value_len_ulong_malformed_length(
        self,
        p11_raw_session: Any,
        attr_len: int,
        case_name: str,
    ) -> None:
        """C_GenerateKey must reject non-CK_ULONG-sized CKA_VALUE_LEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported")

        mech = mech_simple(CKM_AES_KEY_GEN)
        tmpl = template(
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_ENCRYPT, True),
            attr_bool(CKA_DECRYPT, True),
        )
        _storage = make_ulong_attr_with_length(tmpl, 0, 16, attr_len)
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=f"C_GenerateKey with {case_name} CKA_VALUE_LEN CK_ULONG attribute",
        )


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
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
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
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
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
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
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
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
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
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, key.value)
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
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
            pytest.fail("Should have rejected malformed EC params")
        assert_ckr(CKR_KEYGEN["genkeypair_domain_params_invalid"], rv, ckr_strict)

    def test_public_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """C_GenerateKeyPair must reject CK_ULONG-sized public CKA_TOKEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported")

        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(
            attr_ulong(CKA_MODULUS_BITS, 2048),
            attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_VERIFY, True),
            attr_bool(CKA_ENCRYPT, True),
        )
        priv_tmpl = template(
            attr_bool(CKA_SIGN, True),
            attr_bool(CKA_DECRYPT, True),
        )
        _storage = make_bool_attr_overlong(pub_tmpl, 2)
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_GenerateKeyPair with CK_ULONG-sized public CKA_TOKEN boolean attribute",
        )

    def test_private_token_bool_overlong_length(self, p11_raw_session: Any) -> None:
        """C_GenerateKeyPair must reject CK_ULONG-sized private CKA_TOKEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported")

        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(
            attr_ulong(CKA_MODULUS_BITS, 2048),
            attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
            attr_bool(CKA_VERIFY, True),
            attr_bool(CKA_ENCRYPT, True),
        )
        priv_tmpl = template(
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SIGN, True),
            attr_bool(CKA_DECRYPT, True),
        )
        _storage = make_bool_attr_overlong(priv_tmpl, 0)
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_GenerateKeyPair with CK_ULONG-sized private CKA_TOKEN boolean attribute",
        )

    @pytest.mark.parametrize(
        "malformed_template",
        ["public", "private"],
        ids=["public-template", "private-template"],
    )
    def test_ec_token_bool_overlong_length(
        self, p11_raw_session: Any, malformed_template: str
    ) -> None:
        """EC C_GenerateKeyPair must reject CK_ULONG-sized CKA_TOKEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("EC_KEY_PAIR_GEN not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        mech = mech_simple(CKM_EC_KEY_PAIR_GEN)
        control_pub_tmpl = template(
            attr_bytes(CKA_EC_PARAMS, curve_oid),
            attr_bool(CKA_VERIFY, True),
        )
        control_priv_tmpl = template(attr_bool(CKA_SIGN, True))
        control_pub = CK_OBJECT_HANDLE(0)
        control_priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            control_pub_tmpl.ptr,
            control_pub_tmpl.count,
            control_priv_tmpl.ptr,
            control_priv_tmpl.count,
            byref(control_pub),
            byref(control_priv),
        )
        if rv != CKR_OK:
            pytest.xfail(f"EC P-256 keypair generation is not operational: {ckr_name(rv)}")
        destroy_quietly(rs.raw, rs.sh, control_pub.value)
        destroy_quietly(rs.raw, rs.sh, control_priv.value)

        if malformed_template == "public":
            pub_tmpl = template(
                attr_bytes(CKA_EC_PARAMS, curve_oid),
                attr_bool(CKA_TOKEN, False),
                attr_bool(CKA_VERIFY, True),
            )
            priv_tmpl = template(attr_bool(CKA_SIGN, True))
            _storage = make_bool_attr_overlong(pub_tmpl, 1)
        else:
            pub_tmpl = template(
                attr_bytes(CKA_EC_PARAMS, curve_oid),
                attr_bool(CKA_VERIFY, True),
            )
            priv_tmpl = template(
                attr_bool(CKA_TOKEN, False),
                attr_bool(CKA_SIGN, True),
            )
            _storage = make_bool_attr_overlong(priv_tmpl, 0)
        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(
                f"EC C_GenerateKeyPair with CK_ULONG-sized {malformed_template} "
                "CKA_TOKEN boolean attribute"
            ),
        )

    @pytest.mark.pqc
    @pytest.mark.parametrize(
        ("malformed_template", "attr_len", "case_name"),
        [
            pytest.param("public", 1, "underlong", id="public-underlong"),
            pytest.param("public", sizeof(CK_ULONG) + 1, "overlong", id="public-overlong"),
            pytest.param("private", 1, "underlong", id="private-underlong"),
            pytest.param("private", sizeof(CK_ULONG) + 1, "overlong", id="private-overlong"),
        ],
    )
    def test_ml_kem_parameter_set_ulong_malformed_length(
        self,
        p11_raw_session: Any,
        malformed_template: str,
        attr_len: int,
        case_name: str,
    ) -> None:
        """ML-KEM CKA_PARAMETER_SET with non-CK_ULONG-sized storage must be rejected."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_KEM_KEY_PAIR_GEN"):
            pytest.skip("ML_KEM_KEY_PAIR_GEN not supported")

        mech = mech_simple(CKM_ML_KEM_KEY_PAIR_GEN)
        control_pub_tmpl = template(
            attr_bool(CKA_ENCAPSULATE, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
            attr_bool(CKA_TOKEN, False),
        )
        control_priv_tmpl = template(
            attr_bool(CKA_DECAPSULATE, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, False),
        )
        control_pub = CK_OBJECT_HANDLE(0)
        control_priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            control_pub_tmpl.ptr,
            control_pub_tmpl.count,
            control_priv_tmpl.ptr,
            control_priv_tmpl.count,
            byref(control_pub),
            byref(control_priv),
        )
        if rv != CKR_OK:
            pytest.xfail(f"ML-KEM-768 keypair generation is not operational: {ckr_name(rv)}")
        destroy_quietly(rs.raw, rs.sh, control_pub.value)
        destroy_quietly(rs.raw, rs.sh, control_priv.value)

        pub_tmpl = template(
            attr_bool(CKA_ENCAPSULATE, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
            attr_bool(CKA_TOKEN, False),
        )
        priv_tmpl = template(
            attr_bool(CKA_DECAPSULATE, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_KEM_768),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, False),
        )
        if malformed_template == "public":
            _storage = make_ulong_attr_with_length(pub_tmpl, 1, CKP_ML_KEM_768, attr_len)
        else:
            _storage = make_ulong_attr_with_length(priv_tmpl, 1, CKP_ML_KEM_768, attr_len)

        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(
                f"ML-KEM C_GenerateKeyPair with {case_name} {malformed_template} "
                "CKA_PARAMETER_SET CK_ULONG attribute"
            ),
        )

    @pytest.mark.pqc
    @pytest.mark.parametrize(
        ("malformed_template", "attr_len", "case_name"),
        [
            pytest.param("public", 1, "underlong", id="public-underlong"),
            pytest.param("public", sizeof(CK_ULONG) + 1, "overlong", id="public-overlong"),
            pytest.param("private", 1, "underlong", id="private-underlong"),
            pytest.param("private", sizeof(CK_ULONG) + 1, "overlong", id="private-overlong"),
        ],
    )
    def test_ml_dsa_parameter_set_ulong_malformed_length(
        self,
        p11_raw_session: Any,
        malformed_template: str,
        attr_len: int,
        case_name: str,
    ) -> None:
        """ML-DSA CKA_PARAMETER_SET with non-CK_ULONG-sized storage must be rejected."""
        rs = p11_raw_session
        if not rs.has_mechanism("ML_DSA_KEY_PAIR_GEN"):
            pytest.skip("ML_DSA_KEY_PAIR_GEN not supported")

        mech = mech_simple(CKM_ML_DSA_KEY_PAIR_GEN)
        control_pub_tmpl = template(
            attr_bool(CKA_VERIFY, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65),
            attr_bool(CKA_TOKEN, False),
        )
        control_priv_tmpl = template(
            attr_bool(CKA_SIGN, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, False),
        )
        control_pub = CK_OBJECT_HANDLE(0)
        control_priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            control_pub_tmpl.ptr,
            control_pub_tmpl.count,
            control_priv_tmpl.ptr,
            control_priv_tmpl.count,
            byref(control_pub),
            byref(control_priv),
        )
        if rv != CKR_OK:
            pytest.xfail(f"ML-DSA-65 keypair generation is not operational: {ckr_name(rv)}")
        destroy_quietly(rs.raw, rs.sh, control_pub.value)
        destroy_quietly(rs.raw, rs.sh, control_priv.value)

        pub_tmpl = template(
            attr_bool(CKA_VERIFY, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65),
            attr_bool(CKA_TOKEN, False),
        )
        priv_tmpl = template(
            attr_bool(CKA_SIGN, True),
            attr_ulong(CKA_PARAMETER_SET, CKP_ML_DSA_65),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, False),
        )
        if malformed_template == "public":
            _storage = make_ulong_attr_with_length(pub_tmpl, 1, CKP_ML_DSA_65, attr_len)
        else:
            _storage = make_ulong_attr_with_length(priv_tmpl, 1, CKP_ML_DSA_65, attr_len)

        pub = CK_OBJECT_HANDLE(0)
        priv = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKeyPair(
            rs.sh,
            mech.byref(),
            pub_tmpl.ptr,
            pub_tmpl.count,
            priv_tmpl.ptr,
            priv_tmpl.count,
            byref(pub),
            byref(priv),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, pub.value)
            destroy_quietly(rs.raw, rs.sh, priv.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(
                f"ML-DSA C_GenerateKeyPair with {case_name} {malformed_template} "
                "CKA_PARAMETER_SET CK_ULONG attribute"
            ),
        )
