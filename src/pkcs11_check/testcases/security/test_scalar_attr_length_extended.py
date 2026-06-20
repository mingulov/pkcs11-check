"""Scalar attribute declared-length-mismatch probes (Wave 3).

Broaden the existing declared-length-mismatch coverage in
``ckr/test_ckr_object.py`` / ``ckr/test_ckr_keygen.py`` (which covers
``CKA_TOKEN`` bool, ``CKA_CLASS`` / ``CKA_KEY_TYPE`` / ``CKA_VALUE_LEN`` /
``CKA_PARAMETER_SET`` ulong) to the remaining security-relevant matrix:

- Operation-permission booleans (ENCRYPT/DECRYPT/SIGN/VERIFY/WRAP/UNWRAP/DERIVE)
- Sensitivity booleans (SENSITIVE/EXTRACTABLE/ALWAYS_SENSITIVE/NEVER_EXTRACTABLE)
- ``CKA_MODULUS_BITS`` (mechanism-specific integer) in ``C_GenerateKeyPair(RSA)``
- ``CKA_PUBLIC_EXPONENT`` / ``CKA_MODULUS`` wild-oversized in ``C_CreateObject``
- ``CKA_VALUE_LEN`` in ``C_DeriveKey(HKDF)`` (previously zero declared-length coverage)
- Wild-oversized (``ulValueLen=0xFFFFFFFF``) declared length on bool/ulong

Each probe declares a tiny real buffer with an impossible claimed length;
crash or accept-invalid = fail, spec-correct reject = pass, other clean
reject = xfail (nonspec).
"""

from __future__ import annotations

import ctypes
from ctypes import byref, sizeof
from typing import Any

import pytest

from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    LengthArg,
    attr_bool,
    attr_bytes,
    attr_ulong,
    mech_ecdh,
    mech_simple,
    template,
)
from pkcs11_check.raw.pack_mechanisms import mech_hkdf
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    gen_ec_keypair,
    read_attributes,
    wrap_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_NEVER_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKD_NULL,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKK_RSA,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_ECDH1_DERIVE,
    CKM_HKDF_DERIVE,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKO_DATA,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_OK,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS
from pkcs11_check.testcases.ckr._malformed_attrs import (
    make_bool_attr_overlong,
    make_ulong_attr_with_length,
)
from pkcs11_check.testcases.conftest import classify_negative_rv, gen_aes_key_or_xfail

pytestmark = pytest.mark.security


# Wild-oversized declared length: real buffer is tiny, ulValueLen = 0xFFFFFFFF.
# This is the "impossible claimed length" probe class distinct from the
# moderate overlong (CK_ULONG-sized for bool, sizeof+1 for ulong) used by
# the existing make_bool_attr_overlong / make_ulong_attr_with_length helpers.
_WILD_OVERSIZED_LENGTH = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Task 1: Operation-permission booleans (7 attrs) overlong in C_CreateObject
# ---------------------------------------------------------------------------


class TestOperationPermissionBoolOverlong:
    """Operation-permission booleans declared with CK_ULONG-sized storage
    instead of CK_BBOOL must be rejected by ``C_CreateObject``."""

    @pytest.mark.parametrize(
        "attr_type",
        [
            CKA_ENCRYPT,
            CKA_DECRYPT,
            CKA_SIGN,
            CKA_VERIFY,
            CKA_WRAP,
            CKA_UNWRAP,
            CKA_DERIVE,
        ],
        ids=[
            "encrypt",
            "decrypt",
            "sign",
            "verify",
            "wrap",
            "unwrap",
            "derive",
        ],
    )
    def test_op_permission_bool_overlong_in_create(
        self,
        p11_raw_session: Any,
        attr_type: int,
    ) -> None:
        """C_CreateObject must reject a CK_ULONG-sized operation-permission bool."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"op-bool-overlong"),
            attr_bytes(CKA_VALUE, b"value"),
            attr_bool(attr_type, False),
        )
        _storage = make_bool_attr_overlong(tmpl, 3)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(f"C_CreateObject with CK_ULONG-sized {ckr_name(attr_type)} boolean attribute"),
        )


# ---------------------------------------------------------------------------
# Task 2: Sensitivity booleans (4 attrs) overlong in C_CreateObject
# ---------------------------------------------------------------------------


class TestSensitivityBoolOverlong:
    """Sensitivity booleans declared with CK_ULONG-sized storage instead of
    CK_BBOOL must be rejected by ``C_CreateObject``."""

    @pytest.mark.parametrize(
        "attr_type",
        [
            CKA_SENSITIVE,
            CKA_EXTRACTABLE,
            CKA_ALWAYS_SENSITIVE,
            CKA_NEVER_EXTRACTABLE,
        ],
        ids=[
            "sensitive",
            "extractable",
            "always_sensitive",
            "never_extractable",
        ],
    )
    def test_sensitivity_bool_overlong_in_create(
        self,
        p11_raw_session: Any,
        attr_type: int,
    ) -> None:
        """C_CreateObject must reject a CK_ULONG-sized sensitivity bool."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"sens-bool-overlong"),
            attr_bytes(CKA_VALUE, b"value"),
            attr_bool(attr_type, False),
        )
        _storage = make_bool_attr_overlong(tmpl, 3)
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(f"C_CreateObject with CK_ULONG-sized {ckr_name(attr_type)} boolean attribute"),
        )


# ---------------------------------------------------------------------------
# Task 3: CKA_MODULUS_BITS (mechanism-specific integer) malformed in
#         C_GenerateKeyPair(RSA) public template
# ---------------------------------------------------------------------------


class TestRsaModulusBitsInKeygen:
    """``CKA_MODULUS_BITS`` in ``C_GenerateKeyPair(RSA)`` public template must
    reject when declared with a non-CK_ULONG-sized storage. Closes the gap
    left by ``test_ckr_keygen.py`` whose keygen malformed-length coverage is
    limited to ``CKA_TOKEN`` / ``CKA_VALUE_LEN`` / ``CKA_PARAMETER_SET``."""

    @pytest.mark.parametrize(
        ("attr_len", "case_name"),
        [
            pytest.param(1, "underlong", id="underlong"),
            pytest.param(sizeof(CK_ULONG) + 1, "overlong", id="overlong"),
        ],
    )
    def test_rsa_modulus_bits_malformed_length(
        self,
        p11_raw_session: Any,
        attr_len: int,
        case_name: str,
    ) -> None:
        """C_GenerateKeyPair(RSA) must reject malformed CKA_MODULUS_BITS."""
        rs = p11_raw_session
        if not rs.has_mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(
            attr_ulong(CKA_MODULUS_BITS, 2048),
            attr_bool(CKA_TOKEN, False),
        )
        priv_tmpl = template(
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_PRIVATE, True),
        )
        _storage = make_ulong_attr_with_length(pub_tmpl, 0, 2048, attr_len)
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
            label=(f"C_GenerateKeyPair(RSA) with {case_name} CKA_MODULUS_BITS CK_ULONG attribute"),
        )


# ---------------------------------------------------------------------------
# Task 4: CKA_PUBLIC_EXPONENT / CKA_MODULUS wild-oversized in C_CreateObject
# ---------------------------------------------------------------------------


class TestRsaPublicKeyAttrOverlong:
    """``CKA_PUBLIC_EXPONENT`` and ``CKA_MODULUS`` (byte arrays) declared with
    wildly oversized ``ulValueLen`` (real buffer tiny, declared length
    ``0xFFFFFFFF``) in ``C_CreateObject`` must be rejected cleanly."""

    @pytest.mark.parametrize(
        ("attr_type", "attr_name"),
        [
            pytest.param(CKA_PUBLIC_EXPONENT, "public_exponent", id="public-exponent"),
            pytest.param(CKA_MODULUS, "modulus", id="modulus"),
        ],
    )
    def test_rsa_pub_attr_wild_oversized_in_create(
        self,
        p11_raw_session: Any,
        attr_type: int,
        attr_name: str,
    ) -> None:
        """C_CreateObject must reject a wildly oversized RSA public-key attr."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_RSA),
            attr_bytes(CKA_LABEL, b"rsa-pub-wild"),
            attr_bytes(
                attr_type,
                b"\x01\x00\x01",
                length=LengthArg.explicit_value(_WILD_OVERSIZED_LENGTH),
            ),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(f"C_CreateObject with wildly oversized CKA_{attr_name.upper()} bytes attribute"),
        )


# ---------------------------------------------------------------------------
# Task 5: CKA_VALUE_LEN in C_DeriveKey(HKDF) output template (NEW CONTEXT)
# ---------------------------------------------------------------------------


class TestDeriveKeyAttrLengthMismatch:
    """``CKA_VALUE_LEN`` in ``C_DeriveKey(HKDF)`` output template must reject
    when declared with a non-CK_ULONG-sized storage. ``C_DeriveKey`` previously
    had zero declared-length-mismatch coverage."""

    @pytest.mark.parametrize(
        ("attr_len", "case_name"),
        [
            pytest.param(1, "underlong", id="underlong"),
            pytest.param(sizeof(CK_ULONG) + 1, "overlong", id="overlong"),
        ],
    )
    def test_derive_value_len_malformed_length(
        self,
        p11_raw_session: Any,
        attr_len: int,
        case_name: str,
    ) -> None:
        """C_DeriveKey(HKDF) must reject malformed CKA_VALUE_LEN."""
        rs = p11_raw_session
        if not rs.has_mechanism(CKM_HKDF_DERIVE):
            pytest.skip("CKM_HKDF_DERIVE not advertised")
        # Setup: derive base AES-256 key on the fixture session.
        base_key = gen_aes_key(
            rs.raw,
            rs.sh,
            bits=256,
            attrs={CKA_DERIVE: True, CKA_TOKEN: False},
        )
        try:
            out_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 32),
            )
            _storage = make_ulong_attr_with_length(out_tmpl, 2, 32, attr_len)
            mech = mech_hkdf(CKM_HKDF_DERIVE, hash_mech=CKM_SHA256)
            derived = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                mech.byref(),
                base_key,
                out_tmpl.ptr,
                out_tmpl.count,
                byref(derived),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label=(f"C_DeriveKey(HKDF) with {case_name} CKA_VALUE_LEN CK_ULONG attribute"),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, base_key)


# ---------------------------------------------------------------------------
# Task 6: Wild-oversized (ulValueLen=0xFFFFFFFF) bool/ulong in C_CreateObject
# ---------------------------------------------------------------------------


class TestWildOversizedAttrInCreate:
    """Attr declared length = ``0xFFFFFFFF`` (tiny real buffer) in
    ``C_CreateObject`` template must be rejected without crash. Distinct from
    the moderate overlong probes in :class:`TestOperationPermissionBoolOverlong`
    / :class:`TestSensitivityBoolOverlong` (which use ``CK_ULONG``-sized storage
    for a bool) — this probes the wild-oversized class where the declared
    length is far larger than any legitimate value."""

    def test_wild_oversized_bool_attr(self, p11_raw_session: Any) -> None:
        """CKA_ENCRYPT bool with ulValueLen=0xFFFFFFFF must reject cleanly."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"wild-bool"),
            attr_bytes(CKA_VALUE, b"value"),
            attr_bool(
                CKA_ENCRYPT,
                False,
                length=LengthArg.explicit_value(_WILD_OVERSIZED_LENGTH),
            ),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_CreateObject with wildly oversized CKA_ENCRYPT bool attribute",
        )

    def test_wild_oversized_ulong_attr(self, p11_raw_session: Any) -> None:
        """CKA_VALUE_LEN ulong with ulValueLen=0xFFFFFFFF must reject cleanly."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"\x01" * 16),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SENSITIVE, False),
            attr_ulong(
                CKA_VALUE_LEN,
                16,
                length=LengthArg.explicit_value(_WILD_OVERSIZED_LENGTH),
            ),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_CreateObject with wildly oversized CKA_VALUE_LEN ulong attribute",
        )


# ---------------------------------------------------------------------------
# Bool-overlong in C_CopyObject + C_UnwrapKey (new contexts)
# ---------------------------------------------------------------------------


class TestBoolOverlongInUnwrapCopy:
    """A CK_ULONG-sized boolean in unwrap/copy templates must be rejected."""

    def test_op_permission_bool_overlong_in_copy(self, p11_raw_session: Any) -> None:
        """C_CopyObject must reject a CK_ULONG-sized CKA_ENCRYPT boolean."""
        rs = p11_raw_session
        base = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_bytes(CKA_LABEL, b"copy-bool-overlong"),
            attr_bytes(CKA_VALUE, b"value"),
        )
        src_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, base.ptr, base.count, byref(src_h))
        if rv != CKR_OK:
            classify_negative_rv(rv, TEMPLATE_ERRORS, label="C_CreateObject DATA setup")
            return
        try:
            new_attrs = template(attr_bool(CKA_ENCRYPT, False))
            _storage = make_bool_attr_overlong(new_attrs, 3)
            dst_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_CopyObject(
                rs.sh, src_h.value, new_attrs.ptr, new_attrs.count, byref(dst_h)
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, dst_h.value)
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label="C_CopyObject with CK_ULONG-sized CKA_ENCRYPT boolean",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, src_h.value)

    def test_op_permission_bool_overlong_in_unwrap(self, p11_raw_session: Any) -> None:
        """C_UnwrapKey must reject a CK_ULONG-sized CKA_ENCRYPT boolean in the key template."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not advertised")
        kek = gen_aes_key_or_xfail(
            rs, 256, attrs={CKA_WRAP: True, CKA_UNWRAP: True}, purpose="unwrap-bool-overlong KEK"
        )
        target = gen_aes_key_or_xfail(
            rs, 128, attrs={CKA_EXTRACTABLE: True}, purpose="unwrap-bool-overlong target"
        )
        wrapped = wrap_key(rs.raw, rs.sh, kek, target, CKM_AES_KEY_WRAP)
        key_tmpl = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_ENCRYPT, False),
        )
        _storage = make_bool_attr_overlong(key_tmpl, 3)
        out_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_UnwrapKey(
            rs.sh,
            mech_simple(CKM_AES_KEY_WRAP).byref(),
            kek,
            (ctypes.c_ubyte * len(wrapped))(*wrapped),
            len(wrapped),
            key_tmpl.ptr,
            key_tmpl.count,
            byref(out_h),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, out_h.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label="C_UnwrapKey with CK_ULONG-sized CKA_ENCRYPT boolean in key template",
        )


# ---------------------------------------------------------------------------
# Phase 1 (C2 matrix): Bool-overlong in C_GenerateKey / C_GenerateKeyPair /
# C_DeriveKey  — the 3 remaining template contexts not yet covered by MVP.
# ---------------------------------------------------------------------------


class TestBoolOverlongInGenerateDerive:
    """A CK_ULONG-sized boolean in generate / generate-keypair / derive
    templates must be rejected; accepting it (CKR_OK) is the finding
    (accepted_invalid).  Mirrors :class:`TestBoolOverlongInUnwrapCopy`.
    """

    # ------------------------------------------------------------------
    # 1. C_GenerateKey (AES)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "attr_type",
        [
            CKA_ENCRYPT,
            CKA_SENSITIVE,
        ],
        ids=["encrypt", "sensitive"],
    )
    def test_bool_overlong_in_generate_aes_key(
        self,
        p11_raw_session: Any,
        attr_type: int,
    ) -> None:
        """C_GenerateKey(AES) must reject a CK_ULONG-sized operation bool."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not advertised")
        mech = mech_simple(CKM_AES_KEY_GEN)
        keygen_tmpl = template(
            attr_ulong(CKA_VALUE_LEN, 32),
            attr_bool(CKA_TOKEN, False),
            attr_bool(attr_type, False),
        )
        # Corrupt slot 2 (the attr_type bool) to CK_ULONG-sized storage.
        _storage = make_bool_attr_overlong(keygen_tmpl, 2)
        out_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh, mech.byref(), keygen_tmpl.ptr, keygen_tmpl.count, byref(out_h)
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, out_h.value)
        classify_negative_rv(
            rv,
            TEMPLATE_ERRORS,
            label=(
                f"C_GenerateKey(AES) with CK_ULONG-sized {ckr_name(attr_type)} boolean attribute"
            ),
        )

    # ------------------------------------------------------------------
    # 2. C_GenerateKeyPair (RSA) — overlong bool in private-key template
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "attr_type",
        [
            CKA_SIGN,
            CKA_SENSITIVE,
        ],
        ids=["sign", "sensitive"],
    )
    def test_bool_overlong_in_generate_rsa_keypair(
        self,
        p11_raw_session: Any,
        attr_type: int,
    ) -> None:
        """C_GenerateKeyPair(RSA) must reject a CK_ULONG-sized bool in the priv template."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not advertised")
        mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        pub_tmpl = template(
            attr_ulong(CKA_MODULUS_BITS, 2048),
            attr_bytes(CKA_PUBLIC_EXPONENT, b"\x01\x00\x01"),
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_VERIFY, True),
        )
        priv_tmpl = template(
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_PRIVATE, True),
            attr_bool(attr_type, False),
        )
        # Corrupt slot 2 (attr_type bool) in the private template.
        _storage = make_bool_attr_overlong(priv_tmpl, 2)
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
                f"C_GenerateKeyPair(RSA) priv-tmpl with CK_ULONG-sized"
                f" {ckr_name(attr_type)} boolean attribute"
            ),
        )

    # ------------------------------------------------------------------
    # 3. C_DeriveKey (ECDH1) — overlong bool in the derived-key template
    # ------------------------------------------------------------------

    @pytest.mark.parametrize(
        "attr_type",
        [
            CKA_ENCRYPT,
            CKA_SENSITIVE,
        ],
        ids=["encrypt", "sensitive"],
    )
    def test_bool_overlong_in_derive_ecdh(
        self,
        p11_raw_session: Any,
        attr_type: int,
    ) -> None:
        """C_DeriveKey(ECDH1) must reject a CK_ULONG-sized bool in the derived-key template."""
        rs = p11_raw_session
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not advertised")
        if not (rs.has_mechanism("EC_KEY_PAIR_GEN") or rs.has_mechanism("ECDSA_KEY_PAIR_GEN")):
            pytest.skip("EC_KEY_PAIR_GEN not advertised — cannot set up ECDH base key")
        curve_oid = encode_named_curve_parameters("secp256r1")
        pub_a, priv_a = gen_ec_keypair(
            rs.raw,
            rs.sh,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            public_attrs={CKA_TOKEN: False},
        )
        pub_b, priv_b = gen_ec_keypair(
            rs.raw,
            rs.sh,
            curve_oid,
            private_attrs={CKA_DERIVE: True, CKA_TOKEN: False},
            public_attrs={CKA_TOKEN: False},
        )
        try:
            # Read peer public point (raw bytes from DER OCTET STRING).
            from pkcs11_check.raw.der import decode_ec_point

            attrs_b = read_attributes(rs.raw, rs.sh, pub_b, [CKA_EC_POINT])
            raw_point = attrs_b[CKA_EC_POINT]
            assert isinstance(raw_point, bytes)
            # Unwrap DER OCTET STRING wrapper if present (Weierstrass curve).
            if raw_point and raw_point[0] == 0x04:
                peer_point = decode_ec_point(raw_point)
            else:
                peer_point = raw_point
            ecdh_mech = mech_ecdh(CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point)
            out_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_ulong(CKA_VALUE_LEN, 32),
                attr_bool(attr_type, False),
            )
            # Corrupt slot 3 (attr_type bool) in the derived-key template.
            _storage = make_bool_attr_overlong(out_tmpl, 3)
            derived = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                ecdh_mech.byref(),
                priv_a,
                out_tmpl.ptr,
                out_tmpl.count,
                byref(derived),
            )
            if rv == CKR_OK:
                destroy_quietly(rs.raw, rs.sh, derived.value)
            classify_negative_rv(
                rv,
                TEMPLATE_ERRORS,
                label=(
                    f"C_DeriveKey(ECDH1) with CK_ULONG-sized"
                    f" {ckr_name(attr_type)} boolean attribute in derived-key template"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_a)
            destroy_quietly(rs.raw, rs.sh, priv_a)
            destroy_quietly(rs.raw, rs.sh, pub_b)
            destroy_quietly(rs.raw, rs.sh, priv_b)
