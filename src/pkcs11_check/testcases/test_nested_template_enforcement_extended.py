"""Extended nested-template enforcement probes (Wave 5b).

The existing ``test_remaining_gaps.py::TestTemplateConstraintAttributes`` covers
``CKA_WRAP_TEMPLATE`` / ``CKA_UNWRAP_TEMPLATE`` / ``CKA_DERIVE_TEMPLATE`` on
**AES-only** mechanism paths (``CKM_AES_KEY_WRAP``, ``CKM_CONCATENATE_BASE_AND_DATA``)
with an inner ``CKA_LABEL`` constraint. This file extends coverage to the
mechanism paths the existing tests do **not** reach:

- RSA-OAEP unwrap (``CKA_UNWRAP_TEMPLATE`` on an RSA private key, ``CKM_RSA_PKCS_OAEP``)
- ECDH derive (``CKA_DERIVE_TEMPLATE`` on an EC private key, ``CKM_ECDH1_DERIVE``)
- HKDF derive (``CKA_DERIVE_TEMPLATE`` on a generic-secret base, ``CKM_HKDF_DERIVE``)

Each probe mirrors the canonical pattern: generate/import a key with the
nested-template attribute, read it back to confirm the module *claims* the
constraint, attempt a matching-template op (must succeed else ``not_operational``),
then attempt a violating-template op (must reject; ``CKR_OK`` is a policy
self-contradiction → ``fail``).
"""

from __future__ import annotations

from ctypes import byref, c_ubyte, c_ulong, sizeof
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.ec import encode_named_curve_parameters
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_template,
    attr_ulong,
    mech_ecdh,
    mech_hkdf,
    mech_oaep,
    mech_simple,
    template,
)
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_DERIVE_TEMPLATE,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS_BITS,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_UNWRAP_TEMPLATE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKD_NULL,
    CKG_MGF1_SHA1,
    CKK_AES,
    CKK_EC,
    CKK_GENERIC_SECRET,
    CKK_RSA,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDH1_DERIVE,
    CKM_HKDF_DERIVE,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS_OAEP,
    CKM_SHA256,
    CKM_SHA_1,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
)

pytestmark = [pytest.mark.compliance]

# Setup-reject CKRs shared across all template-attribute probes (mirrors
# test_remaining_gaps.py:130-143 — the same set used for the AES-only paths).
_TEMPLATE_ATTR_SETUP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_UNWRAP_TEMPLATE_ENFORCEMENT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)

_DERIVE_TEMPLATE_ENFORCEMENT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_SIZE_RANGE,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


class TestOaepUnwrapTemplateEnforcement:
    """CKA_UNWRAP_TEMPLATE enforcement on the RSA-OAEP unwrap path.

    The existing ``test_unwrap_template_enforces_created_object_attributes``
    covers the AES-key-wrap path. This class exercises RSA-OAEP — the
    asymmetric unwrap path where the unwrapping key is an RSA private key.
    """

    def test_oaep_unwrap_template_enforces_created_object_label(
        self, p11_raw_session: Any
    ) -> None:
        """CKA_UNWRAP_TEMPLATE on an RSA private key must block OAEP-unwrap to a violating label."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")

        allowed_label = b"pkcs11-check-oaep-unwrap-template-allowed"
        denied_label = b"pkcs11-check-oaep-unwrap-template-denied"
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))

        keygen_mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
        wrap_mech = mech_oaep(
            CKM_RSA_PKCS_OAEP, hash_mech=CKM_SHA_1, mgf=CKG_MGF1_SHA1
        )

        pub_rsa = CK_OBJECT_HANDLE(0)
        priv_rsa = CK_OBJECT_HANDLE(0)
        source_key = 0
        matching_unwrapped = 0
        violating_unwrapped = CK_OBJECT_HANDLE(0)
        try:
            pub_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_RSA),
                attr_ulong(CKA_MODULUS_BITS, 2048),
                attr_bool(CKA_ENCRYPT, True),
                attr_bool(CKA_WRAP, True),
                attr_bool(CKA_TOKEN, False),
            )
            priv_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_RSA),
                attr_bool(CKA_DECRYPT, True),
                attr_bool(CKA_UNWRAP, True),
                attr_bool(CKA_SENSITIVE, True),
                attr_bool(CKA_EXTRACTABLE, False),
                attr_bool(CKA_TOKEN, False),
                attr_template(CKA_UNWRAP_TEMPLATE, nested_template),
            )
            rv = rs.raw.C_GenerateKeyPair(
                rs.sh,
                keygen_mech.byref(),
                pub_tmpl.ptr,
                pub_tmpl.count,
                priv_tmpl.ptr,
                priv_tmpl.count,
                byref(pub_rsa),
                byref(priv_rsa),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_UNWRAP_TEMPLATE not supported at RSA keygen: {ckr_name(rv)}"
                    )
                expect_rv(
                    rv, CKR_OK, context="CKA_UNWRAP_TEMPLATE RSA keypair generation"
                )

            claimed = False
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, priv_rsa.value, [CKA_UNWRAP_TEMPLATE]
                )
                raw_template = attrs.get(CKA_UNWRAP_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            source_key = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={CKA_EXTRACTABLE: True, CKA_TOKEN: False},
                purpose="CKA_UNWRAP_TEMPLATE OAEP source-key setup",
            )

            wrapped_len = c_ulong(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                pub_rsa.value,
                source_key,
                None,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_WrapKey (source key size query)",
                    operation="C_WrapKey",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=(
                        "CKM_RSA_PKCS_OAEP advertised but source-key wrap is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            wrapped_buf = (c_ubyte * wrapped_len.value)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                pub_rsa.value,
                source_key,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_WrapKey (source key real)",
                    operation="C_WrapKey",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=(
                        "CKM_RSA_PKCS_OAEP advertised but source-key wrap retry is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )

            matching_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_ENCRYPT, True),
                attr_bool(CKA_DECRYPT, True),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, allowed_label),
            )
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                wrap_mech.byref(),
                priv_rsa.value,
                wrapped_buf,
                wrapped_len.value,
                matching_tmpl.ptr,
                matching_tmpl.count,
                byref(violating_unwrapped),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_RSA_PKCS_OAEP:C_UnwrapKey (matching template)",
                    operation="C_UnwrapKey",
                    mechanism="CKM_RSA_PKCS_OAEP",
                    actual=rv,
                    summary=(
                        "CKM_RSA_PKCS_OAEP advertised but matching-template unwrap is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            matching_unwrapped = violating_unwrapped.value
            violating_unwrapped = CK_OBJECT_HANDLE(0)

            violating_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_ENCRYPT, True),
                attr_bool(CKA_DECRYPT, True),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, denied_label),
            )
            rv = rs.raw.C_UnwrapKey(
                rs.sh,
                wrap_mech.byref(),
                priv_rsa.value,
                wrapped_buf,
                wrapped_len.value,
                violating_tmpl.ptr,
                violating_tmpl.count,
                byref(violating_unwrapped),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_UNWRAP_TEMPLATE OAEP created-object enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _UNWRAP_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_UnwrapKey (OAEP) template violating CKA_UNWRAP_TEMPLATE",
                )
        finally:
            for handle in (
                violating_unwrapped.value,
                matching_unwrapped,
                source_key,
                priv_rsa.value,
                pub_rsa.value,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)


class TestEcdhDeriveTemplateEnforcement:
    """CKA_DERIVE_TEMPLATE enforcement on the ECDH derive path.

    The existing ``test_derive_template_enforces_created_object_attributes``
    covers ``CKM_CONCATENATE_BASE_AND_DATA`` with a ``CKK_GENERIC_SECRET`` base.
    This class exercises ECDH — where the base key is an EC private key and the
    mechanism is ``CKM_ECDH1_DERIVE``.
    """

    def test_ecdh_derive_template_enforces_created_object_label(
        self, p11_raw_session: Any
    ) -> None:
        """CKA_DERIVE_TEMPLATE on an EC private key must block ECDH derive to a violating label."""
        rs = p11_raw_session
        if not rs.has_mechanism("EC_KEY_PAIR_GEN"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("ECDH1_DERIVE"):
            pytest.skip("CKM_ECDH1_DERIVE not supported")

        allowed_label = b"pkcs11-check-ecdh-derive-template-allowed"
        denied_label = b"pkcs11-check-ecdh-derive-template-denied"
        curve_oid = encode_named_curve_parameters("secp256r1")
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))

        keygen_mech = mech_simple(CKM_EC_KEY_PAIR_GEN)

        pub_base = CK_OBJECT_HANDLE(0)
        priv_base = CK_OBJECT_HANDLE(0)
        pub_peer = CK_OBJECT_HANDLE(0)
        priv_peer = CK_OBJECT_HANDLE(0)
        matching_derived = 0
        violating_derived = CK_OBJECT_HANDLE(0)
        try:
            # Base keypair: private key carries CKA_DERIVE_TEMPLATE.
            pub_base_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_EC),
                attr_bytes(CKA_EC_PARAMS, curve_oid),
                attr_bool(CKA_TOKEN, False),
                attr_bool(CKA_VERIFY, True),
            )
            priv_base_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_EC),
                attr_bool(CKA_DERIVE, True),
                attr_bool(CKA_SENSITIVE, True),
                attr_bool(CKA_EXTRACTABLE, False),
                attr_bool(CKA_TOKEN, False),
                attr_template(CKA_DERIVE_TEMPLATE, nested_template),
            )
            rv = rs.raw.C_GenerateKeyPair(
                rs.sh,
                keygen_mech.byref(),
                pub_base_tmpl.ptr,
                pub_base_tmpl.count,
                priv_base_tmpl.ptr,
                priv_base_tmpl.count,
                byref(pub_base),
                byref(priv_base),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_DERIVE_TEMPLATE not supported at EC keygen: {ckr_name(rv)}"
                    )
                expect_rv(
                    rv, CKR_OK, context="CKA_DERIVE_TEMPLATE EC base-keypair generation"
                )

            claimed = False
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, priv_base.value, [CKA_DERIVE_TEMPLATE]
                )
                raw_template = attrs.get(CKA_DERIVE_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            # Peer keypair: only the public EC_POINT is needed for mech_ecdh.
            pub_peer_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_EC),
                attr_bytes(CKA_EC_PARAMS, curve_oid),
                attr_bool(CKA_TOKEN, False),
                attr_bool(CKA_VERIFY, True),
            )
            priv_peer_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_PRIVATE_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_EC),
                attr_bool(CKA_TOKEN, False),
                attr_bool(CKA_SENSITIVE, True),
                attr_bool(CKA_EXTRACTABLE, False),
            )
            rv = rs.raw.C_GenerateKeyPair(
                rs.sh,
                keygen_mech.byref(),
                pub_peer_tmpl.ptr,
                pub_peer_tmpl.count,
                priv_peer_tmpl.ptr,
                priv_peer_tmpl.count,
                byref(pub_peer),
                byref(priv_peer),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_EC_KEY_PAIR_GEN (peer keypair)",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_EC_KEY_PAIR_GEN",
                    actual=rv,
                    summary=f"EC peer-keypair generation failed: {ckr_name(rv)}",
                )

            peer_point = b""
            try:
                peer_attrs = read_attributes(
                    rs.raw, rs.sh, pub_peer.value, [CKA_EC_POINT]
                )
                peer_point = peer_attrs.get(CKA_EC_POINT, b"")
            except (AssertionError, KeyError):
                pass
            if not peer_point:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKA_EC_POINT readback (peer public)",
                    summary="Could not read CKA_EC_POINT from peer public key",
                )

            derive_mech = mech_ecdh(
                CKM_ECDH1_DERIVE, kdf=CKD_NULL, public_data=peer_point
            )
            matching_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_bool(CKA_EXTRACTABLE, True),
                attr_bool(CKA_SENSITIVE, False),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, allowed_label),
            )
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                derive_mech.byref(),
                priv_base.value,
                matching_tmpl.ptr,
                matching_tmpl.count,
                byref(violating_derived),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_ECDH1_DERIVE:C_DeriveKey (matching template)",
                    operation="C_DeriveKey",
                    mechanism="CKM_ECDH1_DERIVE",
                    actual=rv,
                    summary=(
                        "CKM_ECDH1_DERIVE advertised but matching-template derive is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            matching_derived = violating_derived.value
            violating_derived = CK_OBJECT_HANDLE(0)

            violating_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_bool(CKA_EXTRACTABLE, True),
                attr_bool(CKA_SENSITIVE, False),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, denied_label),
            )
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                derive_mech.byref(),
                priv_base.value,
                violating_tmpl.ptr,
                violating_tmpl.count,
                byref(violating_derived),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_DERIVE_TEMPLATE ECDH created-object enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _DERIVE_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_DeriveKey (ECDH) template violating CKA_DERIVE_TEMPLATE",
                )
        finally:
            for handle in (
                violating_derived.value,
                matching_derived,
                priv_peer.value,
                pub_peer.value,
                priv_base.value,
                pub_base.value,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)


class TestHkdfDeriveTemplateEnforcement:
    """CKA_DERIVE_TEMPLATE enforcement on the HKDF derive path.

    The existing ``test_derive_template_enforces_created_object_attributes``
    covers ``CKM_CONCATENATE_BASE_AND_DATA``. This class exercises HKDF —
    where the base key is a generic secret and the mechanism is
    ``CKM_HKDF_DERIVE``.
    """

    def test_hkdf_derive_template_enforces_created_object_label(
        self, p11_raw_session: Any
    ) -> None:
        """CKA_DERIVE_TEMPLATE on a generic-secret base blocks HKDF derive to a violating label."""
        rs = p11_raw_session
        if not rs.has_mechanism("HKDF_DERIVE"):
            pytest.skip("CKM_HKDF_DERIVE not supported")

        allowed_label = b"pkcs11-check-hkdf-derive-template-allowed"
        denied_label = b"pkcs11-check-hkdf-derive-template-denied"
        base_value = b"A" * 32
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))

        base_key = CK_OBJECT_HANDLE(0)
        matching_derived = 0
        violating_derived = CK_OBJECT_HANDLE(0)
        try:
            base_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_bytes(CKA_VALUE, base_value),
                attr_bool(CKA_DERIVE, True),
                attr_bool(CKA_EXTRACTABLE, True),
                attr_bool(CKA_SENSITIVE, False),
                attr_bool(CKA_TOKEN, False),
                attr_template(CKA_DERIVE_TEMPLATE, nested_template),
            )
            rv = rs.raw.C_CreateObject(
                rs.sh,
                base_tmpl.ptr,
                base_tmpl.count,
                byref(base_key),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_DERIVE_TEMPLATE not supported at base-key import: {ckr_name(rv)}"
                    )
                expect_rv(rv, CKR_OK, context="CKA_DERIVE_TEMPLATE HKDF base-key import")

            claimed = False
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, base_key.value, [CKA_DERIVE_TEMPLATE]
                )
                raw_template = attrs.get(CKA_DERIVE_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            derive_mech = mech_hkdf(CKM_HKDF_DERIVE, hash_mech=CKM_SHA256)
            matching_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_bool(CKA_EXTRACTABLE, True),
                attr_bool(CKA_SENSITIVE, False),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, allowed_label),
            )
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                derive_mech.byref(),
                base_key.value,
                matching_tmpl.ptr,
                matching_tmpl.count,
                byref(violating_derived),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_HKDF_DERIVE:C_DeriveKey (matching template)",
                    operation="C_DeriveKey",
                    mechanism="CKM_HKDF_DERIVE",
                    actual=rv,
                    summary=(
                        "CKM_HKDF_DERIVE advertised but matching-template derive is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            matching_derived = violating_derived.value
            violating_derived = CK_OBJECT_HANDLE(0)

            violating_tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
                attr_bool(CKA_EXTRACTABLE, True),
                attr_bool(CKA_SENSITIVE, False),
                attr_bool(CKA_TOKEN, False),
                attr_bytes(CKA_LABEL, denied_label),
            )
            rv = rs.raw.C_DeriveKey(
                rs.sh,
                derive_mech.byref(),
                base_key.value,
                violating_tmpl.ptr,
                violating_tmpl.count,
                byref(violating_derived),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_DERIVE_TEMPLATE HKDF created-object enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _DERIVE_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_DeriveKey (HKDF) template violating CKA_DERIVE_TEMPLATE",
                )
        finally:
            for handle in (
                violating_derived.value,
                matching_derived,
                base_key.value,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)
