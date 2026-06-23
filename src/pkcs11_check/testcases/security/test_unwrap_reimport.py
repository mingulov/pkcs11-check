"""Unwrap-and-strip posture and CKA_UNWRAP_TEMPLATE binding enforcement.

Attack class: Tookan/Cryptosense key-re-import / unwrap-and-strip.

The default PKCS#11 unwrap posture is that the caller's C_UnwrapKey template
governs the resulting key attributes.  A caller can freely request
CKA_SENSITIVE=False / CKA_EXTRACTABLE=True on the unwrapped key, because the
spec places no special restriction on the C_UnwrapKey output template beyond
what it places on C_CreateObject.  This is *by design*: there is no implied
confidentiality binding across a wrap/unwrap cycle unless the wrapping key
carries explicit attribute-binding constraints (CKA_UNWRAP_TEMPLATE or
CKA_WRAP_WITH_TRUSTED / CKA_TRUSTED).

Tests:
  1. test_default_strip_is_permitted:
     Wrap an extractable AES-128 key, unwrap it with a caller template that
     requests CKA_SENSITIVE=False and CKA_EXTRACTABLE=True, then read the
     resulting key's CKA_VALUE.  Regardless of the outcome the test records a
     note (ComplianceLevel.EXTENDED) — this is conformant, NEVER a fail.

  2. test_unwrap_template_binding_enforced:
     Create a wrapping key that carries CKA_UNWRAP_TEMPLATE constraining the
     unwrapped key's CKA_SENSITIVE to True.  Then try to unwrap with a caller
     template that requests CKA_SENSITIVE=False.  Gate on the module actually
     accepting the CKA_UNWRAP_TEMPLATE attribute (''claimed'').  If the module
     did NOT accept it, skip.  If the module claimed the binding:
       - unwrapped key reads CKA_SENSITIVE=True  -> classify_policy_enforcement
         (claimed=True, violated=False)  -> pass.
       - unwrapped key reads CKA_SENSITIVE=False -> classify_policy_enforcement
         (claimed=True, violated=True)   -> fail (self-contradiction / policy).

References:
  PKCS#11 v2.40 / v3.0 §  C_WrapKey / C_UnwrapKey template semantics;
  OASIS PKCS#11 Base Spec §4 CKA_UNWRAP_TEMPLATE / CKA_WRAP_WITH_TRUSTED;
  Tookan: "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010);
  Cryptosense key-separation findings.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_bool, attr_template, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_UNWRAP_TEMPLATE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

# CKR codes that indicate the module refused a keygen template because it does
# not recognise or accept the CKA_UNWRAP_TEMPLATE attribute; used in the skip
# guard for test 2.
_UNWRAP_TEMPLATE_KEYGEN_UNSUPPORTED_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
)

# CKR codes returned by C_UnwrapKey when the caller template contradicts the
# wrapping key's CKA_UNWRAP_TEMPLATE binding.  The module enforces the binding
# by refusing the call — this is correct / protected behaviour.
_UNWRAP_BINDING_ENFORCEMENT_RVS = (
    CKR_TEMPLATE_INCONSISTENT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ARGUMENTS_BAD,
)

# Clean operational-reject codes from C_WrapKey / C_UnwrapKey; routes to xfail
# rather than a false fail when a module cannot complete the operation.
_WRAP_UNWRAP_OP_REJECT_RVS = (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)


class TestDefaultStripIsPermitted:
    """Default C_UnwrapKey strip: caller may request non-sensitive, extractable result."""

    def test_default_strip_is_permitted(self, p11_raw_session: Any) -> None:
        """Wrap then unwrap with CKA_SENSITIVE=False / CKA_EXTRACTABLE=True.

        The C_UnwrapKey output template is fully caller-controlled (PKCS#11 spec
        C_UnwrapKey section).  There is no spec requirement that sensitivity is
        preserved unless the wrapping key carries CKA_UNWRAP_TEMPLATE or the
        unwrapping key carries CKA_WRAP_WITH_TRUSTED protection.  A module
        accepting or even requiring this is conformant.  The outcome is always
        recorded as a compliance note — this test CANNOT fail any module.

        Tookan/Cryptosense note: real key-binding protection requires
        CKA_UNWRAP_TEMPLATE on the wrapping key (tested in
        TestUnwrapTemplateBinding) or CKA_WRAP_WITH_TRUSTED on the wrapping key
        paired with CKA_TRUSTED on the unwrapping key.
        """
        rs = p11_raw_session

        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported by module")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported by module")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        # Target: extractable so wrap succeeds; sensitive=True is just the
        # starting posture; we will intentionally strip it in the unwrap template.
        target_h = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
            purpose="default-strip target",
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _WRAP_UNWRAP_OP_REJECT_RVS,
                    "CKM_AES_KEY_WRAP wrap not operational for this key",
                )
                raise

            # Unwrap with a caller template that explicitly requests
            # CKA_SENSITIVE=False and CKA_EXTRACTABLE=True — this is the
            # ''strip'' step.  Spec-compliant modules must honour the template
            # (or reject it outright with a template error; either is fine).
            unwrap_template: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            }
            unwrapped_h: int | None = None
            try:
                unwrapped_h = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_KEY_WRAP,
                    unwrap_template,
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _WRAP_UNWRAP_OP_REJECT_RVS,
                    "CKM_AES_KEY_WRAP unwrap not operational for this key",
                )
                raise

            try:
                # Read back: the spec says the module should follow the template.
                # Whether CKA_VALUE is readable depends on CKA_SENSITIVE/EXTRACTABLE
                # as set by the module.  We accept whatever the module returns.
                attrs = read_attributes(rs.raw, rs.sh, unwrapped_h, [CKA_SENSITIVE, CKA_VALUE])
                sensitive_after = attrs.get(CKA_SENSITIVE)
                has_value = CKA_VALUE in attrs and attrs[CKA_VALUE] is not None

                # Always a note; NEVER a fail regardless of the readback.
                note(
                    "Sensitive/extractable protection is not retained across wrap+unwrap "
                    "because the C_UnwrapKey output template is caller-specified "
                    "(permitted; Tookan/Cryptosense key-separation depends on "
                    "CKA_UNWRAP_TEMPLATE / CKA_WRAP_WITH_TRUSTED bindings, tested "
                    f"separately). CKA_SENSITIVE after unwrap: {sensitive_after!r}, "
                    f"CKA_VALUE readable: {has_value!r}.",
                    ComplianceLevel.EXTENDED,
                    reference="PKCS#11 C_UnwrapKey template semantics; "
                    "Tookan/Cryptosense key-separation requirements",
                    test_id=("TestDefaultStripIsPermitted.test_default_strip_is_permitted"),
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)


class TestUnwrapTemplateBinding:
    """CKA_UNWRAP_TEMPLATE binding: a claimed constraint must not be bypassable."""

    def test_unwrap_template_binding_enforced(self, p11_raw_session: Any) -> None:
        """A wrapping key's CKA_UNWRAP_TEMPLATE constraint must be honoured.

        Create a wrapping key carrying CKA_UNWRAP_TEMPLATE = {CKA_SENSITIVE: True}.
        If the module accepts the attribute (''claimed''), then call C_UnwrapKey
        with a caller template requesting CKA_SENSITIVE=False.  Read back the
        unwrapped key's CKA_SENSITIVE:

          - Module did NOT accept CKA_UNWRAP_TEMPLATE at keygen time
            -> claimed=False -> pytest.skip (capability absent, not a violation).
          - Module claimed + unwrapped key has CKA_SENSITIVE=True
            -> classify_policy_enforcement(claimed=True, violated=False) -> pass.
          - Module claimed + unwrapped key has CKA_SENSITIVE=False
            -> classify_policy_enforcement(claimed=True, violated=True)
            -> fail (self_contradiction / policy).

        References:
          OASIS PKCS#11 Base Spec §4 CKA_UNWRAP_TEMPLATE semantics;
          Tookan/Cryptosense key-binding attacks.
        """
        rs = p11_raw_session

        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported by module")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported by module")

        # --- Build CKA_UNWRAP_TEMPLATE sub-template -------------------------
        # The value of CKA_UNWRAP_TEMPLATE is a CK_ATTRIBUTE[] encoding
        # {CKA_SENSITIVE: True}.  Use pack.attr_template / pack.attr_bool /
        # pack.template to construct it correctly.
        inner_tmpl = template(attr_bool(CKA_SENSITIVE, True))
        unwrap_tmpl_attr = attr_template(CKA_UNWRAP_TEMPLATE, inner_tmpl)

        # --- Attempt to create the wrapping key with CKA_UNWRAP_TEMPLATE ----
        # pack_attrs cannot handle the ''template'' vtype (CKA_UNWRAP_TEMPLATE
        # is a CK_ATTRIBUTE[] array).  Build the keygen template by hand using
        # the pack primitives imported at module level.
        wrap_key_attrs_packed = [
            attr_ulong(CKA_VALUE_LEN, 32),  # 256-bit AES
            attr_bool(CKA_WRAP, True),
            attr_bool(CKA_UNWRAP, True),
            attr_bool(CKA_ENCRYPT, True),
            attr_bool(CKA_DECRYPT, True),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_EXTRACTABLE, True),
            unwrap_tmpl_attr,
        ]
        keygen_tmpl = template(*wrap_key_attrs_packed)
        mech = mech_simple(CKM_AES_KEY_GEN)
        wrap_h_handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            keygen_tmpl.ptr,
            keygen_tmpl.count,
            byref(wrap_h_handle),
        )

        if rv in _UNWRAP_TEMPLATE_KEYGEN_UNSUPPORTED_RVS:
            pytest.skip(
                f"Module rejected CKA_UNWRAP_TEMPLATE on wrapping-key creation "
                f"(rv={rv!r}); CKA_UNWRAP_TEMPLATE is not supported — "
                f"Tookan/Cryptosense binding test skipped (capability absent)"
            )
        if rv != CKR_OK:
            pytest.skip(
                f"Module refused wrapping-key creation with unexpected rv={rv!r}; "
                f"CKA_UNWRAP_TEMPLATE binding test skipped"
            )

        wrap_h = wrap_h_handle.value
        # The module accepted the keygen — the binding is *claimed*.
        claimed = True

        # Verify the module reflects the attribute (belt-and-suspenders claim check).
        try:
            reflected = read_attributes(rs.raw, rs.sh, wrap_h, [CKA_UNWRAP_TEMPLATE])
            # If the attribute is absent or returns zero-length the module silently
            # discarded it; treat that as not-claimed.
            ut_bytes = reflected.get(CKA_UNWRAP_TEMPLATE)
            if not ut_bytes:
                claimed = False
        except AssertionError:  # audit-ok: template read-back unsupported; creation-accept is claim
            # Read back of a template attribute may fail on some modules; treat
            # accept-at-creation as the claim indicator.
            pass

        if not claimed:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            pytest.skip(
                "Module accepted CKA_UNWRAP_TEMPLATE at keygen but did not reflect it; "
                "treating as capability absent — binding test skipped"
            )

        # --- Wrap a target key -----------------------------------------------
        target_h = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
            purpose="unwrap-template binding target",
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _WRAP_UNWRAP_OP_REJECT_RVS,
                    "CKM_AES_KEY_WRAP wrap not operational (binding test)",
                )
                raise

            # --- Attempt to override the binding in the caller template ------
            # Request CKA_SENSITIVE=False, contradicting the wrapping key's
            # CKA_UNWRAP_TEMPLATE = {CKA_SENSITIVE: True}.
            caller_template: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_SENSITIVE: False,  # caller tries to override the binding
                CKA_EXTRACTABLE: True,
            }
            unwrapped_h: int | None = None
            try:
                unwrapped_h = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_KEY_WRAP,
                    caller_template,
                )
            except AssertionError as exc:
                # Check binding-enforcement rejection first: the module refused
                # the C_UnwrapKey call because the caller template contradicts
                # the wrapping key's CKA_UNWRAP_TEMPLATE constraint.  That is
                # correct enforcement behaviour.
                if is_known_error(exc, _UNWRAP_BINDING_ENFORCEMENT_RVS):
                    classify_policy_enforcement(
                        claimed=True,
                        violated=False,
                        label="CKA_UNWRAP_TEMPLATE sensitivity binding enforced "
                        "(module rejected contradicting C_UnwrapKey caller template "
                        "with a template error)",
                    )
                    return
                xfail_if_known_ckr(
                    exc,
                    _WRAP_UNWRAP_OP_REJECT_RVS,
                    "CKM_AES_KEY_WRAP unwrap not operational (binding test)",
                )
                raise

            try:
                unwrap_attrs = read_attributes(rs.raw, rs.sh, unwrapped_h, [CKA_SENSITIVE])
                sensitive_after = unwrap_attrs.get(CKA_SENSITIVE)
                # Binding bypassed iff module delivered CKA_SENSITIVE=False despite
                # CKA_UNWRAP_TEMPLATE constraining it to True.
                violated = sensitive_after is False
                classify_policy_enforcement(
                    claimed=True,
                    violated=violated,
                    label="CKA_UNWRAP_TEMPLATE sensitivity binding bypassed by "
                    "C_UnwrapKey caller template "
                    "(PKCS#11 CKA_UNWRAP_TEMPLATE MUST constrain unwrapped key; "
                    "Tookan/Cryptosense key-binding attack class)",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)
