"""Unwrap-and-strip posture and CKA_UNWRAP_TEMPLATE binding enforcement.

Attack class: Tookan/Cryptosense key-re-import / unwrap-and-strip.

The default PKCS#11 unwrap posture is that the caller's C_UnwrapKey template
governs the resulting key attributes.  A caller can freely request
CKA_SENSITIVE=False / CKA_EXTRACTABLE=True on the unwrapped key, because the
spec places no special restriction on the C_UnwrapKey output template beyond
what it places on C_CreateObject.  This is *by design*: there is no implied
confidentiality binding across a wrap/unwrap cycle unless the wrapping key
carries CKA_UNWRAP_TEMPLATE.  Trusted wrapping uses CKA_WRAP_WITH_TRUSTED on
the key being wrapped and CKA_TRUSTED on the wrapping key; neither attribute
binds C_UnwrapKey output sensitivity.

Tests:
  1. test_default_strip_is_permitted:
     Wrap an extractable AES-128 key, unwrap it with a caller template that
     requests CKA_SENSITIVE=False and CKA_EXTRACTABLE=True, then read the
     resulting key's CKA_VALUE.  Regardless of the outcome the test records a
     note (ComplianceLevel.NOT_RECOMMENDED) — this is conformant, NEVER a fail.

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
       - missing or malformed CKA_SENSITIVE readback -> honest_deviation xfail;
         the binding result cannot be verified.

References:
  PKCS#11 v2.40 / v3.0 §  C_WrapKey / C_UnwrapKey template semantics;
  OASIS PKCS#11 Base Spec §4 CKA_UNWRAP_TEMPLATE / trusted wrapping attributes;
  Tookan: "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010);
  Cryptosense key-separation findings.
"""

from __future__ import annotations

import ctypes
from ctypes import byref, sizeof
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_bool, attr_template, attr_ulong, mech_simple, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, expect_rv, is_standard_ckr
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
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
    CKR_ATTRIBUTE_SENSITIVE,
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
    classify_negative_rv,
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
_UNWRAP_BINDING_ENFORCEMENT_RVS = (CKR_TEMPLATE_INCONSISTENT,)

# Clean operational-reject codes from C_WrapKey / C_UnwrapKey; routes to xfail
# rather than a false fail when a module cannot complete the operation.
_WRAP_UNWRAP_OP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def _read_unwrap_template_claim(raw: Any, session: int, handle: int) -> str | None:
    """Read the claimed binding into caller-owned nested attribute storage."""
    inner_value = CK_BBOOL(0)
    inner = CK_ATTRIBUTE(
        type=CKA_SENSITIVE,
        pValue=ctypes.cast(ctypes.pointer(inner_value), ctypes.c_void_p),
        ulValueLen=sizeof(CK_BBOOL),
    )
    inner_attrs = (CK_ATTRIBUTE * 1)(inner)
    outer = CK_ATTRIBUTE(
        type=CKA_UNWRAP_TEMPLATE,
        pValue=ctypes.cast(inner_attrs, ctypes.c_void_p),
        ulValueLen=sizeof(CK_ATTRIBUTE),
    )
    outer_attrs = (CK_ATTRIBUTE * 1)(outer)

    rv = raw.C_GetAttributeValue(session, handle, outer_attrs, 1)
    if rv in (CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID):
        return f"C_GetAttributeValue returned rv={rv!r} for CKA_UNWRAP_TEMPLATE"
    expect_rv(rv, CKR_OK)

    outer_record = outer_attrs[0]
    if int(outer_record.type) != int(CKA_UNWRAP_TEMPLATE):
        return f"outer CKA_UNWRAP_TEMPLATE type changed to {outer_record.type!r}"
    if outer_record.ulValueLen != sizeof(CK_ATTRIBUTE):
        return (
            "outer CKA_UNWRAP_TEMPLATE length was "
            f"{outer_record.ulValueLen!r}, expected {sizeof(CK_ATTRIBUTE)}"
        )
    if int(outer_record.pValue or 0) != ctypes.addressof(inner_attrs):
        return "outer CKA_UNWRAP_TEMPLATE pointer was not caller-owned storage"

    inner_record = inner_attrs[0]
    if int(inner_record.type) != int(CKA_SENSITIVE):
        return f"nested CKA_UNWRAP_TEMPLATE type was {inner_record.type!r}"
    if inner_record.ulValueLen != sizeof(CK_BBOOL):
        return (
            "nested CKA_SENSITIVE length was "
            f"{inner_record.ulValueLen!r}, expected {sizeof(CK_BBOOL)}"
        )
    if int(inner_record.pValue or 0) != ctypes.addressof(inner_value):
        return "nested CKA_SENSITIVE pointer was not caller-owned storage"
    if inner_value.value != 1:
        return f"nested CKA_SENSITIVE value was {inner_value.value!r}, expected CK_TRUE"
    return None


class TestDefaultStripIsPermitted:
    """Default C_UnwrapKey strip: caller may request non-sensitive, extractable result."""

    def test_default_strip_is_permitted(self, p11_raw_session: Any) -> None:
        """Wrap then unwrap with CKA_SENSITIVE=False / CKA_EXTRACTABLE=True.

        With no CKA_UNWRAP_TEMPLATE on the wrapping key, the C_UnwrapKey output
        template is fully caller-controlled (PKCS#11 C_UnwrapKey semantics).
        There is no spec requirement that sensitivity is preserved when the
        wrapping key has no CKA_UNWRAP_TEMPLATE binding.  The source key's
        attributes do not create an output binding.  CKA_WRAP_WITH_TRUSTED
        belongs to the key being wrapped and CKA_TRUSTED to the wrapping key;
        neither binds C_UnwrapKey output sensitivity.  A module
        accepting or even requiring this is conformant.  A nonempty CKA_VALUE is
        still a finding if the result itself claims protection; malformed or
        missing protection readback is an xfail, and only a valid unprotected
        result is recorded as posture.

        Tookan/Cryptosense note: real key-binding protection requires
        CKA_UNWRAP_TEMPLATE on the wrapping key (tested in
        TestUnwrapTemplateBinding).  CKA_WRAP_WITH_TRUSTED on the key being
        wrapped and CKA_TRUSTED on the wrapping key govern trusted wrapping,
        but do not bind C_UnwrapKey output sensitivity.
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
        # Target is explicitly non-sensitive and extractable so this scenario
        # isolates caller-controlled output attributes from the binding test below.
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
                # Claim-check the result before interpreting CKA_VALUE.  The
                # caller template is unbound, but a module must not claim
                # protection and return nonempty material from that same object.
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    unwrapped_h,
                    [CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_VALUE],
                )
                sensitive_after = attrs.get(CKA_SENSITIVE)
                extractable_after = attrs.get(CKA_EXTRACTABLE)
                value = attrs.get(CKA_VALUE)
                policy_readback_valid = (
                    type(sensitive_after) is bool and type(extractable_after) is bool
                )
                has_value = type(value) is bytes and bool(value)
                if has_value and (sensitive_after is True or extractable_after is False):
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="Default-strip unwrap result exposes protected key material",
                        operation="C_GetAttributeValue",
                        summary=(
                            "SECURITY: default-strip C_UnwrapKey result contains nonempty "
                            "CKA_VALUE while the same result key reports protective "
                            f"attributes (CKA_SENSITIVE={sensitive_after!r}, "
                            f"CKA_EXTRACTABLE={extractable_after!r})"
                        ),
                    )
                if not policy_readback_valid:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Default-strip result-key protection readback",
                        operation="C_GetAttributeValue",
                        summary=(
                            "Default-strip result-key protection readback is missing or "
                            "malformed: "
                            f"CKA_SENSITIVE={sensitive_after!r}, "
                            f"CKA_EXTRACTABLE={extractable_after!r}"
                        ),
                    )

                if sensitive_after is not False or extractable_after is not True:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Default-strip unwrap result did not honor output template",
                        operation="C_UnwrapKey",
                        summary=(
                            "Default-strip C_UnwrapKey result did not honor the requested "
                            "output template (CKA_SENSITIVE=False, CKA_EXTRACTABLE=True): "
                            f"CKA_SENSITIVE={sensitive_after!r}, "
                            f"CKA_EXTRACTABLE={extractable_after!r}"
                        ),
                    )

                if sensitive_after is False and extractable_after is True:
                    note(
                        "Default wrap+unwrap strip posture: the C_UnwrapKey output "
                        "template requested CKA_SENSITIVE=False / CKA_EXTRACTABLE=True, "
                        "which is permitted because the wrapping key has no "
                        "CKA_UNWRAP_TEMPLATE binding; the source key's posture does not "
                        "create an output binding. Only CKA_UNWRAP_TEMPLATE on the "
                        "wrapping key binds output attributes (tested separately); "
                        "CKA_WRAP_WITH_TRUSTED on the wrapped key and CKA_TRUSTED on the "
                        f"wrapping key govern trusted wrapping, but not output "
                        f"sensitivity. CKA_SENSITIVE after unwrap: {sensitive_after!r}, "
                        f"CKA_EXTRACTABLE after unwrap: {extractable_after!r}, "
                        f"CKA_VALUE readable: {has_value!r}.",
                        ComplianceLevel.NOT_RECOMMENDED,
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
          - Missing or non-boolean CKA_SENSITIVE readback
            -> honest_deviation xfail with the provider's actual value.

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
            classify_negative_rv(
                rv,
                _UNWRAP_TEMPLATE_KEYGEN_UNSUPPORTED_RVS,
                label="C_GenerateKey with CKA_UNWRAP_TEMPLATE",
                kind="policy",
            )

        wrap_h = wrap_h_handle.value

        # CKR_OK is the claim. Preserve missing/malformed readback as a deferred
        # metadata defect, but still exercise the binding effect below.
        template_readback_issue: str | None = None
        try:
            template_readback_issue = _read_unwrap_template_claim(rs.raw, rs.sh, wrap_h)
        except CkrAssertionError as exc:
            if is_standard_ckr(exc.rv):
                template_readback_issue = (
                    "Module accepted CKA_UNWRAP_TEMPLATE but its metadata readback "
                    f"returned standard CK_RV {exc.rv!r}: {exc}"
                )
            else:
                raise

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
                    if template_readback_issue is not None:
                        classify(
                            "honest_deviation",
                            kind="metadata",
                            label="CKA_UNWRAP_TEMPLATE readback missing or malformed",
                            operation="C_GetAttributeValue",
                            summary=template_readback_issue,
                        )
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
                label = (
                    "CKA_UNWRAP_TEMPLATE sensitivity binding bypassed by "
                    "C_UnwrapKey caller template "
                    "(PKCS#11 CKA_UNWRAP_TEMPLATE MUST constrain unwrapped key; "
                    "Tookan/Cryptosense key-binding attack class)"
                )
                if sensitive_after is False:
                    classify_policy_enforcement(claimed=True, violated=True, label=label)
                elif template_readback_issue is not None:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="CKA_UNWRAP_TEMPLATE readback missing or malformed",
                        operation="C_GetAttributeValue",
                        summary=(
                            f"{template_readback_issue}; binding effect was not bypassed "
                            f"(CKA_SENSITIVE={sensitive_after!r})"
                        ),
                    )
                elif sensitive_after is True:
                    classify_policy_enforcement(claimed=True, violated=False, label=label)
                else:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="CKA_UNWRAP_TEMPLATE sensitivity result missing or malformed",
                        operation="C_GetAttributeValue",
                        summary=(
                            "Module accepted CKA_UNWRAP_TEMPLATE but returned "
                            f"CKA_SENSITIVE={sensitive_after!r}; binding result cannot be "
                            "verified"
                        ),
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)
