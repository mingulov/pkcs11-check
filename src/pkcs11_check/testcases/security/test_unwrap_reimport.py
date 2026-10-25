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

from pkcs11_check.classification import (
    Classification,
    classify,
    get_records,
    raise_for_record,
)
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import (
    attr_bool,
    attr_template,
    attr_ulong,
    mech_simple,
    template,
    template_ptr_count,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects_exhaustive,
    gen_aes_key,
    pack_attrs,
    read_attributes,
    to_ubyte_buf,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_OBJECT_HANDLE,
    CKA_ALWAYS_SENSITIVE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_TOKEN,
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
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
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


def _operational_wrap(rs: Any, wrap_h: int, target_h: int) -> tuple[str, int]:
    """Attempt an operational wrap; return (ok|empty|refused, rv)."""
    try:
        wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
    except CkrAssertionError as exc:
        return "refused", int(exc.rv)
    return ("ok", int(CKR_OK)) if wrapped else ("empty", int(CKR_OK))


def _is_defined_rv(rv: int) -> bool:
    return is_standard_ckr(rv) or is_vendor_defined_ckr(rv)


def _raise_missing_record(labels: list[str]) -> None:
    """Terminate with the strongest attr_or_record observation (one record)."""
    records: list[Classification] = [r for r in get_records() if r.label in labels]
    if not records:
        return
    for record in records:
        if record.outcome == "fail":
            raise_for_record(record)
    raise_for_record(records[0])


def _readback_repr(raw: Any) -> str:
    """Render an attribute readback for a summary without inventing a value.

    A provider omission is NOT ``None``: rendering the sentinel as ``None`` would
    put a value the provider never returned into the record.
    """
    if raw is MISSING_ATTRIBUTE:
        return "<unavailable>"
    return repr(raw)


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
                sensitive_after_raw = attr_or_record(
                    attrs,
                    CKA_SENSITIVE,
                    label="Default-strip unwrap result CKA_SENSITIVE readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                sensitive_after: Any
                if sensitive_after_raw is MISSING_ATTRIBUTE:
                    sensitive_after = None
                else:
                    sensitive_after = sensitive_after_raw
                extractable_after_raw = attr_or_record(
                    attrs,
                    CKA_EXTRACTABLE,
                    label="Default-strip unwrap result CKA_EXTRACTABLE readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                extractable_after: Any
                if extractable_after_raw is MISSING_ATTRIBUTE:
                    extractable_after = None
                else:
                    extractable_after = extractable_after_raw
                # CKA_VALUE is the protected secret this oracle probes for exposure.
                # It legitimately CAN be sensitive (that is the point of the
                # protection this test probes), so a clean CKR_ATTRIBUTE_SENSITIVE
                # refusal is conformant, not a deviation -- sensitive_is_conformant=True
                # records it as such. A missing CKR (silent omission) or
                # CKR_ATTRIBUTE_TYPE_INVALID is still a deviation via `reason`. The
                # CKA_SENSITIVE/CKA_EXTRACTABLE attr_or_record() calls above read
                # DIFFERENT attributes and record nothing about CKA_VALUE itself --
                # recording it here, unconditionally, is what makes a refusal vs. a
                # silent omission vs. a refusal-with-leaked-data visible per provider.
                value_raw = attr_or_record(
                    attrs,
                    CKA_VALUE,
                    label="Default-strip unwrap result CKA_VALUE readback",
                    reason="honest_deviation",
                    kind="metadata",
                    inherit_mechanism=False,
                    sensitive_is_conformant=True,
                )
                value: Any
                if value_raw is MISSING_ATTRIBUTE:
                    value = None
                else:
                    value = value_raw
                policy_readback_malformed = (
                    sensitive_after_raw is not MISSING_ATTRIBUTE
                    and type(sensitive_after) is not bool
                ) or (
                    extractable_after_raw is not MISSING_ATTRIBUTE
                    and type(extractable_after) is not bool
                )
                has_value = type(value) is bytes and bool(value)
                # Deliberately NOT gated on the readback being complete: an observed
                # protective attribute plus readable CKA_VALUE is a hard
                # self-contradiction on its own, and a missing sibling must never
                # mask it.
                if has_value and (sensitive_after is True or extractable_after is False):
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="Default-strip unwrap result exposes protected key material",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=(
                            "SECURITY: default-strip C_UnwrapKey result contains nonempty "
                            "CKA_VALUE while the same result key reports protective "
                            "attributes (CKA_SENSITIVE="
                            f"{_readback_repr(sensitive_after_raw)}, "
                            f"CKA_EXTRACTABLE={_readback_repr(extractable_after_raw)})"
                        ),
                    )
                if policy_readback_malformed:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Default-strip result-key protection readback",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=(
                            "Default-strip result-key protection readback is malformed: "
                            f"CKA_SENSITIVE={_readback_repr(sensitive_after_raw)}, "
                            f"CKA_EXTRACTABLE={_readback_repr(extractable_after_raw)}"
                        ),
                    )

                # The template-honouring oracle is evaluated only over the halves the
                # module actually returned: an omitted attribute disables its own half
                # (already recorded above) without suppressing a deviation observed on
                # the other half, and without recording the same omission twice.
                template_deviation_observed = (
                    sensitive_after_raw is not MISSING_ATTRIBUTE and sensitive_after is not False
                ) or (
                    extractable_after_raw is not MISSING_ATTRIBUTE and extractable_after is not True
                )
                if template_deviation_observed:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Default-strip unwrap result did not honor output template",
                        operation="C_UnwrapKey",
                        summary=(
                            "Default-strip C_UnwrapKey result did not honor the requested "
                            "output template (CKA_SENSITIVE=False, CKA_EXTRACTABLE=True): "
                            f"CKA_SENSITIVE={_readback_repr(sensitive_after_raw)}, "
                            f"CKA_EXTRACTABLE={_readback_repr(extractable_after_raw)}"
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
                        "sensitivity. CKA_SENSITIVE after unwrap: "
                        f"{_readback_repr(sensitive_after_raw)}, "
                        "CKA_EXTRACTABLE after unwrap: "
                        f"{_readback_repr(extractable_after_raw)}, "
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
                            inherit_mechanism=False,
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
                sensitive_after_raw = attr_or_record(
                    unwrap_attrs,
                    CKA_SENSITIVE,
                    label="CKA_UNWRAP_TEMPLATE binding result CKA_SENSITIVE readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                sensitive_after: Any
                if sensitive_after_raw is MISSING_ATTRIBUTE:
                    sensitive_after = None
                else:
                    sensitive_after = sensitive_after_raw
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
                        inherit_mechanism=False,
                        summary=(
                            f"{template_readback_issue}; binding effect was not bypassed "
                            f"(CKA_SENSITIVE={_readback_repr(sensitive_after_raw)})"
                        ),
                    )
                elif sensitive_after is True:
                    classify_policy_enforcement(claimed=True, violated=False, label=label)
                elif sensitive_after_raw is MISSING_ATTRIBUTE:
                    # The omission is already an emitted observation (the
                    # attr_or_record() call above): one record per observation, so
                    # nothing further is classified here.  The binding-effect oracle
                    # is simply not evaluable, and nothing was bypassed.
                    pass
                else:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="CKA_UNWRAP_TEMPLATE sensitivity result malformed",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=(
                            "Module accepted CKA_UNWRAP_TEMPLATE but returned "
                            f"CKA_SENSITIVE={_readback_repr(sensitive_after_raw)}; binding "
                            "result cannot be verified"
                        ),
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)


def _qc8b_unwrap(
    rs: Any,
    wrap_h: int,
    wrapped: bytes,
    attrs: dict[Any, Any],
    *,
    label: str,
) -> int:
    """QC8b unwrap with an exhaustive before/after inventory bracket (R9-03).

    A refused unwrap that nevertheless creates an object must not be
    indistinguishable from a clean refusal: the output handle is owned
    (and destroyable) only when the inventory delta proves it new. A
    proved creation on refusal is destroyed and fails; an unproved
    delta stays alive as an honest-deviation xfail; a clean zero-delta
    refusal keeps the node's historical tiers (known operational
    rejects xfail ``not_operational``, anything else propagates).
    """

    def _inventory() -> list[int]:
        return find_objects_exhaustive(rs.raw, rs.sh)

    try:
        before = _inventory()
    except CkrAssertionError as exc:
        if not _is_defined_rv(int(exc.rv)):
            classify(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: inventory",
                operation="C_FindObjects",
                mechanism="CKM_AES_KEY_WRAP",
                actual=int(exc.rv),
                inherit_mechanism=False,
                summary=f"{label}: inventory returned undefined CK_RV {ckr_name(int(exc.rv))}",
            )
        classify(
            "not_operational",
            label=f"{label}: inventory",
            operation="C_FindObjects",
            mechanism="CKM_AES_KEY_WRAP",
            actual=int(exc.rv),
            inherit_mechanism=False,
            summary=f"{label}: inventory failed with {ckr_name(int(exc.rv))}; unwrap unproved",
        )
        raise AssertionError("unreachable: classify always raises") from exc
    mech = mech_simple(CKM_AES_KEY_WRAP)
    packed = pack_attrs(attrs)
    tmpl = template(*packed) if packed else None
    in_buf = to_ubyte_buf(wrapped)
    handle = CK_OBJECT_HANDLE(0)
    rv = int(
        rs.raw.C_UnwrapKey(
            rs.sh,
            mech.byref(),
            wrap_h,
            in_buf,
            len(wrapped),
            *template_ptr_count(tmpl),
            byref(handle),
        )
    )
    handle_after = int(handle.value)
    detail: dict[str, Any] = {"handle_after": handle_after}
    try:
        after = _inventory()
    except CkrAssertionError as exc:
        detail["inventory_rv"] = ckr_name(int(exc.rv))
        detail["disposition"] = "unproved-effect"
        if rv != int(CKR_OK) and not _is_defined_rv(rv):
            classify(
                "self_contradiction",
                kind="metadata",
                label=label,
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                actual=rv,
                inherit_mechanism=False,
                summary=f"{label}: refused with undefined CK_RV {ckr_name(rv)}",
                detail=detail,
            )
        if not _is_defined_rv(int(exc.rv)):
            classify(
                "self_contradiction",
                kind="metadata",
                label=f"{label}: inventory",
                operation="C_FindObjects",
                mechanism="CKM_AES_KEY_WRAP",
                actual=int(exc.rv),
                inherit_mechanism=False,
                summary=f"{label}: inventory returned undefined CK_RV {ckr_name(int(exc.rv))}",
                detail=detail,
            )
        if rv == int(CKR_OK):
            classify(
                "not_operational",
                label=label,
                operation="C_UnwrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                actual=int(exc.rv),
                inherit_mechanism=False,
                summary=(
                    f"{label}: unwrap succeeded but the result handle's ownership "
                    f"is unproved; inventory failed with {ckr_name(int(exc.rv))}"
                ),
                detail=detail,
            )
        classify(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=(
                f"{label}: refusal inventory failed with {ckr_name(int(exc.rv))}; "
                "zero-delta unproved"
            ),
            detail=detail,
        )
        raise AssertionError("unreachable: classify always raises") from exc
    new_handles = sorted(set(after) - set(before))
    proved_new = [handle_after] if handle_after in new_handles else []
    detail["new_handles"] = new_handles
    detail["proved_new_handles"] = proved_new
    if rv == int(CKR_OK):
        if proved_new:
            return handle_after
        classify(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=(
                f"{label}: unwrap reported success but handle {handle_after} "
                "is not a proved-new object in the exhaustive inventory delta"
            ),
            detail=detail,
        )
    if not _is_defined_rv(rv):
        if proved_new:
            destroy_quietly(rs.raw, rs.sh, handle_after)
        classify(
            "self_contradiction",
            kind="metadata",
            label=label,
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=f"{label}: refused with undefined CK_RV {ckr_name(rv)}",
            detail=detail,
        )
    if proved_new:
        destroy_quietly(rs.raw, rs.sh, handle_after)
        classify(
            "self_contradiction",
            kind="lifecycle",
            label=label,
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=(
                f"{label}: unwrap refused with {ckr_name(rv)} but created object {handle_after}"
            ),
            detail=detail,
        )
    if new_handles:
        classify(
            "honest_deviation",
            kind="lifecycle",
            label=label,
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=(
                f"{label}: unwrap refused with {ckr_name(rv)} but the inventory "
                f"gained unproved objects {new_handles}"
            ),
            detail=detail,
        )
    if rv in {int(r) for r in _WRAP_UNWRAP_OP_REJECT_RVS}:
        classify(
            "not_operational",
            label="CKM_AES_KEY_WRAP unwrap not operational",
            operation="C_UnwrapKey",
            mechanism="CKM_AES_KEY_WRAP",
            actual=rv,
            inherit_mechanism=False,
            summary=f"CKM_AES_KEY_WRAP unwrap not operational: {ckr_name(rv)}",
            detail=detail,
        )
    raise AssertionError(f"{label}: C_UnwrapKey refused with {ckr_name(rv)} (0x{rv:08x})")


class TestUnwrapOmittedExtractableDefault:
    """QC8b (#61.2): omitted unwrap CKA_EXTRACTABLE defaults to CK_TRUE.

    A conformance oracle, distinct from this file's posture/binding
    classes: the wrapping key carries no CKA_UNWRAP_TEMPLATE, so nothing
    binds the result except the specified default itself.
    """

    def test_omitted_extractable_defaults_true_and_wrappable(self, p11_raw_session: Any) -> None:
        """Minimal-template unwrap: EXTRACTABLE True, histories False, wrappable.

        SENSITIVE is token-specific (either strict bool passes); the
        histories are judged independently of its outcome.
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
        target_h = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
            purpose="omitted-extractable default target",
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _WRAP_UNWRAP_OP_REJECT_RVS, "CKM_AES_KEY_WRAP wrap not operational"
                )
                raise
            # Minimal template: EXTRACTABLE and SENSITIVE are really omitted.
            unwrap_template: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_TOKEN: False,
            }
            unwrapped_h = _qc8b_unwrap(
                rs,
                wrap_h,
                wrapped,
                unwrap_template,
                label="C_UnwrapKey:omitted-extractable-default",
            )
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    unwrapped_h,
                    [
                        CKA_EXTRACTABLE,
                        CKA_ALWAYS_SENSITIVE,
                        CKA_NEVER_EXTRACTABLE,
                        CKA_SENSITIVE,
                    ],
                )
                labels = [
                    "Omitted-extractable unwrap result CKA_EXTRACTABLE readback",
                    "Omitted-extractable unwrap result CKA_ALWAYS_SENSITIVE readback",
                    "Omitted-extractable unwrap result CKA_NEVER_EXTRACTABLE readback",
                    "Omitted-extractable unwrap result CKA_SENSITIVE readback",
                ]
                extractable_raw = attr_or_record(
                    attrs,
                    CKA_EXTRACTABLE,
                    label=labels[0],
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                extractable: Any
                if extractable_raw is MISSING_ATTRIBUTE:
                    extractable = None
                else:
                    extractable = extractable_raw
                always_raw = attr_or_record(
                    attrs,
                    CKA_ALWAYS_SENSITIVE,
                    label=labels[1],
                    reason="not_operational",
                    kind="metadata",
                    inherit_mechanism=False,
                )
                always: Any
                if always_raw is MISSING_ATTRIBUTE:
                    always = None
                else:
                    always = always_raw
                never_raw = attr_or_record(
                    attrs,
                    CKA_NEVER_EXTRACTABLE,
                    label=labels[2],
                    reason="not_operational",
                    kind="metadata",
                    inherit_mechanism=False,
                )
                never: Any
                if never_raw is MISSING_ATTRIBUTE:
                    never = None
                else:
                    never = never_raw
                sensitive_raw = attr_or_record(
                    attrs,
                    CKA_SENSITIVE,
                    label=labels[3],
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                sensitive: Any
                if sensitive_raw is MISSING_ATTRIBUTE:
                    sensitive = None
                else:
                    sensitive = sensitive_raw
                # All four readbacks precede any verdict; the operational
                # wrap is always attempted, even when a flag is missing.
                op_outcome, op_rv = _operational_wrap(rs, wrap_h, unwrapped_h)
                if op_outcome == "refused" and not _is_defined_rv(op_rv):
                    classify(
                        "self_contradiction",
                        kind="metadata",
                        label="C_WrapKey:omitted-extractable-operational-wrap",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        actual=op_rv,
                        inherit_mechanism=False,
                        summary=(
                            "Operational wrap of the omitted-template unwrap result "
                            f"refused with undefined CK_RV {ckr_name(op_rv)}"
                        ),
                    )
                if (
                    extractable is True
                    and op_outcome == "refused"
                    and op_rv == int(CKR_KEY_UNEXTRACTABLE)
                ):
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="C_WrapKey:omitted-extractable-claimed-wrappable",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        actual=op_rv,
                        inherit_mechanism=False,
                        summary=(
                            "Unwrap result claims CKA_EXTRACTABLE=True but wrapping it "
                            "refused with CKR_KEY_UNEXTRACTABLE"
                        ),
                    )
                if extractable is False:
                    classify(
                        "wrong_result",
                        kind="policy",
                        label="C_UnwrapKey:omitted-extractable-default",
                        operation="C_UnwrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary=(
                            "Omitted CKA_EXTRACTABLE defaulted to False; the specified "
                            "default is CK_TRUE (operational wrap: "
                            f"{op_outcome} {ckr_name(op_rv)})"
                        ),
                    )
                if always is True or never is True:
                    classify(
                        "wrong_result",
                        kind="metadata",
                        label="C_UnwrapKey:omitted-extractable-histories",
                        operation="C_UnwrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary=(
                            "Omitted-template unwrap histories must be false, got "
                            f"CKA_ALWAYS_SENSITIVE={_readback_repr(always_raw)}, "
                            f"CKA_NEVER_EXTRACTABLE={_readback_repr(never_raw)} "
                            "(judged independently of CKA_SENSITIVE="
                            f"{_readback_repr(sensitive_raw)})"
                        ),
                    )
                malformed: list[str] = []
                if extractable_raw is not MISSING_ATTRIBUTE and type(extractable) is not bool:
                    malformed.append(f"CKA_EXTRACTABLE={_readback_repr(extractable_raw)}")
                if always_raw is not MISSING_ATTRIBUTE and type(always) is not bool:
                    malformed.append(f"CKA_ALWAYS_SENSITIVE={_readback_repr(always_raw)}")
                if never_raw is not MISSING_ATTRIBUTE and type(never) is not bool:
                    malformed.append(f"CKA_NEVER_EXTRACTABLE={_readback_repr(never_raw)}")
                if sensitive_raw is not MISSING_ATTRIBUTE and type(sensitive) is not bool:
                    malformed.append(f"CKA_SENSITIVE={_readback_repr(sensitive_raw)}")
                if malformed:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Omitted-extractable unwrap result readback malformed",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=(
                            "Non-boolean protection/history readbacks: " + ", ".join(malformed)
                        ),
                    )
                if (
                    extractable_raw is MISSING_ATTRIBUTE
                    or always_raw is MISSING_ATTRIBUTE
                    or never_raw is MISSING_ATTRIBUTE
                    or sensitive_raw is MISSING_ATTRIBUTE
                ):
                    _raise_missing_record(labels)
                if op_outcome == "refused":
                    classify(
                        "not_operational",
                        label="C_WrapKey:omitted-extractable-operational-wrap",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        actual=op_rv,
                        inherit_mechanism=False,
                        summary=(
                            "Operational wrap of the extractable-by-default result "
                            f"refused cleanly: {ckr_name(op_rv)}"
                        ),
                    )
                if op_outcome == "empty":
                    classify(
                        "wrong_result",
                        kind="metadata",
                        label="C_WrapKey:omitted-extractable-operational-wrap",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary="Operational wrap claimed success with an empty blob",
                    )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)

    def test_explicit_false_extractable_is_the_negative_control(self, p11_raw_session: Any) -> None:
        """Explicit EXTRACTABLE=False must refuse the operational wrap.

        Delta vs the readback-only neighbor in
        ``security/test_cve_regression.py`` (out of this lease): this node
        proves the seal operationally, with C_WrapKey itself.
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
        target_h = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_SENSITIVE: False, CKA_EXTRACTABLE: True},
            purpose="explicit-false negative-control target",
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc, _WRAP_UNWRAP_OP_REJECT_RVS, "CKM_AES_KEY_WRAP wrap not operational"
                )
                raise
            caller_template: dict[Any, Any] = {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_TOKEN: False,
                CKA_EXTRACTABLE: False,
                CKA_SENSITIVE: True,
            }
            unwrapped_h = _qc8b_unwrap(
                rs,
                wrap_h,
                wrapped,
                caller_template,
                label="C_UnwrapKey:explicit-false-negative-control",
            )
            try:
                attrs = read_attributes(
                    rs.raw, rs.sh, unwrapped_h, [CKA_EXTRACTABLE, CKA_SENSITIVE]
                )
                labels = [
                    "Explicit-false unwrap result CKA_EXTRACTABLE readback",
                    "Explicit-false unwrap result CKA_SENSITIVE readback",
                ]
                extractable_raw = attr_or_record(
                    attrs,
                    CKA_EXTRACTABLE,
                    label=labels[0],
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                extractable: Any
                if extractable_raw is MISSING_ATTRIBUTE:
                    extractable = None
                else:
                    extractable = extractable_raw
                sensitive_raw = attr_or_record(
                    attrs,
                    CKA_SENSITIVE,
                    label=labels[1],
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                sensitive: Any
                if sensitive_raw is MISSING_ATTRIBUTE:
                    sensitive = None
                else:
                    sensitive = sensitive_raw
                op_outcome, op_rv = _operational_wrap(rs, wrap_h, unwrapped_h)
                if op_outcome == "refused" and not _is_defined_rv(op_rv):
                    classify(
                        "self_contradiction",
                        kind="metadata",
                        label="C_WrapKey:explicit-unextractable-operational-wrap",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        actual=op_rv,
                        inherit_mechanism=False,
                        summary=(
                            "Operational wrap of the explicit-false result refused "
                            f"with undefined CK_RV {ckr_name(op_rv)}"
                        ),
                    )
                if op_outcome == "empty":
                    classify(
                        "wrong_result",
                        kind="metadata",
                        label="C_WrapKey:explicit-unextractable-operational-wrap",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary="Operational wrap claimed success with an empty blob",
                    )
                if op_outcome == "ok":
                    if extractable is True:
                        classify(
                            "wrong_result",
                            kind="policy",
                            label="C_UnwrapKey:explicit-false-not-honored",
                            operation="C_UnwrapKey",
                            mechanism="CKM_AES_KEY_WRAP",
                            inherit_mechanism=False,
                            summary=(
                                "Explicit CKA_EXTRACTABLE=False was not honored "
                                "(readback True and the key wrapped successfully)"
                            ),
                        )
                    classify(
                        "self_contradiction",
                        kind="policy",
                        label="C_WrapKey:explicit-unextractable-unwrap-result",
                        operation="C_WrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        actual=op_rv,
                        inherit_mechanism=False,
                        summary=(
                            "Key unwrapped with explicit CKA_EXTRACTABLE=False "
                            f"(readback {_readback_repr(extractable)}) was "
                            "successfully wrapped, exporting its material"
                        ),
                    )
                if extractable is True:
                    classify(
                        "wrong_result",
                        kind="policy",
                        label="C_UnwrapKey:explicit-false-not-honored",
                        operation="C_UnwrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary="Explicit CKA_EXTRACTABLE=False read back True",
                    )
                malformed: list[str] = []
                if extractable_raw is not MISSING_ATTRIBUTE and type(extractable) is not bool:
                    malformed.append(f"CKA_EXTRACTABLE={_readback_repr(extractable_raw)}")
                if sensitive_raw is not MISSING_ATTRIBUTE and type(sensitive) is not bool:
                    malformed.append(f"CKA_SENSITIVE={_readback_repr(sensitive_raw)}")
                if malformed:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Explicit-false unwrap result readback malformed",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=("Non-boolean readbacks: " + ", ".join(malformed)),
                    )
                if extractable_raw is MISSING_ATTRIBUTE or sensitive_raw is MISSING_ATTRIBUTE:
                    _raise_missing_record(labels)
                if sensitive is not True:
                    classify(
                        "honest_deviation",
                        kind="metadata",
                        label="Explicit-false unwrap result sensitivity not honored",
                        operation="C_UnwrapKey",
                        mechanism="CKM_AES_KEY_WRAP",
                        inherit_mechanism=False,
                        summary=(
                            f"Explicit CKA_SENSITIVE=True read back {_readback_repr(sensitive)}"
                        ),
                    )
                if op_rv == int(CKR_KEY_UNEXTRACTABLE):
                    return
                classify(
                    "nonspec_reject",
                    kind="policy",
                    label="C_WrapKey:explicit-unextractable-operational-wrap",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    expected=int(CKR_KEY_UNEXTRACTABLE),
                    actual=op_rv,
                    inherit_mechanism=False,
                    summary=(
                        "Operational wrap of the explicit-false result refused "
                        f"with {ckr_name(op_rv)}, expected CKR_KEY_UNEXTRACTABLE"
                    ),
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped_h)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrap_h)
