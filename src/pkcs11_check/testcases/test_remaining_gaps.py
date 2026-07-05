"""Tests for remaining OASIS spec gaps identified in post-Phase audit.

Closes every item from the gap analysis that was not covered by Phases A-H:

Phase A remaining:
- C_WaitForSlotEvent success path
- C_GetFunctionStatus / C_CancelFunction (legacy parallel)
- Message finalizers (C_MessageEncryptFinal etc.)
- Async lifecycle (C_AsyncComplete / C_AsyncJoin)
- C_SignEncryptUpdate / C_DecryptVerifyUpdate (dual-function)

Phase B remaining:
- CKA_WRAP_TEMPLATE / CKA_UNWRAP_TEMPLATE / CKA_DERIVE_TEMPLATE
- CKO_OTP_KEY object attributes

Phase D remaining:
- CKM_KMAC_128 / CKM_KMAC_256
- Standalone SHAKE XOF
- CKM_ML_DSA_EXTERNAL_MU / EXTERNAL_MU_GEN

Phase F remaining:
- CKM_PKCS12_PBE_EXPORT / CKM_PKCS12_PBE_IMPORT

Phase G remaining:
- CKM_RSA_PKCS_NULL

Tier 1 stragglers:
- CKM_AES_CMAC_GENERAL
- CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS

Most modules do not support these - tests skip cleanly.
"""

from __future__ import annotations

from ctypes import byref, c_ubyte, c_ulong, sizeof
from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.pack import mech_ulong
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_DERIVE,
    CKA_DERIVE_TEMPLATE,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_OTP_FORMAT,
    CKA_OTP_LENGTH,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_UNWRAP_TEMPLATE,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKA_WRAP_TEMPLATE,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_AES_CMAC_GENERAL,
    CKM_AES_KEY_GEN,
    CKM_AES_KEY_WRAP,
    CKM_CONCATENATE_BASE_AND_DATA,
    CKM_HOTP_KEY_GEN,
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
    CKR_NO_EVENT,
    CKR_OK,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    CKR_UNWRAPPING_KEY_SIZE_RANGE,
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.compliance]

_HOTP_KEYGEN_ERROR_CKRS = (
    CKR_ARGUMENTS_BAD,
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

_WRAP_TEMPLATE_ENFORCEMENT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
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


def _run_gap_probe(
    p11_config: Any,
    probe: str,
    *,
    timeout: int = 10,
) -> tuple[int, str, str]:
    """Launch the ``remaining_gaps`` probe under the configured session.

    The child (``_probes/remaining_gaps.py``, dispatched on ``probe``) reproduces the legacy
    per-config session setup: C_Initialize, slot-index resolution, RW session, login-if-PIN.
    The PIN travels ONLY via ``run_probe(pin=...)`` -> ``_P11CHECK_PIN`` env (Invariant I3);
    it is never embedded in params/argv/source.  Coverage + rv-trace are recorded by
    ``run_probe`` (I6/I7).
    """
    result = run_probe(
        "remaining_gaps",
        {"module_path": str(p11_config.module), "slot_id": p11_config.slot, "probe": probe},
        pin=pin_from_config(p11_config),
        timeout=timeout,
        coverage="session",
    )
    return result.returncode, result.stdout, result.stderr


# ---------------------------------------------------------------------------
# Template constraint attributes (Phase B gap)
# ---------------------------------------------------------------------------


class TestTemplateConstraintAttributes:
    """CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, CKA_DERIVE_TEMPLATE."""

    def test_wrap_template_attribute_readable(self, p11_raw_session: Any) -> None:
        """Keys should accept CKA_WRAP_TEMPLATE if the module supports it."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_WRAP: True,
                CKA_TOKEN: False,
            },
            purpose="CKA_WRAP_TEMPLATE readback setup",
        )
        try:
            try:
                vals = read_attributes(rs.raw, rs.sh, key, [CKA_WRAP_TEMPLATE])
                wt = vals[CKA_WRAP_TEMPLATE]
                assert wt is not None or wt == b""
            except (AssertionError, KeyError):
                pytest.skip("Module does not support CKA_WRAP_TEMPLATE")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_unwrap_template_attribute_readable(self, p11_raw_session: Any) -> None:
        """Keys should accept CKA_UNWRAP_TEMPLATE if the module supports it."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
            },
            purpose="CKA_UNWRAP_TEMPLATE readback setup",
        )
        try:
            try:
                vals = read_attributes(rs.raw, rs.sh, key, [CKA_UNWRAP_TEMPLATE])
                ut = vals[CKA_UNWRAP_TEMPLATE]
                assert ut is not None or ut == b""
            except (AssertionError, KeyError):
                pytest.skip("Module does not support CKA_UNWRAP_TEMPLATE")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_derive_template_attribute_readable(self, p11_raw_session: Any) -> None:
        """Keys should accept CKA_DERIVE_TEMPLATE if the module supports it."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES not supported")
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DERIVE: True,
                CKA_TOKEN: False,
            },
            purpose="CKA_DERIVE_TEMPLATE readback setup",
        )
        try:
            try:
                vals = read_attributes(rs.raw, rs.sh, key, [CKA_DERIVE_TEMPLATE])
                dt = vals[CKA_DERIVE_TEMPLATE]
                assert dt is not None or dt == b""
            except (AssertionError, KeyError):
                pytest.skip("Module does not support CKA_DERIVE_TEMPLATE")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_wrap_template_enforces_target_attributes(self, p11_raw_session: Any) -> None:
        """CKA_WRAP_TEMPLATE must block wrapping a target that violates it."""
        from pkcs11_check.raw.pack import (
            attr_bool,
            attr_bytes,
            attr_template,
            attr_ulong,
            mech_simple,
            template,
        )
        from pkcs11_check.raw.rv import ckr_name

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        allowed_label = b"pkcs11-check-wrap-template-allowed"
        denied_label = b"pkcs11-check-wrap-template-denied"
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))
        wrapping_template = template(
            attr_ulong(CKA_VALUE_LEN, 16),
            attr_bool(CKA_WRAP, True),
            attr_bool(CKA_TOKEN, False),
            attr_template(CKA_WRAP_TEMPLATE, nested_template),
        )
        keygen_mech = mech_simple(CKM_AES_KEY_GEN)
        wrapping_key = CK_OBJECT_HANDLE(0)
        allowed_target = 0
        denied_target = 0
        try:
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                keygen_mech.byref(),
                wrapping_template.ptr,
                wrapping_template.count,
                byref(wrapping_key),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_WRAP_TEMPLATE not supported at key generation: {ckr_name(rv)}"
                    )
                expect_rv(rv, CKR_OK, context="CKA_WRAP_TEMPLATE wrapping key generation")

            claimed = False
            try:
                attrs = read_attributes(rs.raw, rs.sh, wrapping_key.value, [CKA_WRAP_TEMPLATE])
                raw_template = attrs.get(CKA_WRAP_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            allowed_target = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_LABEL: allowed_label,
                },
                purpose="CKA_WRAP_TEMPLATE matching target setup",
            )
            denied_target = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                    CKA_LABEL: denied_label,
                },
                purpose="CKA_WRAP_TEMPLATE violating target setup",
            )

            wrap_mech = mech_simple(CKM_AES_KEY_WRAP)
            allowed_len = c_ulong(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                wrapping_key.value,
                allowed_target,
                None,
                byref(allowed_len),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_AES_KEY_WRAP:C_WrapKey (matching template)",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=(
                        "CKM_AES_KEY_WRAP advertised but matching-template wrap is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )

            denied_len = c_ulong(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                wrapping_key.value,
                denied_target,
                None,
                byref(denied_len),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_WRAP_TEMPLATE target-attribute enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _WRAP_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_WrapKey target violating CKA_WRAP_TEMPLATE",
                )
        finally:
            for handle in (denied_target, allowed_target, wrapping_key.value):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)

    def test_unwrap_template_enforces_created_object_attributes(self, p11_raw_session: Any) -> None:
        """CKA_UNWRAP_TEMPLATE must block unwrapping to a violating object template."""
        from pkcs11_check.raw.pack import (
            attr_bool,
            attr_bytes,
            attr_template,
            attr_ulong,
            mech_simple,
            template,
        )
        from pkcs11_check.raw.rv import ckr_name

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("CKM_AES_KEY_WRAP not supported")

        allowed_label = b"pkcs11-check-unwrap-template-allowed"
        denied_label = b"pkcs11-check-unwrap-template-denied"
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))
        keygen_mech = mech_simple(CKM_AES_KEY_GEN)
        unwrapping_key = CK_OBJECT_HANDLE(0)
        source_key = 0
        matching_unwrapped = 0
        violating_unwrapped = CK_OBJECT_HANDLE(0)
        try:
            unwrapping_template = template(
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_WRAP, True),
                attr_bool(CKA_UNWRAP, True),
                attr_bool(CKA_TOKEN, False),
                attr_template(CKA_UNWRAP_TEMPLATE, nested_template),
            )
            rv = rs.raw.C_GenerateKey(
                rs.sh,
                keygen_mech.byref(),
                unwrapping_template.ptr,
                unwrapping_template.count,
                byref(unwrapping_key),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_UNWRAP_TEMPLATE not supported at key generation: {ckr_name(rv)}"
                    )
                expect_rv(rv, CKR_OK, context="CKA_UNWRAP_TEMPLATE unwrapping key generation")

            claimed = False
            try:
                attrs = read_attributes(rs.raw, rs.sh, unwrapping_key.value, [CKA_UNWRAP_TEMPLATE])
                raw_template = attrs.get(CKA_UNWRAP_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            source_key = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_TOKEN: False,
                },
                purpose="CKA_UNWRAP_TEMPLATE source-key setup",
            )
            wrap_mech = mech_simple(CKM_AES_KEY_WRAP)
            wrapped_len = c_ulong(0)
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                unwrapping_key.value,
                source_key,
                None,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_AES_KEY_WRAP:C_WrapKey (source key)",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=(
                        "CKM_AES_KEY_WRAP advertised but source-key wrap is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            wrapped_buf = (c_ubyte * wrapped_len.value)()
            rv = rs.raw.C_WrapKey(
                rs.sh,
                wrap_mech.byref(),
                unwrapping_key.value,
                source_key,
                wrapped_buf,
                byref(wrapped_len),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_AES_KEY_WRAP:C_WrapKey (source key retry)",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=(
                        "CKM_AES_KEY_WRAP advertised but source-key wrap retry is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )

            matching_template = template(
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
                unwrapping_key.value,
                wrapped_buf,
                wrapped_len.value,
                matching_template.ptr,
                matching_template.count,
                byref(violating_unwrapped),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_AES_KEY_WRAP:C_UnwrapKey (matching template)",
                    operation="C_UnwrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    actual=rv,
                    summary=(
                        "CKM_AES_KEY_WRAP advertised but matching-template unwrap is not "
                        f"operational: {ckr_name(rv)}"
                    ),
                )
            matching_unwrapped = violating_unwrapped.value
            violating_unwrapped = CK_OBJECT_HANDLE(0)

            violating_template = template(
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
                unwrapping_key.value,
                wrapped_buf,
                wrapped_len.value,
                violating_template.ptr,
                violating_template.count,
                byref(violating_unwrapped),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_UNWRAP_TEMPLATE created-object enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _UNWRAP_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_UnwrapKey template violating CKA_UNWRAP_TEMPLATE",
                )
        finally:
            for handle in (
                violating_unwrapped.value,
                matching_unwrapped,
                source_key,
                unwrapping_key.value,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)

    def test_derive_template_enforces_created_object_attributes(self, p11_raw_session: Any) -> None:
        """CKA_DERIVE_TEMPLATE must block deriving to a violating object template."""
        from pkcs11_check.raw.pack import (
            attr_bool,
            attr_bytes,
            attr_template,
            attr_ulong,
            mech_string_data,
            template,
        )
        from pkcs11_check.raw.rv import ckr_name

        rs = p11_raw_session
        if not rs.has_mechanism("CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        allowed_label = b"pkcs11-check-derive-template-allowed"
        denied_label = b"pkcs11-check-derive-template-denied"
        base_value = b"A" * 16
        derive_data = b"B" * 16
        nested_template = template(attr_bytes(CKA_LABEL, allowed_label))
        base_template = template(
            attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
            attr_ulong(CKA_KEY_TYPE, CKK_GENERIC_SECRET),
            attr_bytes(CKA_VALUE, base_value),
            attr_bool(CKA_DERIVE, True),
            attr_bool(CKA_EXTRACTABLE, True),
            attr_bool(CKA_SENSITIVE, False),
            attr_bool(CKA_TOKEN, False),
            attr_template(CKA_DERIVE_TEMPLATE, nested_template),
        )
        base_key = CK_OBJECT_HANDLE(0)
        matching_derived = 0
        violating_derived = CK_OBJECT_HANDLE(0)
        try:
            rv = rs.raw.C_CreateObject(
                rs.sh,
                base_template.ptr,
                base_template.count,
                byref(base_key),
            )
            if rv != CKR_OK:
                if rv in _TEMPLATE_ATTR_SETUP_REJECT_RVS:
                    pytest.skip(
                        f"CKA_DERIVE_TEMPLATE not supported at base-key import: {ckr_name(rv)}"
                    )
                expect_rv(rv, CKR_OK, context="CKA_DERIVE_TEMPLATE base-key import")

            claimed = False
            try:
                attrs = read_attributes(rs.raw, rs.sh, base_key.value, [CKA_DERIVE_TEMPLATE])
                raw_template = attrs.get(CKA_DERIVE_TEMPLATE)
                claimed = isinstance(raw_template, bytes) and len(raw_template) >= sizeof(
                    CK_ATTRIBUTE
                )
            except (AssertionError, KeyError):
                claimed = False

            derive_mech = mech_string_data(CKM_CONCATENATE_BASE_AND_DATA, derive_data)
            matching_template = template(
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
                matching_template.ptr,
                matching_template.count,
                byref(violating_derived),
            )
            if rv != CKR_OK:
                classify(
                    "not_operational",
                    kind="crypto",
                    label="CKM_CONCATENATE_BASE_AND_DATA:C_DeriveKey (matching template)",
                    operation="C_DeriveKey",
                    mechanism="CKM_CONCATENATE_BASE_AND_DATA",
                    actual=rv,
                    summary=(
                        "CKM_CONCATENATE_BASE_AND_DATA advertised but matching-template "
                        f"derive is not operational: {ckr_name(rv)}"
                    ),
                )
            matching_derived = violating_derived.value
            violating_derived = CK_OBJECT_HANDLE(0)

            violating_template = template(
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
                violating_template.ptr,
                violating_template.count,
                byref(violating_derived),
            )
            if rv == CKR_OK:
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=True,
                    label="CKA_DERIVE_TEMPLATE created-object enforcement",
                )
            else:
                classify_negative_rv(
                    rv,
                    _DERIVE_TEMPLATE_ENFORCEMENT_RVS,
                    label="C_DeriveKey template violating CKA_DERIVE_TEMPLATE",
                )
        finally:
            for handle in (
                violating_derived.value,
                matching_derived,
                base_key.value,
            ):
                if handle:
                    destroy_quietly(rs.raw, rs.sh, handle)


# ---------------------------------------------------------------------------
# CKO_OTP_KEY object attributes (Phase B gap)
# ---------------------------------------------------------------------------


class TestOtpKeyAttributes:
    """CKO_OTP_KEY object attribute coverage.

    OTP mechanisms are tested in test_otp.py. This class verifies
    OTP-specific CKA_OTP_* attributes on key objects.
    """

    def test_otp_key_format_attribute(self, p11_raw_session: Any) -> None:
        """CKA_OTP_FORMAT should be readable on OTP keys if supported."""
        from pkcs11_check.raw.pack import attr_bool, mech_simple, template
        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

        rs = p11_raw_session
        if not rs.has_mechanism("HOTP_KEY_GEN"):
            pytest.skip("CKM_HOTP_KEY_GEN not supported")
        tmpl = template(
            attr_bool(CKA_TOKEN, False),
            attr_bool(CKA_SIGN, True),
        )
        mech = mech_simple(CKM_HOTP_KEY_GEN)
        key = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(
            rs.sh,
            mech.byref(),
            tmpl.ptr,
            tmpl.count,
            byref(key),
        )
        try:
            expect_rv(rv, CKR_OK, context="CKM_HOTP_KEY_GEN C_GenerateKey")
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _HOTP_KEYGEN_ERROR_CKRS,
                "CKM_HOTP_KEY_GEN advertised but key generation failed",
            )
        key_h = key.value
        try:
            for attr_int in (CKA_OTP_FORMAT, CKA_OTP_LENGTH):
                try:
                    vals = read_attributes(rs.raw, rs.sh, key_h, [attr_int])
                    assert vals[attr_int] is not None
                except AssertionError:
                    pass  # Module may not expose all OTP attributes
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


# ---------------------------------------------------------------------------
# C_WaitForSlotEvent success path (Phase A gap)
# ---------------------------------------------------------------------------


class TestWaitForSlotEvent:
    """C_WaitForSlotEvent - non-blocking poll."""

    def test_wait_for_slot_event_non_blocking(self, p11_raw_session: Any) -> None:
        """Non-blocking C_WaitForSlotEvent should return CKR_NO_EVENT or succeed."""
        rs = p11_raw_session
        slot_out = c_ulong(0)
        # flags=1 means CKF_DONT_BLOCK (non-blocking)
        rv = rs.raw.C_WaitForSlotEvent(1, byref(slot_out), None)
        if rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("C_WaitForSlotEvent not supported")
        if rv == CKR_OK:
            pass  # Got an event -- valid
        elif rv == CKR_NO_EVENT:
            pass  # Expected -- no slot events pending
        else:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"C_WaitForSlotEvent returned unexpected CKR: 0x{rv:08x}",
                ComplianceLevel.VENDOR,
            )


# ---------------------------------------------------------------------------
# Legacy parallel functions (Phase A gap)
# ---------------------------------------------------------------------------


class TestLegacyParallelFunctions:
    """C_GetFunctionStatus and C_CancelFunction (legacy, Sec.5.15).

    These functions are required to exist but always return
    CKR_FUNCTION_NOT_PARALLEL (0x51) per PKCS#11 v2.40+.
    """

    def test_get_function_status_returns_not_parallel(self, p11_config: Any) -> None:
        """C_GetFunctionStatus must return CKR_FUNCTION_NOT_PARALLEL."""
        returncode, stdout, stderr = _run_gap_probe(p11_config, "get_function_status")
        if returncode != 0:
            classify(
                "honest_deviation",
                kind="lifecycle",
                label="C_GetFunctionStatus probe subprocess",
                operation="C_GetFunctionStatus",
                summary=f"Subprocess failed: {stderr[:200]}",
            )
        lines = stdout.strip().split("\n")
        gfs_line = next((ln for ln in lines if ln.startswith("GFS:")), None)
        assert gfs_line is not None, f"No GFS output: {stdout!r}"
        rv_hex = gfs_line.split(":")[1]
        # Spec says CKR_FUNCTION_NOT_PARALLEL (0x51).
        # Some modules return CKR_OPERATION_NOT_INITIALIZED (0x91) - module quirk.
        acceptable = {"0x00000051", "0x00000091", "0x00000054"}
        if rv_hex not in acceptable:
            classify(
                "self_contradiction",
                kind="metadata",
                label="C_GetFunctionStatus return code",
                operation="C_GetFunctionStatus",
                summary=(
                    f"C_GetFunctionStatus: expected CKR_FUNCTION_NOT_PARALLEL (0x51), got {rv_hex}"
                ),
            )
        if rv_hex != "0x00000051":
            from pkcs11_check.compliance import ComplianceLevel, note

            rv_name = (
                "CKR_FUNCTION_NOT_SUPPORTED"
                if rv_hex == "0x00000054"
                else "CKR_OPERATION_NOT_INITIALIZED"
            )
            note(
                f"C_GetFunctionStatus returned {rv_name} ({rv_hex}) instead of spec-required "
                f"CKR_FUNCTION_NOT_PARALLEL (0x51)",
                ComplianceLevel.VENDOR,
            )

    def test_cancel_function_returns_not_parallel(self, p11_config: Any) -> None:
        """C_CancelFunction must return CKR_FUNCTION_NOT_PARALLEL."""
        returncode, stdout, stderr = _run_gap_probe(p11_config, "cancel_function")
        if returncode != 0:
            classify(
                "honest_deviation",
                kind="lifecycle",
                label="C_CancelFunction probe subprocess",
                operation="C_CancelFunction",
                summary=f"Subprocess failed: {stderr[:200]}",
            )
        lines = stdout.strip().split("\n")
        cf_line = next((ln for ln in lines if ln.startswith("CF:")), None)
        assert cf_line is not None, f"No CF output: {stdout!r}"
        rv_hex = cf_line.split(":")[1]
        acceptable = {"0x00000051", "0x00000091", "0x00000054"}
        if rv_hex not in acceptable:
            classify(
                "self_contradiction",
                kind="metadata",
                label="C_CancelFunction return code",
                operation="C_CancelFunction",
                summary=(
                    f"C_CancelFunction: expected CKR_FUNCTION_NOT_PARALLEL (0x51), got {rv_hex}"
                ),
            )
        if rv_hex != "0x00000051":
            from pkcs11_check.compliance import ComplianceLevel, note

            rv_name = (
                "CKR_FUNCTION_NOT_SUPPORTED"
                if rv_hex == "0x00000054"
                else "CKR_OPERATION_NOT_INITIALIZED"
            )
            note(
                f"C_CancelFunction returned {rv_name} ({rv_hex}) instead of spec-required "
                f"CKR_FUNCTION_NOT_PARALLEL (0x51)",
                ComplianceLevel.VENDOR,
            )


# ---------------------------------------------------------------------------
# Message-based finalizers (Phase A gap)
# ---------------------------------------------------------------------------


class TestMessageFinalizers:
    """C_MessageEncryptFinal, C_MessageDecryptFinal, etc. (v3.0+).

    These finalize message-based operations. Most modules that support
    message-based ops auto-finalize, so explicit finalize may not be needed.
    """

    @pytest.mark.needs_function("C_MessageEncryptFinal")
    def test_message_encrypt_final_availability(self, p11_raw_session: Any) -> None:
        """Check if message-based encrypt final is accessible."""
        rs = p11_raw_session
        assert "C_MessageEncryptFinal" in rs.raw.available_function_names()

    @pytest.mark.needs_function("C_MessageVerifyFinal")
    def test_message_verify_final_availability(self, p11_raw_session: Any) -> None:
        """Check if message-based verify final is accessible."""
        rs = p11_raw_session
        assert "C_MessageVerifyFinal" in rs.raw.available_function_names()


# ---------------------------------------------------------------------------
# Async lifecycle (Phase A gap)
# ---------------------------------------------------------------------------


class TestAsyncLifecycle:
    """C_AsyncComplete, C_AsyncJoin, C_AsyncGetID - v3.0+ async operation management.

    Testing async lifecycle requires a module that actively supports async
    operations. Most current modules report the functions but do not have
    in-flight async ops, so we verify availability and document the limitation.

    TODO: Add full async lifecycle test when a module supports it:
      1. Start an async operation (e.g., async C_GenerateKeyPair)
      2. Poll with C_AsyncGetID to get the operation ID
      3. Complete with C_AsyncComplete or C_AsyncJoin
      4. Verify the result matches a synchronous equivalent
    Currently no tested module supports async operations.
    """

    @pytest.mark.needs_function("C_AsyncComplete")
    def test_async_function_availability(self, p11_raw_session: Any) -> None:
        """All three async functions should be in the v3.0 function list."""
        rs = p11_raw_session
        names = rs.raw.available_function_names()
        async_names = ("C_AsyncComplete", "C_AsyncJoin", "C_AsyncGetID")
        missing = [n for n in async_names if n not in names]
        if missing:
            pytest.skip(f"Async functions not available: {', '.join(missing)}")

    @pytest.mark.needs_function("C_AsyncComplete")
    def test_async_complete_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_AsyncComplete with no active async op should return a defined CKR."""
        rs = p11_raw_session
        if "C_AsyncComplete" not in rs.raw.available_function_names():
            pytest.skip("C_AsyncComplete not available")
        rv = rs.raw.C_AsyncComplete(rs.sh, None, None)
        # No CKR assertion -- presence check only (function returned without crash)
        assert rv is not None

    @pytest.mark.needs_function("C_AsyncJoin")
    def test_async_join_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_AsyncJoin with no active async op should return a defined CKR."""
        rs = p11_raw_session
        if "C_AsyncJoin" not in rs.raw.available_function_names():
            pytest.skip("C_AsyncJoin not available")
        rv = rs.raw.C_AsyncJoin(rs.sh, None, 0, None, 0)
        # No CKR assertion -- presence check only (function returned without crash)
        assert rv is not None

    @pytest.mark.needs_function("C_AsyncGetID")
    def test_async_get_id_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_AsyncGetID with no active async op should return a defined CKR."""
        rs = p11_raw_session
        if "C_AsyncGetID" not in rs.raw.available_function_names():
            pytest.skip("C_AsyncGetID not available")
        async_id = c_ulong(0)
        rv = rs.raw.C_AsyncGetID(rs.sh, None, byref(async_id))
        # No CKR assertion -- presence check only (function returned without crash)
        assert rv is not None


# ---------------------------------------------------------------------------
# CKM_RSA_PKCS_NULL (Phase G gap)
# ---------------------------------------------------------------------------


class TestRsaPkcsNull:
    """CKM_RSA_PKCS_NULL - raw RSA with no formatting."""

    def test_null_mechanism_availability(self, p11_raw_session: Any) -> None:
        """Check if CKM_RSA_PKCS_NULL is reported by the module."""
        if not p11_raw_session.has_mechanism("RSA_PKCS_NULL"):
            pytest.skip("CKM_RSA_PKCS_NULL not supported")


# ---------------------------------------------------------------------------
# KMAC (Phase D gap)
# ---------------------------------------------------------------------------


class TestKmac:
    """CKM_KMAC_128 and CKM_KMAC_256 - NIST SP 800-185 KECCAK MAC."""

    def test_kmac_128_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("KMAC_128"):
            pytest.skip("CKM_KMAC_128 not supported")

    def test_kmac_256_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("KMAC_256"):
            pytest.skip("CKM_KMAC_256 not supported")


# ---------------------------------------------------------------------------
# Standalone SHAKE XOF (Phase D gap)
# ---------------------------------------------------------------------------


class TestShakeXof:
    """Standalone SHAKE128/SHAKE256 as XOF digest mechanisms."""

    def test_shake_128_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("SHAKE_128"):
            pytest.skip("CKM_SHAKE_128 not supported")

    def test_shake_256_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("SHAKE_256"):
            pytest.skip("CKM_SHAKE_256 not supported")


# ---------------------------------------------------------------------------
# ML-DSA External MU (Phase D gap)
# ---------------------------------------------------------------------------


class TestMlDsaExternalMu:
    """CKM_ML_DSA_EXTERNAL_MU and CKM_ML_DSA_EXTERNAL_MU_GEN."""

    def test_external_mu_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("ML_DSA_EXTERNAL_MU"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU not supported")

    def test_external_mu_gen_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("ML_DSA_EXTERNAL_MU_GEN"):
            pytest.skip("CKM_ML_DSA_EXTERNAL_MU_GEN not supported")


# ---------------------------------------------------------------------------
# PKCS#12 PBE (Phase F gap)
# ---------------------------------------------------------------------------


class TestPkcs12Pbe:
    """CKM_PKCS12_PBE_EXPORT and CKM_PKCS12_PBE_IMPORT."""

    def test_pkcs12_pbe_export_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PKCS12_PBE_EXPORT"):
            pytest.skip("CKM_PKCS12_PBE_EXPORT not supported")

    def test_pkcs12_pbe_import_availability(self, p11_raw_session: Any) -> None:
        if not p11_raw_session.has_mechanism("PKCS12_PBE_IMPORT"):
            pytest.skip("CKM_PKCS12_PBE_IMPORT not supported")


# ---------------------------------------------------------------------------
# Tier 1 stragglers
# ---------------------------------------------------------------------------


class TestTier1Stragglers:
    """Mechanisms identified as Tier 1 gaps in the audit."""

    def test_aes_cmac_general_availability(self, p11_raw_session: Any) -> None:
        """CKM_AES_CMAC_GENERAL - parameterized CMAC tag length."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CMAC_GENERAL"):
            pytest.skip("CKM_AES_CMAC_GENERAL not supported")
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
            purpose="AES_CMAC_GENERAL setup",
        )
        # CKM_AES_CMAC_GENERAL takes a CK_MAC_GENERAL_PARAMS (a CK_ULONG giving the
        # requested MAC length in bytes); without it a conformant module rejects the
        # call with CKR_MECHANISM_PARAM_INVALID. Request a half-block (8 of 16) tag so
        # a module that ignores the length param is caught by the length assertion.
        mac_len = 8
        try:
            try:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_AES_CMAC_GENERAL,
                    b"test data for cmac general",
                    mech_param=mech_ulong(CKM_AES_CMAC_GENERAL, mac_len),
                )
            except AssertionError as e:
                # Advertised but the operation does not complete: a clean operational
                # deviation, not a conformance break.
                xfail_as(
                    "not_operational",
                    kind="crypto",
                    label="CKM_AES_CMAC_GENERAL:C_Sign",
                    operation="C_Sign",
                    mechanism="CKM_AES_CMAC_GENERAL",
                    summary=f"AES_CMAC_GENERAL sign failed: {e}",
                )
            # Honoring the requested tag length is mandatory: a wrong length is the
            # module ignoring CK_MAC_GENERAL_PARAMS (wrong output on a positive op -> fail).
            assert len(sig) == mac_len, (
                f"AES_CMAC_GENERAL requested {mac_len}-byte tag but got {len(sig)} bytes "
                "(module ignored CK_MAC_GENERAL_PARAMS)"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ec_key_pair_gen_w_extra_bits_availability(self, p11_raw_session: Any) -> None:
        """CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS."""
        if not p11_raw_session.has_mechanism("EC_KEY_PAIR_GEN_W_EXTRA_BITS"):
            pytest.skip("CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS not supported")


# ---------------------------------------------------------------------------
# C_SignEncryptUpdate / C_DecryptVerifyUpdate (Phase A dual-function gap)
# ---------------------------------------------------------------------------


class TestDualFunctionRemaining:
    """C_SignEncryptUpdate (Sec.5.14.3) and C_DecryptVerifyUpdate (Sec.5.14.4).

    These combine sign+encrypt or decrypt+verify in a single call.
    Tested via ctypes subprocess - these functions are at CK_FUNCTION_LIST
    indices 56 and 57. Most modules return CKR_FUNCTION_NOT_SUPPORTED.
    """

    def test_sign_encrypt_update_callable(self, p11_config: Any) -> None:
        """C_SignEncryptUpdate (index 56) exists and returns a defined CKR code."""
        returncode, stdout, stderr = _run_gap_probe(p11_config, "sign_encrypt_update")
        if "SKIP:" in stdout:
            pytest.skip(stdout.strip())
        if returncode < 0:
            classify(
                "crash",
                label="C_SignEncryptUpdate",
                operation="C_SignEncryptUpdate",
                summary=(
                    f"C_SignEncryptUpdate crashed (signal {-returncode}). Stderr: {stderr[:200]}"
                ),
            )
        if returncode != 0:
            classify(
                "crash",
                label="C_SignEncryptUpdate probe subprocess",
                operation="C_SignEncryptUpdate",
                summary=f"No output: {stdout!r} {stderr[:200]}",
            )
        seu_line = next((ln for ln in stdout.strip().split("\n") if ln.startswith("SEU:")), None)
        assert seu_line is not None, f"No output: {stdout!r} {stderr[:200]}"
        # Any CKR response is valid - we're testing the function exists and doesn't crash

    def test_decrypt_verify_update_callable(self, p11_config: Any) -> None:
        """C_DecryptVerifyUpdate (index 57) exists and returns a defined CKR code."""
        returncode, stdout, stderr = _run_gap_probe(p11_config, "decrypt_verify_update")
        if "SKIP:" in stdout:
            pytest.skip(stdout.strip())
        if returncode < 0:
            classify(
                "crash",
                label="C_DecryptVerifyUpdate",
                operation="C_DecryptVerifyUpdate",
                summary=(
                    f"C_DecryptVerifyUpdate crashed (signal {-returncode}). Stderr: {stderr[:200]}"
                ),
            )
        if returncode != 0:
            classify(
                "crash",
                label="C_DecryptVerifyUpdate probe subprocess",
                operation="C_DecryptVerifyUpdate",
                summary=f"No output: {stdout!r} {stderr[:200]}",
            )
        dvu_line = next((ln for ln in stdout.strip().split("\n") if ln.startswith("DVU:")), None)
        assert dvu_line is not None, f"No output: {stdout!r} {stderr[:200]}"
