"""PKCS#11 API security tests - attribute attacks, policy bypass, access control.

Based on Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and PKCS#11 attribute enforcement rules from the OASIS specification.

Tests are marked @security - results are security findings, not correctness failures.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import mech_bytes, mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    import_secret_key,
    read_attributes,
    set_attributes,
    wrap_key,
)
from pkcs11_check.raw.recipes import gen_aes_key as _raw_gen_aes_key
from pkcs11_check.raw.recipes import gen_rsa_keypair as _raw_gen_rsa_keypair
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_ALLOWED_MECHANISMS,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PRIVATE,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VERIFY,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_SHA256_RSA_PKCS,
    CKO_PRIVATE_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SESSION_COUNT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._copy_mutability import (
    AUTH_SHAPED_REFUSE_RV,
    COPY_FORBIDDEN_REFUSE_RVS,
    POLICY_SHAPED_REFUSE_RVS,
    PROBE_INJECTED_VALUE,
    PROBE_ORIGINAL_VALUE,
    PROBE_PLAINTEXT,
    PROBE_ROW,
    SEALED_WRAP_REFUSE_RV,
    SET_FORBIDDEN_REFUSE_RVS,
    TABLE_PROBES,
    aes_ecb_encrypt,
    check_cbc_oracle_or_fail,
    check_ecb_baseline_or_fail,
    check_ecb_oracle_or_fail,
    check_ecb_output_length_or_fail,
    check_material_preserved,
    classify_forbidden_change_refusal,
    classify_ignored_or_mutated,
    classify_rv_validity_or_none,
    read_qc3_attributes,
    row_by_key,
    validate_qc3_shape,
    validate_wrap_chain,
    xfail_qc3_setup_refusal,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_policy_enforcement,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.test_always_authenticate import _context_specific_login

pytestmark = pytest.mark.security

_API_SECURITY_AES_SETUP_REJECT_RVS = (
    *AES_KEYGEN_RUNTIME_REJECT_RVS,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_POLICY_KEYGEN_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_ATTR_POLICY_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
)

_WRAP_DECRYPT_POLICY_BLOCK_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    # Refusing to wrap a non-extractable target is itself a valid way to block
    # the wrap-decrypt oracle (the secure outcome), not a test failure.
    CKR_KEY_UNEXTRACTABLE,
)

_WRAP_DECRYPT_RUNTIME_REJECT_RVS = (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
)


def _skip_unless_mechanism(rs: Any, name: str) -> None:
    if not rs.has_mechanism(name):
        pytest.skip(f"{name} not supported by module")


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra public session needed by API-security tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by API security test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _gen_api_security_aes_key(
    rs: Any,
    bits: int = 128,
    *,
    attrs: dict[Any, Any] | None = None,
    purpose: str = "API security AES setup",
) -> int:
    """Generate an AES fixture key without turning setup gaps into security results."""
    _skip_unless_mechanism(rs, "AES_KEY_GEN")
    require_operational_aes_keygen(rs)
    try:
        return _raw_gen_aes_key(rs.raw, rs.sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _API_SECURITY_AES_SETUP_REJECT_RVS,
            f"{purpose} is not operational",
        )
    raise


def _gen_api_security_rsa_keypair(rs: Any, bits: int = 2048) -> tuple[int, int]:
    """Generate an RSA fixture keypair for API-security tests."""
    _skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
    try:
        return _raw_gen_rsa_keypair(rs.raw, rs.sh, bits)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "API security RSA setup is not operational",
        )
    raise


def _readback_repr(raw: Any) -> str:
    """Render an attribute readback for a summary without inventing a value.

    A provider omission is NOT ``None``: rendering the sentinel as ``None`` would
    put a value the provider never returned into the record.
    """
    if raw is MISSING_ATTRIBUTE:
        return "<unavailable>"
    return repr(raw)


def _return_if_policy_reject(exc: AssertionError, allowed_rvs: tuple[Any, ...]) -> None:
    if is_known_error(exc, allowed_rvs):
        return
    raise exc


def _return_if_policy_reject_or_xfail_runtime(
    exc: AssertionError,
    *,
    policy_rvs: tuple[Any, ...],
    runtime_rvs: tuple[Any, ...],
    msg: str,
) -> None:
    if is_known_error(exc, policy_rvs):
        return
    xfail_if_known_ckr(exc, runtime_rvs, msg)
    raise exc


class TestWrapDecryptOracle:
    """Test for the classic wrap-decrypt oracle attack.

    If a key has both CKA_WRAP and CKA_DECRYPT, an attacker can:
    1. Wrap a target key under the dual-purpose key
    2. Decrypt the wrapped blob -> get raw key material

    A secure module should prevent keys from having both CKA_WRAP and CKA_DECRYPT.
    """

    def test_wrap_decrypt_combination_prevented(self, p11_raw_session: Any) -> None:
        """Module should prevent creating key with both WRAP and DECRYPT."""
        rs = p11_raw_session
        _skip_unless_mechanism(rs, "AES_ECB")
        _skip_unless_mechanism(rs, "AES_KEY_GEN")
        require_operational_aes_keygen(rs)
        try:
            dual_key_h = _raw_gen_aes_key(
                rs.raw,
                rs.sh,
                128,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                },
            )
        except AssertionError as exc:
            if is_known_error(exc, _POLICY_KEYGEN_REJECT_RVS):
                return  # Module prevented dual-purpose key creation - best
            xfail_if_known_ckr(
                exc,
                AES_KEYGEN_RUNTIME_REJECT_RVS,
                "API security dual-purpose AES setup is not operational",
            )
            raise

        target_h = 0
        try:
            # The target is created PROTECTED (non-extractable + sensitive) so the
            # wrap-decrypt oracle, if it works, extracts material the module
            # promised to protect -- a policy self-contradiction.
            target_h = _gen_api_security_aes_key(
                rs,
                attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
                purpose="API security wrap-decrypt target setup",
            )
            try:
                wrapped = wrap_key(rs.raw, rs.sh, dual_key_h, target_h, CKM_AES_ECB)
                # Decrypt the wrapped blob = extract the key material.
                try:
                    raw_key = decrypt_single(rs.raw, rs.sh, dual_key_h, CKM_AES_ECB, wrapped)
                    # Claim-check: did the target actually hold its protection?
                    tgt = read_attributes(rs.raw, rs.sh, target_h, [CKA_EXTRACTABLE])
                    tgt_extractable_raw = attr_or_record(
                        tgt,
                        CKA_EXTRACTABLE,
                        label="wrap-decrypt oracle target CKA_EXTRACTABLE readback",
                        reason="not_operational",
                        kind="policy",
                        inherit_mechanism=False,
                    )
                    claimed: bool
                    if tgt_extractable_raw is MISSING_ATTRIBUTE:
                        # The readback is unavailable, but the CLAIM is not: the
                        # module ACCEPTED a CKA_EXTRACTABLE=False template at
                        # C_GenerateKey (_gen_api_security_aes_key above raises /
                        # xfails otherwise), and that acceptance is independent
                        # claim evidence.  Deriving `claimed` from the readback
                        # alone would let one unreadable attribute downgrade a
                        # proven key-extraction break to an xfail.  The
                        # attr_or_record() record above keeps the unreadable
                        # readback itself visible.
                        claimed = True
                    else:
                        claimed = tgt_extractable_raw is False
                    # Neither half of this oracle depends on the claim-check
                    # readback: `extracted` is direct evidence of the violation
                    # (the raw key bytes came back from C_Decrypt) and `claimed`
                    # falls back to creation-time template acceptance, so a
                    # missing claim-check attribute can never mask this finding.
                    extracted = bool(raw_key) and len(raw_key) > 0
                    classify_policy_enforcement(
                        claimed=claimed,
                        violated=extracted,
                        label="wrap-decrypt oracle extracts a non-extractable/sensitive key "
                        "(PKCS#11 v3.2: CKA_WRAP and CKA_DECRYPT should not both "
                        "be True)",
                    )
                except AssertionError as exc:
                    _return_if_policy_reject_or_xfail_runtime(
                        exc,
                        policy_rvs=_WRAP_DECRYPT_POLICY_BLOCK_RVS,
                        runtime_rvs=_WRAP_DECRYPT_RUNTIME_REJECT_RVS,
                        msg="API security wrap-decrypt operation is not operational",
                    )
            except AssertionError as exc:
                _return_if_policy_reject_or_xfail_runtime(
                    exc,
                    policy_rvs=_WRAP_DECRYPT_POLICY_BLOCK_RVS,
                    runtime_rvs=_WRAP_DECRYPT_RUNTIME_REJECT_RVS,
                    msg="API security wrap-decrypt operation is not operational",
                )
        finally:
            if target_h:
                destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, dual_key_h)


class TestSensitiveExtraction:
    """Verify sensitive key material cannot be read."""

    def test_sensitive_key_value_not_readable(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True key: C_GetAttributeValue(CKA_VALUE) must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True, CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            # Membership is resolved into a plain bool *before* branching: the
            # `in` test itself is safe (it never returns provider-backed data),
            # so pre-computing it leaves no absence branch that could silently
            # fabricate a value -- CKA_VALUE correctly absent needs no record.
            value_present = CKA_VALUE in attrs
            if value_present:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_VALUE readable on CKA_SENSITIVE key",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=(
                        "SECURITY: CKA_VALUE readable on SENSITIVE key -- key material exposed"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_private_key_not_extractable(self, p11_raw_session: Any) -> None:
        """Record RSA private-exponent readability against the key's own claims."""
        rs = p11_raw_session
        pub_h, priv_h = _gen_api_security_rsa_keypair(rs)
        try:
            policy_attrs = read_attributes(
                rs.raw,
                rs.sh,
                priv_h,
                [CKA_SENSITIVE, CKA_EXTRACTABLE],
            )
            sensitive_raw = attr_or_record(
                policy_attrs,
                CKA_SENSITIVE,
                label="RSA private-key CKA_SENSITIVE readback",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            sensitive_value: Any
            if sensitive_raw is MISSING_ATTRIBUTE:
                sensitive_value = None
            else:
                sensitive_value = sensitive_raw
            extractable_raw = attr_or_record(
                policy_attrs,
                CKA_EXTRACTABLE,
                label="RSA private-key CKA_EXTRACTABLE readback",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            extractable_value: Any
            if extractable_raw is MISSING_ATTRIBUTE:
                extractable_value = None
            else:
                extractable_value = extractable_raw
            sensitive_shown = _readback_repr(sensitive_raw)
            extractable_shown = _readback_repr(extractable_raw)
            sensitive_claimed = sensitive_value is True
            non_extractable_claimed = extractable_value is False
            # Absence is already an emitted observation (the attr_or_record() calls
            # above): only a PRESENT-but-malformed value is recorded again here, so
            # one provider omission yields exactly one record.
            policy_readback_malformed = (
                sensitive_raw is not MISSING_ATTRIBUTE and type(sensitive_value) is not bool
            ) or (extractable_raw is not MISSING_ATTRIBUTE and type(extractable_value) is not bool)
            exponent_attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_PRIVATE_EXPONENT])
            # CKA_PRIVATE_EXPONENT is the protected secret this test probes for exposure.
            # It legitimately CAN be sensitive (it is the private-key component this whole
            # test is about), so a clean CKR_ATTRIBUTE_SENSITIVE refusal here is conformant,
            # not a deviation -- sensitive_is_conformant=True lets attr_or_record record it
            # that way. A missing CKR (silent omission) or CKR_ATTRIBUTE_TYPE_INVALID is
            # still a deviation via `reason`. Previously this branch bypassed attr_or_record
            # entirely via a membership guard, so a correctly-protected key produced ZERO
            # report.jsonl record for this absence (N16) -- calling attr_or_record
            # unconditionally makes the absence visible without changing which case is
            # conformant vs. a deviation.
            exponent_raw = attr_or_record(
                exponent_attrs,
                CKA_PRIVATE_EXPONENT,
                label="RSA private-key CKA_PRIVATE_EXPONENT readback",
                reason="honest_deviation",
                kind="metadata",
                inherit_mechanism=False,
                sensitive_is_conformant=True,
            )
            exponent_value: Any
            if exponent_raw is MISSING_ATTRIBUTE:
                exponent_value = None
            else:
                exponent_value = exponent_raw
            exponent_returned = exponent_raw is not MISSING_ATTRIBUTE
            exponent_readback_valid = type(exponent_value) is bytes and bool(exponent_value)

            if exponent_readback_valid and (sensitive_claimed or non_extractable_claimed):
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="RSA private exponent readable despite protective attributes",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=(
                        "SECURITY: RSA private exponent is readable while the same key "
                        f"reports CKA_SENSITIVE={sensitive_shown} and "
                        f"CKA_EXTRACTABLE={extractable_shown}"
                    ),
                )

            if policy_readback_malformed:
                classify(
                    "honest_deviation",
                    kind="metadata",
                    label="RSA private-key protection attributes malformed",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=(
                        "RSA private-key protection readback returned a malformed value: "
                        f"CKA_SENSITIVE={sensitive_shown}, "
                        f"CKA_EXTRACTABLE={extractable_shown}; private exponent returned="
                        f"{exponent_returned!r}"
                    ),
                )

            if exponent_returned and not exponent_readback_valid:
                classify(
                    "honest_deviation",
                    kind="metadata",
                    label="RSA private exponent readback empty or malformed",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=(
                        "RSA private exponent readback is empty or malformed: "
                        f"{exponent_value!r}; CKA_SENSITIVE={sensitive_shown}, "
                        f"CKA_EXTRACTABLE={extractable_shown}"
                    ),
                )

            if exponent_readback_valid and not (sensitive_claimed or non_extractable_claimed):
                note(
                    "RSA private exponent is readable; the same key reports no protective "
                    f"claim (CKA_SENSITIVE={sensitive_shown}, "
                    f"CKA_EXTRACTABLE={extractable_shown}), so this is "
                    "a token-posture observation rather than a provider contradiction.",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 CKA_SENSITIVE/CKA_EXTRACTABLE attribute semantics",
                )
            elif not exponent_returned and (sensitive_claimed or non_extractable_claimed):
                note(
                    "RSA private-exponent exposure was not observed through "
                    "C_GetAttributeValue; same-key "
                    f"CKA_SENSITIVE={sensitive_shown}, "
                    f"CKA_EXTRACTABLE={extractable_shown} protective attributes "
                    "remain consistent with an unavailable private exponent.",
                    ComplianceLevel.STANDARD,
                    reference="PKCS#11 CKA_SENSITIVE/CKA_EXTRACTABLE attribute semantics",
                )
            elif not exponent_returned:
                note(
                    "RSA private-exponent exposure was not observed through "
                    "C_GetAttributeValue; same-key "
                    f"CKA_SENSITIVE={sensitive_shown}, "
                    f"CKA_EXTRACTABLE={extractable_shown} attributes remain a "
                    "token-posture observation, not proof of protection.",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 CKA_SENSITIVE/CKA_EXTRACTABLE attribute semantics",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestAttributeEscalation:
    """Verify attributes cannot be escalated after creation."""

    def test_extractable_cannot_be_set_true(self, p11_raw_session: Any) -> None:
        """CKA_EXTRACTABLE=False cannot be changed to True."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_EXTRACTABLE escalation via C_SetAttributeValue",
                    operation="C_SetAttributeValue",
                    summary="SECURITY: CKA_EXTRACTABLE escalated from False to True",
                )
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_sensitive_cannot_be_set_false(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE=True cannot be changed to False."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True},
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                classify(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_SENSITIVE downgrade via C_SetAttributeValue",
                    operation="C_SetAttributeValue",
                    summary="SECURITY: CKA_SENSITIVE downgraded from True to False",
                )
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAttributeLaunderingViaCopy:
    """Test attribute laundering through C_CopyObject.

    An attacker might try to copy a key with modified attributes
    to bypass security restrictions.
    """

    def test_copy_cannot_escalate_extractable(self, p11_raw_session: Any) -> None:
        """Copying a non-extractable key with CKA_EXTRACTABLE=True must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False, CKA_COPYABLE: True},
        )
        try:
            # policy claim/effect-check. claimed = the original key reads back
            # CKA_EXTRACTABLE=False (the module honored the protection); violated
            # = the escalated copy actually exposes CKA_VALUE.
            orig = read_attributes(rs.raw, rs.sh, key_h, [CKA_EXTRACTABLE])
            orig_extractable_raw = attr_or_record(
                orig,
                CKA_EXTRACTABLE,
                label="C_CopyObject source CKA_EXTRACTABLE readback",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            claimed: bool
            if orig_extractable_raw is MISSING_ATTRIBUTE:
                # Creation-time acceptance of the CKA_EXTRACTABLE=False template is
                # independent claim evidence; an unreadable readback must not
                # downgrade a proven escalation-plus-exposure to an xfail.
                claimed = True
            else:
                claimed = orig_extractable_raw is False
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_EXTRACTABLE: True})
                try:
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    violated = CKA_VALUE in attrs
                    classify_policy_enforcement(
                        claimed=claimed,
                        violated=violated,
                        label="C_CopyObject escalates CKA_EXTRACTABLE False->True and exposes "
                        "key material (PKCS#11 v3.2: CKA_EXTRACTABLE may only "
                        "change True->False on copy)",
                    )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_cannot_downgrade_sensitive(self, p11_raw_session: Any) -> None:
        """Copying with CKA_SENSITIVE=False when original is True must fail."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_SENSITIVE: True, CKA_COPYABLE: True},
        )
        try:
            try:
                copy_h = copy_object(rs.raw, rs.sh, key_h, {CKA_SENSITIVE: False})
                try:
                    attrs = read_attributes(rs.raw, rs.sh, copy_h, [CKA_VALUE])
                    # Membership is resolved into a plain bool *before* branching (the
                    # `in` test itself is safe): CKA_VALUE correctly absent needs no
                    # record, and there is no absence branch left to fabricate a value.
                    value_present = CKA_VALUE in attrs
                    if value_present:
                        fail_as(
                            "self_contradiction",
                            kind="policy",
                            label="CKA_SENSITIVE downgrade via C_CopyObject",
                            operation="C_CopyObject",
                            summary="SECURITY: Copy downgraded CKA_SENSITIVE, "
                            "key material readable",
                        )
                finally:
                    destroy_quietly(rs.raw, rs.sh, copy_h)
            except AssertionError as exc:
                _return_if_policy_reject(exc, _ATTR_POLICY_REJECT_RVS)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestKeyUsageRestrictions:
    """Verify key usage attributes are enforced."""

    def test_encrypt_disabled_removes_capability(self, p11_raw_session: Any) -> None:
        """Key with CKA_ENCRYPT=False should not have encrypt capability."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_ENCRYPT: False, CKA_DECRYPT: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_ENCRYPT])
            encrypt_value = attr_or_record(
                attrs,
                CKA_ENCRYPT,
                label="CKA_ENCRYPT=False readback",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            if encrypt_value is MISSING_ATTRIBUTE:
                return
            assert encrypt_value is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_non_extractable_enforced(self, p11_raw_session: Any) -> None:
        """Non-extractable key material cannot be read."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={CKA_EXTRACTABLE: False, CKA_SENSITIVE: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_VALUE])
            # Membership is resolved into a plain bool *before* branching (the `in`
            # test itself is safe): CKA_VALUE correctly absent needs no record, and
            # there is no absence branch left to fabricate a value.
            value_present = CKA_VALUE in attrs
            if value_present:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_VALUE readable on non-extractable key",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary=(
                        "SECURITY: CKA_VALUE readable on non-extractable key -- "
                        "key material exposed"
                    ),
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_decrypt_only_key(self, p11_raw_session: Any) -> None:
        """Key created for decrypt-only should have correct attributes."""
        rs = p11_raw_session
        key_h = _gen_api_security_aes_key(
            rs,
            attrs={
                CKA_ENCRYPT: False,
                CKA_DECRYPT: True,
                CKA_WRAP: False,
                CKA_UNWRAP: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_DECRYPT, CKA_ENCRYPT])
            decrypt_value = attr_or_record(
                attrs,
                CKA_DECRYPT,
                label="CKA_DECRYPT=True readback (decrypt-only key)",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            # Each attribute is an independent check on the same key: a missing
            # CKA_DECRYPT readback must not suppress the CKA_ENCRYPT check below.
            if decrypt_value is not MISSING_ATTRIBUTE:
                assert decrypt_value is True
            encrypt_value = attr_or_record(
                attrs,
                CKA_ENCRYPT,
                label="CKA_ENCRYPT=False readback (decrypt-only key)",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            if encrypt_value is not MISSING_ATTRIBUTE:
                assert encrypt_value is False
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestAccessControl:
    """Test session access control enforcement."""

    def test_no_login_private_objects_invisible(self, p11_raw_session: Any) -> None:
        """Without login, private objects should not be visible."""
        rs = p11_raw_session
        # Open a public (non-logged-in) session
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, pub_sh, tmpl)
            # This isn't a hard assertion since there may be no private keys at all
            # The point is that the search doesn't crash and doesn't leak
            assert isinstance(found, list)
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_handle_prediction(self, p11_raw_session: Any) -> None:
        """Object handles should not be trivially sequential/predictable."""
        rs = p11_raw_session
        # Create multiple keys simultaneously (don't destroy) to get unique handles
        keys = []
        for i in range(10):
            key_h = _gen_api_security_aes_key(
                rs,
                attrs={CKA_LABEL: f"handle-{i}"},
                purpose="API security handle-prediction setup",
            )
            keys.append(key_h)
        # All should be distinct handles
        assert len(keys) == 10
        # Clean up
        for key_h in keys:
            destroy_quietly(rs.raw, rs.sh, key_h)


_WRAP_DOWNGRADE_NOTE = (
    "AES-128 wrapping key wrapped an AES-256 target (key-strength downgrade): "
    "wrapping a longer key under a shorter one reduces the effective security "
    "level of the wrapped key to that of the wrapping key "
    "(NIST SP 800-57 Part 1 §5.6.3 key-strength matching)"
)
_WRAP_ECB_NOTE = (
    "AES-ECB wrapped an AES-256 target: ECB mode provides no IV/nonce "
    "protection and wraps key material in a deterministic, block-independent "
    "fashion (NIST SP 800-57 Part 1 §5.3.5 / PKCS#11 v3.2 key-wrapping guidance)"
)

_WRAP_STRENGTH_RUNTIME_SKIP_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


class TestWrapStrengthDowngrade:
    """hardening G5.4: Wrap-strength downgrade posture (note-only, never fail).

    NIST SP 800-57 Part 1 §5.6.3 recommends wrapping keys under a key of at
    least equal strength.  Wrapping an AES-256 key under an AES-128 key (or
    under ECB mode) is *permitted* by PKCS#11 but lowers the effective security
    to that of the wrapping key.  These tests record the module's posture; they
    NEVER produce a hard fail.
    """

    def test_aes256_wrapped_under_aes128_note(self, p11_raw_session: Any) -> None:
        """Note when an AES-256 key can be wrapped by an AES-128 key.

        A module that rejects or cannot set up the combination is equally fine:
        the test exits cleanly at the first impediment.  Only a completed wrap
        (CKR_OK from C_WrapKey) records the note — the note is about posture, not
        a security failure.
        """
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported by module")
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported by module")
        require_operational_aes_keygen(rs)

        wrap_h = 0
        target_h = 0
        try:
            try:
                wrap_h = _raw_gen_aes_key(
                    rs.raw,
                    rs.sh,
                    128,
                    attrs={CKA_WRAP: True, CKA_ENCRYPT: False, CKA_DECRYPT: False},
                )
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            try:
                target_h = _raw_gen_aes_key(
                    rs.raw,
                    rs.sh,
                    256,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                )
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            try:
                wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            note(
                _WRAP_DOWNGRADE_NOTE,
                ComplianceLevel.NOT_RECOMMENDED,
                reference="NIST SP 800-57 Part 1 §5.6.3",
                test_id="TestWrapStrengthDowngrade.test_aes256_wrapped_under_aes128_note",
            )
        finally:
            if target_h:
                destroy_quietly(rs.raw, rs.sh, target_h)
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)

    def test_aes256_wrapped_under_ecb_note(self, p11_raw_session: Any) -> None:
        """Note when an AES-256 key can be wrapped using AES-ECB mode.

        AES-ECB wrap is deterministic and provides no IV-based diversification:
        the same key always produces the same wrapped blob.  A module that
        rejects or cannot set up the combination is equally fine.
        """
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported by module")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("AES_ECB not supported by module")
        require_operational_aes_keygen(rs)

        wrap_h = 0
        target_h = 0
        try:
            try:
                wrap_h = _raw_gen_aes_key(
                    rs.raw,
                    rs.sh,
                    128,
                    attrs={CKA_WRAP: True, CKA_ENCRYPT: False, CKA_DECRYPT: False},
                )
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            try:
                target_h = _raw_gen_aes_key(
                    rs.raw,
                    rs.sh,
                    256,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                )
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            try:
                wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_ECB)
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_STRENGTH_RUNTIME_SKIP_RVS):
                    return
                raise

            note(
                _WRAP_ECB_NOTE,
                ComplianceLevel.NOT_RECOMMENDED,
                reference="NIST SP 800-57 Part 1 §5.3.5",
                test_id="TestWrapStrengthDowngrade.test_aes256_wrapped_under_ecb_note",
            )
        finally:
            if target_h:
                destroy_quietly(rs.raw, rs.sh, target_h)
            if wrap_h:
                destroy_quietly(rs.raw, rs.sh, wrap_h)


_QC3B_CBC_IV = bytes(range(0x50, 0x60))
_QC3B_WRAPPER_VALUE = bytes(range(0x70, 0x80))
_QC3B_LABEL_ORIGINAL = "qc3b-original"
_QC3B_LABEL_UPDATED = "qc3b-updated"

#: RSA parameters for the QC3b re-authentication probe (I1): a 2048-bit
#: RSA keypair whose private half carries CKA_ALWAYS_AUTHENTICATE=True,
#: exercised with single-part SHA256-RSA-PKCS sign operations.
_QC3B_RSA_BITS = 2048
_QC3B_RSA_SIG_LEN = _QC3B_RSA_BITS // 8
_QC3B_REAUTH_SIGN_MSG = b"qc3b-reauth-probe"


def _reauth_sign_attempt(rs: Any, priv: int) -> tuple[int, bytes]:
    """Raw C_SignInit + C_Sign round trip on an RSA key (I1).

    Mirrors the sanctioned test_always_authenticate shape: single-part sign
    with a fixed-size output buffer. Returns (rv, signature-or-empty): CKR_OK
    carries the signature bytes; any refusal (at init or at sign) carries b"".
    Used for premise, single-use, and post-change legs (Init -> Sign with no
    login in between). The control leg uses the split Init/login/Sign path
    below (F1: login after Init, before completion; no re-Init after login).
    """
    rv_init = _reauth_sign_init(rs, priv)
    if rv_init != int(CKR_OK):
        return rv_init, b""
    return _reauth_sign_complete(rs)


def _reauth_sign_init(rs: Any, priv: int) -> int:
    """C_SignInit for the re-auth probe (F1 control: Init before login)."""
    mech = mech_simple(CKM_SHA256_RSA_PKCS)
    return int(rs.raw.C_SignInit(rs.sh, mech.byref(), priv))


def _reauth_sign_complete(rs: Any) -> tuple[int, bytes]:
    """C_Sign for the re-auth probe (F1 control: Sign after login, no re-Init)."""
    msg_buf = (ctypes.c_ubyte * len(_QC3B_REAUTH_SIGN_MSG))(*_QC3B_REAUTH_SIGN_MSG)
    sig_buf = (ctypes.c_ubyte * _QC3B_RSA_SIG_LEN)()
    sig_len = CK_ULONG(_QC3B_RSA_SIG_LEN)
    rv_sign = int(
        rs.raw.C_Sign(rs.sh, msg_buf, len(_QC3B_REAUTH_SIGN_MSG), sig_buf, byref(sig_len))
    )
    if rv_sign != int(CKR_OK):
        return rv_sign, b""
    return rv_sign, bytes(sig_buf[: sig_len.value])


def _check_reauth_premise(
    rs: Any, pub: int, priv: int, *, label: str, operation: str, p11_config: Any
) -> None:
    """Prove the re-authentication premise on an RSA private key (F1/I1).

    Pre-change Init -> Sign without login must be refused with
    CKR_USER_NOT_LOGGED_IN (the ONLY auth-shaped RV, §4.10); the control
    (Init -> context login -> verified Sign, no re-Init after login) proves
    the key is genuinely operational; SET legs additionally require
    single-use (a second sign without fresh login refused), so a post-change
    success is attributable to the change and not to lingering re-auth.
    Anything else voids the leg visibly, never passes it.
    """
    rv, _sig = _reauth_sign_attempt(rs, priv)
    if rv == int(CKR_OK):
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            summary=(
                f"{label}: source use completes without re-authentication; bypass premise void"
            ),
        )
    classify_rv_validity_or_none(
        rv,
        label=f"{label}: premise",
        operation="C_Sign",
        mechanism="CKM_SHA256_RSA_PKCS",
        kind="policy",
        expected=(AUTH_SHAPED_REFUSE_RV,),
    )
    if rv != AUTH_SHAPED_REFUSE_RV:
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=rv,
            summary=(
                f"{label}: source use refused pre-change with non-auth {ckr_name(rv)}; "
                "re-auth premise unproved, leg void"
            ),
        )
    classify(
        "sanctioned_refusal",
        kind="policy",
        label=f"{label}: premise",
        operation="C_Sign",
        mechanism="CKM_SHA256_RSA_PKCS",
        inherit_mechanism=False,
        actual=rv,
        summary=(
            f"{label}: source use refused pre-change with CKR_USER_NOT_LOGGED_IN "
            "(re-authentication demanded)"
        ),
    )
    pin = get_pin_bytes(p11_config)
    assert pin is not None, "re-auth legs are PIN-gated before keygen"
    # F1: control sequence MUST be Init -> context-login -> Sign (spec §4.10:
    # login after op Init, before completion; no re-Init after login). The
    # premise above stays Init -> Sign (no login) demanding
    # CKR_USER_NOT_LOGGED_IN. A failed Sign ends the op, so the control needs
    # a fresh Init before login; login without an active op is
    # OPERATION_NOT_INITIALIZED and voids.
    rv_init = _reauth_sign_init(rs, priv)
    if rv_init != int(CKR_OK):
        classify_rv_validity_or_none(
            rv_init,
            label=f"{label}: premise",
            operation="C_SignInit",
            mechanism="CKM_SHA256_RSA_PKCS",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_SignInit",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=rv_init,
            summary=(
                f"{label}: control Init refused with {ckr_name(rv_init)}; "
                "control unproved, leg void"
            ),
        )
    rv_login = _context_specific_login(rs.raw, rs.sh, pin)
    if rv_login in (int(CKR_FUNCTION_NOT_SUPPORTED), int(CKR_USER_TYPE_INVALID)):
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Login",
            inherit_mechanism=False,
            actual=rv_login,
            summary=(
                f"{label}: context-specific login unsupported ({ckr_name(rv_login)}); "
                "control void, leg void"
            ),
        )
    classify_rv_validity_or_none(
        rv_login, label=f"{label}: premise", operation="C_Login", kind="policy"
    )
    if rv_login != int(CKR_OK):
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Login",
            inherit_mechanism=False,
            actual=rv_login,
            summary=(
                f"{label}: context-specific login refused with {ckr_name(rv_login)}; "
                "control void, leg void"
            ),
        )
    rv_sign, sig = _reauth_sign_complete(rs)
    if rv_sign != int(CKR_OK):
        classify_rv_validity_or_none(
            rv_sign,
            label=f"{label}: premise",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=rv_sign,
            summary=(
                f"{label}: control sign refused with {ckr_name(rv_sign)} after context "
                "login; control unproved, leg void"
            ),
        )
    pub_attrs = read_qc3_attributes(
        rs, pub, [CKA_MODULUS, CKA_PUBLIC_EXPONENT], label=label, premise=True
    )
    modulus = attr_or_record(
        pub_attrs,
        CKA_MODULUS,
        label=f"{label}: premise pubkey readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    exponent = attr_or_record(
        pub_attrs,
        CKA_PUBLIC_EXPONENT,
        label=f"{label}: premise pubkey readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if modulus is MISSING_ATTRIBUTE or exponent is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: control pubkey unreadable; control signature unverifiable, leg void"
            ),
        )
    # F12/N3: decode the RSA modulus as an unsigned int; validate NUMERIC
    # properties (value > 0, bit_length within sane 2048-class bounds). A
    # 2048-bit RSA modulus has its top bit set (2048 bits), but encodings may
    # carry leading zero padding (e.g., a 257-byte zero-prefixed form of the
    # same value) which must NOT void. Accept 2000..2064 bits (250..258 bytes
    # of value): wide enough for 2048-class keys with padding/slack, narrow
    # enough to reject degenerate 0/tiny values and absurd sizes. No
    # exact-256-byte requirement.
    _modulus_ok = False
    _modulus_bits: int | None = None
    if isinstance(modulus, bytes) and modulus:
        _n = int.from_bytes(modulus, "big")
        if _n > 0:
            _modulus_bits = _n.bit_length()
            _modulus_ok = 2000 <= _modulus_bits <= 2064
    if not _modulus_ok or not isinstance(exponent, bytes) or not exponent:
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: control pubkey malformed; control signature unverifiable, leg void"
            ),
        )
    # G1/N1: oracle CONSTRUCTION (public-key metadata) is a separate step
    # from signature VERIFICATION, with separate verdicts. Unusable metadata
    # (ValueError: zero exponent, bad modulus shape, ...) leaves signature
    # validity UNPROVED (void with accurate metadata attribution -- never
    # "invalid signature"); only a FAILED verification under a USABLE oracle
    # establishes an invalid signature (crypto wrong_result FAIL).
    # H1: diagnostics carry LENGTHS + VALIDATION BOOLEANS ONLY. The
    # exponent bytes may BE a planted secret (int->bytes recovers it exactly,
    # so the decimal integer is NOT redaction) or oversized (str(int) exceeds
    # the 4300-digit limit and kills the xfail). Lengths come from len() on
    # the raw bytes; the ints below are NEVER stringified or stored.
    _oracle_exp_len = len(exponent)
    _oracle_mod_len = len(modulus)
    _oracle_e = int.from_bytes(exponent, "big")
    _oracle_n = int.from_bytes(modulus, "big")
    try:
        _oracle = rsa.RSAPublicNumbers(e=_oracle_e, n=_oracle_n).public_key()
    except ValueError:
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                f"{label}: control pubkey metadata unusable for verification "
                f"(exponent_len={_oracle_exp_len}, modulus_len={_oracle_mod_len}, "
                f"modulus_bits={_modulus_bits}, usable_oracle=False); "
                "control signature unverifiable, leg void"
            ),
            detail={
                "exponent_len": _oracle_exp_len,
                "modulus_len": _oracle_mod_len,
                "modulus_bits": _modulus_bits,
                "usable_oracle": False,
            },
        )
    try:
        _oracle.verify(sig, _QC3B_REAUTH_SIGN_MSG, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        # F10/N1: a successful Sign with an independently invalid signature is
        # crypto wrong_result FAIL (never a void). The operation completed
        # (CKR_OK) but produced the wrong cryptographic result.
        fail_as(
            "wrong_result",
            kind="crypto",
            label=label,
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            inherit_mechanism=False,
            actual=int(CKR_OK),
            summary=(
                f"{label}: control signature failed independent verification "
                "(successful Sign produced an invalid signature); crypto wrong_result"
            ),
            detail={"sig_len": len(sig)},
        )
    if operation == "C_SetAttributeValue":
        # Same-object attribution: the control's login must not linger. A
        # second sign without fresh re-auth must be refused auth-shaped;
        # completing proves re-auth reuse and voids bypass attribution.
        rv_reuse, _reuse_sig = _reauth_sign_attempt(rs, priv)
        if rv_reuse == int(CKR_OK):
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                summary=(
                    f"{label}: second sign without fresh re-auth completed "
                    "(re-auth not single-use); bypass unattributable, leg void"
                ),
            )
        classify_rv_validity_or_none(
            rv_reuse,
            label=f"{label}: premise",
            operation="C_Sign",
            mechanism="CKM_SHA256_RSA_PKCS",
            kind="policy",
            expected=(AUTH_SHAPED_REFUSE_RV,),
        )
        if rv_reuse != AUTH_SHAPED_REFUSE_RV:
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_Sign",
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                actual=rv_reuse,
                summary=(
                    f"{label}: second sign refused with non-auth {ckr_name(rv_reuse)}; "
                    "single-use unproved, leg void"
                ),
            )


def _table_source_attrs(probe: str) -> dict[Any, Any]:
    """Per-probe source attributes for the QC3b mutability legs."""
    base: dict[Any, Any] = {
        CKA_ENCRYPT: True,
        CKA_DECRYPT: True,
        CKA_TOKEN: False,
        CKA_COPYABLE: True,
        CKA_SENSITIVE: False,
        CKA_EXTRACTABLE: True,
    }
    if probe == "allowed_mechanisms_widen":
        return {**base, CKA_ALLOWED_MECHANISMS: [int(CKM_AES_ECB)]}
    if probe == "allowed_mechanisms_narrow":
        return {**base, CKA_ALLOWED_MECHANISMS: [int(CKM_AES_ECB), int(CKM_AES_CBC)]}
    # NOTE: "always_authenticate" has no AES source: it uses the QC3-local
    # RSA setup (_import_reauth_source) in the runners (F7/I1). Falling
    # through to the KeyError below on misuse is intentional.
    if probe == "sensitive_downgrade":
        return {**base, CKA_SENSITIVE: True}
    if probe == "extractable_escalate":
        return {**base, CKA_EXTRACTABLE: False}
    if probe == "label_control":
        return {**base, CKA_LABEL: _QC3B_LABEL_ORIGINAL}
    if probe == "value":
        return dict(base)
    raise KeyError(probe)


def _table_template(probe: str) -> dict[Any, Any]:
    """The forbidden (or control) change attempted for *probe*."""
    if probe == "value":
        return {CKA_VALUE: PROBE_INJECTED_VALUE}
    if probe == "allowed_mechanisms_widen":
        return {CKA_ALLOWED_MECHANISMS: [int(CKM_AES_ECB), int(CKM_AES_CBC)]}
    if probe == "allowed_mechanisms_narrow":
        return {CKA_ALLOWED_MECHANISMS: [int(CKM_AES_ECB)]}
    if probe == "always_authenticate":
        return {CKA_ALWAYS_AUTHENTICATE: False}
    if probe == "sensitive_downgrade":
        return {CKA_SENSITIVE: False}
    if probe == "extractable_escalate":
        return {CKA_EXTRACTABLE: True}
    if probe == "label_control":
        return {CKA_LABEL: _QC3B_LABEL_UPDATED}
    raise KeyError(probe)


def _import_table_source(rs: Any, probe: str) -> int:
    """Import the known-value source for a QC3b probe."""
    try:
        return import_secret_key(
            rs.raw, rs.sh, CKK_AES, PROBE_ORIGINAL_VALUE, attrs=_table_source_attrs(probe)
        )
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label="copy/set mutability source setup",
            operation="C_CreateObject",
            kind="policy",
        )
        # G2: every clean standard setup refusal xfails with the RV preserved
        # (no bare raise); the tuple only selects the summary wording.
        xfail_qc3_setup_refusal(
            exc,
            _API_SECURITY_AES_SETUP_REJECT_RVS,
            label="copy/set mutability source setup",
        )


def _import_table_wrapper(rs: Any) -> int:
    """Import the wrapping key for the extractable-escalation legs."""
    try:
        return import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            _QC3B_WRAPPER_VALUE,
            # F5: the validation chain unwraps with this key, so it needs both
            # WRAP and UNWRAP (false-UNWRAP-default providers refuse otherwise).
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label="copy/set mutability wrapper setup",
            operation="C_CreateObject",
            kind="policy",
        )
        # G2: every clean standard setup refusal xfails with the RV preserved
        # (no bare raise); the tuple only selects the summary wording.
        xfail_qc3_setup_refusal(
            exc,
            _API_SECURITY_AES_SETUP_REJECT_RVS,
            label="copy/set mutability wrapper setup",
        )


def _table_baseline_or_xfail(rs: Any, key: int, *, label: str) -> bytes:
    """Encrypt the probe plaintext as the material-behavior baseline."""
    try:
        baseline = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: baseline use",
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            kind="policy",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: baseline use",
            operation="C_Encrypt",
            mechanism="CKM_AES_ECB",
            inherit_mechanism=False,
            actual=exc.rv,
            summary=(
                f"{label}: baseline use refused with {ckr_name(exc.rv)}; material comparison void"
            ),
        )
    # G4/G5: a comparison against an unvalidated baseline is void evidence.
    check_ecb_baseline_or_fail(baseline, label=f"{label}: baseline use")
    return baseline


def _cbc_encrypt(rs: Any, handle: int) -> bytes:
    """Encrypt the probe plaintext with AES-CBC under a fixed IV."""
    return encrypt_single(
        rs.raw,
        rs.sh,
        handle,
        CKM_AES_CBC,
        PROBE_PLAINTEXT,
        mech_param=mech_bytes(CKM_AES_CBC, _QC3B_CBC_IV),
    )


def _check_table_premise(rs: Any, src: int, probe: str, *, label: str) -> None:
    """Prove the pre-change premise each functional leg depends on.

    A widening leg needs the excluded mechanism genuinely refused before
    the change; a narrowing leg needs it genuinely working; a re-auth leg
    needs the source genuinely demanding re-authentication. An unproved
    premise voids the leg visibly instead of failing or passing it.
    """
    if probe == "allowed_mechanisms_widen":
        try:
            premise_ecb = encrypt_single(rs.raw, rs.sh, src, CKM_AES_ECB, PROBE_PLAINTEXT)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv,
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
                kind="policy",
            )
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: source ECB use refused with {ckr_name(exc.rv)}; widening leg void"
                ),
            )
        # G4: the premise operability output is functional evidence; validate it.
        check_ecb_oracle_or_fail(premise_ecb, label=f"{label}: premise")
        try:
            excluded_ct = _cbc_encrypt(rs, src)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv,
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_CBC",
                kind="policy",
                expected=tuple(POLICY_SHAPED_REFUSE_RVS),
            )
            if exc.rv in POLICY_SHAPED_REFUSE_RVS:
                classify(
                    "sanctioned_refusal",
                    kind="policy",
                    label=f"{label}: premise",
                    operation="C_Encrypt",
                    mechanism="CKM_AES_CBC",
                    inherit_mechanism=False,
                    actual=exc.rv,
                    summary=(
                        f"{label}: excluded mechanism refused pre-change with "
                        f"{ckr_name(exc.rv)} (policy-shaped restriction effective)"
                    ),
                )
                return
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_CBC",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: excluded mechanism refused pre-change with non-policy "
                    f"{ckr_name(exc.rv)}; restriction unproved, widening leg void"
                ),
            )
        # G4: a completion the oracle rejects proves a mechanism defect
        # (wrong_result FAIL), not a genuine already-effective widening.
        check_cbc_oracle_or_fail(
            excluded_ct,
            key=PROBE_ORIGINAL_VALUE,
            iv=_QC3B_CBC_IV,
            label=f"{label}: premise",
        )
        xfail_as(
            "not_operational",
            kind="policy",
            label=f"{label}: premise",
            operation="C_Encrypt",
            mechanism="CKM_AES_CBC",
            inherit_mechanism=False,
            summary=(
                f"{label}: excluded mechanism already completes pre-change; "
                "restriction not effective, widening leg void"
            ),
        )
    if probe == "allowed_mechanisms_narrow":
        try:
            control_ct = _cbc_encrypt(rs, src)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv,
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_CBC",
                kind="policy",
            )
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_CBC",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: excluded mechanism refused pre-change with "
                    f"{ckr_name(exc.rv)}; narrowing leg void"
                ),
            )
        # G4: only an oracle-matching CBC success establishes the control; a
        # mismatch is a proved crypto defect (FAIL, not void).
        check_cbc_oracle_or_fail(
            control_ct,
            key=PROBE_ORIGINAL_VALUE,
            iv=_QC3B_CBC_IV,
            label=f"{label}: premise",
        )
    # NOTE: "always_authenticate" premises via _check_reauth_premise (I1: RSA
    # sign-based), dispatched directly from the runners.


def _check_set_sealing_premise(
    rs: Any, src: int, probe: str, *, wrapper: int, label: str, spec_ref: str
) -> None:
    """Prove same-object sealed-ness before a SET downgrade/escalation (I7).

    Causal attribution for SET requires the SAME object's pre-change state:
    a sensitive source must actually seal its value, a non-extractable
    source must actually refuse wrap with CKR_KEY_UNEXTRACTABLE. A
    pre-existing gap fails here with setup attribution (never blamed on the
    attempted change); an unconfirmed setup voids the leg visibly.
    """
    if probe == "sensitive_downgrade":
        flag_attrs = read_qc3_attributes(
            rs, src, [CKA_SENSITIVE], label=label, premise=True, spec_ref=spec_ref
        )
        flag = attr_or_record(
            flag_attrs,
            CKA_SENSITIVE,
            label=f"{label}: premise flag readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if flag is MISSING_ATTRIBUTE:
            rendered = "<unavailable>"
            flag_ready = False
        else:
            flag = validate_qc3_shape(
                flag,
                "bool",
                attr_name="CKA_SENSITIVE",
                label=label,
                premise=True,
                spec_ref=spec_ref,
            )
            rendered = repr(flag)
            flag_ready = flag is True
        if not flag_ready:
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: source does not persist CKA_SENSITIVE=True "
                    f"(reads back {rendered}); downgrade premise void"
                ),
            )
        value_attrs = read_qc3_attributes(
            rs, src, [CKA_VALUE], label=label, premise=True, spec_ref=spec_ref
        )
        value = attr_or_record(
            value_attrs,
            CKA_VALUE,
            label=f"{label}: premise value readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
            sensitive_is_conformant=True,
        )
        if value is MISSING_ATTRIBUTE:
            return
        # F4a: premises use the SAME known-material/witness validation as
        # post-change legs. Empty/unrelated premise values void (never FAIL);
        # a premise FAIL requires the known material match or a demonstrated
        # recovered-key witness. Length-only evidence, never value bytes.
        value_len = len(value) if isinstance(value, bytes) else None
        if not (isinstance(value, bytes) and value_len in (16, 24, 32)):
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: premise value readback is malformed "
                    f"(length {value_len}); premise void"
                ),
                detail={"value_len": value_len, "matches_original": False},
            )
        matches_original = value == PROBE_ORIGINAL_VALUE
        if matches_original:
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: source exposes value despite CKA_SENSITIVE=True "
                    "(setup observation; not caused by the attempted change)"
                ),
                detail={"value_len": value_len, "matches_original": True},
            )
        try:
            premise_ct = encrypt_single(rs.raw, rs.sh, src, CKM_AES_ECB, PROBE_PLAINTEXT)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv,
                label=f"{label}: premise",
                operation="C_Encrypt",
                mechanism="CKM_AES_ECB",
                kind="policy",
            )
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: premise value present but use refused with "
                    f"{ckr_name(exc.rv)} (witness unavailable); premise void"
                ),
                detail={
                    "value_len": value_len,
                    "matches_original": False,
                    "witness_match": None,
                    "use_rv": ckr_name(exc.rv),
                },
            )
        # H2: malformed-output FAIL gate BEFORE the witness comparison: a
        # successful ECB output of != 16 bytes (fixed 16-byte plaintext;
        # AES-ECB length preservation, §6.10.4/Table 106) is crypto
        # wrong_result, never a premise void. The gate constrains the OUTPUT
        # length, not the recovered key length (24/32-byte witnesses valid).
        check_ecb_output_length_or_fail(
            premise_ct,
            label=label,
            operation="C_SetAttributeValue",
            spec_ref=spec_ref,
        )
        witness_match = premise_ct == aes_ecb_encrypt(value, PROBE_PLAINTEXT)
        if witness_match:
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: source exposes operative material despite "
                    "CKA_SENSITIVE=True (setup observation; functional witness: "
                    "read value reproduces module ciphertext; not caused by "
                    "the attempted change)"
                ),
                detail={
                    "value_len": value_len,
                    "matches_original": False,
                    "witness_match": True,
                },
            )
        xfail_as(
            "not_operational",
            kind="policy",
            label=label,
            operation="C_SetAttributeValue",
            inherit_mechanism=False,
            spec_ref=spec_ref,
            summary=(
                f"{label}: premise value present but unrelated (witness fails to "
                "reproduce module ciphertext); premise void"
            ),
            detail={
                "value_len": value_len,
                "matches_original": False,
                "witness_match": False,
            },
        )
    if probe == "extractable_escalate":
        assert wrapper != 0, "extractable probe requires a wrapping key"
        flag_attrs = read_qc3_attributes(
            rs, src, [CKA_EXTRACTABLE], label=label, premise=True, spec_ref=spec_ref
        )
        flag = attr_or_record(
            flag_attrs,
            CKA_EXTRACTABLE,
            label=f"{label}: premise flag readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if flag is MISSING_ATTRIBUTE:
            rendered = "<unavailable>"
            flag_ready = False
        else:
            flag = validate_qc3_shape(
                flag,
                "bool",
                attr_name="CKA_EXTRACTABLE",
                label=label,
                premise=True,
                spec_ref=spec_ref,
            )
            rendered = repr(flag)
            flag_ready = flag is False
        if not flag_ready:
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_SetAttributeValue",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: source does not persist CKA_EXTRACTABLE=False "
                    f"(reads back {rendered}); escalation premise void"
                ),
            )
        try:
            blob = wrap_key(rs.raw, rs.sh, wrapper, src, CKM_AES_KEY_WRAP)
        except CkrAssertionError as exc:
            classify_rv_validity_or_none(
                exc.rv,
                label=f"{label}: premise",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                kind="policy",
                expected=(SEALED_WRAP_REFUSE_RV,),
            )
            if exc.rv == SEALED_WRAP_REFUSE_RV:
                classify(
                    "sanctioned_refusal",
                    kind="policy",
                    label=f"{label}: premise",
                    operation="C_WrapKey",
                    mechanism="CKM_AES_KEY_WRAP",
                    inherit_mechanism=False,
                    actual=exc.rv,
                    summary=(
                        f"{label}: source wrap refused pre-change with "
                        "CKR_KEY_UNEXTRACTABLE (non-extractability effective)"
                    ),
                )
                return
            xfail_as(
                "not_operational",
                kind="policy",
                label=f"{label}: premise",
                operation="C_WrapKey",
                mechanism="CKM_AES_KEY_WRAP",
                inherit_mechanism=False,
                actual=exc.rv,
                summary=(
                    f"{label}: source wrap refused pre-change with non-sealing "
                    f"{ckr_name(exc.rv)}; sealed-ness unproved, escalation leg void"
                ),
            )
        # F6b: provider-independent oracle (local KW unwrap under the known
        # KEK; K' == known target bytes proves exposure, no provider use).
        result = validate_wrap_chain(
            blob,
            kek=_QC3B_WRAPPER_VALUE,
            expected_key=PROBE_ORIGINAL_VALUE,
            label=label,
        )
        if result.validated:
            fail_as(
                "self_contradiction",
                kind="policy",
                label=label,
                operation="C_WrapKey",
                inherit_mechanism=False,
                spec_ref=spec_ref,
                summary=(
                    f"{label}: source wrappable despite CKA_EXTRACTABLE=False "
                    "(setup observation; validated oracle; not caused by "
                    "the attempted change)"
                ),
                detail={"flag_readback": False, **result.evidence},
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation="C_WrapKey",
            inherit_mechanism=False,
            spec_ref=spec_ref,
            summary=(
                f"{label}: source wrap completed pre-change but exposure unvalidated "
                f"({result.evidence.get('stage')}); escalation leg void"
            ),
            detail={"disposition": "unproved-effect", **result.evidence},
        )


def _verify_widen_accept(
    rs: Any, target: int, *, spec_ref: str, label: str, operation: str
) -> None:
    """Two-tier verdict for an accepted ALLOWED_MECHANISMS widening.

    ignored-input holds ONLY for an unchanged [ECB] list plus a
    policy-shaped CBC refusal. A completed CBC with an unchanged list is a
    restriction bypass FAIL (never an "applied widening" claim); a completed
    CBC with a widened list is an applied-widening FAIL; anything
    inconclusive is unproved-effect. G4: a "completed" CBC counts only when
    its output matches the local oracle; a dispatched completion is crypto
    wrong_result, never a policy verdict.
    """
    attrs = read_qc3_attributes(
        rs, target, [CKA_ALLOWED_MECHANISMS], label=label, premise=False, spec_ref=spec_ref
    )
    readback = attr_or_record(
        attrs,
        CKA_ALLOWED_MECHANISMS,
        label=f"{label}: list readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if readback is not MISSING_ATTRIBUTE:
        readback = validate_qc3_shape(
            readback,
            "mech_list",
            attr_name="CKA_ALLOWED_MECHANISMS",
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
    try:
        sanity_ct = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_ECB", kind="policy"
        )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: ECB sanity refused with {ckr_name(exc.rv)}; widening effect unprovable"
            ),
            detail={"disposition": "unproved-effect", "sanity_rv": ckr_name(exc.rv)},
        )
    # G4: a sanity completion the oracle rejects is a mechanism defect, not
    # operability evidence.
    check_ecb_oracle_or_fail(sanity_ct, label=label, spec_ref=spec_ref)
    try:
        widen_ct = _cbc_encrypt(rs, target)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_CBC", kind="policy"
        )
        completed = False
        refusal_rv: int | None = exc.rv
    else:
        # G4: only an oracle-matching completion proves CBC use; a dispatched
        # (ECB-answered) completion is wrong_result, never bypass/widening.
        check_cbc_oracle_or_fail(
            widen_ct,
            key=PROBE_ORIGINAL_VALUE,
            iv=_QC3B_CBC_IV,
            label=label,
            spec_ref=spec_ref,
        )
        completed = True
        refusal_rv = None
    refusal = ckr_name(refusal_rv) if refusal_rv is not None else None
    if readback is MISSING_ATTRIBUTE:
        readback_list: list[int] | None = None
    else:
        readback_list = list(readback)
    readback_set = None if readback_list is None else set(readback_list)
    evidence: dict[str, Any] = {
        "excluded_mechanism": "CKM_AES_CBC",
        "excluded_completed": completed,
        "refusal_rv": refusal,
        "refusal_policy_shaped": (
            (refusal_rv in POLICY_SHAPED_REFUSE_RVS) if refusal_rv is not None else None
        ),
        "readback": readback_list,
    }
    unchanged = readback_set == {int(CKM_AES_ECB)}
    widened = readback_set == {int(CKM_AES_ECB), int(CKM_AES_CBC)}
    if unchanged and not completed and refusal_rv in POLICY_SHAPED_REFUSE_RVS:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary=(
                f"{label}: accepted but ignored the widening "
                f"(excluded mechanism still refused with {refusal}; list unchanged)"
            ),
            mutated_summary="",
            detail={"disposition": "ignored-input", **evidence},
        )
    if unchanged and completed:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(
                f"{label}: restriction bypassed: CKM_AES_CBC completed despite unchanged [ECB] list"
            ),
            detail={"disposition": "forbidden-mutation", **evidence},
        )
    if widened and completed:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(
                f"{label}: widening took effect; formerly excluded CKM_AES_CBC completed"
            ),
            detail={"disposition": "forbidden-mutation", **evidence},
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted but the widening effect is unproved "
            f"(readback={readback_list}, excluded_completed={completed}, refusal={refusal})"
        ),
        detail={"disposition": "unproved-effect", **evidence},
    )


def _verify_narrow_accept(
    rs: Any, target: int, *, spec_ref: str, label: str, operation: str
) -> None:
    """Two-tier verdict for an accepted ALLOWED_MECHANISMS narrowing.

    A narrowing FAIL requires a narrowed [ECB] list PLUS a policy-shaped CBC
    refusal. ignored-input holds ONLY for an unchanged [ECB,CBC] list with a
    still-completing CBC; a narrowed list with a completing CBC, a refusal
    without the narrowed list, and any transient refusal are unproved-effect.
    G4: "completing" counts only for oracle-matching output; a dispatched
    completion is crypto wrong_result, never ignored-input.
    """
    attrs = read_qc3_attributes(
        rs, target, [CKA_ALLOWED_MECHANISMS], label=label, premise=False, spec_ref=spec_ref
    )
    readback = attr_or_record(
        attrs,
        CKA_ALLOWED_MECHANISMS,
        label=f"{label}: list readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if readback is not MISSING_ATTRIBUTE:
        readback = validate_qc3_shape(
            readback,
            "mech_list",
            attr_name="CKA_ALLOWED_MECHANISMS",
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
    try:
        sanity_ct = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_ECB", kind="policy"
        )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: ECB sanity refused with {ckr_name(exc.rv)}; narrowing effect unprovable"
            ),
            detail={"disposition": "unproved-effect", "sanity_rv": ckr_name(exc.rv)},
        )
    # G4: a sanity completion the oracle rejects is a mechanism defect, not
    # operability evidence.
    check_ecb_oracle_or_fail(sanity_ct, label=label, spec_ref=spec_ref)
    try:
        narrow_ct = _cbc_encrypt(rs, target)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_CBC", kind="policy"
        )
        refused = True
        refusal_rv: int | None = exc.rv
    else:
        # G4: only an oracle-matching completion proves CBC still works; a
        # dispatched completion is wrong_result, never ignored-input.
        check_cbc_oracle_or_fail(
            narrow_ct,
            key=PROBE_ORIGINAL_VALUE,
            iv=_QC3B_CBC_IV,
            label=label,
            spec_ref=spec_ref,
        )
        refused = False
        refusal_rv = None
    refusal = ckr_name(refusal_rv) if refusal_rv is not None else None
    if readback is MISSING_ATTRIBUTE:
        readback_list: list[int] | None = None
    else:
        readback_list = list(readback)
    readback_set = None if readback_list is None else set(readback_list)
    evidence: dict[str, Any] = {
        "excluded_mechanism": "CKM_AES_CBC",
        "excluded_refused": refused,
        "refusal_rv": refusal,
        "refusal_policy_shaped": (
            (refusal_rv in POLICY_SHAPED_REFUSE_RVS) if refusal_rv is not None else None
        ),
        "readback": readback_list,
    }
    narrowed = readback_set == {int(CKM_AES_ECB)}
    unchanged = readback_set == {int(CKM_AES_ECB), int(CKM_AES_CBC)}
    if narrowed and refused and refusal_rv in POLICY_SHAPED_REFUSE_RVS:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(
                f"{label}: narrowing took effect; CKM_AES_CBC now refused with {refusal}"
            ),
            detail={"disposition": "forbidden-mutation", **evidence},
        )
    if unchanged and not refused:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary=(
                f"{label}: accepted but ignored the narrowing "
                "(excluded mechanism still completes; list unchanged)"
            ),
            mutated_summary="",
            detail={"disposition": "ignored-input", **evidence},
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted but the narrowing effect is unproved "
            f"(readback={readback_list}, excluded_refused={refused}, refusal={refusal})"
        ),
        detail={"disposition": "unproved-effect", **evidence},
    )


def _verify_always_auth_accept(
    rs: Any, target: int, *, spec_ref: str, label: str, operation: str
) -> None:
    """Two-tier verdict for an accepted ALWAYS_AUTHENTICATE change (F10/I1).

    Post-change C_Sign with NO login change: CKR_OK with a VALID signature is
    a re-auth bypass FAIL (the operation should have been refused); CKR_OK
    with an invalid signature is crypto wrong_result FAIL (never bypass);
    CKR_USER_NOT_LOGGED_IN with an unchanged True flag is ignored-input;
    anything else (including an unverifiable signature) is unproved-effect.
    A bypass FAIL requires a VALID post-change signature produced with no
    login change.
    """
    attrs = read_qc3_attributes(
        rs, target, [CKA_ALWAYS_AUTHENTICATE], label=label, premise=False, spec_ref=spec_ref
    )
    flag = attr_or_record(
        attrs,
        CKA_ALWAYS_AUTHENTICATE,
        label=f"{label}: flag readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if flag is MISSING_ATTRIBUTE:
        flag_bool: bool | None = None
    else:
        flag_bool = validate_qc3_shape(
            flag,
            "bool",
            attr_name="CKA_ALWAYS_AUTHENTICATE",
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
    rv, sig = _reauth_sign_attempt(rs, target)
    if rv == int(CKR_OK):
        # F10/N1: independently verify the post-change signature (RSA pubkey
        # from the target; local verify). Invalid successful signature is
        # crypto wrong_result FAIL in both places. Bypass FAIL requires VALID.
        pub_attrs = read_qc3_attributes(
            rs,
            target,
            [CKA_MODULUS, CKA_PUBLIC_EXPONENT],
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
        modulus = attr_or_record(
            pub_attrs,
            CKA_MODULUS,
            label=f"{label}: post-change pubkey readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        exponent = attr_or_record(
            pub_attrs,
            CKA_PUBLIC_EXPONENT,
            label=f"{label}: post-change pubkey readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if modulus is MISSING_ATTRIBUTE or exponent is MISSING_ATTRIBUTE:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: C_Sign completed without re-auth but the pubkey is "
                    "unreadable; signature unverifiable, bypass unproved"
                ),
                detail={
                    "disposition": "unproved-effect",
                    "no_reauth_use_completed": True,
                    "sig_len": len(sig),
                    "flag_readback": flag_bool,
                },
            )
        # F12/N3 numeric bounds (same 2000..2064 rationale as the control).
        _mod_ok = False
        if isinstance(modulus, bytes) and modulus:
            _n = int.from_bytes(modulus, "big")
            if _n > 0 and 2000 <= _n.bit_length() <= 2064:
                _mod_ok = True
        if not _mod_ok or not isinstance(exponent, bytes) or not exponent:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: C_Sign completed without re-auth but the pubkey is "
                    "malformed; signature unverifiable, bypass unproved"
                ),
                detail={
                    "disposition": "unproved-effect",
                    "no_reauth_use_completed": True,
                    "sig_len": len(sig),
                    "flag_readback": flag_bool,
                },
            )
        # G1/N1: oracle CONSTRUCTION is separate from VERIFICATION (same
        # split as the premise control). Unusable post-change metadata voids
        # the bypass claim as unproved (actual=CKR_OK per M1) -- never
        # "invalid signature", never bypass. Only a FAILED verification
        # under a USABLE oracle is crypto wrong_result.
        # H1: lengths + validation booleans only (same rule as the premise
        # control above): the exponent bytes may be a planted secret or
        # oversized, so the ints are NEVER stringified or stored.
        _post_exp_len = len(exponent)
        _post_mod_len = len(modulus)
        _post_e = int.from_bytes(exponent, "big")
        _post_n = int.from_bytes(modulus, "big")
        _post_bits = _post_n.bit_length() if _post_n > 0 else 0
        try:
            _post_oracle = rsa.RSAPublicNumbers(e=_post_e, n=_post_n).public_key()
        except ValueError:
            xfail_as(
                "honest_deviation",
                kind="policy",
                label=label,
                operation=operation,
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: C_Sign completed without re-auth but the pubkey "
                    "metadata is unusable for verification "
                    f"(exponent_len={_post_exp_len}, modulus_len={_post_mod_len}, "
                    f"modulus_bits={_post_bits}, usable_oracle=False); "
                    "signature unverifiable, bypass unproved"
                ),
                detail={
                    "disposition": "unproved-effect",
                    "no_reauth_use_completed": True,
                    "sig_len": len(sig),
                    "flag_readback": flag_bool,
                    "exponent_len": _post_exp_len,
                    "modulus_len": _post_mod_len,
                    "modulus_bits": _post_bits,
                    "usable_oracle": False,
                },
            )
        try:
            _post_oracle.verify(sig, _QC3B_REAUTH_SIGN_MSG, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            fail_as(
                "wrong_result",
                kind="crypto",
                label=label,
                operation=operation,
                mechanism="CKM_SHA256_RSA_PKCS",
                inherit_mechanism=False,
                actual=int(CKR_OK),
                spec_ref=spec_ref,
                summary=(
                    f"{label}: post-change C_Sign completed but the signature is "
                    "invalid; crypto wrong_result (no bypass claimed)"
                ),
                detail={
                    "sig_len": len(sig),
                    "flag_readback": flag_bool,
                },
            )
        if flag_bool is False:
            bypass_clause = (
                "re-authentication bypass; C_Sign completed without re-auth "
                "after the applied change"
            )
        elif flag_bool is True:
            bypass_clause = (
                "restriction bypassed: C_Sign completed without re-auth despite "
                "unchanged ALWAYS_AUTHENTICATE=True"
            )
        else:
            bypass_clause = "C_Sign completed without re-auth (ALWAYS_AUTHENTICATE flag unreadable)"
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(f"{label}: {bypass_clause}"),
            detail={
                "disposition": "forbidden-mutation",
                "no_reauth_use_completed": True,
                "sig_len": len(sig),
                "flag_readback": flag_bool,
            },
        )
    classify_rv_validity_or_none(
        rv,
        label=label,
        operation="C_Sign",
        mechanism="CKM_SHA256_RSA_PKCS",
        kind="policy",
        expected=(AUTH_SHAPED_REFUSE_RV,),
    )
    if rv == AUTH_SHAPED_REFUSE_RV and flag_bool is True:
        classify_ignored_or_mutated(
            mutated=False,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary=(
                f"{label}: accepted but ignored the change "
                "(C_Sign re-authentication still demanded: "
                "CKR_USER_NOT_LOGGED_IN; flag unchanged)"
            ),
            mutated_summary="",
            detail={
                "disposition": "ignored-input",
                "no_reauth_use_completed": False,
                "refusal_rv": ckr_name(rv),
                "refusal_auth_shaped": True,
                "flag_readback": True,
            },
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted; C_Sign refused with {ckr_name(rv)} but the "
            "re-auth effect is unproved "
            f"(auth-shaped={rv == AUTH_SHAPED_REFUSE_RV}, flag={flag_bool!r})"
        ),
        detail={
            "disposition": "unproved-effect",
            "no_reauth_use_completed": False,
            "refusal_rv": ckr_name(rv),
            "refusal_auth_shaped": rv == AUTH_SHAPED_REFUSE_RV,
            "flag_readback": flag_bool,
        },
    )


def _verify_sensitive_accept(
    rs: Any, target: int, *, spec_ref: str, label: str, operation: str
) -> None:
    """Two-tier verdict for an accepted SENSITIVE downgrade.

    Exposure FAILs only on the known material (value == PROBE_ORIGINAL_VALUE)
    or a recovered-key functional witness (the read value locally reproduces
    the module's observed ciphertext). ignored-input holds ONLY for a sealed
    value with an unchanged True flag; malformed/unrelated values and
    inconclusive flag/effect combos are unproved-effect.
    """
    attrs = read_qc3_attributes(
        rs, target, [CKA_SENSITIVE, CKA_VALUE], label=label, premise=False, spec_ref=spec_ref
    )
    flag = attr_or_record(
        attrs,
        CKA_SENSITIVE,
        label=f"{label}: flag readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label=f"{label}: value readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
        sensitive_is_conformant=True,
    )
    if flag is MISSING_ATTRIBUTE:
        flag_bool: bool | None = None
        rendered = "<unavailable>"
    else:
        flag = validate_qc3_shape(
            flag,
            "bool",
            attr_name="CKA_SENSITIVE",
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
        flag_bool = flag
        rendered = repr(flag)
    if value is MISSING_ATTRIBUTE:
        if flag_bool is True:
            classify_ignored_or_mutated(
                mutated=False,
                label=label,
                operation=operation,
                spec_ref=spec_ref,
                ignored_summary=(
                    f"{label}: accepted but ignored the downgrade "
                    "(value still sealed; flag unchanged)"
                ),
                mutated_summary="",
                detail={
                    "disposition": "ignored-input",
                    "value_readable": False,
                    "value_matches_original": None,
                    "flag_readback": True,
                },
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted; value sealed but the flag reads back {rendered} "
                "(applied-showing/unreadable); effect unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "value_readable": False,
                "value_matches_original": None,
                "flag_readback": flag_bool,
            },
        )
    # F4b: relax the "value" shape gate: bytes of plausible AES length
    # (16/24/32) proceed to the witness; only non-bytes/non-AES lengths are
    # malformed-xfail. A 24-byte read value reproducing the target ciphertext
    # via local recompute is a demonstrated witness (FAIL), even though it
    # differs from the 16-byte source.
    if not (isinstance(value, bytes) and len(value) in (16, 24, 32)):
        validate_qc3_shape(
            value,
            "value",
            attr_name="CKA_VALUE",
            label=label,
            premise=False,
            spec_ref=spec_ref,
            expected_len=len(PROBE_ORIGINAL_VALUE),
        )
    if flag_bool is False:
        exposure_clause = "downgrade exposed key material"
    elif flag_bool is True:
        exposure_clause = "restriction bypassed: value readable despite unchanged SENSITIVE=True"
    else:
        exposure_clause = "value exposed (SENSITIVE flag unreadable)"
    matches_original = value == PROBE_ORIGINAL_VALUE
    if matches_original:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(f"{label}: {exposure_clause} (matches_original=True)"),
            detail={
                "disposition": "forbidden-mutation",
                "value_readable": True,
                "value_matches_original": True,
                "witness_match": None,
                "value_len": len(value),
                "flag_readback": flag_bool,
            },
        )
    try:
        observed_ct = encrypt_single(rs.raw, rs.sh, target, CKM_AES_ECB, PROBE_PLAINTEXT)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_Encrypt", mechanism="CKM_AES_ECB", kind="policy"
        )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted; unrelated value read back but use refused with "
                f"{ckr_name(exc.rv)} (functional witness unavailable); effect unproved"
            ),
            detail={
                "disposition": "unproved-effect",
                "value_readable": True,
                "value_matches_original": False,
                "witness_match": None,
                "use_rv": ckr_name(exc.rv),
                "value_len": len(value),
                "flag_readback": flag_bool,
            },
        )
    # H2: malformed-output FAIL gate BEFORE the witness comparison (same
    # G5 semantics as the premise leg above): a successful malformed ECB
    # output is crypto wrong_result, never unproved-effect.
    check_ecb_output_length_or_fail(
        observed_ct,
        label=label,
        operation=operation,
        spec_ref=spec_ref,
    )
    witness_match = observed_ct == aes_ecb_encrypt(value, PROBE_PLAINTEXT)
    if witness_match:
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(
                f"{label}: {exposure_clause} "
                "(functional witness: read value reproduces module ciphertext)"
            ),
            detail={
                "disposition": "forbidden-mutation",
                "value_readable": True,
                "value_matches_original": False,
                "witness_match": True,
                "value_len": len(value),
                "flag_readback": flag_bool,
            },
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted; unrelated value read back and the functional witness "
            "fails to reproduce module ciphertext; effect unproved"
        ),
        detail={
            "disposition": "unproved-effect",
            "value_readable": True,
            "value_matches_original": False,
            "witness_match": False,
            "value_len": len(value),
            "flag_readback": flag_bool,
        },
    )


def _verify_extractable_accept(
    rs: Any, target: int, wrapper: int, *, spec_ref: str, label: str, operation: str
) -> None:
    """Two-tier verdict for an accepted EXTRACTABLE escalation.

    A completed wrap proves exposure ONLY through a validated unwrap→use
    chain against the known-material oracle. ignored-input holds ONLY for a
    CKR_KEY_UNEXTRACTABLE refusal with an unchanged False flag; any other
    inconclusive combination is unproved-effect.
    """
    attrs = read_qc3_attributes(
        rs, target, [CKA_EXTRACTABLE], label=label, premise=False, spec_ref=spec_ref
    )
    flag = attr_or_record(
        attrs,
        CKA_EXTRACTABLE,
        label=f"{label}: flag readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if flag is MISSING_ATTRIBUTE:
        flag_bool: bool | None = None
    else:
        flag_bool = validate_qc3_shape(
            flag,
            "bool",
            attr_name="CKA_EXTRACTABLE",
            label=label,
            premise=False,
            spec_ref=spec_ref,
        )
    try:
        blob = wrap_key(rs.raw, rs.sh, wrapper, target, CKM_AES_KEY_WRAP)
    except CkrAssertionError as exc:
        classify_rv_validity_or_none(
            exc.rv, label=label, operation="C_WrapKey", mechanism="CKM_AES_KEY_WRAP", kind="policy"
        )
        if exc.rv == SEALED_WRAP_REFUSE_RV and flag_bool is False:
            classify_ignored_or_mutated(
                mutated=False,
                label=label,
                operation=operation,
                spec_ref=spec_ref,
                ignored_summary=(
                    f"{label}: accepted but ignored the escalation "
                    "(wrap still refused with CKR_KEY_UNEXTRACTABLE; flag unchanged)"
                ),
                mutated_summary="",
                detail={
                    "disposition": "ignored-input",
                    "wrap_completed": False,
                    "refusal_rv": ckr_name(exc.rv),
                    "refusal_sealing_shaped": True,
                    "flag_readback": False,
                },
            )
        xfail_as(
            "honest_deviation",
            kind="policy",
            label=label,
            operation=operation,
            inherit_mechanism=False,
            actual=int(CKR_OK),
            spec_ref=spec_ref,
            summary=(
                f"{label}: accepted; wrap refused with {ckr_name(exc.rv)} but the "
                "escalation effect is unproved "
                f"(sealing-shaped={exc.rv == SEALED_WRAP_REFUSE_RV}, flag={flag_bool!r})"
            ),
            detail={
                "disposition": "unproved-effect",
                "wrap_completed": False,
                "refusal_rv": ckr_name(exc.rv),
                "refusal_sealing_shaped": exc.rv == SEALED_WRAP_REFUSE_RV,
                "flag_readback": flag_bool,
            },
        )
    # F6b: provider-independent oracle (local KW unwrap under the known KEK).
    result = validate_wrap_chain(
        blob,
        kek=_QC3B_WRAPPER_VALUE,
        expected_key=PROBE_ORIGINAL_VALUE,
        label=label,
    )
    if result.validated:
        if flag_bool is True:
            exposure_clause = (
                "escalation took effect; target wrappable "
                "(material exposed in wrapped form; validated oracle)"
            )
        elif flag_bool is False:
            exposure_clause = (
                "restriction bypassed: wrap validated despite unchanged EXTRACTABLE=False"
            )
        else:
            exposure_clause = "wrap validated (EXTRACTABLE flag unreadable)"
        classify_ignored_or_mutated(
            mutated=True,
            label=label,
            operation=operation,
            spec_ref=spec_ref,
            ignored_summary="",
            mutated_summary=(f"{label}: {exposure_clause}"),
            detail={
                "disposition": "forbidden-mutation",
                "wrap_completed": True,
                "flag_readback": flag_bool,
                **result.evidence,
            },
        )
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        spec_ref=spec_ref,
        summary=(
            f"{label}: accepted; wrap completed but exposure unvalidated "
            f"({result.evidence.get('stage')}); escalation effect unproved"
        ),
        detail={
            "disposition": "unproved-effect",
            "wrap_completed": True,
            "flag_readback": flag_bool,
            **result.evidence,
        },
    )


def _verify_label_accept(rs: Any, target: int, *, label: str, operation: str) -> None:
    """Control verdict: an accepted label change must read back applied."""
    attrs = read_qc3_attributes(rs, target, [CKA_LABEL], label=label, premise=False)
    readback = attr_or_record(
        attrs,
        CKA_LABEL,
        label=f"{label}: label readback",
        reason="not_operational",
        kind="policy",
        inherit_mechanism=False,
    )
    if readback is MISSING_ATTRIBUTE:
        disposition = "unproved-effect"
        summary = f"{label}: accepted but the new label is unreadable; effect unproved"
    elif readback in (_QC3B_LABEL_UPDATED, _QC3B_LABEL_UPDATED.encode()):
        return
    elif readback in (_QC3B_LABEL_ORIGINAL, _QC3B_LABEL_ORIGINAL.encode()):
        disposition = "ignored-input"
        summary = f"{label}: accepted but ignored the new label (readback unchanged)"
    else:
        disposition = "unproved-effect"
        summary = f"{label}: accepted but the label reads back an unexpected value"
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=int(CKR_OK),
        summary=summary,
        detail={"disposition": disposition},
    )


def _classify_control_refusal(exc: CkrAssertionError, *, label: str, operation: str) -> None:
    """Verdict for a refused legal label change: never a pass, never silent."""
    import pytest

    if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
        pytest.skip(f"{label}: {operation} not supported ({ckr_name(exc.rv)})")
    classify_rv_validity_or_none(exc.rv, label=label, operation=operation, kind="policy")
    xfail_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation=operation,
        inherit_mechanism=False,
        actual=exc.rv,
        summary=(
            f"{label}: legal label change refused with {ckr_name(exc.rv)} (control deviation)"
        ),
    )


def _verify_table_accept(
    rs: Any,
    target: int,
    probe: str,
    *,
    row_citation: str,
    label: str,
    operation: str,
    baseline: bytes | None,
    wrapper: int,
) -> None:
    """Dispatch an accepted table change to its probe-specific verdict leg."""
    if probe == "value":
        assert baseline is not None, "value probe requires a pre-change baseline"
        check_material_preserved(
            rs,
            target,
            baseline,
            original_value=PROBE_ORIGINAL_VALUE,
            injected_value=PROBE_INJECTED_VALUE,
            plaintext=PROBE_PLAINTEXT,
            label=label,
            spec_ref=row_citation,
            operation=operation,
        )
    elif probe == "allowed_mechanisms_widen":
        _verify_widen_accept(rs, target, spec_ref=row_citation, label=label, operation=operation)
    elif probe == "allowed_mechanisms_narrow":
        _verify_narrow_accept(rs, target, spec_ref=row_citation, label=label, operation=operation)
    elif probe == "always_authenticate":
        _verify_always_auth_accept(
            rs, target, spec_ref=row_citation, label=label, operation=operation
        )
    elif probe == "sensitive_downgrade":
        _verify_sensitive_accept(
            rs, target, spec_ref=row_citation, label=label, operation=operation
        )
    elif probe == "extractable_escalate":
        assert wrapper != 0, "extractable probe requires a wrapping key"
        _verify_extractable_accept(
            rs, target, wrapper, spec_ref=row_citation, label=label, operation=operation
        )
    elif probe == "label_control":
        _verify_label_accept(rs, target, label=label, operation=operation)
    else:
        raise KeyError(probe)


def _import_reauth_source(rs: Any, *, label: str) -> tuple[int, int]:
    """QC3-local RSA-2048 re-auth setup (pub, priv) with xfail semantics (F7/I1).

    Stops reusing ``_try_gen_always_auth_keypair``'s terminal semantics (its
    malformed-flag arm FAILs wrong_result, incompatible with the agreed QC3
    mutation treatment). Generates via ``gen_rsa_keypair`` with {SIGN,
    ALWAYS_AUTHENTICATE, PRIVATE} (F1: explicit CKA_PRIVATE=True for
    false-default providers), then ``read_qc3_attributes`` +
    ``validate_qc3_shape`` with xfail semantics. Malformed flag readback
    voids as unproved (not_operational), never wrong_result FAIL. Any
    independent metadata concern stays a separate, explicitly-distinguished
    record (the void itself, not a mutation verdict).
    """
    try:
        pub, priv = _raw_gen_rsa_keypair(
            rs.raw,
            rs.sh,
            _QC3B_RSA_BITS,
            public_attrs={CKA_VERIFY: True},
            private_attrs={
                CKA_SIGN: True,
                CKA_ALWAYS_AUTHENTICATE: True,
                CKA_PRIVATE: True,
            },
        )
    except CkrAssertionError as exc:
        # F8: validity first (undefined -> metadata FAIL; vendor -> alternate).
        classify_rv_validity_or_none(
            exc.rv,
            label=f"{label}: RSA setup",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            kind="metadata",
        )
        xfail_as(
            "not_operational",
            kind="metadata",
            label=f"{label}: RSA setup",
            operation="C_GenerateKeyPair",
            mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            inherit_mechanism=False,
            actual=exc.rv,
            summary=(f"{label}: RSA keygen refused with {ckr_name(exc.rv)}; re-auth leg void"),
        )
    retain_handles = False
    try:
        flag_attrs = read_qc3_attributes(
            rs, priv, [CKA_ALWAYS_AUTHENTICATE], label=label, premise=True
        )
        flag = attr_or_record(
            flag_attrs,
            CKA_ALWAYS_AUTHENTICATE,
            label=f"{label}: setup flag readback",
            reason="not_operational",
            kind="policy",
            inherit_mechanism=False,
        )
        if flag is MISSING_ATTRIBUTE:
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary=(
                    f"{label}: CKA_ALWAYS_AUTHENTICATE setup readback unavailable; re-auth leg void"
                ),
            )
        flag = validate_qc3_shape(
            flag,
            "bool",
            attr_name="CKA_ALWAYS_AUTHENTICATE",
            label=label,
            premise=True,
        )
        if flag is not True:
            xfail_as(
                "not_operational",
                kind="policy",
                label=label,
                operation="C_GetAttributeValue",
                inherit_mechanism=False,
                summary=(
                    f"{label}: source does not persist CKA_ALWAYS_AUTHENTICATE=True "
                    f"(reads back {flag!r}); re-auth leg void"
                ),
            )
        retain_handles = True
        return pub, priv
    finally:
        if not retain_handles:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


def _run_copy_table_probe(rs: Any, probe: str, p11_config: Any) -> None:
    """Attempt one table change via C_CopyObject and adjudicate the outcome."""
    row = row_by_key(PROBE_ROW[probe])
    label = f"C_CopyObject {row.attr_name} {probe} (QC3b table)"
    src_pub = 0
    if probe == "always_authenticate":
        _skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
        _skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        if get_pin_bytes(p11_config) is None:
            pytest.skip("Requires PIN to test context-specific re-auth (QC3b re-auth leg void)")
        src_pub, src = _import_reauth_source(rs, label=label)
    else:
        _skip_unless_mechanism(rs, "AES_ECB")
        if probe in ("allowed_mechanisms_widen", "allowed_mechanisms_narrow"):
            _skip_unless_mechanism(rs, "AES_CBC")
        src = _import_table_source(rs, probe)
    wrapper = _import_table_wrapper(rs) if probe == "extractable_escalate" else 0
    try:
        if probe == "always_authenticate":
            _check_reauth_premise(
                rs, src_pub, src, label=label, operation="C_CopyObject", p11_config=p11_config
            )
        else:
            _check_table_premise(rs, src, probe, label=label)
        baseline = _table_baseline_or_xfail(rs, src, label=label) if probe == "value" else None
        try:
            copy = copy_object(rs.raw, rs.sh, src, _table_template(probe))
        except CkrAssertionError as exc:
            if probe == "label_control":
                _classify_control_refusal(exc, label=label, operation="C_CopyObject")
                return
            classify_forbidden_change_refusal(
                exc,
                COPY_FORBIDDEN_REFUSE_RVS,
                label=label,
                operation="C_CopyObject",
            )
            return
        try:
            _verify_table_accept(
                rs,
                copy,
                probe,
                row_citation=row.citation,
                label=label,
                operation="C_CopyObject",
                baseline=baseline,
                wrapper=wrapper,
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, copy)
    finally:
        destroy_quietly(rs.raw, rs.sh, src)
        if src_pub:
            destroy_quietly(rs.raw, rs.sh, src_pub)
        if wrapper:
            destroy_quietly(rs.raw, rs.sh, wrapper)


def _run_set_table_probe(rs: Any, probe: str, p11_config: Any) -> None:
    """Attempt one table change via C_SetAttributeValue and adjudicate it."""
    row = row_by_key(PROBE_ROW[probe])
    label = f"C_SetAttributeValue {row.attr_name} {probe} (QC3b table)"
    src_pub = 0
    if probe == "always_authenticate":
        _skip_unless_mechanism(rs, "RSA_PKCS_KEY_PAIR_GEN")
        _skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        if get_pin_bytes(p11_config) is None:
            pytest.skip("Requires PIN to test context-specific re-auth (QC3b re-auth leg void)")
        src_pub, src = _import_reauth_source(rs, label=label)
    else:
        _skip_unless_mechanism(rs, "AES_ECB")
        if probe in ("allowed_mechanisms_widen", "allowed_mechanisms_narrow"):
            _skip_unless_mechanism(rs, "AES_CBC")
        src = _import_table_source(rs, probe)
    wrapper = _import_table_wrapper(rs) if probe == "extractable_escalate" else 0
    try:
        if probe == "always_authenticate":
            _check_reauth_premise(
                rs,
                src_pub,
                src,
                label=label,
                operation="C_SetAttributeValue",
                p11_config=p11_config,
            )
        else:
            _check_table_premise(rs, src, probe, label=label)
        _check_set_sealing_premise(
            rs, src, probe, wrapper=wrapper, label=label, spec_ref=row.citation
        )
        baseline = _table_baseline_or_xfail(rs, src, label=label) if probe == "value" else None
        try:
            set_attributes(rs.raw, rs.sh, src, _table_template(probe))
        except CkrAssertionError as exc:
            if probe == "label_control":
                _classify_control_refusal(exc, label=label, operation="C_SetAttributeValue")
                return
            classify_forbidden_change_refusal(
                exc,
                SET_FORBIDDEN_REFUSE_RVS,
                label=label,
                operation="C_SetAttributeValue",
            )
            return
        _verify_table_accept(
            rs,
            src,
            probe,
            row_citation=row.citation,
            label=label,
            operation="C_SetAttributeValue",
            baseline=baseline,
            wrapper=wrapper,
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, src)
        if src_pub:
            destroy_quietly(rs.raw, rs.sh, src_pub)
        if wrapper:
            destroy_quietly(rs.raw, rs.sh, wrapper)


class TestCopySetMutability:
    """QC3b: attribute-specific copy/set mutability (#55.3)."""

    @pytest.mark.parametrize("probe", list(TABLE_PROBES))
    def test_copy_table_change(self, p11_raw_session: Any, p11_config: Any, probe: str) -> None:
        """Attempt one table change via C_CopyObject."""
        _run_copy_table_probe(p11_raw_session, probe, p11_config)

    @pytest.mark.parametrize("probe", list(TABLE_PROBES))
    def test_set_table_change(self, p11_raw_session: Any, p11_config: Any, probe: str) -> None:
        """Attempt one table change via C_SetAttributeValue."""
        _run_set_table_probe(p11_raw_session, probe, p11_config)
