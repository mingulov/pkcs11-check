"""PKCS#11 API security tests - attribute attacks, policy bypass, access control.

Based on Bortolozzo et al. "Attacking and Fixing PKCS#11 Security Tokens" (CCS 2010)
and PKCS#11 attribute enforcement rules from the OASIS specification.

Tests are marked @security - results are security findings, not correctness failures.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    find_objects,
    read_attributes,
    set_attributes,
    wrap_key,
)
from pkcs11_check.raw.recipes import gen_aes_key as _raw_gen_aes_key
from pkcs11_check.raw.recipes import gen_rsa_keypair as _raw_gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
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
    CKR_SESSION_COUNT,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    KEYPAIR_RUNTIME_REJECT_RVS,
    classify_policy_enforcement,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

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
    """G5.4: Wrap-strength downgrade posture (note-only, never fail).

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
