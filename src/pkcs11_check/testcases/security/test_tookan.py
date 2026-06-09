"""Tookan paper security vectors - conflicting key usage attributes.

Tests based on "Attacking and Fixing PKCS#11 Security Tokens" (2010).
Keys with conflicting usage flags (WRAP+DECRYPT, ENCRYPT+UNWRAP)
can allow key extraction. Modules should reject or enforce policy.

Reference: https://dl.acm.org/doi/10.1145/1866307.1866337
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    gen_aes_key,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKK_AES,
    CKK_DES3,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._negotiation import TEMPLATE_SHAPE_REJECTS
from pkcs11_check.testcases.conftest import (
    classify_discrimination,
    classify_policy_enforcement,
    is_known_error,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

_TYPE_CONFUSION_WRAP_INAPPLICABLE_RVS = {
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_NOT_WRAPPABLE,
}

# Includes the template-shape rejects as a safety net: if a module refuses the AES valid-leg
# unwrap with every negotiated template, that leg routes to xfail rather than a false fail.
# (The policy-attribute negotiation normally lets strict modules establish the valid leg.)
_TYPE_CONFUSION_WRAP_RUNTIME_REJECT_RVS = {
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    *TEMPLATE_SHAPE_REJECTS,
}

# A module that refuses to wrap a non-extractable / sensitive key with one of
# these codes is enforcing the protection the Tookan attack targets -> the
# extraction did NOT happen, so the test passes. (CKR_KEY_HANDLE_INVALID covers
# modules that internally invalidate an unwrappable target handle.)
_WRAP_EXTRACTION_PROTECTED_RVS = {
    CKR_KEY_UNEXTRACTABLE,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_HANDLE_INVALID,
    CKR_ACTION_PROHIBITED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
}

# Other clean reject codes at the wrap site -> honest non-spec deviation (the
# attack still did not succeed); routed to xfail rather than fail.
_WRAP_EXTRACTION_RUNTIME_REJECT_RVS = {
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
}


class TestConflictingUsageAttrs:
    """Tookan vector: conflicting CKA_WRAP + CKA_DECRYPT on same key."""

    def test_wrap_and_decrypt_on_same_key(self, p11_raw_session: Any) -> None:
        """Create AES key with both WRAP and DECRYPT - security risk."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_WRAP: True,
                    CKA_UNWRAP: True,
                    CKA_ENCRYPT: True,
                    CKA_DECRYPT: True,
                    CKA_EXTRACTABLE: False,
                    CKA_SENSITIVE: True,
                },
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            return  # Strict module rejects conflicting attrs - GOOD

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_WRAP + CKA_DECRYPT on same key (Tookan vector)",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper: key extraction via wrap+decrypt",
        )

    def test_encrypt_and_unwrap_on_same_key(self, p11_raw_session: Any) -> None:
        """Create key with ENCRYPT + UNWRAP - inverse Tookan vector."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_UNWRAP: True,
                },
            )
            destroy_quietly(rs.raw, rs.sh, key)
        except AssertionError:
            return  # Strict module - good

        from pkcs11_check.compliance import ComplianceLevel, note

        note(
            "Module allows CKA_ENCRYPT + CKA_UNWRAP on same key",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="Tookan paper inverse vector",
        )


class TestSensitivePreservation:
    """Verify CKA_SENSITIVE is preserved through wrap/unwrap and copy."""

    def test_sensitive_preserved_on_copy(self, p11_raw_session: Any) -> None:
        """Copying a SENSITIVE key must keep SENSITIVE=True."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            assert attrs[CKA_SENSITIVE] is True

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_LABEL: "copy-sensitive"},
                )
            except AssertionError as exc:
                exc_msg = str(exc)
                if "CKR_FUNCTION_NOT_SUPPORTED" in exc_msg:
                    return  # Copy not supported - ok
                raise
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_SENSITIVE])
                assert copy_attrs[CKA_SENSITIVE] is True, (
                    "SENSITIVE flag lost on copy - Tookan vulnerability"
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_extractable_cannot_escalate_on_copy(self, p11_raw_session: Any) -> None:
        """Copying non-EXTRACTABLE key cannot set EXTRACTABLE=True.

        OASIS PKCS#11 spec C_CopyObject section: CKA_EXTRACTABLE may be changed
        from CK_TRUE to CK_FALSE on copy, but NOT the other way around.
        This is a MUST NOT -- escalation is a security violation.
        """
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            # Type-B claim/effect-check. claimed = the original key reads back
            # CKA_EXTRACTABLE=False; violated = the copy reads back True.
            orig = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            claimed = orig.get(CKA_EXTRACTABLE) is False

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_EXTRACTABLE: True},
                )
            except AssertionError:
                return  # Correct: reject the escalation attempt

            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_EXTRACTABLE])
                violated = copy_attrs.get(CKA_EXTRACTABLE) is True
                classify_policy_enforcement(
                    claimed=claimed,
                    violated=violated,
                    label="C_CopyObject escalates CKA_EXTRACTABLE False->True "
                    "(OASIS PKCS#11 C_CopyObject: may only change True->False on copy)",
                )
            finally:
                destroy_quietly(rs.raw, rs.sh, copied)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestWrapExtraction:
    """Test that wrapping a key doesn't leak material via decrypt."""

    def test_wrap_decrypt_extraction_attempt(self, p11_raw_session: Any) -> None:
        """Attempt Tookan key extraction: wrap target, decrypt wrapped blob."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )

        # The target is created PROTECTED (non-extractable + sensitive) so that
        # any plaintext recovered from the wrapped blob is material the module
        # promised never to release -- a Type-B self-contradiction.
        target_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_EXTRACTABLE: False,
                CKA_SENSITIVE: True,
            },
        )
        try:
            # The wrap is the attacker's first step. Refusing to wrap a
            # non-extractable/sensitive key is the module CORRECTLY enforcing the
            # protection -- the Tookan extraction never gets off the ground:
            #   - CKR_KEY_UNEXTRACTABLE / NOT_WRAPPABLE / etc. -> protection
            #     worked -> pass.
            #   - any other clean reject code -> honest non-spec deviation (still
            #     no extraction) -> xfail.
            #   - CKR_OK -> the wrap succeeded; only THEN can the decrypt leg
            #     reveal key material, which is the actual Type-B violation.
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_key_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                if is_known_error(exc, _WRAP_EXTRACTION_PROTECTED_RVS):
                    return  # Module refused to wrap the protected key -- attack blocked.
                xfail_if_known_ckr(
                    exc,
                    _WRAP_EXTRACTION_RUNTIME_REJECT_RVS,
                    "Tookan wrap-extraction wrap rejected before the decrypt leg",
                )
                raise

            # Wrap succeeded. Claim-check: did the target actually hold its
            # protection?
            tgt = read_attributes(rs.raw, rs.sh, target_h, [CKA_EXTRACTABLE])
            claimed = tgt.get(CKA_EXTRACTABLE) is False

            # Attacker decrypts the wrapped blob with the dual-purpose key.
            try:
                recovered = decrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
            except AssertionError:
                recovered = b""  # Module declined to decrypt the wrapped blob.

            # AES-KEY-WRAP adds an 8-byte integrity prefix, so a 16-byte key
            # wraps to 24 bytes; recovering >= the key length of plaintext means
            # the protected key material leaked.
            extracted = bool(recovered) and len(recovered) >= 16
            classify_policy_enforcement(
                claimed=claimed,
                violated=extracted,
                label="wrap-decrypt oracle extracts a non-extractable/sensitive key "
                "(Tookan paper: full key extraction via wrap+decrypt)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_key_h)
            destroy_quietly(rs.raw, rs.sh, target_h)


class TestKeyTypeConfusionOnUnwrap:
    """Tookan paper §3.2 — wrap-key-type confusion on unwrap.

    Unwrap an AES-wrapped key while requesting CKA_KEY_TYPE = CKK_DES3.
    A secure module either:
      (a) rejects the unwrap because the CKA_VALUE_LEN (16 / 24 / 32)
          doesn't match the request type, or
      (b) refuses to materialise a DES3 key whose bytes weren't
          generated through a DES3-aware path (no parity adjustment,
          no weak-key check).

    A module that accepts the unwrap and produces a usable DES3 key
    has a key-type-confusion bug — the attacker can now perform DES3
    operations on bytes that were originally an AES key, leaking
    information through the DES3 codepath that would not otherwise be
    accessible.

    Closes Phase 4.5 GAP-T4 (MED).
    """

    def test_unwrap_aes_as_des3_rejected(self, p11_raw_session: Any, p11_config: Any) -> None:
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        # Wrapping key (AES-256) used both to wrap and to attempt unwrap.
        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        # Target: an AES-128 secret key, created EXTRACTABLE / non-SENSITIVE so
        # its CKA_VALUE is readable for the material comparison below. Wrap
        # output will be 24 bytes.
        target_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            # Capture the original AES-128 key bytes so the valid leg can be
            # confirmed by material comparison (never a literal valid_accepted).
            original = read_attributes(rs.raw, rs.sh, target_h, [CKA_VALUE]).get(CKA_VALUE)

            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                if is_known_error(exc, _TYPE_CONFUSION_WRAP_INAPPLICABLE_RVS):
                    pytest.skip(f"Module cannot wrap AES-128 key for Tookan §3.2: {exc}")
                xfail_if_known_ckr(
                    exc,
                    _TYPE_CONFUSION_WRAP_RUNTIME_REJECT_RVS,
                    "Tookan key-type-confusion wrap rejected before unwrap check",
                )
                raise

            # Valid leg (D4): unwrap the SAME blob as its CORRECT type (CKK_AES),
            # negotiating the accepted template, and recover the original bytes.
            # An advertised-but-not-operational unwrap is routed to xfail (D5),
            # never to valid_accepted=False.
            try:
                good = unwrap_key_for_mechanism_roundtrip(
                    rs,
                    p11_config,
                    unwrapping_key=wrap_h,
                    wrapped_key=wrapped,
                    mechanism=CKM_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_EXTRACTABLE: True,
                        CKA_SENSITIVE: False,
                    },
                    value_len=len(original) if original is not None else None,
                    purpose="tookan AES valid leg",
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _TYPE_CONFUSION_WRAP_RUNTIME_REJECT_RVS,
                    "Tookan key-type-confusion valid-leg AES unwrap not operational",
                )
                raise
            good_value = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE]).get(CKA_VALUE)
            destroy_quietly(rs.raw, rs.sh, good)
            valid_accepted = good_value is not None and good_value == original

            # Invalid leg (D3): unwrap the SAME blob while requesting CKK_DES3.
            # The wrapped blob carries an AES-128 (16-byte) key, but DES3 requires
            # 24 bytes (with parity). A returned handle == type-confusion accepted
            # == break; a clean CkrAssertionError == correctly refused.
            invalid_outcome: Any
            try:
                h = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_DES3,
                        # CKA_VALUE_LEN deliberately omitted: the size mismatch
                        # is exactly what a type-aware module rejects on.
                        CKA_EXTRACTABLE: True,
                    },
                )
                invalid_outcome = h
                destroy_quietly(rs.raw, rs.sh, h)
            except AssertionError as exc:
                invalid_outcome = exc

            classify_discrimination(
                valid_accepted=valid_accepted,
                invalid_outcome=invalid_outcome,
                label="Tookan: unwrap AES-KW blob as CKK_DES3 must be refused",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target_h)
