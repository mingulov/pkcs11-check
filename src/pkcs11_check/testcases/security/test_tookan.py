"""Tookan paper security vectors - conflicting key usage attributes.

Tests based on "Attacking and Fixing PKCS#11 Security Tokens" (2010).
Keys with conflicting usage flags (WRAP+DECRYPT, ENCRYPT+UNWRAP)
can allow key extraction. Modules should reject or enforce policy.

Reference: https://dl.acm.org/doi/10.1145/1866307.1866337
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify, xfail_as
from pkcs11_check.raw.pack import mech_bytes
from pkcs11_check.raw.recipes import (
    copy_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    import_secret_key,
    read_attributes,
    unwrap_key,
    wrap_key,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKK_AES,
    CKK_DES3,
    CKM_AES_CBC,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_KEY_UNEXTRACTABLE,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases._negotiation import TEMPLATE_SHAPE_REJECTS
from pkcs11_check.testcases.conftest import (
    classify_discrimination,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    is_known_error,
    reject_or_classify,
    unwrap_key_for_mechanism_roundtrip,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.security

_CONFLICTING_USAGE_POLICY_REJECT_RVS = {
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
}

_COPY_ESCALATION_REJECT_RVS = {
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
}

_WRAP_DECRYPT_BLOCKED_RVS = {
    CKR_DATA_LEN_RANGE,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
}

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

# Clean reject codes a module may return at an AES-CBC encrypt/decrypt or AES-key
# import *use* site when the operation is advertised-but-not-operational for the
# given key/params (the produce leg of the hardening G5.5 oracle). Each of these means the
# extraction chain could not complete through that leg -> the oracle did not
# extract anything, routed to a not-applicable outcome rather than a false pass.
_CIPHER_OP_REJECT_RVS = {
    CKR_ACTION_PROHIBITED,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
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
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                _CONFLICTING_USAGE_POLICY_REJECT_RVS,
                label="AES key generation with conflicting WRAP+DECRYPT usage",
                kind="policy",
            )
            return

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
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                _CONFLICTING_USAGE_POLICY_REJECT_RVS,
                label="AES key generation with conflicting ENCRYPT+UNWRAP usage",
                kind="policy",
            )
            return

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
        key = gen_aes_key_or_xfail(rs, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE])
            sensitive_value = attr_or_record(
                attrs,
                CKA_SENSITIVE,
                label="CKA_SENSITIVE=True readback (pre-copy baseline)",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            # A missing baseline disables ONLY the baseline claim check.  The copy
            # must still be created and its CKA_SENSITIVE still observed: a module
            # that omits the baseline attribute but reports CKA_SENSITIVE=False on
            # the copy is the exact Tookan SENSITIVE-loss this probe exists to find,
            # and returning here would never probe it.  Creation-time acceptance of
            # the CKA_SENSITIVE=True template (gen_aes_key_or_xfail above) is the
            # claim that the post-copy check is measured against.
            if sensitive_value is not MISSING_ATTRIBUTE:
                assert sensitive_value is True

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_LABEL: "copy-sensitive"},
                )
            except CkrAssertionError as exc:
                if exc.rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                    return  # Copy not supported - ok
                raise
            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_SENSITIVE])
                copy_sensitive_value = attr_or_record(
                    copy_attrs,
                    CKA_SENSITIVE,
                    label="CKA_SENSITIVE=True readback (post-copy)",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                if copy_sensitive_value is MISSING_ATTRIBUTE:
                    return
                assert copy_sensitive_value is True, (
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
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            # policy claim/effect-check. claimed = the original key reads back
            # CKA_EXTRACTABLE=False; violated = the copy reads back True.
            orig = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
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
                # The readback is unavailable, but the CLAIM is not: the module
                # ACCEPTED a CKA_EXTRACTABLE=False template at C_GenerateKey
                # (gen_aes_key_or_xfail above raises/xfails otherwise), and that
                # acceptance is independent claim evidence.  Deriving `claimed`
                # from the readback alone would let one unreadable attribute
                # downgrade a proven copy-escalation to an xfail.  The
                # attr_or_record() record above keeps the unreadable readback
                # itself visible.
                claimed = True
            else:
                claimed = orig_extractable_raw is False

            try:
                copied = copy_object(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_EXTRACTABLE: True},
                )
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    _COPY_ESCALATION_REJECT_RVS,
                    label="C_CopyObject CKA_EXTRACTABLE False-to-True escalation",
                    kind="policy",
                )
                return

            try:
                copy_attrs = read_attributes(rs.raw, rs.sh, copied, [CKA_EXTRACTABLE])
                copy_extractable_raw = attr_or_record(
                    copy_attrs,
                    CKA_EXTRACTABLE,
                    label="C_CopyObject result CKA_EXTRACTABLE readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                copy_extractable: Any
                if copy_extractable_raw is MISSING_ATTRIBUTE:
                    copy_extractable = None
                else:
                    copy_extractable = copy_extractable_raw
                violated = copy_extractable is True
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
        # promised never to release -- a policy self-contradiction.
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
            #     reveal key material, which is the actual policy violation.
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
            tgt_extractable_raw = attr_or_record(
                tgt,
                CKA_EXTRACTABLE,
                label="wrap-extraction target CKA_EXTRACTABLE claim-check readback",
                reason="not_operational",
                kind="policy",
                inherit_mechanism=False,
            )
            claimed: bool
            if tgt_extractable_raw is MISSING_ATTRIBUTE:
                # The readback is unavailable, but the CLAIM is not: gen_aes_key
                # above ACCEPTED a CKA_EXTRACTABLE=False / CKA_SENSITIVE=True
                # template, and that acceptance is independent claim evidence.
                # Without this, an unreadable attribute would downgrade a proven
                # key extraction to an xfail.  The attr_or_record() record above
                # keeps the unreadable readback itself visible.
                claimed = True
            else:
                claimed = tgt_extractable_raw is False

            # Attacker decrypts the wrapped blob with the dual-purpose key.
            try:
                recovered = decrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    _WRAP_DECRYPT_BLOCKED_RVS,
                    label="Tookan wrap-extraction decrypt rejected",
                    kind="policy",
                )
                return

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

    def test_cbc_wrap_then_decrypt_extraction_oracle(self, p11_raw_session: Any) -> None:
        """hardening G5.5: Inverse-injection / CBC wrap-then-decrypt extraction oracle.

        Classic Clulow/Tookan attack variant: create a dual-purpose key K with
        CKA_WRAP=True and CKA_DECRYPT=True (the dangerous combination that lets
        the same key both wrap and then decrypt the wrapped blob).  Use AES-CBC
        (the canonical reversible vehicle — deterministic, no integrity check)
        so that if C_WrapKey produces a blob and C_Decrypt accepts the same blob
        with the same IV, the output is the raw key material.

        Guard chain (every refusal along the chain → pass/skip, only a
        VERIFIED end-to-end extraction → fail):

        1. K creation rejected → pytest.skip (module enforces key separation).
        2. T readback shows EXTRACTABLE=True (the module ignored non-extractable) →
           xfail (metadata deviation — a separate finding, not this probe's fail).
        3. C_WrapKey(K, T, AES_CBC) rejected with a protection code → pass (wrap
           refusal blocked the attack: a module that enforces the non-extractable
           policy stops the chain here, e.g. C_WrapKey → CKR_KEY_UNEXTRACTABLE).
        4. C_WrapKey rejected with a runtime code → xfail (not operational).
        5. C_Decrypt(K, blob, AES_CBC) rejected → pass (module blocked the
           decrypt leg; no extraction occurred).
        6. Wrap + decrypt both succeeded → VERIFY by importing recovered bytes as
           an AES key and comparing its CBC output against T's reference MAC.
           If they match → fail (verified extraction).
           If they do not match → pass + note (wrap succeeded but decrypt output
           did not reconstruct T — no verified extraction).

        Reference: B. Clulow "On the Security of PKCS#11" (2003);
        Tookan paper §3.1 (wrap-decrypt oracle).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC"):
            pytest.skip("AES_CBC not supported by module")
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported by module")

        # Step 1: create dual-purpose K (WRAP + DECRYPT).
        dual_h = 0
        try:
            try:
                dual_h = gen_aes_key(
                    rs.raw,
                    rs.sh,
                    128,
                    attrs={
                        CKA_WRAP: True,
                        CKA_DECRYPT: True,
                        CKA_ENCRYPT: False,
                        CKA_UNWRAP: False,
                        CKA_SENSITIVE: False,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as exc:
                if is_known_error(
                    exc,
                    (
                        CKR_ACTION_PROHIBITED,
                        CKR_KEY_FUNCTION_NOT_PERMITTED,
                        CKR_TEMPLATE_INCOMPLETE,
                        CKR_TEMPLATE_INCONSISTENT,
                    ),
                ):
                    pytest.skip(
                        "Module rejected WRAP+DECRYPT combination "
                        "(key-separation enforced at creation — attack surface absent)"
                    )
                raise

            # Step 2: create a protected non-extractable target key T.
            target_h = 0
            try:
                try:
                    target_h = gen_aes_key(
                        rs.raw,
                        rs.sh,
                        128,
                        attrs={
                            CKA_ENCRYPT: True,
                            CKA_DECRYPT: False,
                            CKA_EXTRACTABLE: False,
                            CKA_SENSITIVE: True,
                        },
                    )
                except AssertionError as exc:
                    if is_known_error(exc, _WRAP_EXTRACTION_PROTECTED_RVS):
                        return  # Cannot set up the protected target — pass.
                    raise

                # Claim-check: does the module actually hold the non-extractable claim?
                tgt_attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_EXTRACTABLE])
                tgt_attrs_extractable_raw = attr_or_record(
                    tgt_attrs,
                    CKA_EXTRACTABLE,
                    label="type-confusion wrap target CKA_EXTRACTABLE claim-check readback",
                    reason="not_operational",
                    kind="policy",
                    inherit_mechanism=False,
                )
                if tgt_attrs_extractable_raw is MISSING_ATTRIBUTE:
                    # ABSENT is not OBSERVED-TRUE.  The module ACCEPTED the
                    # CKA_EXTRACTABLE=False template at C_GenerateKey, so the claim
                    # stands on creation-time acceptance and the oracle remains
                    # applicable; only the readback is unavailable, and
                    # attr_or_record() above already recorded exactly that.  Xfailing
                    # here would both suppress a real extraction and assert something
                    # ("module did not honor CKA_EXTRACTABLE=False") that was never
                    # observed.
                    pass
                elif tgt_attrs_extractable_raw is not False:
                    # OBSERVED: the module ignored the non-extractable request — a
                    # separate metadata deviation, not this probe's verdict.  The
                    # extraction oracle is not applicable to a key that was never made
                    # non-extractable, so record an honest deviation and stop.
                    xfail_as(
                        "honest_deviation",
                        kind="metadata",
                        label="target key was not created non-extractable (module did not honor "
                        "CKA_EXTRACTABLE=False); extraction oracle not applicable",
                    )

                # Produce a reference CBC output from T so we can verify recovery later.
                # Known plaintext (two AES blocks = 32 bytes) and IV (16 bytes).
                reference_pt = b"\x5a" * 32
                cbc_iv = b"\x3c" * 16
                cbc_mech = mech_bytes(CKM_AES_CBC, cbc_iv)
                try:
                    reference_ct = encrypt_single(
                        rs.raw,
                        rs.sh,
                        target_h,
                        CKM_AES_CBC,
                        reference_pt,
                        mech_param=cbc_mech,
                        output_size_hint=len(reference_pt),
                    )
                except AssertionError as exc:
                    rv = getattr(exc, "rv", None)
                    if rv is None:
                        raise
                    if is_known_error(exc, _CIPHER_OP_REJECT_RVS):
                        # T cannot CBC-encrypt the reference plaintext, so the
                        # recovered-material verification cannot be performed: the
                        # oracle is not evaluable, a genuine capability/operability
                        # gap rather than a security result.
                        pytest.skip(
                            "Target key cannot AES-CBC-encrypt the reference plaintext "
                            f"({ckr_name(rv)}); extraction oracle not verifiable"
                        )
                    raise

                # Step 3: attempt C_WrapKey(K, T, AES_CBC).
                try:
                    wrapped = wrap_key(
                        rs.raw,
                        rs.sh,
                        dual_h,
                        target_h,
                        CKM_AES_CBC,
                        mech_param=cbc_mech,
                    )
                except AssertionError as exc:
                    if is_known_error(exc, _WRAP_EXTRACTION_PROTECTED_RVS):
                        return  # Module refused to wrap the non-extractable key — attack blocked.
                    xfail_if_known_ckr(
                        exc,
                        _WRAP_EXTRACTION_RUNTIME_REJECT_RVS,
                        "Tookan CBC oracle: C_WrapKey rejected before the decrypt leg",
                    )
                    raise

                # Step 5: attempt C_Decrypt(K, blob, AES_CBC).
                try:
                    recovered = decrypt_single(
                        rs.raw,
                        rs.sh,
                        dual_h,
                        CKM_AES_CBC,
                        wrapped,
                        mech_param=cbc_mech,
                        output_size_hint=len(wrapped),
                    )
                except AssertionError as exc:
                    rv = getattr(exc, "rv", None)
                    if rv is None:
                        raise
                    if is_known_error(exc, _CIPHER_OP_REJECT_RVS):
                        # Decrypt leg refused with a clean code — no extraction
                        # occurred. The module blocked the decrypt half of the
                        # oracle (e.g. CKA_DECRYPT not honored, or the blob is not
                        # decryptable), so the protection held end-to-end.
                        classify_policy_enforcement(
                            claimed=True,
                            violated=False,
                            label="Tookan/Clulow CBC oracle: C_WrapKey succeeded but C_Decrypt "
                            "of wrapped blob was refused (non-extractable key protected)",
                        )
                        return
                    raise  # Unexpected CKR -- surface it, never swallow into a pass.

                # Step 6: verify recovery.  Only a VERIFIED match is a hard fail.
                if len(recovered) < 16:
                    # The decrypt output is too short to carry a 128-bit key, so it
                    # cannot reconstruct the target -- no verified extraction.
                    classify_policy_enforcement(
                        claimed=True,
                        violated=False,
                        label="Tookan/Clulow CBC oracle: chain succeeded but recovered bytes "
                        "could not be verified against target key material",
                    )
                    return

                # Import the first 16 bytes of recovered output as a candidate AES key
                # and check if it reproduces T's reference ciphertext.
                candidate_h = 0
                try:
                    try:
                        candidate_h = import_secret_key(
                            rs.raw,
                            rs.sh,
                            CKK_AES,
                            recovered[:16],
                            attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
                        )
                    except AssertionError as exc:
                        rv = getattr(exc, "rv", None)
                        if rv is None:
                            raise
                        if is_known_error(exc, _CIPHER_OP_REJECT_RVS):
                            # Cannot import the recovered bytes as an AES key (e.g.
                            # the module has no C_CreateObject): the recovery cannot
                            # be verified, so no extraction is confirmed.
                            classify_policy_enforcement(
                                claimed=True,
                                violated=False,
                                label="Tookan/Clulow CBC oracle: recovered bytes could not be "
                                "imported as an AES key (no verified extraction)",
                            )
                            return
                        raise  # Unexpected CKR -- surface it, never swallow.

                    try:
                        candidate_ct: bytes | None = encrypt_single(
                            rs.raw,
                            rs.sh,
                            candidate_h,
                            CKM_AES_CBC,
                            reference_pt,
                            mech_param=cbc_mech,
                            output_size_hint=len(reference_pt),
                        )
                    except AssertionError as exc:
                        rv = getattr(exc, "rv", None)
                        if rv is None:
                            raise
                        if is_known_error(exc, _CIPHER_OP_REJECT_RVS):
                            candidate_ct = None  # Candidate cannot encrypt -> no match.
                        else:
                            raise  # Unexpected CKR -- surface it, never swallow.

                    material_matches = candidate_ct is not None and candidate_ct == reference_ct
                    classify_policy_enforcement(
                        claimed=True,
                        violated=material_matches,
                        label="Tookan/Clulow CBC wrap-then-decrypt oracle: recovered bytes "
                        "reproduce the non-extractable key's reference output "
                        "(Clulow §4.3 / Tookan §3.1: end-to-end key extraction via "
                        "AES-CBC wrap+decrypt on a dual-purpose WRAP+DECRYPT key)",
                    )
                finally:
                    if candidate_h:
                        destroy_quietly(rs.raw, rs.sh, candidate_h)
            finally:
                if target_h:
                    destroy_quietly(rs.raw, rs.sh, target_h)
        finally:
            if dual_h:
                destroy_quietly(rs.raw, rs.sh, dual_h)


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
            original_attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_VALUE])
            original_raw = attr_or_record(
                original_attrs,
                CKA_VALUE,
                label="Tookan key-type-confusion target CKA_VALUE readback (round-trip reference)",
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            # The sentinel is deliberately NOT collapsed into None: `None` would be
            # indistinguishable from a real readback and would flow into
            # valid_accepted=False below, manufacturing a CRITICAL crypto verdict for
            # a provider that merely omits CKA_VALUE.
            reference_len: int | None = None
            if original_raw is not MISSING_ATTRIBUTE:
                reference_len = len(original_raw)

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

            # Valid leg (Pillar-2 D4): unwrap the SAME blob as its CORRECT type (CKK_AES),
            # negotiating the accepted template, and recover the original bytes.
            # An advertised-but-not-operational unwrap is routed to xfail (Pillar-2 D5),
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
                    value_len=reference_len,
                    purpose="tookan AES valid leg",
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _TYPE_CONFUSION_WRAP_RUNTIME_REJECT_RVS,
                    "Tookan key-type-confusion valid-leg AES unwrap not operational",
                )
                raise
            good_value_attrs = read_attributes(rs.raw, rs.sh, good, [CKA_VALUE])
            good_value_raw = attr_or_record(
                good_value_attrs,
                CKA_VALUE,
                label="Tookan key-type-confusion valid-leg unwrap CKA_VALUE readback",
                reason="not_operational",
                kind="metadata",
                inherit_mechanism=False,
            )
            destroy_quietly(rs.raw, rs.sh, good)
            readback_complete = False
            valid_accepted = False
            if original_raw is not MISSING_ATTRIBUTE and good_value_raw is not MISSING_ATTRIBUTE:
                readback_complete = True
                valid_accepted = good_value_raw == original_raw

            # Invalid leg (Pillar-2 D3): unwrap the SAME blob while requesting CKK_DES3.
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

            confusion_label = "Tookan: unwrap AES-KW blob as CKK_DES3 must be refused"
            if readback_complete:
                classify_discrimination(
                    valid_accepted=valid_accepted,
                    invalid_outcome=invalid_outcome,
                    label=confusion_label,
                )
            else:
                # An unreadable CKA_VALUE disables ONLY the "did the valid leg produce
                # the right material" oracle -- the not_operational records above
                # already say why it is unverifiable.  It must not fabricate
                # valid_accepted=False (which classify_discrimination reports as a
                # CRITICAL crypto break for a provider that correctly REFUSED the
                # type confusion), and it must not suppress the invalid leg, which is
                # independently observable without any readback: the module either
                # raised a clean CkrAssertionError or handed back a live DES3 handle.
                if isinstance(invalid_outcome, CkrAssertionError):
                    pass  # cleanly refused -- the protection held; nothing to classify
                elif isinstance(invalid_outcome, BaseException):
                    raise invalid_outcome
                else:
                    classify(
                        "accepted_invalid",
                        kind="crypto",
                        label=confusion_label,
                        summary=f"{confusion_label}: accepted the tampered/forged/confused "
                        "input (security break)",
                    )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target_h)
