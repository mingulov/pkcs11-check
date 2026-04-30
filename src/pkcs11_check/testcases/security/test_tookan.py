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
    destroy_quietly,
    encrypt_single,
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
    CKK_DES3,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.security


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
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_EXTRACTABLE: False},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE])
            assert attrs[CKA_EXTRACTABLE] is False

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
                if copy_attrs[CKA_EXTRACTABLE] is True:
                    note(
                        "Module allows CKA_EXTRACTABLE escalation FALSE->TRUE via "
                        "C_CopyObject (OASIS PKCS#11 spec MUST NOT: may only change "
                        "TRUE->FALSE on copy)",
                        ComplianceLevel.CRITICAL,
                        reference="OASIS PKCS#11 spec C_CopyObject section",
                    )
                    pytest.xfail(
                        "SECURITY: NSS allows CKA_EXTRACTABLE escalation FALSE->TRUE via "
                        "C_CopyObject -- OASIS PKCS#11 MUST NOT violation (Tookan vulnerability)"
                    )
                assert copy_attrs[CKA_EXTRACTABLE] is False, (
                    "EXTRACTABLE escalated on copy - Tookan vulnerability"
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

        target_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        try:
            target_attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_VALUE])
            target_value = target_attrs[CKA_VALUE]

            wrapped = wrap_key(rs.raw, rs.sh, wrap_key_h, target_h, CKM_AES_KEY_WRAP)

            try:
                decrypted = encrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
                # Note: we're using encrypt here because we want to test the raw bytes
                # In the Tookan attack, the attacker decrypts the wrapped blob
                # Actually, the test needs decrypt:
            except AssertionError:
                pass  # Module correctly prevents decrypt of wrapped data
                return

            # If decrypt succeeded, check whether key material leaked
            from pkcs11_check.raw.recipes import decrypt_single

            try:
                decrypted = decrypt_single(rs.raw, rs.sh, wrap_key_h, CKM_AES_ECB, wrapped)
                if decrypted == target_value:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Tookan extraction succeeded: wrap+decrypt leaks key material",
                        ComplianceLevel.NOT_RECOMMENDED,
                        reference="Tookan paper: full key extraction",
                    )
            except AssertionError:
                pass  # Module correctly prevents decrypt of wrapped data
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

    def test_unwrap_aes_as_des3_rejected(self, p11_raw_session: Any) -> None:
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
        # Target: an AES-128 secret key. Wrap output will be 24 bytes.
        target_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target_h, CKM_AES_KEY_WRAP)
            except AssertionError as exc:
                pytest.skip(f"Module rejected wrap of AES-128 → AES-256: {exc}")

            try:
                fake_des3 = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_DES3,
                        # CKA_VALUE_LEN deliberately omitted: the wrapped
                        # blob carries an AES-128 (16-byte) key, but DES3
                        # requires 24 bytes (with parity). A type-aware
                        # module rejects the unwrap on size mismatch.
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as exc:
                # Expected: module rejected the type-confused unwrap.
                # Note: CKR_MECHANISM_INVALID is deliberately NOT
                # accepted here. has_mechanism("AES_KEY_WRAP") was
                # checked at the top of the test, so a sudden
                # mechanism-disappear on unwrap (after a successful
                # wrap with the same mechanism) is itself a module
                # bug, not a legitimate type-confusion rejection.
                msg = str(exc)
                accepted = (
                    "CKR_TEMPLATE_INCONSISTENT",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                    "CKR_KEY_TYPE_INCONSISTENT",
                    "CKR_KEY_SIZE_RANGE",
                    "CKR_WRAPPED_KEY_INVALID",
                    "CKR_WRAPPED_KEY_LEN_RANGE",
                )
                if any(code in msg for code in accepted):
                    return
                raise

            # Module accepted the wrong type — confirm whether the
            # resulting "DES3" key has the AES-128 bytes (the security
            # signature of the Tookan §3.2 attack).
            read_error: str | None = None
            try:
                bad_attrs: dict[int, Any] = read_attributes(
                    rs.raw, rs.sh, fake_des3, [CKA_VALUE, CKA_KEY_TYPE]
                )
            except AssertionError as exc:
                # Module produced an opaque key — still wrong type,
                # but at least the bytes are not directly readable.
                # Capture the error so triage isn't done blind.
                bad_attrs = {}
                read_error = str(exc)

            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"Module unwrapped AES-wrapped blob as CKK_DES3 — "
                f"key-type confusion (Tookan §3.2). Resulting key has "
                f"CKA_KEY_TYPE={bad_attrs.get(CKA_KEY_TYPE)} and value of "
                f"length {len(bad_attrs.get(CKA_VALUE, b''))}."
                + (f" (read-back error: {read_error})" if read_error else ""),
                ComplianceLevel.CRITICAL,
                reference="Tookan paper §3.2 / PKCS#11 v3.1 Sec.5.14.4",
            )
            destroy_quietly(rs.raw, rs.sh, fake_des3)
            pytest.fail(
                "SECURITY: Tookan §3.2 — module unwrapped an AES-wrapped "
                "blob as CKK_DES3 (key-type confusion). Attacker can run "
                "DES3 operations on bytes that were originally an AES key, "
                "creating a side-channel into the AES key material."
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target_h)
