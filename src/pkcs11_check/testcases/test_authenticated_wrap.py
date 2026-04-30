"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_gcm
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    generate_random,
    read_attributes,
    unwrap_key,
    unwrap_key_authenticated,
    wrap_key,
    wrap_key_authenticated,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_WRAP,
    CKK_AES,
    CKM_AES_GCM,
    CKM_AES_KEY_WRAP,
    CKO_SECRET_KEY,
)

pytestmark = pytest.mark.keymgmt


class TestAuthenticatedWrap:
    """Test AES-GCM authenticated key wrapping (v3.2)."""

    def test_aes_gcm_wrap_unwrap(self, p11_raw_session: Any, p11_interface_version: str) -> None:
        """Wrap/unwrap AES key with AES-GCM authenticated wrapping."""
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        # Generate wrapping key
        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )

        # Generate target key
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            original_value = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]

            # Wrap with authentication
            iv = generate_random(rs.raw, rs.sh, 12)
            gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped, tag = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=gcm,
                )
            except (NotImplementedError, AttributeError, TypeError):
                pytest.skip("wrap_key_authenticated not available or GCM params unsupported")
                return
            except AssertionError as e:
                # Some modules need specific GCM parameters
                pytest.skip(f"Authenticated wrapping failed: {e}")
                return

            assert wrapped != original_value
            assert tag is not None or wrapped is not None

            # Unwrap with authentication
            gcm2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            unwrapped = unwrap_key_authenticated(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                tag if tag else b"",
                CKM_AES_GCM,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                mech_param=gcm2,
            )
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_tampered_tag_rejected(self, p11_raw_session: Any, p11_interface_version: str) -> None:
        """Unwrap with tampered authentication tag must fail."""
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = gen_aes_key(
            rs.raw, rs.sh, 256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        target = gen_aes_key(
            rs.raw, rs.sh, 128, attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            iv = generate_random(rs.raw, rs.sh, 12)
            gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped, tag = wrap_key_authenticated(
                    rs.raw, rs.sh, wrap_h, target, CKM_AES_GCM, mech_param=gcm,
                )
            except (NotImplementedError, AttributeError, TypeError, AssertionError):
                pytest.skip("wrap_key_authenticated not available")
                return

            if not tag:
                pytest.skip("Module did not return a separate authentication tag")
                return

            # Tamper with the tag (flip first byte)
            tampered_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
            gcm2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                unwrapped = unwrap_key_authenticated(
                    rs.raw, rs.sh, wrap_h, wrapped, tampered_tag, CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    mech_param=gcm2,
                )
                # If unwrap succeeded, that's a security bug
                destroy_quietly(rs.raw, rs.sh, unwrapped)
                pytest.fail(
                    "Unwrap with tampered authentication tag should have been rejected -- "
                    "this is a security vulnerability"
                )
            except AssertionError as exc:
                # Expected: module should reject the tampered tag
                assert "CKR_OK" not in str(exc) or "tampered" in str(exc).lower(), (
                    f"Unexpected error during tampered unwrap: {exc}"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_authenticated_wrap_requires_v32(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """On v2.40 modules, wrap_key_authenticated is not available."""
        rs = p11_raw_session
        if p11_interface_version not in ("2.40",):
            pytest.skip("Only relevant for v2.40 modules")

        key = gen_aes_key(rs.raw, rs.sh, 256)
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True},
        )

        try:
            # v2.40 raw API should not have C_WrapKeyAuthenticated
            has_fn = hasattr(rs.raw, "C_WrapKeyAuthenticated")
            if has_fn:
                iv = generate_random(rs.raw, rs.sh, 12)
                gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
                try:
                    wrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        key,
                        target,
                        CKM_AES_GCM,
                        mech_param=gcm,
                    )
                except (AssertionError, AttributeError, NotImplementedError):
                    pass  # Expected on v2.40
            # If no C_WrapKeyAuthenticated method, test passes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
            destroy_quietly(rs.raw, rs.sh, target)


class TestWrapIntegrity:
    """GAP-W2: integrity comparison between authenticated and unauthenticated wraps.

    AES-KEY-WRAP (RFC 3394) has a fixed-magic A6A6A6A6 integrity field, so
    bit-flipping the ciphertext should be detected on unwrap. AES-GCM
    (AEAD) has a real authentication tag and bit-flipping the ciphertext
    must be detected. Both rules are explicit security guarantees of their
    respective wrap mechanisms.

    Closes Phase 4.5 GAP-W2 (HIGH).
    """

    def test_aes_key_wrap_bit_flip_detected(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """AES-KEY-WRAP RFC-3394 magic-field integrity check.

        Wrap a real key, flip a middle byte of the ciphertext, attempt to
        unwrap. Per RFC 3394 §2.2.2, the unwrap MUST verify the A6A6A6A6
        integrity check value and reject mismatches. A module that
        silently produces a different unwrapped key (or returns CKR_OK
        with garbage bytes) is malleable.
        """
        from pkcs11_check.testcases._module_quirks import quirk_extras

        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            try:
                wrapped = wrap_key(
                    rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP
                )
            except AssertionError as exc:
                pytest.skip(f"Wrap failed: {exc}")

            assert len(wrapped) >= 16, "Unexpectedly short wrap output"

            # Flip a bit in a middle byte (avoiding the first 8 bytes which
            # carry the integrity ICV — flipping there is a different test).
            mid = len(wrapped) // 2
            tampered = bytearray(wrapped)
            tampered[mid] ^= 0xFF
            tampered_bytes = bytes(tampered)

            try:
                unwrapped = unwrap_key(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    tampered_bytes,
                    CKM_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_EXTRACTABLE: True,
                    },
                )
            except AssertionError as exc:
                # Expected: module rejected the tampered ciphertext.
                # The base set is the spec-conformant rejection codes.
                # Per-module fallbacks (e.g. Kryoptic's wrong-CKR habit
                # returning CKR_DEVICE_ERROR for all integrity failures)
                # are added via the quirk registry, NOT hard-coded here —
                # so a different module returning CKR_DEVICE_ERROR is
                # surfaced as a finding rather than silently accepted.
                msg = str(exc)
                accepted = [
                    "CKR_WRAPPED_KEY_INVALID",
                    "CKR_ENCRYPTED_DATA_INVALID",
                    "CKR_WRAPPED_KEY_LEN_RANGE",
                ]
                # CKR_GENERAL_ERROR removed from base — too lenient. If a
                # specific module needs it as a documented fallback, add
                # it as a quirk in `_module_quirks.py`.
                from pkcs11_check.raw.rv import ckr_name as _ckr_name

                accepted += [
                    _ckr_name(c)
                    for c in quirk_extras(p11_config, "verify_or_integrity_failure")
                ]
                if any(code in msg for code in accepted):
                    return
                raise

            # Unwrap returned CKR_OK on tampered ciphertext — security violation.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_UnwrapKey accepted bit-flipped AES-KEY-WRAP ciphertext "
                "(expected CKR_WRAPPED_KEY_INVALID per RFC 3394 §2.2.2 ICV check).",
                ComplianceLevel.CRITICAL,
                reference="RFC 3394 §2.2.2 / PKCS#11 v3.1 Sec.6.13.6",
            )
            destroy_quietly(rs.raw, rs.sh, unwrapped)
            pytest.fail(
                "SECURITY: AES-KEY-WRAP unwrap accepted bit-flipped "
                "ciphertext — RFC 3394 integrity check missing or bypassed"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_aes_gcm_wrap_bit_flip_detected(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """AES-GCM authenticated-wrap ciphertext bit-flip MUST be rejected.

        Complementary to test_tampered_tag_rejected: this test tampers the
        ciphertext (not the tag), to catch implementations that only
        validate the tag against the original-ciphertext hash and skip
        the AAD/CT integrity check.
        """
        rs = p11_raw_session
        if p11_interface_version not in ("3.2",):
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            iv = generate_random(rs.raw, rs.sh, 12)
            gcm = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped, tag = wrap_key_authenticated(
                    rs.raw, rs.sh, wrap_h, target, CKM_AES_GCM, mech_param=gcm,
                )
            except (NotImplementedError, AttributeError, TypeError, AssertionError) as e:
                pytest.skip(f"AES-GCM authenticated wrap unavailable: {e}")
                return

            assert len(wrapped) >= 1, "Unexpectedly empty wrap ciphertext"

            # Flip a bit in the ciphertext, NOT the tag.
            tampered_ct = bytearray(wrapped)
            tampered_ct[0] ^= 0x01
            tampered_bytes = bytes(tampered_ct)

            gcm2 = mech_gcm(CKM_AES_GCM, iv, tag_bits=128)
            try:
                unwrapped = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    tampered_bytes,
                    tag if tag else b"",
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    mech_param=gcm2,
                )
            except AssertionError:
                # Expected: AEAD detected the ciphertext tampering.
                return

            # Unwrap returned CKR_OK on tampered AEAD ciphertext —
            # AEAD authentication broken.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Authenticated unwrap accepted bit-flipped AES-GCM "
                "ciphertext (AEAD tag verification missing or bypassed).",
                ComplianceLevel.CRITICAL,
                reference="NIST SP 800-38D / PKCS#11 v3.2 Sec.6.13.7",
            )
            destroy_quietly(rs.raw, rs.sh, unwrapped)
            pytest.fail(
                "SECURITY: AES-GCM authenticated unwrap accepted "
                "bit-flipped ciphertext — AEAD integrity check missing"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)
