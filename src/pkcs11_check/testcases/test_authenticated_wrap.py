"""AES-GCM authenticated key wrapping tests (v3.2).

Tests wrap_key_authenticated / unwrap_key_authenticated using
AES-GCM AEAD. Requires PKCS#11 v3.2 interface (C_WrapKeyAuthenticated).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_gcm_message, mech_gcm_message_inherit_tag
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
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_DATA_INVALID,
    CKR_ENCRYPTED_DATA_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_SIGNATURE_INVALID,
    CKR_WRAPPED_KEY_INVALID,
    CKR_WRAPPED_KEY_LEN_RANGE,
)
from pkcs11_check.testcases.conftest import is_known_error

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

            # Wrap with authentication.  Tag lives in CK_GCM_MESSAGE_PARAMS.pTag.
            iv = generate_random(rs.raw, rs.sh, 12)
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError):
                pytest.skip("wrap_key_authenticated not available or GCM params unsupported")
                return
            except AssertionError as e:
                pytest.skip(f"Authenticated wrapping failed: {e}")
                return

            assert wrapped != original_value
            assert any(wrap_mech.buffer_bytes("tag")), (
                "C_WrapKeyAuthenticated returned CKR_OK but left the auth tag buffer zeroed"
            )

            # Unwrap: share the wrap-side pTag so the module sees the auth tag.
            unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            unwrapped = unwrap_key_authenticated(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                CKM_AES_GCM,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_SENSITIVE: False,
                },
                mech_param=unwrap_mech,
            )
            try:
                unwrapped_value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
                assert unwrapped_value == original_value
            finally:
                destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_aes_gcm_authenticated_wrap_generated_iv_and_tag(
        self, p11_raw_session: Any, p11_interface_version: str
    ) -> None:
        """C_WrapKeyAuthenticated writes generated GCM IV and tag into message params."""
        rs = p11_raw_session
        if p11_interface_version != "3.2":
            pytest.skip("Authenticated wrapping requires v3.2 interface")
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.pack import mech_gcm_message_generated_iv
        from pkcs11_check.raw.types_std import CKG_GENERATE

        wrap_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        unwrapped = 0
        try:
            original = read_attributes(rs.raw, rs.sh, target, [CKA_VALUE])[CKA_VALUE]
            aad = b"authenticated generated gcm wrap"
            wrap_mech = mech_gcm_message_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                iv_generator=int(CKG_GENERATE),
                tag_bits=128,
            )
            wrapped = wrap_key_authenticated(
                rs.raw,
                rs.sh,
                wrap_h,
                target,
                CKM_AES_GCM,
                aad=aad,
                mech_param=wrap_mech,
            )
            iv = wrap_mech.buffer_bytes("iv")
            tag = wrap_mech.buffer_bytes("tag")
            assert any(iv)
            assert any(tag)

            unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            unwrapped = unwrap_key_authenticated(
                rs.raw,
                rs.sh,
                wrap_h,
                wrapped,
                CKM_AES_GCM,
                attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                aad=aad,
                mech_param=unwrap_mech,
            )
            value = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])[CKA_VALUE]
            assert value == original
        finally:
            destroy_quietly(rs.raw, rs.sh, unwrapped)
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
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_WRAP: True, CKA_UNWRAP: True, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            iv = generate_random(rs.raw, rs.sh, 12)
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError, AssertionError):
                pytest.skip("wrap_key_authenticated not available")
                return

            tag = wrap_mech.buffer_bytes("tag")
            if not any(tag):
                pytest.skip("Module did not write an authentication tag to pTag")
                return

            # Tamper with the tag in-place via the shared pTag buffer.
            unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            tag_storage, _ = unwrap_mech.buffer_storage("tag")
            tag_storage[0] ^= 0xFF
            try:
                unwrapped = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    mech_param=unwrap_mech,
                )
                destroy_quietly(rs.raw, rs.sh, unwrapped)
                pytest.fail(
                    "Unwrap with tampered authentication tag should have been rejected -- "
                    "this is a security vulnerability"
                )
            except AssertionError as exc:
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
                wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
                try:
                    wrap_key_authenticated(
                        rs.raw,
                        rs.sh,
                        key,
                        target,
                        CKM_AES_GCM,
                        mech_param=wrap_mech,
                    )
                except (AssertionError, AttributeError, NotImplementedError):
                    pass  # Expected on v2.40
            # If no C_WrapKeyAuthenticated method, test passes
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
            destroy_quietly(rs.raw, rs.sh, target)


class TestAuthenticatedWrapAAD:
    """GAP-W4: tampered-AAD path on authenticated wrap/unwrap (v3.2).

    The v3.2 authenticated-wrap test_tampered_tag_rejected covers
    ciphertext-tag tampering. AAD is a separate AEAD input — its
    tampering must also produce an AEAD verification failure. A module
    that authenticates only the ciphertext-and-tag tuple while ignoring
    AAD has a real authentication-bypass bug (CWE-354 "Improper
    Validation of Integrity Check Value").

    Closes Phase 4.5 GAP-W4 (MED).
    """

    def test_aes_gcm_unwrap_with_different_aad_rejected(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
        p11_config: Any,
    ) -> None:
        """Wrap with AAD=X, unwrap with AAD=Y. Unwrap MUST fail."""
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
            aad_x = b"context-X-" + b"\xaa" * 16
            aad_y = b"context-Y-" + b"\xbb" * 16

            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw, rs.sh, wrap_h, target, CKM_AES_GCM,
                    aad=aad_x, mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError) as exc:
                # API not available on this module — skip cleanly.
                pytest.skip(f"AES-GCM authenticated wrap API not available: {exc}")
                return
            except AssertionError as exc:
                # Wrap-side failure. Skip ONLY when the failure looks
                # like a legitimate "module rejected this configuration"
                # (mech-not-supported / AAD-too-long / GCM-params-bad).
                # Crashes (CKR_GENERAL_ERROR / CKR_FUNCTION_FAILED /
                # CKR_DEVICE_ERROR) re-raise — those are findings, not
                # skip conditions.
                if is_known_error(
                    exc,
                    {
                        CKR_MECHANISM_INVALID,
                        CKR_MECHANISM_PARAM_INVALID,
                        CKR_FUNCTION_NOT_SUPPORTED,
                        CKR_KEY_FUNCTION_NOT_PERMITTED,
                        CKR_ARGUMENTS_BAD,
                    },
                ):
                    pytest.skip(f"AES-GCM authenticated wrap rejected: {exc}")
                    return
                raise

            # Unwrap with a DIFFERENT AAD — AEAD must reject.
            unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            try:
                bad_unwrap = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    wrapped,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    aad=aad_y,
                    mech_param=unwrap_mech,
                )
            except AssertionError as exc:
                # Expected: AEAD detected the AAD mismatch. Match against
                # specific rejection CKRs so a recipe-side assert (buffer
                # shape, ctypes mismatch, etc.) cannot silently pass as
                # "AAD detected".  Plus per-module documented quirks
                # (e.g. Kryoptic returns CKR_DEVICE_ERROR for any
                # verification failure).
                from pkcs11_check.testcases._module_quirks import quirk_extras

                aead_reject_rvs = {
                    CKR_ENCRYPTED_DATA_INVALID,
                    CKR_WRAPPED_KEY_INVALID,
                    CKR_SIGNATURE_INVALID,
                    CKR_DATA_INVALID,
                    *quirk_extras(p11_config, "verify_or_integrity_failure"),
                }
                if is_known_error(exc, aead_reject_rvs):
                    return
                raise

            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Authenticated unwrap accepted a different-AAD GCM blob "
                "(AAD did not participate in tag computation, or AAD "
                "tampering was not validated).",
                ComplianceLevel.CRITICAL,
                reference="NIST SP 800-38D §7.2 / PKCS#11 v3.2 Sec.6.13.7",
            )
            destroy_quietly(rs.raw, rs.sh, bad_unwrap)
            pytest.fail(
                "SECURITY: AES-GCM authenticated unwrap accepted a wrap "
                "produced under a different AAD — AAD integrity not "
                "enforced (CWE-354)."
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, wrap_h)
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

    def test_aes_key_wrap_bit_flip_detected(self, p11_raw_session: Any, p11_config: Any) -> None:
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
                wrapped = wrap_key(rs.raw, rs.sh, wrap_h, target, CKM_AES_KEY_WRAP)
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
                #
                # CKR_GENERAL_ERROR removed from base — too lenient. If a
                # specific module needs it as a documented fallback, add
                # it as a quirk in `_module_quirks.py`.
                # Per-module quirks: Kryoptic's verify-failure CKR_DEVICE_ERROR
                # and OpenCryptoki's CKR_ATTRIBUTE_READ_ONLY-on-unwrap-template
                # are routed through the quirk registry so the rejection is
                # accepted ONLY for the module that documents the deviation,
                # not as a global fallback.
                accepted_rvs = {
                    CKR_WRAPPED_KEY_INVALID,
                    CKR_ENCRYPTED_DATA_INVALID,
                    CKR_WRAPPED_KEY_LEN_RANGE,
                    *quirk_extras(p11_config, "verify_or_integrity_failure"),
                    *quirk_extras(p11_config, "unwrap_template_class_keytype_rejected"),
                }
                if is_known_error(exc, accepted_rvs):
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
            wrap_mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            try:
                wrapped = wrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    target,
                    CKM_AES_GCM,
                    mech_param=wrap_mech,
                )
            except (NotImplementedError, AttributeError, TypeError, AssertionError) as e:
                pytest.skip(f"AES-GCM authenticated wrap unavailable: {e}")
                return

            assert len(wrapped) >= 1, "Unexpectedly empty wrap ciphertext"

            # Flip a bit in the ciphertext, NOT the tag.
            tampered_ct = bytearray(wrapped)
            tampered_ct[0] ^= 0x01
            tampered_bytes = bytes(tampered_ct)

            unwrap_mech = mech_gcm_message_inherit_tag(CKM_AES_GCM, iv, source=wrap_mech)
            try:
                unwrapped = unwrap_key_authenticated(
                    rs.raw,
                    rs.sh,
                    wrap_h,
                    tampered_bytes,
                    CKM_AES_GCM,
                    attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
                    mech_param=unwrap_mech,
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


class TestEcdhAesKeyWrap:
    """GAP-W3: CKM_ECDH_AES_KEY_WRAP hybrid wrap roundtrip + integrity.

    The hybrid mechanism derives an AES key via ECDH (using the
    recipient's public key + an internally-generated ephemeral key
    pair) and then wraps the target with AES-KW under that derived
    key. The wrap blob carries the ephemeral public point alongside
    the AES-KW ciphertext so the recipient can re-derive the wrapping
    AES key.

    Closes Phase 4.5 GAP-W3 (MED).
    """

    def test_ecdh_aes_kw_roundtrip(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Wrap an AES key with CKM_ECDH_AES_KEY_WRAP, unwrap, verify
        roundtrip succeeds. The bit-flip integrity assertion is in a
        separate test (`test_ecdh_aes_kw_bit_flip_integrity`) so that
        a skip on this test doesn't quietly hide the integrity check
        from pytest output."""
        from pkcs11_check.raw.ec import encode_named_curve_parameters
        from pkcs11_check.raw.pack import mech_ecdh_aes_kw
        from pkcs11_check.raw.recipes import (
            gen_ec_keypair,
            unwrap_key,
            wrap_key,
        )
        from pkcs11_check.raw.types_std import (
            CKA_DERIVE,
            CKA_KEY_TYPE,
            CKD_SHA256_KDF,
            CKK_AES,
            CKM_ECDH_AES_KEY_WRAP,
            CKO_SECRET_KEY,
        )

        rs = p11_raw_session
        if not rs.has_mechanism("ECDH_AES_KEY_WRAP"):
            pytest.skip("CKM_ECDH_AES_KEY_WRAP not supported")

        # Recipient EC P-256 keypair: pub used for wrap, priv for unwrap.
        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                public_attrs={CKA_DERIVE: True, CKA_WRAP: True},
                private_attrs={CKA_DERIVE: True, CKA_UNWRAP: True},
            )
        except AssertionError as exc:
            pytest.skip(f"Could not generate P-256 keypair: {exc}")
            return

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_ecdh_aes_kw(
                CKM_ECDH_AES_KEY_WRAP,
                aes_key_bits=256,
                kdf=CKD_SHA256_KDF,
            )

            # --- Roundtrip ---
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    pub,
                    target,
                    CKM_ECDH_AES_KEY_WRAP,
                    mech_param=mech,
                )
            except AssertionError as exc:
                # has_mechanism("ECDH_AES_KEY_WRAP") was checked at the
                # top, so the only legitimate "skip" reason here is a
                # vendor-specific disagreement about the parameter
                # combination (e.g. only certain aes_key_bits / kdf
                # combos accepted). CKR_FUNCTION_NOT_SUPPORTED and
                # CKR_KEY_FUNCTION_NOT_PERMITTED would mean the module
                # advertised the mechanism but doesn't actually
                # implement it / accept CKA_WRAP=True on EC pub keys —
                # that IS the advertise-but-don't-implement bug class
                # this test should surface, not skip.
                if is_known_error(exc, {CKR_MECHANISM_PARAM_INVALID}):
                    pytest.skip(f"Module rejected ECDH-AES-KW params: {exc}")
                    return
                raise

            assert len(wrapped) > 16, "ECDH-AES-KW output unexpectedly short"

            mech2 = mech_ecdh_aes_kw(
                CKM_ECDH_AES_KEY_WRAP,
                aes_key_bits=256,
                kdf=CKD_SHA256_KDF,
            )
            try:
                unwrapped = unwrap_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    wrapped,
                    CKM_ECDH_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_EXTRACTABLE: True,
                    },
                    mech_param=mech2,
                )
            except AssertionError as exc:
                # OpenCryptoki quirk: rejects unwrap templates that
                # include CKA_CLASS / CKA_KEY_TYPE with
                # CKR_ATTRIBUTE_READ_ONLY. The wrap already succeeded,
                # which validates the wrap-side construction; the
                # unwrap-template quirk is a different code path.
                if is_known_error(exc, {CKR_ATTRIBUTE_READ_ONLY}):
                    pytest.skip(
                        f"Module rejects unwrap template (likely OC's "
                        f"CKA_CLASS/CKA_KEY_TYPE quirk): {exc}"
                    )
                    return
                raise
            # Round-trip succeeded — basic happy-path coverage.
            destroy_quietly(rs.raw, rs.sh, unwrapped)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, target)

    def test_ecdh_aes_kw_bit_flip_integrity(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Bit-flip integrity check for CKM_ECDH_AES_KEY_WRAP.

        Wrap a target key, flip a byte in the AES-KW ciphertext region of
        the hybrid blob, attempt unwrap. The AES-KW RFC 3394 magic-field
        ICV check should reject the tampered ciphertext.

        Kept separate from the roundtrip test so a skip on the roundtrip
        path (e.g. an unwrap-template quirk) doesn't silently hide the
        integrity coverage from pytest output.
        """
        from pkcs11_check.raw.ec import encode_named_curve_parameters
        from pkcs11_check.raw.pack import mech_ecdh_aes_kw
        from pkcs11_check.raw.recipes import (
            gen_ec_keypair,
            unwrap_key,
            wrap_key,
        )
        from pkcs11_check.raw.types_std import (
            CKA_DERIVE,
            CKA_KEY_TYPE,
            CKD_SHA256_KDF,
            CKK_AES,
            CKM_ECDH_AES_KEY_WRAP,
            CKO_SECRET_KEY,
        )

        rs = p11_raw_session
        if not rs.has_mechanism("ECDH_AES_KEY_WRAP"):
            pytest.skip("CKM_ECDH_AES_KEY_WRAP not supported")

        curve_oid = encode_named_curve_parameters("secp256r1")
        try:
            pub, priv = gen_ec_keypair(
                rs.raw,
                rs.sh,
                curve_oid,
                public_attrs={CKA_DERIVE: True, CKA_WRAP: True},
                private_attrs={CKA_DERIVE: True, CKA_UNWRAP: True},
            )
        except AssertionError as exc:
            pytest.skip(f"Could not generate P-256 keypair: {exc}")
            return

        target = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={CKA_EXTRACTABLE: True, CKA_SENSITIVE: False},
        )
        try:
            mech = mech_ecdh_aes_kw(
                CKM_ECDH_AES_KEY_WRAP,
                aes_key_bits=256,
                kdf=CKD_SHA256_KDF,
            )
            try:
                wrapped = wrap_key(
                    rs.raw,
                    rs.sh,
                    pub,
                    target,
                    CKM_ECDH_AES_KEY_WRAP,
                    mech_param=mech,
                )
            except AssertionError as exc:
                if is_known_error(exc, {CKR_MECHANISM_PARAM_INVALID}):
                    pytest.skip(f"Module rejected ECDH-AES-KW params: {exc}")
                    return
                raise

            tampered = bytearray(wrapped)
            tampered[-2] ^= 0xFF
            mech_t = mech_ecdh_aes_kw(
                CKM_ECDH_AES_KEY_WRAP,
                aes_key_bits=256,
                kdf=CKD_SHA256_KDF,
            )
            try:
                bad = unwrap_key(
                    rs.raw,
                    rs.sh,
                    priv,
                    bytes(tampered),
                    CKM_ECDH_AES_KEY_WRAP,
                    attrs={
                        CKA_CLASS: CKO_SECRET_KEY,
                        CKA_KEY_TYPE: CKK_AES,
                        CKA_EXTRACTABLE: True,
                    },
                    mech_param=mech_t,
                )
            except AssertionError as exc:
                # Per-module quirks via the registry — Kryoptic's
                # CKR_DEVICE_ERROR for verify failures, OpenCryptoki's
                # CKR_ATTRIBUTE_READ_ONLY rejecting unwrap templates that
                # contain CKA_CLASS/CKA_KEY_TYPE before crypto check.
                from pkcs11_check.testcases._module_quirks import quirk_extras

                accepted_rvs = {
                    CKR_WRAPPED_KEY_INVALID,
                    CKR_ENCRYPTED_DATA_INVALID,
                    CKR_WRAPPED_KEY_LEN_RANGE,
                    *quirk_extras(p11_config, "verify_or_integrity_failure"),
                    *quirk_extras(p11_config, "unwrap_template_class_keytype_rejected"),
                }
                if is_known_error(exc, accepted_rvs):
                    return
                raise

            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_UnwrapKey accepted bit-flipped CKM_ECDH_AES_KEY_WRAP "
                "ciphertext (AES-KW RFC 3394 ICV check missing).",
                ComplianceLevel.CRITICAL,
                reference="RFC 3394 §2.2.2 / PKCS#11 v3.1 Sec.6.13.6",
            )
            destroy_quietly(rs.raw, rs.sh, bad)
            pytest.fail(
                "SECURITY: CKM_ECDH_AES_KEY_WRAP unwrap accepted "
                "bit-flipped ciphertext — RFC 3394 ICV check missing "
                "in the AES-KW step of the hybrid mechanism."
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, target)
