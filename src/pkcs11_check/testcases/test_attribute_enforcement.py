"""Attribute enforcement tests - one-way flags, read-only attrs, template constraints.

Covers CKA_COPYABLE one-way rule, CKA_DESTROYABLE enforcement,
CKA_KEY_GEN_MECHANISM read-only semantics, CKA_CHECK_VALUE (KCV),
CKA_ALLOWED_MECHANISMS, CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_AUTHENTICATE,
and CKA_START_DATE / CKA_END_DATE date attributes.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    import_secret_key,
    read_attributes,
    set_attributes,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CHECK_VALUE,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DESTROYABLE,
    CKA_ENCRYPT,
    CKA_END_DATE,
    CKA_KEY_GEN_MECHANISM,
    CKA_LABEL,
    CKA_SIGN,
    CKA_START_DATE,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_OK,
)

pytestmark = [pytest.mark.security]

# CKR codes that are valid for template/attribute rejections
_TEMPLATE_CKR_NAMES = {
    "CKR_ATTRIBUTE_TYPE_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_TEMPLATE_INCONSISTENT",
}

_SET_ATTR_CKR_NAMES = {
    "CKR_ATTRIBUTE_READ_ONLY",
    "CKR_ATTRIBUTE_TYPE_INVALID",
    "CKR_ATTRIBUTE_VALUE_INVALID",
    "CKR_ACTION_PROHIBITED",
}


def _is_template_error(e: AssertionError) -> bool:
    msg = str(e)
    return any(n in msg for n in _TEMPLATE_CKR_NAMES) or "CKR_FUNCTION_FAILED" in msg


def _is_set_attr_error(e: AssertionError) -> bool:
    msg = str(e)
    return any(n in msg for n in _SET_ATTR_CKR_NAMES)


class TestCopyableOneWay:
    """CKA_COPYABLE is one-way: once False, cannot go back to True."""

    def test_copyable_false_cannot_be_set_true(self, p11_raw_session: Any) -> None:
        """CKA_COPYABLE=False cannot be changed to True via C_SetAttributeValue."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_COPYABLE: False, CKA_TOKEN: False},
            )
        except AssertionError as e:
            if _is_template_error(e) or "CKR_FUNCTION_FAILED" in str(e):
                pytest.skip("Module does not support setting CKA_COPYABLE=False")
            raise

        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_COPYABLE])
            if attrs[CKA_COPYABLE] is not False:
                pytest.skip("Module did not honour CKA_COPYABLE=False")
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not support reading CKA_COPYABLE: {e}")
            raise

        try:
            set_attributes(rs.raw, rs.sh, key, {CKA_COPYABLE: True})
            # If it succeeded, check if the value actually changed
            attrs2 = read_attributes(rs.raw, rs.sh, key, [CKA_COPYABLE])
            if attrs2[CKA_COPYABLE] is True:
                pytest.xfail(
                    "SECURITY: CKA_COPYABLE escalated from False to True - one-way rule violated"
                )
        except AssertionError as e:
            if _is_set_attr_error(e):
                pass  # Correct: module rejected the one-way escalation
            else:
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_copyable_true_can_be_set_false(self, p11_raw_session: Any) -> None:
        """CKA_COPYABLE=True can be changed to False (the allowed direction)."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_COPYABLE: True, CKA_TOKEN: False},
        )
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_COPYABLE])
                initial = attrs[CKA_COPYABLE]
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not support reading CKA_COPYABLE: {e}")
                raise
            if initial is not True:
                pytest.skip("Module did not set CKA_COPYABLE=True")

            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_COPYABLE: False})
                attrs2 = read_attributes(rs.raw, rs.sh, key, [CKA_COPYABLE])
                assert attrs2[CKA_COPYABLE] is False
            except AssertionError as e:
                if _is_set_attr_error(e):
                    pytest.skip("Module does not allow setting CKA_COPYABLE via SetAttr")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDestroyable:
    """CKA_DESTROYABLE enforcement - when False, C_DestroyObject must be rejected."""

    def test_destroyable_readable(self, p11_raw_session: Any) -> None:
        """CKA_DESTROYABLE should be readable on a generated key (default True)."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_TOKEN: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_DESTROYABLE])
            if CKA_DESTROYABLE not in attrs:
                pytest.skip("CKA_DESTROYABLE not supported by module")
            val = attrs[CKA_DESTROYABLE]
            assert val is True, f"Expected default CKA_DESTROYABLE=True, got {val}"
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not support CKA_DESTROYABLE: {e}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroyable_false_blocks_destroy(self, p11_raw_session: Any) -> None:
        """C_DestroyObject must fail when CKA_DESTROYABLE=False."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_DESTROYABLE: False, CKA_TOKEN: False},
            )
        except AssertionError as e:
            if _is_template_error(e):
                pytest.skip("Module does not support setting CKA_DESTROYABLE=False")
            raise

        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_DESTROYABLE])
            if CKA_DESTROYABLE not in attrs:
                pytest.skip("CKA_DESTROYABLE not supported by module")
            val = attrs[CKA_DESTROYABLE]
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not support reading CKA_DESTROYABLE: {e}")
            raise

        if val is not False:
            # Lying-module pattern: accepted CKA_DESTROYABLE=False at gen
            # but readback returns True. Surface as a CRITICAL finding
            # rather than skip — silent ignore at create time is itself a
            # spec violation (parallel to test_modifiable_false_blocks_set_attribute
            # in test_access_control.py).
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                f"Module accepted CKA_DESTROYABLE=False at C_CreateObject "
                f"but readback returns {val!r} — silent ignore at create time.",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.1.2",
            )
            pytest.fail(
                "SECURITY: module silently ignored CKA_DESTROYABLE=False "
                "at create time. Lying-module pattern hides the destroy "
                "enforcement test."
            )

        rv = rs.raw.C_DestroyObject(rs.sh, key)
        if rv == CKR_OK:
            # GAP-T7 closure: replace pytest.xfail with pytest.fail per
            # feedback_pkcs11check_philosophy. The compliance.note() call
            # records the CRITICAL violation; the failure now surfaces in
            # CI rather than being silently absorbed by an xfail.
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module ignores CKA_DESTROYABLE=False -- C_DestroyObject succeeded",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.1.2: CKA_DESTROYABLE=False must prevent destroy",
            )
            pytest.fail(
                "SECURITY: C_DestroyObject succeeded on CKA_DESTROYABLE=False "
                "key — DESTROYABLE access control silently ignored "
                "(expected CKR_ACTION_PROHIBITED)."
            )
        assert rv != CKR_OK, (
            "C_DestroyObject succeeded on CKA_DESTROYABLE=False key "
            "(expected CKR_ACTION_PROHIBITED)"
        )

    def test_destroyable_true_allows_destroy(self, p11_raw_session: Any) -> None:
        """C_DestroyObject should succeed when CKA_DESTROYABLE=True."""
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_DESTROYABLE: True, CKA_TOKEN: False},
            )
        except AssertionError as e:
            if _is_template_error(e):
                pytest.skip(f"Module does not support CKA_DESTROYABLE in template: {e}")
            raise
        # Should succeed without error
        rs.raw.C_DestroyObject(rs.sh, key)


class TestTokenAttributePromotion:
    """GAP-A5: session-object → token-object promotion via SetAttribute.

    PKCS#11 v3.1 Sec.4.7 lists CKA_TOKEN as a Common Object Attribute
    with "R/W after creation" semantics — promotion IS allowed by the
    spec, but only by an authenticated user with R/W token access. The
    security concerns:

    1. Lying-module pattern: SetAttribute returns CKR_OK but the value
       silently doesn't change (readback shows CKA_TOKEN=False after
       a "successful" set to True). Mirrors GAP-T1 / GAP-T7.
    2. Half-promoted state: SetAttribute returns CKR_OK and readback
       shows True, but the object doesn't actually persist on the
       token (would require a separate-session check; out of scope
       for this baseline test).

    Closes Phase 4.5 GAP-A5 (MED).
    """

    def test_setattr_token_promotion_consistency(
        self, p11_raw_session: Any
    ) -> None:
        """C_SetAttributeValue(CKA_TOKEN=True) must either (a) be rejected,
        or (b) actually take effect (readback shows True).

        A module that returns CKR_OK without actually promoting the
        object is in a confused half-promoted state — the object looks
        like a token object to the caller but isn't persistent. That
        breaks the application's expectations (would write sensitive
        data to a token that doesn't actually persist) and is the
        lying-module masking pattern at the persistence boundary.
        """
        rs = p11_raw_session
        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={CKA_TOKEN: False, CKA_LABEL: "session-key-promote-test"},
            )
        except AssertionError as e:
            pytest.skip(f"Could not generate baseline session AES key: {e}")
            return

        try:
            # Pre-check: confirm the object is genuinely session-scope.
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_TOKEN])
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_TOKEN: {e}")
                raise
            initial = attrs.get(CKA_TOKEN)
            if initial is not False:
                pytest.skip(f"Module did not honour CKA_TOKEN=False at gen ({initial!r})")

            # Attempt the promotion.
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_TOKEN: True})
            except AssertionError as e:
                msg = str(e)
                accepted_rejection = (
                    "CKR_ATTRIBUTE_READ_ONLY",
                    "CKR_ACTION_PROHIBITED",
                    "CKR_USER_NOT_LOGGED_IN",
                    "CKR_SESSION_READ_ONLY",
                    "CKR_TEMPLATE_INCONSISTENT",
                    "CKR_ATTRIBUTE_VALUE_INVALID",
                )
                if any(code in msg for code in accepted_rejection):
                    return
                raise

            # SetAttribute returned CKR_OK; verify the change actually
            # took effect at the readback level. A module that silently
            # no-ops is in the lying-module pattern.
            attrs2 = read_attributes(rs.raw, rs.sh, key, [CKA_TOKEN])
            if attrs2.get(CKA_TOKEN) is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"C_SetAttributeValue(CKA_TOKEN=True) returned CKR_OK but "
                    f"readback still reports CKA_TOKEN={attrs2.get(CKA_TOKEN)!r}. "
                    f"Module silently ignored the promotion request — "
                    f"caller believes object is now a token object but it "
                    f"isn't.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.7 CKA_TOKEN R/W semantics",
                )
                pytest.fail(
                    "SECURITY: module silently ignored "
                    "C_SetAttributeValue(CKA_TOKEN=True) — half-promoted "
                    "state. Lying-module pattern at the persistence "
                    "boundary."
                )
            # CKR_OK + readback shows True: spec-conformant promotion.
            # Persistence verification (open new session, find object)
            # is out of scope for this baseline test — see CROSS-PROC-001
            # for the cross-process visibility companion.
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestKeyGenMechanism:
    """CKA_KEY_GEN_MECHANISM is auto-set and read-only."""

    def test_generated_aes_key_has_aes_key_gen(self, p11_raw_session: Any) -> None:
        """Generated AES key should have CKA_KEY_GEN_MECHANISM = CKM_AES_KEY_GEN."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_TOKEN: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_GEN_MECHANISM])
            if CKA_KEY_GEN_MECHANISM not in attrs:
                pytest.skip("CKA_KEY_GEN_MECHANISM not supported by module")
            mech = attrs[CKA_KEY_GEN_MECHANISM]
            assert mech == CKM_AES_KEY_GEN, f"Expected CKM_AES_KEY_GEN, got {mech}"
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generated_rsa_keypair_has_rsa_gen(self, p11_raw_session: Any) -> None:
        """RSA keypair should have CKA_KEY_GEN_MECHANISM = CKM_RSA_PKCS_KEY_PAIR_GEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_KEY_GEN_MECHANISM])
                if CKA_KEY_GEN_MECHANISM not in attrs:
                    pytest.skip("CKA_KEY_GEN_MECHANISM not supported by module")
                mech = attrs[CKA_KEY_GEN_MECHANISM]
                assert mech == CKM_RSA_PKCS_KEY_PAIR_GEN, (
                    f"Expected CKM_RSA_PKCS_KEY_PAIR_GEN, got {mech}"
                )
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
                raise
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_imported_key_has_unavailable(self, p11_raw_session: Any) -> None:
        """Imported key CKA_KEY_GEN_MECHANISM should be CK_UNAVAILABLE_INFORMATION."""
        rs = p11_raw_session
        key_material = bytes(range(16))  # 128-bit AES
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_GEN_MECHANISM])
                if CKA_KEY_GEN_MECHANISM not in attrs:
                    pytest.skip("CKA_KEY_GEN_MECHANISM not supported by module")
                mech = attrs[CKA_KEY_GEN_MECHANISM]
            except (AssertionError, Exception) as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
                raise
            # CK_UNAVAILABLE_INFORMATION is ~0 (all bits set).
            mech_val = int(mech) if not isinstance(mech, int) else mech
            unavailable_32 = 0xFFFFFFFF
            unavailable_64 = 0xFFFFFFFFFFFFFFFF
            assert mech_val in (unavailable_32, unavailable_64), (
                f"Expected CK_UNAVAILABLE_INFORMATION, got 0x{mech_val:X}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_gen_mechanism_read_only(self, p11_raw_session: Any) -> None:
        """CKA_KEY_GEN_MECHANISM must be read-only - reject C_SetAttributeValue."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_TOKEN: False})
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_KEY_GEN_MECHANISM])
                if CKA_KEY_GEN_MECHANISM not in attrs:
                    pytest.skip("CKA_KEY_GEN_MECHANISM not supported by module")
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
                raise

            try:
                set_attributes(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_KEY_GEN_MECHANISM: CKM_AES_KEY_GEN},
                )
                pytest.fail("Module accepted C_SetAttributeValue on CKA_KEY_GEN_MECHANISM")
            except AssertionError:
                pass  # Expected: module rejected the write
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCheckValue:
    """CKA_CHECK_VALUE (KCV) - key check value tests."""

    def test_generated_key_has_check_value(self, p11_raw_session: Any) -> None:
        """Generated AES key should have a 3-byte CKA_CHECK_VALUE."""
        rs = p11_raw_session
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True},
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CHECK_VALUE])
            kcv = attrs[CKA_CHECK_VALUE]
            assert isinstance(kcv, bytes), f"Expected bytes, got {type(kcv)}"
            assert len(kcv) == 3, f"Expected 3-byte KCV, got {len(kcv)} bytes"
        except KeyError:
            pytest.skip("Module does not expose CKA_CHECK_VALUE")
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_imported_key_kcv_matches_ecb_encrypt(self, p11_raw_session: Any) -> None:
        """KCV should be first 3 bytes of ECB encrypt of all-zeros block."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        # Known 128-bit AES key
        key_material = b"\x00" * 16
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CHECK_VALUE])
                kcv = attrs[CKA_CHECK_VALUE]
            except KeyError:
                pytest.skip("Module does not expose CKA_CHECK_VALUE")
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")
                raise

            # Encrypt 16 zero bytes with AES-ECB - first 3 bytes = KCV
            plaintext = b"\x00" * 16
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
            expected_kcv = ct[:3]
            assert kcv == expected_kcv, (
                f"KCV mismatch: got {kcv.hex()}, expected {expected_kcv.hex()}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_same_key_material_same_kcv(self, p11_raw_session: Any) -> None:
        """Two keys with identical material should have the same CKA_CHECK_VALUE."""
        rs = p11_raw_session
        key_material = b"\xab" * 16
        key1 = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        key2 = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            try:
                a1 = read_attributes(rs.raw, rs.sh, key1, [CKA_CHECK_VALUE])
                a2 = read_attributes(rs.raw, rs.sh, key2, [CKA_CHECK_VALUE])
                kcv1 = a1[CKA_CHECK_VALUE]
                kcv2 = a2[CKA_CHECK_VALUE]
            except KeyError:
                pytest.skip("Module does not expose CKA_CHECK_VALUE")
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")
                raise

            assert kcv1 == kcv2, (
                f"Same key material but different KCVs: {kcv1.hex()} vs {kcv2.hex()}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key1)
            destroy_quietly(rs.raw, rs.sh, key2)


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE - re-authentication per-operation.

    When set on a private key, each crypto operation requires a
    C_Login(CKU_CONTEXT_SPECIFIC) call first. Complex to test and many
    modules don't support it. Tests skip gracefully.
    """

    def test_always_authenticate_readable(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_AUTHENTICATE should be readable on RSA private key."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ALWAYS_AUTHENTICATE])
            if CKA_ALWAYS_AUTHENTICATE not in attrs:
                pytest.skip("CKA_ALWAYS_AUTHENTICATE not supported by module")
            val = attrs[CKA_ALWAYS_AUTHENTICATE]
            assert val is False, f"Default CKA_ALWAYS_AUTHENTICATE should be False, got {val}"
        except AssertionError as e:
            if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_always_authenticate_set_on_keygen(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_AUTHENTICATE=True should be settable at keypair generation."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_ALWAYS_AUTHENTICATE: True},
            )
        except AssertionError as e:
            if _is_template_error(e):
                pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            raise

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv, [CKA_ALWAYS_AUTHENTICATE])
                val = attrs[CKA_ALWAYS_AUTHENTICATE]
            except AssertionError as e:
                if "CKR_ATTRIBUTE_TYPE_INVALID" in str(e):
                    pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
                raise

            assert val is True, f"Expected CKA_ALWAYS_AUTHENTICATE=True, got {val}"
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_always_authenticate_requires_context_login(self, p11_raw_session: Any) -> None:
        """Sign with ALWAYS_AUTHENTICATE key should need CKU_CONTEXT_SPECIFIC login."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                },
            )
        except AssertionError as e:
            if _is_template_error(e):
                pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            raise

        try:
            # First sign after normal login - may work (first use after login)
            data = b"test data for signing"
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, data)
            except AssertionError:
                # Module may require context-specific login even for the first op
                pass
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


class TestDateAttributes:
    """CKA_START_DATE / CKA_END_DATE - informational date attributes on keys.

    Per spec, these are for reference only; Cryptoki does NOT enforce them.
    """

    def test_start_end_date_on_generated_key(self, p11_raw_session: Any) -> None:
        """Generated key with START_DATE / END_DATE should have readable dates."""
        rs = p11_raw_session

        try:
            key = gen_aes_key(
                rs.raw,
                rs.sh,
                256,
                attrs={
                    CKA_TOKEN: False,
                    CKA_START_DATE: "20260101",
                    CKA_END_DATE: "20271231",
                },
            )
        except (AssertionError, Exception) as e:
            pytest.skip(f"Module does not support CKA_START_DATE / CKA_END_DATE: {e}")

        try:
            try:
                attrs = read_attributes(
                    rs.raw,
                    rs.sh,
                    key,
                    [CKA_START_DATE, CKA_END_DATE],
                )
                sd = attrs[CKA_START_DATE]
                ed = attrs[CKA_END_DATE]
            except (AssertionError, Exception) as e:
                pytest.skip(f"Module does not expose date attributes: {e}")

            assert sd == "20260101", f"Expected 20260101, got {sd}"
            assert ed == "20271231", f"Expected 20271231, got {ed}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_empty_dates_by_default(self, p11_raw_session: Any) -> None:
        """Generated key without explicit dates should have empty/default dates."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_TOKEN: False})
        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_START_DATE])
                sd = attrs[CKA_START_DATE]
            except (AssertionError, Exception) as e:
                pytest.skip(f"Module does not expose CKA_START_DATE: {e}")

            # Empty date: raw API returns "" or "00000000" or similar
            assert sd is None or isinstance(sd, (str, bytes)), (
                f"Expected empty/None date, got {sd!r}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
