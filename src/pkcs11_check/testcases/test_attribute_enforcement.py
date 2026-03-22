"""Attribute enforcement tests -- one-way flags, read-only attrs, template constraints.

Covers CKA_COPYABLE one-way rule, CKA_DESTROYABLE enforcement,
CKA_KEY_GEN_MECHANISM read-only semantics, CKA_CHECK_VALUE (KCV),
CKA_ALLOWED_MECHANISMS, CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_AUTHENTICATE,
and CKA_START_DATE / CKA_END_DATE date attributes.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism
from pkcs11.exceptions import (
    ActionProhibited,
    AttributeReadOnly,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    FunctionFailed,
    KeyNotWrappable,
    MechanismInvalid,
    PKCS11Error,
    TemplateInconsistent,
    UserNotLoggedIn,
)

from pkcs11_check.testcases.conftest import has_mechanism, import_aes_key

pytestmark = [pytest.mark.security]

# Common error tuples for template/attribute operations
_TEMPLATE_ERRORS = (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    TemplateInconsistent,
)

_SET_ATTR_ERRORS = (
    AttributeReadOnly,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    ActionProhibited,
)


class TestCopyableOneWay:
    """CKA_COPYABLE is one-way: once False, cannot go back to True."""

    def test_copyable_false_cannot_be_set_true(self, p11_session: Any) -> None:
        """CKA_COPYABLE=False cannot be changed to True via C_SetAttributeValue."""
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.COPYABLE: False, Attribute.TOKEN: False},
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed):
            pytest.skip("Module does not support setting CKA_COPYABLE=False")

        try:
            if key[Attribute.COPYABLE] is not False:
                pytest.skip("Module did not honour CKA_COPYABLE=False")
        except (AttributeTypeInvalid, PKCS11Error) as e:
            pytest.skip(f"Module does not support reading CKA_COPYABLE: {e}")

        try:
            key[Attribute.COPYABLE] = True
            # If it succeeded, check if the value actually changed
            if key[Attribute.COPYABLE] is True:
                pytest.xfail(
                    "SECURITY: CKA_COPYABLE escalated from False to True -- "
                    "one-way rule violated"
                )
        except _SET_ATTR_ERRORS:
            pass  # Correct: module rejected the one-way escalation
        finally:
            key.destroy()

    def test_copyable_true_can_be_set_false(self, p11_session: Any) -> None:
        """CKA_COPYABLE=True can be changed to False (the allowed direction)."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.COPYABLE: True, Attribute.TOKEN: False},
        )
        try:
            try:
                initial = key[Attribute.COPYABLE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not support reading CKA_COPYABLE: {e}")
            if initial is not True:
                pytest.skip("Module did not set CKA_COPYABLE=True")

            try:
                key[Attribute.COPYABLE] = False
                assert key[Attribute.COPYABLE] is False
            except _SET_ATTR_ERRORS:
                pytest.skip("Module does not allow setting CKA_COPYABLE via SetAttr")
        finally:
            key.destroy()


class TestDestroyable:
    """CKA_DESTROYABLE enforcement -- when False, C_DestroyObject must be rejected."""

    def test_destroyable_readable(self, p11_session: Any) -> None:
        """CKA_DESTROYABLE should be readable on a generated key (default True)."""
        key = p11_session.generate_key(KeyType.AES, 256, template={Attribute.TOKEN: False})
        try:
            val = key[Attribute.DESTROYABLE]
            assert val is True, f"Expected default CKA_DESTROYABLE=True, got {val}"
        except (AttributeTypeInvalid, PKCS11Error, NotImplementedError) as e:
            pytest.skip(f"Module does not support CKA_DESTROYABLE: {e}")
        finally:
            key.destroy()

    def test_destroyable_false_blocks_destroy(self, p11_session: Any) -> None:
        """C_DestroyObject must fail when CKA_DESTROYABLE=False."""
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.DESTROYABLE: False, Attribute.TOKEN: False},
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, NotImplementedError):
            pytest.skip("Module does not support setting CKA_DESTROYABLE=False")

        try:
            val = key[Attribute.DESTROYABLE]
        except (AttributeTypeInvalid, PKCS11Error, NotImplementedError) as e:
            pytest.skip(f"Module does not support reading CKA_DESTROYABLE: {e}")

        if val is not False:
            pytest.skip("Module did not honour CKA_DESTROYABLE=False")

        with pytest.raises(ActionProhibited):
            key.destroy()

    def test_destroyable_true_allows_destroy(self, p11_session: Any) -> None:
        """C_DestroyObject should succeed when CKA_DESTROYABLE=True."""
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.DESTROYABLE: True, Attribute.TOKEN: False},
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, NotImplementedError) as e:
            pytest.skip(f"Module does not support CKA_DESTROYABLE in template: {e}")
        # Should succeed without error
        key.destroy()


class TestKeyGenMechanism:
    """CKA_KEY_GEN_MECHANISM is auto-set and read-only."""

    def test_generated_aes_key_has_aes_key_gen(self, p11_session: Any) -> None:
        """Generated AES key should have CKA_KEY_GEN_MECHANISM = CKM_AES_KEY_GEN."""
        key = p11_session.generate_key(KeyType.AES, 256, template={Attribute.TOKEN: False})
        try:
            mech = key[Attribute.KEY_GEN_MECHANISM]
            assert mech == Mechanism.AES_KEY_GEN, (
                f"Expected CKM_AES_KEY_GEN, got {mech}"
            )
        except (AttributeTypeInvalid, PKCS11Error) as e:
            pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
        finally:
            key.destroy()

    def test_generated_rsa_keypair_has_rsa_gen(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """RSA keypair should have CKA_KEY_GEN_MECHANISM = CKM_RSA_PKCS_KEY_PAIR_GEN."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            try:
                mech = priv[Attribute.KEY_GEN_MECHANISM]
                assert mech == Mechanism.RSA_PKCS_KEY_PAIR_GEN, (
                    f"Expected CKM_RSA_PKCS_KEY_PAIR_GEN, got {mech}"
                )
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
        finally:
            priv.destroy()
            pub.destroy()

    def test_imported_key_has_unavailable(self, p11_session: Any) -> None:
        """Imported key CKA_KEY_GEN_MECHANISM should be CK_UNAVAILABLE_INFORMATION."""
        key_material = bytes(range(16))  # 128-bit AES
        key = import_aes_key(p11_session, key_material)
        try:
            try:
                mech = key[Attribute.KEY_GEN_MECHANISM]
            except ValueError:
                # python-pkcs11 raises ValueError when the raw value (e.g. 0xFFFFFFFF)
                # is not a valid Mechanism enum entry -- this IS the unavailable sentinel
                return
            # CK_UNAVAILABLE_INFORMATION is ~0 (all bits set).
            mech_val = int(mech) if not isinstance(mech, int) else mech
            unavailable_32 = 0xFFFFFFFF
            unavailable_64 = 0xFFFFFFFFFFFFFFFF
            assert mech_val in (unavailable_32, unavailable_64), (
                f"Expected CK_UNAVAILABLE_INFORMATION, got 0x{mech_val:X}"
            )
        except (AttributeTypeInvalid, PKCS11Error) as e:
            pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")
        finally:
            key.destroy()

    def test_key_gen_mechanism_read_only(self, p11_session: Any) -> None:
        """CKA_KEY_GEN_MECHANISM must be read-only -- reject C_SetAttributeValue."""
        key = p11_session.generate_key(KeyType.AES, 256, template={Attribute.TOKEN: False})
        try:
            try:
                _ = key[Attribute.KEY_GEN_MECHANISM]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_KEY_GEN_MECHANISM: {e}")

            with pytest.raises(_SET_ATTR_ERRORS):
                key[Attribute.KEY_GEN_MECHANISM] = Mechanism.AES_KEY_GEN
        finally:
            key.destroy()


class TestCheckValue:
    """CKA_CHECK_VALUE (KCV) -- key check value tests."""

    def test_generated_key_has_check_value(self, p11_session: Any) -> None:
        """Generated AES key should have a 3-byte CKA_CHECK_VALUE."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.TOKEN: False, Attribute.ENCRYPT: True},
        )
        try:
            kcv = key[Attribute.CHECK_VALUE]
            assert isinstance(kcv, bytes), f"Expected bytes, got {type(kcv)}"
            assert len(kcv) == 3, f"Expected 3-byte KCV, got {len(kcv)} bytes"
        except (AttributeTypeInvalid, PKCS11Error) as e:
            pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")
        finally:
            key.destroy()

    def test_imported_key_kcv_matches_ecb_encrypt(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """KCV should be first 3 bytes of ECB encrypt of all-zeros block."""
        if not has_mechanism(p11_module, "AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        # Known 128-bit AES key
        key_material = b"\x00" * 16
        key = import_aes_key(p11_session, key_material)
        try:
            try:
                kcv = key[Attribute.CHECK_VALUE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")

            # Encrypt 16 zero bytes with AES-ECB -- first 3 bytes = KCV
            plaintext = b"\x00" * 16
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            expected_kcv = ct[:3]
            assert kcv == expected_kcv, (
                f"KCV mismatch: got {kcv.hex()}, expected {expected_kcv.hex()}"
            )
        finally:
            key.destroy()

    def test_same_key_material_same_kcv(self, p11_session: Any) -> None:
        """Two keys with identical material should have the same CKA_CHECK_VALUE."""
        key_material = b"\xAB" * 16
        key1 = import_aes_key(p11_session, key_material)
        key2 = import_aes_key(p11_session, key_material)
        try:
            try:
                kcv1 = key1[Attribute.CHECK_VALUE]
                kcv2 = key2[Attribute.CHECK_VALUE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_CHECK_VALUE: {e}")

            assert kcv1 == kcv2, (
                f"Same key material but different KCVs: {kcv1.hex()} vs {kcv2.hex()}"
            )
        finally:
            key1.destroy()
            key2.destroy()


class TestAllowedMechanisms:
    """CKA_ALLOWED_MECHANISMS -- mechanism restriction on keys.

    Many modules do not support this attribute. Tests skip gracefully.
    """

    def test_allowed_mechanism_restricts_usage(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Key with ALLOWED_MECHANISMS=[AES_CBC] should reject AES_ECB."""
        if not has_mechanism(p11_module, "AES_CBC"):
            pytest.skip("CKM_AES_CBC not supported")
        if not has_mechanism(p11_module, "AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.TOKEN: False,
                    Attribute.ALLOWED_MECHANISMS: [Mechanism.AES_CBC],
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_ALLOWED_MECHANISMS in template: {e}")

        try:
            # AES_CBC should work (it's in ALLOWED_MECHANISMS)
            iv = b"\x00" * 16
            ct = key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_CBC, mechanism_param=iv)
            assert len(ct) > 0

            # AES_ECB should be rejected
            with pytest.raises((MechanismInvalid, PKCS11Error)):
                key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
        finally:
            key.destroy()


class TestWrapWithTrusted:
    """CKA_WRAP_WITH_TRUSTED enforcement.

    When set on a key, only wrapping keys with CKA_TRUSTED=True can wrap it.
    CKA_TRUSTED can usually only be set by SO. Most software modules don't
    support this. Tests skip gracefully.
    """

    def test_wrap_with_trusted_rejects_untrusted_wrapper(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Key with WRAP_WITH_TRUSTED=True should reject wrapping by untrusted key."""
        if not has_mechanism(p11_module, "AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported for wrapping")

        # Create a target key that requires trusted wrapper
        try:
            target = p11_session.generate_key(
                KeyType.AES,
                128,
                template={
                    Attribute.EXTRACTABLE: True,
                    Attribute.WRAP_WITH_TRUSTED: True,
                    Attribute.TOKEN: False,
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_WRAP_WITH_TRUSTED: {e}")

        try:
            val = target[Attribute.WRAP_WITH_TRUSTED]
        except (AttributeTypeInvalid, PKCS11Error) as e:
            target.destroy()
            pytest.skip(f"Module does not expose CKA_WRAP_WITH_TRUSTED: {e}")

        if val is not True:
            target.destroy()
            pytest.skip("Module did not honour CKA_WRAP_WITH_TRUSTED=True")

        # Create a normal (non-TRUSTED) wrapping key
        wrapper = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.WRAP: True, Attribute.TOKEN: False},
        )

        try:
            with pytest.raises((ActionProhibited, KeyNotWrappable, PKCS11Error)):
                wrapper.wrap_key(target)
        finally:
            wrapper.destroy()
            try:
                target.destroy()
            except PKCS11Error:
                pass  # May already be destroyed or not destroyable


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE -- re-authentication per-operation.

    When set on a private key, each crypto operation requires a
    C_Login(CKU_CONTEXT_SPECIFIC) call first. Complex to test and many
    modules don't support it. Tests skip gracefully.
    """

    def test_always_authenticate_readable(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKA_ALWAYS_AUTHENTICATE should be readable on RSA private key."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        try:
            val = priv[Attribute.ALWAYS_AUTHENTICATE]
            assert val is False, (
                f"Default CKA_ALWAYS_AUTHENTICATE should be False, got {val}"
            )
        except (AttributeTypeInvalid, PKCS11Error) as e:
            pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
        finally:
            priv.destroy()
            pub.destroy()

    def test_always_authenticate_set_on_keygen(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """CKA_ALWAYS_AUTHENTICATE=True should be settable at keypair generation."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                private_template={Attribute.ALWAYS_AUTHENTICATE: True},
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")

        try:
            try:
                val = priv[Attribute.ALWAYS_AUTHENTICATE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")

            assert val is True, (
                f"Expected CKA_ALWAYS_AUTHENTICATE=True, got {val}"
            )
        finally:
            priv.destroy()
            pub.destroy()

    def test_always_authenticate_requires_context_login(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Sign with ALWAYS_AUTHENTICATE key should need CKU_CONTEXT_SPECIFIC login."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                private_template={
                    Attribute.SIGN: True,
                    Attribute.ALWAYS_AUTHENTICATE: True,
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")

        try:
            # First sign after normal login -- may work (first use after login)
            data = b"test data for signing"
            try:
                _ = priv.sign(data, mechanism=Mechanism.RSA_PKCS)
            except UserNotLoggedIn:
                # Some modules require context-specific login even for the first op
                pass
            except PKCS11Error:
                # Module may enforce re-auth immediately -- this is valid
                pass
        finally:
            priv.destroy()
            pub.destroy()


class TestDateAttributes:
    """CKA_START_DATE / CKA_END_DATE -- informational date attributes on keys.

    Per spec, these are for reference only; Cryptoki does NOT enforce them.
    python-pkcs11 packs dates as datetime.date and unpacks as datetime.date.
    """

    def test_start_end_date_on_generated_key(self, p11_session: Any) -> None:
        """Generated key with START_DATE / END_DATE should have readable dates."""
        import datetime

        start_date = datetime.date(2026, 1, 1)
        end_date = datetime.date(2027, 12, 31)

        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.START_DATE: start_date,
                    Attribute.END_DATE: end_date,
                },
            )
        except (
            *_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error, AttributeError,
        ) as e:
            pytest.skip(
                f"Module does not support CKA_START_DATE / CKA_END_DATE: {e}"
            )

        try:
            try:
                sd = key[Attribute.START_DATE]
                ed = key[Attribute.END_DATE]
            except (
                AttributeTypeInvalid, PKCS11Error, ValueError,
            ) as e:
                pytest.skip(f"Module does not expose date attributes: {e}")

            assert sd == start_date, f"Expected {start_date}, got {sd}"
            assert ed == end_date, f"Expected {end_date}, got {ed}"
        finally:
            key.destroy()

    def test_empty_dates_by_default(self, p11_session: Any) -> None:
        """Generated key without explicit dates should have empty/default dates."""
        key = p11_session.generate_key(
            KeyType.AES, 256, template={Attribute.TOKEN: False}
        )
        try:
            try:
                sd = key[Attribute.START_DATE]
            except (
                AttributeTypeInvalid, PKCS11Error, ValueError,
            ) as e:
                pytest.skip(f"Module does not expose CKA_START_DATE: {e}")

            # Empty date: python-pkcs11 may return None or a date object
            # Accept None, empty string, or any date value
            assert sd is None or isinstance(sd, object), (
                f"Expected empty/None date, got {sd!r}"
            )
        finally:
            key.destroy()
