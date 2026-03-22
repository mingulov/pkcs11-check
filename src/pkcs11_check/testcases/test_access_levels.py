"""SO vs USER vs public access level tests.

Verifies visibility, operational capabilities, and mutual exclusion for
the three PKCS#11 access levels: public (no login), USER, and SO.
Also covers CKA_TRUSTED, CKA_WRAP_WITH_TRUSTED, and CKA_ALWAYS_AUTHENTICATE
enforcement at the access-level boundary.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    ActionProhibited,
    AnotherUserAlreadyLoggedIn,
    AttributeTypeInvalid,
    AttributeValueInvalid,
    FunctionFailed,
    FunctionNotSupported,
    KeyNotWrappable,
    PinIncorrect,
    PKCS11Error,
    SessionReadOnly,
    SessionReadOnlyExists,
    TemplateIncomplete,
    TemplateInconsistent,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    UserTypeInvalid,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.access

_TEMPLATE_ERRORS = (
    AttributeTypeInvalid,
    AttributeValueInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_pin(p11_config: Any) -> str | None:
    """Extract PIN string from config, or None."""
    return p11_config.pin.get_secret_value() if p11_config.pin else None


def _login_user(session: Any, pin: str | None) -> None:
    """Login as USER, tolerating already-logged-in at token level."""
    if pin is None:
        return
    try:
        session.login(p11.UserType.USER, pin)
    except (UserAlreadyLoggedIn, UserTypeInvalid):
        pass


def _logout_safe(session: Any) -> None:
    """Logout ignoring not-logged-in or closed-session errors."""
    try:
        session.logout()
    except (UserNotLoggedIn, p11.exceptions.SessionClosed):
        pass


# ---------------------------------------------------------------------------
# Public session (no login) visibility
# ---------------------------------------------------------------------------


class TestPublicSessionVisibility:
    """Verify what a public (no-login) session can and cannot see/do."""

    def test_public_sees_non_private_objects(self, p11_module: Any, p11_config: Any) -> None:
        """Public session can see CKA_PRIVATE=False objects."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"pub-vis-{id(self)}"

        # Create a non-private object while logged in
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"public-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )
        finally:
            _logout_safe(session)
            session.close()

        # Open public session (no login) and check visibility
        pub_session = token.open(rw=False)
        try:
            found = list(
                pub_session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                    }
                )
            )
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_PRIVATE=False object not visible in public session",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: public objects visible without login",
                )
        finally:
            pub_session.close()

        # Cleanup
        cleanup = token.open(rw=True)
        try:
            _login_user(cleanup, pin)
            for obj in cleanup.get_objects(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                }
            ):
                obj.destroy()
        finally:
            _logout_safe(cleanup)
            cleanup.close()

    def test_public_cannot_see_private_objects(self, p11_module: Any, p11_config: Any) -> None:
        """Public session cannot see CKA_PRIVATE=True objects."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"priv-invis-{id(self)}"

        # Create a private token object while logged in
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )
        finally:
            _logout_safe(session)
            session.close()

        # Open public session -- private objects must not be visible
        pub_session = token.open(rw=False)
        try:
            found = list(
                pub_session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.LABEL: label,
                    }
                )
            )
            assert len(found) == 0, "CKA_PRIVATE=True object visible in public session"
        finally:
            pub_session.close()

        # Cleanup
        cleanup = token.open(rw=True)
        try:
            _login_user(cleanup, pin)
            for obj in cleanup.get_objects({Attribute.LABEL: label}):
                obj.destroy()
        finally:
            _logout_safe(cleanup)
            cleanup.close()

    def test_public_session_can_digest(self, p11_module: Any, p11_config: Any) -> None:
        """Public session can perform digest operations (no login needed)."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            digest = session.digest(b"public digest", mechanism=Mechanism.SHA256)
            assert len(digest) == 32
        finally:
            session.close()

    def test_public_session_can_generate_random(self, p11_module: Any, p11_config: Any) -> None:
        """Public session can generate random (no login needed)."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            rand = session.generate_random(128)
            assert len(rand) == 16  # 128 bits = 16 bytes
        finally:
            session.close()


# ---------------------------------------------------------------------------
# USER session visibility and capabilities
# ---------------------------------------------------------------------------


class TestUserSessionCapabilities:
    """Verify USER session access level."""

    def test_user_sees_private_objects(self, p11_module: Any, p11_config: Any) -> None:
        """USER session sees CKA_PRIVATE=True objects."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"user-priv-{id(self)}"

        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            key = session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )
            assert key is not None

            # Verify visible in same session
            found = list(session.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1, "Private object not visible in USER session"

            # Cleanup
            for obj in session.get_objects({Attribute.LABEL: label}):
                obj.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_user_sees_non_private_objects(self, p11_module: Any, p11_config: Any) -> None:
        """USER session also sees CKA_PRIVATE=False objects."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"user-pub-{id(self)}"

        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"pub-data",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )
            found = list(
                session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                    }
                )
            )
            assert len(found) >= 1, "Public object not visible in USER session"
            for obj in session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                }
            ):
                obj.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_user_can_create_and_destroy_objects(self, p11_session: Any) -> None:
        """USER session can create and destroy objects."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={Attribute.TOKEN: False, Attribute.LABEL: "user-create-test"},
        )
        assert key is not None
        key.destroy()

    def test_user_can_encrypt_decrypt(self, p11_session: Any, p11_module: Any) -> None:
        """USER session can perform crypto operations on private keys."""
        if not has_mechanism(p11_module, "AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")

        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.TOKEN: False,
                Attribute.PRIVATE: True,
            },
        )
        try:
            iv = b"\x00" * 16
            ct = key.encrypt(
                b"sixteen byte msg",
                mechanism=Mechanism.AES_CBC_PAD,
                mechanism_param=iv,
            )
            pt = key.decrypt(
                ct,
                mechanism=Mechanism.AES_CBC_PAD,
                mechanism_param=iv,
            )
            assert pt == b"sixteen byte msg"
        finally:
            key.destroy()

    def test_user_cannot_login_as_so(self, p11_session: Any, p11_config: Any) -> None:
        """USER session cannot switch to SO login."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        with pytest.raises(
            (
                UserAlreadyLoggedIn,
                AnotherUserAlreadyLoggedIn,
                UserTypeInvalid,
            )
        ):
            p11_session.login(p11.UserType.SO, pin)


# ---------------------------------------------------------------------------
# SO session capabilities
# ---------------------------------------------------------------------------


class TestSOSessionCapabilities:
    """Verify SO access level capabilities.

    All tests marked @destructive because SO login may affect token state.
    """

    @pytest.mark.destructive
    def test_so_login_succeeds_on_rw_session(self, p11_module: Any, p11_config: Any) -> None:
        """SO login succeeds on RW session when no USER is logged in."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)

        # Clear any existing login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, pin)
        except PinIncorrect:
            pytest.skip("SO PIN differs from user PIN on this module")
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            pytest.skip("Another user already logged in on this token")
        else:
            # Verify SO is logged in by attempting USER login (should fail)
            with pytest.raises(
                (
                    UserAlreadyLoggedIn,
                    AnotherUserAlreadyLoggedIn,
                    UserTypeInvalid,
                )
            ):
                session.login(p11.UserType.USER, pin)
        finally:
            _logout_safe(session)
            session.close()

    @pytest.mark.destructive
    def test_so_can_init_pin(self, p11_module: Any, p11_config: Any) -> None:
        """SO session can set USER PIN via C_InitPIN (or skip if unsupported).

        Note: This changes and restores the USER PIN. Marked destructive.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)

        # Clear any existing login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, pin)
        except PinIncorrect:
            session.close()
            pytest.skip("SO PIN differs from user PIN on this module")
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            session.close()
            pytest.skip("Another user already logged in on this token")

        new_pin = pin + "X"
        try:
            session.init_pin(new_pin)
        except (FunctionNotSupported, AttributeError, PKCS11Error) as e:
            pytest.skip(f"C_InitPIN not supported: {e}")
        finally:
            # Restore original PIN: logout SO, login USER with new PIN, set back
            _logout_safe(session)
            session.close()

            restore = token.open(rw=True)
            try:
                restore.login(p11.UserType.USER, new_pin)
                restore.set_pin(new_pin, pin)
            except PKCS11Error:
                # Best-effort restore; if it fails, token may need re-init
                pass
            finally:
                _logout_safe(restore)
                restore.close()

    @pytest.mark.destructive
    def test_so_cannot_use_private_crypto_keys(self, p11_module: Any, p11_config: Any) -> None:
        """SO session should not be able to use private crypto keys.

        Per PKCS#11 spec, SO login gives admin capabilities but not
        access to user's private key operations. Some modules may differ.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        if not has_mechanism(p11_module, "AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        token = p11_module.get_token(p11_config.slot)
        label = f"so-no-crypto-{id(self)}"

        # Create a private key while logged in as USER
        user_sess = token.open(rw=True)
        try:
            _login_user(user_sess, pin)
            user_sess.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.ENCRYPT: True,
                    Attribute.LABEL: label,
                },
            )
        finally:
            _logout_safe(user_sess)
            user_sess.close()

        # Login as SO and try to find/use the key
        so_sess = token.open(rw=True)
        try:
            so_sess.login(p11.UserType.SO, pin)
        except PinIncorrect:
            so_sess.close()
            # Cleanup
            cleanup = token.open(rw=True)
            try:
                _login_user(cleanup, pin)
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()
            finally:
                _logout_safe(cleanup)
                cleanup.close()
            pytest.skip("SO PIN differs from user PIN")
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            so_sess.close()
            # Cleanup
            cleanup = token.open(rw=True)
            try:
                _login_user(cleanup, pin)
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()
            finally:
                _logout_safe(cleanup)
                cleanup.close()
            pytest.skip("Another user already logged in")

        try:
            found = list(so_sess.get_objects({Attribute.LABEL: label}))
            if len(found) == 0:
                # SO cannot see private keys -- expected per spec
                pass
            else:
                # SO can see the key; some modules allow this
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "SO session can see CKA_PRIVATE=True USER objects",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: SO should not access user private objects",
                )
        finally:
            _logout_safe(so_sess)
            so_sess.close()

            # Cleanup the key
            cleanup = token.open(rw=True)
            try:
                _login_user(cleanup, pin)
                for obj in cleanup.get_objects({Attribute.LABEL: label}):
                    obj.destroy()
            finally:
                _logout_safe(cleanup)
                cleanup.close()

    @pytest.mark.destructive
    def test_so_user_mutual_exclusion(self, p11_module: Any, p11_config: Any) -> None:
        """SO and USER cannot be logged in simultaneously on the same token."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)

        # Clear any existing login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        # Login as SO first
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, pin)
        except PinIncorrect:
            session.close()
            pytest.skip("SO PIN differs from user PIN")
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            session.close()
            pytest.skip("Another user already logged in")

        try:
            # Try USER login on a second session -- should fail
            s2 = token.open(rw=True)
            try:
                with pytest.raises(
                    (
                        AnotherUserAlreadyLoggedIn,
                        UserAlreadyLoggedIn,
                        UserTypeInvalid,
                    )
                ):
                    s2.login(p11.UserType.USER, pin)
            finally:
                s2.close()
        finally:
            _logout_safe(session)
            session.close()


# ---------------------------------------------------------------------------
# CKA_TRUSTED enforcement
# ---------------------------------------------------------------------------


class TestTrustedAttribute:
    """CKA_TRUSTED enforcement at the access-level boundary.

    CKA_TRUSTED can typically only be set by SO.
    CKA_WRAP_WITH_TRUSTED protects keys from being wrapped by untrusted keys.
    """

    @pytest.mark.destructive
    def test_so_can_set_trusted(self, p11_module: Any, p11_config: Any) -> None:
        """SO session can set CKA_TRUSTED=True on a key (or skip)."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)

        # Clear login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, pin)
        except PinIncorrect:
            session.close()
            pytest.skip("SO PIN differs from user PIN")
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            session.close()
            pytest.skip("Another user already logged in")

        try:
            try:
                key = session.generate_key(
                    KeyType.AES,
                    256,
                    template={
                        Attribute.TOKEN: False,
                        Attribute.WRAP: True,
                        Attribute.TRUSTED: True,
                    },
                )
            except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Module does not support CKA_TRUSTED: {e}",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: CKA_TRUSTED set by SO",
                )
                pytest.skip(f"CKA_TRUSTED not supported: {e}")
                return

            try:
                val = key[Attribute.TRUSTED]
                assert val is True, f"Expected CKA_TRUSTED=True, got {val}"
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_TRUSTED: {e}")
            finally:
                key.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_user_cannot_set_trusted(self, p11_session: Any) -> None:
        """USER session should not be able to set CKA_TRUSTED=True.

        Per spec, CKA_TRUSTED can only be set by SO.
        """
        try:
            key = p11_session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.WRAP: True,
                    Attribute.TRUSTED: True,
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, ActionProhibited, PKCS11Error):
            # Expected: module rejects CKA_TRUSTED from USER
            return

        # If we get here, module allowed it (some modules are lenient)
        try:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "USER session can set CKA_TRUSTED=True (should require SO)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 spec: CKA_TRUSTED set by SO only",
            )
        finally:
            key.destroy()

    def test_wrap_with_trusted_rejects_untrusted(self, p11_session: Any, p11_module: Any) -> None:
        """Without CKA_TRUSTED, wrapping a CKA_WRAP_WITH_TRUSTED key fails."""
        if not has_mechanism(p11_module, "AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported for wrapping")

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
            pytest.skip(f"CKA_WRAP_WITH_TRUSTED not supported: {e}")
            return

        try:
            val = target[Attribute.WRAP_WITH_TRUSTED]
        except (AttributeTypeInvalid, PKCS11Error) as e:
            target.destroy()
            pytest.skip(f"Module does not expose CKA_WRAP_WITH_TRUSTED: {e}")
            return

        if val is not True:
            target.destroy()
            pytest.skip("Module did not honour CKA_WRAP_WITH_TRUSTED=True")
            return

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
            target.destroy()


# ---------------------------------------------------------------------------
# CKA_ALWAYS_AUTHENTICATE
# ---------------------------------------------------------------------------


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE -- context-specific re-authentication.

    Private keys with CKA_ALWAYS_AUTHENTICATE=True require
    C_Login(CKU_CONTEXT_SPECIFIC) before each crypto operation.
    """

    def test_always_authenticate_key_requires_reauth(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Key with CKA_ALWAYS_AUTHENTICATE=True requires context-specific login."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                private_template={
                    Attribute.SIGN: True,
                    Attribute.ALWAYS_AUTHENTICATE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            return

        try:
            try:
                val = priv[Attribute.ALWAYS_AUTHENTICATE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
                return
            if val is not True:
                pytest.skip("Module did not honour CKA_ALWAYS_AUTHENTICATE=True")
                return

            # Attempt to sign -- should require context-specific login
            data = b"test data for always-auth"
            try:
                _ = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                # Some modules allow first op after normal login
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Sign succeeded without context-specific re-auth on "
                    "CKA_ALWAYS_AUTHENTICATE key (first use after login allowed)",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: CKA_ALWAYS_AUTHENTICATE re-auth",
                )
            except (UserNotLoggedIn, PKCS11Error):
                # Expected: module enforces re-auth
                pass
        finally:
            priv.destroy()
            pub.destroy()

    def test_always_authenticate_with_context_login(
        self, p11_session: Any, p11_module: Any, p11_config: Any
    ) -> None:
        """Context-specific login enables crypto on CKA_ALWAYS_AUTHENTICATE key."""
        if not has_mechanism(p11_module, "RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not has_mechanism(p11_module, "SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        try:
            pub, priv = p11_session.generate_keypair(
                KeyType.RSA,
                2048,
                private_template={
                    Attribute.SIGN: True,
                    Attribute.ALWAYS_AUTHENTICATE: True,
                    Attribute.TOKEN: False,
                },
            )
        except (*_TEMPLATE_ERRORS, FunctionFailed, PKCS11Error) as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            return

        try:
            try:
                val = priv[Attribute.ALWAYS_AUTHENTICATE]
            except (AttributeTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
                return
            if val is not True:
                pytest.skip("Module did not honour CKA_ALWAYS_AUTHENTICATE=True")
                return

            # Do context-specific login, then sign
            try:
                p11_session.login(p11.UserType.CONTEXT_SPECIFIC, pin)
            except (UserAlreadyLoggedIn, UserTypeInvalid, PKCS11Error) as e:
                pytest.skip(f"Context-specific login not supported: {e}")
                return

            data = b"context auth test data"
            try:
                sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
                assert len(sig) > 0
            except PKCS11Error as e:
                pytest.skip(f"Sign after context-specific login failed: {e}")
        finally:
            priv.destroy()
            pub.destroy()


# ---------------------------------------------------------------------------
# Access level matrix: PRIVATE x TOKEN combinations
# ---------------------------------------------------------------------------


class TestAccessLevelMatrix:
    """Create objects with various PRIVATE/TOKEN combos, verify visibility."""

    def test_session_public_object_visible_in_public(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=False visible without login."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"sess-pub-{id(self)}"

        # Create session object (PRIVATE=False, TOKEN=False) while logged in
        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)
            s1.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"session-public",
                    Attribute.TOKEN: False,
                    Attribute.PRIVATE: False,
                }
            )

            # Open another session without login on same token
            # Note: session objects may not be visible across sessions
            s2 = token.open(rw=False)
            try:
                found = list(
                    s2.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                # Session objects belong to their session -- may or may not
                # be visible in s2 depending on module and login state
                # This is implementation-defined behavior
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Session-public object not visible in another session "
                        "(implementation-defined)",
                        ComplianceLevel.VENDOR,
                        reference="PKCS#11 spec: session object visibility",
                    )
            finally:
                s2.close()
        finally:
            _logout_safe(s1)
            s1.close()

    def test_token_public_object_visible_in_public(self, p11_module: Any, p11_config: Any) -> None:
        """Token object with PRIVATE=False visible in public session."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"tok-pub-{id(self)}"

        # Create token object
        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)
            s1.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"token-public",
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: False,
                }
            )
        finally:
            _logout_safe(s1)
            s1.close()

        # Check visibility without login
        s2 = token.open(rw=False)
        try:
            found = list(
                s2.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                    }
                )
            )
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Token-public object not visible without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: CKA_PRIVATE=False visible in public",
                )
        finally:
            s2.close()

        # Cleanup
        cleanup = token.open(rw=True)
        try:
            _login_user(cleanup, pin)
            for obj in cleanup.get_objects(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                }
            ):
                obj.destroy()
        finally:
            _logout_safe(cleanup)
            cleanup.close()

    def test_token_private_object_invisible_in_public(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Token object with PRIVATE=True not visible without login."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"tok-priv-{id(self)}"

        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)
            s1.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )
        finally:
            _logout_safe(s1)
            s1.close()

        # Check NOT visible without login
        s2 = token.open(rw=False)
        try:
            found = list(
                s2.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.LABEL: label,
                    }
                )
            )
            assert len(found) == 0, "Token-private object visible in public session"
        finally:
            s2.close()

        # Cleanup
        cleanup = token.open(rw=True)
        try:
            _login_user(cleanup, pin)
            for obj in cleanup.get_objects({Attribute.LABEL: label}):
                obj.destroy()
        finally:
            _logout_safe(cleanup)
            cleanup.close()

    def test_session_private_object_invisible_after_logout(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=True invisible after logout."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = f"sess-priv-{id(self)}"

        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            session.generate_key(
                KeyType.AES,
                128,
                template={
                    Attribute.TOKEN: False,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )

            # Verify visible while logged in
            found = list(session.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1

            # Logout
            session.logout()

            # Should be invisible
            found = list(session.get_objects({Attribute.LABEL: label}))
            assert len(found) == 0, "Session-private object visible after logout"
        finally:
            _logout_safe(session)
            session.close()

    def test_user_session_visibility_matrix(self, p11_module: Any, p11_config: Any) -> None:
        """USER session sees all four PRIVATE x TOKEN combinations."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)

        combos: list[tuple[bool, bool, str]] = [
            (False, False, f"matrix-sf-{id(self)}"),  # session, public
            (False, True, f"matrix-sp-{id(self)}"),  # session, private
            (True, False, f"matrix-tf-{id(self)}"),  # token, public
            (True, True, f"matrix-tp-{id(self)}"),  # token, private
        ]

        session = token.open(rw=True)
        created_labels: list[str] = []
        try:
            _login_user(session, pin)
            for is_token, is_private, label in combos:
                session.create_object(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                        Attribute.VALUE: b"matrix-data",
                        Attribute.TOKEN: is_token,
                        Attribute.PRIVATE: is_private,
                    }
                )
                created_labels.append(label)

            # USER should see all four
            for label in created_labels:
                found = list(
                    session.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.DATA,
                            Attribute.LABEL: label,
                        }
                    )
                )
                assert len(found) >= 1, f"USER session cannot see object with label {label}"
        finally:
            # Cleanup token objects
            for label in created_labels:
                for obj in session.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                    }
                ):
                    try:
                        obj.destroy()
                    except PKCS11Error:
                        pass
            _logout_safe(session)
            session.close()


# ---------------------------------------------------------------------------
# SO login on RO session (negative test)
# ---------------------------------------------------------------------------


class TestSOOnROSession:
    """SO login requirements."""

    @pytest.mark.destructive
    def test_so_login_rejected_on_ro_session(self, p11_module: Any, p11_config: Any) -> None:
        """C_Login(SO) on R/O session must fail per spec."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            with pytest.raises(
                (
                    SessionReadOnlyExists,
                    SessionReadOnly,
                    UserAlreadyLoggedIn,
                    AnotherUserAlreadyLoggedIn,
                    UserTypeInvalid,
                )
            ):
                session.login(p11.UserType.SO, pin)
        finally:
            _logout_safe(session)
            session.close()


# ---------------------------------------------------------------------------
# Public session cannot create private objects
# ---------------------------------------------------------------------------


class TestPublicSessionRestrictions:
    """Public session operational restrictions."""

    def test_public_cannot_create_private_token_object(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Public session (no login) cannot create CKA_PRIVATE=True token objects."""
        token = p11_module.get_token(p11_config.slot)

        # Clear login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        session = token.open(rw=True)
        try:
            try:
                key = session.generate_key(
                    KeyType.AES,
                    256,
                    template={
                        Attribute.TOKEN: True,
                        Attribute.PRIVATE: True,
                        Attribute.LABEL: "public-no-create",
                    },
                )
                # If it succeeded, some modules don't enforce this
                key.destroy()
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Public session created CKA_PRIVATE=True token object without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: private token objects require login",
                )
            except (
                UserNotLoggedIn,
                ActionProhibited,
                SessionReadOnly,
                *_TEMPLATE_ERRORS,
                PKCS11Error,
            ):
                # Expected: public session cannot create private objects
                pass
        finally:
            session.close()

    def test_public_can_create_non_private_data(self, p11_module: Any, p11_config: Any) -> None:
        """Public session may create CKA_PRIVATE=False data objects."""
        token = p11_module.get_token(p11_config.slot)

        # Clear login
        pre = token.open(rw=True)
        try:
            pre.logout()
        except UserNotLoggedIn:
            pass
        finally:
            pre.close()

        session = token.open(rw=True)
        label = f"pub-create-{id(self)}"
        try:
            try:
                session.create_object(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: label,
                        Attribute.VALUE: b"pub-created",
                        Attribute.TOKEN: True,
                        Attribute.PRIVATE: False,
                    }
                )
            except (
                UserNotLoggedIn,
                ActionProhibited,
                *_TEMPLATE_ERRORS,
                PKCS11Error,
            ):
                # Some modules require login for any creation
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Module requires login to create any objects (even CKA_PRIVATE=False)",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: public objects in public session",
                )
                return

            # Cleanup
            for obj in session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                }
            ):
                obj.destroy()
        finally:
            session.close()
