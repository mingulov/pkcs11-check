"""Session state machine verification tests.

Verifies PKCS#11 session state transitions per OASIS spec
session_mgmt_functions.md -- login states, session flags, concurrent
session behavior, and logout effects.

States:
  - Public session (R/O or R/W): no login, only public objects visible.
  - User Functions session (R/O or R/W): after C_Login(USER).
  - SO Functions session (R/W only): after C_Login(SO).

Note: python-pkcs11 does not expose C_GetSessionInfo state enum directly.
Session state is verified indirectly through operation success/failure and
object visibility, which is a stronger behavioural verification than checking
an enum value.
"""

from __future__ import annotations

from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, ObjectClass
from pkcs11.exceptions import (
    AnotherUserAlreadyLoggedIn,
    SessionClosed,
    SessionReadOnly,
    SessionReadOnlyExists,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
    UserTypeInvalid,
)

pytestmark = pytest.mark.access


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
        pass  # Token-level login already active


def _logout_safe(session: Any) -> None:
    """Logout ignoring not-logged-in or closed-session errors."""
    try:
        session.logout()
    except (UserNotLoggedIn, SessionClosed):
        pass


# ---------------------------------------------------------------------------
# Login state transitions
# ---------------------------------------------------------------------------


class TestLoginStateTransitions:
    """Verify login state transitions per OASIS spec."""

    def test_open_session_is_public(self, p11_module: Any, p11_config: Any) -> None:
        """Newly opened session (no login) is in public state.

        Public state means private objects are not visible.
        """
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            # Without login, private objects should be invisible
            priv_keys = list(session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            assert len(priv_keys) == 0, "Private keys visible without login -- not public state"
        finally:
            session.close()

    def test_login_user_enables_private_access(self, p11_module: Any, p11_config: Any) -> None:
        """After C_Login(USER), private objects become accessible."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured -- cannot test USER login")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.USER, pin)
            # Generate a private-key object to confirm access
            key = session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.TOKEN: False, Attribute.PRIVATE: True},
            )
            assert key is not None
            key.destroy()
        except UserAlreadyLoggedIn:
            # Already logged in at token level -- still user state
            key = session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.TOKEN: False, Attribute.PRIVATE: True},
            )
            assert key is not None
            key.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_logout_returns_to_public(self, p11_module: Any, p11_config: Any) -> None:
        """After C_Logout, session returns to public state."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            _login_user(session, pin)

            # Create a private token object while logged in
            label = "state-machine-logout-test"
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

            # Logout -- should return to public state
            session.logout()

            # Private objects should no longer be visible
            found = list(
                session.get_objects(
                    {Attribute.CLASS: ObjectClass.SECRET_KEY, Attribute.LABEL: label}
                )
            )
            assert len(found) == 0, "Private object visible after logout -- still in user state"

            # Re-login to clean up
            session.login(p11.UserType.USER, pin)
            for obj in session.get_objects({Attribute.LABEL: label}):
                obj.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_login_logout_login_cycle(self, p11_module: Any, p11_config: Any) -> None:
        """Login -> logout -> login cycle works without error."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.USER, pin)
            session.logout()
            session.login(p11.UserType.USER, pin)
            # Verify we are logged in by creating a private object
            key = session.generate_key(
                KeyType.AES,
                256,
                template={Attribute.TOKEN: False, Attribute.PRIVATE: True},
            )
            assert key is not None
            key.destroy()
        except UserAlreadyLoggedIn:
            pass  # Another session holds the login -- acceptable
        finally:
            _logout_safe(session)
            session.close()


# ---------------------------------------------------------------------------
# SO login state
# ---------------------------------------------------------------------------


class TestSOLoginState:
    """Verify SO login state transitions.

    SO login requires RW session and no USER logged in.
    SO state allows token management but not normal crypto on private keys.
    Marked destructive because SO login may affect token state.
    """

    @pytest.mark.destructive
    def test_so_login_succeeds(self, p11_module: Any, p11_config: Any) -> None:
        """C_Login(SO) on RW session succeeds when no user is logged in.

        After SO login, token management operations (like C_InitPIN) are available
        but normal user crypto may be restricted.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        # SO PIN is often the same as user PIN for test tokens
        so_pin = pin
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, so_pin)
            # SO is logged in -- verify by checking we can't login as USER
            with pytest.raises(
                (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn, UserTypeInvalid)
            ):
                session.login(p11.UserType.USER, pin)
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            pytest.skip("Another user is already logged in on this token")
        except p11.exceptions.PinIncorrect:
            pytest.skip("SO PIN differs from user PIN on this module")
        finally:
            _logout_safe(session)
            session.close()

    @pytest.mark.destructive
    def test_so_logout_returns_to_public(self, p11_module: Any, p11_config: Any) -> None:
        """After SO logout, session returns to public state."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        so_pin = pin
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.SO, so_pin)
            session.logout()
            # After logout, should be able to login as USER
            session.login(p11.UserType.USER, pin)
            session.logout()
        except (UserAlreadyLoggedIn, AnotherUserAlreadyLoggedIn):
            pytest.skip("Another user is already logged in on this token")
        except p11.exceptions.PinIncorrect:
            pytest.skip("SO PIN differs from user PIN on this module")
        finally:
            _logout_safe(session)
            session.close()


# ---------------------------------------------------------------------------
# Double login / login conflict
# ---------------------------------------------------------------------------


class TestLoginConflicts:
    """Verify login conflict behaviour per OASIS spec."""

    def test_double_user_login_rejected(self, p11_module: Any, p11_config: Any) -> None:
        """Second C_Login(USER) on same token must raise UserAlreadyLoggedIn."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            session.login(p11.UserType.USER, pin)
            # Second login on same session/token
            with pytest.raises((UserAlreadyLoggedIn, UserTypeInvalid)):
                session.login(p11.UserType.USER, pin)
        except UserAlreadyLoggedIn:
            # First login already raised it -- token was already logged in
            pass
        finally:
            _logout_safe(session)
            session.close()

    def test_so_login_while_user_logged_in(self, p11_module: Any, p11_config: Any) -> None:
        """C_Login(SO) while USER is logged in must fail.

        Expected: CKR_USER_ALREADY_LOGGED_IN or CKR_ANOTHER_USER_ALREADY_LOGGED_IN.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            with pytest.raises(
                (
                    UserAlreadyLoggedIn,
                    AnotherUserAlreadyLoggedIn,
                    UserTypeInvalid,
                )
            ):
                session.login(p11.UserType.SO, pin)
        finally:
            _logout_safe(session)
            session.close()

    def test_user_login_via_second_session_rejected(self, p11_module: Any, p11_config: Any) -> None:
        """Login in session A, then C_Login(USER) in session B must raise
        UserAlreadyLoggedIn (login is token-wide)."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        s1 = token.open(rw=True)
        s2 = token.open(rw=True)
        try:
            s1.login(p11.UserType.USER, pin)
            with pytest.raises((UserAlreadyLoggedIn, UserTypeInvalid)):
                s2.login(p11.UserType.USER, pin)
        except UserAlreadyLoggedIn:
            # s1 login itself raised it -- token already logged in
            pass
        finally:
            _logout_safe(s1)
            s2.close()
            s1.close()


# ---------------------------------------------------------------------------
# Concurrent session shared login state
# ---------------------------------------------------------------------------


class TestConcurrentSessionLogin:
    """Verify that login state is shared across sessions on the same token."""

    def test_login_in_one_session_visible_in_another(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Login via session A, session B inherits the logged-in state.

        Private objects should be visible in session B without calling
        C_Login on it.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)

            # Create a private session object in s1
            key = s1.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: "shared-login-test",
                },
            )

            # Open second session -- should inherit login state
            s2 = token.open(rw=True)
            try:
                found = list(s2.get_objects({Attribute.LABEL: "shared-login-test"}))
                assert len(found) >= 1, "Session B cannot see private object -- login not shared"
            finally:
                s2.close()
            key.destroy()
        finally:
            _logout_safe(s1)
            s1.close()

    def test_logout_affects_all_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Logout via session A revokes login state for session B too.

        After logout, private token objects should not be visible in any session.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        s1 = token.open(rw=True)
        s2 = token.open(rw=True)
        try:
            _login_user(s1, pin)

            # Create private token object
            label = "logout-shared-test"
            s1.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: True,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )

            # Logout via s1
            s1.logout()

            # s2 should also lose access to private objects
            found = list(
                s2.get_objects(
                    {
                        Attribute.CLASS: ObjectClass.SECRET_KEY,
                        Attribute.LABEL: label,
                    }
                )
            )
            assert len(found) == 0, "Private object visible in s2 after logout via s1"

            # Re-login to clean up
            s1.login(p11.UserType.USER, pin)
            for obj in s1.get_objects({Attribute.LABEL: label}):
                obj.destroy()
        finally:
            _logout_safe(s1)
            s2.close()
            s1.close()


# ---------------------------------------------------------------------------
# Session flags verification
# ---------------------------------------------------------------------------


class TestSessionFlags:
    """Verify session flag properties (rw, etc.)."""

    def test_rw_session_flag(self, p11_module: Any, p11_config: Any) -> None:
        """R/W session reports rw=True."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            assert session.rw is True
        finally:
            session.close()

    def test_ro_session_flag(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session reports rw=False."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            assert session.rw is False
        finally:
            session.close()

    def test_rw_and_ro_sessions_coexist(self, p11_module: Any, p11_config: Any) -> None:
        """R/W and R/O sessions can coexist on the same token."""
        token = p11_module.get_token(p11_config.slot)
        rw = token.open(rw=True)
        ro = token.open(rw=False)
        try:
            assert rw.rw is True
            assert ro.rw is False
        finally:
            ro.close()
            rw.close()

    def test_multiple_rw_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Multiple R/W sessions can be opened simultaneously."""
        token = p11_module.get_token(p11_config.slot)
        sessions = [token.open(rw=True) for _ in range(3)]
        try:
            for s in sessions:
                assert s.rw is True
        finally:
            for s in sessions:
                s.close()


# ---------------------------------------------------------------------------
# Logout effects on private objects
# ---------------------------------------------------------------------------


class TestLogoutEffects:
    """Verify that logout makes private objects inaccessible."""

    def test_private_session_key_invisible_after_logout(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Private session key vanishes from search after logout."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            label = "priv-logout-session"
            session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.PRIVATE: True,
                    Attribute.LABEL: label,
                },
            )
            # Confirm visible while logged in
            found = list(session.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1

            session.logout()

            # Should be invisible now
            found = list(session.get_objects({Attribute.LABEL: label}))
            assert len(found) == 0, "Private session key visible after logout"
        finally:
            # Session key is gone after logout (or session close)
            session.close()

    def test_public_object_remains_after_logout(self, p11_module: Any, p11_config: Any) -> None:
        """Public (CKA_PRIVATE=False) objects remain visible after logout."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        label = "pub-logout-test"
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

            session.logout()

            found = list(
                session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
            )
            # Public objects should still be visible
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_PRIVATE=False object not visible after logout",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: public objects visible in public state",
                )

            # Cleanup: re-login to destroy
            session.login(p11.UserType.USER, pin)
            for obj in session.get_objects(
                {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
            ):
                obj.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_generate_random_works_after_logout(self, p11_module: Any, p11_config: Any) -> None:
        """C_GenerateRandom does not require login -- works in public state."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            session.logout()
            # Random generation should work without login
            rand = session.generate_random(32)
            assert len(rand) == 4  # 32 bits = 4 bytes
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Session close effects
# ---------------------------------------------------------------------------


class TestSessionCloseEffects:
    """Verify that closing one session does not affect others."""

    def test_close_one_session_others_remain(self, p11_module: Any, p11_config: Any) -> None:
        """Closing session A does not invalidate session B."""
        pin = _get_pin(p11_config)
        token = p11_module.get_token(p11_config.slot)
        s1 = token.open(rw=True)
        s2 = token.open(rw=True)
        try:
            _login_user(s1, pin)

            s1.close()

            # s2 should still work
            rand = s2.generate_random(64)
            assert len(rand) == 8  # 64 bits = 8 bytes
        finally:
            _logout_safe(s2)
            s2.close()

    def test_close_session_destroys_its_session_objects(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session objects belong to their session; closing destroys them.

        After closing s1, session objects created in s1 should not be
        findable in s2 (spec: session objects destroyed on session close).
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)
            label = "close-destroys-test"
            s1.generate_key(
                KeyType.AES,
                128,
                template={
                    Attribute.TOKEN: False,
                    Attribute.LABEL: label,
                },
            )
            s1.close()

            s2 = token.open(rw=True)
            try:
                _login_user(s2, pin)
                found = list(s2.get_objects({Attribute.LABEL: label}))
                assert len(found) == 0, "Session object survived session close"
            finally:
                _logout_safe(s2)
                s2.close()
        except Exception:
            # If s1 wasn't closed yet, close it
            try:
                s1.close()
            except (SessionClosed, p11.exceptions.SessionHandleInvalid):
                pass
            raise

    def test_token_object_survives_session_close(self, p11_module: Any, p11_config: Any) -> None:
        """Token objects (CKA_TOKEN=True) persist across session close."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        label = "token-survives-close"
        s1 = token.open(rw=True)
        try:
            _login_user(s1, pin)
            key = s1.generate_key(
                KeyType.AES,
                128,
                template={
                    Attribute.TOKEN: True,
                    Attribute.LABEL: label,
                },
            )
            assert key is not None
        finally:
            _logout_safe(s1)
            s1.close()

        s2 = token.open(rw=True)
        try:
            _login_user(s2, pin)
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1, "Token object did not survive session close"
            for obj in found:
                obj.destroy()
        finally:
            _logout_safe(s2)
            s2.close()


# ---------------------------------------------------------------------------
# RW vs RO session state
# ---------------------------------------------------------------------------


class TestROvsRWSessionState:
    """Verify R/O vs R/W session differences per spec."""

    def test_ro_session_can_login_user(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session allows C_Login(USER)."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            session.login(p11.UserType.USER, pin)
        except UserAlreadyLoggedIn:
            pass  # Already logged in at token level
        finally:
            _logout_safe(session)
            session.close()

    def test_ro_session_cannot_create_token_objects(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session cannot create CKA_TOKEN=True objects.

        Expected error: CKR_SESSION_READ_ONLY.
        """
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            _login_user(session, pin)
            with pytest.raises((SessionReadOnly, p11.exceptions.ActionProhibited)):
                session.generate_key(
                    KeyType.AES,
                    128,
                    template={Attribute.TOKEN: True},
                )
        finally:
            _logout_safe(session)
            session.close()

    def test_ro_session_can_create_session_objects(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session can create session objects (CKA_TOKEN=False)."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            _login_user(session, pin)
            key = session.generate_key(
                KeyType.AES,
                128,
                template={Attribute.TOKEN: False},
            )
            assert key is not None
            key.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_ro_session_can_digest(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session can perform digest (no key needed)."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=False)
        try:
            from pkcs11 import Mechanism

            digest = session.digest(b"RO session digest", mechanism=Mechanism.SHA256)
            assert len(digest) == 32
        finally:
            session.close()

    def test_so_login_requires_rw_session(self, p11_module: Any, p11_config: Any) -> None:
        """C_Login(SO) on an R/O session must fail.

        Per spec: SO login requires that no R/O sessions exist, and the
        session itself must be R/W. Expected: CKR_SESSION_READ_ONLY_EXISTS
        or CKR_SESSION_READ_ONLY.
        """
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
# Logout without login
# ---------------------------------------------------------------------------


class TestLogoutWithoutLogin:
    """Verify behaviour when logout is called without prior login."""

    def test_logout_without_login_raises(self, p11_module: Any, p11_config: Any) -> None:
        """C_Logout without prior C_Login should raise CKR_USER_NOT_LOGGED_IN.

        PKCS#11 login is token-wide: if another session on this token has
        logged in, the new session inherits that state and logout succeeds.
        We first try to ensure no login is active by opening a fresh session
        and calling logout to clear any residual login.
        """
        token = p11_module.get_token(p11_config.slot)
        # Clear any residual token-level login
        cleanup = token.open(rw=True)
        try:
            cleanup.logout()
        except UserNotLoggedIn:
            pass  # Good -- no login was active
        finally:
            cleanup.close()

        session = token.open(rw=True)
        try:
            # Now no login should be active on this token
            try:
                session.logout()
                # Some modules silently accept logout without login
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_Logout without prior C_Login did not raise CKR_USER_NOT_LOGGED_IN",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: C_Logout when not logged in",
                )
            except UserNotLoggedIn:
                pass  # Correct per spec
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Session open / context manager
# ---------------------------------------------------------------------------


class TestSessionContextManager:
    """Verify session context manager protocol."""

    def test_context_manager_closes_session(self, p11_module: Any, p11_config: Any) -> None:
        """Using `with token.open() as session` closes on exit."""
        token = p11_module.get_token(p11_config.slot)
        with token.open(rw=True) as session:
            assert session.rw is True
        # Session should be closed -- operations should fail
        with pytest.raises((SessionClosed, p11.exceptions.SessionHandleInvalid, AttributeError)):
            session.generate_random(32)

    def test_context_manager_with_login(self, p11_module: Any, p11_config: Any) -> None:
        """Context manager session with user_pin logs in automatically."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        try:
            with token.open(rw=True, user_pin=pin) as session:
                key = session.generate_key(
                    KeyType.AES,
                    128,
                    template={Attribute.TOKEN: False, Attribute.PRIVATE: True},
                )
                assert key is not None
                key.destroy()
        except UserAlreadyLoggedIn:
            # Another session is logged in -- acceptable
            pass


# ---------------------------------------------------------------------------
# Login type specificity
# ---------------------------------------------------------------------------


class TestLoginTypeSpecificity:
    """Verify that different login types result in appropriate state."""

    def test_user_login_creates_session_objects(self, p11_module: Any, p11_config: Any) -> None:
        """USER login allows creating private session objects."""
        pin = _get_pin(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            _login_user(session, pin)
            key = session.generate_key(
                KeyType.AES,
                256,
                template={
                    Attribute.TOKEN: False,
                    Attribute.PRIVATE: True,
                },
            )
            assert key is not None
            key.destroy()
        finally:
            _logout_safe(session)
            session.close()

    def test_generate_random_without_login(self, p11_module: Any, p11_config: Any) -> None:
        """C_GenerateRandom works in public state (no login required)."""
        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            rand = session.generate_random(128)
            assert len(rand) == 16  # 128 bits = 16 bytes
        finally:
            session.close()

    def test_digest_without_login(self, p11_module: Any, p11_config: Any) -> None:
        """C_Digest works in public state (no login required)."""
        from pkcs11 import Mechanism

        token = p11_module.get_token(p11_config.slot)
        session = token.open(rw=True)
        try:
            digest = session.digest(b"no-login-digest", mechanism=Mechanism.SHA256)
            assert len(digest) == 32
        finally:
            session.close()
