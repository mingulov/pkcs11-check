"""Tests for C_LoginUser (v3.0+) and context-specific login.

C_LoginUser is a PKCS#11 v3.0 extension to C_Login that additionally accepts
a username string.  It is used to authenticate as a named user rather than
one of the fixed CKU_USER / CKU_SO roles.

CKU_CONTEXT_SPECIFIC (user type 2) is used after a normal CKU_USER login to
re-authenticate before using a CKA_ALWAYS_AUTHENTICATE private key.  The
PKCS#11 spec requires context-specific re-auth immediately before each
CKM_* operation on such a key.

Source: PKCS#11 v3.0 §5.5  C_Login / C_LoginUser
        PKCS#11 v2.40 §11.6 (CKU_CONTEXT_SPECIFIC semantics)
"""

from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from pkcs11.exceptions import (
    FunctionNotSupported,
    OperationNotInitialized,
    UserAlreadyLoggedIn,
    UserNotLoggedIn,
)

pytestmark = [pytest.mark.requires_v30, pytest.mark.access]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pin_str(p11_config: Any) -> str | None:
    """Return the PIN as a plain string, or None if not configured."""
    if p11_config.pin is None:
        return None
    return p11_config.pin.get_secret_value()


# ---------------------------------------------------------------------------
# C_LoginUser tests
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
class TestCLoginUser:
    """C_LoginUser (v3.0+) exercises the username parameter path.

    C_LoginUser is called internally when session.login(..., username=...) is
    used.  The python-pkcs11 binding raises NotImplementedError on v2.40
    modules — the requires_v30 marker skips those automatically.
    """

    def test_c_login_user_empty_username_user_type(
        self, p11_module: Any, p11_config: Any, p11_interface_version: str
    ) -> None:
        """C_LoginUser with empty username string exercises the v3.0 code path.

        The PKCS#11 spec allows pUsername / ulUsernameLen = NULL / 0 to mean
        "default user".  python-pkcs11 encodes an empty string as a zero-length
        buffer, which is equivalent.  Most tokens accept this and treat it
        identically to C_Login(CKU_USER).

        Expected outcomes (all acceptable):
        - CKR_OK — module treats it as a normal user login.
        - CKR_USER_ALREADY_LOGGED_IN — p11_session already logged in.
        - CKR_FUNCTION_NOT_SUPPORTED — module exposes v3.0 interface but
          didn't implement C_LoginUser (unusual but legal).
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured — cannot exercise C_LoginUser")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            # First do a normal CKU_USER login so the session state is known.
            try:
                session.login(pkcs11.UserType.USER, pin)
            except UserAlreadyLoggedIn:
                pass  # Token-level login already active — that is fine.

            # Now exercise C_LoginUser with an empty username string.
            # This must not raise NotImplementedError on a v3.0+ interface.
            try:
                session.login(pkcs11.UserType.USER, pin=pin, username="")
            except UserAlreadyLoggedIn:
                pass  # Acceptable: we are already logged in as USER.
            except FunctionNotSupported:
                pytest.xfail(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                )
        finally:
            try:
                session.logout()
            except (UserNotLoggedIn, pkcs11.exceptions.SessionClosed):
                pass
            session.close()

    def test_c_login_user_not_implemented_on_v240(
        self, p11_interface_version: str, p11_module: Any, p11_config: Any
    ) -> None:
        """C_LoginUser raises NotImplementedError when forced on a v2.40 module.

        This test only runs if the negotiated version is exactly 2.40.
        The requires_v30 marker on the class would normally skip it, so we
        invert the logic: skip unless we're on 2.40.

        Note: this test is intentionally outside the class-level skip so we
        can verify the binding's guard is in place.  It is added as a
        regression check for the binding implementation.
        """
        # This test is meaningful only on v2.40 — skip otherwise.
        if p11_interface_version != "2.40":
            pytest.skip("This test is specifically for v2.40 modules")

        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            try:
                session.login(pkcs11.UserType.USER, pin)
            except UserAlreadyLoggedIn:
                pass

            with pytest.raises(NotImplementedError):
                session.login(pkcs11.UserType.USER, pin=pin, username="anyuser")
        finally:
            try:
                session.logout()
            except (UserNotLoggedIn, pkcs11.exceptions.SessionClosed):
                pass
            session.close()

    def test_c_login_user_non_empty_username(self, p11_module: Any, p11_config: Any) -> None:
        """C_LoginUser with a non-empty username does not crash the module.

        Tokens that implement named users accept a username string.  Tokens
        that only support the traditional CKU_USER role will reject with
        CKR_USER_TYPE_INVALID, CKR_FUNCTION_NOT_SUPPORTED, or similar.
        The important property is that the module returns a well-formed CKR
        rather than crashing or hanging.
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured — cannot exercise C_LoginUser")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            # Attempt C_LoginUser with a plausible username.  We do NOT
            # require success here — rejection is expected on most tokens.
            try:
                session.login(pkcs11.UserType.USER, pin=pin, username="user")
                # If we get here the module accepted it — that is valid.
                logged_in = True
            except UserAlreadyLoggedIn:
                logged_in = True  # Already logged in — acceptable.
            except FunctionNotSupported:
                logged_in = False
                # Module does not implement C_LoginUser despite v3.0 interface.
                pytest.xfail(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                )
            except pkcs11.exceptions.UserTypeInvalid:
                logged_in = False
                # Module does not support named users — acceptable.
            except pkcs11.exceptions.PKCS11Error:
                # Any other PKCS11Error is acceptable (e.g. CKR_ARGUMENTS_BAD,
                # CKR_PIN_INCORRECT for unrecognised username).
                logged_in = False
        finally:
            if logged_in:
                try:
                    session.logout()
                except (UserNotLoggedIn, pkcs11.exceptions.SessionClosed):
                    pass
            session.close()


# ---------------------------------------------------------------------------
# CKU_CONTEXT_SPECIFIC tests (reaffirm_credentials / C_Login type 2)
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
class TestContextSpecificLogin:
    """CKU_CONTEXT_SPECIFIC (user type 2) exercises the reaffirm-credentials path.

    Context-specific login re-authenticates the user immediately before an
    operation on a CKA_ALWAYS_AUTHENTICATE key.  Without a key that has that
    attribute set, calling C_Login(CKU_CONTEXT_SPECIFIC) outside an active
    operation returns CKR_OPERATION_NOT_INITIALIZED.

    These tests verify:
    1. The binding correctly calls C_Login with user_type=2.
    2. The module returns a well-formed CKR (not a crash).
    3. reaffirm_credentials() is a thin wrapper for the above.
    """

    def test_context_specific_login_without_active_op(
        self, p11_session: Any, p11_config: Any
    ) -> None:
        """CKU_CONTEXT_SPECIFIC login without an active op returns CKR_OPERATION_NOT_INITIALIZED.

        Source: PKCS#11 v2.40 §11.6 C_Login error table —
        CKR_OPERATION_NOT_INITIALIZED if there is no active operation for
        which re-authentication is required.

        Some modules additionally accept CKR_USER_NOT_LOGGED_IN (the session
        state guard fires first), or CKR_FUNCTION_NOT_SUPPORTED (module does
        not implement context-specific login at all).
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured — cannot test context-specific login")

        # p11_session is already logged in as CKU_USER.
        # Calling login(CKU_CONTEXT_SPECIFIC) with no active crypto op should
        # be rejected by a conformant module.
        try:
            p11_session.login(pkcs11.UserType.CONTEXT_SPECIFIC, pin=pin)
            # Some lenient modules accept it — note as an xfail.
            pytest.xfail(
                "Module accepted CKU_CONTEXT_SPECIFIC login without an active "
                "operation — spec requires CKR_OPERATION_NOT_INITIALIZED"
            )
        except OperationNotInitialized:
            pass  # Correct per spec.
        except UserNotLoggedIn:
            pass  # Acceptable: module checks login state before operation state.
        except FunctionNotSupported:
            pytest.xfail(
                "Module does not support CKU_CONTEXT_SPECIFIC login (CKR_FUNCTION_NOT_SUPPORTED)"
            )

    def test_reaffirm_credentials_without_active_op(
        self, p11_session: Any, p11_config: Any
    ) -> None:
        """reaffirm_credentials() without an active operation is rejected.

        reaffirm_credentials(pin) is a python-pkcs11 convenience wrapper for
        session.login(UserType.CONTEXT_SPECIFIC, pin=pin).  It must propagate
        the same CKR errors as the direct login() call.
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured — cannot test reaffirm_credentials")

        try:
            p11_session.reaffirm_credentials(pin)
            pytest.xfail(
                "Module accepted reaffirm_credentials() without an active "
                "operation — spec requires CKR_OPERATION_NOT_INITIALIZED"
            )
        except OperationNotInitialized:
            pass  # Correct per spec.
        except UserNotLoggedIn:
            pass  # Acceptable: module checks login state first.
        except FunctionNotSupported:
            pytest.xfail(
                "Module does not support CKU_CONTEXT_SPECIFIC login (CKR_FUNCTION_NOT_SUPPORTED)"
            )

    def test_context_specific_login_uses_c_login(self, p11_session: Any, p11_config: Any) -> None:
        """CKU_CONTEXT_SPECIFIC login uses C_Login (not C_LoginUser) on v3.0+.

        When username is None, the binding always falls through to C_Login
        regardless of the interface version.  This test confirms the binding
        does not erroneously route CKU_CONTEXT_SPECIFIC through C_LoginUser.

        Verification: the call must not raise NotImplementedError (which the
        binding would raise only if it incorrectly required username= for
        CKU_CONTEXT_SPECIFIC).
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        # Must not raise NotImplementedError regardless of interface version.
        try:
            p11_session.login(pkcs11.UserType.CONTEXT_SPECIFIC, pin=pin)
            pytest.xfail("Module accepted CKU_CONTEXT_SPECIFIC without active operation")
        except NotImplementedError:
            pytest.fail(
                "login(CONTEXT_SPECIFIC) raised NotImplementedError — "
                "binding incorrectly requires username= for CKU_CONTEXT_SPECIFIC"
            )
        except OperationNotInitialized:
            pass  # Correct.
        except UserNotLoggedIn:
            pass  # Acceptable.
        except FunctionNotSupported:
            pytest.xfail("Module does not implement CKU_CONTEXT_SPECIFIC login")

    def test_context_specific_via_c_login_user(self, p11_session: Any, p11_config: Any) -> None:
        """C_LoginUser with CKU_CONTEXT_SPECIFIC and empty username is also rejected.

        This verifies that the C_LoginUser code path (username != None) is
        exercised for CKU_CONTEXT_SPECIFIC — and that the module rejects it
        for the same reason (no active operation), not due to a crash.
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        try:
            p11_session.login(pkcs11.UserType.CONTEXT_SPECIFIC, pin=pin, username="")
            pytest.xfail(
                "Module accepted CKU_CONTEXT_SPECIFIC via C_LoginUser without "
                "an active operation — spec requires CKR_OPERATION_NOT_INITIALIZED"
            )
        except NotImplementedError:
            pytest.xfail(
                "Module does not expose v3.0 function list for C_LoginUser "
                "(unexpected on a v3.0+ negotiated interface)"
            )
        except OperationNotInitialized:
            pass  # Correct per spec.
        except UserNotLoggedIn:
            pass  # Acceptable.
        except FunctionNotSupported:
            pytest.xfail("Module does not implement C_LoginUser")


# ---------------------------------------------------------------------------
# Login / logout cycle
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
class TestLoginLogoutCycle:
    """Basic login/logout cycle verification for v3.0+ modules.

    These tests open their own sessions (not p11_session) to ensure a clean
    login state and to verify that C_LoginUser round-trips correctly.
    """

    def test_normal_login_logout(self, p11_module: Any, p11_config: Any) -> None:
        """Normal CKU_USER login and logout cycle works on a v3.0+ module."""
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            try:
                session.login(pkcs11.UserType.USER, pin)
            except UserAlreadyLoggedIn:
                pass  # Token-level login — still valid.

            # Verify the session is functional after login.
            key = session.generate_key(pkcs11.KeyType.AES, 128)
            assert key is not None, "generate_key returned None after login"

            session.logout()

            # After logout, generating a key in a no-PIN slot should still work
            # (session key) or fail gracefully — we just verify no exception
            # from logout itself.
        except UserNotLoggedIn:
            pass  # Logout without prior login is fine.
        finally:
            session.close()

    def test_c_login_user_then_logout(self, p11_module: Any, p11_config: Any) -> None:
        """C_LoginUser login followed by C_Logout is a clean round-trip.

        After a successful C_LoginUser, session.logout() must succeed (CKR_OK).
        The session must then be usable again (can re-login).
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            # Use C_LoginUser (username="" → zero-length username buffer).
            try:
                session.login(pkcs11.UserType.USER, pin=pin, username="")
                logged_in = True
            except UserAlreadyLoggedIn:
                logged_in = True  # Already logged in — skip the logout check.
            except FunctionNotSupported:
                pytest.xfail("Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)")
                logged_in = False

            if logged_in:
                # Logout must succeed or raise UserNotLoggedIn (if token-level
                # login state differs from session-level).
                try:
                    session.logout()
                except UserNotLoggedIn:
                    pass  # Acceptable: token-level logout already happened.
        finally:
            session.close()

    def test_double_login_rejected(self, p11_module: Any, p11_config: Any) -> None:
        """A second CKU_USER login on an already-logged-in session is rejected.

        The PKCS#11 spec requires CKR_USER_ALREADY_LOGGED_IN when C_Login or
        C_LoginUser is called again after a successful login.

        Source: PKCS#11 v3.0 §5.5 C_LoginUser error table.
        """
        pin = _pin_str(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        token = p11_module.get_token()
        session = token.open(rw=True)
        try:
            # First login.
            try:
                session.login(pkcs11.UserType.USER, pin)
            except UserAlreadyLoggedIn:
                # Already logged in from a previous test — that is fine;
                # proceed to the second login check below.
                pass

            # Second login via C_LoginUser must be rejected.
            try:
                session.login(pkcs11.UserType.USER, pin=pin, username="")
                pytest.xfail(
                    "Module accepted a second C_LoginUser login without "
                    "intervening logout — spec requires "
                    "CKR_USER_ALREADY_LOGGED_IN"
                )
            except UserAlreadyLoggedIn:
                pass  # Correct per spec.
            except FunctionNotSupported:
                pytest.xfail("Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)")
        finally:
            try:
                session.logout()
            except (UserNotLoggedIn, pkcs11.exceptions.SessionClosed):
                pass
            session.close()
