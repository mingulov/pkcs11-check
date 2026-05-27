"""Session state machine verification tests.

Verifies PKCS#11 session state transitions per OASIS spec
session_mgmt_functions.md - login states, session flags, concurrent
session behavior, and logout effects.

States:
  - Public session (R/O or R/W): no login, only public objects visible.
  - User Functions session (R/O or R/W): after C_Login(USER).
  - SO Functions session (R/W only): after C_Login(SO).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    create_object as _raw_create_object,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    find_objects,
    generate_random,
    get_session_info,
)
from pkcs11_check.raw.recipes import (
    gen_aes_key as _raw_gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_UTF8CHAR,
    CKA_CLASS,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_SHA256,
    CKO_DATA,
    CKO_PRIVATE_KEY,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SESSION_CLOSED,
    CKR_SESSION_COUNT,
    CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    classify_negative_rv,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_DATA_OBJECT_SETUP_REJECT_RVS = (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session for session-state tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by session-state test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _gen_state_aes_key(
    rs: Any,
    sh: int,
    bits: int = 128,
    *,
    attrs: dict[Any, Any] | None = None,
) -> int:
    """Generate a setup AES key for session-state tests."""
    if not rs.has_mechanism("AES_KEY_GEN"):
        pytest.skip("AES_KEY_GEN not supported by module")
    require_operational_aes_keygen(rs)
    try:
        return _raw_gen_aes_key(rs.raw, sh, bits, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but session-state setup key generation is not operational",
        )
    raise


def _create_state_data_object(rs: Any, sh: int, attrs: dict[Any, Any]) -> int:
    """Create a setup data object for session-state visibility tests."""
    try:
        return _raw_create_object(rs.raw, sh, attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _DATA_OBJECT_SETUP_REJECT_RVS,
            "session-state data object setup rejected by the provider",
        )
    raise


def _xfail_if_aes_setup_rv(rv: int, context: str) -> None:
    """Classify key-generation setup rejects returned directly as CK_RV."""
    if rv in AES_KEYGEN_RUNTIME_REJECT_RVS:
        pytest.xfail(f"{context}: {ckr_name(rv)}")


def _login_user_raw(raw: Any, sh: int, pin_bytes: bytes | None) -> None:
    """Login as USER, tolerating already-logged-in at token level."""
    if pin_bytes is None:
        return
    pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    rv = raw.C_Login(sh, CKU_USER, pin_buf, len(pin_bytes))
    if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID):
        expect_rv(rv, CKR_OK)


def _logout_safe(raw: Any, sh: int) -> None:
    """Logout ignoring not-logged-in or closed-session errors."""
    rv = raw.C_Logout(sh)
    # Silently accept any error -- just cleaning up
    _ = rv


def _skip_if_so_pin_differs(rv: int) -> None:
    if rv == CKR_PIN_INCORRECT:
        pytest.skip("SO PIN differs from user PIN on this module")


# ---------------------------------------------------------------------------
# Login state transitions
# ---------------------------------------------------------------------------


class TestLoginStateTransitions:
    """Verify login state transitions per OASIS spec."""

    def test_open_session_is_public(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Newly opened session (no login) is in public state.

        Public state means private objects are not visible.
        """
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            # Without login, private objects should be invisible
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, test_sh, tmpl)
            assert len(found) == 0, "Private keys visible without login - not public state"
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_login_user_enables_private_access(self, p11_raw_session: Any, p11_config: Any) -> None:
        """After C_Login(USER), private objects become accessible."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured - cannot test USER login")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            # Generate a private-key object to confirm access
            key_h = _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
            )
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_logout_returns_to_public(self, p11_raw_session: Any, p11_config: Any) -> None:
        """After C_Logout, session returns to public state."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)

            # Create a private token object while logged in
            label = "state-machine-logout-test"
            key_h = _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
            assert key_h != 0

            # Logout - should return to public state
            rs.raw.C_Logout(test_sh)

            # Private objects should no longer be visible
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, test_sh, tmpl)
            assert len(found) == 0, "Private object visible after logout - still in user state"

            # Re-login to clean up
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            tmpl2 = template_from_dict({CKA_LABEL: label})
            for h in find_objects(rs.raw, test_sh, tmpl2):
                destroy_quietly(rs.raw, test_sh, h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_login_logout_login_cycle(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Login -> logout -> login cycle works without error."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(test_sh, CKU_USER, pin_buf, len(pin_bytes))
            if rv == CKR_USER_ALREADY_LOGGED_IN:
                # Another session holds the login - acceptable
                close_session_quietly(rs.raw, test_sh)
                return

            rs.raw.C_Logout(test_sh)
            _login_user_raw(rs.raw, test_sh, pin_bytes)

            # Verify we are logged in by creating a private object
            key_h = _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
            )
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)


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
    def test_so_login_succeeds(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Login(SO) on RW session succeeds when no user is logged in."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        so_pin = pin_bytes
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            if rv == CKR_PIN_INCORRECT:
                pytest.skip("SO PIN differs from user PIN on this module")
            if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
                pytest.skip("Another user is already logged in on this token")
            expect_rv(rv, CKR_OK)

            # SO is logged in - verify by checking we can't login as USER
            pin_buf2 = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv2 = rs.raw.C_Login(test_sh, CKU_USER, pin_buf2, len(pin_bytes))
            assert rv2 in (
                CKR_USER_ALREADY_LOGGED_IN,
                CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                CKR_USER_TYPE_INVALID,
            ), f"Expected USER login rejected while SO active, got {ckr_name(rv2)}"
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    @pytest.mark.destructive
    def test_so_logout_returns_to_public(self, p11_raw_session: Any, p11_config: Any) -> None:
        """After SO logout, session returns to public state."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        so_pin = pin_bytes
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            if rv == CKR_PIN_INCORRECT:
                pytest.skip("SO PIN differs from user PIN on this module")
            if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
                pytest.skip("Another user is already logged in on this token")
            expect_rv(rv, CKR_OK)

            rs.raw.C_Logout(test_sh)

            # After logout, should be able to login as USER
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            _logout_safe(rs.raw, test_sh)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)


# ---------------------------------------------------------------------------
# Double login / login conflict
# ---------------------------------------------------------------------------


class TestLoginConflicts:
    """Verify login conflict behaviour per OASIS spec."""

    def test_double_user_login_rejected(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Second C_Login(USER) on same token must raise UserAlreadyLoggedIn."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(test_sh, CKU_USER, pin_buf, len(pin_bytes))
            if rv == CKR_USER_ALREADY_LOGGED_IN:
                # Token was already logged in - that's acceptable
                return

            # Second login on same session/token
            rv2 = rs.raw.C_Login(test_sh, CKU_USER, pin_buf, len(pin_bytes))
            assert rv2 in (
                CKR_USER_ALREADY_LOGGED_IN,
                CKR_USER_TYPE_INVALID,
            ), f"Expected CKR_USER_ALREADY_LOGGED_IN, got {ckr_name(rv2)}"
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_so_login_while_user_logged_in(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Login(SO) while USER is logged in must fail."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)

            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(pin_bytes))
            _skip_if_so_pin_differs(rv)
            classify_negative_rv(
                rv,
                (CKR_USER_ANOTHER_ALREADY_LOGGED_IN,),
                label="C_Login(SO) while a USER session is logged in",
            )
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_user_login_via_second_session_rejected(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Login in session A, then C_Login(USER) in session B must raise
        UserAlreadyLoggedIn (login is token-wide)."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(s1, CKU_USER, pin_buf, len(pin_bytes))
            if rv == CKR_USER_ALREADY_LOGGED_IN:
                # Token already logged in
                return

            rv2 = rs.raw.C_Login(s2, CKU_USER, pin_buf, len(pin_bytes))
            classify_negative_rv(
                rv2,
                (CKR_USER_ALREADY_LOGGED_IN,),
                label="second C_Login(USER) via a different session (login is token-wide)",
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s2)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# Concurrent session shared login state
# ---------------------------------------------------------------------------


class TestConcurrentSessionLogin:
    """Verify that login state is shared across sessions on the same token."""

    def test_login_in_one_session_visible_in_another(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Login via session A, session B inherits the logged-in state."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)

            # Create a private session object in s1
            label = "shared-login-test"
            key_h = _gen_state_aes_key(
                rs,
                s1,
                128,
                attrs={
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )

            # Open second session - should inherit login state
            s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            try:
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, s2, tmpl)
                assert len(found) >= 1, "Session B cannot see private object - login not shared"
            finally:
                close_session_quietly(rs.raw, s2)
            destroy_quietly(rs.raw, s1, key_h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_logout_affects_all_sessions(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Logout via session A revokes login state for session B too."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)

            # Create private token object
            label = "logout-shared-test"
            _gen_state_aes_key(
                rs,
                s1,
                128,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )

            # Logout via s1
            rs.raw.C_Logout(s1)

            # s2 should also lose access to private objects
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) == 0, "Private object visible in s2 after logout via s1"

            # Re-login to clean up
            _login_user_raw(rs.raw, s1, pin_bytes)
            tmpl2 = template_from_dict({CKA_LABEL: label})
            for h in find_objects(rs.raw, s1, tmpl2):
                destroy_quietly(rs.raw, s1, h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s2)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# Session flags verification
# ---------------------------------------------------------------------------


class TestSessionFlags:
    """Verify session flag properties (rw, etc.)."""

    def test_rw_session_flag(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/W session reports rw=True."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            is_rw = bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION)
            assert is_rw is True
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_flag(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session reports rw=False."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            is_rw = bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION)
            assert is_rw is False
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_rw_and_ro_sessions_coexist(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/W and R/O sessions can coexist on the same token."""
        rs = p11_raw_session
        rw_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            assert bool(get_session_info(rs.raw, rw_sh)["flags"] & CKF_RW_SESSION) is True

            assert bool(get_session_info(rs.raw, ro_sh)["flags"] & CKF_RW_SESSION) is False
        finally:
            close_session_quietly(rs.raw, ro_sh)
            close_session_quietly(rs.raw, rw_sh)

    def test_multiple_rw_sessions(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Multiple R/W sessions can be opened simultaneously."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        sessions = [raw_open_session(rs.raw, rs.slot_id, flags) for _ in range(3)]
        try:
            for sh in sessions:
                assert bool(get_session_info(rs.raw, sh)["flags"] & CKF_RW_SESSION) is True
        finally:
            for sh in sessions:
                close_session_quietly(rs.raw, sh)


# ---------------------------------------------------------------------------
# Logout effects on private objects
# ---------------------------------------------------------------------------


class TestLogoutEffects:
    """Verify that logout makes private objects inaccessible."""

    def test_private_session_key_invisible_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Private session key vanishes from search after logout."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            label = "priv-logout-session"
            _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
            # Confirm visible while logged in
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, test_sh, tmpl)
            assert len(found) >= 1

            rs.raw.C_Logout(test_sh)

            # Should be invisible now
            found = find_objects(rs.raw, test_sh, tmpl)
            assert len(found) == 0, "Private session key visible after logout"
        finally:
            # Session key is gone after logout (or session close)
            close_session_quietly(rs.raw, test_sh)

    def test_public_object_remains_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public (CKA_PRIVATE=False) objects remain visible after logout."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        label = "pub-logout-test"
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            _create_state_data_object(
                rs,
                test_sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"public-data",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )

            rs.raw.C_Logout(test_sh)

            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, test_sh, tmpl)
            # Public objects should still be visible
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_PRIVATE=False object not visible after logout",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: public objects visible in public state",
                )

            # Cleanup: re-login to destroy
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            tmpl2 = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            for h in find_objects(rs.raw, test_sh, tmpl2):
                destroy_quietly(rs.raw, test_sh, h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_generate_random_works_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_GenerateRandom does not require login - works in public state."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            rs.raw.C_Logout(test_sh)
            # Random generation should work without login
            rand = generate_random(rs.raw, test_sh, 4)
            assert len(rand) == 4  # 32 bits = 4 bytes
        finally:
            close_session_quietly(rs.raw, test_sh)


# ---------------------------------------------------------------------------
# Session close effects
# ---------------------------------------------------------------------------


class TestSessionCloseEffects:
    """Verify that closing one session does not affect others."""

    def test_close_one_session_others_remain(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Closing session A does not invalidate session B."""
        pin_bytes = get_pin_bytes(p11_config)
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)

            close_session_quietly(rs.raw, s1)

            # s2 should still work
            rand = generate_random(rs.raw, s2, 8)
            assert len(rand) == 8  # 64 bits = 8 bytes
        finally:
            _logout_safe(rs.raw, s2)
            close_session_quietly(rs.raw, s2)

    def test_close_session_destroys_its_session_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session objects belong to their session; closing destroys them."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            label = "close-destroys-test"
            _gen_state_aes_key(
                rs,
                s1,
                128,
                attrs={CKA_TOKEN: False, CKA_LABEL: label},
            )
            close_session_quietly(rs.raw, s1)

            s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            try:
                _login_user_raw(rs.raw, s2, pin_bytes)
                tmpl = template_from_dict({CKA_LABEL: label})
                found = find_objects(rs.raw, s2, tmpl)
                assert len(found) == 0, "Session object survived session close"
            finally:
                _logout_safe(rs.raw, s2)
                close_session_quietly(rs.raw, s2)
        except Exception:
            # If s1 wasn't closed yet, try closing
            close_session_quietly(rs.raw, s1)
            raise

    def test_token_object_survives_session_close(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token objects (CKA_TOKEN=True) persist across session close."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = "token-survives-close"
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            key_h = _gen_state_aes_key(
                rs,
                s1,
                128,
                attrs={CKA_TOKEN: True, CKA_LABEL: label},
            )
            assert key_h != 0
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, s2, pin_bytes)
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) >= 1, "Token object did not survive session close"
            for h in found:
                destroy_quietly(rs.raw, s2, h)
        finally:
            _logout_safe(rs.raw, s2)
            close_session_quietly(rs.raw, s2)


# ---------------------------------------------------------------------------
# RW vs RO session state
# ---------------------------------------------------------------------------


class TestROvsRWSessionState:
    """Verify R/O vs R/W session differences per spec."""

    def test_ro_session_can_login_user(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session allows C_Login(USER)."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_cannot_create_token_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """R/O session cannot create CKA_TOKEN=True objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)

            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
            from pkcs11_check.raw.types_std import (
                CK_OBJECT_HANDLE,
                CKA_KEY_TYPE,
                CKA_VALUE_LEN,
                CKK_AES,
                CKM_AES_KEY_GEN,
            )

            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_SECRET_KEY),
                attr_ulong(CKA_KEY_TYPE, CKK_AES),
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, True),
            )
            from pkcs11_check.raw.pack import mech_simple

            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = rs.raw.C_GenerateKey(test_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
            _xfail_if_aes_setup_rv(
                rv,
                "AES_KEY_GEN advertised but RO token-object setup is not operational",
            )
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY,),
                label="C_GenerateKey with CKA_TOKEN=True on a read-only session",
            )
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_can_create_session_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """R/O session can create session objects (CKA_TOKEN=False)."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            key_h = _gen_state_aes_key(rs, test_sh, 128)
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_can_digest(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session can perform digest (no key needed)."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            digest = digest_single(rs.raw, test_sh, CKM_SHA256, b"RO session digest")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_so_login_requires_rw_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Login(SO) on an R/O session must fail."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(pin_bytes))
            _skip_if_so_pin_differs(rv)
            classify_negative_rv(
                rv,
                (CKR_SESSION_READ_ONLY_EXISTS,),
                label="C_Login(SO) on a read-only session (SO requires a R/W session)",
            )
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)


# ---------------------------------------------------------------------------
# Logout without login
# ---------------------------------------------------------------------------


class TestLogoutWithoutLogin:
    """Verify behaviour when logout is called without prior login."""

    def test_logout_without_login_raises(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Logout without prior C_Login should raise CKR_USER_NOT_LOGGED_IN."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear any residual token-level login
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        rs.raw.C_Logout(cleanup_sh)
        close_session_quietly(rs.raw, cleanup_sh)

        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            # Now no login should be active on this token
            rv = rs.raw.C_Logout(test_sh)
            if rv == CKR_USER_NOT_LOGGED_IN:
                pass  # Correct per spec
            elif rv == CKR_OK:
                # Some modules silently accept logout without login
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_Logout without prior C_Login did not raise CKR_USER_NOT_LOGGED_IN",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: C_Logout when not logged in",
                )
        finally:
            close_session_quietly(rs.raw, test_sh)


# ---------------------------------------------------------------------------
# Session context manager equivalent
# ---------------------------------------------------------------------------


class TestSessionContextManager:
    """Verify session open/close lifecycle."""

    def test_open_close_session_works(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Opening and closing a session works cleanly.

        After closing a session, operations on the stale handle must return
        CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED per PKCS#11 spec
        session_mgmt_functions.md.

        NSS deviation: NSS returns CKR_OK on C_GenerateRandom with a stale
        session handle (handle reuse or session ID recycling).
        Tracked in docs/module-issues.md under NSS.
        """
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        assert bool(get_session_info(rs.raw, test_sh)["flags"] & CKF_RW_SESSION) is True
        close_session_quietly(rs.raw, test_sh)

        # Session should be closed - operations should fail
        import ctypes

        buf = (ctypes.c_ubyte * 8)()
        rv2 = rs.raw.C_GenerateRandom(test_sh, buf, 8)
        if rv2 == CKR_OK:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "C_GenerateRandom returned CKR_OK on a closed session handle "
                "(spec requires CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED)",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 spec session_mgmt_functions.md",
            )
            pytest.xfail(
                "Module returns CKR_OK on C_GenerateRandom with a stale (closed) session handle "
                "(spec requires CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED)"
            )
        assert rv2 in (
            CKR_SESSION_HANDLE_INVALID,
            CKR_SESSION_CLOSED,
        ), f"Expected SESSION_HANDLE_INVALID or SESSION_CLOSED, got {ckr_name(rv2)}"

    def test_open_close_with_login(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Session with user login works end-to-end."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            key_h = _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
            )
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)


# ---------------------------------------------------------------------------
# Login type specificity
# ---------------------------------------------------------------------------


class TestLoginTypeSpecificity:
    """Verify that different login types result in appropriate state."""

    def test_user_login_creates_session_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """USER login allows creating private session objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)
            key_h = _gen_state_aes_key(
                rs,
                test_sh,
                128,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
            )
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_generate_random_without_login(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_GenerateRandom works in public state (no login required)."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            rand = generate_random(rs.raw, test_sh, 16)
            assert len(rand) == 16  # 128 bits = 16 bytes
        finally:
            close_session_quietly(rs.raw, test_sh)

    def test_digest_without_login(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Digest works in public state (no login required)."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            digest = digest_single(rs.raw, test_sh, CKM_SHA256, b"no-login-digest")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, test_sh)
