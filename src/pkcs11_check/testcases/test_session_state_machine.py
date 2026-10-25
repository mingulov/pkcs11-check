"""Session state machine verification tests.

Verifies PKCS#11 session state transitions per the OASIS spec
session-management functions - login states, session flags, concurrent
session behavior, and logout effects.

States:
  - Public session (R/O or R/W): no login, only public objects visible.
  - User Functions session (R/O or R/W): after C_Login(USER).
  - SO Functions session (R/W only): after C_Login(SO).
"""

from __future__ import annotations

import sys
import uuid
from ctypes import byref, c_ubyte
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as, xfail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    create_object as _raw_create_object,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    find_objects,
    generate_random,
    get_session_info,
    read_attributes,
    to_ubyte_buf,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
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
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
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
    CKS_RO_PUBLIC_SESSION,
    CKS_RW_PUBLIC_SESSION,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    refusal_rv_for,
)
from pkcs11_check.testcases._so_login import (
    guard_so_lockout,
    resolve_so_pin,
    skip_if_so_pin_rejected,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    classify_lifecycle_effect,
    classify_negative_rv,
    gen_aes_key_or_xfail,
    get_pin_bytes,
    is_known_error,
    reject_or_classify,
    skip_unless_generate_random_supported,
    skip_unless_mechanism,
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
        classify(
            "not_operational",
            label=context,
            operation="C_GenerateKey",
            actual=rv,
            summary=f"{context}: {ckr_name(rv)}",
        )


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


def _cleanup_owned_token_object(raw: Any, sh: int, pin_bytes: bytes | None, tmpl: Any) -> None:
    """Best-effort destroy of an owned private token object (P1).

    Token objects survive logout and session close, so a terminal
    verdict must not leak them. The object is reacquired by exact
    template -- relogging in first when it is invisible in the public
    state -- and everything found is destroyed. A cleanup failure is
    noted on the primary exception when one is in flight and otherwise
    raised, so the primary finding is never masked and a leak is never
    silent.
    """
    pending = sys.exception()
    try:
        found = find_objects(raw, sh, tmpl)
        if not found:
            _login_user_raw(raw, sh, pin_bytes)
            found = find_objects(raw, sh, tmpl)
        for handle in found:
            destroy_quietly(raw, sh, handle)
    except Exception as exc:  # cleanup must never mask the primary verdict
        if pending is None:
            raise
        pending.add_note(f"owned token cleanup also raised {type(exc).__name__}: {exc}")


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
            # F-008: login is token-wide and the fixture may hold one, so a
            # fresh handle does not imply public state. Settle to logged-out
            # first (safe: this fixture is function-scoped and its teardown
            # logout tolerates the logged-out state)...
            _logout_safe(rs.raw, test_sh)
            # ...and prove it with an explicit state observation.
            state = int(get_session_info(rs.raw, test_sh)["state"])
            if state not in (int(CKS_RO_PUBLIC_SESSION), int(CKS_RW_PUBLIC_SESSION)):
                xfail_as(
                    "honest_deviation",
                    kind="lifecycle",
                    label="public session precondition",
                    detail={"session_state": state},
                    summary=(
                        "session still reports non-public state "
                        f"{state:#x} after settling logout; cannot probe "
                        "public-state visibility"
                    ),
                )
            # Without login, private objects should be invisible
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, test_sh, tmpl)
            if found:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="private objects visible in a public session",
                    summary=(
                        f"{len(found)} private key(s) visible in a session reporting public state"
                    ),
                )
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
                sh=test_sh,
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
                sh=test_sh,
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
                sh=test_sh,
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
        so_pin, explicit = resolve_so_pin(p11_config)
        assert so_pin is not None  # pin_bytes above guarantees the fallback
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            skip_if_so_pin_rejected(rv, explicit=explicit)
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
        so_pin, explicit = resolve_so_pin(p11_config)
        assert so_pin is not None  # pin_bytes above guarantees the fallback
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            skip_if_so_pin_rejected(rv, explicit=explicit)
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
        so_pin, explicit = resolve_so_pin(p11_config)
        assert so_pin is not None
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            _login_user_raw(rs.raw, test_sh, pin_bytes)

            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            skip_if_so_pin_rejected(rv, explicit=explicit)
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
                sh=s1,
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
            gen_aes_key_or_xfail(
                rs,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
                sh=s1,
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
# Logout object-lifetime oracles (QC9b)
#
# A successful C_Logout invalidates every old private-object handle
# (session and token alike, permanently) and destroys the application's
# private session objects; public session objects remain and private token
# objects persist (PKCS#11 v3.0 section 5.6.10). Shared with
# security/test_cve_regression.py, which owns the repaired single-session
# premise.
# ---------------------------------------------------------------------------


def _note_logout_observation(description: str) -> None:
    """Record a neutral logout-lifetime observation (never a verdict)."""
    from pkcs11_check.compliance import ComplianceLevel, note

    note(description, ComplianceLevel.STANDARD, reference="PKCS#11 v3.0 section 5.6.10")


def _assert_explicit_lifetime_attrs(
    raw: Any,
    sh: int,
    handle: int,
    *,
    label: str,
    want_private: bool,
    want_token: bool,
) -> None:
    """Prove a logout-lifetime stimulus: read back CKA_PRIVATE/CKA_TOKEN.

    The destruction/hiding/persistence oracles are only sound for an object
    proven to carry the requested visibility attributes. A module that
    accepted creation but stored something else claimed success then
    contradicted it (fail); unreadable attributes leave the premise
    unprovable (xfail).
    """
    attrs = read_attributes(raw, sh, handle, [CKA_PRIVATE, CKA_TOKEN])
    private_raw = attr_or_record(
        attrs,
        CKA_PRIVATE,
        label=f"{label} CKA_PRIVATE readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    token_raw = attr_or_record(
        attrs,
        CKA_TOKEN,
        label=f"{label} CKA_TOKEN readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if private_raw is MISSING_ATTRIBUTE or token_raw is MISSING_ATTRIBUTE:
        xfail_as(
            "not_operational",
            kind="metadata",
            label=f"{label} lifetime premise",
            summary=f"{label}: CKA_PRIVATE/CKA_TOKEN unreadable; lifetime premise unprovable",
        )
    classify_lifecycle_effect(
        claimed_success=True,
        effect_observed=(private_raw is not want_private or token_raw is not want_token),
        label=f"{label} honors requested CKA_PRIVATE/CKA_TOKEN at creation",
    )


def _assert_old_private_handle_invalid(
    raw: Any, sh: int, handle: int, *, label: str, phase: str
) -> None:
    """Probe an old private handle after logout; it must be unusable.

    C_GetAttributeValue on an invalidated handle must reject with
    CKR_OBJECT_HANDLE_INVALID: usability is a lifecycle self-contradiction
    (fail), another clean code an honest deviation (xfail). ``phase`` names
    the checkpoint: immediately after logout, or after relogin before
    reacquisition.

    ``read_attributes`` absorbs CKR_ATTRIBUTE_SENSITIVE and
    CKR_ATTRIBUTE_TYPE_INVALID into its ``refusals`` channel instead of
    raising; those refusals are non-canonical clean rejects (xfail with the
    original RV), never usable handles (no fabricated ``accepted_invalid``).
    A refusal-with-data (refusal CKR plus returned bytes) is a measured
    self-contradiction, not a clean rejection: it is recorded structurally
    via ``attr_or_record`` and then failed, never xfailed.
    """
    probe_label = f"old private handle for {label} ({phase})"
    try:
        observed = read_attributes(raw, sh, handle, [CKA_CLASS])
    except CkrAssertionError as exc:
        reject_or_classify(
            exc,
            (CKR_OBJECT_HANDLE_INVALID,),
            label=probe_label,
            kind="lifecycle",
        )
    else:
        refusal_rv = refusal_rv_for(observed, CKA_CLASS)
        if refusal_rv is not None:
            reject_or_classify(
                CkrAssertionError(
                    f"Unexpected CK_RV {ckr_name(refusal_rv)}",
                    refusal_rv,
                ),
                (CKR_OBJECT_HANDLE_INVALID,),
                label=probe_label,
                kind="lifecycle",
            )
        else:
            probe_value = attr_or_record(
                observed,
                CKA_CLASS,
                label=f"{probe_label} CKA_CLASS readback",
                reason="not_operational",
                kind="lifecycle",
                inherit_mechanism=False,
            )
            if probe_value is MISSING_ATTRIBUTE:
                classify_lifecycle_effect(
                    claimed_success=True,
                    effect_observed=True,
                    label=f"{probe_label} neither usable nor cleanly rejected",
                )
            else:
                reject_or_classify(
                    None,
                    (CKR_OBJECT_HANDLE_INVALID,),
                    label=probe_label,
                    kind="lifecycle",
                )


def _assert_post_relogin_presence(*, found: bool, must_exist: bool, label: str) -> None:
    """Verdict for a post-relogin reacquisition search after logout.

    The claimed success is the successful C_Logout. The contradicting
    effect is a must-be-destroyed object reappearing (hidden, not
    destroyed) or a must-persist object gone. Handle integers are never
    compared: a reacquired handle may reuse the old integer.
    """
    classify_lifecycle_effect(
        claimed_success=True,
        effect_observed=(found != must_exist),
        label=label,
    )


def _assert_reacquired_token_handle_usable(
    raw: Any,
    sh: int,
    handle: int,
    *,
    label: str,
    want_class: int,
    want_label: str,
) -> None:
    """Prove a reacquired token handle usable with the expected identity.

    A post-relogin search returning a handle is not enough: the handle
    must answer attribute reads and report the expected class and label.
    The search just claimed the object persists, so any unusability or
    identity mismatch is a lifecycle self-contradiction (fail). Handle
    integers are never compared: a reused integer is accepted.
    """
    try:
        attrs = read_attributes(raw, sh, handle, [CKA_CLASS, CKA_LABEL])
    except CkrAssertionError as exc:
        classify_lifecycle_effect(
            claimed_success=True,
            effect_observed=True,
            label=f"{label} reacquired handle unusable (observed {ckr_name(exc.rv)})",
        )
        return
    class_raw = attr_or_record(
        attrs,
        CKA_CLASS,
        label=f"{label} reacquired CKA_CLASS readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    label_raw = attr_or_record(
        attrs,
        CKA_LABEL,
        label=f"{label} reacquired CKA_LABEL readback",
        reason="not_operational",
        kind="metadata",
        inherit_mechanism=False,
    )
    if class_raw is MISSING_ATTRIBUTE or label_raw is MISSING_ATTRIBUTE:
        classify_lifecycle_effect(
            claimed_success=True,
            effect_observed=True,
            label=f"{label} reacquired handle reports expected identity",
        )
        return
    identity_ok = class_raw == want_class and label_raw == want_label
    classify_lifecycle_effect(
        claimed_success=True,
        effect_observed=not identity_ok,
        label=f"{label} reacquired handle reports expected identity",
    )


def _stage_held_open_find(raw: Any, sh: int) -> bool:
    """Stage a held-open find for the logout observation leg."""
    rv = raw.C_FindObjectsInit(sh, None, 0)
    if rv != CKR_OK:
        _note_logout_observation(
            "Find-operation logout observation not staged: C_FindObjectsInit "
            f"rejected with {ckr_name(rv)}"
        )
        return False
    return True


def _observe_held_open_find(raw: Any, sh: int) -> None:
    """Continue the held-open find after logout; either outcome is conformant."""
    buf = (CK_OBJECT_HANDLE * 8)()
    count = CK_ULONG(0)
    rv = raw.C_FindObjects(sh, buf, 8, byref(count))
    raw.C_FindObjectsFinal(sh)
    if rv == CKR_OK:
        _note_logout_observation(
            "Active C_FindObjects search survived C_Logout (remains usable); "
            "PKCS#11 v3.0 section 5.6.10 permits active operations to remain "
            "or terminate -- observation only"
        )
    else:
        _note_logout_observation(
            "Active C_FindObjects search ended across C_Logout "
            f"(terminated with {ckr_name(rv)}); PKCS#11 v3.0 section 5.6.10 "
            "permits active operations to remain or terminate -- observation only"
        )


def _stage_held_open_digest(rs: Any, sh: int) -> bool:
    """Stage a held-open digest for the logout observation leg."""
    if not rs.has_mechanism("SHA256"):
        _note_logout_observation(
            "Digest-operation logout observation not staged: CKM_SHA256 unavailable"
        )
        return False
    mech = mech_simple(CKM_SHA256)
    rv = rs.raw.C_DigestInit(sh, mech.byref())
    if rv != CKR_OK:
        _note_logout_observation(
            "Digest-operation logout observation not staged: C_DigestInit "
            f"rejected with {ckr_name(rv)}"
        )
        return False
    return True


def _observe_held_open_digest(raw: Any, sh: int) -> None:
    """Continue the held-open digest after logout; either outcome is conformant."""
    data = b"qc9b-digest-probe"
    in_buf = to_ubyte_buf(data)
    rv = raw.C_DigestUpdate(sh, in_buf, len(data))
    out_buf = (c_ubyte * 64)()
    out_len = CK_ULONG(64)
    raw.C_DigestFinal(sh, out_buf, byref(out_len))
    if rv == CKR_OK:
        _note_logout_observation(
            "Active C_Digest operation survived C_Logout (remains usable); "
            "PKCS#11 v3.0 section 5.6.10 permits active operations to remain "
            "or terminate -- observation only"
        )
    else:
        _note_logout_observation(
            "Active C_Digest operation ended across C_Logout "
            f"(terminated with {ckr_name(rv)}); PKCS#11 v3.0 section 5.6.10 "
            "permits active operations to remain or terminate -- observation only"
        )


def _abandon_held_open_operations(
    raw: Any, find_sh: int, digest_sh: int, *, find_staged: bool, digest_staged: bool
) -> None:
    """Release staged observation operations when logout fails (no verdicts)."""
    if find_staged:
        raw.C_FindObjectsFinal(find_sh)
    if digest_staged:
        out_buf = (c_ubyte * 64)()
        out_len = CK_ULONG(64)
        raw.C_DigestFinal(digest_sh, out_buf, byref(out_len))


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
            gen_aes_key_or_xfail(
                rs,
                attrs={
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
                sh=test_sh,
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

    def test_logout_object_lifetime_across_two_sessions(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """QC9b: logout destroys private session objects and invalidates handles.

        Explicit private-session, public-session and private-token objects
        across two sessions. A successful C_Logout invalidates ALL old
        private handles, checked immediately after logout and after relogin
        before reacquisition: the private session object is destroyed, the
        public session object remains, and the private token object persists
        and is reacquirable. Held-open crypto/find operations are observed
        only (PKCS#11 v3.0 section 5.6.10 permits either outcome).
        """
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            tok_label: str | None = None
            tok_created = False
            tok_cleaned = False
            try:
                _login_user_raw(rs.raw, s1, pin_bytes)

                nonce = uuid.uuid4().hex[:12]
                priv_label = f"qc9b-priv-session-{nonce}"
                pub_label = f"qc9b-pub-session-{nonce}"
                tok_label = f"qc9b-priv-token-{nonce}"
                priv_h = gen_aes_key_or_xfail(
                    rs,
                    128,
                    attrs={
                        CKA_TOKEN: False,
                        CKA_PRIVATE: True,
                        CKA_LABEL: priv_label,
                    },
                    purpose="QC9b private session object",
                    sh=s1,
                )
                _assert_explicit_lifetime_attrs(
                    rs.raw,
                    s1,
                    priv_h,
                    label="QC9b private session object",
                    want_private=True,
                    want_token=False,
                )
                pub_h = _create_state_data_object(
                    rs,
                    s2,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: pub_label,
                        CKA_VALUE: b"qc9b-public",
                        CKA_TOKEN: False,
                        CKA_PRIVATE: False,
                    },
                )
                _assert_explicit_lifetime_attrs(
                    rs.raw,
                    s2,
                    pub_h,
                    label="QC9b public session object",
                    want_private=False,
                    want_token=False,
                )
                tok_h = gen_aes_key_or_xfail(
                    rs,
                    128,
                    attrs={
                        CKA_TOKEN: True,
                        CKA_PRIVATE: True,
                        CKA_LABEL: tok_label,
                    },
                    purpose="QC9b private token object",
                    sh=s1,
                )
                tok_created = True
                _assert_explicit_lifetime_attrs(
                    rs.raw,
                    s1,
                    tok_h,
                    label="QC9b private token object",
                    want_private=True,
                    want_token=True,
                )

                # Setup proof: each object is visible before logout.
                tmpl_priv = template_from_dict({CKA_CLASS: CKO_SECRET_KEY, CKA_LABEL: priv_label})
                tmpl_pub = template_from_dict({CKA_CLASS: CKO_DATA, CKA_LABEL: pub_label})
                tmpl_tok = template_from_dict({CKA_CLASS: CKO_SECRET_KEY, CKA_LABEL: tok_label})
                assert priv_h in find_objects(rs.raw, s1, tmpl_priv)
                assert pub_h in find_objects(rs.raw, s2, tmpl_pub)
                assert tok_h in find_objects(rs.raw, s2, tmpl_tok)

                # Stage held-open operations for the observation legs.
                find_staged = _stage_held_open_find(rs.raw, s1)
                digest_staged = _stage_held_open_digest(rs, s2)

                # Logout via s1; the oracle below needs it to succeed.
                logout_rv = rs.raw.C_Logout(s1)
                if logout_rv != CKR_OK:
                    _abandon_held_open_operations(
                        rs.raw, s1, s2, find_staged=find_staged, digest_staged=digest_staged
                    )
                    destroy_quietly(rs.raw, s1, priv_h)
                    destroy_quietly(rs.raw, s2, pub_h)
                    destroy_quietly(rs.raw, s1, tok_h)
                    tok_cleaned = True
                    classify_negative_rv(
                        logout_rv,
                        (),
                        label="C_Logout for object-lifetime oracle",
                    )
                    return

                # Successful logout invalidates all old private handles:
                # probe immediately after logout, from both sessions.
                for sh in (s1, s2):
                    _assert_old_private_handle_invalid(
                        rs.raw,
                        sh,
                        priv_h,
                        label="QC9b private session object",
                        phase="immediately after C_Logout",
                    )
                    _assert_old_private_handle_invalid(
                        rs.raw,
                        sh,
                        tok_h,
                        label="QC9b private token object",
                        phase="immediately after C_Logout",
                    )
                # The public session object remains usable across logout:
                # any unusability right after logout fails, whatever the code.
                try:
                    pub_attrs = read_attributes(rs.raw, s2, pub_h, [CKA_CLASS])
                except CkrAssertionError as exc:
                    pub_usable: bool = False
                    pub_observed = ckr_name(exc.rv)
                else:
                    pub_usable = CKA_CLASS in pub_attrs
                    pub_observed = "CKR_OK with no CKA_CLASS" if not pub_usable else "CKR_OK"
                classify_lifecycle_effect(
                    claimed_success=True,
                    effect_observed=not pub_usable,
                    label="QC9b public session object remains usable across C_Logout "
                    f"(observed {pub_observed})",
                )

                # Held-open operations: observe only, never a verdict.
                if find_staged:
                    _observe_held_open_find(rs.raw, s1)
                if digest_staged:
                    _observe_held_open_digest(rs.raw, s2)

                # Relogin, then probe the old private handles again BEFORE
                # reacquisition: relogin must not resurrect them.
                _login_user_raw(rs.raw, s1, pin_bytes)
                for sh in (s1, s2):
                    _assert_old_private_handle_invalid(
                        rs.raw,
                        sh,
                        priv_h,
                        label="QC9b private session object",
                        phase="after relogin before reacquisition",
                    )
                    _assert_old_private_handle_invalid(
                        rs.raw,
                        sh,
                        tok_h,
                        label="QC9b private token object",
                        phase="after relogin before reacquisition",
                    )

                # Reacquisition verdicts. The private session object was
                # destroyed (reappearing means hidden, not destroyed); the
                # public session object remains; the private token object
                # persists. Reacquired integers are never compared.
                found_priv = find_objects(rs.raw, s1, tmpl_priv)
                _assert_post_relogin_presence(
                    found=len(found_priv) > 0,
                    must_exist=False,
                    label="QC9b private session object destroyed by C_Logout",
                )
                found_pub = find_objects(rs.raw, s2, tmpl_pub)
                _assert_post_relogin_presence(
                    found=len(found_pub) > 0,
                    must_exist=True,
                    label="QC9b public session object remains across C_Logout",
                )
                found_tok = find_objects(rs.raw, s2, tmpl_tok)
                _assert_post_relogin_presence(
                    found=len(found_tok) > 0,
                    must_exist=True,
                    label="QC9b private token object persists across C_Logout",
                )
                if len(found_tok) > 0:
                    _assert_reacquired_token_handle_usable(
                        rs.raw,
                        s2,
                        found_tok[0],
                        label="QC9b private token object",
                        want_class=int(CKO_SECRET_KEY),
                        want_label=tok_label,
                    )
                for h in found_pub:
                    destroy_quietly(rs.raw, s2, h)
                for h in found_tok:
                    destroy_quietly(rs.raw, s1, h)
                tok_cleaned = True
            finally:
                if tok_created and not tok_cleaned and tok_label is not None:
                    _cleanup_owned_token_object(
                        rs.raw,
                        s1,
                        pin_bytes,
                        template_from_dict({CKA_CLASS: CKO_SECRET_KEY, CKA_LABEL: tok_label}),
                    )
                _logout_safe(rs.raw, s2)
                close_session_quietly(rs.raw, s2)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_generate_random_works_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_GenerateRandom does not require login - works in public state."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        skip_unless_generate_random_supported(rs)
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
            gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: False, CKA_LABEL: label},
                sh=s1,
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: True, CKA_LABEL: label},
                sh=s1,
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
            key_h = gen_aes_key_or_xfail(rs, sh=test_sh)
            assert key_h != 0
            destroy_quietly(rs.raw, test_sh, key_h)
        finally:
            _logout_safe(rs.raw, test_sh)
            close_session_quietly(rs.raw, test_sh)

    def test_ro_session_can_digest(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session can perform digest (no key needed)."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256")
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
        so_pin, explicit = resolve_so_pin(p11_config)
        assert so_pin is not None
        guard_so_lockout(rs.raw, rs.slot_id, explicit=explicit)
        flags = CKF_SERIAL_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            pin_buf = (CK_UTF8CHAR * len(so_pin))(*so_pin)
            rv = rs.raw.C_Login(test_sh, CKU_SO, pin_buf, len(so_pin))
            skip_if_so_pin_rejected(rv, explicit=explicit)
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
        CKR_SESSION_HANDLE_INVALID or CKR_SESSION_CLOSED per the PKCS#11 spec
        session-management functions.

        Observed deviation: some modules return CKR_OK on C_GenerateRandom with a stale
        session handle (handle reuse or session ID recycling).
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
                reference="PKCS#11 spec session-management functions",
            )
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label="C_GenerateRandom:stale-session-handle",
                operation="C_GenerateRandom",
                actual=rv2,
                expected=[CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED],
                summary=(
                    "Module returns CKR_OK on C_GenerateRandom with a stale (closed) "
                    "session handle (spec requires CKR_SESSION_HANDLE_INVALID or "
                    "CKR_SESSION_CLOSED)"
                ),
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
                sh=test_sh,
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
            key_h = gen_aes_key_or_xfail(
                rs,
                attrs={CKA_TOKEN: False, CKA_PRIVATE: True},
                sh=test_sh,
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
        skip_unless_mechanism(rs, "SHA256")
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            digest = digest_single(rs.raw, test_sh, CKM_SHA256, b"no-login-digest")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, test_sh)
