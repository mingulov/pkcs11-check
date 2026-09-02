"""Tests for C_LoginUser (v3.0+) and context-specific login.

C_LoginUser is a PKCS#11 v3.0 extension to C_Login that additionally accepts
a username string.  It is used to authenticate as a named user rather than
one of the fixed CKU_USER / CKU_SO roles.

CKU_CONTEXT_SPECIFIC (user type 2) is used after a normal CKU_USER login to
re-authenticate before using a CKA_ALWAYS_AUTHENTICATE private key.  The
PKCS#11 spec requires context-specific re-auth immediately before each
CKM_* operation on such a key.

Source: PKCS#11 v3.0 Sec.5.5  C_Login / C_LoginUser
        PKCS#11 v2.40 Sec.11.6 (CKU_CONTEXT_SPECIFIC semantics)
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import fail_as, xfail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user_with_name,
    logout_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CK_UTF8CHAR,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_SHA256,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_PIN_INCORRECT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_CONTEXT_SPECIFIC,
    CKU_USER,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases._subprocess_result import assert_subprocess_completed
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.access]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pin_bytes(p11_config: Any) -> bytes | None:
    """Return the PIN as bytes, or None if not configured."""
    if p11_config.pin is None:
        return None
    encoded: bytes = p11_config.pin.get_secret_value().encode("utf-8")
    return encoded


def _raw_login(raw: Any, sh: int, user_type: int, pin: bytes) -> int:
    """Call C_Login and return the raw CKR."""
    pin_buf = (CK_UTF8CHAR * len(pin))(*pin)
    return int(raw.C_Login(sh, user_type, pin_buf, len(pin)))


def _raw_login_user(
    raw: Any,
    sh: int,
    user_type: int,
    pin: bytes,
    username: bytes,
) -> int:
    """Call C_LoginUser and return the raw CKR."""
    pin_buf = (CK_UTF8CHAR * len(pin))(*pin)
    user_buf = (CK_UTF8CHAR * len(username))(*username) if username else None
    user_len = len(username) if username else 0
    return int(raw.C_LoginUser(sh, user_type, pin_buf, len(pin), user_buf, user_len))


def _raw_logout(raw: Any, sh: int) -> int:
    """Call C_Logout and return the raw CKR."""
    return int(raw.C_Logout(sh))


# ---------------------------------------------------------------------------
# C_LoginUser tests
# ---------------------------------------------------------------------------

_CONTEXT_OK = {CKR_OK, CKR_USER_ALREADY_LOGGED_IN}
_LOGIN_REJECT = {
    CKR_USER_TYPE_INVALID,
    CKR_ARGUMENTS_BAD,
    CKR_PIN_INCORRECT,
}


def _classify_unexpected_login_rv(rv: int, label: str) -> None:
    """Keep undefined CK_RVs hard while retaining visible clean-reject xfails."""
    if not is_standard_ckr(rv) and not is_vendor_defined_ckr(rv):
        classify_negative_rv(rv, (), label=label)


def _handle_cancel_rv(rv: int, label: str) -> None:
    """Classify a C_SessionCancel result without hiding unknown return codes."""
    if rv == CKR_OK:
        return
    if rv == CKR_FUNCTION_NOT_SUPPORTED:
        xfail_as(
            "not_operational",
            label=label,
            operation="C_SessionCancel",
            actual=rv,
            summary=(
                "Module exposes v3.0 interface but C_SessionCancel returns "
                "CKR_FUNCTION_NOT_SUPPORTED"
            ),
        )
    classify_negative_rv(rv, (), label=label)


class TestCLoginUser:
    """C_LoginUser (v3.0+) exercises the username parameter path.

    C_LoginUser extends C_Login with a (pUsername, ulUsernameLen) pair.
    On v2.40 modules the function does not exist in the function list.
    """

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_empty_username_user_type(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_LoginUser with empty username string exercises the v3.0 code path.

        The PKCS#11 spec allows pUsername / ulUsernameLen = NULL / 0 to mean
        "default user".  Most tokens accept this and treat it identically to
        C_Login(CKU_USER).

        Expected outcomes (all acceptable):
        - CKR_OK - module treats it as a normal user login.
        - CKR_USER_ALREADY_LOGGED_IN - p11_raw_session already logged in.
        - CKR_FUNCTION_NOT_SUPPORTED - module exposes v3.0 interface but
          didn't implement C_LoginUser (unusual but legal).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot exercise C_LoginUser")

        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("C_LoginUser not in module function list")

        # p11_raw_session is already logged in as CKU_USER.
        # Exercise C_LoginUser with an empty username.
        rv = _raw_login_user(rs.raw, rs.sh, CKU_USER, pin, b"")
        if rv == CKR_USER_ALREADY_LOGGED_IN:
            pass  # Acceptable: we are already logged in as USER.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )
        elif rv == CKR_OK:
            pass  # Accepted.
        else:
            _classify_unexpected_login_rv(rv, "C_LoginUser")
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=f"C_LoginUser returned an unexpected clean CKR: {ckr_name(rv)}",
            )

    def test_c_login_user_not_available_on_v240(
        self,
        p11_raw_session: Any,
        p11_interface_version: str,
    ) -> None:
        """C_LoginUser is not in the function list on a v2.40 module.

        This test only runs if the negotiated version is exactly 2.40.
        """
        if p11_interface_version != "2.40":
            pytest.skip("This test is specifically for v2.40 modules")

        rs = p11_raw_session
        assert "C_LoginUser" not in rs.raw.available_function_names(), (
            "C_LoginUser should not be in the v2.40 function list"
        )

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_non_empty_username(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_LoginUser with a non-empty username does not crash the module.

        Tokens that implement named users accept a username string.  Tokens
        that only support the traditional CKU_USER role will reject with
        CKR_USER_TYPE_INVALID, CKR_FUNCTION_NOT_SUPPORTED, or similar.
        The important property is that the module returns a well-formed CKR
        rather than crashing or hanging.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot exercise C_LoginUser")

        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("C_LoginUser not in module function list")

        rv = _raw_login_user(rs.raw, rs.sh, CKU_USER, pin, b"user")
        if rv == CKR_OK or rv == CKR_USER_ALREADY_LOGGED_IN:
            pass  # Accepted or already logged in.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )
        elif rv in _LOGIN_REJECT:
            pass  # Module does not support named users - acceptable.
        else:
            _classify_unexpected_login_rv(rv, "C_LoginUser")
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=f"C_LoginUser returned an unexpected clean CKR: {ckr_name(rv)}",
            )

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_utf8_multibyte_username(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_LoginUser with a multi-byte UTF-8 username does not crash.

        Spec §5.5 defines pUsername as CK_UTF8CHAR_PTR — UTF-8 encoded.
        Multi-byte sequences are valid input.  Modules may not implement
        named users, but must at least return a defined CKR.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot exercise C_LoginUser")
        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("C_LoginUser not in module function list")

        # "用户" = "user" in Chinese; 6 bytes of UTF-8 from 2 code points
        username = "用户".encode()
        rv = _raw_login_user(rs.raw, rs.sh, CKU_USER, pin, username)
        if rv == CKR_OK or rv == CKR_USER_ALREADY_LOGGED_IN:
            pass  # Module accepted the multi-byte username.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )
        elif rv in _LOGIN_REJECT:
            pass  # Reject is OK; named-users not implemented.
        else:
            _classify_unexpected_login_rv(rv, "C_LoginUser:utf8-username")
            xfail_as(
                "not_operational",
                label="C_LoginUser:utf8-username",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    f"C_LoginUser with a UTF-8 multi-byte username returned an "
                    f"unexpected clean CKR: {ckr_name(rv)}"
                ),
            )

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_long_username(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """A long username (1024 bytes) must not crash the module.

        Spec doesn't bound the length; modules that copy into a fixed
        buffer without bounds-checking would segfault here.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot exercise C_LoginUser")
        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("C_LoginUser not in module function list")

        username = b"u" * 1024
        rv = _raw_login_user(rs.raw, rs.sh, CKU_USER, pin, username)
        # Any defined CKR is acceptable.  What we're catching is a segfault
        # (which manifests as an unhandled signal in the parent process).
        # Most modules reject with CKR_USER_TYPE_INVALID or similar.
        if rv == CKR_OK or rv == CKR_USER_ALREADY_LOGGED_IN:
            pass
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )
        elif rv in _LOGIN_REJECT or rv == CKR_ARGUMENTS_BAD:
            pass
        else:
            _classify_unexpected_login_rv(rv, "C_LoginUser:long-username")
            xfail_as(
                "not_operational",
                label="C_LoginUser:long-username",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    f"C_LoginUser with a 1024-byte username returned an "
                    f"unexpected clean CKR: {ckr_name(rv)}"
                ),
            )

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_username_with_embedded_nul(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Username containing an embedded NUL byte is handled as length-prefixed.

        Spec §5.5 uses (pUsername, ulUsernameLen) so NUL bytes within
        the string are valid.  A module that calls strlen() on
        pUsername would truncate at the NUL — buggy but not security-
        critical.  A crash here is the real finding.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot exercise C_LoginUser")
        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("C_LoginUser not in module function list")

        username = b"user\x00admin"  # 10 bytes, embedded NUL at index 4
        rv = _raw_login_user(rs.raw, rs.sh, CKU_USER, pin, username)
        if rv == CKR_OK or rv == CKR_USER_ALREADY_LOGGED_IN:
            pass
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module exposes v3.0 interface but C_LoginUser returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )
        elif rv in _LOGIN_REJECT or rv == CKR_ARGUMENTS_BAD:
            pass
        else:
            _classify_unexpected_login_rv(rv, "C_LoginUser:embedded-nul-username")
            xfail_as(
                "not_operational",
                label="C_LoginUser:embedded-nul-username",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    f"C_LoginUser with an embedded-NUL username returned an "
                    f"unexpected clean CKR: {ckr_name(rv)}"
                ),
            )


# ---------------------------------------------------------------------------
# CKU_CONTEXT_SPECIFIC tests (C_Login type 2)
# ---------------------------------------------------------------------------


class TestContextSpecificLogin:
    """CKU_CONTEXT_SPECIFIC (user type 2) exercises the reaffirm-credentials path.

    Context-specific login re-authenticates the user immediately before an
    operation on a CKA_ALWAYS_AUTHENTICATE key.  Without a key that has that
    attribute set, calling C_Login(CKU_CONTEXT_SPECIFIC) outside an active
    operation returns CKR_OPERATION_NOT_INITIALIZED.

    These tests verify:
    1. C_Login with user_type=2 is callable.
    2. The module returns a well-formed CKR (not a crash).
    """

    def test_context_specific_login_without_active_op(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """CKU_CONTEXT_SPECIFIC login without an active op returns CKR_OPERATION_NOT_INITIALIZED.

        Source: PKCS#11 v2.40 Sec.11.6 C_Login error table --
        CKR_OPERATION_NOT_INITIALIZED if there is no active operation for
        which re-authentication is required.

        Some modules additionally accept CKR_USER_NOT_LOGGED_IN (the session
        state guard fires first), or CKR_FUNCTION_NOT_SUPPORTED (module does
        not implement context-specific login at all).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured - cannot test context-specific login")

        # p11_raw_session is already logged in as CKU_USER.
        rv = _raw_login(rs.raw, rs.sh, CKU_CONTEXT_SPECIFIC, pin)
        if rv == CKR_OK:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label="CKU_CONTEXT_SPECIFIC:no-active-op",
                operation="C_Login",
                actual=rv,
                summary=(
                    "Module accepted CKU_CONTEXT_SPECIFIC login without an active "
                    "operation - spec requires CKR_OPERATION_NOT_INITIALIZED"
                ),
            )
        elif rv == CKR_OPERATION_NOT_INITIALIZED:
            pass  # Correct per spec.
        elif rv == CKR_USER_NOT_LOGGED_IN:
            pass  # Acceptable: module checks login state before operation state.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC",
                operation="C_Login",
                actual=rv,
                summary=(
                    "Module does not support CKU_CONTEXT_SPECIFIC login "
                    "(CKR_FUNCTION_NOT_SUPPORTED)"
                ),
            )
        else:
            _classify_unexpected_login_rv(rv, "CKU_CONTEXT_SPECIFIC")
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC",
                operation="C_Login",
                actual=rv,
                summary=(
                    f"C_Login(CONTEXT_SPECIFIC) returned an unexpected clean CKR: {ckr_name(rv)}"
                ),
            )

    def test_context_specific_login_uses_c_login(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """CKU_CONTEXT_SPECIFIC login uses C_Login (not C_LoginUser) on v3.0+.

        Verification: calling C_Login directly with CKU_CONTEXT_SPECIFIC
        must return a well-formed CKR (not crash).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        rv = _raw_login(rs.raw, rs.sh, CKU_CONTEXT_SPECIFIC, pin)
        if rv == CKR_OK:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label="CKU_CONTEXT_SPECIFIC:no-active-op",
                operation="C_Login",
                actual=rv,
                summary="Module accepted CKU_CONTEXT_SPECIFIC without active operation",
            )
        elif rv == CKR_OPERATION_NOT_INITIALIZED:
            pass  # Correct.
        elif rv == CKR_USER_NOT_LOGGED_IN:
            pass  # Acceptable.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC",
                operation="C_Login",
                actual=rv,
                summary="Module does not support CKU_CONTEXT_SPECIFIC login",
            )
        else:
            _classify_unexpected_login_rv(rv, "CKU_CONTEXT_SPECIFIC")
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC",
                operation="C_Login",
                actual=rv,
                summary=(
                    f"context-specific login returned an unexpected clean CKR: {ckr_name(rv)}"
                ),
            )

    @pytest.mark.needs_function("C_LoginUser")
    def test_context_specific_via_c_login_user(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """C_LoginUser with CKU_CONTEXT_SPECIFIC and empty username is also rejected.

        This verifies that the C_LoginUser code path is exercised for
        CKU_CONTEXT_SPECIFIC - and that the module rejects it for the same
        reason (no active operation), not due to a crash.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        if "C_LoginUser" not in rs.raw.available_function_names():
            xfail_as(
                "not_operational",
                label="C_LoginUser:absent-on-v3",
                operation="C_LoginUser",
                summary=(
                    "Module does not expose v3.0 function list for C_LoginUser "
                    "(unexpected on a v3.0+ negotiated interface)"
                ),
            )

        rv = _raw_login_user(
            rs.raw,
            rs.sh,
            CKU_CONTEXT_SPECIFIC,
            pin,
            b"",
        )
        if rv == CKR_OK:
            fail_as(
                "self_contradiction",
                kind="lifecycle",
                label="CKU_CONTEXT_SPECIFIC:no-active-op-via-loginuser",
                operation="C_LoginUser",
                actual=rv,
                summary=(
                    "Module accepted CKU_CONTEXT_SPECIFIC via C_LoginUser without "
                    "an active operation - spec requires CKR_OPERATION_NOT_INITIALIZED"
                ),
            )
        elif rv == CKR_OPERATION_NOT_INITIALIZED:
            pass  # Correct per spec.
        elif rv == CKR_USER_NOT_LOGGED_IN:
            pass  # Acceptable.
        elif rv == CKR_FUNCTION_NOT_SUPPORTED:
            xfail_as(
                "not_operational",
                label="C_LoginUser:context-specific",
                operation="C_LoginUser",
                actual=rv,
                summary="Module does not support CKU_CONTEXT_SPECIFIC via C_LoginUser",
            )
        else:
            _classify_unexpected_login_rv(rv, "CKU_CONTEXT_SPECIFIC")
            xfail_as(
                "not_operational",
                label="CKU_CONTEXT_SPECIFIC",
                operation="C_Login",
                actual=rv,
                summary=(
                    f"context-specific login returned an unexpected clean CKR: {ckr_name(rv)}"
                ),
            )


# ---------------------------------------------------------------------------
# Login / logout cycle
# ---------------------------------------------------------------------------


class TestLoginLogoutCycle:
    """Basic login/logout cycle verification for v3.0+ modules.

    These tests open their own sessions to ensure a clean login state and to
    verify that C_LoginUser round-trips correctly.
    """

    def test_normal_login_logout(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Normal CKU_USER login and logout cycle works on a v3.0+ module."""
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        # Open a fresh session for this test.
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            rv = _raw_login(rs.raw, sh2, CKU_USER, pin)
            assert rv in (  # audit-ok: positive-op login idempotency
                CKR_OK,
                CKR_USER_ALREADY_LOGGED_IN,
            ), f"C_Login failed: {ckr_name(rv)}"

            # Verify the session is functional after login.
            key = gen_aes_key_or_xfail(rs, 128, sh=sh2)
            assert key != 0, "generate_key returned 0 after login"
            destroy_quietly(rs.raw, sh2, key)

            rv = _raw_logout(rs.raw, sh2)
            assert rv in (  # audit-ok: positive-op logout idempotency
                CKR_OK,
                CKR_USER_NOT_LOGGED_IN,
            ), f"C_Logout failed: {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, sh2)

    @pytest.mark.needs_function("C_LoginUser")
    def test_c_login_user_then_logout(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_LoginUser login followed by C_Logout is a clean round-trip.

        After a successful C_LoginUser, C_Logout must succeed (CKR_OK).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("Module does not implement C_LoginUser (not in function list)")

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        logged_in = False
        try:
            rv = _raw_login_user(rs.raw, sh2, CKU_USER, pin, b"")
            if rv == CKR_OK:
                logged_in = True
            elif rv == CKR_USER_ALREADY_LOGGED_IN:
                logged_in = True
            elif rv == CKR_FUNCTION_NOT_SUPPORTED:
                xfail_as(
                    "not_operational",
                    label="C_LoginUser:positive-login",
                    operation="C_LoginUser",
                    actual=rv,
                    summary="Module exposes C_LoginUser but does not implement it",
                )
            else:
                _classify_unexpected_login_rv(rv, "C_LoginUser:positive-login")
                xfail_as(
                    "not_operational",
                    label="C_LoginUser:positive-login",
                    operation="C_LoginUser",
                    actual=rv,
                    summary=(
                        f"C_LoginUser (positive login) returned an unexpected clean CKR: "
                        f"{ckr_name(rv)}"
                    ),
                )

            if logged_in:
                rv = _raw_logout(rs.raw, sh2)
                assert rv in (  # audit-ok: positive-op logout idempotency
                    CKR_OK,
                    CKR_USER_NOT_LOGGED_IN,
                ), f"C_Logout failed: {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, sh2)

    @pytest.mark.needs_function("C_LoginUser")
    def test_double_login_rejected(self, p11_raw_session: Any, p11_config: Any) -> None:
        """A second CKU_USER login on an already-logged-in session is rejected.

        The PKCS#11 spec requires CKR_USER_ALREADY_LOGGED_IN when C_Login or
        C_LoginUser is called again after a successful login.

        Source: PKCS#11 v3.0 Sec.5.5 C_LoginUser error table.
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.skip("Module does not implement C_LoginUser (not in function list)")

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            # First login.
            rv = _raw_login(rs.raw, sh2, CKU_USER, pin)
            assert rv in (  # audit-ok: positive-op login idempotency
                CKR_OK,
                CKR_USER_ALREADY_LOGGED_IN,
            ), f"First C_Login failed: {ckr_name(rv)}"

            # Second login via C_LoginUser must be rejected.
            rv2 = _raw_login_user(rs.raw, sh2, CKU_USER, pin, b"")
            if rv2 == CKR_USER_ALREADY_LOGGED_IN:
                pass  # Correct per spec.
            elif rv2 == CKR_OK:
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="C_LoginUser:double-login",
                    operation="C_LoginUser",
                    actual=rv2,
                    summary=(
                        "Module accepted a second C_LoginUser login without "
                        "intervening logout - spec requires "
                        "CKR_USER_ALREADY_LOGGED_IN"
                    ),
                )
            elif rv2 == CKR_FUNCTION_NOT_SUPPORTED:
                xfail_as(
                    "not_operational",
                    label="C_LoginUser:double-login",
                    operation="C_LoginUser",
                    actual=rv2,
                    summary="Module exposes C_LoginUser but does not implement it",
                )
            else:
                _classify_unexpected_login_rv(rv2, "C_LoginUser:double-login")
                xfail_as(
                    "not_operational",
                    label="C_LoginUser:double-login",
                    operation="C_LoginUser",
                    actual=rv2,
                    summary=(
                        f"second C_LoginUser returned an unexpected clean CKR: {ckr_name(rv2)}"
                    ),
                )
        finally:
            _raw_logout(rs.raw, sh2)
            close_session_quietly(rs.raw, sh2)


# ---------------------------------------------------------------------------
# C_SessionCancel tests (v3.0+)
# ---------------------------------------------------------------------------


def _run_cancel_after_digest_probe(p11_config: Any) -> tuple[int, str, str]:
    """Run the ``v30_session`` cancel-after-digest probe and return (rc, stdout, stderr).

    The child (``_probes/v30_session.py``) loads the module via raw ctypes, negotiates the
    v3.0 interface exactly as the legacy inline script did, then drives
    C_DigestInit -> C_SessionCancel(flags=0) -> C_DigestInit.  The raw CDLL path has no
    RawPKCS11 coverage wrapper, so coverage routes to the raw accumulator
    (``coverage="raw"``).  The PIN travels only via ``_P11CHECK_PIN`` (I3); the slot index is
    the positional index into the discovered slot list (legacy ``p11_config.slot`` semantics).
    """
    slot_index = p11_config.slot if p11_config.slot is not None else 0
    result = run_probe(
        "v30_session",
        {
            "module_path": str(p11_config.module),
            "probe": "cancel_after_digest_init",
            "slot_index": slot_index,
        },
        pin=pin_from_config(p11_config),
        timeout=15,
        coverage="raw",
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


@pytest.mark.needs_function("C_SessionCancel")
class TestSessionCancel:
    """C_SessionCancel (v3.0+) cancels active cryptographic operations.

    C_SessionCancel is a PKCS#11 v3.0 extension that terminates any active
    operation on a session.

    Source: PKCS#11 v3.0 Sec.5.15  C_SessionCancel
    """

    def test_cancel_with_no_active_operation(self, p11_raw_session: Any) -> None:
        """C_SessionCancel with no active operation returns CKR_OK.

        The PKCS#11 v3.0 spec states that C_SessionCancel with flags=0
        cancels all active operations.  When no operation is in progress,
        a conformant module must still return CKR_OK.

        Source: PKCS#11 v3.0 Sec.5.15 - no CKR error defined for the case where
        no operation is active; the call is a no-op that returns CKR_OK.
        """
        rs = p11_raw_session
        if "C_SessionCancel" not in rs.raw.available_function_names():
            pytest.skip(
                "C_SessionCancel not in module function list - not available on this module"
            )
        rv = rs.raw.C_SessionCancel(rs.sh, 0)
        _handle_cancel_rv(rv, "C_SessionCancel")
        # CKR_OK means success.

    def test_cancel_leaves_session_usable(self, p11_raw_session: Any) -> None:
        """After C_SessionCancel the session can be used for a new operation.

        Verify that calling cancel() does not corrupt session state.  A digest
        started after cancel() must complete successfully.
        """
        rs = p11_raw_session
        if "C_SessionCancel" not in rs.raw.available_function_names():
            pytest.skip(
                "C_SessionCancel not in module function list - not available on this module"
            )
        rv = rs.raw.C_SessionCancel(rs.sh, 0)
        _handle_cancel_rv(rv, "C_SessionCancel")

        # Session must still be usable: perform a SHA-256 digest.
        result = digest_single(rs.raw, rs.sh, CKM_SHA256, b"pkcs11-cancel-test")
        assert len(result) == 32, f"Expected 32-byte SHA-256 digest, got {len(result)} bytes"

    def test_cancel_with_flags_zero(self, p11_raw_session: Any) -> None:
        """C_SessionCancel(flags=0) cancels all active operations per spec.

        Passing flags=0 is the conventional way to cancel all ongoing
        cryptographic operations on a session.  This test explicitly passes
        the value to exercise the flags parameter path.
        """
        rs = p11_raw_session
        if "C_SessionCancel" not in rs.raw.available_function_names():
            pytest.skip(
                "C_SessionCancel not in module function list - not available on this module"
            )
        rv = rs.raw.C_SessionCancel(rs.sh, 0)
        _handle_cancel_rv(rv, "C_SessionCancel")

    def test_cancel_after_digest_init_subprocess(
        self,
        p11_config: Any,
    ) -> None:
        """C_SessionCancel clears a pending DigestInit state.

        Starts a digest operation via RawPKCS11 (C_DigestInit), then calls
        C_SessionCancel(flags=0), and verifies the session accepts a fresh
        C_DigestInit afterwards.  The subprocess isolates us from potential
        module state corruption.

        Source: PKCS#11 v3.0 Sec.5.15 - after C_SessionCancel, the session may
        be used for new operations without a C_Finalize/C_Initialize cycle.
        """
        rc, stdout, stderr = _run_cancel_after_digest_probe(p11_config)
        assert_subprocess_completed(
            rc,
            stdout,
            stderr,
            context="C_DigestInit/C_SessionCancel subprocess",
        )

        if "SKIP:" in stdout:
            pytest.skip(f"C_DigestInit not supported: {stdout}")

        if "CANCEL:NOT_AVAILABLE" in stdout:
            pytest.skip(
                "C_SessionCancel not available in module function list - "
                "module may not support v3.0 at the raw API level"
            )

        if "CANCEL:NOT_SUPPORTED" in stdout:
            xfail_as(
                "not_operational",
                label="C_SessionCancel",
                operation="C_SessionCancel",
                summary=(
                    "Module exposes v3.0 interface but C_SessionCancel returns "
                    "CKR_FUNCTION_NOT_SUPPORTED"
                ),
            )

        # OASIS PKCS#11 v3.0 spec C_SessionCancel: with flags=0 the spec says
        # "the session state will not be modified and CKR_OK will be returned".
        # Modules that return other CKR codes for flags=0 are non-conformant.
        # Known non-conformant responses:
        #   0x00000091 = CKR_OPERATION_NOT_INITIALIZED (observed)
        #   0x00000001 = CKR_CANCEL (observed)
        #   0x00000051 = CKR_FUNCTION_NOT_PARALLEL (observed)
        if "CANCEL:0x" in stdout:
            cancel_part = next(
                (part for part in stdout.split() if part.startswith("CANCEL:0x")), stdout
            )
            try:
                cancel_rv = int(cancel_part.removeprefix("CANCEL:"), 16)
            except ValueError as exc:
                raise AssertionError(
                    f"Malformed C_SessionCancel probe result: {cancel_part!r}"
                ) from exc
            _handle_cancel_rv(cancel_rv, "C_SessionCancel:flags-0")

        assert "CANCEL:OK" in stdout, (
            f"Expected C_SessionCancel to return CKR_OK after DigestInit, "
            f"got: {stdout!r}\nstderr: {stderr!r}"
        )
        assert "REDIGEST:OK" in stdout, (
            f"Expected session to accept new DigestInit after C_SessionCancel, "
            f"got: {stdout!r}\nstderr: {stderr!r}"
        )


@pytest.mark.needs_function("C_LoginUser")
class TestLoginUserWithNameRecipe:
    """Tests exercising the login_user_with_name() bootstrap recipe."""

    def test_login_user_with_name_empty_username(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """login_user_with_name with empty username behaves like C_Login.

        Observed deviation: some modules return CKR_OPERATION_NOT_INITIALIZED when
        C_LoginUser is called on an already-logged-in session, instead of
        CKR_USER_ALREADY_LOGGED_IN or CKR_OK.
        """
        rs = p11_raw_session
        if not hasattr(rs.raw, "C_LoginUser"):
            pytest.skip("C_LoginUser not available (v2.40 module)")
        pin = (
            p11_config.pin.get_secret_value().encode("utf-8") if p11_config.pin is not None else b""
        )
        try:
            login_user_with_name(rs.raw, rs.sh, CKU_USER, pin)
            logout_quietly(rs.raw, rs.sh)
        except CkrAssertionError as exc:
            from pkcs11_check.raw.types_std import CKR_OPERATION_NOT_INITIALIZED
            from pkcs11_check.testcases.conftest import xfail_if_known_ckr

            xfail_if_known_ckr(
                exc,
                {CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED},
                "Module exposes C_LoginUser but returns a known unsupported/deviation CKR "
                "(expected CKR_OK or CKR_USER_ALREADY_LOGGED_IN per PKCS#11 v3.0 spec)",
            )
            raise

    def test_login_user_with_name_nonempty_username(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """login_user_with_name with non-empty username.

        Most current PKCS#11 providers ignore the username field.
        This test is future-ready for modules that support named users.
        """
        rs = p11_raw_session
        if not hasattr(rs.raw, "C_LoginUser"):
            pytest.skip("C_LoginUser not available (v2.40 module)")
        pin = (
            p11_config.pin.get_secret_value().encode("utf-8") if p11_config.pin is not None else b""
        )
        try:
            login_user_with_name(rs.raw, rs.sh, CKU_USER, pin, username=b"testuser")
            logout_quietly(rs.raw, rs.sh)
        except CkrAssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _LOGIN_REJECT | {CKR_FUNCTION_NOT_SUPPORTED},
                "C_LoginUser with a non-empty username is not operational",
            )
            raise
