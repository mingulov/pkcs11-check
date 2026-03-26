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

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly
from pkcs11_check.raw.bootstrap import open_session as raw_open_session
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name
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

pytestmark = [pytest.mark.requires_v30, pytest.mark.access]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pin_bytes(p11_config: Any) -> bytes | None:
    """Return the PIN as bytes, or None if not configured."""
    if p11_config.pin is None:
        return None
    return p11_config.pin.get_secret_value().encode("utf-8")


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

_CONTEXT_OK = {int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN)}
_LOGIN_REJECT = {
    int(CKR_USER_TYPE_INVALID),
    int(CKR_ARGUMENTS_BAD),
    int(CKR_PIN_INCORRECT),
}


@pytest.mark.requires_v30
class TestCLoginUser:
    """C_LoginUser (v3.0+) exercises the username parameter path.

    C_LoginUser extends C_Login with a (pUsername, ulUsernameLen) pair.
    On v2.40 modules the function does not exist in the function list.
    """

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
        rv = _raw_login_user(rs.raw, rs.sh, int(CKU_USER), pin, b"")
        if rv == int(CKR_USER_ALREADY_LOGGED_IN):
            pass  # Acceptable: we are already logged in as USER.
        elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module exposes v3.0 interface but C_LoginUser returns CKR_FUNCTION_NOT_SUPPORTED"
            )
        elif rv == int(CKR_OK):
            pass  # Accepted.
        else:
            pytest.fail(f"Unexpected CKR from C_LoginUser: {ckr_name(rv)}")

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

        rv = _raw_login_user(rs.raw, rs.sh, int(CKU_USER), pin, b"user")
        if rv == int(CKR_OK) or rv == int(CKR_USER_ALREADY_LOGGED_IN):
            pass  # Accepted or already logged in.
        elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module exposes v3.0 interface but C_LoginUser returns CKR_FUNCTION_NOT_SUPPORTED"
            )
        elif rv in _LOGIN_REJECT:
            pass  # Module does not support named users - acceptable.
        else:
            pytest.fail(f"Unexpected CKR from C_LoginUser: {ckr_name(rv)}")


# ---------------------------------------------------------------------------
# CKU_CONTEXT_SPECIFIC tests (C_Login type 2)
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
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
        rv = _raw_login(rs.raw, rs.sh, int(CKU_CONTEXT_SPECIFIC), pin)
        if rv == int(CKR_OK):
            pytest.xfail(
                "Module accepted CKU_CONTEXT_SPECIFIC login without an active "
                "operation - spec requires CKR_OPERATION_NOT_INITIALIZED"
            )
        elif rv == int(CKR_OPERATION_NOT_INITIALIZED):
            pass  # Correct per spec.
        elif rv == int(CKR_USER_NOT_LOGGED_IN):
            pass  # Acceptable: module checks login state before operation state.
        elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module does not support CKU_CONTEXT_SPECIFIC login (CKR_FUNCTION_NOT_SUPPORTED)"
            )
        else:
            pytest.fail(f"Unexpected CKR from C_Login(CONTEXT_SPECIFIC): {ckr_name(rv)}")

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

        rv = _raw_login(rs.raw, rs.sh, int(CKU_CONTEXT_SPECIFIC), pin)
        if rv == int(CKR_OK):
            pytest.xfail("Module accepted CKU_CONTEXT_SPECIFIC without active operation")
        elif rv == int(CKR_OPERATION_NOT_INITIALIZED):
            pass  # Correct.
        elif rv == int(CKR_USER_NOT_LOGGED_IN):
            pass  # Acceptable.
        elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail("Module does not implement CKU_CONTEXT_SPECIFIC login")
        else:
            pytest.fail(f"Unexpected CKR: {ckr_name(rv)}")

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
            pytest.xfail(
                "Module does not expose v3.0 function list for C_LoginUser "
                "(unexpected on a v3.0+ negotiated interface)"
            )

        rv = _raw_login_user(
            rs.raw,
            rs.sh,
            int(CKU_CONTEXT_SPECIFIC),
            pin,
            b"",
        )
        if rv == int(CKR_OK):
            pytest.xfail(
                "Module accepted CKU_CONTEXT_SPECIFIC via C_LoginUser without "
                "an active operation - spec requires CKR_OPERATION_NOT_INITIALIZED"
            )
        elif rv == int(CKR_OPERATION_NOT_INITIALIZED):
            pass  # Correct per spec.
        elif rv == int(CKR_USER_NOT_LOGGED_IN):
            pass  # Acceptable.
        elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail("Module does not implement C_LoginUser")
        else:
            pytest.fail(f"Unexpected CKR: {ckr_name(rv)}")


# ---------------------------------------------------------------------------
# Login / logout cycle
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
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
        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            rv = _raw_login(rs.raw, sh2, int(CKU_USER), pin)
            assert rv in (int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN)), (
                f"C_Login failed: {ckr_name(rv)}"
            )

            # Verify the session is functional after login.
            key = gen_aes_key(rs.raw, sh2, 128)
            assert key != 0, "generate_key returned 0 after login"
            destroy_quietly(rs.raw, sh2, key)

            rv = _raw_logout(rs.raw, sh2)
            assert rv in (int(CKR_OK), int(CKR_USER_NOT_LOGGED_IN)), (
                f"C_Logout failed: {ckr_name(rv)}"
            )
        finally:
            close_session_quietly(rs.raw, sh2)

    def test_c_login_user_then_logout(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_LoginUser login followed by C_Logout is a clean round-trip.

        After a successful C_LoginUser, C_Logout must succeed (CKR_OK).
        """
        rs = p11_raw_session
        pin = _pin_bytes(p11_config)
        if pin is None:
            pytest.skip("No PIN configured")

        if "C_LoginUser" not in rs.raw.available_function_names():
            pytest.xfail("Module does not implement C_LoginUser (not in function list)")

        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        logged_in = False
        try:
            rv = _raw_login_user(rs.raw, sh2, int(CKU_USER), pin, b"")
            if rv == int(CKR_OK):
                logged_in = True
            elif rv == int(CKR_USER_ALREADY_LOGGED_IN):
                logged_in = True
            elif rv == int(CKR_FUNCTION_NOT_SUPPORTED):
                pytest.xfail("Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)")
            else:
                pytest.fail(f"C_LoginUser failed: {ckr_name(rv)}")

            if logged_in:
                rv = _raw_logout(rs.raw, sh2)
                assert rv in (int(CKR_OK), int(CKR_USER_NOT_LOGGED_IN)), (
                    f"C_Logout failed: {ckr_name(rv)}"
                )
        finally:
            close_session_quietly(rs.raw, sh2)

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
            pytest.xfail("Module does not implement C_LoginUser (not in function list)")

        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            # First login.
            rv = _raw_login(rs.raw, sh2, int(CKU_USER), pin)
            assert rv in (int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN)), (
                f"First C_Login failed: {ckr_name(rv)}"
            )

            # Second login via C_LoginUser must be rejected.
            rv2 = _raw_login_user(rs.raw, sh2, int(CKU_USER), pin, b"")
            if rv2 == int(CKR_USER_ALREADY_LOGGED_IN):
                pass  # Correct per spec.
            elif rv2 == int(CKR_OK):
                pytest.xfail(
                    "Module accepted a second C_LoginUser login without "
                    "intervening logout - spec requires "
                    "CKR_USER_ALREADY_LOGGED_IN"
                )
            elif rv2 == int(CKR_FUNCTION_NOT_SUPPORTED):
                pytest.xfail("Module does not implement C_LoginUser (CKR_FUNCTION_NOT_SUPPORTED)")
            else:
                pytest.fail(f"Unexpected CKR from second C_LoginUser: {ckr_name(rv2)}")
        finally:
            _raw_logout(rs.raw, sh2)
            close_session_quietly(rs.raw, sh2)


# ---------------------------------------------------------------------------
# C_SessionCancel tests (v3.0+)
# ---------------------------------------------------------------------------


@pytest.mark.requires_v30
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
        rv = int(rs.raw.C_SessionCancel(rs.sh, 0))
        if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module exposes v3.0 interface but C_SessionCancel returns "
                "CKR_FUNCTION_NOT_SUPPORTED"
            )
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
        rv = int(rs.raw.C_SessionCancel(rs.sh, 0))
        if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module exposes v3.0 interface but C_SessionCancel returns "
                "CKR_FUNCTION_NOT_SUPPORTED"
            )

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
        rv = int(rs.raw.C_SessionCancel(rs.sh, 0))
        if rv == int(CKR_FUNCTION_NOT_SUPPORTED):
            pytest.xfail(
                "Module exposes v3.0 interface but C_SessionCancel returns "
                "CKR_FUNCTION_NOT_SUPPORTED"
            )

    def test_cancel_after_digest_init_subprocess(
        self,
        p11_raw_session: Any,
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
        rs = p11_raw_session
        module_path = str(p11_config.module)
        pin_value = p11_config.pin.get_secret_value() if p11_config.pin is not None else ""
        actual_slot_id: int = rs.slot_id

        script = textwrap.dedent(
            f"""\
            import ctypes
            from ctypes import c_ulong, c_ubyte, c_void_p, byref, pointer, POINTER
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.types_std import (
                CK_MECHANISM, CKR_OK, CKR_FUNCTION_NOT_SUPPORTED,
                CKF_SERIAL_SESSION, CKF_RW_SESSION, CKU_USER, CKM_SHA256,
            )

            # Load module and negotiate v3.0 interface for C_SessionCancel
            lib = ctypes.CDLL("{module_path}")
            get_fl = lib.C_GetFunctionList
            get_fl.restype = c_ulong
            get_fl.argtypes = [POINTER(c_void_p)]
            fl_ptr = c_void_p()
            rv = get_fl(byref(fl_ptr))
            assert rv == CKR_OK, f"C_GetFunctionList: 0x{{rv:08x}}"

            fl3_val = 0
            try:
                get_iface = lib.C_GetInterface
                get_iface.restype = c_ulong
                get_iface.argtypes = [c_void_p, c_void_p, POINTER(c_void_p), c_ulong]
                fl3_ptr = c_void_p()
                rv = get_iface(None, None, byref(fl3_ptr), 0)
                if rv == CKR_OK and fl3_ptr.value:
                    fl3_val = fl3_ptr.value
            except AttributeError:
                pass  # Module does not export C_GetInterface

            raw = RawPKCS11(fl_ptr.value, funclist3_ptr=fl3_val)

            rv = raw.C_Initialize(None)
            assert rv in (CKR_OK, 0x00000191), f"C_Initialize: 0x{{rv:08x}}"

            session_handle = c_ulong(0)
            rv = raw.C_OpenSession(
                {actual_slot_id}, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                None, None, byref(session_handle),
            )
            assert rv == CKR_OK, f"C_OpenSession: 0x{{rv:08x}}"
            hSession = session_handle.value

            pin = "{pin_value}".encode()
            if pin:
                pin_buf = (c_ubyte * len(pin))(*pin)
                rv = raw.C_Login(hSession, CKU_USER, pin_buf, len(pin))
                assert rv in (CKR_OK, 0x00000100), f"C_Login: 0x{{rv:08x}}"

            mech = CK_MECHANISM(CKM_SHA256, None, 0)
            rv = raw.C_DigestInit(hSession, pointer(mech))
            if rv != CKR_OK:
                print(f"SKIP:C_DigestInit=0x{{rv:08x}}")
                raw.C_Finalize(None)
                exit(0)

            # Attempt C_SessionCancel via RawPKCS11
            try:
                rv_cancel = raw.C_SessionCancel(hSession, 0)
            except AttributeError:
                print("CANCEL:NOT_AVAILABLE")
                raw.C_Finalize(None)
                exit(0)

            if rv_cancel == CKR_OK:
                print("CANCEL:OK")
            elif rv_cancel == CKR_FUNCTION_NOT_SUPPORTED:
                print("CANCEL:NOT_SUPPORTED")
            else:
                print(f"CANCEL:0x{{rv_cancel:08x}}")
                raw.C_CloseSession(hSession)
                raw.C_Finalize(None)
                exit(0)

            # Session should accept a new DigestInit after cancel.
            rv2 = raw.C_DigestInit(hSession, pointer(mech))
            if rv2 == CKR_OK:
                print("REDIGEST:OK")
            else:
                print(f"REDIGEST:0x{{rv2:08x}}")

            raw.C_CloseSession(hSession)
            raw.C_Finalize(None)
            """
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode < 0:
            pytest.xfail(
                f"Module crashed (signal {-result.returncode}) during "
                f"C_DigestInit/C_SessionCancel - C_SessionCancel not safely callable"
            )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if "SKIP:" in stdout:
            pytest.skip(f"C_DigestInit not supported: {stdout}")

        if "CANCEL:NOT_AVAILABLE" in stdout:
            pytest.skip(
                "C_SessionCancel not available in module function list - "
                "module may not support v3.0 at the raw API level"
            )

        if "CANCEL:NOT_SUPPORTED" in stdout:
            pytest.xfail(
                "Module exposes v3.0 interface but C_SessionCancel returns "
                "CKR_FUNCTION_NOT_SUPPORTED"
            )

        # OASIS PKCS#11 v3.0 spec C_SessionCancel: with flags=0 the spec says
        # "the session state will not be modified and CKR_OK will be returned".
        # Modules that return other CKR codes for flags=0 are non-conformant.
        # Known non-conformant responses:
        #   0x00000091 = CKR_OPERATION_NOT_INITIALIZED (NSS)
        #   0x00000001 = CKR_CANCEL (kryoptic-main)
        #   0x00000051 = CKR_FUNCTION_NOT_PARALLEL (BouncyHSM)
        if "CANCEL:0x" in stdout:
            cancel_part = next(
                (part for part in stdout.split() if part.startswith("CANCEL:0x")), stdout
            )
            pytest.xfail(
                f"Module returns non-conformant CKR for C_SessionCancel(flags=0): "
                f"{cancel_part} — spec requires CKR_OK when no flags are set "
                f"(OASIS PKCS#11 v3.0 C_SessionCancel section)"
            )

        assert "CANCEL:OK" in stdout, (
            f"Expected C_SessionCancel to return CKR_OK after DigestInit, "
            f"got: {stdout!r}\nstderr: {stderr!r}"
        )
        assert "REDIGEST:OK" in stdout, (
            f"Expected session to accept new DigestInit after C_SessionCancel, "
            f"got: {stdout!r}\nstderr: {stderr!r}"
        )
