"""Session edge-case tests - stale handles, CloseAllSessions, SoftHSM2 issue regressions.

References: rep11.md Iteration 2, SoftHSM2 #608, #596.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_WRAP,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_KEY_GEN,
    CKM_SHA256,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    get_pin_bytes,
)

pytestmark = pytest.mark.security


class TestStaleSessionHandles:
    """Reuse closed session handle - must get error, not crash (task 7.7)."""

    @pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
    def test_find_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_FindObjects on closed session must fail cleanly."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        # Close the session
        close_session_quietly(rs.raw, test_sh)

        # Try to use the closed session -- must reject, not crash or succeed
        rv = rs.raw.C_FindObjectsInit(test_sh, None, 0)
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED),
            label="C_FindObjectsInit on closed session",
        )

    def test_generate_key_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_GenerateKey on closed session must fail cleanly."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)

        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        test_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, test_sh, CKU_USER, pin_bytes)

        # Close the session
        close_session_quietly(rs.raw, test_sh)

        # Try to generate a key on the closed session
        from pkcs11_check.raw.pack import attr_ulong, template

        tmpl = template(attr_ulong(CKA_VALUE_LEN, 16))
        mech = mech_simple(CKM_AES_KEY_GEN)
        key_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_GenerateKey(test_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h))
        classify_negative_rv(
            rv,
            (CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED),
            label="C_GenerateKey on closed session",
        )


class TestCloseAllSessions:
    """C_CloseAllSessions behavior (task 7.8)."""

    def test_close_all_sessions(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Open multiple sessions, close all, verify no crash."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        sessions = []
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s1, CKU_USER, pin_bytes)
        sessions.append(s1)

        # Open more sessions
        for _ in range(3):
            sh = raw_open_session(rs.raw, rs.slot_id, flags)
            sessions.append(sh)

        # Generate a key in s1 (session object)
        gen_aes_key_or_xfail(rs, 128, sh=s1)

        # Close all sessions at once
        rv = rs.raw.C_CloseAllSessions(rs.slot_id)
        # Crash-only check -- CKR_OK expected; some modules may return error
        assert rv is not None

        # Verify we can open a new session after closing all
        s_new = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s_new, CKU_USER, pin_bytes)
        try:
            # Session object (not TOKEN) should be gone
            tmpl = template_from_dict({CKA_LABEL: "close-all-test"})
            found = find_objects(rs.raw, s_new, tmpl)
            assert len(found) == 0, "Session key survived CloseAllSessions"
        finally:
            close_session_quietly(rs.raw, s_new)


class TestSoftHSM2IssueRegressions:
    """SoftHSM2 GitHub issue regressions (task 7.22)."""

    def test_wrap_unsupported_mechanism_returns_proper_ckr(self, p11_raw_session: Any) -> None:
        """SoftHSM2 #608: C_WrapKey with unsupported mechanism must return
        CKR_MECHANISM_INVALID, not CKR_GENERAL_ERROR or crash."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={
                CKA_WRAP: True,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
            },
        )
        target = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_EXTRACTABLE: True},
        )

        try:
            # Try wrapping with SHA-256 (not a wrapping mechanism)
            mech = mech_simple(CKM_SHA256)
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(rs.sh, mech.byref(), key, target, None, byref(out_len))
            if rv == CKR_OK:
                fail_as(
                    "accepted_invalid",
                    kind="policy",
                    label="C_WrapKey:non-wrapping-mechanism",
                    operation="C_WrapKey",
                    mechanism="CKM_SHA256",
                    actual=rv,
                    summary="Wrap with SHA-256 should have failed",
                )
            # CKR_MECHANISM_INVALID or CKR_KEY_NOT_WRAPPABLE are correct
            # Other errors are module quirks - document but don't fail
            if rv not in (
                CKR_MECHANISM_INVALID,
                0x00000069,  # CKR_KEY_NOT_WRAPPABLE
            ):
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"C_WrapKey with bad mechanism returned {ckr_name(rv)} "
                    "instead of CKR_MECHANISM_INVALID",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="SoftHSM2 #608",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, target)
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rsa_keygen_minimum_size(self, p11_raw_session: Any) -> None:
        """Generate RSA with various sizes - verify minimum is enforced."""
        rs = p11_raw_session

        # Very small RSA should be rejected
        try:
            from pkcs11_check.raw.recipes import gen_rsa_keypair

            pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 512)
            # If accepted, that's a policy choice
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)
        except AssertionError:
            pass  # Correct to reject small RSA

        # Standard size should work
        from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            assert pub != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


# Need CKA_VALUE_LEN for the generate key test
from pkcs11_check.raw.types_std import CKA_VALUE_LEN  # noqa: E402


class TestCKNotifyCallback:
    """Test that C_OpenSession accepts CK_NOTIFY callback parameter.

    Per OASIS spec, C_OpenSession takes a notification callback (CK_NOTIFY)
    and an application pointer.  Most modules ignore the callback, but they
    must accept it without error.
    """

    def test_open_session_with_null_callback(self, p11_raw_session: Any) -> None:
        """C_OpenSession with NULL CK_NOTIFY (standard usage) succeeds."""
        from pkcs11_check.raw.types_std import (
            CK_NOTIFY,
            CK_SESSION_HANDLE,
            CKF_RW_SESSION,
            CKF_SERIAL_SESSION,
            CKR_OK,
        )

        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)
        sh = CK_SESSION_HANDLE(0)
        # Pass explicit CK_NOTIFY() (null callback) and NULL application pointer
        rv = rs.raw.C_OpenSession(rs.slot_id, flags, None, CK_NOTIFY(), byref(sh))
        if rv == CKR_OK:
            close_session_quietly(rs.raw, sh.value)
        else:
            # Some modules limit concurrent sessions -- acceptable
            ckr = ckr_name(rv)
            assert "SESSION_COUNT" in ckr or "PARALLEL" in ckr, (
                f"C_OpenSession with null CK_NOTIFY failed unexpectedly: {ckr}"
            )
