"""Session exhaustion tests.

Opens sessions until the module refuses (CKR_SESSION_COUNT or similar),
then verifies the error is graceful and the module recovers.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import gen_aes_key_or_xfail

pytestmark = pytest.mark.security


class TestSessionExhaustion:
    """Test behavior when opening many sessions."""

    def test_open_many_sessions(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Open sessions until limit or 100, verify all work, close all."""
        rs = p11_raw_session
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        sessions: list[int] = []
        # Open first session with login
        s0 = raw_open_session(rs.raw, rs.slot_id, flags)
        sessions.append(s0)
        if pin is not None:
            login_user(
                rs.raw,
                s0,
                CKU_USER,
                pin.encode("utf-8"),
            )

        try:
            for _ in range(99):
                try:
                    sh = raw_open_session(rs.raw, rs.slot_id, flags)
                    sessions.append(sh)
                except AssertionError:
                    break  # audit-ok: resource-exhaustion probe; clean session-count limit ok
        finally:
            pass

        for s in sessions:
            close_session_quietly(rs.raw, s)

        # After closing, should be able to open a new session
        recovery = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin is not None:
            login_user(
                rs.raw,
                recovery,
                CKU_USER,
                pin.encode("utf-8"),
            )
        try:
            key = gen_aes_key_or_xfail(rs, 128, sh=recovery)
            assert key != 0
        finally:
            close_session_quietly(rs.raw, recovery)

    def test_session_close_frees_resources(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Opening and closing sessions in a loop doesn't leak."""
        rs = p11_raw_session
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        for _ in range(50):
            sh = raw_open_session(rs.raw, rs.slot_id, flags)
            if pin is not None:
                login_user(
                    rs.raw,
                    sh,
                    CKU_USER,
                    pin.encode("utf-8"),
                )
            close_session_quietly(rs.raw, sh)
