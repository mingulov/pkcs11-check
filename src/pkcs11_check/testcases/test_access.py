"""Tests for PKCS#11 session types, login states, and access control.

Covers the session/login matrix from the OASIS specification:
R/O vs R/W sessions, public vs user vs SO login states,
object visibility rules, and session lifecycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as _raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    generate_random,
)
from pkcs11_check.raw.recipes import gen_rsa_keypair as _raw_gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_PRIVATE_KEY,
    CKR_SESSION_COUNT,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    KEYPAIR_RUNTIME_REJECT_RVS,
    gen_aes_key_or_xfail,
    get_pin_bytes,
    is_known_error,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session required by legacy access tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by access test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


def _gen_access_rsa_keypair(
    rs: Any,
    bits: int = 2048,
    *,
    public_attrs: Mapping[Any, Any] | None = None,
    private_attrs: Mapping[Any, Any] | None = None,
) -> tuple[int, int]:
    """Generate an RSA setup keypair for access tests."""
    if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
        pytest.skip("RSA_PKCS_KEY_PAIR_GEN not supported by module")
    try:
        return _raw_gen_rsa_keypair(
            rs.raw,
            rs.sh,
            bits,
            public_attrs=public_attrs,
            private_attrs=private_attrs,
        )
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            KEYPAIR_RUNTIME_REJECT_RVS,
            "RSA_PKCS_KEY_PAIR_GEN advertised but access RSA keypair setup is not operational",
        )
    raise


class TestSessionTypes:
    """Test R/O and R/W session behavior differences."""

    def test_rw_session_can_generate_key(self, p11_raw_session: Any) -> None:
        """R/W session (our default fixture) can generate keys."""
        rs = p11_raw_session
        key_h = gen_aes_key_or_xfail(rs)
        try:
            assert key_h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_ro_session_can_create_session_objects(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """R/O session can create session objects (not token objects)."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION  # RO
        ro_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, ro_sh, CKU_USER, pin_bytes)
        try:
            # Session objects should be creatable in R/O sessions
            key_h = gen_aes_key_or_xfail(
                rs,
                sh=ro_sh,
                purpose="RO-session object setup",
            )
            assert key_h != 0
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_ro_session_can_read(self, p11_raw_session: Any, p11_config: Any) -> None:
        """R/O session can still read objects and generate random."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION  # RO
        ro_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, ro_sh, CKU_USER, pin_bytes)
        try:
            random_data = generate_random(rs.raw, ro_sh, 32)
            assert len(random_data) == 32
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestLoginStates:
    """Test behavior in different login states."""

    def test_public_session_no_private_keys(self, p11_raw_session: Any) -> None:
        """Without login, private objects should not be visible."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION  # RO, no login
        pub_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            priv_keys = find_objects(rs.raw, pub_sh, tmpl)
            # Should be empty (no login = no access to private objects)
            assert len(priv_keys) == 0
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_user_session_can_see_private(self, p11_raw_session: Any) -> None:
        """Logged-in user session can create and find private objects."""
        rs = p11_raw_session
        # Create a keypair (private key is a private object)
        pub_h, priv_h = _gen_access_rsa_keypair(rs)
        try:
            assert priv_h != 0

            # Should be findable
            tmpl = template_from_dict({CKA_CLASS: CKO_PRIVATE_KEY})
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestMultipleSessions:
    """Test behavior with multiple concurrent sessions."""

    def test_two_sessions_independent(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Two sessions can operate independently."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = 0
        s2 = 0
        try:
            s1 = raw_open_session(rs.raw, rs.slot_id, flags)
            if pin_bytes is not None:
                login_user(rs.raw, s1, CKU_USER, pin_bytes)
            s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            key1 = gen_aes_key_or_xfail(rs, attrs={CKA_LABEL: "sess1"}, sh=s1)
            key2 = gen_aes_key_or_xfail(rs, attrs={CKA_LABEL: "sess2"}, sh=s2)
            assert key1 != 0
            assert key2 != 0
            destroy_quietly(rs.raw, s1, key1)
            destroy_quietly(rs.raw, s2, key2)
        finally:
            if s2:
                close_session_quietly(rs.raw, s2)
            if s1:
                close_session_quietly(rs.raw, s1)

    def test_session_object_visible_in_other_session(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session objects created in one session are visible in another."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s1, CKU_USER, pin_bytes)
        try:
            key_h = gen_aes_key_or_xfail(rs, attrs={CKA_LABEL: "session-obj-test"}, sh=s1)
            s2 = raw_open_session(rs.raw, rs.slot_id, flags)
            try:
                tmpl = template_from_dict({CKA_LABEL: "session-obj-test"})
                found = find_objects(rs.raw, s2, tmpl)
                assert len(found) >= 1  # Should be visible
            finally:
                close_session_quietly(rs.raw, s2)
            destroy_quietly(rs.raw, s1, key_h)
        finally:
            close_session_quietly(rs.raw, s1)


class TestSessionLifecycle:
    """Test session object lifetime behavior."""

    def test_session_object_destroyed_on_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Session objects should be destroyed when session closes."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create object in a session, then close it
        temp_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, temp_sh, CKU_USER, pin_bytes)
        gen_aes_key_or_xfail(rs, attrs={CKA_LABEL: "lifecycle-test"}, sh=temp_sh)
        close_session_quietly(rs.raw, temp_sh)

        # Object should be gone in a new session
        new_sh = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, new_sh, CKU_USER, pin_bytes)
        try:
            tmpl = template_from_dict({CKA_LABEL: "lifecycle-test"})
            found = find_objects(rs.raw, new_sh, tmpl)
            assert len(found) == 0
        finally:
            close_session_quietly(rs.raw, new_sh)
