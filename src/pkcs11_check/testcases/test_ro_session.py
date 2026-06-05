"""Read-only session and session-object lifecycle tests.

Verifies that operations work in R/O sessions and that session
objects don't persist after session close.
"""

from __future__ import annotations

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
    digest_single,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKK_RSA,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_PUBLIC_KEY,
    CKR_SESSION_COUNT,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    get_pin_bytes,
    is_known_error,
    skip_if_token_write_protected,
)

pytestmark = pytest.mark.access


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session required by RO/session-lifecycle tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by RO/session-lifecycle test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


class TestROSessionOperations:
    """Test operations that should work in R/O sessions."""

    def test_digest_in_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Digest works in R/O session (no key needed)."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        if pin_bytes is not None:
            login_user(rs.raw, ro_sh, CKU_USER, pin_bytes)
        try:
            digest = digest_single(rs.raw, ro_sh, CKM_SHA256, b"RO session digest test")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_find_objects_in_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Finding objects works in R/O session."""
        rs = p11_raw_session
        # Create a key in R/W session first
        key_h = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: "ro-find-test"})

        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict({CKA_LABEL: "ro-find-test"})
                found = find_objects(rs.raw, ro_sh, tmpl)
                # Session objects may or may not be visible in other sessions
                # but the search operation should work
                assert isinstance(found, list)
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_verify_in_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Signature verification works in R/O session."""
        rs = p11_raw_session
        pub_h, priv_h = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"verify in RO session"
        sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)

        try:
            # Verify in R/O session using the same token-level login
            ro_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                # Find the public key
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_PUBLIC_KEY,
                        CKA_KEY_TYPE: CKK_RSA,
                    }
                )
                keys = find_objects(rs.raw, ro_sh, tmpl)
                if keys:
                    result = verify_single(rs.raw, ro_sh, keys[0], CKM_SHA256_RSA_PKCS, data, sig)
                    assert result is True
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestSessionObjectLifecycle:
    """Test that session objects don't persist after session close."""

    def test_session_object_gone_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Non-TOKEN object disappears after session closes."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Session 1: create session object
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s1, CKU_USER, pin_bytes)
        label = "session-lifecycle-test"
        gen_aes_key(rs.raw, s1, 128, attrs={CKA_LABEL: label})
        # Verify it exists in this session
        tmpl = template_from_dict({CKA_LABEL: label})
        found = find_objects(rs.raw, s1, tmpl)
        assert len(found) >= 1
        close_session_quietly(rs.raw, s1)

        # Session 2: the session object should be gone
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s2, CKU_USER, pin_bytes)
        try:
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) == 0, "Session object survived session close"
        finally:
            close_session_quietly(rs.raw, s2)

    def test_token_object_persists_after_close(self, p11_raw_session: Any, p11_config: Any) -> None:
        """TOKEN=True object persists after session closes."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        label = "token-lifecycle-test"

        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s1, CKU_USER, pin_bytes)
        gen_aes_key(rs.raw, s1, 128, attrs={CKA_LABEL: label, CKA_TOKEN: True})
        close_session_quietly(rs.raw, s1)

        # Session 2: token object should still exist
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes is not None:
            login_user(rs.raw, s2, CKU_USER, pin_bytes)
        try:
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) >= 1, "Token object disappeared after session close"
            # Cleanup
            for h in found:
                destroy_quietly(rs.raw, s2, h)
        finally:
            close_session_quietly(rs.raw, s2)
