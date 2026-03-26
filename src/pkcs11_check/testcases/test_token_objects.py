"""Token (persistent) object tests.

All other tests use TOKEN: False (session objects). These tests verify
that TOKEN: True objects persist across session close/reopen and have
correct visibility semantics.

Marked @destructive because they create persistent objects on the token.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_LABEL,
    CKA_TOKEN,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import get_pin_bytes

pytestmark = [pytest.mark.keymgmt, pytest.mark.destructive]


def _unique_label() -> str:
    """Generate a unique label to avoid collisions across test runs."""
    return f"pkcs11check-tok-{uuid.uuid4().hex[:8]}"


class TestTokenObjectLifecycle:
    """Create, find, use, and destroy persistent token objects."""

    def test_create_token_aes_key(self, p11_raw_session: Any) -> None:
        """AES key with TOKEN=True is created and findable."""
        rs = p11_raw_session
        label = _unique_label()
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_LABEL: label, CKA_TOKEN: True},
        )
        try:
            assert key_h != 0
            attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_TOKEN])
            assert attrs[CKA_TOKEN] is True

            # Findable by label
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_token_object_survives_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Token object created in one session is visible in a new session."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = _unique_label()

        # Session 1: create
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s1, CKU_USER, pin_bytes)
        gen_aes_key(rs.raw, s1, 256, attrs={CKA_LABEL: label, CKA_TOKEN: True})
        close_session_quietly(rs.raw, s1)

        # Session 2: find
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s2, CKU_USER, pin_bytes)
        try:
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) >= 1, f"Token object '{label}' not found in new session"

            # Cleanup
            for h in found:
                destroy_quietly(rs.raw, s2, h)
        finally:
            close_session_quietly(rs.raw, s2)

    def test_token_key_usable_across_sessions(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Token key created in session A can encrypt in session B."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = _unique_label()
        plaintext = b"persistent key!!"  # 16 bytes

        # Session 1: create + encrypt
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s1, CKU_USER, pin_bytes)
        key1_h = gen_aes_key(
            rs.raw,
            s1,
            256,
            attrs={
                CKA_LABEL: label,
                CKA_TOKEN: True,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )
        ct = encrypt_single(rs.raw, s1, key1_h, CKM_AES_ECB, plaintext)
        close_session_quietly(rs.raw, s1)

        # Session 2: find + decrypt
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s2, CKU_USER, pin_bytes)
        try:
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) >= 1
            key2_h = found[0]
            pt = decrypt_single(rs.raw, s2, key2_h, CKM_AES_ECB, ct)
            assert pt == plaintext

            destroy_quietly(rs.raw, s2, key2_h)
        finally:
            close_session_quietly(rs.raw, s2)

    def test_session_object_not_visible_after_close(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object (TOKEN=False) disappears when session closes."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
        label = _unique_label()

        # Session 1: create session object
        s1 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s1, CKU_USER, pin_bytes)
        gen_aes_key(rs.raw, s1, 256, attrs={CKA_LABEL: label})
        # Visible in same session
        tmpl = template_from_dict({CKA_LABEL: label})
        assert len(find_objects(rs.raw, s1, tmpl)) >= 1
        close_session_quietly(rs.raw, s1)

        # Session 2: should NOT be visible
        s2 = raw_open_session(rs.raw, rs.slot_id, flags)
        login_user(rs.raw, s2, CKU_USER, pin_bytes)
        try:
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) == 0, "Session object survived session close"
        finally:
            close_session_quietly(rs.raw, s2)

    def test_destroy_token_object(self, p11_raw_session: Any) -> None:
        """Destroying a token object removes it permanently."""
        rs = p11_raw_session
        label = _unique_label()
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_LABEL: label, CKA_TOKEN: True},
        )
        destroy_quietly(rs.raw, rs.sh, key_h)

        tmpl = template_from_dict({CKA_LABEL: label})
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert len(found) == 0


class TestTokenObjectAttributes:
    """Verify attributes of token objects."""

    def test_token_flag_readable(self, p11_raw_session: Any) -> None:
        """CKA_TOKEN attribute is True for token objects, False for session."""
        rs = p11_raw_session
        label_tok = _unique_label()
        label_ses = _unique_label()

        tok_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_LABEL: label_tok, CKA_TOKEN: True},
        )
        ses_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_LABEL: label_ses},
        )

        try:
            tok_attrs = read_attributes(rs.raw, rs.sh, tok_key_h, [CKA_TOKEN])
            ses_attrs = read_attributes(rs.raw, rs.sh, ses_key_h, [CKA_TOKEN])
            assert tok_attrs[CKA_TOKEN] is True
            assert ses_attrs[CKA_TOKEN] is False
        finally:
            destroy_quietly(rs.raw, rs.sh, tok_key_h)
            destroy_quietly(rs.raw, rs.sh, ses_key_h)
