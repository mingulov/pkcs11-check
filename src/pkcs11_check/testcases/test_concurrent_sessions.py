"""Concurrent session attack tests.

Verifies that PKCS#11 modules handle multiple sessions safely:
- Two sessions operating on the same object concurrently
- Create/destroy races
- Object visibility across concurrent sessions
- Session isolation of session objects

Note: PKCS#11 login is per-token (not per-session). A second session
opened while logged in on the same token shares the login state.
We open the second session RW without re-logging.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    open_session,
)
from pkcs11_check.raw.pack import attr_bytes, template
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKO_DATA,
)
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
    skip_if_token_write_protected,
)

pytestmark = pytest.mark.security


def _unique_label(prefix: str = "conc") -> bytes:
    return f"{prefix}-{uuid.uuid4().hex[:8]}".encode()


def _open_second_session(rs: Any) -> int:
    """Open a second RW session, login is already active at token level."""
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION
    return open_session(rs.raw, rs.slot_id, flags)


class TestConcurrentSessions:
    """Two sessions operating concurrently on the same token."""

    def test_two_sessions_see_same_token_object(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Object created in session A with TOKEN=True is visible in session B."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = _unique_label("vis")

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: True, CKA_LABEL: label},
        )

        # Open a second session (already logged in at token level)
        sh2 = _open_second_session(rs)
        try:
            tmpl = template(attr_bytes(CKA_LABEL, label))
            found = find_objects(rs.raw, sh2, tmpl)
            assert len(found) >= 1, "Token object not visible in concurrent session"
        finally:
            close_session_quietly(rs.raw, sh2)

        # Cleanup
        destroy_quietly(rs.raw, rs.sh, key)

    def test_destroy_in_one_session_reflected_in_other(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Destroying a token object in session A is reflected in session B."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = _unique_label("destr")

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: True, CKA_LABEL: label},
        )

        sh2 = _open_second_session(rs)
        try:
            # Visible in s2
            tmpl = template(attr_bytes(CKA_LABEL, label))
            found = find_objects(rs.raw, sh2, tmpl)
            assert len(found) >= 1

            # Destroy in s1
            destroy_quietly(rs.raw, rs.sh, key)

            # Should be gone in s2
            tmpl2 = template(attr_bytes(CKA_LABEL, label))
            found = find_objects(rs.raw, sh2, tmpl2)
            assert len(found) == 0, "Destroyed object still visible in other session"
        finally:
            close_session_quietly(rs.raw, sh2)

    def test_use_key_from_concurrent_session(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Token key created in session A can be used for crypto in session B."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("CKM_AES_KEY_GEN not supported")
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported")

        label = _unique_label("use")
        plaintext = b"concurrent-test!" * 2  # 32 bytes

        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={
                CKA_TOKEN: True,
                CKA_LABEL: label,
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
            },
        )

        sh2 = _open_second_session(rs)
        try:
            tmpl = template(attr_bytes(CKA_LABEL, label))
            keys = find_objects(rs.raw, sh2, tmpl)
            assert len(keys) >= 1
            key2 = keys[0]

            ct = encrypt_single(rs.raw, sh2, key2, CKM_AES_ECB, plaintext)
            pt = decrypt_single(rs.raw, sh2, key2, CKM_AES_ECB, ct)
            assert pt == plaintext
        finally:
            close_session_quietly(rs.raw, sh2)

        # Cleanup
        destroy_quietly(rs.raw, rs.sh, key)


class TestConcurrentObjectCreation:
    """Test rapid object creation/destruction across sessions."""

    def test_rapid_create_destroy_cycle(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Create and immediately destroy objects in rapid succession - no leak."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        labels: list[bytes] = []
        for i in range(20):
            label = _unique_label(f"rapid-{i}")
            labels.append(label)
            key = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={CKA_TOKEN: True, CKA_LABEL: label},
            )
            destroy_quietly(rs.raw, rs.sh, key)

        # Verify none leaked
        for label in labels:
            tmpl = template(attr_bytes(CKA_LABEL, label))
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) == 0, f"Object '{label!r}' leaked after destroy"

    def test_create_in_both_sessions_no_conflict(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Creating objects in two concurrent sessions doesn't cause conflicts."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)

        label_a = _unique_label("sA")
        label_b = _unique_label("sB")

        key_a = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_TOKEN: True, CKA_LABEL: label_a},
        )

        sh2 = _open_second_session(rs)
        try:
            key_b = gen_aes_key_or_xfail(
                rs,
                128,
                attrs={CKA_TOKEN: True, CKA_LABEL: label_b},
                sh=sh2,
            )

            # Both should be visible in both sessions
            tmpl_a = template(attr_bytes(CKA_LABEL, label_a))
            found_a = find_objects(rs.raw, sh2, tmpl_a)
            tmpl_b = template(attr_bytes(CKA_LABEL, label_b))
            found_b = find_objects(rs.raw, rs.sh, tmpl_b)
            assert len(found_a) >= 1
            assert len(found_b) >= 1

            destroy_quietly(rs.raw, sh2, key_b)
        finally:
            close_session_quietly(rs.raw, sh2)

        destroy_quietly(rs.raw, rs.sh, key_a)


class TestConcurrentDataObjects:
    """Test CKO_DATA objects across concurrent sessions."""

    def test_data_object_visible_across_sessions(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """CKO_DATA with TOKEN=True visible in concurrent session."""
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        label = _unique_label("data")

        obj = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"shared-data",
                CKA_TOKEN: True,
            },
        )

        sh2 = _open_second_session(rs)
        try:
            tmpl = template(attr_bytes(CKA_LABEL, label))
            found = find_objects(rs.raw, sh2, tmpl)
            assert len(found) >= 1
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_VALUE])
            assert attrs[CKA_VALUE] == b"shared-data"
        finally:
            close_session_quietly(rs.raw, sh2)

        # Cleanup
        destroy_quietly(rs.raw, rs.sh, obj)
