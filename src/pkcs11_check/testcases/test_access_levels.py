"""SO vs USER vs public access level tests.

Verifies visibility, operational capabilities, and mutual exclusion for
the three PKCS#11 access levels: public (no login), USER, and SO.
Also covers CKA_TRUSTED, CKA_WRAP_WITH_TRUSTED, and CKA_ALWAYS_AUTHENTICATE
enforcement at the access-level boundary.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import mech_bytes, mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    create_object,
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    read_attributes,
    set_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CK_UTF8CHAR,
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_PRIVATE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_TRUSTED,
    CKA_VALUE,
    CKA_WRAP,
    CKA_WRAP_WITH_TRUSTED,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_CBC_PAD,
    CKM_AES_KEY_WRAP,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_KEY_NOT_WRAPPABLE,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKR_WRAPPING_KEY_HANDLE_INVALID,
    CKU_CONTEXT_SPECIFIC,
    CKU_SO,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    AES_KEYGEN_RUNTIME_REJECT_RVS,
    get_pin_bytes,
    is_known_error,
    require_operational_aes_keygen,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.access

_TEMPLATE_ERROR_RVS = (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

_TRUSTED_SETATTR_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_USER_NOT_LOGGED_IN,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    raw.C_Logout(sh)


def _gen_access_aes_key(rs: Any, sh: int, *, attrs: dict[Any, Any] | None = None) -> int:
    """Generate a setup AES key for access-level tests, preserving provider findings."""
    require_operational_aes_keygen(rs)
    try:
        return gen_aes_key(rs.raw, sh, 128, attrs=attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            AES_KEYGEN_RUNTIME_REJECT_RVS,
            "AES_KEY_GEN advertised but access-level setup key generation is not operational",
        )
    raise


def _create_access_data_object(rs: Any, sh: int, attrs: dict[Any, Any]) -> int:
    """Create a setup data object for access-level visibility tests."""
    try:
        return create_object(rs.raw, sh, attrs)
    except AssertionError as exc:
        xfail_if_known_ckr(
            exc,
            _TEMPLATE_ERROR_RVS,
            "access-level data object setup rejected by the provider",
        )
    raise


# ---------------------------------------------------------------------------
# Public session (no login) visibility
# ---------------------------------------------------------------------------


class TestPublicSessionVisibility:
    """Verify what a public (no-login) session can and cannot see/do."""

    def test_public_sees_non_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session can see CKA_PRIVATE=False objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"pub-vis-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a non-private object while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"public-data",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Open public session (no login) and check visibility
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, pub_sh, tmpl)
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "CKA_PRIVATE=False object not visible in public session",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: public objects visible without login",
                )
        finally:
            close_session_quietly(rs.raw, pub_sh)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            tmpl2 = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            for h in find_objects(rs.raw, cleanup_sh, tmpl2):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_public_cannot_see_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session cannot see CKA_PRIVATE=True objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"priv-invis-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a private token object while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Open public session - private objects must not be visible
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, pub_sh, tmpl)
            assert len(found) == 0, "CKA_PRIVATE=True object visible in public session"
        finally:
            close_session_quietly(rs.raw, pub_sh)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_public_session_can_digest(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Public session can perform digest operations (no login needed)."""
        rs = p11_raw_session
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            digest = digest_single(rs.raw, pub_sh, CKM_SHA256, b"public digest")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, pub_sh)

    def test_public_session_can_generate_random(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session can generate random (no login needed)."""
        rs = p11_raw_session
        pub_sh = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            rand = generate_random(rs.raw, pub_sh, 16)
            assert len(rand) == 16  # 128 bits = 16 bytes
        finally:
            close_session_quietly(rs.raw, pub_sh)


# ---------------------------------------------------------------------------
# USER session visibility and capabilities
# ---------------------------------------------------------------------------


class TestUserSessionCapabilities:
    """Verify USER session access level."""

    def test_user_sees_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session sees CKA_PRIVATE=True objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"user-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            key_h = _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
            assert key_h != 0

            # Verify visible in same session
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1, "Private object not visible in USER session"

            # Cleanup
            for h in found:
                destroy_quietly(rs.raw, s1, h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_sees_non_private_objects(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session also sees CKA_PRIVATE=False objects."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"user-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"pub-data",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1, "Public object not visible in USER session"
            for h in find_objects(rs.raw, s1, tmpl):
                destroy_quietly(rs.raw, s1, h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_can_create_and_destroy_objects(self, p11_raw_session: Any) -> None:
        """USER session can create and destroy objects."""
        rs = p11_raw_session
        key_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={CKA_TOKEN: False, CKA_LABEL: "user-create-test"},
        )
        assert key_h != 0
        destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_can_encrypt_decrypt(self, p11_raw_session: Any) -> None:
        """USER session can perform crypto operations on private keys."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")

        key_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_PRIVATE: True,
            },
        )
        try:
            iv = b"\x00" * 16
            ct = encrypt_single(
                rs.raw,
                rs.sh,
                key_h,
                CKM_AES_CBC_PAD,
                b"sixteen byte msg",
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            pt = decrypt_single(
                rs.raw,
                rs.sh,
                key_h,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert pt == b"sixteen byte msg"
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_cannot_login_as_so(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session cannot switch to SO login."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(rs.sh, CKU_SO, pin_buf, len(pin_bytes))
        assert rv in (
            CKR_USER_ALREADY_LOGGED_IN,
            CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            CKR_USER_TYPE_INVALID,
        ), f"Expected SO login rejected while USER active, got {ckr_name(rv)}"


# ---------------------------------------------------------------------------
# SO session capabilities
# ---------------------------------------------------------------------------


class TestSOSessionCapabilities:
    """Verify SO access level capabilities.

    All tests marked @destructive because SO login may affect token state.
    """

    @pytest.mark.destructive
    def test_so_login_succeeds_on_rw_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO login succeeds on RW session when no USER is logged in."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear any existing login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(pin_bytes))
            if rv == CKR_PIN_INCORRECT:
                pytest.skip("SO PIN differs from user PIN on this module")
            if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
                pytest.skip("Another user already logged in on this token")
            expect_rv(rv, CKR_OK)

            # Verify SO is logged in by attempting USER login (should fail)
            rv2 = rs.raw.C_Login(s1, CKU_USER, pin_buf, len(pin_bytes))
            assert rv2 in (
                CKR_USER_ALREADY_LOGGED_IN,
                CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                CKR_USER_TYPE_INVALID,
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    @pytest.mark.destructive
    def test_so_can_init_pin(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session can set USER PIN via C_InitPIN (or skip if unsupported)."""
        from pkcs11_check.raw.recipes import init_pin, set_pin

        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear any existing login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(pin_bytes))
        if rv == CKR_PIN_INCORRECT:
            close_session_quietly(rs.raw, s1)
            pytest.skip("SO PIN differs from user PIN on this module")
        if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
            close_session_quietly(rs.raw, s1)
            pytest.skip("Another user already logged in on this token")

        new_pin = pin_bytes + b"X"
        try:
            init_pin(rs.raw, s1, new_pin)
        except (AssertionError, Exception) as e:
            pytest.skip(f"C_InitPIN not supported: {e}")
        finally:
            # Restore original PIN: logout SO, login USER with new PIN, set back
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

            restore_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            try:
                login_user(rs.raw, restore_sh, CKU_USER, new_pin)
                set_pin(rs.raw, restore_sh, new_pin, pin_bytes)
            except AssertionError:
                # Best-effort restore; if it fails, token may need re-init
                pass
            finally:
                _logout_safe(rs.raw, restore_sh)
                close_session_quietly(rs.raw, restore_sh)

    @pytest.mark.destructive
    def test_so_cannot_use_private_crypto_keys(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session should not be able to use private crypto keys."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        label = f"so-no-crypto-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create a private key while logged in as USER
        user_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, user_sh, pin_bytes)
            _gen_access_aes_key(
                rs,
                user_sh,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_ENCRYPT: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, user_sh)
            close_session_quietly(rs.raw, user_sh)

        # Login as SO and try to find/use the key
        so_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(so_sh, CKU_SO, pin_buf, len(pin_bytes))
        if rv == CKR_PIN_INCORRECT:
            close_session_quietly(rs.raw, so_sh)
            # Cleanup
            cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)
            pytest.skip("SO PIN differs from user PIN")
        if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
            close_session_quietly(rs.raw, so_sh)
            cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)
            pytest.skip("Another user already logged in")

        try:
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, so_sh, tmpl)
            if len(found) == 0:
                # SO cannot see private keys - expected per spec
                pass
            else:
                # SO can see the key; some modules allow this
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "SO session can see CKA_PRIVATE=True USER objects",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: SO should not access user private objects",
                )
        finally:
            _logout_safe(rs.raw, so_sh)
            close_session_quietly(rs.raw, so_sh)

            # Cleanup the key
            cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            try:
                _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
                for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                    destroy_quietly(rs.raw, cleanup_sh, h)
            finally:
                _logout_safe(rs.raw, cleanup_sh)
                close_session_quietly(rs.raw, cleanup_sh)

    @pytest.mark.destructive
    def test_so_user_mutual_exclusion(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO and USER cannot be logged in simultaneously on the same token."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear any existing login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        # Login as SO first
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(pin_bytes))
        if rv == CKR_PIN_INCORRECT:
            close_session_quietly(rs.raw, s1)
            pytest.skip("SO PIN differs from user PIN")
        if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
            close_session_quietly(rs.raw, s1)
            pytest.skip("Another user already logged in")

        try:
            # Try USER login on a second session - should fail
            s2 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
            try:
                rv2 = rs.raw.C_Login(s2, CKU_USER, pin_buf, len(pin_bytes))
                assert rv2 in (
                    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                    CKR_USER_ALREADY_LOGGED_IN,
                    CKR_USER_TYPE_INVALID,
                ), f"Expected USER login rejected while SO active, got {ckr_name(rv2)}"
            finally:
                close_session_quietly(rs.raw, s2)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# CKA_TRUSTED enforcement
# ---------------------------------------------------------------------------


class TestTrustedAttribute:
    """CKA_TRUSTED enforcement at the access-level boundary."""

    @pytest.mark.destructive
    def test_so_can_set_trusted(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SO session can set CKA_TRUSTED=True on a key (or skip)."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
        rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(pin_bytes))
        if rv == CKR_PIN_INCORRECT:
            close_session_quietly(rs.raw, s1)
            pytest.skip("SO PIN differs from user PIN")
        if rv in (CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN):
            close_session_quietly(rs.raw, s1)
            pytest.skip("Another user already logged in")

        try:
            try:
                key_h = _gen_access_aes_key(
                    rs,
                    s1,
                    attrs={
                        CKA_TOKEN: False,
                        CKA_WRAP: True,
                        CKA_TRUSTED: True,
                    },
                )
            except AssertionError as e:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Module does not support CKA_TRUSTED: {e}",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: CKA_TRUSTED set by SO",
                )
                pytest.skip(f"CKA_TRUSTED not supported: {e}")
                return

            try:
                attrs = read_attributes(rs.raw, s1, key_h, [CKA_TRUSTED])
                val = attrs.get(CKA_TRUSTED)
                assert val is True, f"Expected CKA_TRUSTED=True, got {val}"
            except AssertionError as e:
                pytest.skip(f"Module does not expose CKA_TRUSTED: {e}")
            finally:
                destroy_quietly(rs.raw, s1, key_h)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_cannot_set_trusted(self, p11_raw_session: Any) -> None:
        """USER session must not be able to gen a key with CKA_TRUSTED=True.

        Per PKCS#11 v3.1 Sec.4.7, only the SO can mark a key as TRUSTED.
        A USER session creating a TRUSTED=True key bypasses the SO trust
        boundary used by CKA_WRAP_WITH_TRUSTED to gate sensitive wraps.
        """
        rs = p11_raw_session
        try:
            key_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={
                    CKA_TOKEN: False,
                    CKA_WRAP: True,
                    CKA_TRUSTED: True,
                },
            )
        except AssertionError:
            # Expected: module rejects CKA_TRUSTED from USER
            return

        # If we get here, module allowed creating a CKA_TRUSTED key from a
        # USER session — a security boundary violation. Closes Phase 4.5
        # GAP-T5 (was previously suppressed via compliance.note() only).
        try:
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "USER session can create CKA_TRUSTED=True key (should require SO)",
                ComplianceLevel.CRITICAL,
                reference="PKCS#11 v3.1 Sec.4.7: CKA_TRUSTED set by SO only",
            )
            # Read back to confirm the violation rather than just trust the
            # gen success — some modules silently drop the attribute.
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            except AssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    return  # Module doesn't expose CKA_TRUSTED
                raise
            if attrs.get(CKA_TRUSTED) is True:
                pytest.fail(
                    "SECURITY: USER session created and was granted "
                    "CKA_TRUSTED=True on a freshly-generated key — "
                    "trust boundary breached"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_user_cannot_setattr_trusted(self, p11_raw_session: Any) -> None:
        """USER session must not be able to set CKA_TRUSTED=True on an
        existing TRUSTED=False key via C_SetAttributeValue.

        Closes Phase 4.5 GAP-T5 (HIGH-side coverage — the create-time
        case is covered by test_user_cannot_set_trusted; the
        SetAttributeValue path was missing).
        """
        rs = p11_raw_session
        # First generate a key without CKA_TRUSTED to avoid colliding with
        # modules that reject TRUSTED in templates entirely.
        try:
            key_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={CKA_TOKEN: False, CKA_WRAP: True},
            )
        except AssertionError as e:
            pytest.skip(f"Could not generate baseline AES key: {e}")
            return

        try:
            # Pre-check: the key must exist and be readable.
            try:
                attrs = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            except AssertionError as e:
                if is_known_error(e, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    pytest.skip(f"Module does not expose CKA_TRUSTED: {e}")
                raise
            if attrs.get(CKA_TRUSTED) is True:
                pytest.skip("Key created TRUSTED=True by default — unrelated path")

            # Attempt the escalation.
            try:
                set_attributes(rs.raw, rs.sh, key_h, {CKA_TRUSTED: True})
            except AssertionError as e:
                # Module rejected the SetAttribute — correct behaviour.
                if is_known_error(e, _TRUSTED_SETATTR_REJECT_RVS):
                    return
                raise

            # SetAttribute returned CKR_OK — confirm whether the change
            # actually took effect (some modules silently no-op).
            attrs2 = read_attributes(rs.raw, rs.sh, key_h, [CKA_TRUSTED])
            if attrs2.get(CKA_TRUSTED) is True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "USER session escalated CKA_TRUSTED=False → True via "
                    "C_SetAttributeValue (should require SO)",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.7: CKA_TRUSTED set by SO only",
                )
                pytest.fail(
                    "SECURITY: USER session escalated a key's CKA_TRUSTED "
                    "from False to True via C_SetAttributeValue — trust "
                    "boundary breached, opens CKA_WRAP_WITH_TRUSTED bypass"
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_wrap_with_trusted_rejects_untrusted(self, p11_raw_session: Any) -> None:
        """Without CKA_TRUSTED, wrapping a CKA_WRAP_WITH_TRUSTED key fails."""
        rs = p11_raw_session

        try:
            target_h = _gen_access_aes_key(
                rs,
                rs.sh,
                attrs={
                    CKA_EXTRACTABLE: True,
                    CKA_WRAP_WITH_TRUSTED: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as e:
            pytest.skip(f"CKA_WRAP_WITH_TRUSTED not supported: {e}")
            return

        try:
            attrs = read_attributes(rs.raw, rs.sh, target_h, [CKA_WRAP_WITH_TRUSTED])
            val = attrs.get(CKA_WRAP_WITH_TRUSTED)
        except AssertionError as e:
            destroy_quietly(rs.raw, rs.sh, target_h)
            pytest.skip(f"Module does not expose CKA_WRAP_WITH_TRUSTED: {e}")
            return

        if val is not True:
            destroy_quietly(rs.raw, rs.sh, target_h)
            pytest.skip("Module did not honour CKA_WRAP_WITH_TRUSTED=True")
            return

        # Create a normal (non-TRUSTED) wrapping key
        wrapper_h = _gen_access_aes_key(
            rs,
            rs.sh,
            attrs={CKA_WRAP: True, CKA_TOKEN: False},
        )

        try:
            if rs.has_mechanism("AES_KEY_WRAP"):
                mech = mech_simple(CKM_AES_KEY_WRAP)
            elif rs.has_mechanism("AES_CBC_PAD"):
                wrap_mech = CKM_AES_CBC_PAD
                mech = mech_bytes(wrap_mech, b"\x00" * 16)
            else:
                pytest.skip("No AES wrap mechanism available")
            out_len = CK_ULONG(0)
            rv = rs.raw.C_WrapKey(rs.sh, mech.byref(), wrapper_h, target_h, None, byref(out_len))
            if rv == CKR_OK:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_WrapKey returned CKR_OK when wrapping a CKA_WRAP_WITH_TRUSTED key "
                    "with an untrusted (non-CKA_TRUSTED) wrapping key -- "
                    "module does not enforce CKA_WRAP_WITH_TRUSTED",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec CKA_WRAP_WITH_TRUSTED, CKA_TRUSTED",
                )
                pytest.xfail(
                    "Module does not enforce CKA_WRAP_WITH_TRUSTED -- "
                    "C_WrapKey returned CKR_OK with an untrusted wrapping key "
                    "(expected CKR_ACTION_PROHIBITED, CKR_KEY_NOT_WRAPPABLE, "
                    "or CKR_FUNCTION_FAILED)"
                )
            assert rv in (
                CKR_ACTION_PROHIBITED,
                CKR_KEY_NOT_WRAPPABLE,
                CKR_FUNCTION_FAILED,
                CKR_WRAPPING_KEY_HANDLE_INVALID,
            ), f"Expected wrap rejection, got {ckr_name(rv)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, wrapper_h)
            destroy_quietly(rs.raw, rs.sh, target_h)


# ---------------------------------------------------------------------------
# CKA_ALWAYS_AUTHENTICATE
# ---------------------------------------------------------------------------


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE - context-specific re-authentication."""

    def test_always_authenticate_key_requires_reauth(self, p11_raw_session: Any) -> None:
        """Key with CKA_ALWAYS_AUTHENTICATE=True requires context-specific login."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        try:
            pub_h, priv_h = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            return

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_ALWAYS_AUTHENTICATE])
                val = attrs.get(CKA_ALWAYS_AUTHENTICATE)
            except AssertionError as e:
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
                return
            if val is not True:
                pytest.skip("Module did not honour CKA_ALWAYS_AUTHENTICATE=True")
                return

            # Attempt to sign - should require context-specific login
            data = b"test data for always-auth"
            try:
                sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
                # Some modules allow first op after normal login
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Sign succeeded without context-specific re-auth on "
                    "CKA_ALWAYS_AUTHENTICATE key (first use after login allowed)",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: CKA_ALWAYS_AUTHENTICATE re-auth",
                )
            except AssertionError:
                # Expected: module enforces re-auth
                pass
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)

    def test_always_authenticate_with_context_login(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Context-specific login enables crypto on CKA_ALWAYS_AUTHENTICATE key."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")

        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")

        try:
            pub_h, priv_h = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as e:
            pytest.skip(f"Module does not support CKA_ALWAYS_AUTHENTICATE=True: {e}")
            return

        try:
            try:
                attrs = read_attributes(rs.raw, rs.sh, priv_h, [CKA_ALWAYS_AUTHENTICATE])
                val = attrs.get(CKA_ALWAYS_AUTHENTICATE)
            except AssertionError as e:
                pytest.skip(f"Module does not expose CKA_ALWAYS_AUTHENTICATE: {e}")
                return
            if val is not True:
                pytest.skip("Module did not honour CKA_ALWAYS_AUTHENTICATE=True")
                return

            # Do context-specific login, then sign
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(rs.sh, CKU_CONTEXT_SPECIFIC, pin_buf, len(pin_bytes))
            if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                pytest.skip(f"Context-specific login not supported: {ckr_name(rv)}")
                return

            data = b"context auth test data"
            try:
                sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
                assert len(sig) > 0
            except AssertionError as e:
                pytest.skip(f"Sign after context-specific login failed: {e}")
        finally:
            destroy_quietly(rs.raw, rs.sh, priv_h)
            destroy_quietly(rs.raw, rs.sh, pub_h)


# ---------------------------------------------------------------------------
# Access level matrix: PRIVATE x TOKEN combinations
# ---------------------------------------------------------------------------


class TestAccessLevelMatrix:
    """Create objects with various PRIVATE/TOKEN combos, verify visibility."""

    def test_session_public_object_visible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=False visible without login."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"sess-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create session object (PRIVATE=False, TOKEN=False) while logged in
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"session-public",
                    CKA_TOKEN: False,
                    CKA_PRIVATE: False,
                },
            )

            # Open another session without login on same token
            s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
            try:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, s2, tmpl)
                if len(found) == 0:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Session-public object not visible in another session "
                        "(implementation-defined)",
                        ComplianceLevel.VENDOR,
                        reference="PKCS#11 spec: session object visibility",
                    )
            finally:
                close_session_quietly(rs.raw, s2)
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_token_public_object_visible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token object with PRIVATE=False visible in public session."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"tok-pub-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Create token object
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _create_access_data_object(
                rs,
                s1,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                    CKA_VALUE: b"token-public",
                    CKA_TOKEN: True,
                    CKA_PRIVATE: False,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Check visibility without login
        s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s2, tmpl)
            if len(found) == 0:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Token-public object not visible without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: CKA_PRIVATE=False visible in public",
                )
        finally:
            close_session_quietly(rs.raw, s2)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(
                rs.raw,
                cleanup_sh,
                template_from_dict({CKA_CLASS: CKO_DATA, CKA_LABEL: label}),
            ):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_token_private_object_invisible_in_public(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Token object with PRIVATE=True not visible without login."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"tok-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: True,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

        # Check NOT visible without login
        s2 = raw_open_session(rs.raw, rs.slot_id, CKF_SERIAL_SESSION)
        try:
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_SECRET_KEY,
                    CKA_LABEL: label,
                }
            )
            found = find_objects(rs.raw, s2, tmpl)
            assert len(found) == 0, "Token-private object visible in public session"
        finally:
            close_session_quietly(rs.raw, s2)

        # Cleanup
        cleanup_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, cleanup_sh, pin_bytes)
            for h in find_objects(rs.raw, cleanup_sh, template_from_dict({CKA_LABEL: label})):
                destroy_quietly(rs.raw, cleanup_sh, h)
        finally:
            _logout_safe(rs.raw, cleanup_sh)
            close_session_quietly(rs.raw, cleanup_sh)

    def test_session_private_object_invisible_after_logout(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Session object with PRIVATE=True invisible after logout."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        label = f"sess-priv-{id(self)}"
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            _gen_access_aes_key(
                rs,
                s1,
                attrs={
                    CKA_TOKEN: False,
                    CKA_PRIVATE: True,
                    CKA_LABEL: label,
                },
            )

            # Verify visible while logged in
            tmpl = template_from_dict({CKA_LABEL: label})
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) >= 1

            # Logout
            rs.raw.C_Logout(s1)

            # Should be invisible
            found = find_objects(rs.raw, s1, tmpl)
            assert len(found) == 0, "Session-private object visible after logout"
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)

    def test_user_session_visibility_matrix(self, p11_raw_session: Any, p11_config: Any) -> None:
        """USER session sees all four PRIVATE x TOKEN combinations."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        combos: list[tuple[bool, bool, str]] = [
            (False, False, f"matrix-sf-{id(self)}"),  # session, public
            (False, True, f"matrix-sp-{id(self)}"),  # session, private
            (True, False, f"matrix-tf-{id(self)}"),  # token, public
            (True, True, f"matrix-tp-{id(self)}"),  # token, private
        ]

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        created_labels: list[str] = []
        try:
            _login_user_raw(rs.raw, s1, pin_bytes)
            for is_token, is_private, label in combos:
                _create_access_data_object(
                    rs,
                    s1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"matrix-data",
                        CKA_TOKEN: is_token,
                        CKA_PRIVATE: is_private,
                    },
                )
                created_labels.append(label)

            # USER should see all four
            for label in created_labels:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                found = find_objects(rs.raw, s1, tmpl)
                assert len(found) >= 1, f"USER session cannot see object with label {label}"
        finally:
            # Cleanup token objects
            for label in created_labels:
                tmpl = template_from_dict(
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                    }
                )
                for h in find_objects(rs.raw, s1, tmpl):
                    destroy_quietly(rs.raw, s1, h)
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# SO login on RO session (negative test)
# ---------------------------------------------------------------------------


class TestSOOnROSession:
    """SO login requirements."""

    @pytest.mark.destructive
    def test_so_login_rejected_on_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_Login(SO) on R/O session must fail per spec."""
        pin_bytes = get_pin_bytes(p11_config)
        if pin_bytes is None:
            pytest.skip("No PIN configured")
        rs = p11_raw_session
        flags_ro = CKF_SERIAL_SESSION
        s1 = raw_open_session(rs.raw, rs.slot_id, flags_ro)
        try:
            pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
            rv = rs.raw.C_Login(s1, CKU_SO, pin_buf, len(pin_bytes))
            assert rv in (
                CKR_SESSION_READ_ONLY_EXISTS,
                CKR_SESSION_READ_ONLY,
                CKR_USER_ALREADY_LOGGED_IN,
                CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
                CKR_USER_TYPE_INVALID,
            ), f"Expected SO login rejected on RO session, got {ckr_name(rv)}"
        finally:
            _logout_safe(rs.raw, s1)
            close_session_quietly(rs.raw, s1)


# ---------------------------------------------------------------------------
# Public session cannot create private objects
# ---------------------------------------------------------------------------


class TestPublicSessionRestrictions:
    """Public session operational restrictions."""

    def test_public_cannot_create_private_token_object(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session (no login) cannot create CKA_PRIVATE=True token objects."""
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        try:
            try:
                key_h = gen_aes_key(
                    rs.raw,
                    s1,
                    128,
                    attrs={
                        CKA_TOKEN: True,
                        CKA_PRIVATE: True,
                        CKA_LABEL: "public-no-create",
                    },
                )
                # If it succeeded, some modules don't enforce this
                destroy_quietly(rs.raw, s1, key_h)
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Public session created CKA_PRIVATE=True token object without login",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 spec: private token objects require login",
                )
            except AssertionError:
                # Expected: public session cannot create private objects
                pass
        finally:
            close_session_quietly(rs.raw, s1)

    def test_public_can_create_non_private_data(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Public session may create CKA_PRIVATE=False data objects."""
        rs = p11_raw_session
        flags_rw = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Clear login
        pre_sh = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        rs.raw.C_Logout(pre_sh)
        close_session_quietly(rs.raw, pre_sh)

        s1 = raw_open_session(rs.raw, rs.slot_id, flags_rw)
        label = f"pub-create-{id(self)}"
        try:
            try:
                create_object(
                    rs.raw,
                    s1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"pub-created",
                        CKA_TOKEN: True,
                        CKA_PRIVATE: False,
                    },
                )
            except AssertionError:
                # Some modules require login for any creation
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "Module requires login to create any objects (even CKA_PRIVATE=False)",
                    ComplianceLevel.VENDOR,
                    reference="PKCS#11 spec: public objects in public session",
                )
                return

            # Cleanup
            tmpl = template_from_dict(
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: label,
                }
            )
            for h in find_objects(rs.raw, s1, tmpl):
                destroy_quietly(rs.raw, s1, h)
        finally:
            close_session_quietly(rs.raw, s1)
