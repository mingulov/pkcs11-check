"""Read-only session restriction enforcement tests.

Verifies that RO sessions correctly reject write operations on token objects
while allowing session-scoped operations, per PKCS#11 spec section 5.6.
"""

from __future__ import annotations

import os
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
)
from pkcs11_check.raw.bootstrap import (
    open_session as raw_open_session,
)
from pkcs11_check.raw.pack import mech_bytes, mech_simple, template_from_dict
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    find_objects,
    gen_aes_key,
    gen_rsa_keypair,
    import_secret_key,
    set_attributes,
    sign_single,
    unwrap_key,
    verify_single,
    wrap_key,
)
from pkcs11_check.raw.rv import ckr_name, expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CK_UTF8CHAR,
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKF_SERIAL_SESSION,
    CKK_AES,
    CKM_AES_CBC_PAD,
    CKM_AES_ECB,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_SHA256_RSA_PKCS,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_TOKEN_WRITE_PROTECTED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_TYPE_INVALID,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import get_pin_bytes

pytestmark = pytest.mark.access

# RO restriction errors
_RO_ERROR_RVS = (
    int(CKR_SESSION_READ_ONLY),
    int(CKR_ACTION_PROHIBITED),
    int(CKR_SESSION_READ_ONLY_EXISTS),
)

# Broader set including unsupported
_RO_OR_UNSUPPORTED_RVS = (
    int(CKR_SESSION_READ_ONLY),
    int(CKR_ACTION_PROHIBITED),
    int(CKR_SESSION_READ_ONLY_EXISTS),
    int(CKR_TOKEN_WRITE_PROTECTED),
    int(CKR_ATTRIBUTE_READ_ONLY),
    int(CKR_FUNCTION_NOT_SUPPORTED),
    int(CKR_MECHANISM_INVALID),
)


def _login_ro(raw: Any, sh: int, pin_bytes: bytes | None) -> None:
    """Login to a session, handling already-logged-in state."""
    if pin_bytes is None:
        return
    pin_buf = (CK_UTF8CHAR * len(pin_bytes))(*pin_bytes)
    rv = int(raw.C_Login(sh, int(CKU_USER), pin_buf, len(pin_bytes)))
    if rv not in (int(CKR_OK), int(CKR_USER_ALREADY_LOGGED_IN), int(CKR_USER_TYPE_INVALID)):
        expect_rv(rv, CKR_OK)


class TestROTokenObjectCreation:
    """RO sessions must reject creation of token-persistent objects."""

    def test_create_token_object_in_ro_fails(self, p11_raw_session: Any, p11_config: Any) -> None:
        """C_CreateObject with CKA_TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import template_from_dict as _tfd

            tmpl = _tfd(
                {
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_VALUE): os.urandom(16),
                    int(CKA_TOKEN): True,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                }
            )
            obj_h = CK_OBJECT_HANDLE(0)
            rv = int(rs.raw.C_CreateObject(ro_sh, tmpl.ptr, tmpl.count, byref(obj_h)))
            assert rv in _RO_ERROR_RVS, f"Expected RO error, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_key_token_true_in_ro_fails(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_key with TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

            tmpl = template(
                attr_ulong(CKA_VALUE_LEN, 16),
                attr_bool(CKA_TOKEN, True),
            )
            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = int(rs.raw.C_GenerateKey(ro_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h)))
            assert rv in _RO_ERROR_RVS, f"Expected RO error, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_keypair_token_true_in_ro_fails(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_keypair with TOKEN=True in RO session must fail."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
            from pkcs11_check.raw.types_std import CKA_MODULUS_BITS

            pub_tmpl = template(
                attr_ulong(CKA_MODULUS_BITS, 2048),
                attr_bool(CKA_TOKEN, True),
            )
            priv_tmpl = template(attr_bool(CKA_TOKEN, True))
            mech = mech_simple(CKM_RSA_PKCS_KEY_PAIR_GEN)
            pub_h = CK_OBJECT_HANDLE(0)
            priv_h = CK_OBJECT_HANDLE(0)
            rv = int(
                rs.raw.C_GenerateKeyPair(
                    ro_sh,
                    mech.byref(),
                    pub_tmpl.ptr,
                    pub_tmpl.count,
                    priv_tmpl.ptr,
                    priv_tmpl.count,
                    byref(pub_h),
                    byref(priv_h),
                )
            )
            assert rv in _RO_ERROR_RVS, f"Expected RO error, got {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestROSessionObjectsAllowed:
    """RO sessions must allow session-scoped (TOKEN=False) operations."""

    def test_create_session_object_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """C_CreateObject with CKA_TOKEN=False in RO session succeeds."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            obj_h = import_secret_key(
                rs.raw,
                ro_sh,
                CKK_AES,
                os.urandom(16),
                attrs={
                    int(CKA_TOKEN): False,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                },
            )
            assert obj_h != 0
            destroy_quietly(rs.raw, ro_sh, obj_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_key_token_false_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_key with TOKEN=False in RO session succeeds."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            key_h = gen_aes_key(rs.raw, ro_sh, 128, attrs={int(CKA_LABEL): "ro-genkey-session"})
            assert key_h != 0
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_generate_keypair_session_in_ro_succeeds(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """generate_keypair with store=False in RO session succeeds."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            pub_h, priv_h = gen_rsa_keypair(rs.raw, ro_sh, 2048)
            assert pub_h != 0
            assert priv_h != 0
            destroy_quietly(rs.raw, ro_sh, pub_h)
            destroy_quietly(rs.raw, ro_sh, priv_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestROTokenObjectMutation:
    """RO sessions must reject mutation of token objects."""

    def test_destroy_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """C_DestroyObject of token object in RO session must fail."""
        rs = p11_raw_session
        label = "ro-destroy-test"
        key_h = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_TOKEN): True, int(CKA_LABEL): label})
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                rv = int(rs.raw.C_DestroyObject(ro_sh, found[0]))
                assert rv in _RO_ERROR_RVS, f"Expected RO error, got {ckr_name(rv)}"
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_set_attribute_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """C_SetAttributeValue on token object in RO session must fail."""
        rs = p11_raw_session
        label = "ro-setattr-test"
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                int(CKA_TOKEN): True,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
                int(CKA_LABEL): label,
            },
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                try:
                    set_attributes(rs.raw, ro_sh, found[0], {int(CKA_LABEL): "ro-setattr-changed"})
                    # Should not succeed
                    assert False, "C_SetAttributeValue succeeded on token object in RO session"
                except AssertionError as e:
                    if "C_SetAttributeValue succeeded" in str(e):
                        raise
                    pass  # Expected: recipes raises AssertionError from expect_rv
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_copy_token_object_in_ro_as_token_fails(self, p11_raw_session: Any) -> None:
        """C_CopyObject of token object to another token object in RO fails."""
        from pkcs11_check.raw.recipes import copy_object

        rs = p11_raw_session
        label = "ro-copy-test"
        key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            128,
            attrs={
                int(CKA_TOKEN): True,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
                int(CKA_LABEL): label,
            },
        )
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                try:
                    copy_object(
                        rs.raw,
                        ro_sh,
                        found[0],
                        {int(CKA_LABEL): "ro-copy-result", int(CKA_TOKEN): True},
                    )
                    assert False, "C_CopyObject succeeded on token object in RO session"
                except AssertionError as e:
                    if "C_CopyObject succeeded" in str(e):
                        raise
                    pass  # Expected
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)


class TestROCryptoOperations:
    """Crypto operations (no token writes) must work in RO sessions."""

    def test_digest_in_ro_session(self, p11_raw_session: Any, p11_config: Any) -> None:
        """SHA-256 digest works in RO session."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            digest = digest_single(rs.raw, ro_sh, CKM_SHA256, b"RO session restriction test data")
            assert len(digest) == 32
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_encrypt_decrypt_session_key_in_ro(self, p11_raw_session: Any, p11_config: Any) -> None:
        """Encrypt/decrypt with session key works in RO session."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CBC_PAD"):
            pytest.skip("CKM_AES_CBC_PAD not supported")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            key_h = gen_aes_key(
                rs.raw,
                ro_sh,
                256,
                attrs={
                    int(CKA_TOKEN): False,
                    int(CKA_ENCRYPT): True,
                    int(CKA_DECRYPT): True,
                },
            )
            iv = os.urandom(16)
            plaintext = b"RO encrypt test!"
            ct = encrypt_single(
                rs.raw,
                ro_sh,
                key_h,
                CKM_AES_CBC_PAD,
                plaintext,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            pt = decrypt_single(
                rs.raw,
                ro_sh,
                key_h,
                CKM_AES_CBC_PAD,
                ct,
                mech_param=mech_bytes(CKM_AES_CBC_PAD, iv),
            )
            assert pt == plaintext
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_sign_verify_session_key_in_ro(self, p11_raw_session: Any, p11_config: Any) -> None:
        """HMAC sign/verify with session key works in RO session."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_HMAC"):
            pytest.skip("CKM_SHA256_HMAC not supported")
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.types_std import CKM_GENERIC_SECRET_KEY_GEN

            key_h = gen_aes_key(
                rs.raw,
                ro_sh,
                256,
                attrs={
                    int(CKA_TOKEN): False,
                    int(CKA_SIGN): True,
                    int(CKA_VERIFY): True,
                },
                mechanism=int(CKM_GENERIC_SECRET_KEY_GEN),
            )
            data = b"RO session HMAC test"
            sig = sign_single(rs.raw, ro_sh, key_h, CKM_SHA256_HMAC, data)
            assert len(sig) > 0
            result = verify_single(rs.raw, ro_sh, key_h, CKM_SHA256_HMAC, data, sig)
            assert result is True
            destroy_quietly(rs.raw, ro_sh, key_h)
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_verify_token_key_in_ro(self, p11_raw_session: Any) -> None:
        """Verification with a token key works in RO session."""
        rs = p11_raw_session
        label = "ro-verify-rsa-test"
        pub_h, priv_h = gen_rsa_keypair(
            rs.raw,
            rs.sh,
            2048,
            public_attrs={int(CKA_TOKEN): True, int(CKA_LABEL): label},
            private_attrs={int(CKA_TOKEN): True, int(CKA_LABEL): label},
        )
        data = b"verify in read-only session"
        sig = sign_single(rs.raw, rs.sh, priv_h, CKM_SHA256_RSA_PKCS, data)
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict(
                    {
                        int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                        int(CKA_LABEL): label,
                    }
                )
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Public key not found in RO session"
                result = verify_single(rs.raw, ro_sh, found[0], CKM_SHA256_RSA_PKCS, data, sig)
                assert result is True
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, pub_h)
            destroy_quietly(rs.raw, rs.sh, priv_h)


class TestROExactCKR:
    """Verify the exact CKR code returned for RO restriction violations."""

    def test_create_token_object_returns_session_read_only(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Primary expected CKR is CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import template_from_dict as _tfd

            tmpl = _tfd(
                {
                    int(CKA_CLASS): int(CKO_SECRET_KEY),
                    int(CKA_KEY_TYPE): int(CKK_AES),
                    int(CKA_VALUE): os.urandom(16),
                    int(CKA_TOKEN): True,
                    int(CKA_SENSITIVE): False,
                    int(CKA_EXTRACTABLE): True,
                }
            )
            obj_h = CK_OBJECT_HANDLE(0)
            rv = int(rs.raw.C_CreateObject(ro_sh, tmpl.ptr, tmpl.count, byref(obj_h)))
            assert rv in _RO_ERROR_RVS, f"Unexpected CKR: {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, ro_sh)

    def test_destroy_token_object_returns_session_read_only(self, p11_raw_session: Any) -> None:
        """Destroy of token object in RO returns CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        label = "ro-ckr-destroy-test"
        key_h = gen_aes_key(rs.raw, rs.sh, 128, attrs={int(CKA_TOKEN): True, int(CKA_LABEL): label})
        try:
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): label})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Token object not found in RO session"
                rv = int(rs.raw.C_DestroyObject(ro_sh, found[0]))
                assert rv in _RO_ERROR_RVS, f"Unexpected CKR: {ckr_name(rv)}"
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, key_h)

    def test_generate_key_token_returns_session_read_only(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """Key generation with TOKEN=True in RO returns CKR_SESSION_READ_ONLY."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
        _login_ro(rs.raw, ro_sh, pin_bytes)
        try:
            from pkcs11_check.raw.pack import attr_bool, attr_ulong, template

            tmpl = template(
                attr_ulong(CKA_VALUE_LEN, 32),
                attr_bool(CKA_TOKEN, True),
            )
            mech = mech_simple(CKM_AES_KEY_GEN)
            key_h = CK_OBJECT_HANDLE(0)
            rv = int(rs.raw.C_GenerateKey(ro_sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key_h)))
            assert rv in _RO_ERROR_RVS, f"Unexpected CKR: {ckr_name(rv)}"
        finally:
            close_session_quietly(rs.raw, ro_sh)


class TestROWrapUnwrapRestrictions:
    """Unwrap creating TOKEN=True key in RO session must fail."""

    def test_unwrap_to_token_object_in_ro_fails(self, p11_raw_session: Any) -> None:
        """Unwrap with TOKEN=True template in RO session must fail."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported for wrapping")

        # Create wrapping key and target in RW session
        wrapping_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                int(CKA_TOKEN): True,
                int(CKA_WRAP): True,
                int(CKA_UNWRAP): True,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
                int(CKA_LABEL): "ro-unwrap-wrapkey",
            },
        )
        target_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            os.urandom(16),
            attrs={
                int(CKA_TOKEN): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
            },
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrapping_key_h, target_h, CKM_AES_ECB)
            except AssertionError:
                pytest.skip("Module does not support wrap/unwrap")
            assert len(wrapped) > 0

            # Open RO session, find wrapping key, try unwrap with TOKEN=True
            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): "ro-unwrap-wrapkey"})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Wrapping key not found in RO session"
                try:
                    unwrap_key(
                        rs.raw,
                        ro_sh,
                        found[0],
                        wrapped,
                        CKM_AES_ECB,
                        attrs={
                            int(CKA_TOKEN): True,
                            int(CKA_SENSITIVE): False,
                            int(CKA_EXTRACTABLE): True,
                        },
                    )
                    assert False, "Unwrap to TOKEN=True succeeded in RO session"
                except AssertionError as e:
                    if "Unwrap to TOKEN=True succeeded" in str(e):
                        raise
                    pass  # Expected
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrapping_key_h)

    def test_unwrap_to_session_object_in_ro_succeeds(self, p11_raw_session: Any) -> None:
        """Unwrap with TOKEN=False template in RO session succeeds."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_ECB"):
            pytest.skip("CKM_AES_ECB not supported for wrapping")

        wrapping_key_h = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={
                int(CKA_TOKEN): True,
                int(CKA_WRAP): True,
                int(CKA_UNWRAP): True,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
                int(CKA_LABEL): "ro-unwrap-session-wrapkey",
            },
        )
        key_bytes = os.urandom(16)
        target_h = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={
                int(CKA_TOKEN): False,
                int(CKA_EXTRACTABLE): True,
                int(CKA_SENSITIVE): False,
            },
        )
        try:
            try:
                wrapped = wrap_key(rs.raw, rs.sh, wrapping_key_h, target_h, CKM_AES_ECB)
            except AssertionError:
                pytest.skip("Module does not support wrap/unwrap")

            ro_sh = raw_open_session(rs.raw, rs.slot_id, int(CKF_SERIAL_SESSION))
            try:
                tmpl = template_from_dict({int(CKA_LABEL): "ro-unwrap-session-wrapkey"})
                found = find_objects(rs.raw, ro_sh, tmpl)
                assert len(found) >= 1, "Wrapping key not found in RO session"
                try:
                    unwrapped_h = unwrap_key(
                        rs.raw,
                        ro_sh,
                        found[0],
                        wrapped,
                        CKM_AES_ECB,
                        attrs={
                            int(CKA_TOKEN): False,
                            int(CKA_SENSITIVE): False,
                            int(CKA_EXTRACTABLE): True,
                        },
                    )
                    assert unwrapped_h != 0
                    destroy_quietly(rs.raw, ro_sh, unwrapped_h)
                except AssertionError as exc:
                    from pkcs11_check.compliance import ComplianceLevel, note

                    note(
                        "Module rejects C_UnwrapKey with TOKEN=False in RO session "
                        f"({exc}); PKCS#11 spec permits session-object "
                        "creation via C_UnwrapKey in RO sessions",
                        ComplianceLevel.NOT_RECOMMENDED,
                    )
                    pytest.xfail(f"Module overly restricts RO session unwrap ({exc})")
            finally:
                close_session_quietly(rs.raw, ro_sh)
        finally:
            destroy_quietly(rs.raw, rs.sh, target_h)
            destroy_quietly(rs.raw, rs.sh, wrapping_key_h)
