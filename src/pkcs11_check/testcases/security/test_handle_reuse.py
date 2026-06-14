"""Handle reuse after destroy tests.

Verifies that using a destroyed object handle returns proper CKR errors,
not crashes or undefined behavior.

Reference: rep11.md - stale handles after C_DestroyObject + reuse.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    read_attributes,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_LABEL,
    CKA_WRAP,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_SHA256_RSA_PKCS,
    CKR_OK,
)
from pkcs11_check.testcases._error_tuples import HANDLE_ERRORS
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    is_known_error,
    skip_unless_mechanism,
)

pytestmark = pytest.mark.security


def _aes_handle_reuse_key(rs: Any, *, attrs: dict[Any, Any] | None = None) -> int:
    return gen_aes_key_or_xfail(rs, 128, attrs=attrs, purpose="handle-reuse setup")


def _destroy_object(raw: Any, sh: int, handle: int) -> None:
    expect_rv(raw.C_DestroyObject(sh, handle), CKR_OK)


def _assert_destroyed_handle_error(rv: int, operation: str) -> None:
    # lifecycle use-after-destroy 3-way classification. The object was already
    # destroyed (the prior C_DestroyObject was asserted to return CKR_OK), so
    # the operation must reject the stale handle:
    #   CKR_OK              -> fail (use-after-destroy: the op succeeded),
    #   rv in HANDLE_ERRORS -> pass (spec-correct handle rejection),
    #   other clean reject  -> xfail (rejected, but with a non-handle code).
    classify_negative_rv(
        rv,
        HANDLE_ERRORS,
        label=f"{operation} on a destroyed object handle (use-after-destroy)",
    )


def _assert_read_destroyed_handle_fails(rs: Any, key: int) -> None:
    try:
        read_attributes(rs.raw, rs.sh, key, [CKA_LABEL])
    except AssertionError as exc:
        if is_known_error(exc, HANDLE_ERRORS):
            return
        raise
    classify(
        "self_contradiction",
        kind="lifecycle",
        label="C_GetAttributeValue on a destroyed object handle (use-after-destroy)",
        operation="C_GetAttributeValue",
        summary="C_GetAttributeValue succeeded with destroyed handle",
    )


class TestHandleReuseAfterDestroy:
    """Use destroyed object handles - must get CKR error, not crash."""

    def test_get_attribute_after_destroy(self, p11_raw_session: Any) -> None:
        """Reading attribute from destroyed key must fail cleanly."""
        rs = p11_raw_session
        key = _aes_handle_reuse_key(rs, attrs={CKA_LABEL: "handle-reuse-1"})
        _destroy_object(rs.raw, rs.sh, key)
        _assert_read_destroyed_handle_fails(rs, key)

    def test_encrypt_after_destroy(self, p11_raw_session: Any) -> None:
        """Encrypting with destroyed key must fail cleanly."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "AES_ECB")
        key = _aes_handle_reuse_key(rs, attrs={CKA_ENCRYPT: True})
        _destroy_object(rs.raw, rs.sh, key)

        # Attempt C_EncryptInit with destroyed handle
        mech = mech_simple(CKM_AES_ECB)
        rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
        _assert_destroyed_handle_error(rv, "C_EncryptInit")

    def test_sign_after_destroy(self, p11_raw_session: Any) -> None:
        """Signing with destroyed RSA key must fail cleanly."""
        rs = p11_raw_session
        skip_unless_mechanism(rs, "SHA256_RSA_PKCS")
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        _destroy_object(rs.raw, rs.sh, priv)

        try:
            # Attempt C_SignInit with destroyed handle
            mech = mech_simple(CKM_SHA256_RSA_PKCS)
            rv = rs.raw.C_SignInit(rs.sh, mech.byref(), priv)
            _assert_destroyed_handle_error(rv, "C_SignInit")
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_wrap_after_destroy(self, p11_raw_session: Any) -> None:
        """Wrapping with destroyed key must fail cleanly."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP"):
            pytest.skip("AES_KEY_WRAP not supported")
        wrap_key = _aes_handle_reuse_key(rs, attrs={CKA_WRAP: True})
        target = _aes_handle_reuse_key(rs, attrs={CKA_EXTRACTABLE: True})
        _destroy_object(rs.raw, rs.sh, wrap_key)

        try:
            # Attempt C_WrapKey with destroyed wrapping key
            mech = mech_simple(CKM_AES_KEY_WRAP)
            buf = (ctypes.c_ubyte * 256)()
            buf_len = CK_ULONG(256)
            rv = rs.raw.C_WrapKey(rs.sh, mech.byref(), wrap_key, target, buf, byref(buf_len))
            _assert_destroyed_handle_error(rv, "C_WrapKey")
        finally:
            destroy_quietly(rs.raw, rs.sh, target)

    def test_double_destroy(self, p11_raw_session: Any) -> None:
        """Destroying an already-destroyed key must fail cleanly."""
        rs = p11_raw_session
        key = _aes_handle_reuse_key(rs)
        _destroy_object(rs.raw, rs.sh, key)

        # Second destroy should return an error, not crash
        rv = rs.raw.C_DestroyObject(rs.sh, key)
        _assert_destroyed_handle_error(rv, "C_DestroyObject")

    def test_set_attribute_after_destroy(self, p11_raw_session: Any) -> None:
        """Setting attribute on destroyed object must fail cleanly."""
        rs = p11_raw_session
        key = _aes_handle_reuse_key(rs, attrs={CKA_LABEL: "modify-after-destroy"})
        _destroy_object(rs.raw, rs.sh, key)

        # Attempt C_SetAttributeValue on destroyed handle
        from pkcs11_check.raw.pack import attr_string, template

        tmpl = template(attr_string(CKA_LABEL, "new-label"))
        rv = rs.raw.C_SetAttributeValue(rs.sh, key, tmpl.ptr, tmpl.count)
        _assert_destroyed_handle_error(rv, "C_SetAttributeValue")

    def test_copy_after_destroy(self, p11_raw_session: Any) -> None:
        """Copying a destroyed object must fail cleanly."""
        rs = p11_raw_session
        key = _aes_handle_reuse_key(rs, attrs={CKA_LABEL: "copy-after-destroy"})
        _destroy_object(rs.raw, rs.sh, key)

        from pkcs11_check.raw.pack import attr_string, template
        from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE

        tmpl = template(attr_string(CKA_LABEL, "copied"))
        new_h = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CopyObject(rs.sh, key, tmpl.ptr, tmpl.count, byref(new_h))
        _assert_destroyed_handle_error(rv, "C_CopyObject")
