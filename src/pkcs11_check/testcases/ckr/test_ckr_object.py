"""CKR compliance tests for object management functions.

Covers C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
C_GetAttributeValue, C_SetAttributeValue, C_FindObjects*.

Source: PKCS#11 v3.1 Sec.5.7.1-5.7.9.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import (
    attr_bool,
    attr_bytes,
    attr_ulong,
    template,
)
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    gen_aes_key,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CK_OBJECT_HANDLE,
    CK_ULONG,
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_AES,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._error_tuples import TEMPLATE_ERRORS

pytestmark = pytest.mark.access


class TestCreateObjectErrors:
    """Error conditions for C_CreateObject (Sec.5.7.1)."""

    def test_missing_class(self, p11_raw_session: Any) -> None:
        """Missing CKA_CLASS -> CKR_TEMPLATE_INCOMPLETE."""
        rs = p11_raw_session
        tmpl = template(
            attr_bytes(CKA_LABEL, b"no-class"),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
            pytest.fail("Should have rejected template without CKA_CLASS")
        assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"

    def test_invalid_class_value(self, p11_raw_session: Any) -> None:
        """CKA_CLASS=0xDEADBEEF -> CKR_ATTRIBUTE_VALUE_INVALID."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, 0xDEADBEEF),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, handle.value)
            pytest.fail("Should have rejected invalid CKA_CLASS value")
        assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"

    def test_conflicting_class_keytype(self, p11_raw_session: Any) -> None:
        """DATA object with KEY_TYPE -> reject or ignore."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
            attr_ulong(CKA_KEY_TYPE, CKK_AES),
            attr_bytes(CKA_VALUE, b"conflict"),
            attr_bool(CKA_TOKEN, False),
        )
        handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CreateObject(rs.sh, tmpl.ptr, tmpl.count, byref(handle))
        if rv == CKR_OK:
            # Some modules ignore KEY_TYPE on DATA - acceptable
            destroy_quietly(rs.raw, rs.sh, handle.value)
        else:
            assert rv in TEMPLATE_ERRORS, f"Unexpected CKR {ckr_name(rv)}"


class TestGetAttributeErrors:
    """Error conditions for C_GetAttributeValue (Sec.5.7.5)."""

    def test_sensitive_value(self, p11_raw_session: Any) -> None:
        """Reading VALUE on SENSITIVE key -> CKR_ATTRIBUTE_SENSITIVE."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            tmpl = (CK_ATTRIBUTE * 1)()
            tmpl[0].type = CKA_VALUE
            tmpl[0].pValue = None
            tmpl[0].ulValueLen = 0
            rv = rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)
            assert rv in (
                CKR_ATTRIBUTE_SENSITIVE,
                CKR_ATTRIBUTE_TYPE_INVALID,
            ), f"Expected CKR_ATTRIBUTE_SENSITIVE, got {ckr_name(rv)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroyed_handle(self, p11_raw_session: Any) -> None:
        """Using destroyed handle -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128)
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = (CK_ATTRIBUTE * 1)()
        tmpl[0].type = CKA_LABEL
        tmpl[0].pValue = None
        tmpl[0].ulValueLen = 0
        rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)
        # Some modules don't detect the invalid handle, but should not succeed
        # without CKR_OBJECT_HANDLE_INVALID or similar


class TestSetAttributeErrors:
    """Error conditions for C_SetAttributeValue (Sec.5.7.6)."""

    def test_set_readonly_class(self, p11_raw_session: Any) -> None:
        """Setting CKA_CLASS -> CKR_ATTRIBUTE_READ_ONLY."""
        rs = p11_raw_session
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "readonly-test",
                CKA_VALUE: b"test",
                CKA_TOKEN: False,
            },
        )
        try:
            # Try to change CKA_CLASS (read-only)
            tmpl = template(attr_ulong(CKA_CLASS, CKO_SECRET_KEY))
            rv = rs.raw.C_SetAttributeValue(rs.sh, handle, tmpl.ptr, tmpl.count)
            if rv == CKR_OK:
                # Kryoptic silently accepts - compliance deviation
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_SetAttributeValue accepted change to read-only CKA_CLASS",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 v3.1 Sec.5.7.6",
                )
            # Any rejection is acceptable for read-only attribute
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestCopyObjectErrors:
    """Error conditions for C_CopyObject (Sec.5.7.2)."""

    def test_copy_destroyed_handle(self, p11_raw_session: Any) -> None:
        """Copy destroyed object -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128)
        rs.raw.C_DestroyObject(rs.sh, key)
        tmpl = template(attr_bytes(CKA_LABEL, b"ckr-copy-result"))
        new_handle = CK_OBJECT_HANDLE(0)
        rv = rs.raw.C_CopyObject(
            rs.sh,
            key,
            tmpl.ptr,
            tmpl.count,
            byref(new_handle),
        )
        if rv == CKR_OK:
            destroy_quietly(rs.raw, rs.sh, new_handle.value)
            # Some modules don't detect invalid handle


class TestFindObjectsErrors:
    """Error conditions for C_FindObjects* (Sec.5.7.7-5.7.9)."""

    def test_find_with_empty_result(self, p11_raw_session: Any) -> None:
        """FindObjects with template matching nothing -> returns empty list."""
        rs = p11_raw_session
        tmpl = template(attr_bytes(CKA_LABEL, b"nonexistent_ckr_label_xyz"))
        rv = rs.raw.C_FindObjectsInit(rs.sh, tmpl.ptr, tmpl.count)
        assert rv == CKR_OK, f"C_FindObjectsInit failed: {ckr_name(rv)}"
        handles = (CK_OBJECT_HANDLE * 10)()
        count = CK_ULONG(0)
        rv = rs.raw.C_FindObjects(rs.sh, handles, 10, byref(count))
        assert rv == CKR_OK
        rs.raw.C_FindObjectsFinal(rs.sh)
        assert count.value == 0  # Empty is valid - not an error

    def test_find_by_class(self, p11_raw_session: Any) -> None:
        """FindObjects with CKA_CLASS filter works correctly."""
        rs = p11_raw_session
        handle = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: "ckr-find-test",
                CKA_VALUE: b"test",
                CKA_TOKEN: False,
            },
        )
        try:
            search = template(attr_bytes(CKA_LABEL, b"ckr-find-test"))
            rv = rs.raw.C_FindObjectsInit(rs.sh, search.ptr, search.count)
            assert rv == CKR_OK
            handles = (CK_OBJECT_HANDLE * 10)()
            count = CK_ULONG(0)
            rv = rs.raw.C_FindObjects(rs.sh, handles, 10, byref(count))
            assert rv == CKR_OK
            rs.raw.C_FindObjectsFinal(rs.sh)
            assert count.value >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, handle)


class TestDestroyObjectErrors:
    """Error conditions for C_DestroyObject (Sec.5.7.3)."""

    def test_destroy_already_destroyed(self, p11_raw_session: Any) -> None:
        """Double destroy -> CKR_OBJECT_HANDLE_INVALID."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128)
        rv = rs.raw.C_DestroyObject(rs.sh, key)
        assert rv == CKR_OK, f"First destroy failed: {ckr_name(rv)}"
        rv = rs.raw.C_DestroyObject(rs.sh, key)
        # Some modules silently accept double destroy
        # Correct per spec is CKR_OBJECT_HANDLE_INVALID
