"""CKO_DATA object tests.

Verifies create, search by label/application, read value, and destroy
of generic data objects (CKO_DATA / ObjectClass.DATA).

CKO_DATA is the simplest PKCS#11 object type - no cryptographic
operations, just opaque byte storage with metadata.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly, login_user
from pkcs11_check.raw.bootstrap import open_session as raw_open_session
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_APPLICATION,
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_DATA,
    CKU_USER,
)

pytestmark = pytest.mark.keymgmt


def _unique_label(prefix: str = "data") -> str:
    """Generate a unique label to avoid test interference."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _read_str(attrs: dict[int, bytes | int | bool], key: int) -> str:
    """Decode a raw attribute value to str (labels / application names).

    read_attributes() decodes CK_ULONG-sized values as int. When the
    attribute is actually a UTF-8 string whose length happens to equal
    sizeof(CK_ULONG) (8 on 64-bit), reverse the int encoding first.
    """
    import ctypes as _ct
    import sys as _sys

    v = attrs[key]
    if isinstance(v, bytes):
        return v.decode("utf-8")
    if isinstance(v, int):
        raw_bytes = v.to_bytes(_ct.sizeof(_ct.c_ulong), byteorder=_sys.byteorder)
        return raw_bytes.decode("utf-8")
    return str(v)


def _search_by_label(raw: Any, sh: int, label: str) -> list[int]:
    """Find CKO_DATA objects matching a label."""
    tmpl = template(
        attr_ulong(CKA_CLASS, int(CKO_DATA)),
        attr_bytes(CKA_LABEL, label.encode("utf-8")),
    )
    return find_objects(raw, sh, tmpl)


class TestDataObjectCreate:
    """Test CKO_DATA object creation."""

    def test_create_data_object(self, p11_raw_session: Any) -> None:
        """Can create a CKO_DATA object with label, app, and value."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_APPLICATION): "pkcs11-check",
            int(CKA_VALUE): b"hello world",
            int(CKA_TOKEN): False,
        })
        try:
            assert h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_create_data_object_empty_value(self, p11_raw_session: Any) -> None:
        """CKO_DATA with empty VALUE is valid."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): b"",
            int(CKA_TOKEN): False,
        })
        try:
            assert h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_create_data_object_large_value(self, p11_raw_session: Any) -> None:
        """CKO_DATA with 64KB value - tests large blob storage."""
        rs = p11_raw_session
        label = _unique_label()
        big_data = bytes(range(256)) * 256  # 64KB
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): big_data,
            int(CKA_TOKEN): False,
        })
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == big_data
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestDataObjectSearch:
    """Test searching for CKO_DATA objects."""

    def test_search_by_label(self, p11_raw_session: Any) -> None:
        """Find CKO_DATA by CKA_LABEL."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): b"searchable",
            int(CKA_TOKEN): False,
        })
        try:
            found = _search_by_label(rs.raw, rs.sh, label)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_search_by_application(self, p11_raw_session: Any) -> None:
        """Find CKO_DATA by CKA_APPLICATION."""
        rs = p11_raw_session
        app_name = _unique_label("app")
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_APPLICATION): app_name,
            int(CKA_VALUE): b"app-data",
            int(CKA_TOKEN): False,
        })
        try:
            tmpl = template(
                attr_ulong(CKA_CLASS, int(CKO_DATA)),
                attr_bytes(CKA_APPLICATION, app_name.encode("utf-8")),
            )
            found = find_objects(rs.raw, rs.sh, tmpl)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_search_by_class_only(self, p11_raw_session: Any) -> None:
        """Search for all CKO_DATA objects returns at least the one we created."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): b"class-search",
            int(CKA_TOKEN): False,
        })
        try:
            tmpl = template(attr_ulong(CKA_CLASS, int(CKO_DATA)))
            found = find_objects(rs.raw, rs.sh, tmpl)
            labels = []
            for fh in found:
                attrs = read_attributes(rs.raw, rs.sh, fh, [int(CKA_LABEL)])
                labels.append(_read_str(attrs, int(CKA_LABEL)))
            assert label in labels
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_search_no_match_returns_empty(self, p11_raw_session: Any) -> None:
        """Search for non-existent label returns empty list."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, int(CKO_DATA)),
            attr_bytes(CKA_LABEL, ("does-not-exist-" + uuid.uuid4().hex).encode("utf-8")),
        )
        found = find_objects(rs.raw, rs.sh, tmpl)
        assert found == []


class TestDataObjectReadValue:
    """Test reading CKA_VALUE from CKO_DATA objects."""

    def test_read_value_matches_written(self, p11_raw_session: Any) -> None:
        """CKA_VALUE read matches what was written."""
        rs = p11_raw_session
        label = _unique_label()
        payload = b"\x00\x01\x02\xff" * 100
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): payload,
            int(CKA_TOKEN): False,
        })
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == payload
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_read_label_and_application(self, p11_raw_session: Any) -> None:
        """CKA_LABEL and CKA_APPLICATION are readable."""
        rs = p11_raw_session
        label = _unique_label()
        app = "test-app"
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_APPLICATION): app,
            int(CKA_VALUE): b"meta",
            int(CKA_TOKEN): False,
        })
        try:
            attrs = read_attributes(
                rs.raw, rs.sh, h, [int(CKA_LABEL), int(CKA_APPLICATION)]
            )
            assert _read_str(attrs, int(CKA_LABEL)) == label
            assert _read_str(attrs, int(CKA_APPLICATION)) == app
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_object_class_is_data(self, p11_raw_session: Any) -> None:
        """CKA_CLASS reports CKO_DATA."""
        rs = p11_raw_session
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): _unique_label(),
            int(CKA_VALUE): b"class-check",
            int(CKA_TOKEN): False,
        })
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [int(CKA_CLASS)])
            assert attrs[int(CKA_CLASS)] == int(CKO_DATA)
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestDataObjectDestroy:
    """Test CKO_DATA object destruction."""

    def test_destroy_removes_object(self, p11_raw_session: Any) -> None:
        """Destroyed CKO_DATA no longer appears in search."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(rs.raw, rs.sh, {
            int(CKA_CLASS): int(CKO_DATA),
            int(CKA_LABEL): label,
            int(CKA_VALUE): b"destroy-me",
            int(CKA_TOKEN): False,
        })
        rs.raw.C_DestroyObject(rs.sh, h)
        found = _search_by_label(rs.raw, rs.sh, label)
        assert len(found) == 0

    def test_create_destroy_multiple(self, p11_raw_session: Any) -> None:
        """Create several CKO_DATA objects, destroy them all, verify clean."""
        rs = p11_raw_session
        labels = [_unique_label() for _ in range(5)]
        handles = []
        for lbl in labels:
            h = create_object(rs.raw, rs.sh, {
                int(CKA_CLASS): int(CKO_DATA),
                int(CKA_LABEL): lbl,
                int(CKA_VALUE): b"multi",
                int(CKA_TOKEN): False,
            })
            handles.append(h)

        for h in handles:
            rs.raw.C_DestroyObject(rs.sh, h)

        for lbl in labels:
            found = _search_by_label(rs.raw, rs.sh, lbl)
            assert len(found) == 0


class TestDataObjectToken:
    """Test CKO_DATA with TOKEN=True (persistent)."""

    def test_token_data_object_survives_session(
        self, p11_raw_session: Any, p11_config: Any
    ) -> None:
        """CKO_DATA with TOKEN=True persists across sessions."""
        rs = p11_raw_session
        pin = p11_config.pin
        pin_bytes = (
            pin.get_secret_value().encode("utf-8")
            if hasattr(pin, "get_secret_value")
            else (pin.encode("utf-8") if isinstance(pin, str) else pin)
        )
        label = _unique_label("persist")
        flags = int(CKF_SERIAL_SESSION | CKF_RW_SESSION)

        # Session 1: create token object
        sh1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes:
            login_user(rs.raw, sh1, int(CKU_USER), pin_bytes)
        try:
            create_object(rs.raw, sh1, {
                int(CKA_CLASS): int(CKO_DATA),
                int(CKA_LABEL): label,
                int(CKA_VALUE): b"persistent-data",
                int(CKA_TOKEN): True,
            })
        finally:
            close_session_quietly(rs.raw, sh1)

        # Session 2: find and verify
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes:
            login_user(rs.raw, sh2, int(CKU_USER), pin_bytes)
        try:
            found = _search_by_label(rs.raw, sh2, label)
            assert len(found) >= 1
            attrs = read_attributes(rs.raw, sh2, found[0], [int(CKA_VALUE)])
            assert attrs[int(CKA_VALUE)] == b"persistent-data"
        finally:
            # Cleanup: destroy all matching objects
            for fh in _search_by_label(rs.raw, sh2, label):
                rs.raw.C_DestroyObject(sh2, fh)
            close_session_quietly(rs.raw, sh2)
