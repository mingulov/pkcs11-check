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
from pkcs11_check.raw.bootstrap import open_session as _raw_open_session
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    read_attributes,
)
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_APPLICATION,
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKO_DATA,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_SESSION_COUNT,
    CKU_USER,
)
from pkcs11_check.testcases.conftest import (
    get_pin_bytes,
    is_known_error,
    skip_if_data_objects_unsupported,
    skip_if_token_write_protected,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt


@pytest.fixture(autouse=True)
def _skip_if_no_data_objects(p11_raw_session: Any) -> None:
    """Skip every CKO_DATA test when the module lacks data-object storage.

    Five-plus providers (nethsm, corepkcs11, tpm2, wolfpkcs11, craton-hsm) do
    not implement CKO_DATA; for them every test in this file is a genuine
    capability absence (PKCS#11 v3.2 §6.4) and the right classification is
    ``skip``, not ``xfail``.
    """
    skip_if_data_objects_unsupported(p11_raw_session)


def _unique_label(prefix: str = "data") -> str:
    """Generate a unique label to avoid test interference."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _read_str(attrs: dict[int, Any], key: int) -> str:
    """Read a string attribute (read_attributes returns str for RFC2279 attrs)."""
    v = attrs[key]
    if isinstance(v, str):
        return v
    return v.decode("utf-8") if isinstance(v, bytes) else str(v)


def _search_by_label(raw: Any, sh: int, label: str) -> list[int]:
    """Find CKO_DATA objects matching a label."""
    tmpl = template(
        attr_ulong(CKA_CLASS, CKO_DATA),
        attr_bytes(CKA_LABEL, label.encode("utf-8")),
    )
    return find_objects(raw, sh, tmpl)


def raw_open_session(raw: Any, slot_id: int, flags: int) -> int:
    """Open an extra session needed by data-object persistence tests."""
    try:
        return _raw_open_session(raw, slot_id, flags)
    except AssertionError as exc:
        if is_known_error(exc, (CKR_SESSION_COUNT,)):
            pytest.skip(
                "Cannot open additional session required by data-object test: "
                f"{ckr_name(int(CKR_SESSION_COUNT))}"
            )
        raise


class TestDataObjectCreate:
    """Test CKO_DATA object creation."""

    def test_create_data_object(self, p11_raw_session: Any) -> None:
        """Can create a CKO_DATA object with label, app, and value."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_APPLICATION: "pkcs11-check",
                CKA_VALUE: b"hello world",
                CKA_TOKEN: False,
            },
        )
        try:
            assert h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_create_data_object_empty_value(self, p11_raw_session: Any) -> None:
        """CKO_DATA with empty VALUE is valid."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"",
                CKA_TOKEN: False,
            },
        )
        try:
            assert h != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_create_data_object_large_value(self, p11_raw_session: Any) -> None:
        """CKO_DATA with 64KB value - tests large blob storage."""
        rs = p11_raw_session
        label = _unique_label()
        big_data = bytes(range(256)) * 256  # 64KB
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: big_data,
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
            assert attrs[CKA_VALUE] == big_data
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestDataObjectSearch:
    """Test searching for CKO_DATA objects."""

    def test_search_by_label(self, p11_raw_session: Any) -> None:
        """Find CKO_DATA by CKA_LABEL."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"searchable",
                CKA_TOKEN: False,
            },
        )
        try:
            found = _search_by_label(rs.raw, rs.sh, label)
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_search_by_application(self, p11_raw_session: Any) -> None:
        """Find CKO_DATA by CKA_APPLICATION."""
        rs = p11_raw_session
        app_name = _unique_label("app")
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_APPLICATION: app_name,
                CKA_VALUE: b"app-data",
                CKA_TOKEN: False,
            },
        )
        try:
            tmpl = template(
                attr_ulong(CKA_CLASS, CKO_DATA),
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
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"class-search",
                CKA_TOKEN: False,
            },
        )
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_DATA))
            found = find_objects(rs.raw, rs.sh, tmpl)
            labels = []
            for fh in found:
                attrs = read_attributes(rs.raw, rs.sh, fh, [CKA_LABEL])
                labels.append(_read_str(attrs, CKA_LABEL))
            assert label in labels
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_search_no_match_returns_empty(self, p11_raw_session: Any) -> None:
        """Search for non-existent label returns empty list."""
        rs = p11_raw_session
        tmpl = template(
            attr_ulong(CKA_CLASS, CKO_DATA),
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
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: payload,
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])
            assert attrs[CKA_VALUE] == payload
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_read_label_and_application(self, p11_raw_session: Any) -> None:
        """CKA_LABEL and CKA_APPLICATION are readable."""
        rs = p11_raw_session
        label = _unique_label()
        app = "test-app"
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_APPLICATION: app,
                CKA_VALUE: b"meta",
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_LABEL, CKA_APPLICATION])
            assert _read_str(attrs, CKA_LABEL) == label
            assert _read_str(attrs, CKA_APPLICATION) == app
        finally:
            destroy_quietly(rs.raw, rs.sh, h)

    def test_object_class_is_data(self, p11_raw_session: Any) -> None:
        """CKA_CLASS reports CKO_DATA."""
        rs = p11_raw_session
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: _unique_label(),
                CKA_VALUE: b"class-check",
                CKA_TOKEN: False,
            },
        )
        try:
            attrs = read_attributes(rs.raw, rs.sh, h, [CKA_CLASS])
            assert attrs[CKA_CLASS] == CKO_DATA
        finally:
            destroy_quietly(rs.raw, rs.sh, h)


class TestDataObjectDestroy:
    """Test CKO_DATA object destruction."""

    def test_destroy_removes_object(self, p11_raw_session: Any) -> None:
        """Destroyed CKO_DATA no longer appears in search."""
        rs = p11_raw_session
        label = _unique_label()
        h = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"destroy-me",
                CKA_TOKEN: False,
            },
        )
        rs.raw.C_DestroyObject(rs.sh, h)
        found = _search_by_label(rs.raw, rs.sh, label)
        assert len(found) == 0

    def test_create_destroy_multiple(self, p11_raw_session: Any) -> None:
        """Create several CKO_DATA objects, destroy them all, verify clean."""
        rs = p11_raw_session
        labels = [_unique_label() for _ in range(5)]
        handles = []
        for lbl in labels:
            h = create_object(
                rs.raw,
                rs.sh,
                {
                    CKA_CLASS: CKO_DATA,
                    CKA_LABEL: lbl,
                    CKA_VALUE: b"multi",
                    CKA_TOKEN: False,
                },
            )
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
        """CKO_DATA with TOKEN=True persists across sessions.

        NSS deviation: NSS slot 1 (Certificate DB) rejects token CKO_DATA
        objects with CKR_ATTRIBUTE_VALUE_INVALID -- the slot does not support
        persistent storage of generic data objects.
        Tracked in docs/module-issues.md under NSS.
        """
        rs = p11_raw_session
        skip_if_token_write_protected(rs.raw, rs.slot_id)
        pin_bytes = get_pin_bytes(p11_config)
        label = _unique_label("persist")
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        # Session 1: create token object
        sh1 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes:
            login_user(rs.raw, sh1, CKU_USER, pin_bytes)
        try:
            try:
                create_object(
                    rs.raw,
                    sh1,
                    {
                        CKA_CLASS: CKO_DATA,
                        CKA_LABEL: label,
                        CKA_VALUE: b"persistent-data",
                        CKA_TOKEN: True,
                    },
                )
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    {CKR_ATTRIBUTE_VALUE_INVALID},
                    "NSS rejects token=True CKO_DATA objects with CKR_ATTRIBUTE_VALUE_INVALID "
                    "(slot does not support persistent generic data object storage)",
                )
                raise
        finally:
            close_session_quietly(rs.raw, sh1)

        # Session 2: find and verify
        sh2 = raw_open_session(rs.raw, rs.slot_id, flags)
        if pin_bytes:
            login_user(rs.raw, sh2, CKU_USER, pin_bytes)
        try:
            found = _search_by_label(rs.raw, sh2, label)
            assert len(found) >= 1
            attrs = read_attributes(rs.raw, sh2, found[0], [CKA_VALUE])
            assert attrs[CKA_VALUE] == b"persistent-data"
        finally:
            # Cleanup: destroy all matching objects
            for fh in _search_by_label(rs.raw, sh2, label):
                rs.raw.C_DestroyObject(sh2, fh)
            close_session_quietly(rs.raw, sh2)
