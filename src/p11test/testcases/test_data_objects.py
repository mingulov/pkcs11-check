"""CKO_DATA object tests.

Verifies create, search by label/application, read value, and destroy
of generic data objects (CKO_DATA / ObjectClass.DATA).

CKO_DATA is the simplest PKCS#11 object type — no cryptographic
operations, just opaque byte storage with metadata.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.keymgmt


def _unique_label(prefix: str = "data") -> str:
    """Generate a unique label to avoid test interference."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestDataObjectCreate:
    """Test CKO_DATA object creation."""

    def test_create_data_object(self, p11_session: Any) -> None:
        """Can create a CKO_DATA object with label, app, and value."""
        label = _unique_label()
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.APPLICATION: "p11test",
                Attribute.VALUE: b"hello world",
                Attribute.TOKEN: False,
            }
        )
        assert obj is not None

    def test_create_data_object_empty_value(self, p11_session: Any) -> None:
        """CKO_DATA with empty VALUE is valid."""
        label = _unique_label()
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"",
                Attribute.TOKEN: False,
            }
        )
        assert obj is not None

    def test_create_data_object_large_value(self, p11_session: Any) -> None:
        """CKO_DATA with 64KB value — tests large blob storage."""
        label = _unique_label()
        big_data = bytes(range(256)) * 256  # 64KB
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: big_data,
                Attribute.TOKEN: False,
            }
        )
        stored = obj[Attribute.VALUE]
        assert stored == big_data


class TestDataObjectSearch:
    """Test searching for CKO_DATA objects."""

    def test_search_by_label(self, p11_session: Any) -> None:
        """Find CKO_DATA by CKA_LABEL."""
        label = _unique_label()
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"searchable",
                Attribute.TOKEN: False,
            }
        )
        found = list(
            p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
        )
        assert len(found) >= 1

    def test_search_by_application(self, p11_session: Any) -> None:
        """Find CKO_DATA by CKA_APPLICATION."""
        app_name = _unique_label("app")
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.APPLICATION: app_name,
                Attribute.VALUE: b"app-data",
                Attribute.TOKEN: False,
            }
        )
        found = list(
            p11_session.get_objects(
                {Attribute.CLASS: ObjectClass.DATA, Attribute.APPLICATION: app_name}
            )
        )
        assert len(found) >= 1

    def test_search_by_class_only(self, p11_session: Any) -> None:
        """Search for all CKO_DATA objects returns at least the one we created."""
        label = _unique_label()
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"class-search",
                Attribute.TOKEN: False,
            }
        )
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA}))
        labels = [obj[Attribute.LABEL] for obj in found]
        assert label in labels

    def test_search_no_match_returns_empty(self, p11_session: Any) -> None:
        """Search for non-existent label returns empty list."""
        found = list(
            p11_session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "does-not-exist-" + uuid.uuid4().hex,
                }
            )
        )
        assert found == []


class TestDataObjectReadValue:
    """Test reading CKA_VALUE from CKO_DATA objects."""

    def test_read_value_matches_written(self, p11_session: Any) -> None:
        """CKA_VALUE read matches what was written."""
        label = _unique_label()
        payload = b"\x00\x01\x02\xff" * 100
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: payload,
                Attribute.TOKEN: False,
            }
        )
        assert obj[Attribute.VALUE] == payload

    def test_read_label_and_application(self, p11_session: Any) -> None:
        """CKA_LABEL and CKA_APPLICATION are readable."""
        label = _unique_label()
        app = "test-app"
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.APPLICATION: app,
                Attribute.VALUE: b"meta",
                Attribute.TOKEN: False,
            }
        )
        assert obj[Attribute.LABEL] == label
        assert obj[Attribute.APPLICATION] == app

    def test_object_class_is_data(self, p11_session: Any) -> None:
        """CKA_CLASS reports ObjectClass.DATA."""
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: _unique_label(),
                Attribute.VALUE: b"class-check",
                Attribute.TOKEN: False,
            }
        )
        assert obj[Attribute.CLASS] == ObjectClass.DATA


class TestDataObjectDestroy:
    """Test CKO_DATA object destruction."""

    def test_destroy_removes_object(self, p11_session: Any) -> None:
        """Destroyed CKO_DATA no longer appears in search."""
        label = _unique_label()
        obj = p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"destroy-me",
                Attribute.TOKEN: False,
            }
        )
        obj.destroy()
        found = list(
            p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
        )
        assert len(found) == 0

    def test_create_destroy_multiple(self, p11_session: Any) -> None:
        """Create several CKO_DATA objects, destroy them all, verify clean."""
        labels = [_unique_label() for _ in range(5)]
        objs = []
        for lbl in labels:
            obj = p11_session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: lbl,
                    Attribute.VALUE: b"multi",
                    Attribute.TOKEN: False,
                }
            )
            objs.append(obj)

        for obj in objs:
            obj.destroy()

        for lbl in labels:
            found = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: lbl})
            )
            assert len(found) == 0


class TestDataObjectToken:
    """Test CKO_DATA with TOKEN=True (persistent)."""

    def test_token_data_object_survives_session(self, p11_module: Any, p11_config: Any) -> None:
        """CKO_DATA with TOKEN=True persists across sessions."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else pin
        label = _unique_label("persist")

        # Session 1: create
        with token.open(rw=True, user_pin=pin_str) as session:
            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"persistent-data",
                    Attribute.TOKEN: True,
                }
            )

        # Session 2: find and verify
        try:
            with token.open(rw=True, user_pin=pin_str) as session:
                found = list(
                    session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
                )
                assert len(found) >= 1
                assert found[0][Attribute.VALUE] == b"persistent-data"
        finally:
            # Cleanup: destroy in session 3
            try:
                with token.open(rw=True, user_pin=pin_str) as session:
                    for obj in session.get_objects(
                        {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
                    ):
                        obj.destroy()
            except PKCS11Error:
                pass
