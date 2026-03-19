"""Duplicate label handling tests.

Verifies that PKCS#11 modules handle multiple objects with the same
CKA_LABEL correctly — search should return all matching objects.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt


def _unique_label(prefix: str = "dup") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestDuplicateLabels:
    """Test that duplicate labels are handled correctly."""

    def test_two_keys_same_label(self, p11_session: Any) -> None:
        """Two AES keys with the same label — search returns both."""
        label = _unique_label()
        p11_session.generate_key(KeyType.AES, 128, label=label)
        p11_session.generate_key(KeyType.AES, 256, label=label)

        found = list(p11_session.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 2, f"Expected >=2 objects with label '{label}', got {len(found)}"

    def test_data_objects_same_label(self, p11_session: Any) -> None:
        """Two CKO_DATA objects with the same label — both findable."""
        label = _unique_label()
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"first",
                Attribute.TOKEN: False,
            }
        )
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"second",
                Attribute.TOKEN: False,
            }
        )

        found = list(
            p11_session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
        )
        assert len(found) >= 2

        values = sorted(obj[Attribute.VALUE] for obj in found)
        assert b"first" in values
        assert b"second" in values

    def test_different_types_same_label(self, p11_session: Any) -> None:
        """AES key and CKO_DATA with the same label — both findable."""
        label = _unique_label()
        p11_session.generate_key(KeyType.AES, 128, label=label)
        p11_session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: b"data-obj",
                Attribute.TOKEN: False,
            }
        )

        # Search by label only (no class filter)
        found = list(p11_session.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 2

    def test_destroy_one_of_duplicates(self, p11_session: Any) -> None:
        """Destroying one of two same-label objects leaves the other."""
        label = _unique_label()
        k1 = p11_session.generate_key(KeyType.AES, 128, label=label)
        p11_session.generate_key(KeyType.AES, 256, label=label)

        k1.destroy()

        found = list(p11_session.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 1
