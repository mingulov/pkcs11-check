"""Duplicate label handling tests.

Verifies that PKCS#11 modules handle multiple objects with the same
CKA_LABEL correctly - search should return all matching objects.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    create_object,
    destroy_quietly,
    find_objects,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_LABEL,
    CKA_TOKEN,
    CKA_VALUE,
    CKO_DATA,
)

pytestmark = pytest.mark.keymgmt


def _unique_label(prefix: str = "dup") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


class TestDuplicateLabels:
    """Test that duplicate labels are handled correctly."""

    def test_two_keys_same_label(self, p11_raw_session: Any) -> None:
        """Two AES keys with the same label - search returns both."""
        rs = p11_raw_session
        label = _unique_label()
        k1 = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: label})
        k2 = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: label})
        try:
            found = find_objects(rs.raw, rs.sh, template_from_dict({CKA_LABEL: label}))
            assert len(found) >= 2, f"Expected >=2 objects with label '{label}', got {len(found)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, k2)

    def test_data_objects_same_label(self, p11_raw_session: Any) -> None:
        """Two CKO_DATA objects with the same label - both findable."""
        rs = p11_raw_session
        label = _unique_label()
        o1 = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"first",
                CKA_TOKEN: False,
            },
        )
        o2 = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"second",
                CKA_TOKEN: False,
            },
        )
        try:
            found = find_objects(
                rs.raw,
                rs.sh,
                template_from_dict({CKA_CLASS: CKO_DATA, CKA_LABEL: label}),
            )
            assert len(found) >= 2

            values = sorted(
                read_attributes(rs.raw, rs.sh, h, [CKA_VALUE])[CKA_VALUE] for h in found
            )
            assert b"first" in values
            assert b"second" in values
        finally:
            destroy_quietly(rs.raw, rs.sh, o1)
            destroy_quietly(rs.raw, rs.sh, o2)

    def test_different_types_same_label(self, p11_raw_session: Any) -> None:
        """AES key and CKO_DATA with the same label - both findable."""
        rs = p11_raw_session
        label = _unique_label()
        k1 = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: label})
        o1 = create_object(
            rs.raw,
            rs.sh,
            {
                CKA_CLASS: CKO_DATA,
                CKA_LABEL: label,
                CKA_VALUE: b"data-obj",
                CKA_TOKEN: False,
            },
        )
        try:
            # Search by label only (no class filter)
            found = find_objects(rs.raw, rs.sh, template_from_dict({CKA_LABEL: label}))
            assert len(found) >= 2
        finally:
            destroy_quietly(rs.raw, rs.sh, k1)
            destroy_quietly(rs.raw, rs.sh, o1)

    def test_destroy_one_of_duplicates(self, p11_raw_session: Any) -> None:
        """Destroying one of two same-label objects leaves the other."""
        rs = p11_raw_session
        label = _unique_label()
        k1 = gen_aes_key(rs.raw, rs.sh, 128, attrs={CKA_LABEL: label})
        k2 = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_LABEL: label})
        try:
            destroy_quietly(rs.raw, rs.sh, k1)
            found = find_objects(rs.raw, rs.sh, template_from_dict({CKA_LABEL: label}))
            assert len(found) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, k2)
