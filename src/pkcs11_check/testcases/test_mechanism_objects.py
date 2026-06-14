"""PKCS#11 v3.0 mechanism object tests.

CKO_MECHANISM objects provide information beyond CK_MECHANISM_INFO, including
supported parameter sets.  These are read-only token objects defined in
PKCS#11 v3.0 and later.  Tests auto-skip on v2.40 modules and skip gracefully
when no mechanism objects are present.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import template_from_dict
from pkcs11_check.raw.recipes import (
    find_objects,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_MECHANISM_TYPE,
    CKM_AES_KEY_GEN,
    CKO_MECHANISM,
)

pytestmark = [pytest.mark.object]


class TestMechanismObjects:
    """Tests for CKO_MECHANISM object enumeration (PKCS#11 v3.0+)."""

    def test_mechanism_object_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_MECHANISM objects without error."""
        rs = p11_raw_session
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_MECHANISM})
            mechs = find_objects(rs.raw, rs.sh, tmpl)
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_MECHANISM enumeration: {e}")
        assert isinstance(mechs, list)

    def test_mechanism_objects_have_mechanism_type(self, p11_raw_session: Any) -> None:
        """Each CKO_MECHANISM object has a readable CKA_MECHANISM_TYPE."""
        rs = p11_raw_session
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_MECHANISM})
            mechs = find_objects(rs.raw, rs.sh, tmpl)
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_MECHANISM enumeration: {e}")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        for obj_h in mechs:
            try:
                attrs = read_attributes(rs.raw, rs.sh, obj_h, [CKA_MECHANISM_TYPE])
                mtype = attrs[CKA_MECHANISM_TYPE]
                assert isinstance(mtype, int), f"Expected int MECHANISM_TYPE, got {type(mtype)}"
            except AssertionError as e:
                classify(
                    "not_operational",
                    kind="metadata",
                    label="CKO_MECHANISM:CKA_MECHANISM_TYPE",
                    operation="C_GetAttributeValue",
                    summary=f"Cannot read CKA_MECHANISM_TYPE from mechanism object: {e}",
                )

    def test_mechanism_type_is_known(self, p11_raw_session: Any) -> None:
        """CKA_MECHANISM_TYPE values correspond to known mechanisms or vendor range."""
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

        rs = p11_raw_session
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_MECHANISM})
            mechs = find_objects(rs.raw, rs.sh, tmpl)
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_MECHANISM enumeration: {e}")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        known = set(MECHANISM_NAMES.keys())
        vendor_base = 0x80000000
        for obj_h in mechs:
            try:
                attrs = read_attributes(rs.raw, rs.sh, obj_h, [CKA_MECHANISM_TYPE])
                mtype = attrs[CKA_MECHANISM_TYPE]
            except AssertionError:
                continue
            if isinstance(mtype, int) and mtype < vendor_base and mtype not in known:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    f"Module exposes CKO_MECHANISM with unknown type 0x{mtype:08X} "
                    "-- may be a newer spec mechanism not in python-pkcs11 enum",
                    ComplianceLevel.VENDOR,
                )

    def test_mechanism_objects_are_read_only(self, p11_raw_session: Any) -> None:
        """CKO_MECHANISM objects reject C_SetAttributeValue."""
        rs = p11_raw_session
        try:
            tmpl = template_from_dict({CKA_CLASS: CKO_MECHANISM})
            mechs = find_objects(rs.raw, rs.sh, tmpl)
        except AssertionError as e:
            pytest.skip(f"Module does not support CKO_MECHANISM enumeration: {e}")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        obj_h = mechs[0]
        # Attempt to modify CKA_MECHANISM_TYPE - should be rejected
        try:
            set_attributes(rs.raw, rs.sh, obj_h, {CKA_MECHANISM_TYPE: CKM_AES_KEY_GEN})
            # If we get here, module silently accepted the write
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module allows C_SetAttributeValue on CKO_MECHANISM - "
                "spec says these should be read-only",
                ComplianceLevel.VENDOR,
            )
        except AssertionError:
            pass  # Expected: module correctly rejects write
