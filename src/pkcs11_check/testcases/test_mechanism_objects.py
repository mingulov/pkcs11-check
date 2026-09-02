"""PKCS#11 mechanism object tests.

CKO_MECHANISM objects provide information beyond CK_MECHANISM_INFO, including
supported parameter sets.  These are read-only token objects defined in
PKCS#11 v2.40 and later. Tests skip gracefully when no mechanism objects are
present.
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
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_MECHANISM_TYPE,
    CKM_AES_KEY_GEN,
    CKO_MECHANISM,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
)
from pkcs11_check.testcases.conftest import reject_or_classify

pytestmark = pytest.mark.object


def _mechanism_objects(rs: Any) -> list[int]:
    try:
        return find_objects(
            rs.raw,
            rs.sh,
            template_from_dict({CKA_CLASS: CKO_MECHANISM}),
        )
    except CkrAssertionError as exc:
        reject_or_classify(exc, (), label="CKO_MECHANISM enumeration", kind="metadata")
        raise


def _mechanism_type(rs: Any, handle: int) -> int:
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_MECHANISM_TYPE])
    except CkrAssertionError as exc:
        reject_or_classify(
            exc,
            (),
            label="CKO_MECHANISM CKA_MECHANISM_TYPE read",
            kind="metadata",
        )
        raise
    value = attrs[CKA_MECHANISM_TYPE]
    assert isinstance(value, int), f"Expected int MECHANISM_TYPE, got {type(value)}"
    return value


class TestMechanismObjects:
    """Tests for CKO_MECHANISM object enumeration (PKCS#11 v2.40+)."""

    def test_mechanism_object_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_MECHANISM objects without error."""
        mechs = _mechanism_objects(p11_raw_session)
        assert isinstance(mechs, list)

    def test_mechanism_objects_have_mechanism_type(self, p11_raw_session: Any) -> None:
        """Each CKO_MECHANISM object has a readable CKA_MECHANISM_TYPE."""
        rs = p11_raw_session
        mechs = _mechanism_objects(rs)
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        for obj_h in mechs:
            _mechanism_type(rs, obj_h)

    def test_mechanism_type_is_known(self, p11_raw_session: Any) -> None:
        """CKA_MECHANISM_TYPE values correspond to known mechanisms or vendor range."""
        from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

        rs = p11_raw_session
        mechs = _mechanism_objects(rs)
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        known = set(MECHANISM_NAMES.keys())
        vendor_base = 0x80000000
        for obj_h in mechs:
            mtype = _mechanism_type(rs, obj_h)
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
        mechs = _mechanism_objects(rs)
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        obj_h = mechs[0]
        # Attempt to modify CKA_MECHANISM_TYPE - should be rejected
        try:
            set_attributes(rs.raw, rs.sh, obj_h, {CKA_MECHANISM_TYPE: CKM_AES_KEY_GEN})
            classify(
                "self_contradiction",
                kind="metadata",
                label="CKO_MECHANISM read-only policy",
                summary="Module accepted C_SetAttributeValue on read-only CKO_MECHANISM",
            )
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                (CKR_ATTRIBUTE_READ_ONLY, CKR_ACTION_PROHIBITED),
                label="write read-only CKO_MECHANISM",
                kind="metadata",
            )
