"""PKCS#11 v3.0 mechanism object tests.

CKO_MECHANISM objects provide information beyond CK_MECHANISM_INFO, including
supported parameter sets.  These are read-only token objects defined in
PKCS#11 v3.0 and later.  Tests auto-skip on v2.40 modules and skip gracefully
when no mechanism objects are present.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, Mechanism, ObjectClass
from pkcs11.exceptions import (
    AttributeReadOnly,
    AttributeTypeInvalid,
    PKCS11Error,
)

pytestmark = [pytest.mark.requires_v30, pytest.mark.object]


class TestMechanismObjects:
    """Tests for CKO_MECHANISM object enumeration (PKCS#11 v3.0+)."""

    def test_mechanism_object_enumeration(self, p11_session: Any) -> None:
        """Enumerate CKO_MECHANISM objects without error."""
        try:
            mechs = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.MECHANISM})
            )
        except PKCS11Error:
            pytest.xfail("Module does not support CKO_MECHANISM enumeration")
        assert isinstance(mechs, list)

    def test_mechanism_objects_have_mechanism_type(
        self, p11_session: Any
    ) -> None:
        """Each CKO_MECHANISM object has a readable CKA_MECHANISM_TYPE."""
        try:
            mechs = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.MECHANISM})
            )
        except PKCS11Error:
            pytest.xfail("Module does not support CKO_MECHANISM enumeration")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        for obj in mechs:
            try:
                mtype = obj[Attribute.MECHANISM_TYPE]
                assert isinstance(mtype, int), (
                    f"Expected int MECHANISM_TYPE, got {type(mtype)}"
                )
            except PKCS11Error:
                pytest.xfail(
                    "Cannot read CKA_MECHANISM_TYPE from mechanism object"
                )

    def test_mechanism_type_is_known(self, p11_session: Any) -> None:
        """CKA_MECHANISM_TYPE values correspond to known mechanisms or vendor range."""
        try:
            mechs = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.MECHANISM})
            )
        except PKCS11Error:
            pytest.xfail("Module does not support CKO_MECHANISM enumeration")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        known = {int(m) for m in Mechanism}
        vendor_base = 0x80000000
        for obj in mechs:
            try:
                mtype = int(obj[Attribute.MECHANISM_TYPE])
            except PKCS11Error:
                continue
            if mtype < vendor_base:
                assert mtype in known, (
                    f"Unknown non-vendor mechanism type 0x{mtype:08X}"
                )

    def test_mechanism_objects_are_read_only(self, p11_session: Any) -> None:
        """CKO_MECHANISM objects reject C_SetAttributeValue."""
        try:
            mechs = list(
                p11_session.get_objects({Attribute.CLASS: ObjectClass.MECHANISM})
            )
        except PKCS11Error:
            pytest.xfail("Module does not support CKO_MECHANISM enumeration")
        if not mechs:
            pytest.skip("No CKO_MECHANISM objects present")
        obj = mechs[0]
        # Attempt to modify CKA_MECHANISM_TYPE — should be rejected
        with pytest.raises(
            (AttributeReadOnly, AttributeTypeInvalid, PKCS11Error)
        ):
            obj[Attribute.MECHANISM_TYPE] = int(Mechanism.AES_KEY_GEN)
