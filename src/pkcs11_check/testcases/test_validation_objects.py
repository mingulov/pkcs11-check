"""PKCS#11 v3.1 validation object tests.

CKO_VALIDATION objects describe third-party validations such as FIPS or
Common Criteria certifications.  These are read-only token objects defined
in PKCS#11 v3.1.  Most modules will not have validation objects, so tests
skip gracefully when none are present.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, ObjectClass
from pkcs11.constants import ValidationAuthorityType, ValidationType
from pkcs11.exceptions import (
    AttributeReadOnly,
    AttributeTypeInvalid,
    PKCS11Error,
)

pytestmark = [pytest.mark.requires_v30, pytest.mark.object]


class TestValidationObjects:
    """Tests for CKO_VALIDATION object enumeration (PKCS#11 v3.1+)."""

    def test_validation_object_enumeration(self, p11_session: Any) -> None:
        """Enumerate CKO_VALIDATION objects without error."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        assert isinstance(validations, list)

    def test_validation_type_is_known(self, p11_session: Any) -> None:
        """CKA_VALIDATION_TYPE values are known types or vendor-defined."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        known = {int(v) for v in ValidationType}
        vendor_base = 0x80000000
        for obj in validations:
            try:
                vtype = int(obj[Attribute.VALIDATION_TYPE])
            except PKCS11Error:
                pytest.xfail(
                    "Cannot read CKA_VALIDATION_TYPE from validation object"
                )
            if vtype < vendor_base:
                assert vtype in known, (
                    f"Unknown non-vendor validation type 0x{vtype:08X}"
                )

    def test_validation_level_is_readable(self, p11_session: Any) -> None:
        """CKA_VALIDATION_LEVEL is a readable unsigned integer."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        for obj in validations:
            try:
                level = obj[Attribute.VALIDATION_LEVEL]
                assert isinstance(level, int), (
                    f"Expected int VALIDATION_LEVEL, got {type(level)}"
                )
            except PKCS11Error:
                pytest.xfail(
                    "Cannot read CKA_VALIDATION_LEVEL from validation object"
                )

    def test_validation_authority_type_is_known(
        self, p11_session: Any
    ) -> None:
        """CKA_VALIDATION_AUTHORITY_TYPE is a known authority or vendor."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        known = {int(v) for v in ValidationAuthorityType}
        vendor_base = 0x80000000
        for obj in validations:
            try:
                auth = int(obj[Attribute.VALIDATION_AUTHORITY_TYPE])
            except PKCS11Error:
                # Not all modules expose this optional attribute
                continue
            if auth < vendor_base:
                assert auth in known, (
                    f"Unknown authority type 0x{auth:08X}"
                )

    def test_validation_module_id_is_string(self, p11_session: Any) -> None:
        """CKA_VALIDATION_MODULE_ID is a readable UTF-8 string if present."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        for obj in validations:
            try:
                mod_id = obj[Attribute.VALIDATION_MODULE_ID]
                assert isinstance(mod_id, (str, bytes)), (
                    f"Expected str/bytes MODULE_ID, got {type(mod_id)}"
                )
            except PKCS11Error:
                # Optional attribute — some modules may not expose it
                continue

    def test_validation_objects_are_read_only(
        self, p11_session: Any
    ) -> None:
        """CKO_VALIDATION objects reject C_SetAttributeValue."""
        try:
            validations = list(
                p11_session.get_objects(
                    {Attribute.CLASS: ObjectClass.VALIDATION}
                )
            )
        except PKCS11Error:
            pytest.xfail(
                "Module does not support CKO_VALIDATION enumeration"
            )
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        obj = validations[0]
        with pytest.raises(
            (AttributeReadOnly, AttributeTypeInvalid, PKCS11Error)
        ):
            obj[Attribute.VALIDATION_TYPE] = int(ValidationType.UNSPECIFIED)
