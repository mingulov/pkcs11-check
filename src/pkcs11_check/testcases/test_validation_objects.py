"""PKCS#11 v3.2 validation object tests.

CKO_VALIDATION objects describe third-party validations such as FIPS or
Common Criteria certifications.  These are read-only token objects defined
in PKCS#11 v3.2.  Most modules will not have validation objects, so tests
skip gracefully when none are present.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import attr_ulong, template
from pkcs11_check.raw.recipes import find_objects, read_attributes, set_attributes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_VALIDATION_AUTHORITY_TYPE,
    CKA_VALIDATION_LEVEL,
    CKA_VALIDATION_MODULE_ID,
    CKA_VALIDATION_TYPE,
    CKO_VALIDATION,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKV_AUTHORITY_TYPE_COMMON_CRITERIA,
    CKV_AUTHORITY_TYPE_NIST_CMVP,
    CKV_AUTHORITY_TYPE_UNSPECIFIED,
    CKV_TYPE_FIRMWARE,
    CKV_TYPE_HARDWARE,
    CKV_TYPE_HYBRID,
    CKV_TYPE_SOFTWARE,
    CKV_TYPE_UNSPECIFIED,
)
from pkcs11_check.testcases.conftest import reject_or_classify

pytestmark = [pytest.mark.object]

# Known CKV_TYPE values
_KNOWN_VALIDATION_TYPES = {
    CKV_TYPE_UNSPECIFIED,
    CKV_TYPE_SOFTWARE,
    CKV_TYPE_HARDWARE,
    CKV_TYPE_FIRMWARE,
    CKV_TYPE_HYBRID,
}

# Known CKV_AUTHORITY_TYPE values
_KNOWN_AUTHORITY_TYPES = {
    CKV_AUTHORITY_TYPE_UNSPECIFIED,
    CKV_AUTHORITY_TYPE_NIST_CMVP,
    CKV_AUTHORITY_TYPE_COMMON_CRITERIA,
}


def _find_validation_objects(raw: Any, sh: int) -> list[int]:
    """Find CKO_VALIDATION objects, surfacing typed enumeration failures."""
    try:
        tmpl = template(attr_ulong(CKA_CLASS, CKO_VALIDATION))
        return find_objects(raw, sh, tmpl)
    except CkrAssertionError as exc:
        reject_or_classify(exc, (), label="CKO_VALIDATION enumeration", kind="metadata")
        raise


class TestValidationObjects:
    """Tests for CKO_VALIDATION object enumeration (PKCS#11 v3.2+)."""

    def test_validation_object_enumeration(self, p11_raw_session: Any) -> None:
        """Enumerate CKO_VALIDATION objects without error."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        assert isinstance(validations, list)

    def test_validation_type_is_known(self, p11_raw_session: Any) -> None:
        """CKA_VALIDATION_TYPE values are known types or vendor-defined."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        vendor_base = 0x80000000
        for h in validations:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALIDATION_TYPE])
                vtype = attrs[CKA_VALIDATION_TYPE]
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_VALIDATION:CKA_VALIDATION_TYPE read",
                    kind="metadata",
                )
                raise
            if vtype < vendor_base:
                assert vtype in _KNOWN_VALIDATION_TYPES, (
                    f"Unknown non-vendor validation type 0x{vtype:08X}"
                )

    def test_validation_level_is_readable(self, p11_raw_session: Any) -> None:
        """CKA_VALIDATION_LEVEL is a readable unsigned integer."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        for h in validations:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALIDATION_LEVEL])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_VALIDATION:CKA_VALIDATION_LEVEL read",
                    kind="metadata",
                )
                raise
            level = attrs[CKA_VALIDATION_LEVEL]
            assert isinstance(level, int), f"Expected int VALIDATION_LEVEL, got {type(level)}"

    def test_validation_authority_type_is_known(self, p11_raw_session: Any) -> None:
        """CKA_VALIDATION_AUTHORITY_TYPE is a known authority or vendor."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        vendor_base = 0x80000000
        for h in validations:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALIDATION_AUTHORITY_TYPE])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_VALIDATION:CKA_VALIDATION_AUTHORITY_TYPE read",
                    kind="metadata",
                )
                raise
            if CKA_VALIDATION_AUTHORITY_TYPE not in attrs:
                continue  # audit-ok: optional attribute is absent
            auth = attrs[CKA_VALIDATION_AUTHORITY_TYPE]
            if auth < vendor_base:
                assert auth in _KNOWN_AUTHORITY_TYPES, f"Unknown authority type 0x{auth:08X}"

    def test_validation_module_id_is_string(self, p11_raw_session: Any) -> None:
        """CKA_VALIDATION_MODULE_ID is a readable UTF-8 string if present."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        for h in validations:
            try:
                attrs = read_attributes(rs.raw, rs.sh, h, [CKA_VALIDATION_MODULE_ID])
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (),
                    label="CKO_VALIDATION:CKA_VALIDATION_MODULE_ID read",
                    kind="metadata",
                )
                raise
            if CKA_VALIDATION_MODULE_ID not in attrs:
                continue  # audit-ok: optional attribute is absent
            mod_id = attrs[CKA_VALIDATION_MODULE_ID]
            assert isinstance(mod_id, (str, bytes)), (
                f"Expected str/bytes MODULE_ID, got {type(mod_id)}"
            )

    def test_validation_objects_are_read_only(self, p11_raw_session: Any) -> None:
        """CKO_VALIDATION objects reject C_SetAttributeValue."""
        rs = p11_raw_session
        validations = _find_validation_objects(rs.raw, rs.sh)
        if not validations:
            pytest.skip("No CKO_VALIDATION objects present")
        h = validations[0]
        try:
            set_attributes(
                rs.raw,
                rs.sh,
                h,
                {CKA_VALIDATION_TYPE: CKV_TYPE_UNSPECIFIED},
            )
            classify(
                "self_contradiction",
                kind="policy",
                label="CKO_VALIDATION:read-only",
                operation="C_SetAttributeValue",
                summary="Module accepted C_SetAttributeValue on CKO_VALIDATION",
            )
        except CkrAssertionError as exc:
            reject_or_classify(
                exc,
                (CKR_ATTRIBUTE_READ_ONLY, CKR_ACTION_PROHIBITED),
                label="write read-only CKO_VALIDATION",
                kind="policy",
            )
