"""Honorable empty/minimal template-count edges: ulCount=0 must not crash.

PKCS#11 calls that take (pTemplate, ulCount) must handle ulCount=0 (an empty
request) gracefully -- never crash. This is a *valid* input (an attacker cannot
be blamed: zero attributes is a legal request), so a crash here is unambiguously
a module bug. Un-honorable huge counts are deliberately NOT tested (they would
over-read the caller's own short array -> harness-induced UB).
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CK_OBJECT_HANDLE, CK_ULONG, CKR_OK
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.security


def test_get_attribute_value_zero_count_no_crash(p11_raw_session: Any) -> None:
    """C_GetAttributeValue with ulCount=0 on a valid object must not crash."""
    rs = p11_raw_session
    # A handle that exists: find any object; if none, skip (no object to query).
    rs.raw.C_FindObjectsInit(rs.sh, None, 0)
    found = (CK_OBJECT_HANDLE * 1)()
    n = CK_ULONG(0)
    rs.raw.C_FindObjects(rs.sh, found, 1, byref(n))
    rs.raw.C_FindObjectsFinal(rs.sh)
    if n.value < 1:
        pytest.skip("no object available to query")
    obj = found[0]
    # ulCount=0, NULL template: a valid empty request.
    rv = rs.raw.C_GetAttributeValue(rs.sh, obj, None, 0)
    # No crash => we reached here. Any rv is acceptable; CKR_OK is the spec-normal.
    if rv != CKR_OK:
        classify_negative_rv(rv, (), label="C_GetAttributeValue(ulCount=0)", allow_ok=True)


def test_find_objects_init_zero_count_no_crash(p11_raw_session: Any) -> None:
    """C_FindObjectsInit with an empty (ulCount=0) template must not crash."""
    rs = p11_raw_session
    rv = rs.raw.C_FindObjectsInit(rs.sh, None, 0)  # find-all
    if rv == CKR_OK:
        rs.raw.C_FindObjectsFinal(rs.sh)
    # Reaching here without a crash is the assertion; allow any clean rv.
    if rv != CKR_OK:
        classify_negative_rv(rv, (), label="C_FindObjectsInit(ulCount=0)", allow_ok=True)
