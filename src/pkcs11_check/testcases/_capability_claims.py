"""Claim-layer verdict for advertised-but-refused (mechanism, operation) roundtrips.

The test_mech_* registry suites are the per-(mechanism, operation) claim layer:
their roundtrip IS the canonical operation for the advertised capability
(C_GetMechanismList + CK_MECHANISM_INFO flags). A clean refusal of that
roundtrip is classified here:

- CKR_OPERATION_NOT_VALIDATED  the v3.2 spec-sanctioned validation-policy
  refusal; does not contradict the advertisement -> the test PASSES and a
  compliance note records the policy refusal (and whether the token exposes
  CKO_VALIDATION objects -- capability-based, no provider identity).
- any other clean CKR          advertised but not operational -> xfail with
  the shared not_operational_reason wording. No CKR allowlist (model
  positive-op row; same rationale as _operability.classify_kat_clean_error).
- non-CKR exception            wrong-output assert or harness bug -> re-raise.

Design: docs/superpowers/specs/2026-06-10-advertised-capability-honesty-design.md.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import compliance
from pkcs11_check.compliance import ComplianceLevel
from pkcs11_check.raw.pack import attr_ulong, template
from pkcs11_check.raw.recipes import find_objects
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKO_VALIDATION,
    CKR_OPERATION_NOT_VALIDATED,
)
from pkcs11_check.testcases._operability import not_operational_reason

# Cached once per process: whether the token exposes CKO_VALIDATION objects
# (None = the token refused enumeration of that class).
_VALIDATION_CACHE: dict[str, bool | None] = {}


def reset_validation_object_cache() -> None:
    """Test hook: forget the cached CKO_VALIDATION presence."""
    _VALIDATION_CACHE.clear()


def _validation_objects_present(rs: Any) -> bool | None:
    if "present" not in _VALIDATION_CACHE:
        try:
            tmpl = template(attr_ulong(CKA_CLASS, CKO_VALIDATION))
            _VALIDATION_CACHE["present"] = bool(find_objects(rs.raw, rs.sh, tmpl))
        except AssertionError:
            _VALIDATION_CACHE["present"] = None
    return _VALIDATION_CACHE["present"]


def claim_refusal_passes(exc: AssertionError, rs: Any, *, probe_key: str) -> bool:
    """Classify a clean refusal of an advertised (mechanism, operation) roundtrip.

    Returns True for the spec-sanctioned validation-policy refusal
    (CKR_OPERATION_NOT_VALIDATED): the caller must end the test immediately
    (``return``) so it records as PASS; the compliance note carries the
    evidence. Otherwise xfails (any clean CKR) or re-raises (non-CKR).
    """
    rv = getattr(exc, "rv", None)
    if not isinstance(exc, CkrAssertionError) or rv is None:
        raise exc
    if rv == int(CKR_OPERATION_NOT_VALIDATED):
        present = _validation_objects_present(rs)
        compliance.note(
            f"{probe_key}: refused via sanctioned CKR_OPERATION_NOT_VALIDATED "
            f"(validation-policy refusal; CKO_VALIDATION objects present: {present})",
            ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED / Sec. 4.15",
        )
        return True
    pytest.xfail(not_operational_reason(probe_key, ckr_name(rv)))
