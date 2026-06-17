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

Design: advertised-capability-honesty model (see docs/architecture.md).
"""

from __future__ import annotations

import inspect
from typing import Any, Literal

from pkcs11_check import compliance
from pkcs11_check.classification import classify, xfail_as
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

# Cached once per process: successful enumeration results keyed by "present".
# CKR refusals are NOT cached (a later clean-session probe may succeed).
_VALIDATION_CACHE: dict[str, str] = {}


def reset_validation_object_cache() -> None:
    """Test hook: forget the cached CKO_VALIDATION presence."""
    _VALIDATION_CACHE.clear()


def _enclosing_test_qualname() -> str:
    """Walk the stack outward to the nearest enclosing ``test_*`` frame.

    ``claim_refusal_passes`` is often called from inside a helper (e.g.
    ``_digest_or_xfail``, ``_run_asymmetric_sign_kat``) rather than directly
    from the test body. The compliance note must attribute to the test, not
    the helper, so we skip our own frame and search outward for the first
    frame whose function name starts with ``test_``. Falls back to the
    immediate caller's qualname if none is found within a sane bound.

    Failure modes: if a helper is itself named ``test_*`` it wins the walk
    before the real test frame; non-test callers (e.g. unit tests of this
    module) fall back to the immediate caller's qualname.
    """
    frame = inspect.currentframe()
    try:
        # Skip this function's own frame; start at our caller (claim_refusal_passes).
        caller = frame.f_back if frame else None
        immediate = caller.f_back if caller else None
        fallback = immediate.f_code.co_qualname if immediate else ""
        cursor = immediate
        for _ in range(10):
            if cursor is None:
                break
            if cursor.f_code.co_name.startswith("test_"):
                return cursor.f_code.co_qualname
            cursor = cursor.f_back
        return fallback
    finally:
        # Release frame references to avoid reference cycles (inspect hygiene).
        del frame


def _validation_objects_present(rs: Any) -> str:
    """Return a presence description for CKO_VALIDATION objects.

    Returns:
        ``"True"``  -- at least one CKO_VALIDATION object was found.
        ``"False"`` -- enumeration succeeded but returned no objects.
        ``"unknown (CKR_*)"`` -- enumeration was refused with a CKR; NOT cached
            so a later probe on a fresh session can succeed.

    Non-CkrAssertionError exceptions (harness bugs) propagate unchanged.
    """
    if "present" in _VALIDATION_CACHE:
        return _VALIDATION_CACHE["present"]
    tmpl = template(attr_ulong(CKA_CLASS, CKO_VALIDATION))
    try:
        handles = find_objects(rs.raw, rs.sh, tmpl)
    except CkrAssertionError as exc:
        # Transient refusal -- do NOT cache so future clean-session probes work.
        return f"unknown ({ckr_name(exc.rv)})"
    # Successful enumeration: cache the outcome.
    presence = "True" if handles else "False"
    _VALIDATION_CACHE["present"] = presence
    return presence


def claim_refusal_passes(exc: AssertionError, rs: Any, *, probe_key: str) -> Literal[True]:
    """Classify a clean refusal of an advertised (mechanism, operation) roundtrip.

    Returns True for the spec-sanctioned validation-policy refusal
    (CKR_OPERATION_NOT_VALIDATED): the caller must end the test immediately
    (``return``) so it records as PASS; the compliance note carries the
    evidence. Otherwise xfails (any clean CKR) or re-raises (non-CKR).
    """
    if not isinstance(exc, CkrAssertionError):
        raise exc
    if exc.rv == int(CKR_OPERATION_NOT_VALIDATED):
        # Attribute the note to the enclosing test, not an intermediate helper.
        caller_qualname = _enclosing_test_qualname()
        presence = _validation_objects_present(rs)
        compliance.note(
            f"{probe_key}: refused via sanctioned CKR_OPERATION_NOT_VALIDATED "
            f"(validation-policy refusal; CKO_VALIDATION objects present: {presence})",
            ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.2 CKR_OPERATION_NOT_VALIDATED / Sec. 4.15",
            test_id=caller_qualname,
        )
        classify(
            "sanctioned_refusal",
            label=probe_key,
            actual=exc.rv,
            summary=(
                f"{probe_key}: refused via sanctioned CKR_OPERATION_NOT_VALIDATED "
                f"(validation-policy refusal; CKO_VALIDATION objects present: {presence})"
            ),
        )
        return True
    xfail_as(
        "not_operational",
        label=probe_key,
        actual=exc.rv,
        summary=not_operational_reason(probe_key, ckr_name(exc.rv)),
    )
