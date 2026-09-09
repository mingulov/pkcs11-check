"""C_SetAttributeValue restricted-attribute mutation tests.

Covers the four mutations that PKCS#11 forbids on a sensitive, non-extractable
secret key:
  1. Downgrading CKA_SENSITIVE from True to False (one-way: can only tighten).
  2. Upgrading CKA_EXTRACTABLE from False to True (one-way: can only tighten).
  3. Flipping CKA_PRIVATE from True to False.
  4. Mutating CKA_CLASS (always read-only after creation).

Design rule: verify the *effect*, not the return code.  For the protected
boolean attributes, CKR_OK with no observed weakening passes; a finding
requires the protection to be actually removed (re-read confirms change).
For CKA_CLASS, CKR_OK with an unchanged or unprovable effect is a visible
provider deviation, while a trusted before/after transition is a hard finding.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    ckr_name,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    gen_aes_key_or_xfail,
)

pytestmark = [pytest.mark.security]

# Reject codes expected for a CKA_CLASS mutation attempt.
_CLASS_MUTATION_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCONSISTENT,
)

_RESTRICTED_MUTATION_REJECT_RVS = _CLASS_MUTATION_REJECT_RVS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_protected_key(rs: Any) -> int:
    """Generate a sensitive, non-extractable, private AES-256 session key.

    Returns the object handle.  Skips if AES_KEY_GEN is not advertised or the
    template is cleanly rejected (genuine capability absence).
    """
    return gen_aes_key_or_xfail(
        rs,
        256,
        attrs={
            CKA_SENSITIVE: True,
            CKA_EXTRACTABLE: False,
            CKA_PRIVATE: True,
            CKA_TOKEN: False,
        },
        purpose="protected-key setup",
    )


def _set_bool(rs: Any, handle: int, attr: int, value: bool) -> int:
    """C_SetAttributeValue with a single boolean attribute; returns the raw CK_RV.

    Calls raw C_SetAttributeValue directly (not the recipe that raises on
    non-CKR_OK) so callers can inspect the rv to distinguish a clean reject
    from CKR_OK-but-no-effect.
    """
    tmpl = template(attr_bool(attr, value))
    return int(rs.raw.C_SetAttributeValue(rs.sh, handle, tmpl.ptr, tmpl.count))


def _attribute_detail(attr: int) -> dict[str, dict[str, int | str]]:
    attr_id = int(attr)
    return {"attribute": {"name": ATTR_NAMES.get(attr_id, str(attr)), "id": attr_id}}


def _record_unavailable_ckr(
    exc: CkrAssertionError,
    *,
    attr: int,
    label: str,
    mechanism: str | None,
) -> None:
    """Retain direct CKR evidence when an attribute read is unavailable."""
    classification.record_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        expected=CKR_OK,
        actual=exc.rv,
        detail=_attribute_detail(attr),
        summary=f"{label}: attribute unavailable ({ckr_name(exc.rv)})",
    )


def _read_bool(
    rs: Any,
    handle: int,
    attr: int,
    *,
    label: str | None = None,
    mechanism: str | None = "CKM_AES_KEY_GEN",
) -> Any:
    """Read a boolean attribute without conflating absence with a present value.

    ``read_attributes`` omits attributes whose value is unavailable.  The
    presence helper returns a unique sentinel for that case, while values such
    as ``False``, ``0``, empty bytes, and ``None`` remain exactly as returned so
    callers can classify malformed present values instead of treating them as
    missing.
    """
    read_label = label or f"CKA attribute 0x{int(attr):08X} readback"
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [attr])
    except CkrAssertionError as exc:
        if exc.rv in {CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID}:
            _record_unavailable_ckr(exc, attr=attr, label=read_label, mechanism=mechanism)
            return MISSING_ATTRIBUTE
        raise
    return attr_or_record(
        attrs,
        attr,
        label=read_label,
        kind="metadata",
        mechanism=mechanism,
    )


def _validate_bool(
    value: Any,
    *,
    attr: int,
    label: str,
    mechanism: str | None,
) -> tuple[bool | None, classification.Classification | None]:
    """Validate a present provider value without stopping independent operations."""
    if value is MISSING_ATTRIBUTE:
        return None, None
    if type(value) is bool:
        return (True if value is True else False), None
    return None, classification.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        expected=CKR_OK,
        detail={
            **_attribute_detail(attr),
            "expected_shape": "CK_BBOOL",
            "actual_type": type(value).__name__,
            "actual_repr": repr(value),
        },
        summary=f"{label}: present value has invalid CK_BBOOL shape ({type(value).__name__})",
    )


def _read_class(
    rs: Any,
    handle: int,
    *,
    label: str,
    mechanism: str | None,
) -> Any:
    """Read CKA_CLASS while retaining missing and direct CKR evidence."""
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [CKA_CLASS])
    except CkrAssertionError as exc:
        if exc.rv in {CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID}:
            _record_unavailable_ckr(exc, attr=CKA_CLASS, label=label, mechanism=mechanism)
            return MISSING_ATTRIBUTE
        raise
    return attr_or_record(
        attrs,
        CKA_CLASS,
        label=label,
        kind="metadata",
        mechanism=mechanism,
    )


def _validate_class(
    value: Any,
    *,
    label: str,
    mechanism: str | None,
    deferred: list[classification.Classification],
) -> int | None:
    """Validate CKA_CLASS while allowing setter and post-read evidence to proceed."""
    if value is MISSING_ATTRIBUTE:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    deferred.append(
        classification.record_as(
            "wrong_result",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            expected=CKR_OK,
            detail={
                **_attribute_detail(CKA_CLASS),
                "expected_shape": "CK_ULONG",
                "actual_type": type(value).__name__,
                "actual_repr": repr(value),
            },
            summary=(f"{label}: invalid CK_ULONG shape ({type(value).__name__})"),
        )
    )
    return None


def _class_name(value: int) -> int | str:
    """Use stable PKCS#11 names for the classes involved in this probe."""
    return {
        int(CKO_SECRET_KEY): "CKO_SECRET_KEY",
        int(CKO_DATA): "CKO_DATA",
    }.get(int(value), int(value))


def _record_class_baseline_deviation(
    *,
    value: int,
    label: str,
) -> classification.Classification | None:
    """Record an isolated class mismatch without attributing it to the setter."""
    if value == CKO_SECRET_KEY:
        return None
    return classification.record_as(
        "honest_deviation",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism="CKM_AES_KEY_GEN",
        expected=CKR_OK,
        detail={
            **_attribute_detail(CKA_CLASS),
            "expected": "CKO_SECRET_KEY",
            "actual": _class_name(value),
        },
        summary=(
            f"{label}: generated AES key reported class {_class_name(value)} "
            "instead of CKO_SECRET_KEY"
        ),
    )


def _record_class_setter_deviation(
    *,
    rv: int,
    effect: str,
    label: str,
) -> classification.Classification:
    """Record CKR_OK when the class effect is unchanged or cannot be proven."""
    return classification.record_as(
        "honest_deviation",
        kind="lifecycle",
        label=label,
        operation="C_SetAttributeValue",
        mechanism=None,
        expected=_CLASS_MUTATION_REJECT_RVS,
        actual=rv,
        detail={
            **_attribute_detail(CKA_CLASS),
            "effect": effect,
        },
        summary=(f"{label}: C_SetAttributeValue returned CKR_OK but class effect was {effect}"),
    )


def _record_setter_result(
    rv: int,
    *,
    attr: int,
    label: str,
    expected_rvs: tuple[int, ...],
) -> classification.Classification | None:
    """Record a non-OK setter result without raising before cleanup/readback."""
    if rv == CKR_OK or rv in expected_rvs:
        return None
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    return classification.record_as(
        reason,
        kind="policy" if reason == "nonspec_reject" else "metadata",
        label=label,
        operation="C_SetAttributeValue",
        mechanism=None,
        expected=expected_rvs,
        actual=rv,
        detail=_attribute_detail(attr),
        summary=(
            f"{label}: rejected with {ckr_name(rv)}; expected a restricted-attribute rejection"
        ),
    )


def _raise_deferred(records: list[classification.Classification]) -> None:
    """Raise a deferred setter/baseline result after readback and cleanup."""
    if not records:
        return
    kind_priority = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
    severity_priority = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    candidates = [record for record in records if record.outcome in {"fail", "xfail"}]
    if not candidates:
        return
    strongest = max(
        candidates,
        key=lambda record: (
            1 if record.outcome == "fail" else 0,
            kind_priority.get(record.kind or "", 0),
            severity_priority.get(record.severity, 0),
        ),
    )
    classification.raise_for_record(strongest)


def _record_baseline_deviation(
    *,
    value: bool,
    expected: bool,
    attr: int,
    label: str,
) -> classification.Classification | None:
    if value is expected:
        return None
    return classification.record_as(
        "honest_deviation",
        kind="policy",
        label=label,
        operation="C_GetAttributeValue",
        mechanism="CKM_AES_KEY_GEN",
        expected=CKR_OK,
        detail={
            **_attribute_detail(attr),
            "expected": expected,
            "actual": value,
        },
        summary=f"{label}: provider did not preserve the requested protected baseline",
    )


def _run_restricted_boolean_mutation(
    rs: Any,
    key: int,
    *,
    attr: int,
    expected_initial: bool,
    target: bool,
    label: str,
) -> None:
    """Run one restricted setter while retaining independent evidence."""
    deferred: list[classification.Classification] = []
    try:
        initial_value = _read_bool(
            rs,
            key,
            attr,
            label=f"{label}: initial readback",
            mechanism="CKM_AES_KEY_GEN",
        )
        initial: bool | None
        baseline: classification.Classification | None = None
        if initial_value is MISSING_ATTRIBUTE:
            initial = None
        else:
            initial, malformed = _validate_bool(
                initial_value,
                attr=attr,
                label=f"{label}: initial readback",
                mechanism="CKM_AES_KEY_GEN",
            )
            if malformed is not None:
                deferred.append(malformed)
            elif initial is not None:
                baseline = _record_baseline_deviation(
                    value=initial,
                    expected=expected_initial,
                    attr=attr,
                    label=f"{label}: initial readback",
                )

        rv = _set_bool(rs, key, attr, target)
        setter = _record_setter_result(
            rv,
            attr=attr,
            label=label,
            expected_rvs=_RESTRICTED_MUTATION_REJECT_RVS,
        )

        after_value = _read_bool(
            rs,
            key,
            attr,
            label=f"{label}: after readback",
            mechanism=None,
        )
        after: bool | None
        if after_value is MISSING_ATTRIBUTE:
            after = None
        else:
            after, malformed = _validate_bool(
                after_value,
                attr=attr,
                label=f"{label}: after readback",
                mechanism=None,
            )
            if malformed is not None:
                deferred.append(malformed)

        if initial is not None and after is not None and after is not initial:
            deferred.append(
                classification.record_as(
                    "self_contradiction",
                    kind="policy",
                    label=label,
                    operation="C_SetAttributeValue",
                    mechanism=None,
                    expected=_RESTRICTED_MUTATION_REJECT_RVS,
                    actual=rv,
                    detail={
                        **_attribute_detail(attr),
                        "expected": initial,
                        "actual": after,
                        "producer_operation": "C_SetAttributeValue",
                        "producer_mechanism": None,
                    },
                    summary=(
                        f"{label}: C_SetAttributeValue changed a restricted attribute "
                        f"from {initial!r} to {after!r}"
                    ),
                )
            )
        if setter is not None:
            deferred.append(setter)
        if baseline is not None:
            deferred.append(baseline)
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
    _raise_deferred(deferred)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cannot_downgrade_sensitive_to_false(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not clear CKA_SENSITIVE.

    PKCS#11 v3.2 §10.7: CKA_SENSITIVE is one-way — it can be set to True at
    creation or tightened later, but a True→False downgrade must be rejected.
    A module that removes sensitivity exposes the raw key material to extraction.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    _run_restricted_boolean_mutation(
        rs,
        key,
        attr=CKA_SENSITIVE,
        expected_initial=True,
        target=False,
        label="C_SetAttributeValue CKA_SENSITIVE->FALSE",
    )


def test_cannot_upgrade_extractable_to_true(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not set CKA_EXTRACTABLE=True.

    PKCS#11 v3.2 §10.7: CKA_EXTRACTABLE is one-way — once False it must stay
    False.  A module that allows the upgrade lets an attacker export key material.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    _run_restricted_boolean_mutation(
        rs,
        key,
        attr=CKA_EXTRACTABLE,
        expected_initial=False,
        target=True,
        label="C_SetAttributeValue CKA_EXTRACTABLE->TRUE",
    )


def test_cannot_flip_private(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not clear CKA_PRIVATE.

    CKA_PRIVATE=True means the object is accessible only after USER login.
    Downgrading it to False exposes a private key to public (unauthenticated)
    sessions — a security boundary bypass.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    _run_restricted_boolean_mutation(
        rs,
        key,
        attr=CKA_PRIVATE,
        expected_initial=True,
        target=False,
        label="C_SetAttributeValue CKA_PRIVATE->FALSE",
    )


def test_cannot_mutate_class(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not change CKA_CLASS.

    CKA_CLASS is always read-only after creation (PKCS#11 v3.2 Table 12).
    Accepting a class mutation can produce type-confused objects that bypass
    key-type enforcement in subsequent operations.  CKR_OK is a hard finding
    only when a trusted before/after read proves the mutation; unchanged or
    unprovable effect remains a visible provider deviation.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    deferred: list[classification.Classification] = []
    try:
        before_label = "C_SetAttributeValue CKA_CLASS before readback"
        after_label = "C_SetAttributeValue CKA_CLASS after readback"
        class_before_value = _read_class(
            rs,
            key,
            label=before_label,
            mechanism="CKM_AES_KEY_GEN",
        )
        class_before = _validate_class(
            class_before_value,
            label=before_label,
            mechanism="CKM_AES_KEY_GEN",
            deferred=deferred,
        )
        class_baseline: classification.Classification | None = None
        if class_before is not None:
            class_baseline = _record_class_baseline_deviation(
                value=class_before,
                label=before_label,
            )

        # Attempt to change the class from CKO_SECRET_KEY to CKO_DATA.
        # Any conformant module must reject this.
        tmpl = template(attr_ulong(CKA_CLASS, CKO_DATA))
        rv = int(rs.raw.C_SetAttributeValue(rs.sh, key, tmpl.ptr, tmpl.count))
        setter = _record_setter_result(
            rv,
            attr=CKA_CLASS,
            label="C_SetAttributeValue CKA_CLASS mutation",
            expected_rvs=_CLASS_MUTATION_REJECT_RVS,
        )

        # Read back to determine whether the operation changed the class.  Only
        # a trustworthy before->after transition can attribute an observed
        # mutation to this setter; a pre-existing CKO_DATA value is merely a
        # provider deviation in the setup/readback oracle.
        class_after_value = _read_class(
            rs,
            key,
            label=after_label,
            mechanism=None,
        )
        class_after = _validate_class(
            class_after_value,
            label=after_label,
            mechanism=None,
            deferred=deferred,
        )
        effect_proven = (
            class_before is not None and class_after is not None and class_after != class_before
        )
        effect = (
            "changed"
            if effect_proven
            else "unchanged"
            if class_before is not None and class_after is not None
            else "unproven"
        )
        if class_before is not None and class_after is not None and class_after != class_before:
            deferred.append(
                classification.record_as(
                    "self_contradiction",
                    kind="policy",
                    label="C_SetAttributeValue CKA_CLASS mutation",
                    operation="C_SetAttributeValue",
                    mechanism=None,
                    expected=_CLASS_MUTATION_REJECT_RVS,
                    actual=rv,
                    detail={
                        **_attribute_detail(CKA_CLASS),
                        "expected": _class_name(class_before),
                        "actual": _class_name(class_after),
                    },
                    summary=(
                        "C_SetAttributeValue changed read-only CKA_CLASS "
                        f"from {_class_name(class_before)} to {_class_name(class_after)}"
                    ),
                )
            )
        if setter is not None:
            deferred.append(setter)
        if rv == CKR_OK and not effect_proven:
            deferred.append(
                _record_class_setter_deviation(
                    rv=rv,
                    effect=effect,
                    label="C_SetAttributeValue CKA_CLASS mutation",
                )
            )
        if class_baseline is not None:
            deferred.append(class_baseline)
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
    _raise_deferred(deferred)
