"""C_SetAttributeValue tests - attribute mutation on existing objects.

Tests modifying CKA_LABEL, CKA_ID on keys, and verifying that
read-only attributes (CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS) are rejected.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check import classification
from pkcs11_check.classification import raise_for_record, record_as
from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, template
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    find_objects,
    read_attributes,
    set_attributes,
)
from pkcs11_check.raw.rv import CkrAssertionError, is_standard_ckr, is_vendor_defined_ckr
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_ID,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_VALUE,
    CKK_AES,
    CKK_RSA,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_GENERAL_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.conftest import (
    assert_correct,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    xfail_if_known_ckr,
)

pytestmark = pytest.mark.keymgmt

_SET_ATTR_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)


def _attribute_name(attr: int) -> str:
    names: dict[int, str] = {
        int(CKA_CLASS): "CKA_CLASS",
        int(CKA_KEY_TYPE): "CKA_KEY_TYPE",
        int(CKA_LABEL): "CKA_LABEL",
        int(CKA_ID): "CKA_ID",
        int(CKA_MODULUS): "CKA_MODULUS",
        int(CKA_VALUE): "CKA_VALUE",
    }
    return names.get(int(attr), f"0x{int(attr):08x}")


def _expected_baseline(attr: int) -> tuple[bool, Any]:
    """Return a setup baseline only where the generated object fixes its value."""
    if attr == CKA_CLASS:
        return True, CKO_SECRET_KEY
    if attr == CKA_KEY_TYPE:
        return True, CKK_AES
    return False, None


def _record_malformed_readback(
    attr: int,
    value: Any,
    *,
    label: str,
) -> classification.Classification | None:
    """Record malformed values returned by C_GetAttributeValue.

    ``read_attributes`` has already completed both raw calls successfully at
    this point.  A value with the wrong Python shape is provider evidence, not
    an unavailable attribute and must remain a hard metadata finding.
    """
    if value is MISSING_ATTRIBUTE:
        return None
    if attr in {CKA_CLASS, CKA_KEY_TYPE}:
        valid = isinstance(value, int) and not isinstance(value, bool)
        expected = "CK_ULONG integer"
    elif attr == CKA_LABEL:
        valid = isinstance(value, str)
        expected = "UTF-8 string"
    elif attr in {CKA_ID, CKA_MODULUS, CKA_VALUE}:
        valid = isinstance(value, bytes)
        expected = "bytes"
    else:
        valid = True
        expected = "provider-defined value"
    if valid:
        return None
    name = _attribute_name(attr)
    return record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        expected=CKR_OK,
        actual=CKR_OK,
        detail={
            "attribute": {
                "name": name,
                "id": int(attr),
                "expected": expected,
                "actual": repr(value),
            }
        },
        summary=f"{label}: C_GetAttributeValue returned malformed {name}",
    )


def _record_setter_result(
    rv: int,
    *,
    label: str,
    attr: int,
) -> classification.Classification | None:
    """Record a raw setter result without terminating the evidence pass."""
    if rv == CKR_OK or rv in _SET_ATTR_REJECT_RVS:
        return None
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    return record_as(
        reason,
        kind="lifecycle" if reason == "nonspec_reject" else "metadata",
        label=label,
        operation="C_SetAttributeValue",
        expected=_SET_ATTR_REJECT_RVS,
        actual=rv,
        detail={
            "attribute": {"name": _attribute_name(attr), "id": int(attr)},
            "expected_rejections": [int(rv) for rv in _SET_ATTR_REJECT_RVS],
            "actual": int(rv),
        },
        summary=(
            f"{label}: C_SetAttributeValue returned an undefined CK_RV"
            if reason == "self_contradiction"
            else f"{label}: C_SetAttributeValue returned an unexpected CK_RV"
        ),
    )


def _classify_setter_rejection(
    exc: CkrAssertionError,
    *,
    label: str,
    attr: int,
) -> classification.Classification | None:
    """Record an unexpected C_SetAttributeValue rejection without terminating."""
    return _record_setter_result(exc.rv, label=label, attr=attr)


def _record_baseline_mismatch(
    attr: int,
    actual: Any,
    expected: Any,
    *,
    label: str,
) -> classification.Classification:
    """Record a setup mismatch before using a baseline as an effect oracle."""
    if actual is MISSING_ATTRIBUTE:
        actual_text = "unavailable"
    else:
        actual_text = repr(actual)
    return record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        expected=CKR_OK,
        actual=CKR_OK,
        detail={
            "attribute": {
                "name": _attribute_name(attr),
                "id": int(attr),
                "expected_baseline": repr(expected),
                "actual": actual_text,
            }
        },
        summary=(f"{label}: setup did not preserve the expected {_attribute_name(attr)} baseline"),
    )


def _record_effect_mutation(
    attr: int,
    baseline: Any,
    actual: Any,
    *,
    requested: Any,
    setter_rv: int,
    label: str,
) -> classification.Classification | None:
    """Record a present post-write transition against an observed baseline."""
    if baseline is MISSING_ATTRIBUTE:
        return None
    if actual is MISSING_ATTRIBUTE:
        return None
    return record_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation="C_SetAttributeValue",
        expected=_SET_ATTR_REJECT_RVS,
        actual=setter_rv,
        detail={
            "attribute": {
                "name": _attribute_name(attr),
                "id": int(attr),
                "baseline": repr(baseline),
                "requested": repr(requested),
                "actual": repr(actual),
            }
        },
        summary=(
            f"{label}: C_SetAttributeValue changed the read-only "
            f"{_attribute_name(attr)} from its observed baseline"
        ),
    )


def _record_positive_setter_result(
    rv: int,
    *,
    label: str,
    attr: int,
) -> classification.Classification | None:
    """Record a non-OK setter result for a positive mutation test."""
    if rv == CKR_OK:
        return None
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    return record_as(
        reason,
        kind="lifecycle" if reason == "nonspec_reject" else "metadata",
        label=label,
        operation="C_SetAttributeValue",
        expected=CKR_OK,
        actual=rv,
        detail={
            "attribute": {"name": _attribute_name(attr), "id": int(attr)},
            "expected": int(CKR_OK),
            "actual": int(rv),
        },
        summary=(
            f"{label}: C_SetAttributeValue returned an undefined CK_RV"
            if reason == "self_contradiction"
            else f"{label}: C_SetAttributeValue did not accept the requested mutation"
        ),
    )


def _record_positive_readback_mismatch(
    attr: int,
    actual: Any,
    expected: Any,
    *,
    label: str,
) -> classification.Classification | None:
    """Record a present, well-typed post-write value that is semantically wrong."""
    if actual is MISSING_ATTRIBUTE:
        return None
    return record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_SetAttributeValue",
        expected=CKR_OK,
        actual=CKR_OK,
        detail={
            "attribute": {
                "name": _attribute_name(attr),
                "id": int(attr),
                "expected": repr(expected),
                "actual": repr(actual),
            }
        },
        summary=f"{label}: C_SetAttributeValue did not produce the requested attribute value",
    )


def _record_rejected_positive_transition(
    attr: int,
    baseline: Any,
    actual: Any,
    *,
    requested: Any,
    setter_rv: int,
    label: str,
) -> classification.Classification | None:
    """Record a state transition after a rejected positive mutation."""
    if baseline is MISSING_ATTRIBUTE:
        return None
    if actual is MISSING_ATTRIBUTE:
        return None
    return record_as(
        "self_contradiction",
        kind="lifecycle",
        label=label,
        operation="C_SetAttributeValue",
        expected=_SET_ATTR_REJECT_RVS,
        actual=setter_rv,
        detail={
            "attribute": {
                "name": _attribute_name(attr),
                "id": int(attr),
                "baseline": repr(baseline),
                "requested": repr(requested),
                "actual": repr(actual),
            },
            "expected_rejections": [int(code) for code in _SET_ATTR_REJECT_RVS],
        },
        summary=(
            f"{label}: C_SetAttributeValue rejected the mutation but the "
            f"{_attribute_name(attr)} changed from its observed baseline"
        ),
    )


def _record_atomic_setter_result(
    rv: int,
    *,
    label: str,
) -> classification.Classification | None:
    """Record a mixed-template CK_RV while leaving post-state evaluation running."""
    if rv == CKR_OK or rv in _SET_ATTR_REJECT_RVS:
        return None
    reason = (
        "nonspec_reject"
        if is_standard_ckr(rv) or is_vendor_defined_ckr(rv)
        else "self_contradiction"
    )
    return record_as(
        reason,
        kind="lifecycle" if reason == "nonspec_reject" else "metadata",
        label=label,
        operation="C_SetAttributeValue",
        expected=_SET_ATTR_REJECT_RVS,
        actual=rv,
        detail={
            "attributes": [
                {"name": "CKA_LABEL", "id": int(CKA_LABEL)},
                {"name": "CKA_CLASS", "id": int(CKA_CLASS)},
            ],
            "expected_rejections": [int(code) for code in _SET_ATTR_REJECT_RVS],
            "actual": int(rv),
        },
        summary=(
            f"{label}: C_SetAttributeValue returned an undefined CK_RV"
            if reason == "self_contradiction"
            else f"{label}: C_SetAttributeValue returned an unexpected CK_RV"
        ),
    )


def _present_readback_or_record(
    attrs: dict[int, Any],
    attr: int,
    *,
    label: str,
) -> Any:
    """Read one entry while retaining a structured omission finding."""
    return attr_or_record(
        attrs,
        attr,
        label=label,
        kind="metadata",
        mechanism=None,
    )


def _read_back_for_effect(
    rs: Any,
    handle: int,
    attrs: list[int],
    *,
    label: str,
) -> tuple[dict[int, Any], bool, classification.Classification | None]:
    """Read an effect oracle while retaining clean C_GetAttributeValue rejects.

    A read failure before or after a setter is an unavailable oracle, not a
    reason to suppress the independent setter operation.  Plain reader
    exceptions still propagate; only the CK_RV-bearing recipe exception is
    classified here.
    """
    try:
        return read_attributes(rs.raw, rs.sh, handle, attrs), True, None
    except CkrAssertionError as exc:
        reason = (
            "not_operational"
            if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv)
            else "self_contradiction"
        )
        record = record_as(
            reason,
            kind="metadata" if reason == "not_operational" else "lifecycle",
            label=label,
            operation="C_GetAttributeValue",
            expected=CKR_OK,
            actual=exc.rv,
            detail={"attributes": [int(attr) for attr in attrs]},
            summary=f"{label}: C_GetAttributeValue did not provide an effect oracle",
        )
        return {}, False, record


def _classify_readonly_write(
    rs: Any, handle: int, attr: int, new_value: Any, *, label: str
) -> None:
    """lifecycle effect-check for a write to a read-only attribute.

    C_SetAttributeValue on a read-only attribute must reject. Verify the effect,
    not the return code:

    - rejected (set_attributes raised) with an unchanged observed value -> pass
      (spec-correct),
    - any setter result followed by a present transition from the observed
      baseline -> fail (the module changed a read-only attribute),
    - accepted but the value is unchanged (no-op) -> xfail (wrong return code,
      but no harm; spec prefers CKR_ATTRIBUTE_READ_ONLY).
    """
    # Read the original value before the write.  A post-write value that is
    # merely different from the requested value is not necessarily a no-op:
    # only equality with this baseline proves that the object stayed unchanged.
    before, baseline_read, baseline_error = _read_back_for_effect(
        rs,
        handle,
        [attr],
        label=f"{label}:baseline",
    )
    baseline = (
        _present_readback_or_record(before, attr, label=f"{label}:baseline")
        if baseline_read
        else MISSING_ATTRIBUTE
    )
    baseline_malformed = _record_malformed_readback(
        attr,
        baseline,
        label=f"{label}:baseline",
    )
    hard_results: list[classification.Classification] = []
    soft_results: list[classification.Classification] = []
    if baseline_error is not None:
        (hard_results if baseline_error.outcome == "fail" else soft_results).append(baseline_error)
    if baseline_malformed is not None:
        hard_results.append(baseline_malformed)
    observable_baseline = baseline is not MISSING_ATTRIBUTE and baseline_malformed is None
    expected_known, expected_baseline = _expected_baseline(attr)
    setup_valid = not expected_known
    if expected_known and baseline is not MISSING_ATTRIBUTE and baseline_malformed is None:
        setup_valid = baseline == expected_baseline
    if (
        baseline is not MISSING_ATTRIBUTE
        and baseline_malformed is None
        and expected_known
        and baseline != expected_baseline
    ):
        hard_results.append(
            _record_baseline_mismatch(
                attr,
                baseline,
                expected_baseline,
                label=f"{label}:baseline",
            )
        )
        setup_valid = False

    setter_rv = int(CKR_OK)
    setter_rejected = False
    try:
        set_attributes(rs.raw, rs.sh, handle, {attr: new_value})
    except CkrAssertionError as exc:
        setter_rv = int(exc.rv)
        setter_rejected = True
        setter_result = _classify_setter_rejection(exc, label=label, attr=attr)
        if setter_result is not None:
            (hard_results if setter_result.outcome == "fail" else soft_results).append(
                setter_result
            )

    after, after_read, after_error = _read_back_for_effect(
        rs,
        handle,
        [attr],
        label=f"{label}:readback",
    )
    value = (
        _present_readback_or_record(after, attr, label=f"{label}:readback")
        if after_read
        else MISSING_ATTRIBUTE
    )
    if after_error is not None:
        (hard_results if after_error.outcome == "fail" else soft_results).append(after_error)
    if setter_rejected and setter_rv == CKR_GENERAL_ERROR:
        # CKR_GENERAL_ERROR leaves the post-call state unspecified.  Keep the
        # independent readback evidence, but never turn it into a mutation
        # verdict for this setter result.
        note(
            f"{label}: C_SetAttributeValue returned CKR_GENERAL_ERROR; "
            "post-call state is explicitly unspecified",
            ComplianceLevel.NOT_RECOMMENDED,
            reference="PKCS#11 base specification: CKR_GENERAL_ERROR execution semantics",
        )
    if value is MISSING_ATTRIBUTE:
        if not setter_rejected:
            # The provider accepted the setter but omitted the dependent oracle.
            # Keep both facts visible: absence is a C_GetAttributeValue xfail,
            # and CKR_OK from the setter is an effect-unobservable deviation.
            record_as(
                "honest_deviation",
                kind="lifecycle",
                label=f"{label}:effect-unobservable",
                operation="C_SetAttributeValue",
                expected=_SET_ATTR_REJECT_RVS,
                actual=setter_rv,
                detail={
                    "attribute": {
                        "name": _attribute_name(attr),
                        "id": int(attr),
                        "baseline": "unavailable" if baseline is MISSING_ATTRIBUTE else "malformed",
                        "readback": "unavailable",
                    }
                },
                summary=(
                    f"{label}: C_SetAttributeValue returned CKR_OK, but the post-write "
                    "attribute was unavailable so its effect could not be observed"
                ),
            )
        if hard_results:
            raise_for_record(hard_results[0])
        if soft_results:
            raise_for_record(soft_results[0])
        return

    malformed = _record_malformed_readback(attr, value, label=f"{label}:readback")
    if malformed is not None:
        hard_results.append(malformed)
        if not setter_rejected:
            # A CKR_OK setter plus malformed post-readback has the same
            # effect-unobservable limitation as an omitted value.  Keep the
            # setter deviation visible even though C_GetAttributeValue is the
            # strongest terminal finding.
            record_as(
                "honest_deviation",
                kind="lifecycle",
                label=f"{label}:effect-unobservable",
                operation="C_SetAttributeValue",
                expected=_SET_ATTR_REJECT_RVS,
                actual=setter_rv,
                detail={
                    "attribute": {
                        "name": _attribute_name(attr),
                        "id": int(attr),
                        "baseline": (
                            "unavailable"
                            if baseline is MISSING_ATTRIBUTE
                            else "malformed"
                            if baseline_malformed is not None
                            else "present"
                        ),
                        "readback": "malformed",
                    }
                },
                summary=(
                    f"{label}: C_SetAttributeValue returned CKR_OK, but the post-write "
                    "attribute was malformed so its effect could not be observed"
                ),
            )
    if (
        malformed is None
        and not (setter_rejected and setter_rv == CKR_GENERAL_ERROR)
        and baseline is not MISSING_ATTRIBUTE
        and baseline_malformed is None
    ):
        if value != baseline:
            mutation = _record_effect_mutation(
                attr,
                baseline,
                value,
                requested=new_value,
                setter_rv=setter_rv,
                label=(f"{label}: C_SetAttributeValue changed {_attribute_name(attr)}"),
            )
            if mutation is not None:
                hard_results.append(mutation)
        elif not setter_rejected:
            soft_results.append(
                record_as(
                    "honest_deviation",
                    kind="lifecycle",
                    label=label,
                    operation="C_SetAttributeValue",
                    expected=_SET_ATTR_REJECT_RVS,
                    actual=setter_rv,
                    detail={
                        "attribute": {"name": _attribute_name(attr), "id": int(attr)},
                        "setup_valid": setup_valid,
                    },
                    summary=(
                        f"{label}: returned CKR_OK but the value matched the pre-write baseline "
                        "(no-op; spec prefers CKR_ATTRIBUTE_READ_ONLY)"
                    ),
                )
            )
    elif malformed is None and not setter_rejected:
        # A present post-write value with no usable pre-write oracle cannot
        # establish either mutation or a no-op.
        record_as(
            "honest_deviation",
            kind="lifecycle",
            label=f"{label}:effect-unobservable",
            operation="C_SetAttributeValue",
            expected=_SET_ATTR_REJECT_RVS,
            actual=setter_rv,
            detail={
                "attribute": {
                    "name": _attribute_name(attr),
                    "id": int(attr),
                    "setup_valid": setup_valid,
                    "observable_baseline": observable_baseline,
                    "baseline": "unavailable" if baseline is MISSING_ATTRIBUTE else "malformed",
                    "readback": repr(value),
                }
            },
            summary=(
                f"{label}: C_SetAttributeValue returned CKR_OK, but the baseline was "
                "unavailable so the observed value cannot establish its effect"
            ),
        )
    if hard_results:
        raise_for_record(hard_results[0])
    if soft_results:
        raise_for_record(soft_results[0])


class TestSetAttributePositive:
    """Verify that mutable attributes can be changed."""

    def test_change_label(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_LABEL: "before"},
            purpose="set-attribute label mutation",
        )
        try:
            hard_results: list[classification.Classification] = []
            soft_results: list[classification.Classification] = []
            attrs, initial_read, initial_error = _read_back_for_effect(
                rs,
                key,
                [CKA_LABEL],
                label="CKA_LABEL readback after create",
            )
            initial = (
                _present_readback_or_record(
                    attrs,
                    CKA_LABEL,
                    label="CKA_LABEL readback after create",
                )
                if initial_read
                else MISSING_ATTRIBUTE
            )
            if initial_error is not None:
                (hard_results if initial_error.outcome == "fail" else soft_results).append(
                    initial_error
                )
            initial_malformed = None
            if initial is not MISSING_ATTRIBUTE:
                initial_malformed = _record_malformed_readback(
                    CKA_LABEL,
                    initial,
                    label="CKA_LABEL readback after create",
                )
                if initial_malformed is not None:
                    hard_results.append(initial_malformed)
                elif initial != "before":
                    hard_results.append(
                        _record_baseline_mismatch(
                            CKA_LABEL,
                            initial,
                            "before",
                            label="CKA_LABEL readback after create",
                        )
                    )

            setter_rejected = False
            setter_rv = int(CKR_OK)
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: "after"})
            except CkrAssertionError as exc:
                setter_rejected = True
                setter_rv = int(exc.rv)
                setter_result = _record_positive_setter_result(
                    setter_rv,
                    label="C_SetAttributeValue CKA_LABEL mutation",
                    attr=CKA_LABEL,
                )
                if setter_result is not None:
                    (hard_results if setter_result.outcome == "fail" else soft_results).append(
                        setter_result
                    )

            after_attrs, after_read, after_error = _read_back_for_effect(
                rs,
                key,
                [CKA_LABEL],
                label="CKA_LABEL readback after C_SetAttributeValue",
            )
            after = (
                _present_readback_or_record(
                    after_attrs,
                    CKA_LABEL,
                    label="CKA_LABEL readback after C_SetAttributeValue",
                )
                if after_read
                else MISSING_ATTRIBUTE
            )
            if after_error is not None:
                (hard_results if after_error.outcome == "fail" else soft_results).append(
                    after_error
                )
            if setter_rejected and setter_rv == CKR_GENERAL_ERROR:
                # CKR_GENERAL_ERROR does not specify whether object state was
                # changed.  Preserve the independent readback, but do not
                # infer a setter mutation from it.
                note(
                    "C_SetAttributeValue CKA_LABEL returned CKR_GENERAL_ERROR; "
                    "post-call state is explicitly unspecified",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 base specification: CKR_GENERAL_ERROR execution semantics",
                )
            after_malformed = None
            if after is not MISSING_ATTRIBUTE:
                after_malformed = _record_malformed_readback(
                    CKA_LABEL,
                    after,
                    label="CKA_LABEL readback after C_SetAttributeValue",
                )
                if after_malformed is not None:
                    hard_results.append(after_malformed)
                elif setter_rejected:
                    if (
                        setter_rv != CKR_GENERAL_ERROR
                        and initial is not MISSING_ATTRIBUTE
                        and initial_malformed is None
                        and after != initial
                    ):
                        transition = _record_rejected_positive_transition(
                            CKA_LABEL,
                            initial,
                            after,
                            requested="after",
                            setter_rv=setter_rv,
                            label="CKA_LABEL rejected mutation transition",
                        )
                        if transition is not None:
                            hard_results.append(transition)
                elif after != "after":
                    mismatch = _record_positive_readback_mismatch(
                        CKA_LABEL,
                        after,
                        "after",
                        label="CKA_LABEL semantic post-write result",
                    )
                    if mismatch is not None:
                        hard_results.append(mismatch)

            # Search by the new label only when C_SetAttributeValue actually
            # returned CKR_OK; a rejected positive mutation cannot prove search.
            if not setter_rejected:
                tmpl = template(attr_bytes(CKA_LABEL, b"after"))
                found = find_objects(rs.raw, rs.sh, tmpl)
                if len(found) < 1:
                    hard_results.append(
                        record_as(
                            "wrong_result",
                            kind="metadata",
                            label="C_FindObjects CKA_LABEL mutation search",
                            operation="C_FindObjects",
                            expected=CKR_OK,
                            actual=CKR_OK,
                            detail={"attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)}},
                            summary="C_FindObjects did not find the key under its new CKA_LABEL",
                        )
                    )

            if hard_results:
                raise_for_record(hard_results[0])
            if soft_results:
                raise_for_record(soft_results[0])
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_id(self, p11_raw_session: Any) -> None:
        """CKA_ID can be changed on an existing key."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_ID: b"\x01\x02"},
            purpose="set-attribute ID mutation",
        )
        try:
            set_attributes(rs.raw, rs.sh, key, {CKA_ID: b"\xaa\xbb"})
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_ID])
            value = _present_readback_or_record(
                attrs,
                CKA_ID,
                label="CKA_ID readback after C_SetAttributeValue",
            )
            if value is MISSING_ATTRIBUTE:
                return
            malformed = _record_malformed_readback(
                CKA_ID,
                value,
                label="CKA_ID readback after C_SetAttributeValue",
            )
            if malformed is not None:
                raise_for_record(malformed)
            assert_correct(
                actual=value,
                expected=b"\xaa\xbb",
                label="CKA_ID readback after C_SetAttributeValue",
                operation="C_GetAttributeValue",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_change_label_on_keypair(self, p11_raw_session: Any) -> None:
        """CKA_LABEL can be changed on RSA public and private keys."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            public_attrs={CKA_LABEL: "rsa-orig"},
            private_attrs={CKA_LABEL: "rsa-orig"},
        )
        try:
            set_attributes(rs.raw, rs.sh, pub, {CKA_LABEL: "rsa-pub-new"})
            set_attributes(rs.raw, rs.sh, priv, {CKA_LABEL: "rsa-priv-new"})

            tmpl_pub = template(attr_bytes(CKA_LABEL, b"rsa-pub-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_pub)) >= 1
            tmpl_priv = template(attr_bytes(CKA_LABEL, b"rsa-priv-new"))
            assert len(find_objects(rs.raw, rs.sh, tmpl_priv)) >= 1
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSetAttributeAtomicity:
    """Verify that rejected multi-row updates do not leave partial state behind."""

    def test_set_attribute_mixed_template_is_atomic(self, p11_raw_session: Any) -> None:
        """A failing SetAttribute template must not partially apply earlier rows."""
        rs = p11_raw_session
        original = "atomic-before"
        control = "atomic-control"
        target = "atomic-after"
        key = gen_aes_key_or_xfail(
            rs,
            128,
            attrs={CKA_LABEL: original},
            purpose="set-attribute atomicity",
        )
        try:
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: control})
                set_attributes(rs.raw, rs.sh, key, {CKA_LABEL: original})
            except AssertionError as exc:
                xfail_if_known_ckr(
                    exc,
                    _SET_ATTR_REJECT_RVS,
                    "C_SetAttributeValue rejected mutable CKA_LABEL setup",
                )
                raise

            mixed = template(
                attr_bytes(CKA_LABEL, target.encode("utf-8")),
                attr_ulong(CKA_CLASS, CKO_PUBLIC_KEY),
            )
            hard_results: list[classification.Classification] = []
            soft_results: list[classification.Classification] = []

            # Read both actual setup values immediately before the raw mixed
            # setter.  Do not infer a baseline from the preceding setup writes:
            # a provider may have silently ignored one of those writes.
            baseline_attrs, baseline_read, baseline_error = _read_back_for_effect(
                rs,
                key,
                [CKA_LABEL, CKA_CLASS],
                label="C_SetAttributeValue mixed template baseline readback",
            )
            label_before = (
                _present_readback_or_record(
                    baseline_attrs,
                    CKA_LABEL,
                    label="C_SetAttributeValue mixed template baseline label",
                )
                if baseline_read
                else MISSING_ATTRIBUTE
            )
            class_before = (
                _present_readback_or_record(
                    baseline_attrs,
                    CKA_CLASS,
                    label="C_SetAttributeValue mixed template baseline class",
                )
                if baseline_read
                else MISSING_ATTRIBUTE
            )
            if baseline_error is not None:
                (hard_results if baseline_error.outcome == "fail" else soft_results).append(
                    baseline_error
                )

            observable_baseline: dict[int, Any] = {}
            setup_valid: set[int] = set()
            expected_baselines = {
                CKA_LABEL: original,
                CKA_CLASS: CKO_SECRET_KEY,
            }
            for attr, value in ((CKA_LABEL, label_before), (CKA_CLASS, class_before)):
                if value is MISSING_ATTRIBUTE:
                    continue
                malformed = _record_malformed_readback(
                    attr,
                    value,
                    label=(f"C_SetAttributeValue mixed template baseline {_attribute_name(attr)}"),
                )
                if malformed is not None:
                    hard_results.append(malformed)
                    continue
                # A well-typed value is still an observable baseline even
                # when setup did not produce the value the test requested.
                observable_baseline[attr] = value
                if value != expected_baselines[attr]:
                    hard_results.append(
                        _record_baseline_mismatch(
                            attr,
                            value,
                            expected_baselines[attr],
                            label=(
                                "C_SetAttributeValue mixed template baseline "
                                f"{_attribute_name(attr)}"
                            ),
                        )
                    )
                    continue
                setup_valid.add(attr)

            rv = int(rs.raw.C_SetAttributeValue(rs.sh, key, mixed.ptr, mixed.count))
            setter_result = _record_atomic_setter_result(
                rv,
                label="C_SetAttributeValue mixed mutable/read-only template",
            )
            if setter_result is not None:
                (hard_results if setter_result.outcome == "fail" else soft_results).append(
                    setter_result
                )

            # Always read both post-call legs.  Even a clean setter rejection
            # must not hide malformed or contradictory provider readback.
            post_attrs, post_read, post_error = _read_back_for_effect(
                rs,
                key,
                [CKA_LABEL, CKA_CLASS],
                label="C_SetAttributeValue mixed template post-call readback",
            )
            label_after = (
                _present_readback_or_record(
                    post_attrs,
                    CKA_LABEL,
                    label="C_SetAttributeValue mixed template post-call label",
                )
                if post_read
                else MISSING_ATTRIBUTE
            )
            class_after = (
                _present_readback_or_record(
                    post_attrs,
                    CKA_CLASS,
                    label="C_SetAttributeValue mixed template post-call class",
                )
                if post_read
                else MISSING_ATTRIBUTE
            )
            if post_error is not None:
                (hard_results if post_error.outcome == "fail" else soft_results).append(post_error)

            # CKR_GENERAL_ERROR explicitly leaves post-call object state
            # unspecified.  Still validate present values for ABI integrity,
            # retain every omission, and do not apply an atomicity oracle.
            if rv == CKR_GENERAL_ERROR:
                state_parts: list[str] = []
                for attr, value in ((CKA_LABEL, label_after), (CKA_CLASS, class_after)):
                    if value is MISSING_ATTRIBUTE:
                        state_parts.append(f"{_attribute_name(attr)}=<unavailable>")
                        continue
                    state_parts.append(f"{_attribute_name(attr)}={value!r}")
                    malformed = _record_malformed_readback(
                        attr,
                        value,
                        label=(
                            f"C_SetAttributeValue mixed template post-call {_attribute_name(attr)}"
                        ),
                    )
                    if malformed is not None:
                        hard_results.append(malformed)
                note(
                    "C_SetAttributeValue returned CKR_GENERAL_ERROR for a mixed template; "
                    f"post-call state is explicitly unspecified ({', '.join(state_parts)})",
                    ComplianceLevel.NOT_RECOMMENDED,
                    reference="PKCS#11 base specification: CKR_GENERAL_ERROR execution semantics",
                )
                if hard_results:
                    raise_for_record(hard_results[0])
                return

            # Validate every post-call leg before choosing any terminal result.
            post_malformed: set[int] = set()
            for attr, value in ((CKA_LABEL, label_after), (CKA_CLASS, class_after)):
                if value is MISSING_ATTRIBUTE:
                    continue
                malformed = _record_malformed_readback(
                    attr,
                    value,
                    label=(f"C_SetAttributeValue mixed template post-call {_attribute_name(attr)}"),
                )
                if malformed is not None:
                    hard_results.append(malformed)
                    post_malformed.add(attr)
                    continue
                if attr not in observable_baseline:
                    continue
                if value != observable_baseline[attr]:
                    hard_results.append(
                        record_as(
                            "self_contradiction",
                            kind="lifecycle",
                            label=(
                                "C_SetAttributeValue mixed template "
                                f"{_attribute_name(attr)} mutation"
                            ),
                            operation="C_SetAttributeValue",
                            expected=_SET_ATTR_REJECT_RVS,
                            actual=rv,
                            detail={
                                "attribute": {
                                    "name": _attribute_name(attr),
                                    "id": int(attr),
                                    "baseline": repr(observable_baseline[attr]),
                                    "requested": repr(
                                        target if attr == CKA_LABEL else CKO_PUBLIC_KEY
                                    ),
                                    "actual": repr(value),
                                }
                            },
                            summary=(
                                f"C_SetAttributeValue partially applied or changed "
                                f"atomicity leg {_attribute_name(attr)} from its baseline"
                            ),
                        )
                    )

            if rv != CKR_OK:
                if hard_results:
                    raise_for_record(hard_results[0])
                if soft_results:
                    raise_for_record(soft_results[0])
                return

            if (
                label_after is MISSING_ATTRIBUTE
                or class_after is MISSING_ATTRIBUTE
                or post_malformed
                or len(observable_baseline) != 2
            ):
                # CKR_OK plus an omitted/unobservable baseline or post-call
                # oracle cannot establish either mutation or a no-op.
                record_as(
                    "honest_deviation",
                    kind="lifecycle",
                    label="C_SetAttributeValue:mixed-template-effect-unobservable",
                    operation="C_SetAttributeValue",
                    expected=_SET_ATTR_REJECT_RVS,
                    actual=rv,
                    detail={
                        "attributes": [
                            {
                                "name": "CKA_LABEL",
                                "id": int(CKA_LABEL),
                                "baseline": repr(observable_baseline[CKA_LABEL])
                                if CKA_LABEL in observable_baseline
                                else "unavailable-or-invalid",
                                "setup_valid": CKA_LABEL in setup_valid,
                                "readback": (
                                    "unavailable"
                                    if label_after is MISSING_ATTRIBUTE
                                    else "malformed"
                                    if CKA_LABEL in post_malformed
                                    else "present"
                                ),
                            },
                            {
                                "name": "CKA_CLASS",
                                "id": int(CKA_CLASS),
                                "baseline": repr(observable_baseline[CKA_CLASS])
                                if CKA_CLASS in observable_baseline
                                else "unavailable-or-invalid",
                                "setup_valid": CKA_CLASS in setup_valid,
                                "readback": (
                                    "unavailable"
                                    if class_after is MISSING_ATTRIBUTE
                                    else "malformed"
                                    if CKA_CLASS in post_malformed
                                    else "present"
                                ),
                            },
                        ]
                    },
                    summary=(
                        "C_SetAttributeValue returned CKR_OK, but the atomicity "
                        "effect could not be established from complete trustworthy oracles"
                    ),
                )
                if hard_results:
                    raise_for_record(hard_results[0])
                return
            if (
                label_after == observable_baseline[CKA_LABEL]
                and class_after == observable_baseline[CKA_CLASS]
            ):
                record_as(
                    "honest_deviation",
                    kind="lifecycle",
                    label="C_SetAttributeValue:mixed-template-noop",
                    operation="C_SetAttributeValue",
                    expected=_SET_ATTR_REJECT_RVS,
                    actual=rv,
                    summary=(
                        "C_SetAttributeValue returned CKR_OK for a mixed template containing "
                        "read-only CKA_CLASS, but left both object attributes at baseline"
                    ),
                )
            if hard_results:
                raise_for_record(hard_results[0])
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestSetAttributeNegative:
    """Verify that read-only / immutable attributes are rejected."""

    def test_cannot_change_class(self, p11_raw_session: Any) -> None:
        """CKA_CLASS is read-only - must reject; mutating it is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute class rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_CLASS,
                CKO_PUBLIC_KEY,
                label="write read-only CKA_CLASS (PKCS#11 Base v3.0 Table 15)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_key_type(self, p11_raw_session: Any) -> None:
        """CKA_KEY_TYPE is read-only - must reject; mutating it is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute key-type rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_KEY_TYPE,
                CKK_RSA,
                label="write read-only CKA_KEY_TYPE (PKCS#11 Base v3.0 Table 15)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_cannot_change_modulus(self, p11_raw_session: Any) -> None:
        """CKA_MODULUS on RSA key is read-only - must reject."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            _classify_readonly_write(
                rs,
                pub,
                CKA_MODULUS,
                b"\x00" * 256,
                label="write read-only CKA_MODULUS on an RSA public key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_cannot_set_value_on_sensitive_key(self, p11_raw_session: Any) -> None:
        """CKA_VALUE on a key - must reject; mutating the key bytes is a contradiction."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(rs, 128, purpose="set-attribute sensitive value rejection")
        try:
            _classify_readonly_write(
                rs,
                key,
                CKA_VALUE,
                b"\x00" * 32,
                label="write read-only CKA_VALUE on a secret key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
