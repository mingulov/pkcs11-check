"""Attribute enforcement tests - one-way flags, read-only attrs, template constraints.

Covers CKA_COPYABLE one-way rule, CKA_DESTROYABLE enforcement,
CKA_KEY_GEN_MECHANISM read-only semantics, CKA_CHECK_VALUE (KCV),
CKA_ALLOWED_MECHANISMS, CKA_WRAP_WITH_TRUSTED, CKA_ALWAYS_AUTHENTICATE,
and CKA_START_DATE / CKA_END_DATE date attributes.
"""

from __future__ import annotations

from typing import Any, NoReturn

import pytest

from pkcs11_check import classification
from pkcs11_check.classification import fail_as
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    read_attributes,
    set_attributes,
    sign_single,
)
from pkcs11_check.raw.rv import (
    CkrAssertionError,
    expect_rv,
    is_standard_ckr,
    is_vendor_defined_ckr,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_AUTHENTICATE,
    CKA_CHECK_VALUE,
    CKA_COPYABLE,
    CKA_DECRYPT,
    CKA_DESTROYABLE,
    CKA_ENCRYPT,
    CKA_END_DATE,
    CKA_KEY_GEN_MECHANISM,
    CKA_LABEL,
    CKA_SIGN,
    CKA_START_DATE,
    CKA_TOKEN,
    CKK_AES,
    CKM_AES_KEY_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKR_ACTION_PROHIBITED,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    gen_aes_key_or_xfail,
    gen_rsa_keypair_or_xfail,
    import_secret_key_negotiated,
    is_known_error,
    reject_or_classify,
    xfail_if_known_ckr,
)

pytestmark = [pytest.mark.security]

_TEMPLATE_ERROR_RVS = {
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCONSISTENT,
}

_SET_ATTR_ERROR_RVS = {
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ACTION_PROHIBITED,
}
# NOTE (F-010): CKR_ATTRIBUTE_TYPE_INVALID is deliberately NOT in the
# accepted mutation-rejection set. Call sites read the attribute first, so
# the module has already proven it recognises the type; a TYPE_INVALID on
# the mutation is unjustified by that read. Reading and changing are
# different operations -- the rejection proves no bypass and falls through
# to the visible nonspec_reject deviation path instead of passing.


def _is_template_error(e: BaseException) -> bool:
    return is_known_error(e, _TEMPLATE_ERROR_RVS)


def _attribute_value(
    attrs: dict[int, Any],
    attr: int,
    *,
    label: str,
) -> Any:
    """Return an attribute while retaining an omitted provider value as evidence."""
    return attr_or_record(attrs, attr, inherit_mechanism=False, label=label, kind="metadata")


_KIND_PRIORITY = {"metadata": 1, "lifecycle": 2, "policy": 2, "crypto": 3}
_SEVERITY_PRIORITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _record_malformed_attribute(
    value: Any,
    *,
    attr: int,
    label: str,
    expected: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
) -> classification.Classification:
    """Record a present value with the wrong provider ABI shape/type."""
    if value is MISSING_ATTRIBUTE:
        return classification.record_as(
            "honest_deviation",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=None,
            inherit_mechanism=False,
            detail={"attribute": attr},
            summary=f"{label}: attribute unavailable",
        )
    return classification.record_as(
        "wrong_result",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        mechanism=None,
        inherit_mechanism=False,
        detail={
            "attribute": attr,
            "expected_shape": expected,
            "producer_operation": producer_operation,
            "producer_mechanism": producer_mechanism,
            "actual_type": type(value).__name__,
        },
        summary=f"{label}: present value has invalid {expected} shape: {value!r}",
    )


def _raise_strongest(records: list[classification.Classification]) -> None:
    """Raise the strongest deferred hard finding after sibling evidence/cleanup."""
    if not records:
        return
    strongest = max(
        records,
        key=lambda record: (
            _KIND_PRIORITY.get(record.kind or "", 0),
            _SEVERITY_PRIORITY.get(record.severity, 0),
        ),
    )
    classification.raise_for_record(strongest)


def _require_bool(
    value: Any,
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
) -> bool:
    if value is MISSING_ATTRIBUTE:
        classification.raise_for_record(
            _record_malformed_attribute(
                value,
                attr=attr,
                label=label,
                expected="CK_BBOOL",
                producer_operation=producer_operation,
                producer_mechanism=producer_mechanism,
            )
        )
        return False
    if type(value) is bool:
        return value
    classification.raise_for_record(
        _record_malformed_attribute(
            value,
            attr=attr,
            label=label,
            expected="CK_BBOOL",
            producer_operation=producer_operation,
            producer_mechanism=producer_mechanism,
        )
    )


def _require_ulong(
    value: Any,
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
) -> int:
    if value is MISSING_ATTRIBUTE:
        classification.raise_for_record(
            _record_malformed_attribute(
                value,
                attr=attr,
                label=label,
                expected="CK_ULONG",
                producer_operation=producer_operation,
                producer_mechanism=producer_mechanism,
            )
        )
        return 0
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    classification.raise_for_record(
        _record_malformed_attribute(
            value,
            attr=attr,
            label=label,
            expected="CK_ULONG",
            producer_operation=producer_operation,
            producer_mechanism=producer_mechanism,
        )
    )


def _record_attribute(
    actual: Any,
    expected: Any,
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
    comparison_operation: str | None = None,
    comparison_mechanism: str | None = None,
    reason: str = "wrong_result",
    kind: str = "metadata",
) -> classification.Classification | None:
    """Record a present readback mismatch without raising before sibling checks."""
    if actual is MISSING_ATTRIBUTE or expected is MISSING_ATTRIBUTE:
        return classification.record_as(
            "honest_deviation",
            kind=kind,
            label=label,
            operation="C_GetAttributeValue",
            mechanism=producer_mechanism,
            detail={"attribute": attr},
            summary=f"{label}: attribute unavailable",
        )
    if actual == expected:
        return None
    detail: dict[str, Any] = {
        "attribute": attr,
        "producer_operation": producer_operation,
        "producer_mechanism": producer_mechanism,
    }
    if comparison_operation is not None:
        detail["comparison_operation"] = comparison_operation
        detail["comparison_mechanism"] = comparison_mechanism
    operation = comparison_operation or "C_GetAttributeValue"
    mechanism = comparison_mechanism if comparison_operation is not None else producer_mechanism
    return classification.record_as(
        reason,
        kind=kind,
        label=label,
        operation=operation,
        mechanism=mechanism,
        detail=detail,
        summary=f"{label}: got {actual!r}, expected {expected!r}",
    )


def _assert_attribute(
    actual: Any,
    expected: Any,
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
    comparison_operation: str | None = None,
    comparison_mechanism: str | None = None,
    reason: str = "wrong_result",
    kind: str = "metadata",
) -> None:
    """Classify a present readback mismatch with both read and producer identity."""
    record = _record_attribute(
        actual,
        expected,
        attr=attr,
        label=label,
        producer_operation=producer_operation,
        producer_mechanism=producer_mechanism,
        comparison_operation=comparison_operation,
        comparison_mechanism=comparison_mechanism,
        reason=reason,
        kind=kind,
    )
    if record is not None:
        classification.raise_for_record(record)


def _record_attribute_one_of(
    actual: Any,
    expected: tuple[Any, ...],
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
    reason: str = "wrong_result",
    kind: str = "metadata",
) -> classification.Classification | None:
    """Record a present readback that has a small, explicit valid set."""
    if actual is MISSING_ATTRIBUTE:
        return classification.record_as(
            "honest_deviation",
            kind=kind,
            label=label,
            operation="C_GetAttributeValue",
            mechanism=producer_mechanism,
            detail={"attribute": attr},
            summary=f"{label}: attribute unavailable",
        )
    if actual in expected:
        return None
    return classification.record_as(
        reason,
        kind=kind,
        label=label,
        operation="C_GetAttributeValue",
        mechanism=producer_mechanism,
        detail={
            "attribute": attr,
            "expected_values": [repr(value) for value in expected],
            "producer_operation": producer_operation,
            "producer_mechanism": producer_mechanism,
        },
        summary=f"{label}: got {actual!r}, expected one of {expected!r}",
    )


def _assert_attribute_one_of(
    actual: Any,
    expected: tuple[Any, ...],
    *,
    attr: int,
    label: str,
    producer_operation: str,
    producer_mechanism: str | None = None,
    reason: str = "wrong_result",
    kind: str = "metadata",
) -> None:
    """Classify a present readback that has a small, explicit valid set."""
    record = _record_attribute_one_of(
        actual,
        expected,
        attr=attr,
        label=label,
        producer_operation=producer_operation,
        producer_mechanism=producer_mechanism,
        reason=reason,
        kind=kind,
    )
    if record is not None:
        classification.raise_for_record(record)


def _xfail_setup_reject(
    exc: CkrAssertionError,
    *,
    label: str,
    operation: str,
    mechanism: str,
) -> None:
    """Record an advertised attribute-template refusal without silently skipping it."""
    classification.classify(
        "not_operational",
        kind="metadata",
        label=label,
        operation=operation,
        mechanism=mechanism,
        expected=CKR_OK,
        actual=exc.rv,
        detail={"producer_operation": operation, "producer_mechanism": mechanism},
        summary=f"{label}: advertised operation rejected requested attribute template",
    )


def _record_attribute_read_rejection(
    exc: CkrAssertionError,
    *,
    label: str,
    attr: int | tuple[int, ...],
) -> classification.Classification:
    """Record a read refusal, keeping undefined CK_RV values as hard findings."""
    detail: dict[str, Any]
    if isinstance(attr, tuple):
        detail = {"attributes": list(attr)}
    else:
        detail = {"attribute": attr}
    if is_standard_ckr(exc.rv) or is_vendor_defined_ckr(exc.rv):
        return classification.record_as(
            "not_operational",
            kind="metadata",
            label=label,
            operation="C_GetAttributeValue",
            expected=CKR_OK,
            actual=exc.rv,
            detail=detail,
            summary=f"{label}: attribute read was rejected",
        )
    return classification.record_as(
        "self_contradiction",
        kind="metadata",
        label=label,
        operation="C_GetAttributeValue",
        expected=CKR_OK,
        actual=exc.rv,
        detail=detail,
        summary=f"{label}: attribute read returned undefined CK_RV",
    )


def _xfail_attribute_read_reject(
    exc: CkrAssertionError,
    *,
    label: str,
    attr: int | tuple[int, ...],
) -> NoReturn:
    """Raise the recorded read refusal after preserving exact operation metadata."""
    classification.raise_for_record(_record_attribute_read_rejection(exc, label=label, attr=attr))


def _read_attributes_or_xfail(
    raw: Any,
    session: int,
    handle: int,
    attr_types: list[int] | tuple[int, ...] | set[int] | frozenset[int],
    *,
    label: str,
    attr: int | tuple[int, ...],
) -> dict[int, Any]:
    """Read attributes, classifying only typed provider CKR refusals."""
    try:
        return read_attributes(raw, session, handle, attr_types)
    except CkrAssertionError as exc:
        _xfail_attribute_read_reject(exc, label=label, attr=attr)


class TestCopyableOneWay:
    """CKA_COPYABLE is one-way: once False, cannot go back to True."""

    def test_copyable_false_cannot_be_set_true(self, p11_raw_session: Any) -> None:
        """CKA_COPYABLE=False cannot be changed to True via C_SetAttributeValue."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_COPYABLE: False, CKA_TOKEN: False},
            purpose="CKA_COPYABLE=False setup",
        )

        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_COPYABLE],
                label="CKA_COPYABLE=False after C_GenerateKey",
                attr=CKA_COPYABLE,
            )
            initial = _attribute_value(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_GenerateKey",
            )
            if initial is MISSING_ATTRIBUTE:
                return
            initial = _require_bool(
                initial,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _assert_attribute(
                initial,
                False,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="policy",
            )
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_COPYABLE: True})
            except CkrAssertionError as e:
                reject_or_classify(
                    e,
                    tuple(_SET_ATTR_ERROR_RVS),
                    label="CKA_COPYABLE:one-way-escalation",
                    kind="policy",
                )
                return

            # A setter success is distinct from a subsequent attribute-read refusal.
            attrs2 = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_COPYABLE],
                label="CKA_COPYABLE:one-way-escalation readback",
                attr=CKA_COPYABLE,
            )
            final = _attribute_value(
                attrs2,
                CKA_COPYABLE,
                label="CKA_COPYABLE:one-way-escalation readback",
            )
            if final is MISSING_ATTRIBUTE:
                return
            final = _require_bool(
                final,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE:one-way-escalation readback",
                producer_operation="C_SetAttributeValue",
            )
            if final is MISSING_ATTRIBUTE:
                return
            if final is True:
                fail_as(
                    "self_contradiction",
                    kind="policy",
                    label="CKA_COPYABLE:one-way-escalation",
                    operation="C_SetAttributeValue",
                    detail={"attribute": CKA_COPYABLE},
                    summary=(
                        "SECURITY: CKA_COPYABLE escalated from False to True - "
                        "one-way rule violated"
                    ),
                )
            # CKR_OK with an unchanged value is a clean but nonspec refusal
            # encoding; preserve it as a provider deviation rather than a pass.
            classification.classify(
                "honest_deviation",
                kind="policy",
                label="CKA_COPYABLE:one-way-escalation-return-code",
                operation="C_SetAttributeValue",
                detail={"attribute": CKA_COPYABLE},
                summary=("CKA_COPYABLE escalation returned CKR_OK but the value remained False"),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_copyable_true_can_be_set_false(self, p11_raw_session: Any) -> None:
        """CKA_COPYABLE=True can be changed to False (the allowed direction)."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_COPYABLE: True, CKA_TOKEN: False},
            purpose="CKA_COPYABLE=True setup",
        )
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_COPYABLE],
                label="CKA_COPYABLE=True after C_GenerateKey",
                attr=CKA_COPYABLE,
            )
            initial = _attribute_value(
                attrs,
                CKA_COPYABLE,
                label="CKA_COPYABLE=True after C_GenerateKey",
            )
            if initial is MISSING_ATTRIBUTE:
                return
            initial = _require_bool(
                initial,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=True after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _assert_attribute(
                initial,
                True,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=True after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="policy",
            )

            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_COPYABLE: False})
            except CkrAssertionError as e:
                classification.classify(
                    "not_operational",
                    kind="policy",
                    label="CKA_COPYABLE:one-way-downgrade",
                    operation="C_SetAttributeValue",
                    expected=CKR_OK,
                    actual=e.rv,
                    detail={"attribute": CKA_COPYABLE},
                    summary=(
                        "CKA_COPYABLE=True to False was rejected despite being a valid "
                        "one-way transition"
                    ),
                )
                raise
            # The valid transition succeeded; classify a later read refusal as a
            # C_GetAttributeValue deviation, never as a setter rejection.
            attrs2 = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_COPYABLE],
                label="CKA_COPYABLE=False after C_SetAttributeValue",
                attr=CKA_COPYABLE,
            )
            final = _attribute_value(
                attrs2,
                CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_SetAttributeValue",
            )
            if final is MISSING_ATTRIBUTE:
                return
            final = _require_bool(
                final,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_SetAttributeValue",
                producer_operation="C_SetAttributeValue",
            )
            if final is MISSING_ATTRIBUTE:
                return
            _assert_attribute(
                final,
                False,
                attr=CKA_COPYABLE,
                label="CKA_COPYABLE=False after C_SetAttributeValue",
                producer_operation="C_SetAttributeValue",
                reason="self_contradiction",
                kind="policy",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestDestroyable:
    """CKA_DESTROYABLE enforcement - when False, C_DestroyObject must be rejected."""

    def test_destroyable_readable(self, p11_raw_session: Any) -> None:
        """CKA_DESTROYABLE should be readable on a generated key (default True)."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False},
            purpose="CKA_DESTROYABLE readback setup",
        )
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_DESTROYABLE],
                label="CKA_DESTROYABLE default after C_GenerateKey",
                attr=CKA_DESTROYABLE,
            )
            val = _attribute_value(
                attrs,
                CKA_DESTROYABLE,
                label="CKA_DESTROYABLE default after C_GenerateKey",
            )
            if val is MISSING_ATTRIBUTE:
                return
            val = _require_bool(
                val,
                attr=CKA_DESTROYABLE,
                label="CKA_DESTROYABLE default after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _assert_attribute(
                val,
                True,
                attr=CKA_DESTROYABLE,
                label="CKA_DESTROYABLE default after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="policy",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroyable_false_blocks_destroy(self, p11_raw_session: Any) -> None:
        """C_DestroyObject must fail when CKA_DESTROYABLE=False."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DESTROYABLE: False, CKA_TOKEN: False},
            purpose="CKA_DESTROYABLE=False setup",
        )

        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_DESTROYABLE],
                label="CKA_DESTROYABLE=False after C_GenerateKey",
                attr=CKA_DESTROYABLE,
            )
            val = _attribute_value(
                attrs,
                CKA_DESTROYABLE,
                label="CKA_DESTROYABLE=False after C_GenerateKey",
            )
            if val is MISSING_ATTRIBUTE:
                return
            val = _require_bool(
                val,
                attr=CKA_DESTROYABLE,
                label="CKA_DESTROYABLE=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )

            _assert_attribute(
                val,
                False,
                attr=CKA_DESTROYABLE,
                label="CKA_DESTROYABLE=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="policy",
            )

            rv = rs.raw.C_DestroyObject(rs.sh, key)
            classify_negative_rv(
                rv,
                (CKR_ACTION_PROHIBITED,),
                label="C_DestroyObject on CKA_DESTROYABLE=False key",
                kind="policy",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_destroyable_true_allows_destroy(self, p11_raw_session: Any) -> None:
        """C_DestroyObject should succeed when CKA_DESTROYABLE=True."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_DESTROYABLE: True, CKA_TOKEN: False},
            purpose="CKA_DESTROYABLE=True setup",
        )
        try:
            try:
                rv = rs.raw.C_DestroyObject(rs.sh, key)
                expect_rv(rv, CKR_OK, context="C_DestroyObject on CKA_DESTROYABLE=True key")
            except CkrAssertionError as e:
                xfail_if_known_ckr(
                    e,
                    (CKR_ACTION_PROHIBITED, CKR_ATTRIBUTE_VALUE_INVALID),
                    "C_DestroyObject on CKA_DESTROYABLE=True key is not operational",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestTokenAttributePromotion:
    """GAP-A5: session-object → token-object promotion via SetAttribute.

    PKCS#11 v3.2 lists CKA_TOKEN as a Common Object Attribute
    with "R/W after creation" semantics — promotion IS allowed by the
    spec, but only by an authenticated user with R/W token access. The
    security concerns:

    1. Lying-module pattern: SetAttribute returns CKR_OK but the value
       silently doesn't change (readback shows CKA_TOKEN=False after
       a "successful" set to True). Mirrors GAP-T1 / GAP-T7.
    2. Half-promoted state: SetAttribute returns CKR_OK and readback
       shows True, but the object doesn't actually persist on the
       token (would require a separate-session check; out of scope
       for this baseline test).

    Closes Phase 4.5 GAP-A5 (MED).
    """

    def test_setattr_token_promotion_consistency(self, p11_raw_session: Any) -> None:
        """C_SetAttributeValue(CKA_TOKEN=True) must either (a) be rejected,
        or (b) actually take effect (readback shows True).

        A module that returns CKR_OK without actually promoting the
        object is in a confused half-promoted state — the object looks
        like a token object to the caller but isn't persistent. That
        breaks the application's expectations (would write sensitive
        data to a token that doesn't actually persist) and is the
        lying-module masking pattern at the persistence boundary.
        """
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False, CKA_LABEL: "session-key-promote-test"},
            purpose="CKA_TOKEN promotion setup",
        )

        try:
            # Pre-check: confirm the object is genuinely session-scope.
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_TOKEN],
                label="CKA_TOKEN=False after C_GenerateKey",
                attr=CKA_TOKEN,
            )
            initial = _attribute_value(
                attrs,
                CKA_TOKEN,
                label="CKA_TOKEN=False after C_GenerateKey",
            )
            if initial is MISSING_ATTRIBUTE:
                return
            initial = _require_bool(
                initial,
                attr=CKA_TOKEN,
                label="CKA_TOKEN=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _assert_attribute(
                initial,
                False,
                attr=CKA_TOKEN,
                label="CKA_TOKEN=False after C_GenerateKey",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="policy",
            )

            # Attempt the promotion.
            try:
                set_attributes(rs.raw, rs.sh, key, {CKA_TOKEN: True})
            except CkrAssertionError as e:
                # Exact rv match (via CkrAssertionError.rv) avoids the
                # CKR_SESSION_READ_ONLY ⊂ CKR_SESSION_READ_ONLY_EXISTS
                # substring collision the older `code in msg` pattern hit.
                from pkcs11_check.raw.types_std import (
                    CKR_ACTION_PROHIBITED,
                    CKR_ATTRIBUTE_READ_ONLY,
                    CKR_ATTRIBUTE_VALUE_INVALID,
                    CKR_SESSION_READ_ONLY,
                    CKR_TEMPLATE_INCONSISTENT,
                    CKR_USER_NOT_LOGGED_IN,
                )

                if is_known_error(
                    e,
                    {
                        CKR_ATTRIBUTE_READ_ONLY,
                        CKR_ACTION_PROHIBITED,
                        CKR_USER_NOT_LOGGED_IN,
                        CKR_SESSION_READ_ONLY,
                        CKR_TEMPLATE_INCONSISTENT,
                        CKR_ATTRIBUTE_VALUE_INVALID,
                    },
                ):
                    reject_or_classify(
                        e,
                        (
                            CKR_ATTRIBUTE_READ_ONLY,
                            CKR_ACTION_PROHIBITED,
                            CKR_USER_NOT_LOGGED_IN,
                            CKR_TEMPLATE_INCONSISTENT,
                            CKR_ATTRIBUTE_VALUE_INVALID,
                        ),
                        label="CKA_TOKEN promotion",
                        kind="policy",
                    )
                    return
                raise

            # SetAttribute returned CKR_OK; verify the change actually
            # took effect at the readback level. A module that silently
            # no-ops is in the lying-module pattern.
            attrs2 = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_TOKEN],
                label="CKA_TOKEN=True after C_SetAttributeValue",
                attr=CKA_TOKEN,
            )
            final = _attribute_value(
                attrs2,
                CKA_TOKEN,
                label="CKA_TOKEN=True after C_SetAttributeValue",
            )
            if final is MISSING_ATTRIBUTE:
                return
            final = _require_bool(
                final,
                attr=CKA_TOKEN,
                label="CKA_TOKEN=True after C_SetAttributeValue",
                producer_operation="C_SetAttributeValue",
            )
            if final is MISSING_ATTRIBUTE:
                return
            if final is not True:
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_SetAttributeValue(CKA_TOKEN=True) returned CKR_OK but "
                    "readback still reports CKA_TOKEN=False. "
                    "Module silently ignored the promotion request — "
                    "caller believes object is now a token object but it "
                    "isn't.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.2 CKA_TOKEN R/W semantics",
                )
                fail_as(
                    "self_contradiction",
                    kind="lifecycle",
                    label="CKA_TOKEN:setattr-half-promoted",
                    operation="C_SetAttributeValue",
                    summary=(
                        "SECURITY: module silently ignored "
                        "C_SetAttributeValue(CKA_TOKEN=True) — half-promoted "
                        "state. Lying-module pattern at the persistence "
                        "boundary."
                    ),
                )
            # CKR_OK + readback shows True: spec-conformant promotion.
            # Persistence verification (open new session, find object)
            # is out of scope for this baseline test — see
            # test_subprocess_safety.py TestSessionObjectProcessIsolation
            # for the cross-process visibility companion.
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestKeyGenMechanism:
    """CKA_KEY_GEN_MECHANISM is auto-set and read-only."""

    def test_generated_aes_key_has_aes_key_gen(self, p11_raw_session: Any) -> None:
        """Generated AES key should have CKA_KEY_GEN_MECHANISM = CKM_AES_KEY_GEN."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False},
            purpose="CKA_KEY_GEN_MECHANISM readback setup",
        )
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_KEY_GEN_MECHANISM],
                label="AES:CKA_KEY_GEN_MECHANISM readback",
                attr=CKA_KEY_GEN_MECHANISM,
            )
            mech = _attribute_value(
                attrs,
                CKA_KEY_GEN_MECHANISM,
                label="AES:CKA_KEY_GEN_MECHANISM readback",
            )
            if mech is MISSING_ATTRIBUTE:
                return
            mech_val = _require_ulong(
                mech,
                attr=CKA_KEY_GEN_MECHANISM,
                label="AES:CKA_KEY_GEN_MECHANISM readback",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
            )
            _assert_attribute(
                mech_val,
                CKM_AES_KEY_GEN,
                attr=CKA_KEY_GEN_MECHANISM,
                label="AES:CKA_KEY_GEN_MECHANISM readback",
                producer_operation="C_GenerateKey",
                producer_mechanism="CKM_AES_KEY_GEN",
                reason="self_contradiction",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_generated_rsa_keypair_has_rsa_gen(self, p11_raw_session: Any) -> None:
        """RSA keypair should have CKA_KEY_GEN_MECHANISM = CKM_RSA_PKCS_KEY_PAIR_GEN."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                priv,
                [CKA_KEY_GEN_MECHANISM],
                label="RSA:CKA_KEY_GEN_MECHANISM readback",
                attr=CKA_KEY_GEN_MECHANISM,
            )
            mech = _attribute_value(
                attrs,
                CKA_KEY_GEN_MECHANISM,
                label="RSA:CKA_KEY_GEN_MECHANISM readback",
            )
            if mech is MISSING_ATTRIBUTE:
                return
            mech_val = _require_ulong(
                mech,
                attr=CKA_KEY_GEN_MECHANISM,
                label="RSA:CKA_KEY_GEN_MECHANISM readback",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            _assert_attribute(
                mech_val,
                CKM_RSA_PKCS_KEY_PAIR_GEN,
                attr=CKA_KEY_GEN_MECHANISM,
                label="RSA:CKA_KEY_GEN_MECHANISM readback",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                reason="self_contradiction",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_imported_key_has_unavailable(self, p11_raw_session: Any) -> None:
        """Imported key CKA_KEY_GEN_MECHANISM should be CK_UNAVAILABLE_INFORMATION."""
        rs = p11_raw_session
        key_material = bytes(range(16))  # 128-bit AES
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_KEY_GEN_MECHANISM],
                label="imported AES:CKA_KEY_GEN_MECHANISM unavailable",
                attr=CKA_KEY_GEN_MECHANISM,
            )
            mech = _attribute_value(
                attrs,
                CKA_KEY_GEN_MECHANISM,
                label="imported AES:CKA_KEY_GEN_MECHANISM unavailable",
            )
            if mech is MISSING_ATTRIBUTE:
                return
            # CK_UNAVAILABLE_INFORMATION is ~0 (all bits set).
            mech_val = _require_ulong(
                mech,
                attr=CKA_KEY_GEN_MECHANISM,
                label="imported AES:CKA_KEY_GEN_MECHANISM unavailable",
                producer_operation="C_CreateObject",
            )
            unavailable_32 = 0xFFFFFFFF
            unavailable_64 = 0xFFFFFFFFFFFFFFFF
            _assert_attribute_one_of(
                mech_val,
                (unavailable_32, unavailable_64),
                attr=CKA_KEY_GEN_MECHANISM,
                label="imported AES:CKA_KEY_GEN_MECHANISM unavailable",
                producer_operation="C_CreateObject",
                reason="self_contradiction",
                kind="metadata",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_key_gen_mechanism_read_only(self, p11_raw_session: Any) -> None:
        """CKA_KEY_GEN_MECHANISM must be read-only - reject C_SetAttributeValue."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False},
            purpose="CKA_KEY_GEN_MECHANISM read-only setup",
        )
        try:
            try:
                set_attributes(
                    rs.raw,
                    rs.sh,
                    key,
                    {CKA_KEY_GEN_MECHANISM: CKM_AES_KEY_GEN},
                )
                fail_as(
                    "accepted_invalid",
                    kind="policy",
                    label="CKA_KEY_GEN_MECHANISM:read-only-write",
                    operation="C_SetAttributeValue",
                    summary="Module accepted C_SetAttributeValue on CKA_KEY_GEN_MECHANISM",
                )
            except CkrAssertionError as exc:
                reject_or_classify(
                    exc,
                    (CKR_ATTRIBUTE_READ_ONLY, CKR_ATTRIBUTE_VALUE_INVALID),
                    label="CKA_KEY_GEN_MECHANISM:read-only-write rejected",
                    kind="policy",
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestCheckValue:
    """CKA_CHECK_VALUE (KCV) - key check value tests."""

    def test_generated_key_has_check_value(self, p11_raw_session: Any) -> None:
        """Generated AES key should have a 3-byte CKA_CHECK_VALUE."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True},
            purpose="CKA_CHECK_VALUE setup",
        )
        try:
            attrs: dict[int, Any]
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CHECK_VALUE])
            except CkrAssertionError as exc:
                if is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    attrs = {}
                else:
                    _xfail_attribute_read_reject(
                        exc,
                        label="AES:CKA_CHECK_VALUE after C_GenerateKey",
                        attr=CKA_CHECK_VALUE,
                    )
            record_count = len(classification.get_records())
            kcv = attr_or_record(
                attrs,
                CKA_CHECK_VALUE,
                label="AES:CKA_CHECK_VALUE after C_GenerateKey",
                kind="metadata",
                inherit_mechanism=False,
                optional_if_absent=True,
            )
            if kcv is MISSING_ATTRIBUTE:
                _raise_strongest(classification.get_records()[record_count:])
                pytest.skip("CKA_CHECK_VALUE is not supported")
                return
            if not isinstance(kcv, bytes) or len(kcv) != 3:
                classification.raise_for_record(
                    _record_malformed_attribute(
                        kcv,
                        attr=CKA_CHECK_VALUE,
                        label="AES:CKA_CHECK_VALUE after C_GenerateKey",
                        expected="three-byte bytes",
                        producer_operation="C_GenerateKey",
                        producer_mechanism="CKM_AES_KEY_GEN",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_imported_key_kcv_matches_ecb_encrypt(self, p11_raw_session: Any) -> None:
        """KCV should be first 3 bytes of ECB encrypt of all-zeros block."""
        rs = p11_raw_session

        # Known 128-bit AES key
        key_material = b"\x00" * 16
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            attrs: dict[int, Any]
            try:
                attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CHECK_VALUE])
            except CkrAssertionError as exc:
                if is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    attrs = {}
                else:
                    _xfail_attribute_read_reject(
                        exc,
                        label="imported AES:CKA_CHECK_VALUE",
                        attr=CKA_CHECK_VALUE,
                    )
            record_count = len(classification.get_records())
            kcv = attr_or_record(
                attrs,
                CKA_CHECK_VALUE,
                label="imported AES:CKA_CHECK_VALUE",
                kind="metadata",
                inherit_mechanism=False,
                optional_if_absent=True,
            )
            if kcv is MISSING_ATTRIBUTE:
                _raise_strongest(classification.get_records()[record_count:])
                pytest.skip("CKA_CHECK_VALUE is not supported")
                return
            if not isinstance(kcv, bytes) or len(kcv) != 3:
                classification.raise_for_record(
                    _record_malformed_attribute(
                        kcv,
                        attr=CKA_CHECK_VALUE,
                        label="imported AES:CKA_CHECK_VALUE",
                        expected="three-byte bytes",
                        producer_operation="C_CreateObject",
                    )
                )
            # FIPS-197 AES-128 known answer for key=00..00, plaintext=00..00.
            # This must remain independent of the provider under test: using its
            # own C_Encrypt output could make two wrong implementations agree.
            expected_kcv = bytes.fromhex("66e94b")
            if kcv != expected_kcv:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="AES:CKA_CHECK_VALUE vs independent AES-ECB oracle",
                    operation="C_GetAttributeValue",
                    mechanism=None,
                    inherit_mechanism=False,
                    summary="Imported AES key has an incorrect CKA_CHECK_VALUE",
                    detail={
                        "attribute": CKA_CHECK_VALUE,
                        "producer_operation": "C_CreateObject",
                        "producer_mechanism": None,
                        "comparison_mechanism": "CKM_AES_ECB",
                        "oracle": "AES-128(key=00..00, plaintext=00..00)[:3]",
                        "expected_hex": expected_kcv.hex(),
                        "actual_hex": kcv.hex(),
                    },
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_check_value_present_when_encrypt_false(self, p11_raw_session: Any) -> None:
        """A supported KCV is supplied even when CKA_ENCRYPT is false."""
        rs = p11_raw_session
        key_material = b"\x00" * 16
        expected_kcv = bytes.fromhex("66e94b")
        support: list[bool] = []
        hard_results: list[classification.Classification] = []

        for encrypt_enabled in (True, False):
            policy = "enabled" if encrypt_enabled else "disabled"
            key = import_secret_key_negotiated(
                rs,
                CKK_AES,
                key_material,
                attrs={CKA_ENCRYPT: encrypt_enabled, CKA_DECRYPT: True},
            )
            kcv: Any = MISSING_ATTRIBUTE
            try:
                attrs: dict[int, Any]
                try:
                    attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CHECK_VALUE])
                except CkrAssertionError as exc:
                    attrs = {}
                    if not is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                        hard_results.append(
                            _record_attribute_read_rejection(
                                exc,
                                label=f"imported AES ({policy}):CKA_CHECK_VALUE",
                                attr=CKA_CHECK_VALUE,
                            )
                        )
                else:
                    record_count = len(classification.get_records())
                    kcv = attr_or_record(
                        attrs,
                        CKA_CHECK_VALUE,
                        label=f"imported AES ({policy}):CKA_CHECK_VALUE",
                        kind="metadata",
                        inherit_mechanism=False,
                        optional_if_absent=True,
                    )
                    hard_results.extend(classification.get_records()[record_count:])

                if kcv is MISSING_ATTRIBUTE:
                    support.append(False)
                else:
                    support.append(True)
                    if not isinstance(kcv, bytes) or len(kcv) != 3:
                        hard_results.append(
                            _record_malformed_attribute(
                                kcv,
                                attr=CKA_CHECK_VALUE,
                                label=f"imported AES ({policy}):CKA_CHECK_VALUE",
                                expected="three-byte bytes",
                                producer_operation="C_CreateObject",
                            )
                        )
                    elif kcv != expected_kcv:
                        hard_results.append(
                            classification.record_as(
                                "wrong_result",
                                kind="crypto",
                                label=(
                                    f"imported AES ({policy}):CKA_CHECK_VALUE vs "
                                    "independent AES-ECB oracle"
                                ),
                                operation="C_GetAttributeValue",
                                inherit_mechanism=False,
                                summary="Imported AES key has an incorrect CKA_CHECK_VALUE",
                                detail={
                                    "attribute": CKA_CHECK_VALUE,
                                    "producer_operation": "C_CreateObject",
                                    "producer_mechanism": None,
                                    "comparison_mechanism": "CKM_AES_ECB",
                                    "oracle": "AES-128(key=00..00, plaintext=00..00)[:3]",
                                    "expected_hex": expected_kcv.hex(),
                                    "actual_hex": kcv.hex(),
                                    "cka_encrypt": encrypt_enabled,
                                },
                            )
                        )
            finally:
                destroy_quietly(rs.raw, rs.sh, key)

        normal_supported, disabled_supported = support
        # Normative SHALL (PKCS#11 secret_key_objects.md): an optional CKA_CHECK_VALUE,
        # if supported, is always supplied -- even when CKA_ENCRYPT is CK_FALSE. Support
        # that appears or disappears with the ENCRYPT policy contradicts that SHALL.
        if normal_supported != disabled_supported:
            hard_results.append(
                classification.record_as(
                    "self_contradiction",
                    kind="metadata",
                    label="AES:CKA_CHECK_VALUE support across CKA_ENCRYPT policy",
                    operation="C_GetAttributeValue",
                    inherit_mechanism=False,
                    summary="CKA_CHECK_VALUE support changed with CKA_ENCRYPT policy",
                    detail={
                        "attribute": CKA_CHECK_VALUE,
                        "enabled_supported": normal_supported,
                        "disabled_supported": disabled_supported,
                    },
                )
            )
        _raise_strongest(hard_results)
        if not normal_supported and not disabled_supported:
            pytest.skip("CKA_CHECK_VALUE is not supported")

    def test_same_key_material_same_kcv(self, p11_raw_session: Any) -> None:
        """Two keys with identical material should have the same CKA_CHECK_VALUE."""
        rs = p11_raw_session
        key_material = b"\xab" * 16
        key1 = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        hard_results: list[classification.Classification] = []
        kcv1: Any = MISSING_ATTRIBUTE
        try:
            attrs1: dict[int, Any]
            try:
                attrs1 = read_attributes(rs.raw, rs.sh, key1, [CKA_CHECK_VALUE])
            except CkrAssertionError as exc:
                attrs1 = {}
                if not is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    hard_results.append(
                        _record_attribute_read_rejection(
                            exc,
                            label="AES:key1 CKA_CHECK_VALUE",
                            attr=CKA_CHECK_VALUE,
                        )
                    )
            else:
                record_count = len(classification.get_records())
                kcv1 = attr_or_record(
                    attrs1,
                    CKA_CHECK_VALUE,
                    label="AES:key1 CKA_CHECK_VALUE",
                    kind="metadata",
                    inherit_mechanism=False,
                    optional_if_absent=True,
                )
                hard_results.extend(classification.get_records()[record_count:])
            if kcv1 is not MISSING_ATTRIBUTE and (not isinstance(kcv1, bytes) or len(kcv1) != 3):
                hard_results.append(
                    _record_malformed_attribute(
                        kcv1,
                        attr=CKA_CHECK_VALUE,
                        label="AES:key1 CKA_CHECK_VALUE",
                        expected="three-byte bytes",
                        producer_operation="C_CreateObject",
                    )
                )
        finally:
            # Keep the two provider objects independent and ensure key1 is
            # gone before exercising the second import path.
            destroy_quietly(rs.raw, rs.sh, key1)

        key2 = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_material,
            attrs={CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        kcv2: Any = MISSING_ATTRIBUTE
        try:
            attrs2: dict[int, Any]
            try:
                attrs2 = read_attributes(rs.raw, rs.sh, key2, [CKA_CHECK_VALUE])
            except CkrAssertionError as exc:
                attrs2 = {}
                if not is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
                    hard_results.append(
                        _record_attribute_read_rejection(
                            exc,
                            label="AES:key2 CKA_CHECK_VALUE",
                            attr=CKA_CHECK_VALUE,
                        )
                    )
            else:
                record_count = len(classification.get_records())
                kcv2 = attr_or_record(
                    attrs2,
                    CKA_CHECK_VALUE,
                    label="AES:key2 CKA_CHECK_VALUE",
                    kind="metadata",
                    inherit_mechanism=False,
                    optional_if_absent=True,
                )
                hard_results.extend(classification.get_records()[record_count:])
            if kcv2 is not MISSING_ATTRIBUTE and (not isinstance(kcv2, bytes) or len(kcv2) != 3):
                hard_results.append(
                    _record_malformed_attribute(
                        kcv2,
                        attr=CKA_CHECK_VALUE,
                        label="AES:key2 CKA_CHECK_VALUE",
                        expected="three-byte bytes",
                        producer_operation="C_CreateObject",
                    )
                )

            # Evaluate every present leg before applying the equality oracle.
            # A missing first value must not prevent evidence from key2, and a
            # malformed leg must not prevent the other leg from being checked.
            if (kcv1 is MISSING_ATTRIBUTE) != (kcv2 is MISSING_ATTRIBUTE):
                hard_results.append(
                    classification.record_as(
                        "self_contradiction",
                        kind="metadata",
                        label="AES:CKA_CHECK_VALUE support is consistent",
                        operation="C_GetAttributeValue",
                        inherit_mechanism=False,
                        summary=(
                            "Identically created AES keys disagree on CKA_CHECK_VALUE support"
                        ),
                        detail={"attribute": CKA_CHECK_VALUE},
                    )
                )
            _raise_strongest(hard_results)
            if kcv1 is MISSING_ATTRIBUTE and kcv2 is MISSING_ATTRIBUTE:
                pytest.skip("CKA_CHECK_VALUE is not supported")

            _assert_attribute(
                kcv1,
                kcv2,
                attr=CKA_CHECK_VALUE,
                label="AES:identical key material has identical CKA_CHECK_VALUE",
                producer_operation="C_CreateObject",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key2)


class TestAlwaysAuthenticate:
    """CKA_ALWAYS_AUTHENTICATE - re-authentication per-operation.

    When set on a private key, each crypto operation requires a
    C_Login(CKU_CONTEXT_SPECIFIC) call first. Complex to test and many
    modules don't support it. Tests skip gracefully.
    """

    def test_always_authenticate_readable(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_AUTHENTICATE should be readable on RSA private key."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        pub, priv = gen_rsa_keypair_or_xfail(rs, 2048)
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                priv,
                [CKA_ALWAYS_AUTHENTICATE],
                label="CKA_ALWAYS_AUTHENTICATE default after C_GenerateKeyPair",
                attr=CKA_ALWAYS_AUTHENTICATE,
            )
            val = _attribute_value(
                attrs,
                CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE default after C_GenerateKeyPair",
            )
            if val is MISSING_ATTRIBUTE:
                return
            val = _require_bool(
                val,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE default after C_GenerateKeyPair",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            _assert_attribute(
                val,
                False,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE default after C_GenerateKeyPair",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                reason="self_contradiction",
                kind="policy",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_always_authenticate_set_on_keygen(self, p11_raw_session: Any) -> None:
        """CKA_ALWAYS_AUTHENTICATE=True should be settable at keypair generation."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")

        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={CKA_ALWAYS_AUTHENTICATE: True},
            )
        except CkrAssertionError as e:
            if _is_template_error(e):
                _xfail_setup_reject(
                    e,
                    label="CKA_ALWAYS_AUTHENTICATE=True setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
            raise

        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                priv,
                [CKA_ALWAYS_AUTHENTICATE],
                label="CKA_ALWAYS_AUTHENTICATE=True after C_GenerateKeyPair",
                attr=CKA_ALWAYS_AUTHENTICATE,
            )
            val = _attribute_value(
                attrs,
                CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE=True after C_GenerateKeyPair",
            )
            if val is MISSING_ATTRIBUTE:
                return
            val = _require_bool(
                val,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE=True after C_GenerateKeyPair",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
            )
            _assert_attribute(
                val,
                True,
                attr=CKA_ALWAYS_AUTHENTICATE,
                label="CKA_ALWAYS_AUTHENTICATE=True after C_GenerateKeyPair",
                producer_operation="C_GenerateKeyPair",
                producer_mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                reason="self_contradiction",
                kind="policy",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_always_authenticate_requires_context_login(self, p11_raw_session: Any) -> None:
        """Sign with ALWAYS_AUTHENTICATE key should need CKU_CONTEXT_SPECIFIC login."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_KEY_PAIR_GEN"):
            pytest.skip("CKM_RSA_PKCS_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")

        try:
            pub, priv = gen_rsa_keypair(
                rs.raw,
                rs.sh,
                2048,
                private_attrs={
                    CKA_SIGN: True,
                    CKA_ALWAYS_AUTHENTICATE: True,
                },
            )
        except CkrAssertionError as e:
            if _is_template_error(e):
                _xfail_setup_reject(
                    e,
                    label="CKA_ALWAYS_AUTHENTICATE=True setup",
                    operation="C_GenerateKeyPair",
                    mechanism="CKM_RSA_PKCS_KEY_PAIR_GEN",
                )
            raise

        try:
            # First sign after normal login - may work (first use after login)
            data = b"test data for signing"
            try:
                sign_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, data)
            except CkrAssertionError as exc:
                # A module may require context-specific login even for the first op;
                # only the exact state errors are an expected clean refusal.
                xfail_if_known_ckr(
                    exc,
                    (CKR_USER_NOT_LOGGED_IN,),
                    "CKA_ALWAYS_AUTHENTICATE first sign requires context-specific login",
                )
                raise
            fail_as(
                "self_contradiction",
                kind="policy",
                label="CKA_ALWAYS_AUTHENTICATE:first-sign-without-reauth",
                operation="C_Sign",
                mechanism="CKM_RSA_PKCS",
                summary=(
                    "C_Sign succeeded on CKA_ALWAYS_AUTHENTICATE=True key without "
                    "a prior CKU_CONTEXT_SPECIFIC login"
                ),
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


class TestDateAttributes:
    """CKA_START_DATE / CKA_END_DATE - informational date attributes on keys.

    Per spec, these are for reference only; Cryptoki does NOT enforce them.
    """

    def test_start_end_date_on_generated_key(self, p11_raw_session: Any) -> None:
        """Generated key with START_DATE / END_DATE should have readable dates."""
        rs = p11_raw_session

        try:
            key = gen_aes_key_or_xfail(
                rs,
                256,
                attrs={
                    CKA_TOKEN: False,
                    CKA_START_DATE: "20260101",
                    CKA_END_DATE: "20271231",
                },
                purpose="date attribute setup",
            )
        except CkrAssertionError as e:
            if _is_template_error(e):
                _xfail_setup_reject(
                    e,
                    label="CKA_START_DATE / CKA_END_DATE setup",
                    operation="C_GenerateKey",
                    mechanism="CKM_AES_KEY_GEN",
                )
            raise

        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_START_DATE, CKA_END_DATE],
                label="CKA_START_DATE / CKA_END_DATE readback after C_GenerateKey",
                attr=(CKA_START_DATE, CKA_END_DATE),
            )
            sd = _attribute_value(
                attrs,
                CKA_START_DATE,
                label="CKA_START_DATE readback after C_GenerateKey",
            )
            ed = _attribute_value(
                attrs,
                CKA_END_DATE,
                label="CKA_END_DATE readback after C_GenerateKey",
            )
            hard_results: list[classification.Classification] = []
            if sd is not MISSING_ATTRIBUTE:
                start_record = _record_attribute(
                    sd,
                    "20260101",
                    attr=CKA_START_DATE,
                    label="CKA_START_DATE readback after C_GenerateKey",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                if start_record is not None:
                    hard_results.append(start_record)
            if ed is not MISSING_ATTRIBUTE:
                end_record = _record_attribute(
                    ed,
                    "20271231",
                    attr=CKA_END_DATE,
                    label="CKA_END_DATE readback after C_GenerateKey",
                    producer_operation="C_GenerateKey",
                    producer_mechanism="CKM_AES_KEY_GEN",
                )
                if end_record is not None:
                    hard_results.append(end_record)
            _raise_strongest(hard_results)
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_empty_dates_by_default(self, p11_raw_session: Any) -> None:
        """Generated key without explicit dates should have empty/default dates."""
        rs = p11_raw_session
        key = gen_aes_key_or_xfail(
            rs,
            256,
            attrs={CKA_TOKEN: False},
            purpose="default date attribute setup",
        )
        try:
            attrs = _read_attributes_or_xfail(
                rs.raw,
                rs.sh,
                key,
                [CKA_START_DATE],
                label="CKA_START_DATE default after C_GenerateKey",
                attr=CKA_START_DATE,
            )
            sd = _attribute_value(
                attrs,
                CKA_START_DATE,
                label="CKA_START_DATE default after C_GenerateKey",
            )
            if sd is MISSING_ATTRIBUTE:
                return

            # Empty date: raw API returns "" or "00000000" or similar
            if sd is not None and not isinstance(sd, (str, bytes)):
                classification.raise_for_record(
                    _record_malformed_attribute(
                        sd,
                        attr=CKA_START_DATE,
                        label="CKA_START_DATE default after C_GenerateKey",
                        expected="empty date string/bytes or None",
                        producer_operation="C_GenerateKey",
                        producer_mechanism="CKM_AES_KEY_GEN",
                    )
                )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
