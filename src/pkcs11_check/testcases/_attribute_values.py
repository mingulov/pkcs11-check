"""Attribute value validation helpers for testcases."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final, Literal

from pkcs11_check.classification import record_as, xfail_as
from pkcs11_check.raw.metadata_std import ATTR_NAMES
from pkcs11_check.raw.recipes import AttrRefusal
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID

MISSING_ATTRIBUTE: Final[object] = object()


def _refusal_for(attrs: Mapping[Any, Any], attr: Any) -> AttrRefusal | None:
    """Return the :class:`AttrRefusal` for ``attr``, if ``read_attributes`` observed one.

    ``attrs`` is normally an ``AttrReadResult`` (a ``dict`` subclass carrying an
    additive ``refusals`` channel); any other ``Mapping`` -- e.g. a plain dict built
    by a test double -- simply has no such channel, so this returns ``None`` rather
    than inventing a CKR.
    """
    refusals = getattr(attrs, "refusals", None)
    if not refusals:
        return None
    result = refusals.get(attr)
    return result if isinstance(result, AttrRefusal) else None


def _sentinel_without_ckr(attrs: Mapping[Any, Any], attr: Any) -> bool:
    """Whether the CK_UNAVAILABLE_INFORMATION sentinel was observed for ``attr``.

    True only when ``read_attributes`` saw the sentinel on a CKR_OK read (its
    additive ``unavailable_without_ckr`` channel); a plain ``Mapping`` with no
    such channel -- e.g. a test double modelling an unsupported attribute --
    reports ``False``.
    """
    observed = getattr(attrs, "unavailable_without_ckr", None)
    if not observed:
        return False
    try:
        return attr in observed
    except TypeError:
        return False


def attr_or_record(
    attrs: Mapping[Any, Any],
    attr: Any,
    *,
    label: str,
    reason: Literal["honest_deviation", "not_operational"] = "honest_deviation",
    kind: str = "metadata",
    mechanism: str | None = None,
    inherit_mechanism: bool = True,
    sensitive_is_conformant: bool = False,
    optional_if_absent: bool = False,
) -> Any:
    """Return an attribute or record its absence without terminating the test.

    The absence is always retained as a distinguishable observation: when
    ``read_attributes`` observed an actual refusal CKR for ``attr`` (carried via
    its additive ``refusals`` channel), that CKR rides on the emitted record as
    ``actual_ckr`` -- never invented when no CKR was actually observed.

    Whether a ``CKR_ATTRIBUTE_SENSITIVE`` refusal is *conformant* or a *defect*
    depends on whether ``attr`` could legitimately be sensitive, which only the
    call site knows (e.g. CKA_VALUE of a CKA_SENSITIVE key or a private-key
    component: conformant; CKA_CLASS, CKA_LABEL, or another public metadata
    attribute: a defect -- a module refusing to disclose its own object class
    is hiding behaviour). Pass ``sensitive_is_conformant=True`` only for the
    former; the default (``False``) keeps a bare CKR_ATTRIBUTE_SENSITIVE
    refusal classified as ``reason`` (a deviation), same as CKR_ATTRIBUTE_TYPE_INVALID
    and a plain no-CKR absence -- so existing call sites are unaffected unless
    they opt in.

    ``optional_if_absent=True`` is reserved for attributes the specification
    explicitly makes optional. Two shapes then return ``MISSING_ATTRIBUTE``
    without recording a deviation: an affirmative CKR_ATTRIBUTE_TYPE_INVALID
    refusal (the module positively states it has no such attribute) and a
    plain omission with nothing observed at all (an unsupported attribute).
    But CKR_OK plus the CK_UNAVAILABLE_INFORMATION sentinel -- success
    claimed, no value delivered -- is a spec-shape deviation and is recorded
    exactly as the default path records it. Other refusal codes remain
    visible, and a refusal-with-data remains a finding.

    A refusal-with-data (the module answered a refusal CKR but still wrote real
    attribute bytes into the template) is always a self-contradiction and is
    always recorded as one, regardless of ``sensitive_is_conformant`` -- and the
    value is never returned as present. Only bounded length metadata is ever
    recorded; the bytes themselves never appear in any record.
    """
    if reason not in ("honest_deviation", "not_operational"):
        raise ValueError(f"invalid missing-attribute reason: {reason!r}")
    if attr in attrs:
        return attrs[attr]

    try:
        attr_id: int | None = int(attr)
    except (TypeError, ValueError, OverflowError):
        attr_id = None
    attr_name = ATTR_NAMES.get(attr_id, str(attr)) if attr_id is not None else str(attr)
    detail: dict[str, Any] = {"attribute": {"name": attr_name, "id": attr_id}}

    refusal = _refusal_for(attrs, attr)

    if refusal is not None and refusal.leaked_len is not None:
        # Self-contradiction: the module answered a refusal CKR for this attribute
        # but still wrote real bytes into the template -- a finding regardless of
        # whether this attribute could legitimately be sensitive. Bounded length
        # only; the bytes themselves are never carried into the record.
        detail["leaked_len"] = refusal.leaked_len
        record_as(
            "self_contradiction",
            kind="policy",
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            inherit_mechanism=inherit_mechanism,
            actual=refusal.ckr,
            summary=(
                f"{label}: module answered {ckr_name(refusal.ckr)} for this attribute "
                f"but still wrote {refusal.leaked_len} bytes into the template"
            ),
            detail=detail,
        )
        return MISSING_ATTRIBUTE

    if optional_if_absent and refusal is not None and refusal.ckr == CKR_ATTRIBUTE_TYPE_INVALID:
        return MISSING_ATTRIBUTE
    if optional_if_absent and refusal is None and not _sentinel_without_ckr(attrs, attr):
        # Plain omission: nothing was observed for this attribute at all. A
        # CKR_OK-plus-sentinel observation falls through and is recorded like
        # the default path (F20).
        return MISSING_ATTRIBUTE

    if sensitive_is_conformant and refusal is not None and refusal.ckr == CKR_ATTRIBUTE_SENSITIVE:
        record_as(
            "sanctioned_refusal",
            kind=kind,
            label=label,
            operation="C_GetAttributeValue",
            mechanism=mechanism,
            inherit_mechanism=inherit_mechanism,
            actual=refusal.ckr,
            summary=f"{label}: attribute sensitive (conformant refusal)",
            detail=detail,
        )
        return MISSING_ATTRIBUTE

    record_as(
        reason,
        kind=kind,
        label=label,
        operation="C_GetAttributeValue",
        mechanism=mechanism,
        inherit_mechanism=inherit_mechanism,
        actual=refusal.ckr if refusal is not None else None,
        summary=f"{label}: attribute unavailable",
        detail=detail,
    )
    return MISSING_ATTRIBUTE


def require_ulong_attr(value: Any, label: str) -> int:
    """Return a CK_ULONG-valued attribute or xfail malformed readback."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    xfail_as(
        "not_operational",
        kind="metadata",
        label=label,
        summary=f"{label}: malformed CK_ULONG attribute value: {value!r}",
    )


def require_bool_attr(value: Any, label: str) -> bool:
    """Return a CK_BBOOL-valued attribute or xfail malformed readback."""
    if isinstance(value, bool):
        return value
    xfail_as(
        "not_operational",
        kind="metadata",
        label=label,
        summary=f"{label}: malformed CK_BBOOL attribute value: {value!r}",
    )
