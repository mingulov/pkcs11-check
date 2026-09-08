"""Attribute value validation helpers for testcases."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final, Literal

from pkcs11_check.classification import record_as, xfail_as
from pkcs11_check.raw.metadata_std import ATTR_NAMES

MISSING_ATTRIBUTE: Final[object] = object()


def attr_or_record(
    attrs: Mapping[Any, Any],
    attr: Any,
    *,
    label: str,
    reason: Literal["honest_deviation", "not_operational"] = "honest_deviation",
    kind: str = "metadata",
) -> Any:
    """Return an attribute or record its absence without terminating the test."""
    if reason not in ("honest_deviation", "not_operational"):
        raise ValueError(f"invalid missing-attribute reason: {reason!r}")
    if attr in attrs:
        return attrs[attr]

    try:
        attr_id: int | None = int(attr)
    except (TypeError, ValueError, OverflowError):
        attr_id = None
    attr_name = ATTR_NAMES.get(attr_id, str(attr)) if attr_id is not None else str(attr)
    record_as(
        reason,
        kind=kind,
        label=label,
        operation="C_GetAttributeValue",
        summary=f"{label}: attribute unavailable",
        detail={"attribute": {"name": attr_name, "id": attr_id}},
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
