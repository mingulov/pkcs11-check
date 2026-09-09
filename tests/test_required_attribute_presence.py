"""Regression tests for non-terminating required-attribute evidence."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_LABEL
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record


@pytest.fixture(autouse=True)
def _clear_classification() -> None:
    C.clear()
    yield
    C.clear()


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_present_false_like_values_are_not_missing(value: Any) -> None:
    attrs = {CKA_LABEL: value}

    result = attr_or_record(attrs, CKA_LABEL, label="CKA_LABEL")

    assert result is value
    assert C.get_records() == []


@pytest.mark.parametrize("reason", ["honest_deviation", "not_operational"])
def test_missing_attribute_is_structured_without_raising(reason: str) -> None:
    result = attr_or_record(
        {},
        CKA_LABEL,
        label="certificate label",
        reason=reason,  # type: ignore[arg-type] - parametrized literal values
    )

    assert result is MISSING_ATTRIBUTE
    records = C.get_records()
    assert len(records) == 1
    rec = records[0]
    assert rec.reason == reason
    assert rec.outcome == "xfail"
    assert rec.kind == "metadata"
    assert rec.operation == "C_GetAttributeValue"
    assert rec.summary == "certificate label: attribute unavailable"
    assert rec.actual_ckr is None
    assert rec.detail == {
        "attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)},
    }


def test_missing_attribute_inherits_context_and_spec_lookup() -> None:
    C.set_params({"curve": "P-256"})
    C.set_vector("attributes.json", "id=3")
    C.set_mechanism("CKM_ECDSA", operation="C_Verify")

    rec = C.get_records()[0] if C.get_records() else None
    assert rec is None
    attr_or_record({}, CKA_LABEL, label="required label")
    rec = C.get_records()[0]

    assert rec.params == {"curve": "secp256r1"}
    assert rec.source == "attributes.json" and rec.vector_id == "id=3"
    assert rec.mechanism == "CKM_ECDSA"
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue · CKM_ECDSA"


def test_missing_attribute_can_leave_stale_mechanism_unset() -> None:
    C.set_mechanism("CKM_ECDSA", operation="C_Verify")

    attr_or_record(
        {},
        CKA_LABEL,
        label="required label",
        inherit_mechanism=False,
    )

    rec = C.get_records()[0]
    assert rec.mechanism is None
    assert rec.operation == "C_GetAttributeValue"
    assert rec.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_missing_attribute_serializes_stably_without_actual_ckr() -> None:
    attr_or_record({}, CKA_LABEL, label="required label")

    rec = C.get_records()[0]
    serialized = C.serialize([rec])[0]
    assert serialized["actual_ckr"] is None
    assert serialized["detail"] == {
        "attribute": {"name": "CKA_LABEL", "id": int(CKA_LABEL)},
    }


def test_invalid_missing_attribute_reason_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid missing-attribute reason"):
        attr_or_record({}, CKA_LABEL, label="required label", reason="wrong_result")  # type: ignore[arg-type]

    assert C.get_records() == []


class _ExplodingMapping(Mapping[Any, Any]):
    def __getitem__(self, key: Any) -> Any:
        raise RuntimeError(f"lookup failed: {key!r}")

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0

    def __contains__(self, key: object) -> bool:
        raise RuntimeError(f"membership failed: {key!r}")


def test_attribute_mapping_exception_propagates() -> None:
    with pytest.raises(RuntimeError, match="membership failed"):
        attr_or_record(_ExplodingMapping(), CKA_LABEL, label="required label")

    assert C.get_records() == []


class _AccessExplodingMapping(Mapping[Any, Any]):
    def __getitem__(self, key: Any) -> Any:
        raise RuntimeError(f"access failed: {key!r}")

    def __iter__(self):
        return iter(())

    def __len__(self) -> int:
        return 0

    def __contains__(self, key: object) -> bool:
        return True


def test_attribute_access_exception_propagates() -> None:
    with pytest.raises(RuntimeError, match="access failed"):
        attr_or_record(_AccessExplodingMapping(), CKA_LABEL, label="required label")

    assert C.get_records() == []
