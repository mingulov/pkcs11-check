"""Default-attribute checks preserve unavailable provider metadata."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_LOCAL,
    CKA_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases import test_attribute_defaults as defaults
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def test_read_attr_missing_response_records_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(defaults, "read_attributes", lambda *_a, **_k: {})

    value = defaults._read_attr(object(), 1, 2, CKA_SENSITIVE)

    assert value is MISSING_ATTRIBUTE
    record = C.get_records()[0]
    assert record.reason == "honest_deviation"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None


def test_read_attr_exact_type_invalid_keeps_direct_ckr_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("attribute unsupported", int(CKR_ATTRIBUTE_TYPE_INVALID))

    monkeypatch.setattr(defaults, "read_attributes", _read)

    value = defaults._read_attr(object(), 1, 2, CKA_SENSITIVE)

    assert value is MISSING_ATTRIBUTE
    assert C.get_records()[0].actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def test_read_attr_unexpected_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise CkrAssertionError("device failed", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(defaults, "read_attributes", _read)

    with pytest.raises(CkrAssertionError) as exc_info:
        defaults._read_attr(object(), 1, 2, CKA_SENSITIVE)

    assert exc_info.value.rv == int(CKR_DEVICE_ERROR)
    assert C.get_records() == []


def test_paired_default_invariant_records_both_missing_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[int] = []

    def _read(_raw: object, _sh: int, _handle: int, attrs: list[int]) -> dict[int, Any]:
        requested.extend(attrs)
        return {}

    monkeypatch.setattr(defaults, "read_attributes", _read)
    aes_key = (SimpleNamespace(raw=object(), sh=1), 3)

    defaults.TestSecretKeyDefaults().test_always_sensitive_consistent(aes_key)

    assert requested == [int(CKA_SENSITIVE), int(CKA_ALWAYS_SENSITIVE)]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_SENSITIVE),
        int(CKA_ALWAYS_SENSITIVE),
    ]


def test_direct_default_read_missing_records_without_keyerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(defaults, "read_attributes", lambda *_a, **_k: {})
    aes_key = (SimpleNamespace(raw=object(), sh=1), 5)

    defaults.TestSecretKeyDefaults().test_local_is_true(aes_key)

    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_LOCAL)
    ]
