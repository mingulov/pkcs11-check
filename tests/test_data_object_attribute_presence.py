"""Data-object readback must preserve missing-attribute evidence and cleanup."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_APPLICATION, CKA_CLASS, CKA_LABEL
from pkcs11_check.testcases import test_data_objects as data_objects


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def test_missing_written_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(data_objects, "create_object", lambda *_a, **_k: 11)
    monkeypatch.setattr(data_objects, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        data_objects,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    data_objects.TestDataObjectReadValue().test_read_value_matches_written(_session())

    assert destroyed == [11]
    assert [(rec.reason, rec.operation) for rec in C.get_records()] == [
        ("not_operational", "C_GetAttributeValue")
    ]


def test_missing_label_does_not_hide_present_application_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(data_objects, "create_object", lambda *_a, **_k: 13)
    monkeypatch.setattr(
        data_objects,
        "read_attributes",
        lambda *_a, **_k: {CKA_APPLICATION: "wrong-application"},
    )
    monkeypatch.setattr(data_objects, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        data_objects.TestDataObjectReadValue().test_read_label_and_application(_session())

    missing = [(rec.reason, rec.detail["attribute"]["id"]) for rec in C.get_records() if rec.detail]
    assert missing == [("not_operational", int(CKA_LABEL))]


def test_missing_class_records_required_metadata_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(data_objects, "create_object", lambda *_a, **_k: 17)
    monkeypatch.setattr(data_objects, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        data_objects,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    data_objects.TestDataObjectReadValue().test_object_class_is_data(_session())

    assert destroyed == [17]
    record = C.get_records()[0]
    assert record.reason == "honest_deviation"
    assert record.detail == {"attribute": {"name": "CKA_CLASS", "id": int(CKA_CLASS)}}


def test_missing_search_label_continues_to_later_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([19])
    monkeypatch.setattr(data_objects, "_unique_label", lambda *_a: "wanted")
    monkeypatch.setattr(data_objects, "create_object", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(data_objects, "find_objects", lambda *_a: [21, 22])

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 21 else {CKA_LABEL: "wanted"}

    monkeypatch.setattr(data_objects, "read_attributes", _read)
    monkeypatch.setattr(data_objects, "destroy_quietly", lambda *_a: None)

    data_objects.TestDataObjectSearch().test_search_by_class_only(_session())

    assert [rec.reason for rec in C.get_records()] == ["not_operational"]
