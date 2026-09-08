"""Runtime classification regressions for large-object value readback."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.testcases import test_large_objects as large_objects


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


@pytest.mark.parametrize(
    ("method_name", "label"),
    [
        ("test_1mb_data_object", "CKO_DATA:1MB CKA_VALUE readback"),
        ("test_100kb_data_object", "CKO_DATA:100KB CKA_VALUE readback"),
    ],
)
def test_missing_written_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    label: str,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(large_objects, "skip_if_data_objects_unsupported", lambda _rs: None)
    monkeypatch.setattr(large_objects, "create_object", lambda *_a, **_k: 401)
    monkeypatch.setattr(large_objects, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        large_objects,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    getattr(large_objects.TestLargeDataObjects(), method_name)(_session())

    assert destroyed == [401]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].label == label
