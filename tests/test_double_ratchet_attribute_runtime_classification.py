"""Runtime regressions for Double Ratchet derived-value readback."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases import test_double_ratchet as ratchet
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "X2RATCHET_INITIALIZE",
    )


def _patch_two_run_setup(
    monkeypatch: pytest.MonkeyPatch,
    read_results: list[dict[int, Any]],
    *,
    derive_error: BaseException | None = None,
    read_error: BaseException | None = None,
) -> list[str]:
    handles = iter(((101, 201), (102, 202), (103, 203), (104, 204)))
    derived = iter((301, 302))
    events: list[str] = []

    monkeypatch.setattr(ratchet, "_create_ec_keypair", lambda _rs: next(handles))

    def _derive_key(*_args: Any, **_kwargs: Any) -> int:
        events.append("derive")
        if derive_error is not None and len([event for event in events if event == "derive"]) == 2:
            raise derive_error
        return next(derived)

    def _read_attributes(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        events.append("read")
        if read_error is not None:
            raise read_error
        return read_results.pop(0)

    def _destroy(_raw: Any, _sh: int, handle: int) -> None:
        events.append(f"destroy:{handle}")

    monkeypatch.setattr(ratchet, "derive_key", _derive_key)
    monkeypatch.setattr(ratchet, "read_attributes", _read_attributes)
    monkeypatch.setattr(ratchet, "destroy_quietly", _destroy)
    return events


def test_missing_first_value_keeps_second_read_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_two_run_setup(monkeypatch, [{}, {CKA_VALUE: b"b" * 32}])

    ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer already lives in the label (set by every
    # caller of _read_derived_value).
    assert records[0].mechanism is None
    assert "CKM_X2RATCHET_INITIALIZE" in records[0].label
    assert records[0].detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
    }
    assert events[:6] == ["derive", "read", "destroy:301", "derive", "read", "destroy:302"]
    assert MISSING_ATTRIBUTE is not False


def test_malformed_first_value_and_missing_second_are_both_retained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_two_run_setup(monkeypatch, [{CKA_VALUE: False}, {}])

    with pytest.raises(BaseException):
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
    ]
    # records[0] ("wrong_result", malformed present value) is an unrelated
    # C_GetAttributeValue record outside the F6 fix scope and keeps its mechanism;
    # records[1] ("not_operational", missing value) is the fixed readback site.
    assert records[0].mechanism == "CKM_X2RATCHET_INITIALIZE"
    assert records[1].mechanism is None
    assert "CKM_X2RATCHET_INITIALIZE" in records[1].label
    malformed = records[0]
    assert malformed.detail is not None
    assert malformed.detail["attribute"]["actual"] == "False"


def test_equal_present_values_are_a_derive_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_two_run_setup(monkeypatch, [{CKA_VALUE: b"s" * 32}, {CKA_VALUE: b"s" * 32}])

    with pytest.raises(BaseException):
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism is None
    assert record.detail == {
        "relation": {
            "operator": "must_differ",
            "expected": "different derived CKA_VALUE outputs",
            "left": {
                "label": "CKM_X2RATCHET_INITIALIZE:first derived CKA_VALUE",
                "mechanism": "CKM_X2RATCHET_INITIALIZE",
                "operation": "C_DeriveKey",
                "length": 32,
            },
            "right": {
                "label": "CKM_X2RATCHET_INITIALIZE:second derived CKA_VALUE",
                "mechanism": "CKM_X2RATCHET_INITIALIZE",
                "operation": "C_DeriveKey",
                "length": 32,
            },
            "equal": True,
        }
    }


def test_short_first_value_is_hard_and_second_run_still_executes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_two_run_setup(monkeypatch, [{CKA_VALUE: b"a"}, {CKA_VALUE: b"b" * 32}])

    with pytest.raises(BaseException):
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_X2RATCHET_INITIALIZE"
    assert record.detail is not None
    assert record.detail["attribute"]["expected"] == "32-byte bytes"
    assert record.detail["attribute"]["actual"] == "bytes[1]"
    assert events[:6] == ["derive", "read", "destroy:301", "derive", "read", "destroy:302"]


def test_first_missing_value_survives_second_derive_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = _patch_two_run_setup(
        monkeypatch,
        [{}],
        derive_error=CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        ),
    )

    with pytest.raises(BaseException):
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "not_operational"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert "CKM_X2RATCHET_INITIALIZE" in records[0].label
    assert records[1].operation == "C_DeriveKey"
    assert records[1].mechanism == "CKM_X2RATCHET_INITIALIZE"
    assert events[:4] == ["derive", "read", "destroy:301", "derive"]


def test_first_malformed_value_remains_hard_when_second_derive_rejects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_two_run_setup(
        monkeypatch,
        [{CKA_VALUE: False}],
        derive_error=CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_INVALID",
            int(CKR_MECHANISM_INVALID),
        ),
    )

    with pytest.raises(BaseException):
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_X2RATCHET_INITIALIZE"
    assert records[1].operation == "C_DeriveKey"
    assert records[1].mechanism == "CKM_X2RATCHET_INITIALIZE"
    assert records[1].actual_ckr == "CKR_MECHANISM_INVALID"


def test_attribute_reader_ckr_is_not_misattributed_to_derive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader_error = CkrAssertionError(
        "Unexpected CK_RV CKR_ATTRIBUTE_TYPE_INVALID",
        int(CKR_ATTRIBUTE_TYPE_INVALID),
    )
    _patch_two_run_setup(monkeypatch, [], read_error=reader_error)

    with pytest.raises(CkrAssertionError) as exc_info:
        ratchet.TestX2RatchetDerive().test_x2ratchet_initialize_two_runs_differ(_session())

    assert exc_info.value.rv == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert C.get_records() == []


def test_double_ratchet_attribute_access_slice_is_analyzer_clean() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_double_ratchet.py"
    )
    assert analyze_file(source) == []
