"""Metadata-object probes must not turn harness/provider defects into absence."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_HAS_RESET,
    CKA_HW_FEATURE_TYPE,
    CKA_RESET_ON_INIT,
    CKA_VALIDATION_AUTHORITY_TYPE,
    CKA_VALIDATION_LEVEL,
    CKA_VALIDATION_MODULE_ID,
    CKA_VALIDATION_TYPE,
    CKV_TYPE_SOFTWARE,
)
from pkcs11_check.testcases import test_hw_features as hw
from pkcs11_check.testcases import test_mechanism_objects as mechanisms
from pkcs11_check.testcases import test_profiles as profiles
from pkcs11_check.testcases import test_validation_objects as validation
from tests._attribute_access_guard import analyze_paths


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def test_mechanism_enumeration_plain_assertion_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mechanisms,
        "find_objects",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        mechanisms._mechanism_objects(SimpleNamespace(raw=object(), sh=1))


def test_hw_type_plain_assertion_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hw,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        hw._hw_type(SimpleNamespace(raw=object(), sh=1), 1)


def test_missing_hw_type_records_and_later_objects_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        reads.append(handle)
        return {} if handle == 1 else {CKA_HW_FEATURE_TYPE: int(hw.CKH_CLOCK)}

    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1, 2])
    monkeypatch.setattr(hw, "read_attributes", _read)

    clocks = hw.TestHwFeatureClock()._get_clock_features(SimpleNamespace(raw=object(), sh=1))

    assert clocks == [2]
    assert reads == [1, 2]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.severity == "LOW"
    assert record.kind == "metadata"
    assert record.label == "CKA_HW_FEATURE_TYPE:hardware-feature"
    assert record.operation == "C_GetAttributeValue"
    assert record.summary == "CKA_HW_FEATURE_TYPE:hardware-feature: attribute unavailable"
    assert record.detail == {
        "attribute": {"name": "CKA_HW_FEATURE_TYPE", "id": int(CKA_HW_FEATURE_TYPE)},
    }


def test_missing_counter_type_records_and_later_objects_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        reads.append(handle)
        return {} if handle == 1 else {CKA_HW_FEATURE_TYPE: int(hw.CKH_MONOTONIC_COUNTER)}

    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1, 2])
    monkeypatch.setattr(hw, "read_attributes", _read)

    counters = hw.TestHwFeatureCounter()._get_counter_features(SimpleNamespace(raw=object(), sh=1))

    assert counters == [2]
    assert reads == [1, 2]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].label == "CKA_HW_FEATURE_TYPE:hardware-feature"
    assert records[0].detail == {
        "attribute": {"name": "CKA_HW_FEATURE_TYPE", "id": int(CKA_HW_FEATURE_TYPE)},
    }


class _ComparisonHostileSentinel:
    def __eq__(self, other: object) -> bool:
        raise AssertionError("missing sentinel must be checked by identity")


@pytest.mark.parametrize(
    ("selector", "selected_type", "expected"),
    [
        ("clock", hw.CKH_CLOCK, [2]),
        ("counter", hw.CKH_MONOTONIC_COUNTER, [2]),
    ],
)
def test_selector_guards_missing_sentinel_before_comparison(
    monkeypatch: pytest.MonkeyPatch,
    selector: str,
    selected_type: int,
    expected: list[int],
) -> None:
    missing = _ComparisonHostileSentinel()
    values = iter((missing, int(selected_type)))
    monkeypatch.setattr(hw, "MISSING_ATTRIBUTE", missing)
    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1, 2])
    monkeypatch.setattr(hw, "_hw_type", lambda _rs, _handle: next(values))

    method = (
        hw.TestHwFeatureClock()._get_clock_features
        if selector == "clock"
        else hw.TestHwFeatureCounter()._get_counter_features
    )
    selected = method(SimpleNamespace(raw=object(), sh=1))

    assert selected == expected


@pytest.mark.parametrize(
    ("selector", "selected_type", "expected"),
    [
        ("clock", hw.CKH_CLOCK, [2]),
        ("counter", hw.CKH_MONOTONIC_COUNTER, [3]),
    ],
)
def test_present_false_like_and_standard_hw_types_keep_selection_semantics(
    monkeypatch: pytest.MonkeyPatch,
    selector: str,
    selected_type: int,
    expected: list[int],
) -> None:
    values = {
        1: 0,
        2: int(hw.CKH_CLOCK),
        3: int(hw.CKH_MONOTONIC_COUNTER),
        4: int(hw.CKH_USER_INTERFACE),
    }
    reads: list[int] = []

    def _type(_rs: object, handle: int) -> int:
        reads.append(handle)
        return values[handle]

    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1, 2, 3, 4])
    monkeypatch.setattr(hw, "_hw_type", _type)

    method = (
        hw.TestHwFeatureClock()._get_clock_features
        if selector == "clock"
        else hw.TestHwFeatureCounter()._get_counter_features
    )
    selected = method(SimpleNamespace(raw=object(), sh=1))

    assert selected == expected
    assert values[expected[0]] == selected_type
    assert reads == [1, 2, 3, 4]


def test_malformed_present_hw_type_remains_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1])
    monkeypatch.setattr(
        hw,
        "read_attributes",
        lambda *_a, **_k: {CKA_HW_FEATURE_TYPE: object()},
    )

    with pytest.raises(AssertionError, match="Expected int or bytes CKA_HW_FEATURE_TYPE"):
        hw.TestHwFeatureClock()._get_clock_features(SimpleNamespace(raw=object(), sh=1))


def test_f7_hw_feature_attribute_access_scoped_analyzer_is_clean() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "test_hw_features.py"
    )

    assert analyze_paths([source]) == []


def test_missing_counter_reset_fields_record_both_and_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, bool]:
        reads.append(handle)
        return {}

    monkeypatch.setattr(hw.TestHwFeatureCounter, "_get_counter_features", lambda _self, _rs: [3, 4])
    monkeypatch.setattr(hw, "read_attributes", _read)

    hw.TestHwFeatureCounter().test_counter_reset_attributes(SimpleNamespace(raw=object(), sh=1))

    assert reads == [3, 4]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_RESET_ON_INIT),
        int(CKA_HAS_RESET),
        int(CKA_RESET_ON_INIT),
        int(CKA_HAS_RESET),
    ]


def test_missing_required_validation_type_records_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        reads.append(handle)
        return {} if handle == 5 else {CKA_VALIDATION_TYPE: int(CKV_TYPE_SOFTWARE)}

    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_a: [5, 6])
    monkeypatch.setattr(validation, "read_attributes", _read)

    validation.TestValidationObjects().test_validation_type_is_known(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert reads == [5, 6]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_VALIDATION_TYPE)
    ]


def test_missing_required_validation_level_records_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        reads.append(handle)
        return {} if handle == 7 else {CKA_VALIDATION_LEVEL: 3}

    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_a: [7, 8])
    monkeypatch.setattr(validation, "read_attributes", _read)

    validation.TestValidationObjects().test_validation_level_is_readable(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert reads == [7, 8]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_VALIDATION_LEVEL)
    ]


@pytest.mark.parametrize(
    ("method_name", "attribute", "label"),
    [
        (
            "test_validation_authority_type_is_known",
            CKA_VALIDATION_AUTHORITY_TYPE,
            "CKA_VALIDATION_AUTHORITY_TYPE:validation-object",
        ),
        (
            "test_validation_module_id_is_string",
            CKA_VALIDATION_MODULE_ID,
            "CKA_VALIDATION_MODULE_ID:validation-object",
        ),
    ],
)
def test_missing_required_validation_attributes_record_and_continue(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    attribute: int,
    label: str,
) -> None:
    reads: list[int] = []

    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_a: [9, 10])

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, object]:
        reads.append(handle)
        return {}

    monkeypatch.setattr(validation, "read_attributes", _read)

    getattr(validation.TestValidationObjects(), method_name)(SimpleNamespace(raw=object(), sh=1))

    assert reads == [9, 10]
    records = C.get_records()
    assert len(records) == 2
    for record in records:
        assert record.reason == "honest_deviation"
        assert record.outcome == "xfail"
        assert record.severity == "LOW"
        assert record.kind == "metadata"
        assert record.label == label
        assert record.operation == "C_GetAttributeValue"
        assert record.summary == f"{label}: attribute unavailable"
        assert record.detail == {
            "attribute": {"name": label.split(":", 1)[0], "id": int(attribute)},
        }
        assert record.expected_ckr is None
        assert record.actual_ckr is None
        assert record.mechanism is None
        assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
        assert record.source is None
        assert record.vector_id is None
        assert record.params is None


def test_profile_id_read_failure_is_not_empty_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(profiles, "find_objects", lambda *_a, **_k: [1])
    monkeypatch.setattr(
        profiles,
        "read_attributes",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("harness bug")),
    )
    with pytest.raises(AssertionError, match="harness bug"):
        profiles._read_profile_ids(SimpleNamespace(raw=object(), sh=1))


def test_mechanism_read_only_acceptance_is_a_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mechanisms, "_mechanism_objects", lambda _rs: [1])
    monkeypatch.setattr(mechanisms, "set_attributes", lambda *_a, **_k: None)
    with pytest.raises(Failed, match="read-only CKO_MECHANISM"):
        mechanisms.TestMechanismObjects().test_mechanism_objects_are_read_only(
            SimpleNamespace(raw=object(), sh=1)
        )
