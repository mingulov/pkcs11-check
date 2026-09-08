"""Metadata-object probes must not turn harness/provider defects into absence."""

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_HAS_RESET,
    CKA_HW_FEATURE_TYPE,
    CKA_RESET_ON_INIT,
    CKA_VALIDATION_LEVEL,
    CKA_VALIDATION_TYPE,
    CKV_TYPE_SOFTWARE,
)
from pkcs11_check.testcases import test_hw_features as hw
from pkcs11_check.testcases import test_mechanism_objects as mechanisms
from pkcs11_check.testcases import test_profiles as profiles
from pkcs11_check.testcases import test_validation_objects as validation
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


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
    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, int]:
        return {} if handle == 1 else {CKA_HW_FEATURE_TYPE: int(hw.CKH_CLOCK)}

    monkeypatch.setattr(hw, "_hw_features", lambda _rs: [1, 2])
    monkeypatch.setattr(hw, "read_attributes", _read)

    clocks = hw.TestHwFeatureClock()._get_clock_features(SimpleNamespace(raw=object(), sh=1))

    assert clocks == [2]
    assert hw._hw_type(SimpleNamespace(raw=object(), sh=1), 1) is MISSING_ATTRIBUTE
    assert [rec.label for rec in C.get_records()] == [
        "CKA_HW_FEATURE_TYPE:hardware-feature",
        "CKA_HW_FEATURE_TYPE:hardware-feature",
    ]


def test_missing_counter_reset_fields_record_both_and_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, bool]:
        reads.append(handle)
        return {}

    monkeypatch.setattr(hw.TestHwFeatureCounter, "_get_counter_features", lambda _self, _rs: [3, 4])
    monkeypatch.setattr(hw, "read_attributes", _read)

    hw.TestHwFeatureCounter().test_counter_reset_attributes(
        SimpleNamespace(raw=object(), sh=1)
    )

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
    "method_name",
    ["test_validation_authority_type_is_known", "test_validation_module_id_is_string"],
)
def test_absent_optional_validation_attributes_remain_silent(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    monkeypatch.setattr(validation, "_find_validation_objects", lambda *_a: [9])
    monkeypatch.setattr(validation, "read_attributes", lambda *_a, **_k: {})

    getattr(validation.TestValidationObjects(), method_name)(
        SimpleNamespace(raw=object(), sh=1)
    )

    assert C.get_records() == []


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
