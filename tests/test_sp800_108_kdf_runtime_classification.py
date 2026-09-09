"""Runtime classification regressions for SP800-108 KDF output reads."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_sp800_108_kdf


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session(mechanism: str = "SP800_108_COUNTER_KDF") -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == mechanism,
    )


def test_sp800_counter_determinism_records_missing_and_reads_pair_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    reads: list[int] = []

    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    derived = iter([11, 12])
    monkeypatch.setattr(test_sp800_108_kdf, "_sp800_derive", lambda *_args: next(derived))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 11 else {CKA_VALUE: b"second"}

    monkeypatch.setattr(test_sp800_108_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_sp800_108_kdf.TestSP800108CounterKDF().test_derive_deterministic(_session())

    assert reads == [11, 12]
    assert destroyed == [10, 11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["id"] == int(CKA_VALUE)


def test_sp800_counter_kat_treats_empty_value_as_present_and_keeps_hard_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    monkeypatch.setattr(test_sp800_108_kdf, "_sp800_derive", lambda *_args: 11)
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b""},
    )
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_sp800_108_kdf.TestSP800108CounterKDF().test_derive_aes128(_session())

    assert destroyed == [10, 11]
    assert C.get_records()[0].reason == "wrong_result"


def test_sp800_feedback_determinism_records_missing_and_reads_pair_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    reads: list[int] = []

    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    derived = iter([11, 12])
    monkeypatch.setattr(test_sp800_108_kdf, "_sp800_derive", lambda *_args: next(derived))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 11 else {CKA_VALUE: b"second"}

    monkeypatch.setattr(test_sp800_108_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_sp800_108_kdf.TestSP800108FeedbackKDF().test_derive_deterministic(
        _session("SP800_108_FEEDBACK_KDF")
    )

    assert reads == [11, 12]
    assert destroyed == [10, 11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"


def test_sp800_counter_different_labels_classifies_equal_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    derived = iter([11, 12])
    monkeypatch.setattr(test_sp800_108_kdf, "_sp800_derive", lambda *_args: next(derived))
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b"same output"},
    )
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_sp800_108_kdf.TestSP800108CounterKDF().test_different_label_produces_different_key(
            _session()
        )

    assert destroyed == [10, 11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"


def test_sp800_counter_additional_values_guard_missing_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    reads: list[int] = []
    asserted_values: list[Any] = []
    additional_refs: list[Any] = []

    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    original_additional_keys = test_sp800_108_kdf._additional_derived_keys

    def _additional_keys(_count: int, _key_bits: int) -> tuple[Any, list[Any], list[Any]]:
        derived_array, refs, keepalive = original_additional_keys(2, 128)
        additional_refs.extend(refs)
        return derived_array, refs, keepalive

    monkeypatch.setattr(test_sp800_108_kdf, "_additional_derived_keys", _additional_keys)

    def _derive(*_args: Any) -> int:
        for ref, value in zip(additional_refs, (12, 13), strict=True):
            ref.value = value
        return 11

    monkeypatch.setattr(test_sp800_108_kdf, "_sp800_derive", _derive)
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "_build_counter_kdf_mech",
        lambda: SimpleNamespace(
            _keepalive=[],
            params=SimpleNamespace(ulAdditionalDerivedKeys=0, pAdditionalDerivedKeys=None),
        ),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 12 else {CKA_VALUE: b"malformed"}

    monkeypatch.setattr(test_sp800_108_kdf, "read_attributes", _read)
    original_assert = test_sp800_108_kdf._assert_sp800_bytes

    def _assert(value: Any, **kwargs: Any) -> None:
        asserted_values.append(value)
        original_assert(value, **kwargs)

    monkeypatch.setattr(test_sp800_108_kdf, "_assert_sp800_bytes", _assert)
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(pytest.fail.Exception):
        test_sp800_108_kdf.TestSP800108CounterKDF().test_additional_derived_key_handles(_session())

    assert reads == [12, 13]
    assert asserted_values == [b"malformed"]
    assert destroyed == [11, 12, 13, 10]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[1].operation == "C_GetAttributeValue"


def test_sp800_counter_additional_missing_value_completes_without_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    additional_refs: list[Any] = []

    monkeypatch.setattr(test_sp800_108_kdf, "_create_base_key", lambda *_args: 10)
    original_additional_keys = test_sp800_108_kdf._additional_derived_keys

    def _additional_keys(_count: int, _key_bits: int) -> tuple[Any, list[Any], list[Any]]:
        derived_array, refs, keepalive = original_additional_keys(1, 128)
        additional_refs.extend(refs)
        return derived_array, refs, keepalive

    monkeypatch.setattr(test_sp800_108_kdf, "_additional_derived_keys", _additional_keys)

    def _derive(*_args: Any) -> int:
        additional_refs[0].value = 12
        return 11

    monkeypatch.setattr(
        test_sp800_108_kdf,
        "_sp800_derive",
        _derive,
    )
    monkeypatch.setattr(test_sp800_108_kdf, "read_attributes", lambda *_args: {})
    monkeypatch.setattr(
        test_sp800_108_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_sp800_108_kdf.TestSP800108CounterKDF().test_additional_derived_key_handles(_session())

    assert destroyed == [11, 12, 10]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"


def test_sp800_counter_additional_value_access_is_analyzer_clean() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "pkcs11_check" / "testcases" / "test_sp800_108_kdf.py"
    )
    from tests._attribute_access_guard import analyze_file

    assert analyze_file(source) == []
