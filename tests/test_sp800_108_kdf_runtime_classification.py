"""Runtime classification regressions for SP800-108 KDF output reads."""

from __future__ import annotations

from collections.abc import Generator
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
