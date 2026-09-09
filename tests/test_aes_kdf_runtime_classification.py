"""Runtime classification regressions for AES data-encryption KDFs."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_aes_kdf


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_ecb_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 11)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 12)
    monkeypatch.setattr(test_aes_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    assert destroyed == [12, 11]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


def test_cbc_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 21)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 22)
    monkeypatch.setattr(test_aes_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_aes_kdf.TestAESCBCEncryptData().test_derive_basic(_session())

    assert destroyed == [22, 21]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecb_pair_reads_both_missing_outputs_before_skipping_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    derived = iter([31, 32])
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 30)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(test_aes_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_aes_kdf.TestAESECBEncryptData().test_derive_deterministic(_session())

    assert destroyed == [32, 31, 30]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_cbc_pair_reads_present_and_missing_output_before_skipping_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    derived = iter([41, 42])
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 40)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: next(derived))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 41 else {CKA_VALUE: b"x" * 16}

    monkeypatch.setattr(test_aes_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_aes_kdf.TestAESCBCEncryptData().test_derive_deterministic(_session())

    assert destroyed == [42, 41, 40]
    assert len(C.get_records()) == 1
    assert C.get_records()[0].reason == "not_operational"


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_present_false_like_derived_value_is_not_missing(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 50)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 51)
    monkeypatch.setattr(test_aes_kdf, "read_attributes", lambda *_a, **_k: {CKA_VALUE: value})
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises((AssertionError, TypeError)):
        test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    assert C.get_records() == []


def test_later_crypto_mismatch_remains_failure_after_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 60)
    derived = iter([61, 62])
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: next(derived))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_VALUE: b"a" * 16} if handle == 61 else {CKA_VALUE: b"b" * 16}

    monkeypatch.setattr(test_aes_kdf, "read_attributes", _read)
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        test_aes_kdf.TestAESECBEncryptData().test_derive_deterministic(_session())

    assert C.get_records() == []


def test_reader_exception_propagates_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 70)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 71)

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        raise RuntimeError("unexpected attribute reader failure")

    monkeypatch.setattr(test_aes_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(RuntimeError, match="unexpected attribute reader failure"):
        test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    assert destroyed == [71, 70]
    assert C.get_records() == []


def test_all_zero_derived_value_remains_a_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 80)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 81)
    monkeypatch.setattr(
        test_aes_kdf,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16},
    )
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError, match="all zeros"):
        test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    assert C.get_records() == []
