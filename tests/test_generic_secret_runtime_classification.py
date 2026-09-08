"""Runtime classification regressions for generated generic secret material."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_generic_secret as generic_secret


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_missing_generated_value_records_each_size_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([101, 102, 103])
    generated: list[int] = []
    destroyed: list[int] = []

    def _generate(*_args: Any, **_kwargs: Any) -> int:
        handle = next(handles)
        generated.append(handle)
        return handle

    monkeypatch.setattr(generic_secret, "gen_aes_key_or_xfail", _generate)
    monkeypatch.setattr(generic_secret, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        generic_secret,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    generic_secret.TestGenericSecretKeyGen().test_generate_generic_secret(_session())

    assert generated == [101, 102, 103]
    assert destroyed == generated
    records = C.get_records()
    assert len(records) == 3
    assert all(record.reason == "not_operational" for record in records)
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(
        record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
        for record in records
    )


def test_missing_unique_operand_records_only_missing_operand_and_skips_compare(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([201, 202])
    monkeypatch.setattr(generic_secret, "gen_aes_key_or_xfail", lambda *_a, **_k: next(handles))
    monkeypatch.setattr(generic_secret, "read_attributes", lambda *_a, **_k: {})
    destroyed: list[int] = []
    monkeypatch.setattr(
        generic_secret,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    generic_secret.TestGenericSecretKeyGen().test_generic_secret_unique(_session())

    assert destroyed == [201, 202]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_later_invalid_generated_value_still_fails_after_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([301, 302])
    monkeypatch.setattr(generic_secret, "gen_aes_key_or_xfail", lambda *_a, **_k: next(handles))
    reads = iter([{}, {CKA_VALUE: b"too short"}])
    monkeypatch.setattr(generic_secret, "read_attributes", lambda *_a, **_k: next(reads))
    destroyed: list[int] = []
    monkeypatch.setattr(
        generic_secret,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(AssertionError):
        generic_secret.TestGenericSecretKeyGen().test_generate_generic_secret(_session())

    assert destroyed == [301, 302]
    assert [record.reason for record in C.get_records()] == ["not_operational"]
