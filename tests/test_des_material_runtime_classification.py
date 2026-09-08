"""Runtime classification regressions for generated DES key material."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_des


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_missing_generated_des_value_continues_ten_generations_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter(range(501, 511))
    generated: list[int] = []
    destroyed: list[int] = []

    def _generate(*_args: Any, **_kwargs: Any) -> int:
        handle = next(handles)
        generated.append(handle)
        return handle

    monkeypatch.setattr(test_des, "_gen_des_key", _generate)
    monkeypatch.setattr(test_des, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_des,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_des.TestDESWeakKeys().test_des_keygen_avoids_weak_keys(_session())

    assert generated == list(range(501, 511))
    assert destroyed == generated
    records = C.get_records()
    assert len(records) == 10
    assert all(record.reason == "not_operational" for record in records)
    assert all(
        record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
        for record in records
    )


def test_later_weak_key_failure_survives_prior_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([601, 602])
    monkeypatch.setattr(test_des, "_gen_des_key", lambda *_a, **_k: next(handles))
    reads = iter([{}, {CKA_VALUE: bytes.fromhex("0101010101010101")}])
    monkeypatch.setattr(test_des, "read_attributes", lambda *_a, **_k: next(reads))
    destroyed: list[int] = []
    monkeypatch.setattr(
        test_des,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(AssertionError, match="known weak key"):
        test_des.TestDESWeakKeys().test_des_keygen_avoids_weak_keys(_session())

    assert destroyed == [601, 602]
    assert [record.reason for record in C.get_records()] == ["not_operational"]
