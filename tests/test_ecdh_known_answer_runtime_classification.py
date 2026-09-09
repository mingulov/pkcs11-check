"""Runtime classification regressions for ECDH known-answer consumers."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_VALUE
from pkcs11_check.testcases import _ec_export, test_ecdh_known_answer
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _wrap_octet_string(value: bytes) -> bytes:
    assert len(value) < 128
    return b"\x04" + bytes([len(value)]) + value


def _p256_point() -> bytes:
    return (
        ec.derive_private_key(17, ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


def _p384_point() -> bytes:
    return (
        ec.derive_private_key(19, ec.SECP384R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_provider_point_consumer_accepts_and_normalizes_operational_encodings(
    monkeypatch: pytest.MonkeyPatch,
    wrapped: bool,
) -> None:
    point = _p256_point()
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_a, **_k: {CKA_EC_POINT: _wrap_octet_string(point) if wrapped else point},
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    assert test_ecdh_known_answer._ec_point_from_handle(rs, 2) == point
    assert C.get_records() == []


def test_provider_point_consumer_records_malformed_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_a, **_k: {CKA_EC_POINT: b"\x04\x03\x04\x01"},
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(pytest.xfail.Exception):
        test_ecdh_known_answer._ec_point_from_handle(rs, 2)

    assert C.get_records()[0].reason == "not_operational"


def test_provider_point_consumer_keeps_wrong_curve_as_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_a, **_k: {CKA_EC_POINT: _wrap_octet_string(_p384_point())},
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer._ec_point_from_handle(rs, 2)

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.outcome == "fail"


def test_missing_derived_value_records_without_inventing_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", lambda *_a, **_k: {})
    rs = SimpleNamespace(raw=object(), sh=1)

    value = test_ecdh_known_answer._read_value_or_record(rs, 2, label="derived secret")

    assert value is MISSING_ATTRIBUTE
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.actual_ckr is None
    assert record.operation == "C_GetAttributeValue"
    assert record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_false_like_derived_values_remain_present(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: value},
    )
    rs = SimpleNamespace(raw=object(), sh=1)

    assert test_ecdh_known_answer._read_value_or_record(rs, 2, label="derived secret") is value
    assert C.get_records() == []


def test_symmetric_agreement_reads_both_missing_secrets_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(test_ecdh_known_answer, "_ec_point_from_handle", lambda *_a: _p256_point())
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "not_operational",
    ]
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_cleans_first_pair_when_second_generation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    destroyed: list[int] = []

    def generate(_rs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 11, 12
        raise RuntimeError("second keypair failed")

    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", generate)
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)

    with pytest.raises(RuntimeError, match="second keypair failed"):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert destroyed == [11, 12]
