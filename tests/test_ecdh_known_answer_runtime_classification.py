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
from pkcs11_check.testcases._ec_export import ConventionalECPoint
from tests._attribute_access_guard import analyze_file


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


def _conventional_p256_point() -> ConventionalECPoint:
    point = _p256_point()
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
    return ConventionalECPoint(point, point, public_key)


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

    assert test_ecdh_known_answer._ec_point_from_handle(rs, 2).sec1_bytes == point
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


def test_missing_derived_value_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", lambda *_a, **_k: {})

    value = test_ecdh_known_answer._read_value_or_record(
        SimpleNamespace(raw=object(), sh=1),
        2,
        label="derived secret",
    )

    assert value is MISSING_ATTRIBUTE
    record = C.get_records()[0]
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_malformed_derived_value_drops_stale_active_mechanism() -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")

    record = test_ecdh_known_answer._validate_derived_value(
        b"short",
        leg="crossverify",
        label="derived secret",
    )

    assert record is not None
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_crossverify_rejects_malformed_present_secret_as_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: value},
    )
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: (11, 12))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: 21)
    destroyed: list[int] = []
    kat_calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_assert_kat_secret",
        lambda *args, **_kwargs: kat_calls.append(args),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_p256_crossverify(rs)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
        "leg": "crossverify",
        "expected": {"type": "bytes", "length": 32},
        "actual": {
            "type": type(value).__name__,
            "length": len(value) if isinstance(value, (bytes, bytearray, memoryview)) else None,
        },
        "producer_operation": "C_DeriveKey",
        "producer_mechanism": "CKM_ECDH1_DERIVE",
    }
    assert destroyed == [21, 11, 12]
    assert kat_calls == []


@pytest.mark.parametrize("value", [b"", False, 0], ids=["empty", "false", "zero"])
def test_symmetric_agreement_rejects_equal_malformed_secrets(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: value},
    )
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    records = C.get_records()
    assert len(records) == 2
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.detail["leg"] for record in records if record.detail is not None] == [
        "A-to-B",
        "B-to-A",
    ]
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_retains_missing_first_and_malformed_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    reads: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 21 else {CKA_VALUE: b"x" * 31}

    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", read)
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert reads == [21, 22]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}
    assert records[1].detail is not None
    assert records[1].detail["leg"] == "B-to-A"
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_retains_malformed_first_and_missing_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    reads: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {CKA_VALUE: False} if handle == 21 else {}

    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", read)
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert reads == [21, 22]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[1].detail is not None
    assert records[1].detail["leg"] == "A-to-B"
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_retains_both_malformed_records_before_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"x" * (31 if handle == 21 else 33)},
    )
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    records = C.get_records()
    assert len(records) == 2
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.detail["leg"] for record in records if record.detail is not None] == [
        "A-to-B",
        "B-to-A",
    ]
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_keeps_valid_mismatch_as_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"a" * 32 if _a[2] == 21 else b"b" * 32},
    )
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(pytest.fail.Exception):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_ECDH1_DERIVE"
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_reads_second_secret_after_first_missing_even_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    reads: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        if handle == 21:
            return {}
        raise RuntimeError("second C_GetAttributeValue failed")

    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", read)
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    with pytest.raises(RuntimeError, match="second C_GetAttributeValue failed"):
        test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    assert reads == [21, 22]
    assert [record.reason for record in C.get_records()] == ["not_operational"]
    assert destroyed == [21, 22, 11, 12, 13, 14]


def test_symmetric_agreement_reads_both_missing_secrets_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    keypairs = iter([(11, 12), (13, 14)])
    derived = iter([21, 22])
    destroyed: list[int] = []
    monkeypatch.setattr(test_ecdh_known_answer, "_gen_p256_or_skip", lambda _rs: next(keypairs))
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "_ec_point_from_handle",
        lambda *_a: _conventional_p256_point(),
    )
    monkeypatch.setattr(test_ecdh_known_answer, "derive_key", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(test_ecdh_known_answer, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_ecdh_known_answer,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    test_ecdh_known_answer.TestECDHKnownAnswer().test_ecdh_symmetric_agreement(rs)

    records = C.get_records()
    assert [record.reason for record in records] == [
        "not_operational",
        "not_operational",
    ]
    assert len(records) == 2
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)
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


def test_ecdh_known_answer_source_analyzer_is_clean() -> None:
    assert analyze_file("src/pkcs11_check/testcases/test_ecdh_known_answer.py") == []
