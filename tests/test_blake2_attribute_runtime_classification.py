"""Runtime regressions for BLAKE2B attribute evidence handling."""

from __future__ import annotations

import hashlib
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.types_std import CKA_KEY_TYPE, CKA_VALUE, CKK_GENERIC_SECRET
from pkcs11_check.testcases import test_blake2 as blake2
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def test_missing_attribute_is_recorded_without_false_like_coercion() -> None:
    value = attr_or_record({}, CKA_VALUE, label="BLAKE2B CKA_VALUE", mechanism="CKM_BLAKE2B_256")

    assert value is MISSING_ATTRIBUTE
    record = C.get_records()[0]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_BLAKE2B_256"
    assert record.detail == {"attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)}}


@pytest.mark.parametrize("value", [False, 0, b"", None])
def test_present_false_like_values_are_not_treated_as_missing(value: Any) -> None:
    attrs = {CKA_VALUE: value}

    assert attr_or_record(attrs, CKA_VALUE, label="value") is value
    assert C.get_records() == []


def test_present_malformed_value_is_deferred_until_cleanup() -> None:
    record = blake2._record_attribute_mismatch(
        label="BLAKE2B generated CKA_VALUE",
        expected="32-byte bytes",
        actual=False,
        kind="crypto",
        mechanism="CKM_BLAKE2B_256_KEY_GEN",
    )

    assert record.reason == "wrong_result"
    assert record.outcome == "fail"
    assert record.operation == "C_GetAttributeValue"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail == {"attribute": {"expected": "'32-byte bytes'", "actual": "False"}}


def test_keygen_sign_reference_keeps_signing_when_attribute_readback_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    calls: list[str] = []
    monkeypatch.setattr(blake2, "_generate_blake2b_hmac_key", lambda *_args: 7)
    monkeypatch.setattr(
        blake2,
        "read_attributes",
        lambda *_args: {CKA_KEY_TYPE: case.key_type},
    )

    def fake_sign(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append("sign")
        return b"m" * case.digest_len

    monkeypatch.setattr(blake2, "sign_single", fake_sign)
    monkeypatch.setattr(blake2, "destroy_quietly", lambda *_args: calls.append("destroy"))

    blake2.TestBlake2bKeyed()._key_gen_signs_reference(_Session(), case)

    assert calls == ["sign", "destroy"]
    assert any(record.reason == "not_operational" for record in C.get_records())


def test_keygen_keeps_independent_attribute_evidence_and_cleans_before_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    calls: list[str] = []

    def fake_generate(*_args: Any, **_kwargs: Any) -> int:
        return 7

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_VALUE: b"short"}

    monkeypatch.setattr(blake2, "_generate_blake2b_hmac_key", fake_generate)
    monkeypatch.setattr(blake2, "read_attributes", fake_read)

    def fake_sign(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append("sign")
        return b"m" * case.digest_len

    monkeypatch.setattr(blake2, "sign_single", fake_sign)
    monkeypatch.setattr(blake2, "destroy_quietly", lambda *_args: calls.append("destroy"))

    with pytest.raises(pytest.fail.Exception):
        blake2.TestBlake2bKeyed()._key_gen_signs_reference(_Session(), case)

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_BLAKE2B_256_KEY_GEN"
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism == "CKM_BLAKE2B_256_KEY_GEN"
    assert calls == ["sign", "destroy"]


def test_keygen_well_typed_key_type_contradiction_uses_producer_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    calls: list[str] = []

    def fake_generate(*_args: Any, **_kwargs: Any) -> int:
        return 7

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, int]:
        return {CKA_KEY_TYPE: CKK_GENERIC_SECRET}

    monkeypatch.setattr(blake2, "_generate_blake2b_hmac_key", fake_generate)
    monkeypatch.setattr(
        blake2,
        "read_attributes",
        fake_read,
    )

    def fake_sign(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append("sign")
        return b"m" * 32

    monkeypatch.setattr(blake2, "sign_single", fake_sign)
    monkeypatch.setattr(blake2, "destroy_quietly", lambda *_args: calls.append("destroy"))

    with pytest.raises(pytest.fail.Exception):
        blake2.TestBlake2bKeyed()._key_gen_signs_reference(_Session(), case)

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_GenerateKey"
    assert records[0].mechanism == "CKM_BLAKE2B_256_KEY_GEN"
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism == "CKM_BLAKE2B_256_KEY_GEN"
    assert calls == ["sign", "destroy"]


def test_default_derive_preserves_missing_type_and_malformed_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    destroyed: list[int] = []

    def fake_import(*_args: Any, **_kwargs: Any) -> int:
        return 5

    def fake_derive(*_args: Any, **_kwargs: Any) -> int:
        return 9

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_VALUE: b"bad"}

    def fake_destroy(_raw: Any, _sh: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr(blake2, "_import_blake2b_setup_key", fake_import)
    monkeypatch.setattr(blake2, "derive_key", fake_derive)
    monkeypatch.setattr(blake2, "read_attributes", fake_read)
    monkeypatch.setattr(blake2, "destroy_quietly", fake_destroy)

    with pytest.raises(pytest.fail.Exception):
        blake2.TestBlake2bKeyed()._key_derive_default_template_value(_Session(), case)

    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism == "CKM_BLAKE2B_256_KEY_DERIVE"
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism == "CKM_BLAKE2B_256_KEY_DERIVE"
    assert destroyed == [5, 9]


def test_length_only_derive_preserves_contradictory_type_and_missing_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    destroyed: list[int] = []

    def fake_import(*_args: Any, **_kwargs: Any) -> int:
        return 5

    def fake_derive(*_args: Any, **_kwargs: Any) -> int:
        return 9

    def fake_read(*_args: Any, **_kwargs: Any) -> dict[int, int]:
        return {CKA_KEY_TYPE: 0}

    def fake_destroy(_raw: Any, _sh: int, handle: int) -> None:
        destroyed.append(handle)

    monkeypatch.setattr(blake2, "_import_blake2b_setup_key", fake_import)
    monkeypatch.setattr(blake2, "derive_key", fake_derive)
    monkeypatch.setattr(blake2, "read_attributes", fake_read)
    monkeypatch.setattr(blake2, "destroy_quietly", fake_destroy)

    with pytest.raises(pytest.fail.Exception):
        blake2.TestBlake2bKeyed()._key_derive_length_only_template_value(_Session(), case)

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_BLAKE2B_256_KEY_DERIVE"
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism == "CKM_BLAKE2B_256_KEY_DERIVE"
    assert destroyed == [5, 9]


def test_derived_value_semantic_mismatch_uses_derive_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = blake2._BLAKE2B_KEYED_CASE_BY_BITS[256]
    expected = hashlib.blake2b(
        blake2._BLAKE2B_TEST_KEY,
        digest_size=case.digest_len,
    ).digest()

    record = blake2._check_bytes_attribute(
        expected[:-1] + b"x",
        expected_len=case.digest_len,
        expected=expected,
        label="derived value",
        mechanism="CKM_BLAKE2B_256_KEY_DERIVE",
        operation="C_DeriveKey",
    )

    assert record is not None
    assert record.reason == "wrong_result"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_BLAKE2B_256_KEY_DERIVE"


def test_owned_source_has_no_unsafe_attribute_access() -> None:
    from tests._attribute_access_guard import analyze_paths

    path = Path(blake2.__file__)
    assert analyze_paths([path]) == []


class _Session:
    raw = object()
    sh = 1

    @staticmethod
    def has_mechanism(_name: str) -> bool:
        return True
