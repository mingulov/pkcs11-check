"""Runtime classification regressions for AES data-encryption KDFs."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_aes_kdf
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


_PAIR_CASES = (
    pytest.param(
        (
            test_aes_kdf.TestAESECBEncryptData,
            "test_derive_deterministic",
            "CKM_AES_ECB_ENCRYPT_DATA",
            "equal",
        ),
        id="ecb-deterministic",
    ),
    pytest.param(
        (
            test_aes_kdf.TestAESECBEncryptData,
            "test_derive_different_data",
            "CKM_AES_ECB_ENCRYPT_DATA",
            "different",
        ),
        id="ecb-different-data",
    ),
    pytest.param(
        (
            test_aes_kdf.TestAESCBCEncryptData,
            "test_derive_deterministic",
            "CKM_AES_CBC_ENCRYPT_DATA",
            "equal",
        ),
        id="cbc-deterministic",
    ),
    pytest.param(
        (
            test_aes_kdf.TestAESCBCEncryptData,
            "test_derive_different_data",
            "CKM_AES_CBC_ENCRYPT_DATA",
            "different",
        ),
        id="cbc-different-data",
    ),
    pytest.param(
        (
            test_aes_kdf.TestAESCBCEncryptData,
            "test_derive_different_iv",
            "CKM_AES_CBC_ENCRYPT_DATA",
            "different",
        ),
        id="cbc-different-iv",
    ),
)


def _install_pair(
    monkeypatch: pytest.MonkeyPatch,
    values: tuple[Any, Any],
    *,
    reader_error: BaseException | None = None,
) -> tuple[list[int], list[int]]:
    destroyed: list[int] = []
    reads: list[int] = []
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 90)
    derived = iter([91, 92])
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: next(derived))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        if reader_error is not None and len(reads) == 2:
            raise reader_error
        value = values[0] if handle == 91 else values[1]
        return {} if value is MISSING_ATTRIBUTE else {CKA_VALUE: value}

    monkeypatch.setattr(test_aes_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    return reads, destroyed


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
    assert records[0].mechanism is None
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
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational"]
    assert records[0].mechanism is None


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

    with pytest.raises(BaseException):
        test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_GetAttributeValue"


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

    with pytest.raises(BaseException):
        test_aes_kdf.TestAESECBEncryptData().test_derive_deterministic(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_DeriveKey"


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
    """Mutation: derived CKA_VALUE = 16 zero bytes.

    This used to be a bare ``assert okm != b"\\x00" * 16`` -- an unclassified pytest failure
    with no reason/kind and no classification record at all. It must now be a properly
    classified ``wrong_result``/``crypto`` finding (a crypto-correctness break) while still
    failing -- same direction/strength, now with a real finding instead of "unclassified".
    """
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 80)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 81)
    monkeypatch.setattr(
        test_aes_kdf,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16},
    )
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(BaseException, match="all zeros"):
        test_aes_kdf.TestAESECBEncryptData().test_derive_basic(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].outcome == "fail"
    assert records[0].mechanism == "CKM_AES_ECB_ENCRYPT_DATA"
    assert records[0].operation == "C_DeriveKey"


@pytest.mark.parametrize("case", _PAIR_CASES)
@pytest.mark.parametrize("value", [b"", "not-bytes"])
def test_pair_reads_both_present_malformed_outputs_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
    value: Any,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    test_class, method_name, _mechanism, _relation = case
    reads, destroyed = _install_pair(monkeypatch, (value, value))

    with pytest.raises(BaseException):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert len(records) == 2
    assert all(record.reason == "wrong_result" for record in records)
    assert all(record.kind == "metadata" for record in records)
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)
    assert all(record.detail is not None for record in records)
    assert all("actual" in record.detail for record in records if record.detail is not None)
    assert all(
        "producer_operation" in record.detail and "producer_mechanism" in record.detail
        for record in records
        if record.detail is not None
    )


@pytest.mark.parametrize("case", _PAIR_CASES)
def test_pair_must_differ_retains_malformed_leg_and_never_compares(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
) -> None:
    test_class, method_name, _mechanism, relation = case
    if relation != "different":
        pytest.skip("only must-differ paths have this relation")
    reads, destroyed = _install_pair(monkeypatch, (b"short", b"x" * 16))

    with pytest.raises(BaseException):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].detail is not None
    assert records[0].detail["leg"] == "output 1"


@pytest.mark.parametrize("case", _PAIR_CASES)
@pytest.mark.parametrize("missing_index", [0, 1])
def test_pair_missing_and_malformed_reads_both_legs_and_raises_shape_finding(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
    missing_index: int,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    test_class, method_name, _mechanism, _relation = case
    values: tuple[Any, Any]
    malformed = b"short"
    if missing_index == 0:
        values = (MISSING_ATTRIBUTE, malformed)
    else:
        values = (malformed, MISSING_ATTRIBUTE)
    reads, destroyed = _install_pair(monkeypatch, values)

    with pytest.raises(BaseException):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert sorted(record.reason for record in records) == ["not_operational", "wrong_result"]
    assert sum(record.reason == "wrong_result" for record in records) == 1
    missing = next(record for record in records if record.reason == "not_operational")
    assert missing.mechanism is None
    assert missing.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    shape = next(record for record in records if record.reason == "wrong_result")
    assert shape.kind == "metadata"
    assert shape.operation == "C_GetAttributeValue"
    assert shape.mechanism is None
    assert shape.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert not any(record.operation == "C_DeriveKey" for record in records)


@pytest.mark.parametrize("case", _PAIR_CASES)
def test_pair_reader_exception_after_missing_first_propagates_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
) -> None:
    test_class, method_name, _mechanism, _relation = case
    reads, destroyed = _install_pair(
        monkeypatch,
        (MISSING_ATTRIBUTE, b"x" * 16),
        reader_error=RuntimeError("second output read failed"),
    )

    with pytest.raises(RuntimeError, match="second output read failed"):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].mechanism is None
    assert not any(record.operation == "C_DeriveKey" for record in records)


@pytest.mark.parametrize("case", _PAIR_CASES)
def test_pair_valid_relation_violation_is_structured_crypto_finding(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
) -> None:
    test_class, method_name, mechanism, relation = case
    value = b"x" * 16
    values = (value, value) if relation == "different" else (b"a" * 16, b"b" * 16)
    reads, destroyed = _install_pair(monkeypatch, values)

    with pytest.raises(BaseException):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == mechanism
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["relation"] == relation


@pytest.mark.parametrize("case", _PAIR_CASES)
def test_pair_malformed_first_is_retained_when_second_reader_raises(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
) -> None:
    test_class, method_name, mechanism, _relation = case
    reads, destroyed = _install_pair(
        monkeypatch,
        (b"short", b"x" * 16),
        reader_error=RuntimeError("second output read failed"),
    )

    with pytest.raises(RuntimeError, match="second output read failed"):
        getattr(test_class(), method_name)(_session())

    assert reads == [91, 92]
    assert destroyed == [92, 91, 90]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["leg"] == "output 1"
    assert record.detail["producer_operation"] == "C_DeriveKey"
    assert record.detail["producer_mechanism"] == mechanism


@pytest.mark.parametrize("case", _PAIR_CASES)
def test_pair_second_derive_error_cleans_first_handle_before_base(
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[type[Any], str, str, str],
) -> None:
    test_class, method_name, _mechanism, _relation = case
    destroyed: list[int] = []
    derive_calls = 0
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 90)

    def _derive(*_args: Any, **_kwargs: Any) -> int:
        nonlocal derive_calls
        derive_calls += 1
        if derive_calls == 1:
            return 91
        raise RuntimeError("second derive failed")

    monkeypatch.setattr(test_aes_kdf, "derive_key", _derive)
    monkeypatch.setattr(
        test_aes_kdf,
        "read_attributes",
        lambda *_a, **_k: pytest.fail("readback must not run after second derive failure"),
    )
    monkeypatch.setattr(
        test_aes_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    with pytest.raises(RuntimeError, match="second derive failed"):
        getattr(test_class(), method_name)(_session())

    assert derive_calls == 2
    assert destroyed == [91, 90]


def test_cbc_all_zero_derived_key_is_classified_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: same all-zero defect on the CBC leg (a second, separate bare assert site)."""
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 100)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 101)
    monkeypatch.setattr(
        test_aes_kdf, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x00" * 16}
    )
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(BaseException, match="all zeros"):
        test_aes_kdf.TestAESCBCEncryptData().test_derive_basic(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].outcome == "fail"
    assert records[0].mechanism == "CKM_AES_CBC_ENCRYPT_DATA"
    assert records[0].operation == "C_DeriveKey"


@pytest.mark.parametrize(
    "test_class",
    [test_aes_kdf.TestAESECBEncryptData, test_aes_kdf.TestAESCBCEncryptData],
)
def test_nonzero_derived_key_is_not_flagged_zero(
    monkeypatch: pytest.MonkeyPatch,
    test_class: type[Any],
) -> None:
    """Control: a normal non-zero derived key must not trip the all-zero check."""
    monkeypatch.setattr(test_aes_kdf, "_create_base_key", lambda *_a, **_k: 110)
    monkeypatch.setattr(test_aes_kdf, "derive_key", lambda *_a, **_k: 111)
    monkeypatch.setattr(
        test_aes_kdf, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b"\x01" * 16}
    )
    monkeypatch.setattr(test_aes_kdf, "destroy_quietly", lambda *_a: None)

    test_class().test_derive_basic(_session())

    assert C.get_records() == []
