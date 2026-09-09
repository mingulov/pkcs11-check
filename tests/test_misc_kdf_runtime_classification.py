"""Regression tests for miscellaneous KDF runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_VALUE, CKR_ATTRIBUTE_VALUE_INVALID
from pkcs11_check.testcases import test_misc_kdf


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    C.clear()
    yield
    C.clear()


def test_extract_key_from_key_attribute_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "EXTRACT_KEY_FROM_KEY",
    )
    monkeypatch.setattr(test_misc_kdf, "_import_generic_secret", lambda *_args: 10)
    monkeypatch.setattr(test_misc_kdf, "destroy_quietly", lambda *_args: None)

    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_misc_kdf, "_derive_generic_secret", _derive_reject)
    monkeypatch.setattr(
        test_misc_kdf,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("read should not run after derive reject"),
    )

    with pytest.raises(pytest.xfail.Exception, match="CKM_EXTRACT_KEY_FROM_KEY derive failed"):
        test_misc_kdf.TestExtractKeyFromKey().test_extract_from_offset_zero(rs)


def test_extract_different_offsets_records_missing_pair_member_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_misc_kdf, "_import_generic_secret", lambda *_args: 10)
    derived = iter([11, 12])
    monkeypatch.setattr(
        test_misc_kdf,
        "_derive_generic_secret",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 11 else {CKA_VALUE: b"second"}

    monkeypatch.setattr(test_misc_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_misc_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "EXTRACT_KEY_FROM_KEY",
    )
    test_misc_kdf.TestExtractKeyFromKey().test_extract_different_offsets_yield_different_keys(rs)

    assert destroyed == [11, 12, 10]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["id"] == int(CKA_VALUE)


def test_concat_kat_treats_empty_value_as_present_and_keeps_hard_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_misc_kdf, "_import_generic_secret", lambda *_args: 10)
    monkeypatch.setattr(test_misc_kdf, "_derive_generic_secret", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(
        test_misc_kdf,
        "read_attributes",
        lambda *_args: {CKA_VALUE: b""},
    )
    monkeypatch.setattr(
        test_misc_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "CONCATENATE_BASE_AND_KEY",
    )
    with pytest.raises(pytest.fail.Exception):
        test_misc_kdf.TestConcatenateBaseAndKey().test_concat_two_keys_value(rs)

    assert destroyed == [11, 10, 10]
    assert C.get_records()[0].reason == "wrong_result"


def test_concat_ordering_reads_both_outputs_and_keeps_mechanism_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    reads: list[int] = []
    labels: list[str] = []
    monkeypatch.setattr(test_misc_kdf, "_import_generic_secret", lambda *_args: 10)
    derived = iter([11, 12])
    monkeypatch.setattr(
        test_misc_kdf,
        "_derive_generic_secret",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {CKA_VALUE: b"same output"}

    monkeypatch.setattr(test_misc_kdf, "read_attributes", _read)
    original_read = test_misc_kdf._read_attr_or_record

    def _read_labeled(*args: Any, **kwargs: Any) -> Any:
        labels.append(str(kwargs["label"]))
        return original_read(*args, **kwargs)

    monkeypatch.setattr(test_misc_kdf, "_read_attr_or_record", _read_labeled)
    monkeypatch.setattr(
        test_misc_kdf,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: (
            name in {"CONCATENATE_BASE_AND_DATA", "CONCATENATE_DATA_AND_BASE"}
        ),
    )

    with pytest.raises(pytest.fail.Exception):
        test_misc_kdf.TestConcatenateDataAndBase().test_base_and_data_ordering_differ(rs)

    assert reads == [11, 12]
    assert labels == [
        "CKM_CONCATENATE_BASE_AND_DATA:base-data CKA_VALUE readback",
        "CKM_CONCATENATE_DATA_AND_BASE:data-base CKA_VALUE readback",
    ]
    assert destroyed == [11, 12, 10]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].mechanism == "CKM_CONCATENATE_DATA_AND_BASE"
    assert "data-base" in records[0].label
