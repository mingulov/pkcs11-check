"""Runtime regressions for AES key-wrap output readback classification."""

from __future__ import annotations

import os
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_aes_modes as aes


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "AES_KEY_WRAP_PKCS7",
    )


def _patch_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    *,
    read_value: Any,
) -> list[int]:
    monkeypatch.setattr(aes, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(aes, "import_secret_key_negotiated", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(aes, "wrap_key", lambda *_args, **_kwargs: b"wrapped")
    monkeypatch.setattr(aes, "unwrap_key_for_mechanism_roundtrip", lambda *_args, **_kwargs: 12)
    monkeypatch.setattr(aes, "read_attributes", lambda *_args, **_kwargs: read_value)
    destroyed: list[int] = []
    monkeypatch.setattr(aes, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    return destroyed


def test_target_import_failure_cleans_wrapping_key(monkeypatch: pytest.MonkeyPatch) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(aes, "gen_aes_key", lambda *_args, **_kwargs: 10)
    monkeypatch.setattr(
        aes,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("target import failed")),
    )
    monkeypatch.setattr(aes, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="target import failed"):
        aes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(_rs(), object())

    assert destroyed == [10]


def test_missing_unwrapped_value_is_structured_and_cleanup_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_value={})

    aes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(_rs(), object())

    assert destroyed == [12, 11, 10]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    # F6: a plain readback is never stamped with the mechanism that produced the
    # object being read; the producer survives in the label instead.
    assert records[0].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_WRAP_PKCS7" in records[0].label
    assert records[0].detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
    }


def test_earlier_wrap_output_failure_is_preserved_with_missing_unwrapped_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "urandom", lambda _length: b"k" * 24)
    destroyed = _patch_roundtrip(monkeypatch, read_value={})
    monkeypatch.setattr(aes, "wrap_key", lambda *_args, **_kwargs: b"k" * 24)

    with pytest.raises(pytest.fail.Exception):
        aes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(_rs(), object())

    assert destroyed == [12, 11, 10]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "not_operational"]
    assert records[0].operation == "C_WrapKey"
    assert records[0].mechanism == "CKM_AES_KEY_WRAP_PKCS7"
    assert records[0].detail == {
        "output": {
            "expected": "wrapped blob differs from raw key value",
            "actual": repr(b"k" * 24),
        }
    }
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].mechanism is None
    assert "producer_mechanism=CKM_AES_KEY_WRAP_PKCS7" in records[1].label


@pytest.mark.parametrize("value", [False, 0, b"", None], ids=["false", "zero", "empty", "none"])
def test_present_malformed_unwrapped_value_is_structured_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_value={CKA_VALUE: value})

    with pytest.raises(pytest.fail.Exception):
        aes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(_rs(), object())

    assert destroyed == [12, 11, 10]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism == "CKM_AES_KEY_WRAP_PKCS7"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["actual"] == repr(value)


def test_unequal_well_typed_unwrapped_value_is_unwrap_semantic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_value={CKA_VALUE: b"u" * 24})

    with pytest.raises(pytest.fail.Exception):
        aes.TestAESKeyWrapPKCS7().test_aes_key_wrap_pkcs7_roundtrip(_rs(), object())

    assert destroyed == [12, 11, 10]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_UnwrapKey"
    assert record.mechanism == "CKM_AES_KEY_WRAP_PKCS7"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
