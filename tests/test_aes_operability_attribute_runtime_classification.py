"""Runtime regressions for AES-KW operability attribute readback."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_VALUE, CKR_ATTRIBUTE_SENSITIVE
from pkcs11_check.testcases import _aes_operability as aes
from pkcs11_check.testcases._operability import Operability, reset_operability_cache


@pytest.fixture(autouse=True)
def _clear_probe_state() -> Generator[None, None, None]:
    reset_operability_cache()
    C.clear()
    yield
    reset_operability_cache()
    C.clear()


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _patch_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    *,
    read_result: Any = None,
    read_error: BaseException | None = None,
) -> list[int]:
    handles = iter([10, 11])
    monkeypatch.setattr(
        aes,
        "import_secret_key_negotiated",
        lambda *_args, **_kwargs: next(handles),
    )
    monkeypatch.setattr(aes, "wrap_key", lambda *_args, **_kwargs: b"wrapped")
    monkeypatch.setattr(aes, "unwrap_key", lambda *_args, **_kwargs: 12)

    def _read(*_args: Any, **_kwargs: Any) -> Any:
        if read_error is not None:
            raise read_error
        return read_result

    monkeypatch.setattr(aes, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(aes, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    return destroyed


def test_missing_recovered_value_is_inconclusive_and_records_structured_omission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_result={})

    result = aes.kw_unwrap_operability(_rs())

    assert result.status is Operability.INCONCLUSIVE
    assert "recovered value unavailable" in result.detail
    assert destroyed == [10, 11, 12]
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    # The readback is a pure C_GetAttributeValue observation; the CKM_AES_KEY_WRAP
    # producer context lives in the label text, not in `mechanism` (see F6 fix:
    # a readback must never be attributed to the operation that produced its input).
    assert record.mechanism is None
    assert record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.detail == {
        "attribute": {"name": "CKA_VALUE", "id": int(CKA_VALUE)},
    }


@pytest.mark.parametrize("value", [b"", None], ids=["empty-bytes", "none"])
def test_present_false_like_recovered_value_is_wrong_output_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_result={CKA_VALUE: value})

    result = aes.kw_unwrap_operability(_rs())

    assert result.status is Operability.WRONG_OUTPUT
    assert result.detail == "KW roundtrip value mismatch"
    assert destroyed == [10, 11, 12]
    assert C.get_records() == []


def test_present_correct_recovered_value_is_operational_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_result={CKA_VALUE: aes._PROBE_KEY2})

    result = aes.kw_unwrap_operability(_rs())

    assert result.status is Operability.OPERATIONAL
    assert result.detail == "KW wrap+unwrap OK"
    assert destroyed == [10, 11, 12]


def test_recovered_value_ckr_read_is_inconclusive_with_exact_provider_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = CkrAssertionError("read refusal", int(CKR_ATTRIBUTE_SENSITIVE))
    destroyed = _patch_roundtrip(monkeypatch, read_error=error)

    result = aes.kw_unwrap_operability(_rs())

    assert result.status is Operability.INCONCLUSIVE
    assert result.detail == f"KW recovered value read failed: {error}"
    assert error.rv == int(CKR_ATTRIBUTE_SENSITIVE)
    assert C.get_records() == []
    assert destroyed == [10, 11, 12]


def test_unexpected_recovered_value_read_exception_propagates_and_is_cleaned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("read failed")
    destroyed = _patch_roundtrip(monkeypatch, read_error=error)

    with pytest.raises(RuntimeError, match="read failed") as raised:
        aes.kw_unwrap_operability(_rs())

    assert raised.value is error
    assert C.get_records() == []
    assert destroyed == [10, 11, 12]


def test_unwrap_refusal_remains_not_operational_and_does_not_read_or_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed = _patch_roundtrip(monkeypatch, read_result={CKA_VALUE: aes._PROBE_KEY2})
    refusals = iter(
        (
            CkrAssertionError("first refusal", int(CKR_ATTRIBUTE_SENSITIVE)),
            CkrAssertionError("second refusal", int(CKR_ATTRIBUTE_SENSITIVE)),
        )
    )
    unwrap_calls: list[int] = []

    def _unwrap(*_args: Any, **_kwargs: Any) -> int:
        unwrap_calls.append(1)
        raise next(refusals)

    monkeypatch.setattr(aes, "unwrap_key", _unwrap)
    monkeypatch.setattr(
        aes,
        "read_attributes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not read")),
    )

    result = aes.kw_unwrap_operability(_rs())

    assert result.status is Operability.NOT_OPERATIONAL
    assert result.detail == "canonical KW unwrap rejected (both template variants)"
    assert len(unwrap_calls) == 2
    assert destroyed == [10, 11]


def test_aes_operability_attribute_access_analyzer_is_clean() -> None:
    """The canonical AES operability probe must preserve explicit missing sentinels."""
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "pkcs11_check"
        / "testcases"
        / "_aes_operability.py"
    )
    from tests._attribute_access_guard import analyze_paths

    assert analyze_paths([source]) == []
