"""Regression tests for mechanism-level unwrap template fallback."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKR_ATTRIBUTE_READ_ONLY,
)
from pkcs11_check.testcases import conftest as tc


class _Session:
    raw = object()
    sh = 1


class _Config:
    module = "/usr/lib/opencryptoki/lib/pkcs11_api.so"


class _UnknownConfig:
    module = "/tmp/vendor-pkcs11.so"


def test_mechanism_unwrap_retries_without_type_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[Any, Any]] = []

    def _unwrap_key(*_args: Any, attrs: dict[Any, Any], **_kwargs: Any) -> int:
        calls.append(attrs)
        if len(calls) == 1:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY",
                int(CKR_ATTRIBUTE_READ_ONLY),
            )
        return 77

    clear_notes()
    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", _unwrap_key)

    handle = tc.unwrap_key_for_mechanism_roundtrip(
        _Session(),
        _Config(),
        unwrapping_key=1,
        wrapped_key=b"wrapped",
        mechanism=0x2109,
        attrs={CKA_CLASS: 4, CKA_KEY_TYPE: 31, CKA_SENSITIVE: False},
        purpose="test mechanism unwrap",
    )

    assert handle == 77
    assert calls == [
        {CKA_CLASS: 4, CKA_KEY_TYPE: 31, CKA_SENSITIVE: False},
        {CKA_SENSITIVE: False},
    ]
    assert any(
        "retried without CKA_CLASS/CKA_KEY_TYPE" in note.description for note in get_notes()
    )


def test_mechanism_unwrap_does_not_retry_unknown_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def _unwrap_key(*_args: Any, **_kwargs: Any) -> int:
        nonlocal calls
        calls += 1
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY",
            int(CKR_ATTRIBUTE_READ_ONLY),
        )

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", _unwrap_key)

    with pytest.raises(CkrAssertionError):
        tc.unwrap_key_for_mechanism_roundtrip(
            _Session(),
            _UnknownConfig(),
            unwrapping_key=1,
            wrapped_key=b"wrapped",
            mechanism=0x2109,
            attrs={CKA_CLASS: 4, CKA_KEY_TYPE: 31},
        )

    assert calls == 1
