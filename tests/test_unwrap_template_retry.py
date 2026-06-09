"""Regression tests for mechanism-level unwrap template negotiation.

``unwrap_key_for_mechanism_roundtrip`` negotiates the accepted unwrap template
provider-generally (no provider identity, no compliance note). The canonical
variant carries both CKA_CLASS and CKA_KEY_TYPE; on a clean template-shape reject
it retries a variant that drops ONLY CKA_CLASS. CKA_KEY_TYPE is spec-mandatory on
C_UnwrapKey and is never dropped. A non-shape reject propagates immediately.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases import conftest as tc


class _Session:
    raw = object()
    sh = 1


class _Config:
    module = "/usr/lib/opencryptoki/lib/pkcs11_api.so"


class _UnknownConfig:
    module = "/tmp/vendor-pkcs11.so"


def test_mechanism_unwrap_retries_dropping_only_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shape-reject of the canonical template retries with CKA_CLASS dropped, KEY_TYPE kept."""
    calls: list[dict[Any, Any]] = []

    def _unwrap_key(*_args: Any, attrs: dict[Any, Any], **_kwargs: Any) -> int:
        calls.append(attrs)
        if len(calls) == 1:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY",
                int(CKR_ATTRIBUTE_READ_ONLY),
            )
        return 77

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
    # Canonical variant first, then the relaxed variant which keeps CKA_KEY_TYPE
    # (spec-mandatory) and drops only CKA_CLASS.
    assert calls == [
        {CKA_CLASS: 4, CKA_KEY_TYPE: 31, CKA_SENSITIVE: False},
        {CKA_KEY_TYPE: 31, CKA_SENSITIVE: False},
    ]


def test_mechanism_unwrap_negotiates_provider_generally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Negotiation is provider-general: a shape-reject retries regardless of module identity."""
    calls: list[dict[Any, Any]] = []

    def _unwrap_key(*_args: Any, attrs: dict[Any, Any], **_kwargs: Any) -> int:
        calls.append(attrs)
        if len(calls) == 1:
            raise CkrAssertionError(
                "Unexpected CK_RV CKR_ATTRIBUTE_READ_ONLY",
                int(CKR_ATTRIBUTE_READ_ONLY),
            )
        return 99

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", _unwrap_key)

    handle = tc.unwrap_key_for_mechanism_roundtrip(
        _Session(),
        _UnknownConfig(),
        unwrapping_key=1,
        wrapped_key=b"wrapped",
        mechanism=0x2109,
        attrs={CKA_CLASS: 4, CKA_KEY_TYPE: 31},
    )

    assert handle == 99
    assert calls == [
        {CKA_CLASS: 4, CKA_KEY_TYPE: 31},
        {CKA_KEY_TYPE: 31},
    ]


def test_mechanism_unwrap_non_shape_reject_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-template-shape reject propagates immediately without a relaxed retry."""
    calls = 0

    def _unwrap_key(*_args: Any, **_kwargs: Any) -> int:
        nonlocal calls
        calls += 1
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_FAILED",
            int(CKR_FUNCTION_FAILED),
        )

    monkeypatch.setattr("pkcs11_check.raw.recipes.unwrap_key", _unwrap_key)

    with pytest.raises(CkrAssertionError):
        tc.unwrap_key_for_mechanism_roundtrip(
            _Session(),
            _Config(),
            unwrapping_key=1,
            wrapped_key=b"wrapped",
            mechanism=0x2109,
            attrs={CKA_CLASS: 4, CKA_KEY_TYPE: 31},
        )

    assert calls == 1
