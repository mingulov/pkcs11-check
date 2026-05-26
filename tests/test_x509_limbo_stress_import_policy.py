"""Regression tests for x509-limbo stress import error handling."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.x509 import test_limbo_stress


class _RawSession:
    raw = object()
    sh = 1


def test_cert_stress_allows_pkcs11_import_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    """A CKR-style import rejection is fine for malformed x509-limbo material."""

    def reject_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise AssertionError("CKR_ATTRIBUTE_VALUE_INVALID")

    monkeypatch.setattr(test_limbo_stress, "create_object", reject_create_object)

    test_limbo_stress.test_exhaustive_cert_import_no_crash(
        "case",
        b"not-a-cert",
        _RawSession(),
        object(),
    )


def test_cert_stress_does_not_swallow_python_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected harness errors must remain visible instead of looking like rejects."""

    def broken_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise ValueError("broken test harness")

    monkeypatch.setattr(test_limbo_stress, "create_object", broken_create_object)

    with pytest.raises(ValueError, match="broken test harness"):
        test_limbo_stress.test_exhaustive_cert_import_no_crash(
            "case",
            b"not-a-cert",
            _RawSession(),
            object(),
        )


def test_crl_stress_does_not_swallow_python_import_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CRL import stress has the same error boundary as certificate stress."""

    def broken_create_object(*_args: Any, **_kwargs: Any) -> int:
        raise TypeError("broken CRL setup")

    monkeypatch.setattr(test_limbo_stress, "create_object", broken_create_object)

    with pytest.raises(TypeError, match="broken CRL setup"):
        test_limbo_stress.test_exhaustive_crl_import_no_crash(
            "case",
            b"not-a-crl",
            _RawSession(),
            object(),
        )
