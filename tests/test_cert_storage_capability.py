"""Meta-test: cert_storage_supported probe (no real module needed)."""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID
from pkcs11_check.testcases.x509 import conftest as x509conftest


def _fake_module(monkeypatch, *, accept_on: int | None, raise_rv: int) -> tuple[Any, list[int]]:
    """accept_on: 0-based attempt index that stores OK; None = always refuse.
    Returns (rs, attempts) where attempts[0] is the create_object call count."""
    attempts = [0]

    def fake_create_object(raw: Any, sh: int, tmpl: dict[Any, Any]) -> int:
        i = attempts[0]
        attempts[0] += 1
        if accept_on is not None and i == accept_on:
            return 7
        raise CkrAssertionError("refuse", raise_rv)

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", fake_create_object)
    monkeypatch.setattr("pkcs11_check.raw.recipes.destroy_quietly", lambda *a, **k: None)
    x509conftest._CERT_STORAGE_SUPPORTED.clear()
    rs = type("RS", (), {"raw": object(), "sh": 0, "slot_id": 0})()
    return rs, attempts


def test_supported_when_any_template_accepted(monkeypatch):
    rs, _ = _fake_module(monkeypatch, accept_on=1, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    assert x509conftest.cert_storage_supported(rs) is True


def test_unsupported_only_after_trying_all(monkeypatch):
    rs, attempts = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    assert x509conftest.cert_storage_supported(rs) is False
    assert attempts[0] >= 2  # exhaustive before concluding (no false-skip)


def test_non_refusal_ckr_propagates(monkeypatch):
    # CKR_GENERAL_ERROR is NOT a clean cert-storage refusal -> real finding, not swallowed.
    rs, _ = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_GENERAL_ERROR))
    with pytest.raises(CkrAssertionError):
        x509conftest.cert_storage_supported(rs)


def test_skip_helper_skips_when_unsupported(monkeypatch):
    rs, _ = _fake_module(monkeypatch, accept_on=None, raise_rv=int(CKR_KEY_HANDLE_INVALID))
    with pytest.raises(pytest.skip.Exception):
        x509conftest.skip_unless_cert_storage(rs)
