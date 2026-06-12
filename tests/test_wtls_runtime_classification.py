"""Regression tests for WTLS protocol-KDF coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import CKA_VALUE
from pkcs11_check.testcases import test_wtls


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_wtls_prf_seed_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter((10, 11))

    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "derive_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        test_wtls,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"same-prf-output!"},
    )
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("WTLS_PRF")
    with pytest.raises(AssertionError, match="WTLS PRF seed"):
        test_wtls.TestWTLSPRF().test_prf_seed_affects_output(rs)
