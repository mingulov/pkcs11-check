"""Regression tests for IKE protocol-KDF coverage."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.testcases import test_ike


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_ike2_prf_plus_base_key_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_keys = iter((1, 2))
    derived_keys = iter((10, 11))

    monkeypatch.setattr(test_ike, "_create_base_key", lambda *_args, **_kwargs: next(base_keys))
    monkeypatch.setattr(test_ike, "_derive_generic", lambda *_args, **_kwargs: next(derived_keys))
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"same-ike2-output")
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE2_PRF_PLUS_DERIVE")
    with pytest.raises(AssertionError, match="IKE2 PRF\\+ base key"):
        test_ike.TestIKE2PRFPlusDerive().test_base_key_affects_output(rs)
