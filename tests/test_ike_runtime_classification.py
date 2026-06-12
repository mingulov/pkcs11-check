"""Regression tests for IKE protocol-KDF coverage."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

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


def test_ike1_prf_exact_vector_uses_typed_helper_and_fails_on_wrong_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, int]] = []

    monkeypatch.setattr(test_ike, "_create_sha256_hmac_derive_key", lambda *_args: 1)
    monkeypatch.setattr(test_ike, "_create_ike1_keygxy_key", lambda *_args: 2)

    def fake_derive(*args: Any, **kwargs: Any) -> int:
        calls.append((int(args[1]), int(args[2]), int(kwargs["key_number"])))
        return 10

    monkeypatch.setattr(test_ike, "_derive_ike1_prf", fake_derive)
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"\x00" * 32)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE1_PRF_DERIVE")
    with pytest.raises(AssertionError):
        test_ike.TestIKE1PRFDerive().test_prf_hmac_sha256_exact_vector(rs)

    assert calls == [(1, 2, 0)]


def test_ike1_extended_exact_vector_uses_typed_helper_and_fails_on_wrong_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[int, int, bytes]] = []

    monkeypatch.setattr(test_ike, "_create_sha256_hmac_derive_key", lambda *_args: 1)
    monkeypatch.setattr(test_ike, "_create_ike1_keygxy_key", lambda *_args: 2)

    def fake_derive(*args: Any, **kwargs: Any) -> int:
        calls.append((int(args[1]), int(kwargs["keygxy_key"]), bytes(kwargs["extra_data"])))
        return 10

    monkeypatch.setattr(test_ike, "_derive_ike1_extended", fake_derive)
    monkeypatch.setattr(test_ike, "_get_value", lambda *_args, **_kwargs: b"\x00" * 32)
    monkeypatch.setattr(test_ike, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("IKE1_EXTENDED_DERIVE")
    with pytest.raises(AssertionError):
        test_ike.TestIKE1ExtendedDerive().test_extended_hmac_sha256_exact_vector(rs)

    expected_extra = test_ike._NONCE_I + test_ike._NONCE_R + test_ike._SPI_I + test_ike._SPI_R
    assert calls == [(1, 2, expected_extra)]
