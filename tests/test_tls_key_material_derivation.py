"""Regression tests for TLS key-material derivation contracts."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import CKR_OK
from pkcs11_check.testcases import test_tls12


class _FakeKeyMatMechanism:
    def __init__(self) -> None:
        self.key_mat_out = SimpleNamespace(
            hClientMacSecret=0,
            hServerMacSecret=0,
            hClientKey=11,
            hServerKey=12,
        )

    def byref(self) -> object:
        return object()

    def buffer_bytes(self, name: str) -> bytes:
        if name in {"iv_client", "iv_server"}:
            return b"\x01" * 16
        raise KeyError(name)


class _FakeRaw:
    def __init__(self) -> None:
        self.ph_keys: list[Any] = []

    def C_DeriveKey(  # noqa: N802
        self,
        _session: int,
        _mechanism: object,
        _base_key: int,
        _template: object,
        _template_count: int,
        ph_key: object | None,
    ) -> int:
        self.ph_keys.append(ph_key)
        if ph_key is not None:
            raise AssertionError("TLS key-material derive must pass phKey as NULL_PTR")
        return int(CKR_OK)


def _session(raw: _FakeRaw) -> SimpleNamespace:
    return SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name in {"TLS12_KEY_AND_MAC_DERIVE", "TLS12_KEY_SAFE_DERIVE"},
    )


def _patch_tls_material_dependencies(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_tls12, "_create_tls_pms", lambda _rs: 101)
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_tls12, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(
        test_tls12,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("should not read a primary derived handle"),
    )
    monkeypatch.setattr(
        test_tls12,
        "mech_tls12_key_mat",
        lambda *_args, **_kwargs: _FakeKeyMatMechanism(),
    )


def test_tls12_key_and_mac_derive_uses_null_phkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _FakeRaw()
    _patch_tls_material_dependencies(monkeypatch)

    test_tls12.TestTLS12KeyAndMacDerive().test_key_and_mac_derive(_session(raw))

    assert raw.ph_keys == [None]


def test_tls12_key_safe_derive_uses_null_phkey(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _FakeRaw()
    _patch_tls_material_dependencies(monkeypatch)

    test_tls12.TestTLS12KeyAndMacDerive().test_key_safe_derive(_session(raw))

    assert raw.ph_keys == [None]
