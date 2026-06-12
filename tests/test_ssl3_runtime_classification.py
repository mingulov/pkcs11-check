"""Regression tests for SSL3 runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_ssl3


def test_ssl3_premaster_attribute_value_invalid_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rs = SimpleNamespace(
        raw=SimpleNamespace(
            C_GenerateKey=lambda *_args: int(CKR_ATTRIBUTE_VALUE_INVALID),
        ),
        sh=1,
        has_mechanism=lambda name: name == "SSL3_PRE_MASTER_KEY_GEN",
    )
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="CKM_SSL3_PRE_MASTER_KEY_GEN"):
        test_ssl3.TestSSL3PreMasterKeyGen().test_generate_pre_master_key(rs)


class _FakeKeyMatMechanism:
    def __init__(self) -> None:
        self.key_mat_out = SimpleNamespace(
            hClientMacSecret=21,
            hServerMacSecret=22,
            hClientKey=23,
            hServerKey=24,
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
            raise AssertionError("SSL3 key-material derive must pass phKey as NULL_PTR")
        return int(CKR_OK)


def test_ssl3_key_and_mac_derive_uses_null_phkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _FakeRaw()
    fake_mech = _FakeKeyMatMechanism()
    rs = SimpleNamespace(
        raw=raw,
        sh=1,
        has_mechanism=lambda name: name == "SSL3_KEY_AND_MAC_DERIVE",
    )
    monkeypatch.setattr(test_ssl3, "_create_generic_secret", lambda *_args: 101)
    monkeypatch.setattr(test_ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: fake_mech)
    monkeypatch.setattr(test_ssl3, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_ssl3,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("should not read a primary derived handle"),
    )

    test_ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material(rs)

    assert raw.ph_keys == [None]


def test_ssl3_master_key_derive_dh_fails_on_wrong_exact_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = b"\x00" * 48
    derive_calls: list[dict[str, Any]] = []

    def _create_generic_secret(_rs: object, data: bytes) -> int:
        assert data == bytes(range(32))
        return 101

    def _derive_key(
        _raw: object,
        _sh: int,
        base_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return 202

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SSL3_MASTER_KEY_DERIVE_DH",
    )
    monkeypatch.setattr(test_ssl3, "_create_generic_secret", _create_generic_secret)
    monkeypatch.setattr(test_ssl3, "derive_key", _derive_key)
    monkeypatch.setattr(test_ssl3, "read_attributes", lambda *_args: {CKA_VALUE: wrong})
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="SSL3 master secret DH output mismatch"):
        test_ssl3.TestSSL3MasterKeyDeriveDH().test_derive_master_secret_dh_exact_vector(
            rs
        )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_SSL3_MASTER_KEY_DERIVE_DH)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    assert derive_calls[0]["mech_param"].params.pVersion is None
