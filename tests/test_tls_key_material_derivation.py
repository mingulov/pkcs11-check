"""Regression tests for TLS key-material derivation contracts."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKM_SHA256,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
    CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
    CKM_TLS12_MASTER_KEY_DERIVE,
    CKM_TLS12_MASTER_KEY_DERIVE_DH,
    CKM_TLS_KDF,
    CKM_TLS_PRF,
    CKR_OK,
)
from pkcs11_check.testcases import test_tls12

_TLS10_KDF_EXPECTED_HEX = "023d49a0cea8ad8071bf64519dc8f45bd302c1db3e33d39d1f21c548d05194aa"
_TLS12_MASTER_EXPECTED_HEX = (
    "2b7cccb6d48adb8692df640b9252502fb000fd68fb2dc4b6a8cd67d870492f38"
    "e4c5dd509ba7c4863c003c07d23f9a3b"
)
_TLS12_MASTER_DH_EXPECTED_HEX = (
    "2f759d1b14d26737622ba106d6321958f3913a545a502a34073d305f2c90fe73"
    "d184bf43c4352b4b83e1b58072a47eb8"
)
_TLS12_EMS_EXPECTED_HEX = (
    "c3d5ea08b472cbb67e205711e5006647e2b8cb5f6b2a20847780122bdb78cf87"
    "4a37fb5aa6ae0e3ce513256f888efa1b"
)
_TLS12_EMS_DH_EXPECTED_HEX = (
    "48cf0bec47fd85bf9c0ed067a961a5b0bae70feef18b231d32e11c6155c49959"
    "f333fa7c155d455e67cf44cd295e3f0a"
)


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


def _tls_kdf_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "TLS_KDF",
    )


def _tls12_ems_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "TLS12_EXTENDED_MASTER_KEY_DERIVE",
    )


def _tls12_master_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "TLS12_MASTER_KEY_DERIVE",
    )


def _tls12_master_dh_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "TLS12_MASTER_KEY_DERIVE_DH",
    )


def _tls12_ems_dh_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "TLS12_EXTENDED_MASTER_KEY_DERIVE_DH",
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


def test_tls10_prf_reference_matches_rfc2246_split_secret_vector() -> None:
    value = test_tls12._tls_prf_legacy_md5_sha1(
        bytes(range(48)),
        b"key expansion",
        bytes(range(32)),
        bytes(range(32, 64)),
        32,
    )

    assert value.hex() == _TLS10_KDF_EXPECTED_HEX


def test_tls12_master_secret_reference_matches_prf_vector() -> None:
    value = test_tls12._tls12_prf_sha256(
        bytes(range(48)),
        b"master secret",
        bytes(range(32)),
        bytes(range(32, 64)),
        48,
    )

    assert value.hex() == _TLS12_MASTER_EXPECTED_HEX


def test_tls12_master_secret_dh_reference_matches_prf_vector() -> None:
    value = test_tls12._tls12_prf_sha256(
        bytes(range(32)),
        b"master secret",
        bytes(range(32)),
        bytes(range(32, 64)),
        48,
    )

    assert value.hex() == _TLS12_MASTER_DH_EXPECTED_HEX


def test_tls12_extended_master_secret_reference_matches_rfc7627_prf_vector() -> None:
    value = test_tls12._tls12_extended_master_secret_reference(
        bytes(range(48)),
        bytes(range(32)),
        48,
    )

    assert value.hex() == _TLS12_EMS_EXPECTED_HEX


def test_tls12_extended_master_secret_dh_reference_matches_rfc7627_prf_vector() -> None:
    value = test_tls12._tls12_extended_master_secret_reference(
        bytes(range(32)),
        bytes(range(32)),
        48,
    )

    assert value.hex() == _TLS12_EMS_DH_EXPECTED_HEX


def test_tls_kdf_tls10_exact_vector_uses_tls_prf_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = bytes.fromhex(_TLS10_KDF_EXPECTED_HEX)
    derive_calls: list[dict[str, Any]] = []

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

    monkeypatch.setattr(test_tls12, "_create_tls_pms", lambda _rs: 101)
    monkeypatch.setattr(test_tls12, "derive_key", _derive_key)
    monkeypatch.setattr(test_tls12, "read_attributes", lambda *_args: {CKA_VALUE: expected})
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)

    test_tls12.TestTLS12KDF().test_tls_kdf_tls10_prf_exact_vector(_tls_kdf_session())

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_TLS_KDF)
    assert derive_calls[0]["mech_param"].params.prfMechanism == int(CKM_TLS_PRF)


def test_tls12_master_key_derive_fails_on_wrong_exact_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = b"\x00" * 48
    derive_calls: list[dict[str, Any]] = []

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
        return 303

    monkeypatch.setattr(test_tls12, "_create_tls_pms", lambda _rs: 101)
    monkeypatch.setattr(test_tls12, "derive_key", _derive_key)
    monkeypatch.setattr(test_tls12, "read_attributes", lambda *_args: {CKA_VALUE: wrong})
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="master secret output mismatch"):
        test_tls12.TestTLS12MasterKeyDerive().test_master_key_derive(_tls12_master_session())

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_TLS12_MASTER_KEY_DERIVE)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    assert derive_calls[0]["mech_param"].params.prfHashMechanism == int(CKM_SHA256)


def test_tls12_master_key_derive_dh_fails_on_wrong_exact_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = b"\x00" * 48
    derive_calls: list[dict[str, Any]] = []

    def _create_generic_secret(_rs: object, data: bytes, *args: object) -> int:
        assert data == bytes(range(32))
        assert args == ()
        return 111

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
        return 404

    monkeypatch.setattr(test_tls12, "_create_generic_secret", _create_generic_secret)
    monkeypatch.setattr(test_tls12, "derive_key", _derive_key)
    monkeypatch.setattr(test_tls12, "read_attributes", lambda *_args: {CKA_VALUE: wrong})
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="master secret DH output mismatch"):
        test_tls12.TestTLS12MasterKeyDerive().test_master_key_derive_dh(
            _tls12_master_dh_session()
        )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 111
    assert derive_calls[0]["mechanism"] == int(CKM_TLS12_MASTER_KEY_DERIVE_DH)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    assert derive_calls[0]["mech_param"].params.prfHashMechanism == int(CKM_SHA256)


def test_tls12_extended_master_key_derive_fails_on_wrong_exact_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = b"\x00" * 48
    derive_calls: list[dict[str, Any]] = []

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
        return 303

    monkeypatch.setattr(test_tls12, "_create_tls_pms", lambda _rs: 101)
    monkeypatch.setattr(test_tls12, "derive_key", _derive_key)
    monkeypatch.setattr(test_tls12, "read_attributes", lambda *_args: {CKA_VALUE: wrong})
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="extended master secret output mismatch"):
        test_tls12.TestTLS12Extended().test_extended_master_key_derive(_tls12_ems_session())

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    params = derive_calls[0]["mech_param"].params
    assert params.prfHashMechanism == int(CKM_SHA256)
    assert params.ulSessionHashLen == 32
    assert ctypes.string_at(params.pSessionHash, params.ulSessionHashLen) == bytes(range(32))


def test_tls12_extended_master_key_derive_dh_fails_on_wrong_exact_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong = b"\x00" * 48
    derive_calls: list[dict[str, Any]] = []

    def _create_generic_secret(_rs: object, data: bytes, *args: object) -> int:
        assert data == bytes(range(32))
        assert args == ()
        return 111

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
        return 404

    monkeypatch.setattr(test_tls12, "_create_generic_secret", _create_generic_secret)
    monkeypatch.setattr(test_tls12, "derive_key", _derive_key)
    monkeypatch.setattr(test_tls12, "read_attributes", lambda *_args: {CKA_VALUE: wrong})
    monkeypatch.setattr(test_tls12, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="extended master secret DH output mismatch"):
        test_tls12.TestTLS12Extended().test_extended_master_key_derive_dh(
            _tls12_ems_dh_session()
        )

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 111
    assert derive_calls[0]["mechanism"] == int(CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    params = derive_calls[0]["mech_param"].params
    assert params.prfHashMechanism == int(CKM_SHA256)
    assert params.ulSessionHashLen == 32
    assert ctypes.string_at(params.pSessionHash, params.ulSessionHashLen) == bytes(range(32))
