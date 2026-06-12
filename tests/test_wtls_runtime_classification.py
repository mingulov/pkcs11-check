"""Regression tests for WTLS protocol-KDF coverage."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from pkcs11_check.raw.pack import mech_wtls_prf
from pkcs11_check.raw.types_std import CK_ULONG, CKA_VALUE, CKM_SHA256, CKM_WTLS_PRF, CKR_OK
from pkcs11_check.testcases import test_wtls


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def test_wtls_prf_helper_uses_output_buffer_and_null_key_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    packed = mech_wtls_prf(
        CKM_WTLS_PRF,
        digest_mechanism=CKM_SHA256,
        seed=b"seed",
        label=b"label",
        output_len=8,
    )
    calls: list[tuple[int, object, int, object, int, object]] = []

    class Raw:
        def C_DeriveKey(  # noqa: N802 - mirrors the PKCS#11 entry point name.
            self,
            session: int,
            mechanism: object,
            base_key: int,
            template: object,
            attribute_count: int,
            new_key: object,
        ) -> int:
            calls.append((session, mechanism, base_key, template, attribute_count, new_key))
            ctypes.memmove(packed.params.pOutput, b"abc", 3)
            output_len = ctypes.cast(
                packed.params.pulOutputLen, ctypes.POINTER(CK_ULONG)
            )
            output_len[0] = 3
            return int(CKR_OK)

    monkeypatch.setattr(test_wtls, "mech_wtls_prf", lambda *_args, **_kwargs: packed)

    result = test_wtls._derive_wtls_prf_output(
        SimpleNamespace(raw=Raw(), sh=42),
        7,
        seed=b"seed",
        label=b"label",
        output_len=8,
    )

    assert result == b"abc"
    assert len(calls) == 1
    assert calls[0][0] == 42
    assert calls[0][2] == 7
    assert calls[0][3] is None
    assert calls[0][4] == 0
    assert calls[0][5] is None


def test_wtls_prf_seed_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        test_wtls,
        "_derive_wtls_prf_output",
        lambda *_args, **_kwargs: b"same-prf-output!",
    )
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("WTLS_PRF")
    with pytest.raises(AssertionError, match="WTLS PRF seed"):
        test_wtls.TestWTLSPRF().test_prf_seed_affects_output(rs)


def test_wtls_prf_label_sensitivity_fails_on_same_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        test_wtls,
        "_derive_wtls_prf_output",
        lambda *_args, **_kwargs: b"same-prf-output!",
    )
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    rs = _session_with_mechanisms("WTLS_PRF")
    with pytest.raises(AssertionError, match="WTLS PRF label"):
        test_wtls.TestWTLSPRF().test_prf_label_affects_output(rs)


class _FakeWTLSKeyMatMechanism:
    def __init__(self, *, mac_handle: int = 11, key_handle: int = 12) -> None:
        self.key_mat_out = SimpleNamespace(
            hMacSecret=mac_handle,
            hKey=key_handle,
        )

    def byref(self) -> object:
        return object()

    def buffer_bytes(self, name: str) -> bytes:
        if name == "iv":
            return b"\x01" * 8
        raise KeyError(name)


class _FakeDeriveRaw:
    def __init__(self) -> None:
        self.ph_keys: list[object | None] = []

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
            raise AssertionError("WTLS key-material derive must pass phKey as NULL_PTR")
        return int(CKR_OK)


def test_wtls_server_key_and_mac_derive_uses_null_phkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _FakeDeriveRaw()
    fake_mech = _FakeWTLSKeyMatMechanism()
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args: 101)
    monkeypatch.setattr(test_wtls, "mech_wtls_key_mat", lambda *_args, **_kwargs: fake_mech)
    monkeypatch.setattr(test_wtls, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_wtls,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("should not read a primary derived handle"),
    )

    test_wtls.TestWTLSKeyAndMacDerive().test_server_key_and_mac_derive(
        SimpleNamespace(
            raw=raw,
            sh=1,
            has_mechanism=lambda name: name == "WTLS_SERVER_KEY_AND_MAC_DERIVE",
        )
    )

    assert raw.ph_keys == [None]


def test_wtls_client_key_and_mac_derive_uses_null_phkey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _FakeDeriveRaw()
    fake_mech = _FakeWTLSKeyMatMechanism()
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args: 101)
    monkeypatch.setattr(test_wtls, "mech_wtls_key_mat", lambda *_args, **_kwargs: fake_mech)
    monkeypatch.setattr(test_wtls, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(
        test_wtls,
        "read_attributes",
        lambda *_args, **_kwargs: pytest.fail("should not read a primary derived handle"),
    )

    test_wtls.TestWTLSKeyAndMacDerive().test_client_key_and_mac_derive(
        SimpleNamespace(
            raw=raw,
            sh=1,
            has_mechanism=lambda name: name == "WTLS_CLIENT_KEY_AND_MAC_DERIVE",
        )
    )

    assert raw.ph_keys == [None]


def test_wtls_server_client_differ_uses_param_key_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _FakeDeriveRaw()
    mechanisms = iter(
        [
            _FakeWTLSKeyMatMechanism(mac_handle=11, key_handle=12),
            _FakeWTLSKeyMatMechanism(mac_handle=21, key_handle=22),
        ]
    )
    read_handles: list[int] = []

    def _read_attributes(_raw: object, _sh: int, handle: int, _attrs: object) -> dict[int, bytes]:
        read_handles.append(handle)
        return {CKA_VALUE: {12: b"server-key", 22: b"client-key"}[handle]}

    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args: 101)
    monkeypatch.setattr(test_wtls, "mech_wtls_key_mat", lambda *_args, **_kwargs: next(mechanisms))
    monkeypatch.setattr(test_wtls, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_wtls, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args: None)

    test_wtls.TestWTLSKeyAndMacDerive().test_server_and_client_differ(
        SimpleNamespace(
            raw=raw,
            sh=1,
            has_mechanism=lambda name: name
            in {"WTLS_SERVER_KEY_AND_MAC_DERIVE", "WTLS_CLIENT_KEY_AND_MAC_DERIVE"},
        )
    )

    assert raw.ph_keys == [None, None]
    assert read_handles == [12, 22]
