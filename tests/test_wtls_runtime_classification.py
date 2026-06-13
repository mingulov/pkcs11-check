"""Regression tests for WTLS protocol-KDF coverage."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.raw.pack import mech_wtls_prf
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKK_GENERIC_SECRET,
    CKM_SHA256,
    CKM_VENDOR_DEFINED,
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE,
    CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
    CKM_WTLS_PRF,
    CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
    CKO_SECRET_KEY,
    CKR_MECHANISM_PARAM_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
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


def test_wtls_prf_output_length_probe_requests_prefix_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)
    output_lengths: list[int] = []

    def _derive_wtls_prf_output(
        *_args: object,
        output_len: int = 16,
        **_kwargs: object,
    ) -> bytes:
        output_lengths.append(output_len)
        return b"a" * 16 if output_len == 16 else (b"a" * 16) + (b"b" * 16)

    monkeypatch.setattr(test_wtls, "_derive_wtls_prf_output", _derive_wtls_prf_output)

    test_wtls.TestWTLSPRF().test_prf_output_len_extends_output(
        _session_with_mechanisms("WTLS_PRF")
    )

    assert output_lengths == [16, 32]


def test_wtls_prf_output_length_fails_on_prefix_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    def _derive_wtls_prf_output(
        *_args: object,
        output_len: int = 16,
        **_kwargs: object,
    ) -> bytes:
        return b"a" * 16 if output_len == 16 else b"b" * 32

    monkeypatch.setattr(test_wtls, "_derive_wtls_prf_output", _derive_wtls_prf_output)

    with pytest.raises(AssertionError, match="longer output"):
        test_wtls.TestWTLSPRF().test_prf_output_len_extends_output(
            _session_with_mechanisms("WTLS_PRF")
        )


def test_wtls_prf_invalid_digest_uses_negative_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)

    digest_mechanisms: list[int] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _derive_prf_output(
        *_args: object,
        digest_mechanism: int = int(CKM_SHA256),
        **_kwargs: object,
    ) -> bytes:
        digest_mechanisms.append(int(digest_mechanism))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, expected_rvs, label))

    monkeypatch.setattr(test_wtls, "_derive_wtls_prf_output", _derive_prf_output)
    monkeypatch.setattr(test_wtls, "reject_or_classify", _reject_or_classify)

    test_wtls.TestWTLSPRF().test_prf_rejects_invalid_digest_mechanism(
        _session_with_mechanisms("WTLS_PRF")
    )

    assert digest_mechanisms == [int(CKM_VENDOR_DEFINED)]
    assert len(classifier_calls) == 1
    assert isinstance(classifier_calls[0][0], CkrAssertionError)
    assert int(CKR_MECHANISM_PARAM_INVALID) in classifier_calls[0][1]
    assert classifier_calls[0][2] == "WTLS PRF invalid digest mechanism"


def test_wtls_derive_invalid_digest_uses_negative_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_wtls, "destroy_returned_handles", lambda *_args, **_kwargs: None)

    derive_calls: list[tuple[int, int]] = []
    key_mat_calls: list[tuple[int, int]] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _rejecting_derive_key(
        _raw: object,
        _session: int,
        _base_key: int,
        mechanism: int,
        **kwargs: object,
    ) -> int:
        mech_param = cast(Any, kwargs["mech_param"])
        derive_calls.append((int(mechanism), int(mech_param.params.DigestMechanism)))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    def _rejecting_key_material(
        _rs: object,
        _base_key: int,
        _attrs: object,
        mech: Any,
    ) -> None:
        key_mat_calls.append((int(mech.ck.mechanism), int(mech.params.DigestMechanism)))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, expected_rvs, label))

    monkeypatch.setattr(test_wtls, "derive_key", _rejecting_derive_key)
    monkeypatch.setattr(test_wtls, "_derive_key_material_to_params", _rejecting_key_material)
    monkeypatch.setattr(test_wtls, "reject_or_classify", _reject_or_classify)

    rs = _session_with_mechanisms(
        "WTLS_MASTER_KEY_DERIVE",
        "WTLS_MASTER_KEY_DERIVE_DH_ECC",
        "WTLS_SERVER_KEY_AND_MAC_DERIVE",
        "WTLS_CLIENT_KEY_AND_MAC_DERIVE",
    )
    test_wtls.TestWTLSMasterKeyDerive().test_rejects_invalid_digest_mechanism(rs)
    test_wtls.TestWTLSMasterKeyDeriveDHECC().test_rejects_invalid_digest_mechanism(rs)
    test_wtls.TestWTLSKeyAndMacDerive().test_server_rejects_invalid_digest_mechanism(rs)
    test_wtls.TestWTLSKeyAndMacDerive().test_client_rejects_invalid_digest_mechanism(rs)

    assert derive_calls == [
        (int(CKM_WTLS_MASTER_KEY_DERIVE), int(CKM_VENDOR_DEFINED)),
        (int(CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC), int(CKM_VENDOR_DEFINED)),
    ]
    assert key_mat_calls == [
        (int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE), int(CKM_VENDOR_DEFINED)),
        (int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE), int(CKM_VENDOR_DEFINED)),
    ]
    assert [call[2] for call in classifier_calls] == [
        "WTLS master key derive invalid digest mechanism",
        "WTLS master key derive DH/ECC invalid digest mechanism",
        "WTLS server key-and-MAC derive invalid digest mechanism",
        "WTLS client key-and-MAC derive invalid digest mechanism",
    ]
    assert all(isinstance(call[0], CkrAssertionError) for call in classifier_calls)
    assert all(int(CKR_MECHANISM_PARAM_INVALID) in call[1] for call in classifier_calls)


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


def test_wtls_key_material_rejects_template_protection_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_wtls, "_create_generic_secret", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(test_wtls, "destroy_quietly", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(test_wtls, "destroy_returned_handles", lambda *_args, **_kwargs: None)

    key_mat_calls: list[tuple[int, dict[int, Any]]] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _rejecting_key_material(
        _rs: object,
        _base_key: int,
        attrs: dict[int, Any],
        mech: Any,
    ) -> None:
        key_mat_calls.append((int(mech.ck.mechanism), attrs))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
            int(CKR_TEMPLATE_INCONSISTENT),
        )

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, expected_rvs, label))

    monkeypatch.setattr(test_wtls, "_derive_key_material_to_params", _rejecting_key_material)
    monkeypatch.setattr(test_wtls, "reject_or_classify", _reject_or_classify)

    rs = _session_with_mechanisms(
        "WTLS_SERVER_KEY_AND_MAC_DERIVE",
        "WTLS_CLIENT_KEY_AND_MAC_DERIVE",
    )
    test_wtls.TestWTLSKeyAndMacDerive().test_server_rejects_template_protection_conflict(rs)
    test_wtls.TestWTLSKeyAndMacDerive().test_client_rejects_template_protection_conflict(rs)

    expected_attrs = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_GENERIC_SECRET,
        CKA_SENSITIVE: True,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }
    assert key_mat_calls == [
        (int(CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE), expected_attrs),
        (int(CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE), expected_attrs),
    ]
    assert [call[2] for call in classifier_calls] == [
        "WTLS server key-and-MAC derive template protection conflict",
        "WTLS client key-and-MAC derive template protection conflict",
    ]
    assert all(isinstance(call[0], CkrAssertionError) for call in classifier_calls)
    assert all(int(CKR_TEMPLATE_INCONSISTENT) in call[1] for call in classifier_calls)
