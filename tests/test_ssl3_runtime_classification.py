"""Regression tests for SSL3 runtime reject classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_AES,
    CKM_SSL3_KEY_AND_MAC_DERIVE,
    CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKO_SECRET_KEY,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
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
    def __init__(
        self,
        *,
        iv_client: bytes = b"\x01" * 16,
        iv_server: bytes = b"\x01" * 16,
    ) -> None:
        self.key_mat_out = SimpleNamespace(
            hClientMacSecret=21,
            hServerMacSecret=22,
            hClientKey=23,
            hServerKey=24,
        )
        self._iv_client = iv_client
        self._iv_server = iv_server

    def byref(self) -> object:
        return object()

    def buffer_bytes(self, name: str) -> bytes:
        if name == "iv_client":
            return self._iv_client
        if name == "iv_server":
            return self._iv_server
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


def test_ssl3_key_material_rejects_template_protection_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_ssl3, "_create_generic_secret", lambda *_args: 101)
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(test_ssl3, "destroy_returned_handles", lambda *_args: None)

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

    monkeypatch.setattr(test_ssl3, "_derive_key_material_to_params", _rejecting_key_material)
    monkeypatch.setattr(test_ssl3, "reject_or_classify", _reject_or_classify, raising=False)

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SSL3_KEY_AND_MAC_DERIVE",
    )
    test_ssl3.TestSSL3KeyAndMacDerive().test_rejects_template_protection_conflict(rs)

    expected_attrs = {
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_SENSITIVE: True,
        CKA_EXTRACTABLE: True,
        CKA_TOKEN: False,
    }
    assert key_mat_calls == [(int(CKM_SSL3_KEY_AND_MAC_DERIVE), expected_attrs)]
    assert [call[2] for call in classifier_calls] == [
        "CKM_SSL3_KEY_AND_MAC_DERIVE template protection conflict"
    ]
    assert all(isinstance(call[0], CkrAssertionError) for call in classifier_calls)
    assert all(int(CKR_TEMPLATE_INCONSISTENT) in call[1] for call in classifier_calls)


def test_ssl3_key_material_reference_matches_rfc6101_key_block() -> None:
    """The SSL3 key-block helper follows RFC 6101 section 6.2.2 ordering."""
    master_secret = test_ssl3._ssl3_master_secret_reference(
        test_ssl3._PRE_MASTER_SECRET,
        test_ssl3._CLIENT_RANDOM,
        test_ssl3._SERVER_RANDOM,
    )

    assert test_ssl3._ssl3_key_block_reference(
        master_secret,
        test_ssl3._CLIENT_RANDOM,
        test_ssl3._SERVER_RANDOM,
        96,
    ) == bytes.fromhex(
        "698e3265825326fdf57444e2b1e45064"
        "cceb1267b84f81e14a1ce6c2d9696031"
        "f9efaf9d8e27955f638bda4d0df1d6ab"
        "0eca6dccabd29fdff201da989870bcea"
        "083ea2e07385c9580f7cf01db35d0a20"
        "e601719a5c2a088bd3478436d42fe569"
    )


def test_ssl3_key_material_exact_vector_fails_on_wrong_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_mech = _FakeKeyMatMechanism(iv_client=b"\x00" * 16, iv_server=b"\x00" * 16)
    expected_master = test_ssl3._ssl3_master_secret_reference(
        test_ssl3._PRE_MASTER_SECRET,
        test_ssl3._CLIENT_RANDOM,
        test_ssl3._SERVER_RANDOM,
    )
    created_secrets: list[bytes] = []
    derive_calls: list[tuple[int, dict[int, Any]]] = []
    read_handles: list[int] = []

    def _create_generic_secret(_rs: object, data: bytes) -> int:
        created_secrets.append(data)
        return 101

    def _derive_key_material_to_params(
        _rs: object,
        base_key: int,
        attrs: dict[int, Any],
        mech: Any,
    ) -> None:
        derive_calls.append((base_key, attrs))
        assert mech is fake_mech

    def _read_attributes(
        _raw: object,
        _sh: int,
        handle: int,
        _attrs: list[int],
    ) -> dict[int, bytes]:
        read_handles.append(handle)
        return {CKA_VALUE: b"\x00" * 16}

    rs = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "SSL3_KEY_AND_MAC_DERIVE",
    )
    monkeypatch.setattr(test_ssl3, "_create_generic_secret", _create_generic_secret)
    monkeypatch.setattr(test_ssl3, "mech_ssl3_key_mat", lambda *_args, **_kwargs: fake_mech)
    monkeypatch.setattr(test_ssl3, "_derive_key_material_to_params", _derive_key_material_to_params)
    monkeypatch.setattr(test_ssl3, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_ssl3, "destroy_returned_handles", lambda *_args: None)
    monkeypatch.setattr(test_ssl3, "destroy_quietly", lambda *_args: None)

    with pytest.raises(AssertionError, match="SSL3 key material output mismatch"):
        test_ssl3.TestSSL3KeyAndMacDerive().test_derive_key_material_exact_vector(rs)

    assert created_secrets == [expected_master]
    assert derive_calls == [
        (
            101,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_AES,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            },
        )
    ]
    assert read_handles == [21, 22, 23, 24]


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

    with pytest.raises(pytest.fail.Exception, match="does not match known answer"):
        test_ssl3.TestSSL3MasterKeyDeriveDH().test_derive_master_secret_dh_exact_vector(rs)

    assert len(derive_calls) == 1
    assert derive_calls[0]["base_key"] == 101
    assert derive_calls[0]["mechanism"] == int(CKM_SSL3_MASTER_KEY_DERIVE_DH)
    assert derive_calls[0]["attrs"][CKA_VALUE_LEN] == 48
    assert derive_calls[0]["mech_param"].params.pVersion is None
