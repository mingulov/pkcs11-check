"""Regression tests for X9.42 DH generated-parameter coverage."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_X9_42_DH1_DERIVE_PARAMS,
    CK_X9_42_DH2_DERIVE_PARAMS,
    CK_X9_42_MQV_DERIVE_PARAMS,
    CKA_BASE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKD_SHA1_KDF_ASN1,
    CKD_SHA1_KDF_CONCATENATE,
    CKK_AES,
    CKM_X9_42_DH_DERIVE,
    CKM_X9_42_DH_HYBRID_DERIVE,
    CKM_X9_42_MQV_DERIVE,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_x942_dh


def _session_with_mechanisms(*mechanisms: str) -> SimpleNamespace:
    names = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in names,
    )


def _generated_param_attrs() -> dict[int, Any]:
    return {
        CKA_PRIME: b"\x80" + (b"\x00" * 255),
        CKA_BASE: b"\x02",
        CKA_SUBPRIME: b"\x80" + (b"\x00" * 31),
        CKA_PRIME_BITS: 2048,
        CKA_SUBPRIME_BITS: 256,
    }


def test_x942_parameter_gen_exercises_advertised_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def _param_gen_ok(*_args: Any, **_kwargs: Any) -> int:
        nonlocal called
        called = True
        return 77

    rs = _session_with_mechanisms("X9_42_DH_PARAMETER_GEN")
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", _param_gen_ok, raising=False)
    monkeypatch.setattr(test_x942_dh, "read_attributes", lambda *_args: _generated_param_attrs())
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHParameterGen().test_generate_parameters(rs)

    assert called


def test_x942_parameter_gen_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _param_gen_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms("X9_42_DH_PARAMETER_GEN")
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", _param_gen_reject, raising=False)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    with pytest.raises(pytest.xfail.Exception, match="X9_42_DH_PARAMETER_GEN advertised"):
        test_x942_dh.TestX942DHParameterGen().test_generate_parameters(rs)


def test_x942_keypair_from_generated_params_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _keypair_reject(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    rs = _session_with_mechanisms(
        "X9_42_DH_PARAMETER_GEN",
        "X9_42_DH_KEY_PAIR_GEN",
        "X9_42_DH_DERIVE",
    )
    monkeypatch.setattr(test_x942_dh, "_generate_x942_params", lambda *_args, **_kwargs: 77)
    monkeypatch.setattr(test_x942_dh, "read_attributes", lambda *_args: _generated_param_attrs())
    monkeypatch.setattr(test_x942_dh, "_generate_x942_keypair", _keypair_reject)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    with pytest.raises(pytest.xfail.Exception, match="X9_42_DH_KEY_PAIR_GEN advertised"):
        test_x942_dh.TestX942DHParameterGen().test_generated_params_produce_valid_derive(rs)


def test_x942_rfc5114_exact_vector_constant_matches_modexp() -> None:
    """The embedded X9.42 exact-vector expected value is derived from RFC 5114 params."""
    prime = int.from_bytes(test_x942_dh.X942_PRIME_2048, "big")
    generator = int.from_bytes(test_x942_dh.X942_GEN, "big")
    alice_private = int.from_bytes(test_x942_dh._X942_RFC5114_ALICE_PRIVATE, "big")
    bob_public = int.from_bytes(test_x942_dh._X942_RFC5114_BOB_PUBLIC, "big")

    assert pow(generator, alice_private, prime) != bob_public

    full_secret = pow(bob_public, alice_private, prime).to_bytes(
        len(test_x942_dh.X942_PRIME_2048),
        "big",
    )
    assert full_secret[-32:] == test_x942_dh._X942_RFC5114_EXPECTED_SECRET_32


def test_x942_concatenate_kdf_other_info_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[dict[str, Any]] = []
    encrypted: list[bytes] = []

    def _derive_key(
        _raw: Any,
        _sh: int,
        _base_key: int,
        mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        assert mechanism == CKM_X9_42_DH_DERIVE
        assert attrs[CKA_KEY_TYPE] == CKK_AES
        assert isinstance(mech_param.params, CK_X9_42_DH1_DERIVE_PARAMS)
        params = mech_param.params
        assert params.kdf == CKD_SHA1_KDF_CONCATENATE
        assert params.ulOtherInfoLen > 0
        assert params.pOtherInfo is not None
        derive_calls.append({"value_len": attrs[CKA_VALUE_LEN]})
        return 77

    def _encrypt(_raw: Any, _sh: int, _key: int, _mechanism: int, plaintext: bytes) -> bytes:
        encrypted.append(plaintext)
        return b"ciphertext"

    rs = _session_with_mechanisms("X9_42_DH_DERIVE")
    monkeypatch.setattr(test_x942_dh, "_import_x942_private_key", lambda *_args: 55)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "encrypt_single", _encrypt)
    monkeypatch.setattr(test_x942_dh, "decrypt_single", lambda *_args: encrypted[-1])
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHDerive().test_x942_dh_derive_concatenate_other_info(rs)

    assert derive_calls == [{"value_len": 16}]


def test_x942_asn1_kdf_other_info_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[dict[str, Any]] = []
    encrypted: list[bytes] = []

    def _derive_key(
        _raw: Any,
        _sh: int,
        _base_key: int,
        mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        assert mechanism == CKM_X9_42_DH_DERIVE
        assert attrs[CKA_KEY_TYPE] == CKK_AES
        assert isinstance(mech_param.params, CK_X9_42_DH1_DERIVE_PARAMS)
        params = mech_param.params
        assert params.kdf == CKD_SHA1_KDF_ASN1
        assert params.ulOtherInfoLen == len(b"\x04\x03der")
        assert params.pOtherInfo is not None
        derive_calls.append({"value_len": attrs[CKA_VALUE_LEN]})
        return 78

    def _encrypt(_raw: Any, _sh: int, _key: int, _mechanism: int, plaintext: bytes) -> bytes:
        encrypted.append(plaintext)
        return b"ciphertext"

    rs = _session_with_mechanisms("X9_42_DH_DERIVE")
    monkeypatch.setattr(test_x942_dh, "_import_x942_private_key", lambda *_args: 55)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "encrypt_single", _encrypt)
    monkeypatch.setattr(test_x942_dh, "decrypt_single", lambda *_args: encrypted[-1])
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHDerive().test_x942_dh_derive_asn1_other_info(rs)

    assert derive_calls == [{"value_len": 16}]


@pytest.mark.parametrize(
    ("case_cls", "method_name", "mechanism", "param_type"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_matches_between_parties",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_matches_between_parties",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
        ),
    ),
)
def test_x942_extended_derive_tests_reach_c_derive_key_with_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
) -> None:
    assert hasattr(case_cls, method_name)

    party_calls = 0
    next_handle = 100
    derived_values: dict[int, bytes] = {}
    seen_param_types: list[type] = []

    def _import_party_keys(_rs: Any, _first_private: bytes, _second_private: bytes) -> tuple[
        int,
        int,
        int,
        int,
        bytes,
        bytes,
    ]:
        nonlocal party_calls, next_handle
        party_calls += 1
        prefix = b"alice" if party_calls == 1 else b"bob"
        handles = tuple(range(next_handle, next_handle + 4))
        next_handle += 4
        return (
            handles[0],
            handles[1],
            handles[2],
            handles[3],
            prefix + b"-public-1",
            prefix + b"-public-2",
        )

    def _derive_key(
        _raw: Any,
        _sh: int,
        _base_key: int,
        actual_mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        nonlocal next_handle
        assert actual_mechanism == mechanism
        assert attrs[CKA_VALUE_LEN] == 32
        assert int(mech_param.ck.mechanism) == int(mechanism)
        assert isinstance(mech_param.params, param_type)
        params = cast(
            CK_X9_42_DH2_DERIVE_PARAMS | CK_X9_42_MQV_DERIVE_PARAMS,
            mech_param.params,
        )
        assert params.ulPublicDataLen > 0
        assert params.ulPublicDataLen2 > 0
        seen_param_types.append(type(mech_param.params))
        handle = next_handle
        next_handle += 1
        derived_values[handle] = b"shared x9.42 extended secret!".ljust(32, b"\x00")
        return handle

    def _read_attributes(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: derived_values[handle]}

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party_keys)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    rs = _session_with_mechanisms(
        "X9_42_DH_HYBRID_DERIVE",
        "X9_42_MQV_DERIVE",
    )
    getattr(case_cls(), method_name)(rs)

    assert party_calls == 2
    assert seen_param_types == [param_type, param_type]


@pytest.mark.parametrize(
    (
        "case_cls",
        "method_name",
        "mechanism",
        "param_type",
        "expected_kdf",
        "expects_other_info",
        "expected_label",
    ),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_rejects_ckd_null_other_info",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
            CKD_NULL,
            True,
            "CKM_X9_42_DH_HYBRID_DERIVE CKD_NULL with OtherInfo",
        ),
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_rejects_asn1_kdf_missing_other_info",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
            CKD_SHA1_KDF_ASN1,
            False,
            "CKM_X9_42_DH_HYBRID_DERIVE CKD_SHA1_KDF_ASN1 missing OtherInfo",
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_rejects_ckd_null_other_info",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
            CKD_NULL,
            True,
            "CKM_X9_42_MQV_DERIVE CKD_NULL with OtherInfo",
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_rejects_asn1_kdf_missing_other_info",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
            CKD_SHA1_KDF_ASN1,
            False,
            "CKM_X9_42_MQV_DERIVE CKD_SHA1_KDF_ASN1 missing OtherInfo",
        ),
    ),
)
def test_x942_extended_other_info_negative_rules_use_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
    expected_kdf: int,
    expects_other_info: bool,
    expected_label: str,
) -> None:
    assert hasattr(case_cls, method_name)

    party_calls = 0
    derive_calls = 0
    classified_labels: list[str] = []

    class _Raw:
        def C_DeriveKey(  # noqa: N802
            self,
            _sh: int,
            mech_ref: Any,
            _base_key: int,
            _attrs_ptr: Any,
            _attrs_count: int,
            _derived: Any,
        ) -> int:
            nonlocal derive_calls
            derive_calls += 1
            ck_mech = mech_ref._obj
            assert int(ck_mech.mechanism) == int(mechanism)
            assert int(ck_mech.ulParameterLen) == ctypes.sizeof(param_type)
            params = ctypes.cast(ck_mech.pParameter, ctypes.POINTER(param_type)).contents
            assert isinstance(params, param_type)
            assert int(params.kdf) == int(expected_kdf)
            if expects_other_info:
                assert params.ulOtherInfoLen > 0
                assert params.pOtherInfo is not None
            else:
                assert params.ulOtherInfoLen == 0
                assert params.pOtherInfo is None
            assert params.ulPublicDataLen > 0
            assert params.ulPublicDataLen2 > 0
            return int(CKR_MECHANISM_PARAM_INVALID)

    def _import_party_keys(_rs: Any, _first_private: bytes, _second_private: bytes) -> tuple[
        int,
        int,
        int,
        int,
        bytes,
        bytes,
    ]:
        nonlocal party_calls
        party_calls += 1
        prefix = b"alice" if party_calls == 1 else b"bob"
        base = 10 * party_calls
        return (
            base + 1,
            base + 2,
            base + 3,
            base + 4,
            prefix + b"-public-1",
            prefix + b"-public-2",
        )

    def _classify_negative_rv(rv: int, expected_rvs: tuple[int, ...], *, label: str) -> None:
        assert int(rv) == int(CKR_MECHANISM_PARAM_INVALID)
        assert int(CKR_MECHANISM_PARAM_INVALID) in {int(expected) for expected in expected_rvs}
        classified_labels.append(label)

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party_keys)
    monkeypatch.setattr(test_x942_dh, "classify_negative_rv", _classify_negative_rv)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    rs = SimpleNamespace(
        raw=_Raw(),
        sh=1,
        has_mechanism=lambda name: name in {"X9_42_DH_HYBRID_DERIVE", "X9_42_MQV_DERIVE"},
    )
    getattr(case_cls(), method_name)(rs)

    assert party_calls == 2
    assert derive_calls == 1
    assert classified_labels == [expected_label]


@pytest.mark.parametrize(
    ("case_cls", "method_name", "mechanism", "param_type"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_concatenate_other_info",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_concatenate_other_info",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
        ),
    ),
)
def test_x942_extended_concatenate_kdf_other_info_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
) -> None:
    assert hasattr(case_cls, method_name)

    party_calls = 0
    next_handle = 100
    derived_values: dict[int, bytes] = {}
    seen_param_types: list[type] = []

    def _import_party_keys(_rs: Any, _first_private: bytes, _second_private: bytes) -> tuple[
        int,
        int,
        int,
        int,
        bytes,
        bytes,
    ]:
        nonlocal party_calls, next_handle
        party_calls += 1
        prefix = b"alice" if party_calls == 1 else b"bob"
        handles = tuple(range(next_handle, next_handle + 4))
        next_handle += 4
        return (
            handles[0],
            handles[1],
            handles[2],
            handles[3],
            prefix + b"-public-1",
            prefix + b"-public-2",
        )

    def _derive_key(
        _raw: Any,
        _sh: int,
        _base_key: int,
        actual_mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        nonlocal next_handle
        assert actual_mechanism == mechanism
        assert attrs[CKA_VALUE_LEN] == 32
        assert int(mech_param.ck.mechanism) == int(mechanism)
        assert isinstance(mech_param.params, param_type)
        params = cast(
            CK_X9_42_DH2_DERIVE_PARAMS | CK_X9_42_MQV_DERIVE_PARAMS,
            mech_param.params,
        )
        assert params.kdf == CKD_SHA1_KDF_CONCATENATE
        assert params.ulOtherInfoLen > 0
        assert params.pOtherInfo is not None
        seen_param_types.append(type(mech_param.params))
        handle = next_handle
        next_handle += 1
        derived_values[handle] = b"shared x9.42 extended secret!".ljust(32, b"\x00")
        return handle

    def _read_attributes(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: derived_values[handle]}

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party_keys)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    rs = _session_with_mechanisms(
        "X9_42_DH_HYBRID_DERIVE",
        "X9_42_MQV_DERIVE",
    )
    getattr(case_cls(), method_name)(rs)

    assert party_calls == 2
    assert seen_param_types == [param_type, param_type]


@pytest.mark.parametrize(
    ("case_cls", "method_name", "mechanism", "param_type"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_asn1_other_info",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_asn1_other_info",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
        ),
    ),
)
def test_x942_extended_asn1_kdf_other_info_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
) -> None:
    assert hasattr(case_cls, method_name)

    party_calls = 0
    next_handle = 100
    derived_values: dict[int, bytes] = {}
    seen_param_types: list[type] = []

    def _import_party_keys(_rs: Any, _first_private: bytes, _second_private: bytes) -> tuple[
        int,
        int,
        int,
        int,
        bytes,
        bytes,
    ]:
        nonlocal party_calls, next_handle
        party_calls += 1
        prefix = b"alice" if party_calls == 1 else b"bob"
        handles = tuple(range(next_handle, next_handle + 4))
        next_handle += 4
        return (
            handles[0],
            handles[1],
            handles[2],
            handles[3],
            prefix + b"-public-1",
            prefix + b"-public-2",
        )

    def _derive_key(
        _raw: Any,
        _sh: int,
        _base_key: int,
        actual_mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        nonlocal next_handle
        assert actual_mechanism == mechanism
        assert attrs[CKA_VALUE_LEN] == 32
        assert int(mech_param.ck.mechanism) == int(mechanism)
        assert isinstance(mech_param.params, param_type)
        params = cast(
            CK_X9_42_DH2_DERIVE_PARAMS | CK_X9_42_MQV_DERIVE_PARAMS,
            mech_param.params,
        )
        assert params.kdf == CKD_SHA1_KDF_ASN1
        assert params.ulOtherInfoLen == len(b"\x04\x03der")
        assert params.pOtherInfo is not None
        seen_param_types.append(type(mech_param.params))
        handle = next_handle
        next_handle += 1
        derived_values[handle] = b"shared x9.42 extended asn1".ljust(32, b"\x00")
        return handle

    def _read_attributes(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: derived_values[handle]}

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party_keys)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    rs = _session_with_mechanisms(
        "X9_42_DH_HYBRID_DERIVE",
        "X9_42_MQV_DERIVE",
    )
    getattr(case_cls(), method_name)(rs)

    assert party_calls == 2
    assert seen_param_types == [param_type, param_type]


@pytest.mark.parametrize(
    ("case_cls", "method_name", "mechanism", "param_type"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_value_len_truncation",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_value_len_truncation",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
        ),
    ),
)
def test_x942_extended_derive_value_len_truncation_uses_rightmost_bytes(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
) -> None:
    assert hasattr(case_cls, method_name)

    party_calls = 0
    next_handle = 100
    base_value = b"x9.42 extended truncation vector"
    base_value = base_value[:32].ljust(32, b"\x00")
    derived_values: dict[int, bytes] = {}
    derive_calls: list[dict[str, Any]] = []

    def _import_party_keys(_rs: Any, _first_private: bytes, _second_private: bytes) -> tuple[
        int,
        int,
        int,
        int,
        bytes,
        bytes,
    ]:
        nonlocal party_calls, next_handle
        party_calls += 1
        prefix = b"alice" if party_calls == 1 else b"bob"
        handles = tuple(range(next_handle, next_handle + 4))
        next_handle += 4
        return (
            handles[0],
            handles[1],
            handles[2],
            handles[3],
            prefix + b"-public-1",
            prefix + b"-public-2",
        )

    def _derive_key(
        _raw: Any,
        _sh: int,
        base_key: int,
        actual_mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        nonlocal next_handle
        assert actual_mechanism == mechanism
        assert int(mech_param.ck.mechanism) == int(mechanism)
        assert isinstance(mech_param.params, param_type)
        requested_len = attrs[CKA_VALUE_LEN]
        handle = next_handle
        next_handle += 1
        derived_values[handle] = base_value[-requested_len:]
        derive_calls.append(
            {
                "base_key": base_key,
                "mechanism": int(actual_mechanism),
                "value_len": requested_len,
                "param_type": type(mech_param.params),
            }
        )
        return handle

    def _read_attributes(_raw: Any, _sh: int, handle: int, attrs: list[int]) -> dict[int, Any]:
        assert attrs == [CKA_VALUE]
        return {CKA_VALUE: derived_values[handle]}

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party_keys)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_key)
    monkeypatch.setattr(test_x942_dh, "read_attributes", _read_attributes)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    rs = _session_with_mechanisms(
        "X9_42_DH_HYBRID_DERIVE",
        "X9_42_MQV_DERIVE",
    )
    getattr(case_cls(), method_name)(rs)

    assert party_calls == 2
    assert [call["value_len"] for call in derive_calls] == [32, 16]
    assert {call["mechanism"] for call in derive_calls} == {int(mechanism)}
    assert {call["param_type"] for call in derive_calls} == {param_type}
