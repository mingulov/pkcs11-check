"""Regression tests for X9.42 DH generated-parameter coverage."""

from __future__ import annotations

import ctypes
from collections.abc import Generator
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_X9_42_DH1_DERIVE_PARAMS,
    CK_X9_42_DH2_DERIVE_PARAMS,
    CK_X9_42_MQV_DERIVE_PARAMS,
    CKA_BASE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_PRIME,
    CKA_PRIME_BITS,
    CKA_SENSITIVE,
    CKA_SUBPRIME,
    CKA_SUBPRIME_BITS,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKD_NULL,
    CKD_SHA1_KDF_ASN1,
    CKD_SHA1_KDF_CONCATENATE,
    CKK_AES,
    CKK_GENERIC_SECRET,
    CKM_X9_42_DH_DERIVE,
    CKM_X9_42_DH_HYBRID_DERIVE,
    CKM_X9_42_MQV_DERIVE,
    CKO_SECRET_KEY,
    CKR_GENERAL_ERROR,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases import test_x942_dh
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


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


def test_x942_shared_secret_records_both_missing_public_values_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21), (12, 22)])
    derive_calls: list[tuple[int, bytes]] = []
    destroyed: list[int] = []

    monkeypatch.setattr(test_x942_dh, "_generate_x942_keypair", lambda *_args: next(generated))
    monkeypatch.setattr(
        test_x942_dh,
        "read_attributes",
        lambda *_args: {},
    )

    def _derive(_rs: Any, private: int, peer_value: bytes, **_kwargs: Any) -> int:
        derive_calls.append((private, peer_value))
        return 100 + len(derive_calls)

    monkeypatch.setattr(test_x942_dh, "_x942_derive_aes", _derive)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    rs = _session_with_mechanisms("X9_42_DH_KEY_PAIR_GEN", "X9_42_DH_DERIVE")
    test_x942_dh.TestX942DHDerive().test_derive_shared_secret(rs)

    assert derive_calls == []
    assert destroyed == [11, 21, 12, 22]
    records = C.get_records()
    assert len(records) == 2
    assert [record.operation for record in records] == [
        "C_GetAttributeValue",
        "C_GetAttributeValue",
    ]
    assert [record.detail["attribute"]["id"] for record in records if record.detail] == [
        int(CKA_VALUE),
        int(CKA_VALUE),
    ]


def test_x942_shared_secret_derives_independent_available_side_when_peer_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21), (12, 22)])
    derive_calls: list[tuple[int, bytes]] = []
    destroyed: list[int] = []

    monkeypatch.setattr(test_x942_dh, "_generate_x942_keypair", lambda *_args: next(generated))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 11 else {CKA_VALUE: b"bob-public"}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)

    def _derive(_rs: Any, private: int, peer_value: bytes, **_kwargs: Any) -> int:
        derive_calls.append((private, peer_value))
        return 100

    monkeypatch.setattr(test_x942_dh, "_x942_derive_aes", _derive)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    rs = _session_with_mechanisms("X9_42_DH_KEY_PAIR_GEN", "X9_42_DH_DERIVE")
    test_x942_dh.TestX942DHDerive().test_derive_shared_secret(rs)

    assert derive_calls == [(21, b"bob-public")]
    assert destroyed == [11, 21, 12, 22, 100]
    assert [record.detail["attribute"]["id"] for record in C.get_records() if record.detail] == [
        int(CKA_VALUE),
    ]


def test_x942_parameter_read_preserves_independent_presence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        test_x942_dh,
        "read_attributes",
        lambda *_args: {
            CKA_PRIME: b"prime",
            CKA_SUBPRIME: b"subprime",
            CKA_PRIME_BITS: 2048,
            CKA_SUBPRIME_BITS: 256,
        },
    )

    result = test_x942_dh._read_x942_params(object(), 1, 77)

    assert result == (b"prime", MISSING_ATTRIBUTE, b"subprime", 2048, 256)
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail is not None
    assert records[0].detail["attribute"]["id"] == int(CKA_BASE)


def test_x942_generated_params_keep_metadata_contradiction_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attrs = _generated_param_attrs()
    attrs.pop(CKA_BASE)
    attrs[CKA_PRIME_BITS] = 1024
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_x942_dh,
        "_generate_x942_params_for_session",
        lambda _rs: (77, 2048, 256),
    )
    monkeypatch.setattr(test_x942_dh, "read_attributes", lambda *_args: attrs)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms(
        "X9_42_DH_PARAMETER_GEN",
        "X9_42_DH_KEY_PAIR_GEN",
        "X9_42_DH_DERIVE",
    )

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942DHParameterGen().test_generated_params_produce_valid_derive(rs)

    records = C.get_records()
    assert destroyed == [77]
    assert {record.reason for record in records} == {"not_operational", "wrong_result"}
    missing = [record for record in records if record.reason == "not_operational"]
    assert len(missing) == 1
    assert missing[0].detail is not None
    assert missing[0].detail["attribute"]["id"] == int(CKA_BASE)
    assert missing[0].operation == "C_GetAttributeValue"
    wrong = [record for record in records if record.reason == "wrong_result"]
    assert len(wrong) == 1
    assert wrong[0].kind == "metadata"
    assert wrong[0].operation == "C_GenerateKey"
    assert wrong[0].mechanism == "CKM_X9_42_DH_PARAMETER_GEN"


def test_x942_keypair_validates_private_type_when_public_type_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    monkeypatch.setattr(test_x942_dh, "_generate_x942_keypair", lambda *_args: (11, 12))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 11 else {CKA_KEY_TYPE: 999}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms("X9_42_DH_KEY_PAIR_GEN")

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942DHKeyPairGen().test_keypair_has_correct_key_type(rs)

    records = C.get_records()
    assert destroyed == [11, 12]
    assert {record.reason for record in records} == {"not_operational", "wrong_result"}
    assert any(
        record.detail and record.detail["attribute"]["id"] == int(CKA_KEY_TYPE)
        for record in records
        if record.reason == "not_operational"
    )
    wrong = [record for record in records if record.reason == "wrong_result"]
    assert len(wrong) == 1
    assert wrong[0].kind == "metadata"
    assert wrong[0].operation == "C_GenerateKeyPair"
    assert wrong[0].mechanism == "CKM_X9_42_DH_KEY_PAIR_GEN"


def test_x942_hybrid_reads_peer_secret_after_missing_first_and_classifies_malformed_second(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    party_calls = 0
    read_handles: list[int] = []
    destroyed: list[int] = []
    derived = iter([203, 204])

    def _import_party(
        _rs: Any, _first: bytes, _second: bytes
    ) -> tuple[int, int, int, int, bytes, bytes]:
        nonlocal party_calls
        party_calls += 1
        base = 10 if party_calls == 1 else 20
        prefix = b"alice" if party_calls == 1 else b"bob"
        return base + 1, base + 2, base + 3, base + 4, prefix + b"-one", prefix + b"-two"

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party)
    monkeypatch.setattr(
        test_x942_dh,
        "_x942_derive_generic_secret",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {} if handle == 203 else {CKA_VALUE: b""}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms("X9_42_DH_HYBRID_DERIVE")

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942DHHybridDerive().test_hybrid_derive_matches_between_parties(rs)

    assert read_handles == [203, 204]
    assert destroyed == [11, 12, 13, 14, 21, 22, 23, 24, 203, 204]
    assert any(record.reason == "wrong_result" for record in C.get_records())


def test_x942_dh_truncation_reads_later_output_after_missing_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[int] = []
    destroyed: list[int] = []
    derived = iter([601, 602])
    monkeypatch.setattr(test_x942_dh, "_import_x942_private_key", lambda *_args: 501)
    monkeypatch.setattr(
        test_x942_dh,
        "derive_key",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 601 else {CKA_VALUE: b"bad"}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms("X9_42_DH_DERIVE")

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942DHDerive().test_x942_dh_derive_rfc5114_value_len_truncation(rs)

    assert reads == [601, 602]
    assert destroyed == [601, 602, 501]
    assert {record.reason for record in C.get_records()} == {"not_operational", "wrong_result"}


def test_x942_hybrid_truncation_reads_later_output_after_missing_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    party_calls = 0
    reads: list[int] = []
    destroyed: list[int] = []
    derived = iter([603, 604])

    def _import_party(
        _rs: Any, _first: bytes, _second: bytes
    ) -> tuple[int, int, int, int, bytes, bytes]:
        nonlocal party_calls
        party_calls += 1
        base = 10 if party_calls == 1 else 20
        return base + 1, base + 2, base + 3, base + 4, b"public-1", b"public-2"

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party)
    monkeypatch.setattr(
        test_x942_dh,
        "_x942_derive_generic_secret_len",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 603 else {CKA_VALUE: b"bad"}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms("X9_42_DH_HYBRID_DERIVE")

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942DHHybridDerive().test_hybrid_derive_value_len_truncation(rs)

    assert reads == [603, 604]
    assert destroyed == [11, 12, 13, 14, 21, 22, 23, 24, 603, 604]
    assert {record.reason for record in C.get_records()} == {"not_operational", "wrong_result"}


def test_x942_mqv_truncation_reads_later_output_after_missing_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    party_calls = 0
    reads: list[int] = []
    destroyed: list[int] = []
    derived = iter([605, 606])

    def _import_party(
        _rs: Any, _first: bytes, _second: bytes
    ) -> tuple[int, int, int, int, bytes, bytes]:
        nonlocal party_calls
        party_calls += 1
        base = 30 if party_calls == 1 else 40
        return base + 1, base + 2, base + 3, base + 4, b"public-1", b"public-2"

    monkeypatch.setattr(test_x942_dh, "_import_x942_party_keys", _import_party)
    monkeypatch.setattr(
        test_x942_dh,
        "_x942_derive_generic_secret_len",
        lambda *_args, **_kwargs: next(derived),
    )

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        return {} if handle == 605 else {CKA_VALUE: b"bad"}

    monkeypatch.setattr(test_x942_dh, "read_attributes", _read)
    monkeypatch.setattr(
        test_x942_dh,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )
    rs = _session_with_mechanisms("X9_42_MQV_DERIVE")

    with pytest.raises(pytest.fail.Exception):
        test_x942_dh.TestX942MQVDerive().test_mqv_derive_value_len_truncation(rs)

    assert reads == [605, 606]
    assert destroyed == [31, 32, 33, 34, 41, 42, 43, 44, 605, 606]
    assert {record.reason for record in C.get_records()} == {"not_operational", "wrong_result"}


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


def test_x942_rfc5114_zero_value_len_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_calls: list[dict[str, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _base_key: int,
        mechanism: int,
        *,
        attrs: dict[int, Any],
        mech_param: Any,
    ) -> int:
        assert mechanism == CKM_X9_42_DH_DERIVE
        assert isinstance(mech_param.params, CK_X9_42_DH1_DERIVE_PARAMS)
        params = mech_param.params
        assert params.kdf == CKD_NULL
        assert params.ulOtherInfoLen == 0
        assert params.pOtherInfo is None
        assert params.ulPublicDataLen == len(test_x942_dh._X942_RFC5114_BOB_PUBLIC)
        assert params.pPublicData is not None
        derive_calls.append({"attrs": attrs})
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    rs = _session_with_mechanisms("X9_42_DH_DERIVE")
    monkeypatch.setattr(test_x942_dh, "_import_x942_private_key", lambda *_args: 501)
    monkeypatch.setattr(test_x942_dh, "derive_key", _derive_reject)
    monkeypatch.setattr(test_x942_dh, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}"))

    test_x942_dh.TestX942DHDerive().test_x942_dh_derive_rfc5114_rejects_zero_value_len(rs)

    assert derive_calls == [
        {
            "attrs": {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_VALUE_LEN: 0,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
                CKA_TOKEN: False,
            }
        }
    ]


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

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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
    ("case_cls", "method_name", "mechanism", "param_type", "expected_label"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_rejects_invalid_kdf",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
            "CKM_X9_42_DH_HYBRID_DERIVE invalid KDF",
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_rejects_invalid_kdf",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
            "CKM_X9_42_MQV_DERIVE invalid KDF",
        ),
    ),
)
def test_x942_extended_invalid_kdf_negative_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
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
            assert int(params.kdf) == int(test_x942_dh._X942_INVALID_KDF)
            assert params.ulOtherInfoLen == 0
            assert params.pOtherInfo is None
            assert params.ulPublicDataLen > 0
            assert params.pPublicData is not None
            assert params.ulPublicDataLen2 > 0
            assert params.pPublicData2 is not None
            return int(CKR_MECHANISM_PARAM_INVALID)

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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
    ("case_cls", "method_name", "mechanism", "param_type", "expected_label"),
    (
        (
            test_x942_dh.TestX942DHHybridDerive,
            "test_hybrid_derive_rejects_malformed_peer_public_value",
            CKM_X9_42_DH_HYBRID_DERIVE,
            CK_X9_42_DH2_DERIVE_PARAMS,
            "CKM_X9_42_DH_HYBRID_DERIVE malformed peer public value",
        ),
        (
            test_x942_dh.TestX942MQVDerive,
            "test_mqv_derive_rejects_malformed_peer_public_value",
            CKM_X9_42_MQV_DERIVE,
            CK_X9_42_MQV_DERIVE_PARAMS,
            "CKM_X9_42_MQV_DERIVE malformed peer public value",
        ),
    ),
)
def test_x942_extended_malformed_peer_public_negative_uses_typed_params(
    monkeypatch: pytest.MonkeyPatch,
    case_cls: type,
    method_name: str,
    mechanism: int,
    param_type: type[Any],
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
            assert params.ulPublicDataLen == 1
            assert params.pPublicData is not None
            assert params.ulPublicDataLen2 > 0
            assert params.pPublicData2 is not None
            return int(CKR_MECHANISM_PARAM_INVALID)

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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

    def _import_party_keys(
        _rs: Any, _first_private: bytes, _second_private: bytes
    ) -> tuple[
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
