"""Regression tests for classic DH runtime classification."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_BASE,
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKK_GENERIC_SECRET,
    CKM_DH_PKCS_DERIVE,
    CKO_SECRET_KEY,
    CKR_DEVICE_ERROR,
    CKR_KEY_SIZE_RANGE,
)
from pkcs11_check.testcases import test_dh_key_agreement as dh


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in {"DH_PKCS_KEY_PAIR_GEN", "DH_PKCS_DERIVE"},
    )


def test_dh_derive_clean_runtime_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    public_values = {
        11: b"\x02",
        12: b"\x03",
    }

    def _derive_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_args, **_kwargs: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: public_values[handle]},
    )
    monkeypatch.setattr(dh, "derive_key", _derive_reject)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="DH derive advertised"):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())


def test_dh_rfc3526_group14_exact_vector_constant_matches_modexp() -> None:
    """The embedded DH exact-vector expected value is the rightmost derived secret bytes."""
    prime = int.from_bytes(dh.DH_PRIME_2048, "big")
    generator = int.from_bytes(dh.DH_GEN, "big")
    alice_private = int.from_bytes(dh._DH_RFC3526_GROUP14_ALICE_PRIVATE, "big")
    bob_public = int.from_bytes(dh._DH_RFC3526_GROUP14_BOB_PUBLIC, "big")

    assert pow(generator, alice_private, prime) != bob_public

    full_secret = pow(bob_public, alice_private, prime).to_bytes(len(dh.DH_PRIME_2048), "big")
    assert full_secret[-32:] == dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32


def test_dh_rfc3526_group14_value_len_truncation_uses_rightmost_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived_values = {
        501: dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32,
        502: dh._DH_RFC3526_GROUP14_EXPECTED_SECRET_32[-16:],
    }
    handles_by_len = {32: 501, 16: 502}
    derive_calls: list[dict[str, Any]] = []

    def _derive_key(
        _raw: object,
        _sh: int,
        private_key: int,
        mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_calls.append(
            {
                "private_key": private_key,
                "mechanism": int(mechanism),
                "attrs": attrs,
                "mech_param": mech_param,
            }
        )
        return handles_by_len[attrs[CKA_VALUE_LEN]]

    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)
    monkeypatch.setattr(dh, "derive_key", _derive_key)
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: derived_values[handle]},
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(_session())

    assert [call["attrs"][CKA_VALUE_LEN] for call in derive_calls] == [32, 16]
    assert {call["private_key"] for call in derive_calls} == {301}
    assert {call["mechanism"] for call in derive_calls} == {int(CKM_DH_PKCS_DERIVE)}


def test_wrong_32_byte_kat_fails_even_when_16_byte_value_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)

    def _derive(
        _rs: Any,
        _private_key: int,
        _peer_public: bytes,
        attrs: dict[int, Any],
        *,
        label: str,
    ) -> int:
        del label
        return 501 if attrs[CKA_VALUE_LEN] == 32 else 502

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"x" * 32} if handle == 501 else {},
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(
            _session()
        )

    assert destroyed == [501, 502, 301]
    assert [record.reason for record in C.get_records()] == ["not_operational", "wrong_result"]


@pytest.mark.parametrize(
    "method_name",
    [
        "test_dh_derive_shared_secret",
        "test_dh_derived_key_encrypts",
        "test_dh_derive_respects_requested_value_len_truncation",
    ],
)
def test_first_keypair_is_cleaned_when_second_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    generated = iter([(11, 21)])
    destroyed: list[int] = []

    def _generate(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration as exc:
            raise RuntimeError("second keypair failed") from exc

    monkeypatch.setattr(dh, "_gen_dh_keypair", _generate)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="second keypair failed"):
        getattr(dh.TestDHKeyAgreement(), method_name)(_session())

    assert destroyed == [11, 21]


def test_dh_rfc3526_group14_zero_value_len_is_expected_reject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derive_attrs: list[dict[int, Any]] = []

    def _derive_reject(
        _raw: object,
        _sh: int,
        _private_key: int,
        _mechanism: int,
        attrs: dict[int, Any],
        *,
        mech_param: Any,
    ) -> int:
        derive_attrs.append(attrs)
        raise CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))

    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_args: 301)
    monkeypatch.setattr(dh, "derive_key", _derive_reject)
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_args: None)

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_rejects_zero_value_len(_session())

    assert derive_attrs == [
        {
            CKA_CLASS: CKO_SECRET_KEY,
            CKA_KEY_TYPE: CKK_GENERIC_SECRET,
            CKA_VALUE_LEN: 0,
            CKA_SENSITIVE: False,
            CKA_EXTRACTABLE: True,
            CKA_TOKEN: False,
        }
    ]


def test_shared_secret_missing_alice_public_still_derives_alice_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derive_calls: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_VALUE: b"bob"} if handle == 12 else {}

    monkeypatch.setattr(dh, "read_attributes", _read)

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derive_calls.append(args[1])
        return 101

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    assert derive_calls == [21]
    assert destroyed == [101, 11, 21, 12, 22]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_shared_secret_collects_both_public_missing_records_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derive_calls: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {})

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derive_calls.append(args[1])
        return 101

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    assert derive_calls == []
    assert destroyed == [11, 21, 12, 22]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_shared_secret_reads_both_derived_values_before_skipping_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derives = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {CKA_VALUE: b"alice" if handle == 11 else b"bob"} if handle in {11, 12} else {}

    monkeypatch.setattr(dh, "read_attributes", _read)
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: next(derives))
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    assert read_handles == [11, 12, 101, 102]
    assert destroyed == [101, 102, 11, 21, 12, 22]
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "not_operational",
    ]


def test_encrypt_path_keeps_alice_derive_and_encrypt_when_alice_public_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derive_calls: list[int] = []
    encrypt_calls: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"bob"} if handle == 12 else {},
    )

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derive_calls.append(args[1])
        return 101

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)

    def _encrypt(_raw: object, _sh: int, key: int, _mechanism: int, _plaintext: bytes) -> bytes:
        encrypt_calls.append(key)
        return b"cipher"

    monkeypatch.setattr(dh, "encrypt_single", _encrypt)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHKeyAgreement().test_dh_derived_key_encrypts(_session())

    assert derive_calls == [21]
    assert encrypt_calls == [101]
    assert destroyed == [101, 11, 21, 12, 22]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_encrypt_noop_remains_hard_failure_after_missing_public_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"bob"} if handle == 12 else {},
    )
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: 101)
    monkeypatch.setattr(
        dh,
        "encrypt_single",
        lambda _raw, _sh, _key, _mechanism, plaintext: plaintext,
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(pytest.fail.Exception, match="no-op"):
        dh.TestDHKeyAgreement().test_dh_derived_key_encrypts(_session())

    assert destroyed == [101, 11, 21, 12, 22]
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "wrong_result",
    ]


def test_multiple_exchanges_continue_second_leg_and_clean_up_on_missing_first_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22), (13, 23), (14, 24)])
    derive_calls: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_VALUE: b"second"} if handle in {14, 101} else {}

    monkeypatch.setattr(dh, "read_attributes", _read)

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derive_calls.append(args[1])
        return 101

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHKeyAgreement().test_dh_different_keypairs_different_secrets(_session())

    assert derive_calls == [23]
    assert destroyed == [101, 11, 21, 12, 22, 13, 23, 14, 24]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


class _RawGenerateKey:
    def C_GenerateKey(  # noqa: N802
        self, _sh: int, _mech: Any, _tmpl: Any, _count: int, out: Any
    ) -> int:
        out._obj.value = 77
        return 0


def _parameter_session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=_RawGenerateKey(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


def test_generated_prime_missing_is_honest_deviation_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHParameterGeneration().test_generate_dh_parameters(_parameter_session())

    assert destroyed == [77]
    assert [record.reason for record in C.get_records()] == ["honest_deviation"]


def test_generated_params_missing_prime_and_base_blocks_keygen_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    keygen_calls: list[tuple[bytes, bytes]] = []
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, _handle, _attrs: {CKA_BASE: b"\x02"},
    )

    def _gen(_raw: object, _sh: int, prime: bytes, base: bytes) -> tuple[int, int]:
        keygen_calls.append((prime, base))
        return 11, 21

    monkeypatch.setattr(dh, "_gen_dh_keypair", _gen)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(
        _parameter_session()
    )

    assert keygen_calls == []
    assert destroyed == [77]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_present_malformed_base_fails_even_when_prime_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {CKA_BASE: 0})
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(AssertionError):
        dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(
            _parameter_session()
        )

    assert destroyed == [77]
    assert [record.reason for record in C.get_records()] == ["not_operational"]
