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
    CKA_PRIME,
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
        dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(_session())

    assert destroyed == [501, 502, 301]
    assert [record.reason for record in C.get_records()] == ["wrong_result", "not_operational"]


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
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "not_operational",
    ]


def test_shared_secret_collects_both_public_missing_records_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
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
    assert all(record.mechanism is None for record in C.get_records())
    assert all(
        record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in C.get_records()
    )


def test_shared_secret_reads_both_derived_values_before_skipping_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
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
    assert all(record.mechanism is None for record in C.get_records())
    assert all(
        record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in C.get_records()
    )


def test_dh_paired_both_malformed_outputs_drop_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    reads, destroyed = _install_paired_dh_case(
        monkeypatch,
        "test_dh_derive_shared_secret",
        (b"", b"short"),
    )

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    assert reads[-2:] == [101, 102]
    assert destroyed
    records = C.get_records()
    assert len(records) == 2
    assert all(record.reason == "wrong_result" for record in records)
    assert all(record.kind == "metadata" for record in records)
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


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
        if handle == 14:
            return {CKA_VALUE: b"second"}
        if handle == 101:
            return {CKA_VALUE: b"x" * 16}
        return {}

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
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    dh.TestDHParameterGeneration().test_generate_dh_parameters(_parameter_session())

    assert destroyed == [77]
    records = C.get_records()
    assert [record.reason for record in records] == ["honest_deviation"]
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_generated_prime_too_short_is_classified_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: generated CKA_PRIME readback is present but under the requested 2048 bits.

    Before the fix this was a bare ``assert isinstance(prime, bytes)`` /
    ``assert len(prime) * 8 >= 2048`` -- an unclassified pytest failure. It must now surface
    as a properly classified ``wrong_result``/``metadata`` finding (still a hard failure).
    """
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {CKA_PRIME: b"\x01" * 8})
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    with pytest.raises(BaseException):
        dh.TestDHParameterGeneration().test_generate_dh_parameters(_parameter_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].outcome == "fail"
    assert records[0].detail is not None
    assert records[0].detail["actual"]["bits"] == 64


def test_dh_public_missing_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: (11, 21))
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    dh.TestDHKeyAgreement().test_dh_keypair_generation(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "honest_deviation"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


def test_dh_public_present_empty_value_is_classified_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: CKA_VALUE readback for the generated public key is present but empty.

    Before the fix this was a bare ``assert isinstance(pub_value, bytes)`` /
    ``assert len(pub_value) > 0`` -- an unclassified pytest failure. It must now surface as
    a properly classified ``wrong_result``/``metadata`` finding (still a hard failure).
    """
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: (11, 21))
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {CKA_VALUE: b""})
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    with pytest.raises(BaseException):
        dh.TestDHKeyAgreement().test_dh_keypair_generation(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "metadata"
    assert records[0].outcome == "fail"


def test_dh_exact_vector_missing_value_drops_stale_active_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_a, **_k: 301)
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: 302)
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_exact_vector(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None
    assert records[0].spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue"


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

    dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(_parameter_session())

    assert keygen_calls == []
    assert destroyed == [77]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_present_malformed_base_fails_even_when_prime_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {CKA_BASE: 0})
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(
            _parameter_session()
        )

    assert destroyed == [77]
    assert [record.reason for record in C.get_records()] == ["not_operational", "wrong_result"]


_PAIRED_DH_CASES = (
    pytest.param(
        "test_dh_derive_shared_secret",
        id="shared-secret",
    ),
    pytest.param(
        "test_dh_pkcs_derive_rfc3526_group14_value_len_truncation",
        id="rfc3526-truncation",
    ),
    pytest.param(
        "test_dh_derive_respects_requested_value_len_truncation",
        id="generated-truncation",
    ),
    pytest.param(
        "test_dh_different_keypairs_different_secrets",
        id="different-exchanges",
    ),
)


def _install_paired_dh_case(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    values: tuple[Any, Any],
    *,
    reader_error: BaseException | None = None,
) -> tuple[list[int], list[int]]:
    """Install deterministic handles for one two-output DH test path."""
    keypair_values = (
        [(11, 21), (12, 22), (13, 23), (14, 24)]
        if method_name == "test_dh_different_keypairs_different_secrets"
        else [(11, 21), (12, 22)]
    )
    keypairs = iter(keypair_values)
    derived = iter([101, 102])
    reads: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_a, **_k: 301)
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: next(derived))

    public_handles = {11, 12, 13, 14}

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        reads.append(handle)
        if reader_error is not None and handle in {102, 502}:
            raise reader_error
        if handle in public_handles:
            return {CKA_VALUE: f"public-{handle}".encode()}
        if handle in {101, 501}:
            return {CKA_VALUE: values[0]}
        if handle in {102, 502}:
            return {CKA_VALUE: values[1]}
        raise AssertionError(f"unexpected DH read handle {handle}")

    monkeypatch.setattr(dh, "read_attributes", _read)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))
    return reads, destroyed


@pytest.mark.parametrize("method_name", _PAIRED_DH_CASES)
def test_dh_paired_derived_malformed_outputs_are_retained_before_raising(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    reads, destroyed = _install_paired_dh_case(
        monkeypatch,
        method_name,
        (b"", b"x" * 16),
    )

    with pytest.raises(BaseException):
        getattr(dh.TestDHKeyAgreement(), method_name)(_session())

    assert reads[-2:] == [101, 102]
    assert destroyed
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.mechanism is None
    assert record.detail is not None
    assert record.detail["attribute"]["name"] == "CKA_VALUE"
    assert record.detail["leg"]
    assert record.detail["expected"]["type"] == "bytes"
    assert record.detail["actual"]["type"] == "bytes"
    assert record.detail["actual"]["length"] == 0
    assert record.detail["producer_operation"] == "C_DeriveKey"
    assert record.detail["producer_mechanism"] == "CKM_DH_PKCS_DERIVE"


@pytest.mark.parametrize("method_name", _PAIRED_DH_CASES)
def test_dh_paired_reader_error_preserves_first_shape_record(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    reads, destroyed = _install_paired_dh_case(
        monkeypatch,
        method_name,
        (b"short", b"x" * 16),
        reader_error=RuntimeError("second DH output read failed"),
    )

    with pytest.raises(RuntimeError, match="second DH output read failed"):
        getattr(dh.TestDHKeyAgreement(), method_name)(_session())

    assert reads[-2:] == [101, 102]
    assert destroyed
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail is not None
    assert records[0].detail["leg"]


def test_dh_shared_secret_valid_outputs_have_exact_length_before_relation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_paired_dh_case(monkeypatch, "test_dh_derive_shared_secret", (b"x", b"x"))

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    records = C.get_records()
    assert len(records) == 2
    assert all(record.reason == "wrong_result" for record in records)
    assert all(record.kind == "metadata" for record in records)
    assert not any(record.kind == "crypto" for record in records)


def test_dh_public_shape_failure_disables_only_dependent_exchange(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    keypairs = iter([(11, 21), (12, 22), (13, 23), (14, 24)])
    derives: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        if handle == 12:
            return {CKA_VALUE: b""}
        if handle in {12, 14}:
            return {CKA_VALUE: b"valid-public"}
        if handle == 13:
            return {CKA_VALUE: b"other-public"}
        return {CKA_VALUE: b"x" * 16}

    monkeypatch.setattr(dh, "read_attributes", _read)

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derives.append(args[1])
        return 101 + len(derives)

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_different_keypairs_different_secrets(_session())

    assert derives == [23]
    assert destroyed
    records = C.get_records()
    assert any(
        record.reason == "wrong_result" and record.operation == "C_GetAttributeValue"
        for record in records
    )
    read_records = [record for record in records if record.operation == "C_GetAttributeValue"]
    assert all(record.mechanism is None for record in read_records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in read_records)
    assert not any(record.operation == "C_DeriveKey" for record in records)


def test_generated_params_retains_missing_prime_and_malformed_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    C.set_mechanism("CKM_STALE", operation="C_Stale")
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "read_attributes", lambda *_a, **_k: {CKA_BASE: 0})
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(
            _parameter_session()
        )

    assert destroyed == [77]
    records = C.get_records()
    assert [record.reason for record in records] == ["not_operational", "wrong_result"]
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.mechanism is None for record in records)
    assert all(record.spec_ref == "PKCS#11 v3.2 · C_GetAttributeValue" for record in records)


def test_rfc_wrong_kat_and_second_malformed_value_retain_both_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derived = iter([501, 502])
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_import_dh_private_key", lambda *_a: 301)
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: next(derived))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {
            CKA_VALUE: (b"wrong-value" + b"x" * 21) if handle == 501 else b"short"
        },
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, h: destroyed.append(h))

    with pytest.raises(pytest.fail.Exception, match="wrong shape"):
        dh.TestDHKeyAgreement().test_dh_pkcs_derive_rfc3526_group14_value_len_truncation(_session())

    assert destroyed == [501, 502, 301]
    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result", "wrong_result"]
    assert [record.kind for record in records] == ["crypto", "metadata"]
    assert records[0].operation == "C_DeriveKey"
    assert records[1].operation == "C_GetAttributeValue"
    assert records[1].actual_ckr is None
    assert records[1].detail is not None
    assert "actual" in records[1].detail
    assert "bytes" not in records[1].detail["actual"]


@pytest.mark.parametrize(
    ("method_name", "values"),
    [
        pytest.param("test_dh_derive_shared_secret", (b"a" * 16, b"b" * 16), id="equal"),
        pytest.param(
            "test_dh_different_keypairs_different_secrets",
            (b"x" * 16, b"x" * 16),
            id="different",
        ),
    ],
)
def test_dh_valid_derived_relation_breach_is_structured_crypto_finding(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    values: tuple[bytes, bytes],
) -> None:
    _install_paired_dh_case(monkeypatch, method_name, values)

    with pytest.raises(pytest.fail.Exception):
        getattr(dh.TestDHKeyAgreement(), method_name)(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_DeriveKey"
    assert records[0].mechanism == "CKM_DH_PKCS_DERIVE"


def test_dh_duplicate_generated_public_value_is_structured_keygen_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: 101)
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {
            CKA_VALUE: b"same-public-value" if handle in {11, 12} else b"x" * 16
        },
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_GenerateKeyPair"
    assert records[0].mechanism == "CKM_DH_PKCS_KEY_PAIR_GEN"


def _install_encrypt_public_case(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[int, Any],
    *,
    reader_error_handle: int | None = None,
) -> tuple[list[int], list[int], list[int]]:
    keypairs = iter([(11, 21), (12, 22)])
    derive_calls: list[int] = []
    encrypt_calls: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        if handle == reader_error_handle:
            raise RuntimeError("sibling public-value read failed")
        return {} if handle not in values else {CKA_VALUE: values[handle]}

    monkeypatch.setattr(dh, "read_attributes", _read)

    def _derive(*args: Any, **_kwargs: Any) -> int:
        derive_calls.append(args[1])
        return 100 + len(derive_calls)

    monkeypatch.setattr(dh, "_dh_derive_or_xfail", _derive)

    def _encrypt(
        _raw: Any,
        _sh: int,
        key: int,
        _mechanism: int,
        _plaintext: bytes,
    ) -> bytes:
        encrypt_calls.append(key)
        return b"cipher"

    monkeypatch.setattr(
        dh,
        "encrypt_single",
        _encrypt,
    )
    monkeypatch.setattr(dh, "decrypt_single", lambda *_a, **_k: b"plaintext")
    monkeypatch.setattr(dh, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))
    return derive_calls, encrypt_calls, destroyed


@pytest.mark.parametrize(
    ("values", "expected_derives", "expected_encrypts"),
    [
        pytest.param({12: b"", 11: b"alice-public"}, [22], [], id="bob-malformed"),
        pytest.param({12: b"bob-public", 11: b""}, [21], [101], id="alice-malformed"),
        pytest.param({11: b"alice-public"}, [22], [], id="bob-missing"),
        pytest.param({12: b"bob-public"}, [21], [101], id="alice-missing"),
    ],
)
def test_encrypt_public_dependency_is_local_and_safe_to_continue(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[int, Any],
    expected_derives: list[int],
    expected_encrypts: list[int],
) -> None:
    derives, encrypts, destroyed = _install_encrypt_public_case(monkeypatch, values)

    if any(value == b"" for value in values.values()):
        with pytest.raises(pytest.fail.Exception):
            dh.TestDHKeyAgreement().test_dh_derived_key_encrypts(_session())
    else:
        dh.TestDHKeyAgreement().test_dh_derived_key_encrypts(_session())

    assert derives == expected_derives
    assert encrypts == expected_encrypts
    assert destroyed == [101, 11, 21, 12, 22]
    records = C.get_records()
    if any(value == b"" for value in values.values()):
        assert any(record.reason == "wrong_result" for record in records)
    else:
        assert any(record.reason == "not_operational" for record in records)


def test_encrypt_malformed_first_public_value_retains_evidence_when_sibling_read_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    derives, encrypts, destroyed = _install_encrypt_public_case(
        monkeypatch,
        {12: b""},
        reader_error_handle=11,
    )

    with pytest.raises(RuntimeError, match="sibling public-value read failed"):
        dh.TestDHKeyAgreement().test_dh_derived_key_encrypts(_session())

    assert derives == []
    assert encrypts == []
    assert destroyed == [11, 21, 12, 22]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].mechanism is None


@pytest.mark.parametrize(
    "method_name",
    [
        pytest.param("test_dh_derive_shared_secret", id="shared-secret"),
        pytest.param("test_dh_different_keypairs_different_secrets", id="different-exchanges"),
    ],
)
def test_equal_empty_public_values_record_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    _install_paired_dh_case(monkeypatch, method_name, (b"x" * 16, b"y" * 16))

    def _read(_raw: Any, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        if handle in {11, 12, 13, 14}:
            return {CKA_VALUE: b""}
        return {CKA_VALUE: b"x" * 16}

    monkeypatch.setattr(dh, "read_attributes", _read)

    with pytest.raises(pytest.fail.Exception):
        getattr(dh.TestDHKeyAgreement(), method_name)(_session())

    records = C.get_records()
    assert records
    assert all(record.kind == "metadata" for record in records)
    assert not any(record.operation == "C_GenerateKeyPair" for record in records)


def test_generated_params_equal_empty_public_values_record_metadata_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, attrs: (
            {CKA_PRIME: b"prime"}
            if CKA_PRIME in attrs
            else {CKA_BASE: b"base"}
            if CKA_BASE in attrs
            else {CKA_VALUE: b""}
        ),
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHParameterGeneration().test_generated_params_produce_valid_keypair(
            _parameter_session()
        )

    records = C.get_records()
    assert records
    assert all(record.kind == "metadata" for record in records)
    assert not any(record.operation == "C_GenerateKeyPair" for record in records)


def test_duplicate_public_detail_is_bounded_and_contains_no_provider_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    monkeypatch.setattr(dh, "_gen_dh_keypair", lambda *_a, **_k: next(keypairs))
    monkeypatch.setattr(dh, "_dh_derive_or_xfail", lambda *_a, **_k: 101)
    monkeypatch.setattr(
        dh,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {
            CKA_VALUE: b"same-public-value" if handle in {11, 12} else b"x" * 16
        },
    )
    monkeypatch.setattr(dh, "destroy_quietly", lambda *_a: None)

    with pytest.raises(pytest.fail.Exception):
        dh.TestDHKeyAgreement().test_dh_derive_shared_secret(_session())

    duplicate = next(
        record for record in C.get_records() if record.operation == "C_GenerateKeyPair"
    )
    assert duplicate.detail is not None
    assert duplicate.detail["actual"] == {"type": "bytes", "length": len(b"same-public-value")}
    assert "same-public-value" not in str(duplicate.detail)
