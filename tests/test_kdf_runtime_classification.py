"""Runtime classification regressions for generic KDF and ECDH checks."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import CKA_EC_POINT, CKA_VALUE, CKM_SHA3_224_KEY_DERIVE
from pkcs11_check.testcases import _ec_export, test_kdf


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


def test_hkdf_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 11)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 12)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestHKDF().test_hkdf_derive_basic(_session())

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].operation == "C_GetAttributeValue"


def test_ecdh_shared_secret_reads_both_missing_outputs_before_gating(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: b"a" if handle == 11 else b"b",
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 101, 102]
    assert len(C.get_records()) == 2
    assert all(record.reason == "not_operational" for record in C.get_records())


def test_ecdh_keypair_independence_cleans_up_when_second_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21)])
    destroyed: list[int] = []

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration:
            raise RuntimeError("second keypair generation failed") from None

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match="second keypair"):
        test_kdf.TestECDHDerive().test_ecdh_keypair_independence(_session())

    assert destroyed == [11, 21]


def test_ecdh_shared_secret_cleans_up_when_second_generation_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 21)])
    destroyed: list[int] = []

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        try:
            return next(generated)
        except StopIteration:
            raise RuntimeError("second keypair generation failed") from None

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match="second keypair"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert destroyed == [11, 21]


@pytest.mark.parametrize("failed_generation", [2, 3])
def test_ecdh_different_peers_cleans_up_partial_generations(
    monkeypatch: pytest.MonkeyPatch,
    failed_generation: int,
) -> None:
    generated = iter([(11, 21), (12, 22)])
    destroyed: list[int] = []
    calls = 0

    def _generate(_self: Any, _rs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == failed_generation:
            raise RuntimeError(f"generation {failed_generation} failed")
        return next(generated)

    monkeypatch.setattr(test_kdf.TestECDHDerive, "_generate_ec_keypair", _generate)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(RuntimeError, match=f"generation {failed_generation}"):
        test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    expected = [11, 21] if failed_generation == 2 else [11, 21, 12, 22]
    assert destroyed == expected


def test_ecdh_different_peers_continues_pair_read_on_missing_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22), (13, 23)])
    derived = iter([101, 102])
    read_handles: list[int] = []
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, _handle: b"point",
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        read_handles.append(handle)
        return {} if handle == 101 else {CKA_VALUE: b"value"}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestECDHDerive().test_ecdh_different_peers_different_secrets(_session())

    assert read_handles == [101, 102]
    assert destroyed == [11, 21, 12, 22, 13, 23, 101, 102]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecdh_shared_mismatch_remains_a_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keypairs = iter([(11, 21), (12, 22)])
    derived = iter([101, 102])
    destroyed: list[int] = []

    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_generate_ec_keypair",
        lambda _self, _rs: next(keypairs),
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_extract_ec_point",
        lambda _self, _rs, handle: b"a" if handle == 11 else b"b",
    )
    monkeypatch.setattr(
        test_kdf.TestECDHDerive,
        "_derive_shared",
        lambda _self, *_args: next(derived),
    )
    monkeypatch.setattr(
        test_kdf,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_VALUE: b"a" if handle == 101 else b"b"},
    )
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    with pytest.raises(pytest.fail.Exception, match="does not match"):
        test_kdf.TestECDHDerive().test_ecdh_shared_secret_agreement(_session())

    assert destroyed == [11, 21, 12, 22, 101, 102]
    assert [record.reason for record in C.get_records()] == ["wrong_result"]


def test_sha3_missing_derived_value_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 31)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 32)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_kdf, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle)
    )

    test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
        _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
    )

    assert destroyed == [32, 31]
    assert [record.reason for record in C.get_records()] == ["not_operational"]


@pytest.mark.parametrize("value", [None, b"short"])
def test_sha3_present_invalid_output_remains_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    monkeypatch.setattr(test_kdf, "_import_generic_secret", lambda *_a, **_k: 33)
    monkeypatch.setattr(test_kdf, "derive_key", lambda *_a, **_k: 34)
    monkeypatch.setattr(test_kdf, "read_attributes", lambda *_a, **_k: {CKA_VALUE: value})
    monkeypatch.setattr(test_kdf, "destroy_quietly", lambda *_a: None)

    with pytest.raises(AssertionError):
        test_kdf.TestSHA3ShakeKeyDerive().test_derive_produces_key(
            _session(), "SHA3_224_KEY_DERIVE", int(CKM_SHA3_224_KEY_DERIVE)
        )

    assert C.get_records() == []


def test_ecdh_extract_delegates_to_curve_aware_export_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"\x04" + b"\x01" * 64
    calls: list[tuple[int, str]] = []

    class _PublicKey:
        def public_bytes(
            self,
            _encoding: serialization.Encoding,
            _format: serialization.PublicFormat,
        ) -> bytes:
            return expected

    def _read(_rs: Any, handle: int, curve: ec.EllipticCurve, *, label: str) -> _PublicKey:
        calls.append((handle, curve.name + ":" + label))
        return _PublicKey()

    monkeypatch.setattr(test_kdf, "read_ec_public_key_or_xfail", _read, raising=False)
    monkeypatch.setattr(
        test_kdf,
        "read_attributes",
        lambda *_a, **_k: {CKA_EC_POINT: b"\x04\x41" + expected},
    )

    point = test_kdf.TestECDHDerive()._extract_ec_point(_session(), 41)

    assert point == expected
    assert calls == [(41, "secp256r1:ECDH P-256 public key")]


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_ecdh_extract_accepts_raw_and_wrapped_p256_points(
    monkeypatch: pytest.MonkeyPatch,
    wrapped: bool,
) -> None:
    curve = ec.SECP256R1()
    raw = (
        ec.derive_private_key(7, curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    data = b"\x04" + bytes([len(raw)]) + raw if wrapped else raw

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: data}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    assert test_kdf.TestECDHDerive()._extract_ec_point(_session(), 42) == raw


def test_ecdh_extract_malformed_point_is_structured_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: b"\x04\x03\x04\x01"}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    with pytest.raises(pytest.xfail.Exception, match="canonical DER"):
        test_kdf.TestECDHDerive()._extract_ec_point(_session(), 43)

    assert [record.reason for record in C.get_records()] == ["not_operational"]


def test_ecdh_extract_off_curve_point_is_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    curve = ec.SECP256R1()
    raw = bytearray(
        ec.derive_private_key(8, curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
    )
    raw[-1] ^= 1

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, bytes]:
        return {CKA_EC_POINT: bytes(raw)}

    monkeypatch.setattr(test_kdf, "read_attributes", _read)
    monkeypatch.setattr(_ec_export, "read_attributes", _read)

    with pytest.raises(pytest.fail.Exception, match="off-curve"):
        test_kdf.TestECDHDerive()._extract_ec_point(_session(), 44)

    assert [record.reason for record in C.get_records()] == ["wrong_result"]
