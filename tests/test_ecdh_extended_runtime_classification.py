"""Runtime regressions for extended ECDH provider-point consumers."""

from __future__ import annotations

from collections.abc import Generator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_VALUE,
    CKK_AES,
    CKK_EC_MONTGOMERY,
)
from pkcs11_check.testcases import _ec_export
from pkcs11_check.testcases import test_ecdh_extended as tee
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from pkcs11_check.testcases._ec_export import RawECPointFamily


@pytest.fixture(autouse=True)
def _clear_classifications() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _rs(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


def _p256_key() -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(17, ec.SECP256R1()).public_key()


def _p256_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def test_p256_consumer_uses_explicit_curve_and_x962_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _p256_key()
    calls: list[tuple[int, ec.EllipticCurve]] = []

    def _read(_rs: Any, handle: int, curve: ec.EllipticCurve, **_kwargs: Any) -> Any:
        calls.append((handle, curve))
        return key

    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", _read)

    result = tee._p256_point(SimpleNamespace(raw=object(), sh=1), 7)

    assert result == _p256_point(key)
    assert calls[0][0] == 7
    assert calls[0][1].name == ec.SECP256R1().name


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_p256_consumer_normalizes_raw_and_wrapped_provider_points(
    monkeypatch: pytest.MonkeyPatch,
    wrapped: bool,
) -> None:
    point = _p256_point(_p256_key())
    provider_value = b"\x04\x41" + point if wrapped else point
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: provider_value},
    )

    result = tee._p256_point(SimpleNamespace(raw=object(), sh=1), 7)

    assert result == point
    assert C.get_records() == []


def test_x25519_derive_preserves_raw_point_starting_with_sec1_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    points = {11: b"\x04" + b"\x00" * 31, 13: b"\x05" + b"\x00" * 31}
    derive_calls: list[tuple[int, bytes]] = []

    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        tee,
        "read_raw_ec_point_or_xfail",
        lambda _rs, handle, family, **_kwargs: (
            points[handle] if family is RawECPointFamily.X25519 else pytest.fail("wrong family")
        ),
    )

    def _derive(_rs: Any, private: int, peer: bytes, *_args: Any, **_kwargs: Any) -> int:
        derive_calls.append((private, peer))
        return 20 + len(derive_calls)

    monkeypatch.setattr(tee, "_ecdh_derive", _derive)
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: b"s" * 32)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    tee.TestECMontgomeryKeyPairGen().test_x25519_ecdh_derive(
        _rs("EC_MONTGOMERY_KEY_PAIR_GEN", "ECDH1_DERIVE")
    )

    assert derive_calls == [
        (12, points[13]),
        (14, points[11]),
    ]


@pytest.mark.parametrize(
    ("method_name", "family", "point"),
    [
        ("test_x25519_keygen", RawECPointFamily.X25519, b"\x04" + b"\x00" * 31),
        ("test_x448_keygen", RawECPointFamily.X448, b"\x04" + b"\x00" * 55),
    ],
)
def test_montgomery_keygen_uses_exact_family_validator(
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
    family: RawECPointFamily,
    point: bytes,
) -> None:
    families: list[RawECPointFamily] = []
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: (7, 8))
    monkeypatch.setattr(
        tee,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: CKK_EC_MONTGOMERY},
    )

    def _read(_rs: Any, _handle: int, selected: RawECPointFamily, **_kwargs: Any) -> bytes:
        families.append(selected)
        return point

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    getattr(tee.TestECMontgomeryKeyPairGen(), method_name)(_rs("EC_MONTGOMERY_KEY_PAIR_GEN"))

    assert families == [family]


def test_x25519_uniqueness_reads_second_point_after_first_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    generated = iter([(11, 12), (13, 14)])
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: next(generated))

    def _read(_rs: Any, handle: int, *_args: Any, **_kwargs: Any) -> bytes:
        calls.append(handle)
        C.xfail_as(
            "not_operational",
            kind="metadata",
            label=f"point {handle}",
            operation="C_GetAttributeValue",
            summary="point unavailable",
        )

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_two_keypairs_differ(
            _rs("EC_MONTGOMERY_KEY_PAIR_GEN")
        )

    assert calls == [11, 13]


def test_x25519_uniqueness_keeps_equal_points_as_hard_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    point = b"\x04" + b"\x00" * 31
    generated = iter([(11, 12), (13, 14)])
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: next(generated))

    def _read(_rs: Any, handle: int, *_args: Any, **_kwargs: Any) -> bytes:
        calls.append(handle)
        return point

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_two_keypairs_differ(
            _rs("EC_MONTGOMERY_KEY_PAIR_GEN")
        )

    assert calls == [11, 13]
    assert C.get_records()[0].reason == "wrong_result"


def test_keygen_missing_type_does_not_hide_point_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: (7, 8))
    monkeypatch.setattr(tee, "read_attributes", lambda *_args, **_kwargs: {})

    def _read(*_args: Any, **_kwargs: Any) -> bytes:
        calls.append(1)
        C.xfail_as(
            "not_operational",
            kind="metadata",
            label="point",
            operation="C_GetAttributeValue",
            summary="point unavailable",
        )

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_keygen(_rs("EC_MONTGOMERY_KEY_PAIR_GEN"))

    assert calls == [1]
    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "not_operational",
    ]


def test_keygen_missing_point_does_not_hide_wrong_key_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: (7, 8))
    monkeypatch.setattr(
        tee,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: 999},
    )

    def _read(*_args: Any, **_kwargs: Any) -> bytes:
        C.xfail_as(
            "not_operational",
            kind="metadata",
            label="point",
            operation="C_GetAttributeValue",
            summary="point unavailable",
        )

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_keygen(_rs("EC_MONTGOMERY_KEY_PAIR_GEN"))

    assert [record.reason for record in C.get_records()] == [
        "not_operational",
        "wrong_result",
    ]


def test_p256_shared_secret_mismatch_remains_hard_failure_after_point_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    keys = iter([(11, 12), (13, 14)])
    key = _p256_key()
    monkeypatch.setattr(tee, "_gen_ec", lambda _rs: next(keys))
    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", lambda *_args, **_kwargs: key)
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: 21)
    values = iter([b"a" * 32, b"b" * 32])
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(tee, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tee.TestECDH1CofactorDerive().test_cofactor_derive_shared_secret(
            _rs("ECDH1_COFACTOR_DERIVE")
        )

    assert C.get_records()[0].reason == "wrong_result"


@pytest.mark.parametrize("pair_helper", [tee._gen_ec_pairs, tee._gen_montgomery_pairs])
def test_pair_generation_cleans_completed_pair_when_next_generation_fails(
    monkeypatch: pytest.MonkeyPatch,
    pair_helper: Any,
) -> None:
    destroyed: list[int] = []
    calls = 0

    def _generate(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return 11, 12
        raise RuntimeError("second keypair failed")

    monkeypatch.setattr(
        tee,
        "_gen_ec" if pair_helper is tee._gen_ec_pairs else "_gen_montgomery",
        _generate,
    )
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="second keypair failed"):
        if pair_helper is tee._gen_ec_pairs:
            pair_helper(SimpleNamespace(raw=object(), sh=1), 2)
        else:
            pair_helper(SimpleNamespace(raw=object(), sh=1), b"oid", 2)

    assert destroyed == [12, 11]


def test_p256_first_xfail_does_not_hide_second_hard_failure_or_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    calls: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(tee, "_gen_ec", lambda *_args, **_kwargs: next(generated))

    def _read(_rs: Any, handle: int, *_args: Any, **_kwargs: Any) -> Any:
        calls.append(handle)
        if handle == 11:
            C.xfail_as(
                "not_operational",
                kind="metadata",
                label="first P-256 point",
                operation="C_GetAttributeValue",
                summary="first point unavailable",
            )
        C.fail_as(
            "wrong_result",
            kind="crypto",
            label="second P-256 point",
            operation="C_GetAttributeValue",
            summary="second point is off curve",
        )

    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECDH1CofactorDerive().test_cofactor_derive_shared_secret(
            _rs("ECDH1_COFACTOR_DERIVE")
        )

    assert calls == [11, 13]
    assert destroyed == [12, 11, 14, 13]
    assert [record.reason for record in C.get_records()] == ["not_operational", "wrong_result"]


def test_x25519_first_xfail_does_not_hide_second_hard_failure_or_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    calls: list[int] = []
    destroyed: list[int] = []
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: next(generated))

    def _read(_rs: Any, handle: int, *_args: Any, **_kwargs: Any) -> bytes:
        calls.append(handle)
        if handle == 11:
            C.xfail_as(
                "not_operational",
                kind="metadata",
                label="first X25519 point",
                operation="C_GetAttributeValue",
                summary="first point unavailable",
            )
        C.fail_as(
            "wrong_result",
            kind="crypto",
            label="second X25519 point",
            operation="C_GetAttributeValue",
            summary="second point is invalid",
        )

    monkeypatch.setattr(tee, "read_raw_ec_point_or_xfail", _read)
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_ecdh_derive(
            _rs("EC_MONTGOMERY_KEY_PAIR_GEN", "ECDH1_DERIVE")
        )

    assert calls == [11, 13]
    assert destroyed == [12, 11, 14, 13]
    assert [record.reason for record in C.get_records()] == ["not_operational", "wrong_result"]


def test_cofactor_missing_value_does_not_hide_malformed_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    destroyed: list[int] = []
    values = iter((MISSING_ATTRIBUTE, b"b" * 31))
    derived = iter((20, 21))
    monkeypatch.setattr(tee, "_gen_ec", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", lambda *_args, **_kwargs: _p256_key())
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: next(derived))
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECDH1CofactorDerive().test_cofactor_derive_shared_secret(
            _rs("ECDH1_COFACTOR_DERIVE")
        )

    assert C.get_records()[0].reason == "wrong_result"
    assert all(record.reason != "unclassified" for record in C.get_records())
    assert destroyed == [20, 21, 12, 11, 14, 13]


def test_cofactor_equal_malformed_values_are_all_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    destroyed: list[int] = []
    values = iter((b"a" * 31, b"a" * 31))
    derived = iter((20, 21))
    monkeypatch.setattr(tee, "_gen_ec", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", lambda *_args, **_kwargs: _p256_key())
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: next(derived))
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECDH1CofactorDerive().test_cofactor_derive_shared_secret(
            _rs("ECDH1_COFACTOR_DERIVE")
        )

    assert [record.reason for record in C.get_records()] == ["wrong_result", "wrong_result"]
    assert all(record.kind == "metadata" for record in C.get_records())
    assert destroyed == [20, 21, 12, 11, 14, 13]


def test_aes_derived_value_length_is_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    destroyed: list[int] = []
    derived = iter((20, 21))
    monkeypatch.setattr(tee, "_gen_ec", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", lambda *_args, **_kwargs: _p256_key())
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: next(derived))
    monkeypatch.setattr(
        tee,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_KEY_TYPE: CKK_AES, CKA_VALUE: b"a" * 31},
    )
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECDH1CofactorDerive().test_cofactor_derive_as_aes_key(_rs("ECDH1_COFACTOR_DERIVE"))

    assert C.get_records()[0].reason == "wrong_result"
    assert all(record.reason != "unclassified" for record in C.get_records())
    assert destroyed == [20, 12, 11, 14, 13]


def test_ecmqv_malformed_derived_value_is_structured_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    destroyed: list[int] = []
    monkeypatch.setattr(tee, "_gen_ec", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(tee, "read_ec_public_key_or_xfail", lambda *_args, **_kwargs: _p256_key())
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: 20)
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: b"a" * 31)
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECMQVDerive().test_ecmqv_derive(_rs("ECMQV_DERIVE"))

    assert C.get_records()[0].reason == "wrong_result"
    assert all(record.reason != "unclassified" for record in C.get_records())
    assert destroyed == [20, 12, 11, 14, 13]


def test_x25519_equal_malformed_derived_values_are_structured_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    destroyed: list[int] = []
    values = iter((b"a" * 31, b"a" * 31))
    derived = iter((20, 21))
    monkeypatch.setattr(tee, "_gen_montgomery", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        tee,
        "read_raw_ec_point_or_xfail",
        lambda *_args, **_kwargs: b"p" * 32,
    )
    monkeypatch.setattr(tee, "_ecdh_derive", lambda *_args, **_kwargs: next(derived))
    monkeypatch.setattr(tee, "_read_value", lambda *_args, **_kwargs: next(values))
    monkeypatch.setattr(tee, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tee.TestECMontgomeryKeyPairGen().test_x25519_ecdh_derive(
            _rs("EC_MONTGOMERY_KEY_PAIR_GEN", "ECDH1_DERIVE")
        )

    assert [record.reason for record in C.get_records()] == ["wrong_result", "wrong_result"]
    assert all(record.kind == "metadata" for record in C.get_records())
    assert destroyed == [20, 21, 12, 11, 14, 13]


@pytest.mark.parametrize(
    "value",
    ["not bytes", b"a" * 31],
    ids=["non-bytes", "wrong-length"],
)
def test_derived_value_non_ckr_facts_do_not_populate_ckr_fields(value: Any) -> None:
    tee._validate_derived_value(
        value,
        label="CKM_ECDH1_DERIVE:derived CKA_VALUE",
        mechanism="CKM_ECDH1_DERIVE",
    )

    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    serialized = C.serialize(C.get_records())[0]
    assert serialized["expected_ckr"] is None
    assert serialized["actual_ckr"] is None
    assert serialized["detail"]["attribute"]["name"] == "CKA_VALUE"
