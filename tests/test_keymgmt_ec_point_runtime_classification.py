"""Runtime regressions for key-management provider readback classification."""

from __future__ import annotations

from collections.abc import Generator, Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKA_VALUE,
    CKF_EC_UNCOMPRESS,
    CKK_AES,
)
from pkcs11_check.testcases import _ec_export
from pkcs11_check.testcases import test_keymgmt as tkm
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE


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
        has_mechanism_flag=lambda _mechanism, flag: int(flag) == int(CKF_EC_UNCOMPRESS),
    )


def _p256_key() -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(17, ec.SECP256R1()).public_key()


def _p256_point(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )


def _provider_point(encoding: str) -> bytes:
    point = _p256_point(_p256_key())
    if encoding == "raw":
        return point
    if encoding == "wrapped":
        return b"\x04\x41" + point
    if encoding == "compressed":
        compressed = _p256_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.CompressedPoint,
        )
        return b"\x04" + bytes([len(compressed)]) + compressed
    raise AssertionError(f"unknown encoding: {encoding}")


@pytest.mark.parametrize("encoding", ["raw", "wrapped", "compressed"])
def test_ec_point_export_accepts_and_validates_p256_encodings(
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
) -> None:
    """P-256 export accepts raw and canonical wrapped SEC1 representations."""
    destroyed: list[int] = []
    provider_value = _provider_point(encoding)
    monkeypatch.setattr(tkm, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: provider_value},
    )
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    tkm.TestKeyExport().test_ec_point_export(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert C.get_records() == []


def test_ec_point_export_malformed_point_is_not_operational_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tkm, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: b"malformed"},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.xfail.Exception):
        tkm.TestKeyExport().test_ec_point_export(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert C.get_records()[0].reason == "not_operational"
    assert all(record.reason != "unclassified" for record in C.get_records())


def test_ec_point_export_wrong_curve_is_hard_crypto_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrong_curve_key = ec.derive_private_key(17, ec.SECP256K1()).public_key()
    wrong_curve_point = _p256_point(wrong_curve_key)
    monkeypatch.setattr(tkm, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: wrong_curve_point},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyExport().test_ec_point_export(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert C.get_records()[0].reason == "wrong_result"
    assert C.get_records()[0].kind == "crypto"


@pytest.mark.parametrize("invalid", ["malformed", "wrong_curve"])
def test_ecdh_invalid_p256_peer_is_classified_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
    invalid: str,
) -> None:
    generated = iter([(11, 12), (13, 14)])
    if invalid == "malformed":
        provider_value = b"malformed"
    else:
        provider_value = _p256_point(ec.derive_private_key(17, ec.SECP256K1()).public_key())
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: provider_value},
    )
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    outcome = pytest.xfail.Exception if invalid == "malformed" else pytest.fail.Exception
    with pytest.raises(outcome):
        tkm.TestKeyDerive().test_ecdh_derive_produces_key(_rs("EC_KEY_PAIR_GEN", "ECDH1_DERIVE"))

    assert destroyed == [11, 12, 13, 14]
    expected_reason = "not_operational" if invalid == "malformed" else "wrong_result"
    assert C.get_records()[0].reason == expected_reason
    assert all(record.reason != "unclassified" for record in C.get_records())


@pytest.mark.parametrize("encoding", ["raw", "wrapped", "compressed"])
def test_ecdh_derive_normalizes_all_p256_provider_encodings_identically(
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
) -> None:
    """Raw and wrapped peer points produce identical normalized derive parameters."""
    generated = iter([(11, 12), (13, 14)])
    derive_public_data: list[bytes] = []
    destroyed: list[int] = []

    monkeypatch.setattr(tkm, "gen_ec_keypair_or_xfail", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: _provider_point(encoding)},
    )

    def _mech_ecdh(*_args: Any, **kwargs: Any) -> Any:
        derive_public_data.append(kwargs["public_data"])
        return object()

    monkeypatch.setattr(tkm, "mech_ecdh", _mech_ecdh)
    monkeypatch.setattr(tkm, "derive_key", lambda *_args, **_kwargs: 21)
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    tkm.TestKeyDerive().test_ecdh_derive_produces_key(_rs("EC_KEY_PAIR_GEN", "ECDH1_DERIVE"))

    assert derive_public_data == [_p256_point(_p256_key())]
    assert destroyed == [11, 12, 13, 14, 21]
    assert C.get_records() == []


def test_copy_reads_all_independent_attributes_before_hard_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing label must not hide a contradictory present key type."""
    monkeypatch.setattr(tkm, "_aes_keymgmt_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(tkm, "copy_object", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(tkm, "read_attributes", lambda *_args, **_kwargs: {CKA_KEY_TYPE: 999})
    monkeypatch.setattr(tkm, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyCopy().test_copy_preserves_attributes(_rs())

    assert C.get_records()[0].reason == "not_operational"
    assert C.get_records()[1].reason == "wrong_result"
    assert C.get_records()[1].kind == "metadata"
    assert all(record.reason != "unclassified" for record in C.get_records())


def test_false_like_present_key_type_is_not_treated_as_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tkm, "import_secret_key", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(tkm, "read_attributes", lambda *_args, **_kwargs: {CKA_KEY_TYPE: False})
    monkeypatch.setattr(tkm, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyImport().test_import_aes_key(_rs())

    assert C.get_records()[0].reason == "wrong_result"
    assert C.get_records()[0].kind == "metadata"
    record = C.get_records()[0]
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    assert record.detail["attribute"]["expected"] == repr(CKK_AES)
    assert record.detail["attribute"]["actual"] == repr(False)
    serialized = C.serialize([record])[0]
    assert serialized["expected_ckr"] is None
    assert serialized["actual_ckr"] is None
    assert serialized["detail"]["attribute"]["actual"] == repr(False)
    assert all(record.reason != "unclassified" for record in C.get_records())


def test_missing_present_key_type_is_structured_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tkm, "import_secret_key", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(tkm, "read_attributes", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(tkm, "destroy_quietly", lambda *_args: None)

    tkm.TestKeyImport().test_import_aes_key(_rs())

    assert C.get_records()[0].reason == "not_operational"
    assert MISSING_ATTRIBUTE is not False
    assert all(record.reason != "unclassified" for record in C.get_records())


@pytest.mark.parametrize(
    ("modulus", "exponent"),
    [
        (b"m" * 255, b"\x01\x00\x01"),
        (b"m" * 256, b""),
        (False, b"\x01\x00\x01"),
    ],
    ids=["short-modulus", "empty-exponent", "false-like-modulus"],
)
def test_rsa_attribute_shape_mismatch_is_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
    modulus: Any,
    exponent: Any,
) -> None:
    monkeypatch.setattr(tkm, "gen_rsa_keypair_or_xfail", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        tkm,
        "read_attributes",
        lambda *_args, **_kwargs: {
            CKA_MODULUS: modulus,
            CKA_PUBLIC_EXPONENT: exponent,
        },
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyExport().test_rsa_modulus_export(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.expected_ckr is None
    assert record.actual_ckr is None
    assert record.detail is not None
    actual = record.detail["attribute"]["actual"]
    assert actual in {repr(modulus), repr(exponent)}
    assert all(item.reason != "unclassified" for item in C.get_records())


def test_rsa_records_both_independent_attribute_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tkm, "gen_rsa_keypair_or_xfail", lambda *_args, **_kwargs: (11, 12))
    monkeypatch.setattr(
        tkm,
        "read_attributes",
        lambda *_args, **_kwargs: {
            CKA_MODULUS: b"short",
            CKA_PUBLIC_EXPONENT: b"",
        },
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyExport().test_rsa_modulus_export(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert [record.reason for record in C.get_records()] == ["wrong_result", "wrong_result"]


def test_copy_records_both_independent_attribute_mismatches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tkm, "_aes_keymgmt_key", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(tkm, "copy_object", lambda *_args, **_kwargs: 2)
    monkeypatch.setattr(
        tkm,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_LABEL: b"wrong", CKA_KEY_TYPE: 999},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyCopy().test_copy_preserves_attributes(_rs())

    assert destroyed == [1, 2]
    assert [record.reason for record in C.get_records()] == ["wrong_result", "wrong_result"]


def test_import_multiple_sizes_records_every_mismatch_and_cleans_all_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([11, 12, 13])
    monkeypatch.setattr(tkm, "import_secret_key", lambda *_args, **_kwargs: next(handles))
    monkeypatch.setattr(
        tkm,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_VALUE: b"wrong"},
    )
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(pytest.fail.Exception):
        tkm.TestKeyImport().test_import_multiple_sizes(_rs())

    assert destroyed == [11, 12, 13]
    assert [record.reason for record in C.get_records()] == [
        "wrong_result",
        "wrong_result",
        "wrong_result",
    ]


def test_import_multiple_sizes_retains_mismatch_before_later_reader_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handles = iter([11, 12, 13])
    reads: Iterator[dict[int, Any] | BaseException] = iter(
        [{CKA_VALUE: b"wrong"}, RuntimeError("reader failed")]
    )
    monkeypatch.setattr(tkm, "import_secret_key", lambda *_args, **_kwargs: next(handles))

    def _read(*_args: Any, **_kwargs: Any) -> dict[int, Any]:
        result: dict[int, Any] | BaseException = next(reads)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(tkm, "read_attributes", _read)
    destroyed: list[int] = []
    monkeypatch.setattr(tkm, "destroy_quietly", lambda _raw, _sh, handle: destroyed.append(handle))

    with pytest.raises(RuntimeError, match="reader failed"):
        tkm.TestKeyImport().test_import_multiple_sizes(_rs())

    assert destroyed == [11, 12]
    assert [record.reason for record in C.get_records()] == ["wrong_result"]
