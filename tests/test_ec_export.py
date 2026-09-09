from collections.abc import Generator

import pytest
from _pytest.outcomes import Failed
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases import _ec_export
from pkcs11_check.testcases._ec_export import (
    InvalidProviderECPointError,
    MalformedSignature,
    ProviderECPointEncodingError,
    RawECPointFamily,
    coord_len_for_curve,
    decode_provider_ec_point,
    read_ec_public_key_or_xfail,
    read_raw_ec_point_or_xfail,
    split_raw_ecdsa,
)


@pytest.fixture(autouse=True)
def _clear_classification() -> Generator[None, None, None]:
    C.clear()
    yield
    C.clear()


def _encoded_point(
    curve: ec.EllipticCurve,
    private_value: int,
    form: serialization.PublicFormat = serialization.PublicFormat.UncompressedPoint,
) -> bytes:
    return (
        ec.derive_private_key(private_value, curve)
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            form,
        )
    )


def _wrap_octet_string(value: bytes) -> bytes:
    if len(value) < 128:
        length = bytes([len(value)])
    else:
        length_bytes = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(length_bytes)]) + length_bytes
    return b"\x04" + length + value


def test_split_p256_fixed_width() -> None:
    r = (1).to_bytes(32, "big")
    s = (2).to_bytes(32, "big")
    assert split_raw_ecdsa(r + s, 32) == (1, 2)


def test_split_p521_fixed_width() -> None:
    r = (3).to_bytes(66, "big")
    s = (4).to_bytes(66, "big")
    assert split_raw_ecdsa(r + s, 66) == (3, 4)


def test_raw_ec_point_export_api_is_present() -> None:
    assert hasattr(_ec_export, "RawECPointFamily")
    assert hasattr(_ec_export, "read_raw_ec_point_or_xfail")


def test_split_odd_width_raises_malformed() -> None:
    with pytest.raises(MalformedSignature):
        split_raw_ecdsa(b"\x00" * 67, 32)


def test_coord_len_for_curve() -> None:
    assert coord_len_for_curve(ec.SECP256R1()) == 32
    assert coord_len_for_curve(ec.SECP384R1()) == 48
    assert coord_len_for_curve(ec.SECP521R1()) == 66


@pytest.mark.parametrize(
    ("curve", "private_value"),
    [(ec.SECP256R1(), 1), (ec.SECP384R1(), 2), (ec.SECP521R1(), 3)],
)
def test_decode_provider_ec_point_accepts_exact_raw_uncompressed(
    curve: ec.EllipticCurve, private_value: int
) -> None:
    raw = _encoded_point(curve, private_value)

    assert decode_provider_ec_point(raw, curve, label="generated key") == raw


def test_decode_provider_ec_point_prefers_exact_raw_with_der_like_coordinate() -> None:
    # Private value 30 has x[0] == 0x40, so the raw point also looks exactly like
    # an OCTET STRING with a 64-byte payload. Raw-first handling must retain 0x04.
    raw = _encoded_point(ec.SECP256R1(), 30)
    assert raw[:2] == b"\x04\x40"

    assert decode_provider_ec_point(raw, ec.SECP256R1(), label="generated key") == raw


@pytest.mark.parametrize(
    "form",
    [serialization.PublicFormat.UncompressedPoint, serialization.PublicFormat.CompressedPoint],
)
def test_decode_provider_ec_point_accepts_wrapped_sec1(form: serialization.PublicFormat) -> None:
    curve = ec.SECP256R1()
    point = _encoded_point(curve, 7, form)

    assert (
        decode_provider_ec_point(_wrap_octet_string(point), curve, label="generated key") == point
    )


def test_decode_provider_ec_point_rejects_raw_compressed_as_unsupported_encoding() -> None:
    raw = _encoded_point(ec.SECP256R1(), 5, serialization.PublicFormat.CompressedPoint)

    with pytest.raises(ProviderECPointEncodingError):
        decode_provider_ec_point(raw, ec.SECP256R1(), label="generated key")


@pytest.mark.parametrize("length", [32, 56, 57], ids=["25519", "448-montgomery", "448-edwards"])
def test_decode_provider_ec_point_rejects_nonconventional_family_bytes(length: int) -> None:
    raw = b"\x04" + b"\x00" * (length - 1)

    with pytest.raises(ProviderECPointEncodingError):
        decode_provider_ec_point(raw, ec.SECP256R1(), label="nonconventional key")


def test_decode_provider_ec_point_rejects_off_curve_without_der_fallback() -> None:
    raw = bytearray(_encoded_point(ec.SECP256R1(), 11))
    raw[-1] ^= 1

    with pytest.raises(InvalidProviderECPointError):
        decode_provider_ec_point(bytes(raw), ec.SECP256R1(), label="generated key")


def test_decode_provider_ec_point_rejects_wrapped_point_for_wrong_curve() -> None:
    point = _encoded_point(ec.SECP384R1(), 13)

    with pytest.raises(InvalidProviderECPointError):
        decode_provider_ec_point(
            _wrap_octet_string(point),
            ec.SECP256R1(),
            label="wrong-curve key",
        )


def test_alternate_curve_probe_ignores_backend_unsupported_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    point = _encoded_point(ec.BrainpoolP384R1(), 13)
    original = ec.EllipticCurvePublicKey.from_encoded_point

    def _restricted_backend(
        curve: ec.EllipticCurve,
        data: bytes,
    ) -> ec.EllipticCurvePublicKey:
        if curve.name == "secp384r1":
            raise UnsupportedAlgorithm("curve disabled by backend policy")
        return original(curve, data)

    monkeypatch.setattr(ec.EllipticCurvePublicKey, "from_encoded_point", _restricted_backend)

    with pytest.raises(InvalidProviderECPointError):
        decode_provider_ec_point(
            _wrap_octet_string(point),
            ec.SECP256R1(),
            label="wrong-curve key",
        )


def test_decode_provider_ec_point_distinguishes_malformed_wrapper() -> None:
    with pytest.raises(ProviderECPointEncodingError):
        decode_provider_ec_point(b"\x04\x03\x04\x01", ec.SECP256R1(), label="generated key")


@pytest.mark.parametrize(
    "inner",
    [
        b"\x04" + b"\x00" * 63,
        b"\x02" + b"\x00" * 31,
        b"\x05" + b"\x00" * 64,
    ],
    ids=["wrong-uncompressed-length", "wrong-compressed-length", "bad-prefix"],
)
def test_decode_provider_ec_point_rejects_malformed_inner_sec1_as_encoding(
    inner: bytes,
) -> None:
    with pytest.raises(ProviderECPointEncodingError):
        decode_provider_ec_point(
            _wrap_octet_string(inner),
            ec.SECP256R1(),
            label="generated key",
        )


def test_decode_provider_ec_point_does_not_infer_wrong_curve_from_length_alone() -> None:
    malformed_p224_sized = b"\x04" + b"\x00" * 56

    with pytest.raises(ProviderECPointEncodingError):
        decode_provider_ec_point(
            _wrap_octet_string(malformed_p224_sized),
            ec.SECP256R1(),
            label="malformed key",
        )


@pytest.mark.parametrize("wrapped", [False, True], ids=["raw", "wrapped"])
def test_read_ec_public_key_accepts_raw_and_wrapped_points(
    monkeypatch: pytest.MonkeyPatch, wrapped: bool
) -> None:
    curve = ec.SECP256R1()
    point = _encoded_point(curve, 17)
    read_calls: list[tuple[object, ...]] = []

    def read_attributes(*args: object, **_kwargs: object) -> dict[object, bytes]:
        read_calls.append(args)
        return {CKA_EC_POINT: _wrap_octet_string(point) if wrapped else point}

    monkeypatch.setattr(_ec_export, "read_attributes", read_attributes)
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    result = read_ec_public_key_or_xfail(rs, 2, curve, label="exported key")

    assert isinstance(result, ec.EllipticCurvePublicKey)
    assert len(read_calls) == 1
    assert C.get_records() == []


def test_read_ec_public_key_missing_point_is_one_structured_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_calls: list[tuple[object, ...]] = []

    def read_attributes(*args: object, **_kwargs: object) -> dict[object, bytes]:
        read_calls.append(args)
        return {}

    monkeypatch.setattr(_ec_export, "read_attributes", read_attributes)
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception, match="attribute unavailable"):
        read_ec_public_key_or_xfail(rs, 2, ec.SECP256R1(), label="exported key")

    assert len(read_calls) == 1
    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.expected_ckr is None
    assert record.detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "curve": "secp256r1",
    }


@pytest.mark.parametrize(
    "ec_point",
    [
        b"\x04\x03\x04\x01",
        b"\x04\x81\x21\x02" + b"\x01" * 32,
    ],
    ids=["truncated", "noncanonical-length"],
)
def test_read_ec_public_key_malformed_point_is_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
    ec_point: bytes,
) -> None:
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: ec_point},
    )
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception, match="canonical DER"):
        read_ec_public_key_or_xfail(rs, 2, ec.SECP256R1(), label="exported key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].kind == "metadata"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "curve": "secp256r1",
    }


def test_read_ec_public_key_malformed_inner_sec1_is_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = _wrap_octet_string(b"\x04" + b"\x00" * 63)
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: malformed},
    )
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception, match="invalid SEC1 point shape"):
        read_ec_public_key_or_xfail(rs, 2, ec.SECP256R1(), label="exported key")

    assert C.get_records()[0].reason == "not_operational"


def test_read_ec_public_key_direct_attribute_ckr_keeps_exact_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read(*_args: object, **_kwargs: object) -> dict[object, bytes]:
        raise CkrAssertionError("attribute unavailable", int(CKR_ATTRIBUTE_TYPE_INVALID))

    monkeypatch.setattr(_ec_export, "read_attributes", _read)
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception):
        read_ec_public_key_or_xfail(rs, 2, ec.SECP256R1(), label="exported key")

    record = C.get_records()[0]
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.operation == "C_GetAttributeValue"
    assert record.detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "curve": "secp256r1",
    }


def test_read_ec_public_key_off_curve_is_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = bytearray(_encoded_point(ec.SECP256R1(), 19))
    raw[-1] ^= 1
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: bytes(raw)},
    )
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(Failed, match="off-curve"):
        read_ec_public_key_or_xfail(rs, 2, ec.SECP256R1(), label="exported key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].kind == "crypto"
    assert records[0].outcome == "fail"
    assert records[0].operation == "C_GetAttributeValue"
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "curve": "secp256r1",
    }


def _raw_ec_rs(monkeypatch: pytest.MonkeyPatch, value: object) -> object:
    monkeypatch.setattr(
        _ec_export,
        "read_attributes",
        lambda *_args, **_kwargs: {CKA_EC_POINT: value},
    )
    return type("RS", (), {"raw": object(), "sh": 1})()


@pytest.mark.parametrize(
    ("family", "value"),
    [
        (RawECPointFamily.X25519, b"\x04" + b"\x00" * 31),
        (RawECPointFamily.X448, b"\x04" + b"\x00" * 55),
        (RawECPointFamily.ED25519, b"\x01" + b"\x00" * 31),
        (RawECPointFamily.ED448, b"\x01" + b"\x00" * 56),
    ],
    ids=["x25519", "x448", "ed25519", "ed448"],
)
def test_read_raw_ec_point_accepts_each_family_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch,
    family: RawECPointFamily,
    value: bytes,
) -> None:
    rs = _raw_ec_rs(monkeypatch, value)

    result = read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    assert result == value
    assert result is value
    assert C.get_records() == []


@pytest.mark.parametrize(
    ("family", "expected_length"),
    [
        (RawECPointFamily.X25519, 32),
        (RawECPointFamily.X448, 56),
        (RawECPointFamily.ED25519, 32),
        (RawECPointFamily.ED448, 57),
    ],
    ids=["x25519", "x448", "ed25519", "ed448"],
)
def test_read_raw_ec_point_wrong_length_is_one_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
    family: RawECPointFamily,
    expected_length: int,
) -> None:
    actual_length = expected_length - 1
    rs = _raw_ec_rs(monkeypatch, b"\x00" * actual_length)

    with pytest.raises(pytest.xfail.Exception, match="does not match"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": expected_length, "actual": actual_length},
    }


@pytest.mark.parametrize(
    "value",
    [None, object(), "not bytes"],
    ids=["none", "object", "str"],
)
def test_read_raw_ec_point_non_bytes_is_one_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    family = RawECPointFamily.X25519
    rs = _raw_ec_rs(monkeypatch, value)

    with pytest.raises(pytest.xfail.Exception, match="bytes"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": 32, "actual": None},
    }


def test_read_raw_ec_point_empty_is_one_metadata_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = RawECPointFamily.X25519
    rs = _raw_ec_rs(monkeypatch, b"")

    with pytest.raises(pytest.xfail.Exception, match="empty"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": 32, "actual": 0},
    }


def test_read_raw_ec_point_missing_is_one_metadata_xfail_without_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ec_export, "read_attributes", lambda *_args, **_kwargs: {})
    family = RawECPointFamily.X448
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception, match="unavailable"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": 56, "actual": None},
    }


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID])
def test_read_raw_ec_point_known_attribute_ckr_is_attributed_exactly(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    def _read(*_args: object, **_kwargs: object) -> dict[int, bytes]:
        raise CkrAssertionError("attribute unavailable", int(rv))

    monkeypatch.setattr(_ec_export, "read_attributes", _read)
    family = RawECPointFamily.ED25519
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(pytest.xfail.Exception):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].actual_ckr == (
        "CKR_ATTRIBUTE_SENSITIVE" if rv == CKR_ATTRIBUTE_SENSITIVE else "CKR_ATTRIBUTE_TYPE_INVALID"
    )
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": 32, "actual": None},
    }


def test_read_raw_ec_point_unexpected_ckr_propagates_without_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _read(*_args: object, **_kwargs: object) -> dict[int, bytes]:
        raise CkrAssertionError("unexpected", int(CKR_FUNCTION_FAILED))

    monkeypatch.setattr(_ec_export, "read_attributes", _read)
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(CkrAssertionError, match="unexpected"):
        read_raw_ec_point_or_xfail(rs, 2, RawECPointFamily.X25519, label="raw public key")

    assert C.get_records() == []


def test_read_raw_ec_point_mapping_exception_propagates_without_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = RuntimeError("attribute mapping failed")

    def _read(*_args: object, **_kwargs: object) -> dict[int, bytes]:
        raise error

    monkeypatch.setattr(_ec_export, "read_attributes", _read)
    rs = type("RS", (), {"raw": object(), "sh": 1})()

    with pytest.raises(RuntimeError, match="attribute mapping failed"):
        read_raw_ec_point_or_xfail(rs, 2, RawECPointFamily.X25519, label="raw public key")

    assert C.get_records() == []


def test_read_raw_ec_point_constructor_invalid_is_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = RawECPointFamily.X25519
    value = b"\x04" + b"\x00" * 31
    rs = _raw_ec_rs(monkeypatch, value)

    def _invalid(_value: bytes) -> object:
        raise ValueError("invalid raw public key")

    monkeypatch.setitem(_ec_export._RAW_EC_POINT_CONSTRUCTORS, family, _invalid)

    with pytest.raises(Failed, match="invalid"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].outcome == "fail"
    assert records[0].kind == "crypto"
    assert records[0].actual_ckr is None
    assert records[0].detail == {
        "attribute": {"name": "CKA_EC_POINT", "id": int(CKA_EC_POINT)},
        "family": family.value,
        "length": {"expected": 32, "actual": 32},
    }


def test_read_raw_ec_point_unsupported_algorithm_propagates_without_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = RawECPointFamily.ED448
    value = b"\x01" + b"\x00" * 56
    rs = _raw_ec_rs(monkeypatch, value)

    def _unsupported(_value: bytes) -> object:
        raise UnsupportedAlgorithm("raw public-key backend unavailable")

    monkeypatch.setitem(_ec_export._RAW_EC_POINT_CONSTRUCTORS, family, _unsupported)

    with pytest.raises(UnsupportedAlgorithm, match="backend unavailable"):
        read_raw_ec_point_or_xfail(rs, 2, family, label="raw public key")

    assert C.get_records() == []
