"""Regression tests for ACVP ECDH runtime/setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_POINT,
    CKA_VALUE,
    CKF_EC_COMPRESS,
    CKF_EC_UNCOMPRESS,
    CKM_ECDH1_DERIVE,
    CKR_DEVICE_ERROR,
)
from pkcs11_check.testcases.acvp import test_acvp_ecdh


def test_generated_ec_point_decode_error_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    generated = iter([(1, 2), (3, 4)])

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: b"\x04\xff\xff"},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="malformed CKA_EC_POINT"):
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-521")

    record = classification.get_records()[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None


def test_generated_point_read_error_keeps_get_attribute_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A point-read CKR must not be relabeled as an ECDH derive rejection."""
    classification.clear()
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    generated = iter([(1, 2), (3, 4)])

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))

    def _read_point(*_args: Any, **_kwargs: Any) -> dict[int, object]:
        raise CkrAssertionError(
            "C_GetAttributeValue(CKA_EC_POINT): CKR_DEVICE_ERROR",
            int(CKR_DEVICE_ERROR),
        )

    monkeypatch.setattr(test_acvp_ecdh, "read_attributes", _read_point)
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(CkrAssertionError, match=r"C_GetAttributeValue\(CKA_EC_POINT\)") as excinfo:
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    assert excinfo.value.rv == int(CKR_DEVICE_ERROR)
    assert classification.get_records() == []


def test_generated_keygen_error_keeps_keygen_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key-generation CKR must not be relabeled as an ECDH derive rejection."""
    classification.clear()
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )

    import pkcs11_check.raw.recipes as recipes

    def _generate_fail(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        raise CkrAssertionError(
            "C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN): CKR_DEVICE_ERROR",
            int(CKR_DEVICE_ERROR),
        )

    monkeypatch.setattr(recipes, "gen_ec_keypair", _generate_fail)
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(
        CkrAssertionError, match=r"C_GenerateKeyPair\(CKM_EC_KEY_PAIR_GEN\)"
    ) as excinfo:
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    assert excinfo.value.rv == int(CKR_DEVICE_ERROR)
    assert classification.get_records() == []


def test_empty_generated_ec_point_is_type_c_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that claims EC keygen success but cannot expose CKA_EC_POINT is a
    lifecycle self-contradiction (claimed success, effect not observable), not a skip.

    D1 determination: the former ``pytest.skip("Cannot extract public key point for
    ECDH")`` masked this. ``gen_ec_keypair`` asserts ``CKR_OK`` (success claimed); a
    public key's ``CKA_EC_POINT`` is a mandatory, non-sensitive attribute, so an empty
    readback contradicts the claim and must ``fail``.
    """
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    generated = iter([(1, 2), (3, 4)])

    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: b""},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    # Outcome-class hard-pin (e0340c2d pattern): a regression back to skip (or a
    # downgrade to xfail) must FAIL this meta-test, not silently change its outcome.
    try:
        with pytest.raises(pytest.fail.Exception, match="self_contradiction"):
            test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of lifecycle failing: {exc}")
    except pytest.xfail.Exception as exc:
        pytest.fail(f"xfailed instead of lifecycle failing: {exc}")


def test_generated_off_curve_point_is_hard_crypto_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ec.derive_private_key(7, ec.SECP256R1()).public_key()
    off_curve = bytearray(
        key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )
    off_curve[-1] ^= 1
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    generated = iter([(1, 2), (3, 4)])
    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: bytes(off_curve)},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="wrong_result|off-curve"):
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    record = classification.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"


def test_vector_import_keeps_der_and_derive_receives_only_inner_sec1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = ec.derive_private_key(7, ec.SECP256R1()).public_key()
    sec1 = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    vector_der = b"\x04" + bytes([len(sec1)]) + sec1
    expected = b"shared-secret".ljust(32, b"\x00")
    imported: list[bytes] = []
    mechanism_data: list[bytes] = []
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
    )
    vec = {
        "curve": "P-256",
        "private_key": b"\x01" * 32,
        "ec_point_der": vector_der,
        "expected_shared": expected,
    }

    monkeypatch.setattr(test_acvp_ecdh, "provision_ec_private_key", lambda *_a, **_k: 1)

    def _import_public(*_args: Any, **kwargs: Any) -> int:
        imported.append(kwargs["ec_point"])
        return 2

    def _mech(*_args: Any, **kwargs: Any) -> object:
        mechanism_data.append(kwargs["public_data"])
        return object()

    monkeypatch.setattr(test_acvp_ecdh, "import_ec_public_key", _import_public)
    monkeypatch.setattr(test_acvp_ecdh, "mech_ecdh", _mech)
    monkeypatch.setattr(test_acvp_ecdh, "derive_key", lambda *_a, **_k: 3)
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_a, **_k: {CKA_VALUE: expected},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    test_acvp_ecdh.test_acvp_ecdh_shared_secret(rs, SimpleNamespace(), "vector", vec)

    assert imported == [vector_der]
    assert mechanism_data == [sec1]


@pytest.mark.parametrize("value", ["missing", None, object(), b""])
def test_generated_point_shape_failures_are_lifecycle_failures_without_ckr(
    monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, _flag: False,
    )
    generated = iter([(1, 2), (3, 4)])
    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))
    monkeypatch.setattr(
        test_acvp_ecdh,
        "read_attributes",
        lambda *_args, value=value, **_kwargs: {} if value == "missing" else {CKA_EC_POINT: value},
    )
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="self_contradiction"):
        test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    record = classification.get_records()[0]
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None
    assert record.kind == "lifecycle"


@pytest.mark.parametrize(
    ("form", "wrapped", "compress", "uncompress"),
    [
        (serialization.PublicFormat.UncompressedPoint, False, True, False),
        (serialization.PublicFormat.UncompressedPoint, True, True, False),
        (serialization.PublicFormat.CompressedPoint, True, False, True),
    ],
)
def test_generated_valid_point_reaches_derive_with_exact_raw_form(
    monkeypatch: pytest.MonkeyPatch,
    form: serialization.PublicFormat,
    wrapped: bool,
    compress: bool,
    uncompress: bool,
) -> None:
    key = ec.derive_private_key(7, ec.SECP256R1()).public_key()
    sec1 = key.public_bytes(serialization.Encoding.X962, form)
    provider = b"\x04" + bytes([len(sec1)]) + sec1 if wrapped else sec1
    rs: Any = SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "ECDH1_DERIVE",
        has_mechanism_flag=lambda _mechanism, flag: {
            int(CKF_EC_COMPRESS): compress,
            int(CKF_EC_UNCOMPRESS): uncompress,
        }.get(int(flag), False),
    )
    generated = iter([(1, 2), (3, 4)])
    captured: list[bytes] = []
    flag_calls: list[tuple[int, int]] = []
    import pkcs11_check.raw.recipes as recipes

    monkeypatch.setattr(recipes, "gen_ec_keypair", lambda *_args, **_kwargs: next(generated))

    def _read(_raw: object, _sh: int, handle: int, _attrs: object) -> dict[int, object]:
        return {CKA_EC_POINT: provider} if handle == 3 else {CKA_VALUE: b"x"}

    def _has_flag(mechanism: Any, flag: Any) -> bool:
        flag_calls.append((int(mechanism), int(flag)))
        return {
            int(CKF_EC_COMPRESS): compress,
            int(CKF_EC_UNCOMPRESS): uncompress,
        }.get(int(flag), False)

    rs.has_mechanism_flag = _has_flag
    monkeypatch.setattr(test_acvp_ecdh, "read_attributes", _read)
    monkeypatch.setattr(test_acvp_ecdh, "destroy_quietly", lambda *_args: None)

    def _mech(*_args: Any, **kwargs: Any) -> object:
        captured.append(kwargs["public_data"])
        return object()

    monkeypatch.setattr(test_acvp_ecdh, "mech_ecdh", _mech)
    monkeypatch.setattr(test_acvp_ecdh, "derive_key", lambda *_args, **_kwargs: 9)

    test_acvp_ecdh.TestEcdhKeyAgreement().test_ecdh_key_agreement_basic(rs, "P-256")

    expected_form = (
        serialization.PublicFormat.CompressedPoint
        if compress and not uncompress
        else serialization.PublicFormat.UncompressedPoint
    )
    expected = key.public_bytes(serialization.Encoding.X962, expected_form)
    assert captured == [expected]
    assert flag_calls == [
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_COMPRESS)),
        (int(CKM_ECDH1_DERIVE), int(CKF_EC_UNCOMPRESS)),
    ]
