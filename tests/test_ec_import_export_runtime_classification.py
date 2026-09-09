"""Regression tests for EC import/export runtime-result classification."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
)
from pkcs11_check.testcases import test_ec_import_export

pytest_plugins = ["pytester"]


def _session(*mechanisms: str) -> SimpleNamespace:
    advertised = set(mechanisms)
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name in advertised,
    )


@pytest.fixture(autouse=True)
def _clear_classifications() -> Any:
    C.clear()
    yield
    C.clear()


def _point(
    private_value: int = 30,
    form: serialization.PublicFormat = serialization.PublicFormat.UncompressedPoint,
) -> bytes:
    return (
        ec.derive_private_key(private_value, ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.X962,
            form,
        )
    )


def _wrap(point: bytes) -> bytes:
    return b"\x04" + bytes([len(point)]) + point


def test_ec_public_import_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _import_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID",
            int(CKR_ATTRIBUTE_VALUE_INVALID),
        )

    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {
            CKA_EC_POINT: _wrap(_point()),
            CKA_EC_PARAMS: b"params",
        },
    )
    monkeypatch.setattr(test_ec_import_export, "sign_single", lambda *_args: b"sig")
    monkeypatch.setattr(test_ec_import_export, "import_ec_public_key", _import_reject)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception, match="EC public key import not operational"):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"),
            "secp256r1",
        )


@pytest.mark.parametrize(
    "point",
    [_wrap(_point(form=serialization.PublicFormat.CompressedPoint)), _wrap(_point())],
    ids=["wrapped-compressed", "wrapped-uncompressed"],
)
def test_wrapped_sec1_forms_pass_representation_checks(
    monkeypatch: pytest.MonkeyPatch, point: bytes
) -> None:
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: point, CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    test_ec_import_export.TestECPointExport().test_ec_point_is_uncompressed(_session("ECDSA"))
    assert C.get_records() == []


def test_raw_der_looking_point_is_structured_deviation_but_round_trip_is_independent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_point = _point()
    imported: list[tuple[bytes, bytes]] = []
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: raw_point, CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(test_ec_import_export, "sign_single", lambda *_args: b"signature")

    def _import(*_args: Any, **kwargs: Any) -> int:
        imported.append((kwargs["ec_point"], kwargs["ec_params"]))
        return 3

    monkeypatch.setattr(test_ec_import_export, "import_ec_public_key", _import)
    monkeypatch.setattr(test_ec_import_export, "verify_single", lambda *_args: True)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
        _session("ECDSA"), "secp256r1"
    )

    assert imported == [(raw_point, b"params")]
    assert C.get_records() == []


def test_operational_verification_failure_is_independent_crypto_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_point = _point()
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: raw_point, CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(test_ec_import_export, "sign_single", lambda *_args: b"signature")
    monkeypatch.setattr(test_ec_import_export, "import_ec_public_key", lambda *_args, **_k: 3)
    monkeypatch.setattr(test_ec_import_export, "verify_single", lambda *_args: False)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )

    records = C.get_records()
    assert [record.reason for record in records] == ["wrong_result"]
    assert records[0].kind == "crypto"
    assert records[0].operation == "C_Verify"


@pytest.mark.parametrize("missing", [CKA_EC_POINT, CKA_EC_PARAMS])
@pytest.mark.parametrize(
    "value",
    [None, False, 0, object(), bytearray(b"point"), b""],
    ids=["none", "false", "zero", "object", "bytearray", "empty"],
)
def test_present_false_like_or_missing_export_attribute_is_not_fabricated_ckr(
    monkeypatch: pytest.MonkeyPatch, missing: int, value: object
) -> None:
    attrs: dict[int, object] = {CKA_EC_POINT: _wrap(_point()), CKA_EC_PARAMS: b"params"}
    attrs[missing] = value
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_ec_import_export, "read_attributes", lambda *_args: attrs)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )

    assert C.get_records()
    assert all(record.reason == "not_operational" for record in C.get_records())
    assert all(record.actual_ckr is None for record in C.get_records())


def test_missing_export_attributes_are_independent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(test_ec_import_export, "read_attributes", lambda *_args: {})
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )

    assert [record.detail["attribute"]["name"] for record in C.get_records() if record.detail] == [
        "CKA_EC_POINT",
        "CKA_EC_PARAMS",
    ]


@pytest.mark.parametrize("rv", [CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID])
def test_explicit_attribute_read_refusal_is_attributed(
    monkeypatch: pytest.MonkeyPatch, rv: int
) -> None:
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: (_ for _ in ()).throw(CkrAssertionError("read refused", int(rv))),
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )

    assert C.get_records()[0].actual_ckr == str(rv)
    assert C.get_records()[0].operation == "C_GetAttributeValue"


def test_unexpected_attribute_read_ckr_is_propagated(monkeypatch: pytest.MonkeyPatch) -> None:
    error = CkrAssertionError("unexpected read error", int(CKR_ATTRIBUTE_VALUE_INVALID))
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: (_ for _ in ()).throw(error),
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(CkrAssertionError) as exc_info:
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )
    assert exc_info.value is error
    assert C.get_records() == []


def test_malformed_point_is_metadata_not_operational_and_does_not_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sign_called = False
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: b"\x04\x03\x04\x01", CKA_EC_PARAMS: b"params"},
    )

    def _sign(*_args: Any) -> bytes:
        nonlocal sign_called
        sign_called = True
        return b"signature"

    monkeypatch.setattr(test_ec_import_export, "sign_single", _sign)
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.xfail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )
    assert not sign_called
    record = C.get_records()[0]
    assert record.reason == "not_operational"
    assert record.kind == "metadata"
    assert record.operation == "C_GetAttributeValue"
    assert record.actual_ckr is None


def test_off_curve_point_is_crypto_failure_not_representation_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    off_curve = bytearray(_point())
    off_curve[-1] ^= 1
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: bytes(off_curve), CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_GetAttributeValue"


def test_empty_signature_is_crypto_failure_attributed_to_sign(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: _wrap(_point()), CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(test_ec_import_export, "sign_single", lambda *_args: b"")
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        test_ec_import_export.TestECPublicKeyImport().test_generate_export_import_verify(
            _session("ECDSA"), "secp256r1"
        )
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"
    assert record.operation == "C_Sign"


def test_different_mathematical_points_pass_even_with_mixed_forms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    points = iter((_wrap(_point(7)), _point(8)))
    handles = iter(((1, 2), (3, 4)))
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: next(handles))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: next(points)},
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(_session("ECDSA"))
    assert C.get_records() == []


def test_second_keypair_exception_cleans_first_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    error = RuntimeError("second keygen failed")
    destroyed: list[int] = []
    calls = iter(((1, 2), error))

    def _make(*_args: Any) -> tuple[int, int]:
        item = next(calls)
        if isinstance(item, tuple):
            return item
        raise item

    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", _make)
    monkeypatch.setattr(
        test_ec_import_export,
        "destroy_quietly",
        lambda _r, _s, h: destroyed.append(h),
    )

    with pytest.raises(RuntimeError) as exc_info:
        test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(
            _session("ECDSA")
        )
    assert exc_info.value is error
    assert destroyed == [1, 2]


def test_same_point_in_raw_and_wrapped_forms_is_not_unique(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_point = _point()
    wrapped_point = _wrap(raw_point)
    # Use the handle to select encodings so that equal mathematical Q has distinct bytes.
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {
            CKA_EC_POINT: raw_point if handle == 1 else wrapped_point
        },
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    # The test's generator must produce two distinct keypair handles.
    handles = iter(((1, 2), (3, 4)))
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: next(handles))

    with pytest.raises(pytest.fail.Exception):
        test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(
            _session("ECDSA")
        )
    assert C.get_records()[0].reason == "wrong_result"
    assert C.get_records()[0].kind == "crypto"


def test_same_point_in_wrapped_compressed_and_uncompressed_forms_is_not_unique(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compressed = _wrap(_point(form=serialization.PublicFormat.CompressedPoint))
    uncompressed = _wrap(_point())
    handles = iter(((1, 2), (3, 4)))
    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: next(handles))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {
            CKA_EC_POINT: compressed if handle == 1 else uncompressed
        },
    )
    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception):
        test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(
            _session("ECDSA")
        )
    assert C.get_records()[0].reason == "wrong_result"
    assert C.get_records()[0].kind == "crypto"


def test_second_keypair_generation_refusal_cleans_first_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    calls = iter(((1, 2), pytest.xfail.Exception("second keygen")))

    def _make(*_args: Any) -> tuple[int, int]:
        item = next(calls)
        if isinstance(item, tuple):
            return item
        raise item

    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", _make)
    monkeypatch.setattr(
        test_ec_import_export,
        "destroy_quietly",
        lambda _r, _s, h: destroyed.append(h),
    )

    with pytest.raises(pytest.xfail.Exception):
        test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(
            _session("ECDSA")
        )
    assert destroyed == [1, 2]


def test_cleanup_access_violation_wins_after_all_handles_are_attempted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ordinary = RuntimeError("first cleanup")
    access_violation = OSError("exception: access violation reading 0x0")
    destroyed: list[int] = []
    calls = iter(((1, 2), (3, 4)))

    monkeypatch.setattr(test_ec_import_export, "_make_ec_keypair", lambda *_args: next(calls))
    monkeypatch.setattr(
        test_ec_import_export,
        "read_attributes",
        lambda _raw, _sh, handle, _attrs: {CKA_EC_POINT: _wrap(_point(7 if handle == 1 else 8))},
    )

    def _destroy(_raw: object, _sh: int, handle: int) -> None:
        destroyed.append(handle)
        if handle == 1:
            raise ordinary
        if handle == 2:
            raise access_violation

    monkeypatch.setattr(test_ec_import_export, "destroy_quietly", _destroy)

    with pytest.raises(OSError) as exc_info:
        test_ec_import_export.TestECPointExport().test_two_keypairs_different_points(
            _session("ECDSA")
        )
    assert exc_info.value is access_violation
    assert destroyed == [1, 2, 3, 4]


@pytest.mark.usefixtures("classification_report_plugin_enabled")
def test_strict_and_operational_ec_nodes_are_independent_in_report(
    pytester: pytest.Pytester,
) -> None:
    pytester.makepyfile(
        test_ec_report="""
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.raw.types_std import CKA_EC_PARAMS, CKA_EC_POINT
from pkcs11_check.testcases import test_ec_import_export as target


def _point() -> bytes:
    return ec.derive_private_key(30, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda name: name == "ECDSA")


def _setup(monkeypatch, *, verify: bool | None = None) -> None:
    point = _point()
    monkeypatch.setattr(target, "_make_ec_keypair", lambda *_args: (1, 2))
    monkeypatch.setattr(
        target,
        "read_attributes",
        lambda *_args: {CKA_EC_POINT: point, CKA_EC_PARAMS: b"params"},
    )
    monkeypatch.setattr(target, "destroy_quietly", lambda *_args: None)
    monkeypatch.setattr(target, "sign_single", lambda *_args: b"signature")
    monkeypatch.setattr(target, "import_ec_public_key", lambda *_args, **_kwargs: 3)
    if verify is not None:
        monkeypatch.setattr(target, "verify_single", lambda *_args: verify)


def test_strict_raw_node(monkeypatch):
    _setup(monkeypatch)
    target.TestECPointExport().test_ec_point_is_uncompressed(_session())


def test_operational_raw_node(monkeypatch):
    _setup(monkeypatch, verify=True)
    target.TestECPublicKeyImport().test_generate_export_import_verify(_session(), "secp256r1")


def test_operational_false_verify_node(monkeypatch):
    _setup(monkeypatch, verify=False)
    target.TestECPublicKeyImport().test_generate_export_import_verify(_session(), "secp256r1")
"""
    )
    result = pytester.runpytest_subprocess("--report-log=report.jsonl", "-q")
    result.assert_outcomes(xfailed=1, failed=1, passed=1)
    reports = [
        json.loads(line)
        for line in (pytester.path / "report.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    calls = {
        report["nodeid"].rsplit("::", 1)[-1]: report
        for report in reports
        if report.get("when") == "call"
    }

    def classifications(name: str) -> list[dict[str, Any]]:
        return list(dict(calls[name].get("user_properties", [])).get("pkcs11_classification", []))

    strict = classifications("test_strict_raw_node")
    assert [(record["reason"], record["outcome"]) for record in strict] == [
        ("honest_deviation", "xfail")
    ]
    assert classifications("test_operational_raw_node") == []
    false_verify = classifications("test_operational_false_verify_node")
    assert [(record["reason"], record["outcome"]) for record in false_verify] == [
        ("wrong_result", "fail")
    ]
