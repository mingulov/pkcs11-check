"""Runtime regressions for keypair-consistency attribute evidence."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_KEY_TYPE,
    CKA_MODULUS,
    CKA_PUBLIC_EXPONENT,
    CKR_ATTRIBUTE_TYPE_INVALID,
)
from pkcs11_check.testcases import test_keypair_consistency as kpc
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE
from tests._attribute_access_guard import analyze_file


@pytest.fixture(autouse=True)
def _clear_classifications() -> Iterator[None]:
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


def _setup(
    monkeypatch: pytest.MonkeyPatch,
    *,
    rsa: bool = False,
    ec: bool = False,
    reads: Callable[..., dict[int, Any]] | None = None,
    destroyed: list[int] | None = None,
) -> None:
    if rsa:
        monkeypatch.setattr(kpc, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    if ec:
        monkeypatch.setattr(kpc, "gen_ec_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    if reads is not None:
        monkeypatch.setattr(kpc, "read_attributes", reads)
    if destroyed is not None:
        monkeypatch.setattr(
            kpc,
            "destroy_quietly",
            lambda _raw, _sh, handle: destroyed.append(handle),
        )


def test_rsa_modulus_mismatch_is_linked_metadata_failure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_MODULUS: b"public" if handle == 11 else b"private"}

    _setup(monkeypatch, rsa=True, reads=read, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "self_contradiction"
    assert records[0].kind == "metadata"
    assert records[0].detail is not None
    assert records[0].detail["attribute"] == {
        "name": "CKA_MODULUS",
        "id": int(CKA_MODULUS),
    }
    assert records[0].detail["public_leg"] == "public"
    assert records[0].detail["private_leg"] == "private"
    assert records[0].detail["producer_operation"] == "C_GenerateKeyPair"
    assert records[0].detail["producer_mechanism"] == "CKM_RSA_PKCS_KEY_PAIR_GEN"


def test_rsa_exponent_mismatch_is_linked_metadata_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_PUBLIC_EXPONENT: b"one" if handle == 11 else b"two"}

    _setup(monkeypatch, rsa=True, reads=read, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        kpc.TestRSAKeypairConsistency().test_public_exponent_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert C.get_records()[0].reason == "self_contradiction"
    record = C.get_records()[0]
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == int(CKA_PUBLIC_EXPONENT)


def test_ec_params_mismatch_preserves_provider_representation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {CKA_EC_PARAMS: b"\x06\x03\x2a\x03\x04" if handle == 11 else b"\x06\x03\x2a\x03\x05"}

    _setup(monkeypatch, ec=True, reads=read, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        kpc.TestECKeypairConsistency().test_ec_params_match(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    record = C.get_records()[0]
    assert record.reason == "self_contradiction"
    assert record.kind == "metadata"
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == int(CKA_EC_PARAMS)
    assert record.detail["producer_mechanism"] == "CKM_EC_KEY_PAIR_GEN"


@pytest.mark.parametrize("missing_handle", [11, 12], ids=["public-missing", "private-missing"])
def test_missing_first_or_second_pair_leg_does_not_hide_other_read(
    monkeypatch: pytest.MonkeyPatch,
    missing_handle: int,
) -> None:
    calls: list[int] = []
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        calls.append(handle)
        return {} if handle == missing_handle else {CKA_MODULUS: b"valid"}

    _setup(monkeypatch, rsa=True, reads=read, destroyed=destroyed)

    with pytest.raises(pytest.xfail.Exception):
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert calls == [11, 12]
    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "not_operational"
    assert records[0].actual_ckr is None
    assert records[0].detail is not None
    assert records[0].detail["attribute"] == {
        "name": "CKA_MODULUS",
        "id": int(CKA_MODULUS),
    }
    assert records[0].detail["leg"] == ("public" if missing_handle == 11 else "private")


@pytest.mark.parametrize("rv", [int(CKR_ATTRIBUTE_TYPE_INVALID), 0x80000001, 0x12345678])
def test_reader_ckr_is_attributed_without_suppressing_second_leg(
    monkeypatch: pytest.MonkeyPatch,
    rv: int,
) -> None:
    calls: list[int] = []
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        calls.append(handle)
        if handle == 11:
            raise CkrAssertionError("reader rejected", rv)
        return {CKA_MODULUS: b"valid"}

    _setup(monkeypatch, rsa=True, reads=read, destroyed=destroyed)

    expected = pytest.fail.Exception if rv == 0x12345678 else pytest.xfail.Exception
    with pytest.raises(expected):
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert calls == [11, 12]
    assert destroyed == [11, 12]
    record = C.get_records()[0]
    assert record.actual_ckr is not None
    assert record.expected_ckr == ["CKR_OK"]
    assert record.detail is not None
    assert record.detail["attribute"]["id"] == int(CKA_MODULUS)
    assert record.detail["leg"] == "public"


def test_missing_then_malformed_present_value_keeps_both_and_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 11 else {CKA_MODULUS: b""}

    _setup(monkeypatch, rsa=True, reads=read, destroyed=destroyed)

    with pytest.raises(pytest.fail.Exception):
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert [record.reason for record in C.get_records()] == ["not_operational", "wrong_result"]


@pytest.mark.parametrize(
    ("method", "mechanism", "attr"),
    [
        ("test_modulus_matches", "RSA_PKCS_KEY_PAIR_GEN", CKA_MODULUS),
        ("test_public_exponent_matches", "RSA_PKCS_KEY_PAIR_GEN", CKA_PUBLIC_EXPONENT),
        ("test_ec_params_match", "EC_KEY_PAIR_GEN", CKA_EC_PARAMS),
    ],
)
@pytest.mark.parametrize("value", [False, 0, None, object(), b""])
def test_present_malformed_bytes_are_hard_for_every_pair_attribute(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    mechanism: str,
    attr: int,
    value: Any,
) -> None:
    destroyed: list[int] = []
    is_ec = method == "test_ec_params_match"

    def read(_raw: object, _sh: int, _handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {attr: value}

    _setup(monkeypatch, rsa=not is_ec, ec=is_ec, reads=read, destroyed=destroyed)
    instance: Any = kpc.TestECKeypairConsistency() if is_ec else kpc.TestRSAKeypairConsistency()

    with pytest.raises(pytest.fail.Exception):
        getattr(instance, method)(_rs(mechanism))

    assert destroyed == [11, 12]
    assert len(C.get_records()) == 2
    assert all(record.reason == "wrong_result" for record in C.get_records())
    assert all(record.actual_ckr is None for record in C.get_records())


@pytest.mark.parametrize("value", [False, 0, None, object(), b"", b"x" * 255])
def test_rsa_public_modulus_size_malformed_present_value_is_hard(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    destroyed: list[int] = []

    _setup(
        monkeypatch,
        rsa=True,
        reads=lambda *_a, **_k: {CKA_MODULUS: value},
        destroyed=destroyed,
    )

    with pytest.raises(pytest.fail.Exception):
        kpc.TestRSAKeypairConsistency().test_modulus_correct_size(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    record = C.get_records()[0]
    assert record.reason == "wrong_result"
    assert record.kind == "metadata"
    assert record.actual_ckr is None


def test_ec_point_readability_accepts_raw_and_der_looking_bytes_without_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    decoder_called = False

    def forbidden_decoder(*_args: object, **_kwargs: object) -> None:
        nonlocal decoder_called
        decoder_called = True
        raise AssertionError("keypair consistency must not decode CKA_EC_POINT")

    monkeypatch.setattr(kpc, "decode_ec_point", forbidden_decoder, raising=False)
    _setup(
        monkeypatch,
        ec=True,
        reads=lambda *_a, **_k: {CKA_EC_POINT: b"\x04raw-looking-or-DER-looking"},
        destroyed=destroyed,
    )

    kpc.TestECKeypairConsistency().test_ec_point_on_pub_only(_rs("EC_KEY_PAIR_GEN"))

    assert not decoder_called
    assert destroyed == [11, 12]
    assert C.get_records() == []


def test_ec_key_type_checks_private_after_malformed_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []

    _setup(
        monkeypatch,
        ec=True,
        reads=lambda *_a, **_k: {CKA_KEY_TYPE: False},
        destroyed=destroyed,
    )

    with pytest.raises(pytest.fail.Exception):
        kpc.TestECKeypairConsistency().test_key_type_consistent(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 2
    assert [record.detail["leg"] for record in records if record.detail is not None] == [
        "public",
        "private",
    ]
    assert all(record.reason == "wrong_result" for record in records)


def test_ec_key_type_bool_is_malformed_not_integer_zero_or_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    _setup(
        monkeypatch,
        ec=True,
        reads=lambda *_a, **_k: {CKA_KEY_TYPE: True},
        destroyed=destroyed,
    )

    with pytest.raises(pytest.fail.Exception):
        kpc.TestECKeypairConsistency().test_key_type_consistent(_rs("EC_KEY_PAIR_GEN"))

    assert len(C.get_records()) == 2
    assert destroyed == [11, 12]


@pytest.mark.parametrize("value", [False, 0, None, object(), b""])
def test_ec_point_present_malformed_value_is_hard(
    monkeypatch: pytest.MonkeyPatch,
    value: Any,
) -> None:
    destroyed: list[int] = []
    _setup(
        monkeypatch,
        ec=True,
        reads=lambda *_a, **_k: {CKA_EC_POINT: value},
        destroyed=destroyed,
    )

    with pytest.raises(pytest.fail.Exception):
        kpc.TestECKeypairConsistency().test_ec_point_on_pub_only(_rs("EC_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    assert C.get_records()[0].reason == "wrong_result"


@pytest.mark.parametrize("kind", ["pass", "xfail", "fail", "unexpected"])
def test_both_pair_handles_are_cleaned_once_for_every_terminal_body(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    destroyed: list[int] = []
    _setup(monkeypatch, rsa=True, destroyed=destroyed)
    if kind == "pass":
        monkeypatch.setattr(kpc, "read_attributes", lambda *_a, **_k: {CKA_MODULUS: b"same"})
    elif kind == "xfail":
        monkeypatch.setattr(kpc, "read_attributes", lambda *_a, **_k: {})
    elif kind == "fail":
        monkeypatch.setattr(
            kpc,
            "read_attributes",
            lambda _raw, _sh, handle, _attrs: {CKA_MODULUS: b"one" if handle == 11 else b"two"},
        )
    else:

        def read_error(*_a: object, **_k: object) -> dict[int, Any]:
            raise RuntimeError("reader")

        monkeypatch.setattr(kpc, "read_attributes", read_error)

    expected: type[BaseException] | None = {
        "pass": None,
        "xfail": pytest.xfail.Exception,
        "fail": pytest.fail.Exception,
        "unexpected": RuntimeError,
    }[kind]
    if expected is None:
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))
    else:
        with pytest.raises(expected):
            kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))
    assert destroyed == [11, 12]


def test_first_cleanup_failure_still_cleans_second_and_controls_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_error = RuntimeError("first cleanup")
    calls: list[int] = []
    monkeypatch.setattr(kpc, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(kpc, "read_attributes", lambda *_a, **_k: {CKA_MODULUS: b"same"})

    def destroy(_raw: object, _sh: int, handle: int) -> None:
        calls.append(handle)
        if handle == 11:
            raise cleanup_error

    monkeypatch.setattr(kpc, "destroy_quietly", destroy)

    with pytest.raises(RuntimeError) as exc_info:
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert exc_info.value is cleanup_error
    assert calls == [11, 12]


@pytest.mark.parametrize(
    ("method", "mechanism", "attr"),
    [
        ("test_modulus_matches", "RSA_PKCS_KEY_PAIR_GEN", CKA_MODULUS),
        ("test_key_type_consistent", "EC_KEY_PAIR_GEN", CKA_KEY_TYPE),
    ],
)
def test_public_malformed_value_is_recorded_before_private_reader_exception(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    mechanism: str,
    attr: int,
) -> None:
    private_error = RuntimeError("private reader failed")
    destroyed: list[int] = []
    calls: list[int] = []

    def read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        calls.append(handle)
        if handle == 11:
            return {attr: False}
        raise private_error

    _setup(
        monkeypatch,
        rsa=method == "test_modulus_matches",
        ec=method == "test_key_type_consistent",
        reads=read,
        destroyed=destroyed,
    )
    instance: Any = (
        kpc.TestRSAKeypairConsistency()
        if method == "test_modulus_matches"
        else kpc.TestECKeypairConsistency()
    )

    with pytest.raises(RuntimeError) as exc_info:
        getattr(instance, method)(_rs(mechanism))

    assert exc_info.value is private_error
    assert calls == [11, 12]
    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 1
    assert records[0].reason == "wrong_result"
    assert records[0].detail is not None
    assert records[0].detail["leg"] == "public"


def test_second_cleanup_access_violation_outranks_first_ordinary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ordinary_error = RuntimeError("first cleanup failed")
    access_violation = OSError("Exception: access violation")
    calls: list[int] = []
    monkeypatch.setattr(kpc, "gen_rsa_keypair_or_xfail", lambda *_a, **_k: (11, 12))
    monkeypatch.setattr(kpc, "read_attributes", lambda *_a, **_k: {CKA_MODULUS: b"same"})

    def destroy(_raw: object, _sh: int, handle: int) -> None:
        calls.append(handle)
        if handle == 11:
            raise ordinary_error
        raise access_violation

    monkeypatch.setattr(kpc, "destroy_quietly", destroy)

    with pytest.raises(OSError) as exc_info:
        kpc.TestRSAKeypairConsistency().test_modulus_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert exc_info.value is access_violation
    assert calls == [11, 12]


def test_mapping_omission_has_no_fabricated_ckr_and_exact_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    _setup(
        monkeypatch,
        rsa=True,
        reads=lambda *_a, **_k: {},
        destroyed=destroyed,
    )

    with pytest.raises(pytest.xfail.Exception):
        kpc.TestRSAKeypairConsistency().test_public_exponent_matches(_rs("RSA_PKCS_KEY_PAIR_GEN"))

    assert destroyed == [11, 12]
    records = C.get_records()
    assert len(records) == 2
    assert all(record.operation == "C_GetAttributeValue" for record in records)
    assert all(record.actual_ckr is None for record in records)
    assert [record.detail["leg"] for record in records if record.detail is not None] == [
        "public",
        "private",
    ]
    assert all(
        record.detail is not None
        and record.detail["producer_operation"] == "C_GenerateKeyPair"
        and record.detail["producer_mechanism"] == "CKM_RSA_PKCS_KEY_PAIR_GEN"
        for record in records
    )


def test_scoped_source_analyzer_is_clean() -> None:
    assert analyze_file("src/pkcs11_check/testcases/test_keypair_consistency.py") == []


def test_missing_attribute_sentinel_is_not_a_false_like_provider_value() -> None:
    assert MISSING_ATTRIBUTE is not False
