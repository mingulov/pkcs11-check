"""Regression tests for CKO_DOMAIN_PARAMETERS setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKA_KEY_TYPE, CKR_GENERAL_ERROR, CKR_TEMPLATE_INCONSISTENT
from pkcs11_check.testcases import test_domain_params


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


@pytest.fixture(autouse=True)
def _clear_classifications() -> None:
    C.clear()
    yield
    C.clear()


def test_ec_domain_param_generic_create_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _create_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_domain_params, "create_object", _create_reject)
    monkeypatch.setattr(
        test_domain_params.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="EC domain parameter creation"):
        test_domain_params.TestEcDomainParameters().test_ec_domain_params_key_type(_session())


def test_ec_domain_param_template_reject_stays_unsupported() -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT",
        int(CKR_TEMPLATE_INCONSISTENT),
    )

    try:
        raise exc
    except AssertionError as caught:
        assert test_domain_params._ec_domain_param_create_rejected_as_unsupported(caught)


def test_multiple_curve_generic_create_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _create_reject(*_args: Any, **_kwargs: Any) -> int:
        raise CkrAssertionError("Unexpected CK_RV CKR_GENERAL_ERROR", int(CKR_GENERAL_ERROR))

    monkeypatch.setattr(test_domain_params, "create_object", _create_reject)
    monkeypatch.setattr(
        test_domain_params.pytest,
        "skip",
        lambda message: pytest.fail(f"unexpected skip: {message}"),
    )

    with pytest.raises(pytest.xfail.Exception, match="EC domain parameter creation"):
        test_domain_params.TestMultipleCurveDomainParams().test_ec_curve_domain_params(
            _session(),
            "secp256r1",
        )


def test_missing_domain_key_type_records_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_domain_params, "_create_ec_domain_params", lambda *_a, **_k: 31)
    monkeypatch.setattr(test_domain_params, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_domain_params,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_domain_params.TestEcDomainParameters().test_ec_domain_params_key_type(_session())

    assert destroyed == [31]
    assert [(rec.reason, rec.operation) for rec in C.get_records()] == [
        ("honest_deviation", "C_GetAttributeValue")
    ]


def test_missing_domain_params_suppresses_only_dependent_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_domain_params, "_create_ec_domain_params", lambda *_a, **_k: 37)
    monkeypatch.setattr(test_domain_params, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(test_domain_params, "destroy_quietly", lambda *_a: None)
    monkeypatch.setattr(
        test_domain_params,
        "encode_named_curve_parameters",
        lambda *_a: pytest.fail("dependent parse must not run"),
    )

    test_domain_params.TestEcDomainParameters().test_ec_domain_params_ec_params_readable(_session())

    assert [rec.label for rec in C.get_records()] == ["CKA_EC_PARAMS:domain-parameters"]


def test_enumeration_missing_key_type_continues_to_later_object_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(test_domain_params, "find_objects", lambda *_a, **_k: [41, 43])

    def _read(_raw: object, _sh: int, handle: int, _attrs: list[int]) -> dict[int, Any]:
        return {} if handle == 41 else {CKA_KEY_TYPE: b"not-an-integer"}

    monkeypatch.setattr(test_domain_params, "read_attributes", _read)

    with pytest.raises(AssertionError, match="Expected int"):
        test_domain_params.TestDomainParameterEnumeration().test_domain_params_have_key_type(
            _session()
        )

    assert [rec.reason for rec in C.get_records()] == ["honest_deviation"]


def test_multiple_curve_missing_key_type_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destroyed: list[int] = []
    monkeypatch.setattr(test_domain_params, "create_object", lambda *_a, **_k: 47)
    monkeypatch.setattr(test_domain_params, "read_attributes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        test_domain_params,
        "destroy_quietly",
        lambda _raw, _sh, handle: destroyed.append(handle),
    )

    test_domain_params.TestMultipleCurveDomainParams().test_ec_curve_domain_params(
        _session(), "secp256r1"
    )

    assert destroyed == [47]
    assert [rec.detail["attribute"]["id"] for rec in C.get_records() if rec.detail] == [
        int(CKA_KEY_TYPE)
    ]
