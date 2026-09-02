"""Regression tests for CKO_DOMAIN_PARAMETERS setup/runtime classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_TEMPLATE_INCONSISTENT
from pkcs11_check.testcases import test_domain_params


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda _name: True,
    )


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
