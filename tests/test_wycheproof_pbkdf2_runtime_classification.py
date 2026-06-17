"""Regression tests for PBKDF2 runtime-negative classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_MECHANISM_PARAM_INVALID
from pkcs11_check.testcases.wycheproof import test_wycheproof_pbkdf2


def _session_with_pbkdf2() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(),
        sh=1,
        has_mechanism=lambda name: name == "PKCS5_PBKD2",
    )


def test_pbkdf2_invalid_prf_uses_negative_classifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generate_calls: list[tuple[int, int]] = []
    classifier_calls: list[tuple[BaseException | None, tuple[int, ...], str]] = []

    def _generate_key_with_mech(
        _raw: object,
        _session: int,
        mech: Any,
        attrs: dict[int, Any],
    ) -> int:
        value_len = int(attrs[test_wycheproof_pbkdf2.CKA_VALUE_LEN])
        generate_calls.append((int(mech.params.prf), value_len))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID",
            int(CKR_MECHANISM_PARAM_INVALID),
        )

    def _reject_or_classify(
        exc: BaseException | None,
        expected_rvs: tuple[int, ...],
        *,
        label: str,
    ) -> None:
        classifier_calls.append((exc, tuple(int(rv) for rv in expected_rvs), label))

    monkeypatch.setattr(
        test_wycheproof_pbkdf2,
        "_generate_key_with_mech",
        _generate_key_with_mech,
    )
    monkeypatch.setattr(
        test_wycheproof_pbkdf2,
        "reject_or_classify",
        _reject_or_classify,
        raising=False,
    )
    monkeypatch.setattr(test_wycheproof_pbkdf2, "destroy_quietly", lambda *_args: None)

    test_wycheproof_pbkdf2.test_pbkdf2_rejects_invalid_prf(_session_with_pbkdf2())

    assert generate_calls == [(0, 32)]
    assert len(classifier_calls) == 1
    exc, expected_rvs, label = classifier_calls[0]
    assert isinstance(exc, CkrAssertionError)
    assert expected_rvs == (int(CKR_MECHANISM_PARAM_INVALID),)
    assert label == "PKCS5_PBKD2 invalid PRF selector"


def test_pbkdf2_invalid_prf_acceptance_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _generate_key_with_mech(
        _raw: object,
        _session: int,
        _mech: Any,
        _attrs: dict[int, Any],
    ) -> int:
        return 99

    monkeypatch.setattr(
        test_wycheproof_pbkdf2,
        "_generate_key_with_mech",
        _generate_key_with_mech,
    )
    monkeypatch.setattr(test_wycheproof_pbkdf2, "destroy_quietly", lambda *_args: None)

    with pytest.raises(pytest.fail.Exception, match="accepted invalid"):
        test_wycheproof_pbkdf2.test_pbkdf2_rejects_invalid_prf(_session_with_pbkdf2())
