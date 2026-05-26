"""Regression tests for SO PIN setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
)
from pkcs11_check.testcases import test_access_levels, test_session_state_machine, test_so_pin


class _Raw:
    def C_Logout(self, _session: int) -> int:  # noqa: N802
        return 0


def _raw_session() -> SimpleNamespace:
    return SimpleNamespace(raw=_Raw(), slot_id=1)


def _config() -> SimpleNamespace:
    return SimpleNamespace(pin="1234")


def _patch_set_pin_setup(
    monkeypatch: pytest.MonkeyPatch,
    set_pin_impl: Any,
) -> None:
    monkeypatch.setattr(test_so_pin, "raw_open_session", lambda *_args: 1)
    monkeypatch.setattr(test_so_pin, "close_session_quietly", lambda *_args: None)
    monkeypatch.setattr(test_so_pin, "login_user", lambda *_args: None)
    monkeypatch.setattr(test_so_pin, "set_pin", set_pin_impl)


@pytest.mark.parametrize(
    "module",
    [test_access_levels, test_session_state_machine],
)
def test_so_pin_incorrect_is_setup_skip(module: object) -> None:
    classifier = getattr(module, "_skip_if_so_pin_differs")

    with pytest.raises(pytest.skip.Exception, match="SO PIN differs from user PIN"):
        classifier(CKR_PIN_INCORRECT)


def test_set_pin_python_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def _set_pin_bug(*_args: Any) -> None:
        raise ValueError("local C_SetPIN setup bug")

    _patch_set_pin_setup(monkeypatch, _set_pin_bug)

    with pytest.raises(BaseException) as exc_info:
        test_so_pin.TestSetPIN().test_set_pin_changes_pin(_raw_session(), _config())
    assert isinstance(exc_info.value, ValueError)
    assert "local C_SetPIN setup bug" in str(exc_info.value)


def test_set_pin_generic_runtime_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    def _set_pin_reject(*_args: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_FAILED",
            int(CKR_FUNCTION_FAILED),
        )

    _patch_set_pin_setup(monkeypatch, _set_pin_reject)

    with pytest.raises(BaseException) as exc_info:
        test_so_pin.TestSetPIN().test_set_pin_changes_pin(_raw_session(), _config())
    assert isinstance(exc_info.value, pytest.xfail.Exception)
    assert "C_SetPIN rejected" in str(exc_info.value)


def test_set_pin_token_policy_reject_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    def _set_pin_reject(*_args: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_PIN_LEN_RANGE",
            int(CKR_PIN_LEN_RANGE),
        )

    _patch_set_pin_setup(monkeypatch, _set_pin_reject)

    with pytest.raises(BaseException) as exc_info:
        test_so_pin.TestSetPIN().test_set_pin_changes_pin(_raw_session(), _config())
    assert isinstance(exc_info.value, pytest.skip.Exception)
    assert "C_SetPIN not usable" in str(exc_info.value)
