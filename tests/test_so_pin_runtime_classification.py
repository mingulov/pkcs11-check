"""Regression tests for SO PIN setup classification."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw import recipes
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_PIN_LEN_RANGE,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases import test_access_levels, test_session_state_machine, test_so_pin


class _Raw:
    def C_Logout(self, _session: int) -> int:  # noqa: N802
        return 0

    def C_Login(self, _session: int, _user_type: int, _pin: object, _pin_len: int) -> int:  # noqa: N802
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


def _patch_access_init_pin_setup(
    monkeypatch: pytest.MonkeyPatch,
    init_pin_impl: Any,
    *,
    c_login_rv: int = 0,
) -> SimpleNamespace:
    class Raw(_Raw):
        def C_Login(  # noqa: N802
            self,
            _session: int,
            _user_type: int,
            _pin: object,
            _pin_len: int,
        ) -> int:
            return c_login_rv

    monkeypatch.setattr(test_access_levels, "raw_open_session", lambda *_args: 1)
    monkeypatch.setattr(test_access_levels, "close_session_quietly", lambda *_args: None)
    monkeypatch.setattr(test_access_levels, "login_user", lambda *_args: None)
    monkeypatch.setattr(recipes, "init_pin", init_pin_impl)
    monkeypatch.setattr(recipes, "set_pin", lambda *_args: None)
    return SimpleNamespace(raw=Raw(), slot_id=1)


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


def test_access_init_pin_login_reject_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    rs = _patch_access_init_pin_setup(
        monkeypatch,
        lambda *_args: None,
        c_login_rv=int(CKR_USER_TYPE_INVALID),
    )

    with pytest.raises(CkrAssertionError, match="CKR_USER_TYPE_INVALID"):
        test_access_levels.TestSOSessionCapabilities().test_so_can_init_pin(
            rs,
            _config(),
        )


def test_access_init_pin_python_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    def _init_pin_bug(*_args: Any) -> None:
        raise ValueError("local C_InitPIN setup bug")

    rs = _patch_access_init_pin_setup(monkeypatch, _init_pin_bug)

    with pytest.raises(BaseException) as exc_info:
        test_access_levels.TestSOSessionCapabilities().test_so_can_init_pin(
            rs,
            _config(),
        )
    assert isinstance(exc_info.value, ValueError)
    assert "local C_InitPIN setup bug" in str(exc_info.value)


def test_access_init_pin_generic_runtime_reject_is_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _init_pin_reject(*_args: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_FUNCTION_FAILED",
            int(CKR_FUNCTION_FAILED),
        )

    rs = _patch_access_init_pin_setup(monkeypatch, _init_pin_reject)

    with pytest.raises(BaseException) as exc_info:
        test_access_levels.TestSOSessionCapabilities().test_so_can_init_pin(
            rs,
            _config(),
        )
    assert isinstance(exc_info.value, pytest.xfail.Exception)
    assert "C_InitPIN rejected" in str(exc_info.value)


def test_access_init_pin_token_policy_reject_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    def _init_pin_reject(*_args: Any) -> None:
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_PIN_LEN_RANGE",
            int(CKR_PIN_LEN_RANGE),
        )

    rs = _patch_access_init_pin_setup(monkeypatch, _init_pin_reject)

    with pytest.raises(BaseException) as exc_info:
        test_access_levels.TestSOSessionCapabilities().test_so_can_init_pin(
            rs,
            _config(),
        )
    assert isinstance(exc_info.value, pytest.skip.Exception)
    assert "C_InitPIN not usable" in str(exc_info.value)


# --- Phase 4 N2: SO-login wrong-PIN guard -> classify_negative_rv ---


def _login_session(login_rv: int) -> SimpleNamespace:
    class Raw(_Raw):
        def C_Login(  # noqa: N802
            self,
            _session: int,
            _user_type: int,
            _pin: object,
            _pin_len: int,
        ) -> int:
            return int(login_rv)

    return SimpleNamespace(raw=Raw(), slot_id=1, sh=1)


def _run_wrong_pin(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(test_so_pin, "raw_open_session", lambda *_a, **_k: 5)
    monkeypatch.setattr(test_so_pin, "close_session_quietly", lambda *_a, **_k: None)
    test_so_pin.TestSOLogin().test_so_login_wrong_pin(_login_session(login_rv))


def test_so_wrong_pin_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_wrong_pin(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_so_wrong_pin_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrong_pin(monkeypatch, int(CKR_PIN_INCORRECT))


def test_so_wrong_pin_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_wrong_pin(monkeypatch, int(CKR_ARGUMENTS_BAD))
