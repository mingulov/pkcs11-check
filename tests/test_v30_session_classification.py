"""Classification meta-tests for test_v30_session C_LoginUser legs (Phase 5 P1a).

C_LoginUser / context-specific-login robustness probes treat any well-formed
CKR as acceptable; an *unexpected-but-clean* CKR from an advertised v3.0 op is a
noted deviation -> ``xfail``, not a hard ``fail`` (the module did not crash).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases import test_v30_session as tv
from tests._skip_assert import assert_skips


class _Cfg:
    pin = SimpleNamespace(get_secret_value=lambda: b"1234")


def _session_with_login_user() -> SimpleNamespace:
    raw = SimpleNamespace(available_function_names=lambda: ["C_LoginUser", "C_Login"])
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def test_login_user_unexpected_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_DEVICE_ERROR))
    with pytest.raises(XFailed):
        tv.TestCLoginUser().test_c_login_user_empty_username_user_type(
            _session_with_login_user(), _Cfg()
        )


def test_login_user_undefined_ckr_is_hard_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: 0x12345678)
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        tv.TestCLoginUser().test_c_login_user_empty_username_user_type(
            _session_with_login_user(), _Cfg()
        )


def test_login_user_already_logged_in_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_USER_ALREADY_LOGGED_IN))
    tv.TestCLoginUser().test_c_login_user_empty_username_user_type(
        _session_with_login_user(), _Cfg()
    )


def test_session_cancel_undefined_ckr_is_hard_failure() -> None:
    with pytest.raises(pytest.fail.Exception, match="undefined CK_RV"):
        tv._handle_cancel_rv(0x12345678, "C_SessionCancel")


def test_double_login_unexpected_clean_ckr_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_DEVICE_ERROR))
    monkeypatch.setattr(tv, "_raw_logout", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "raw_open_session", lambda *_a, **_k: 2)
    monkeypatch.setattr(tv, "close_session_quietly", lambda *_a, **_k: None)
    with pytest.raises(XFailed):
        tv.TestLoginLogoutCycle().test_double_login_rejected(_session_with_login_user(), _Cfg())


def _drive_positive_login_unexpected(monkeypatch: pytest.MonkeyPatch, method: str) -> Any:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_DEVICE_ERROR))
    monkeypatch.setattr(tv, "_raw_logout", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "raw_open_session", lambda *_a, **_k: 2)
    monkeypatch.setattr(tv, "close_session_quietly", lambda *_a, **_k: None)
    return getattr(tv.TestLoginLogoutCycle(), method)


def test_login_then_logout_positive_unexpected_clean_ckr_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fn = _drive_positive_login_unexpected(monkeypatch, "test_c_login_user_then_logout")
    with pytest.raises(XFailed):
        fn(_session_with_login_user(), _Cfg())


# ---------------------------------------------------------------------------
# CKR_FUNCTION_NOT_SUPPORTED from C_LoginUser / C_SessionCancel is capability
# absence (both are optional v3.0 functions with no mechanism parameter): a
# module may list a non-null function-table pointer yet stub the call. That
# must skip, never record an "advertised but not operational" xfail finding.
# ---------------------------------------------------------------------------


def test_login_user_function_not_supported_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_FUNCTION_NOT_SUPPORTED))
    assert_skips(
        tv.TestCLoginUser().test_c_login_user_empty_username_user_type,
        _session_with_login_user(),
        _Cfg(),
        match="C_LoginUser",
    )


def test_login_user_context_specific_function_not_supported_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_FUNCTION_NOT_SUPPORTED))
    assert_skips(
        tv.TestContextSpecificLogin().test_context_specific_via_c_login_user,
        _session_with_login_user(),
        _Cfg(),
        match="C_LoginUser",
    )


def test_double_login_function_not_supported_is_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_FUNCTION_NOT_SUPPORTED))
    monkeypatch.setattr(tv, "_raw_logout", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "raw_open_session", lambda *_a, **_k: 2)
    monkeypatch.setattr(tv, "close_session_quietly", lambda *_a, **_k: None)
    assert_skips(
        tv.TestLoginLogoutCycle().test_double_login_rejected,
        _session_with_login_user(),
        _Cfg(),
        match="C_LoginUser",
    )


def test_login_then_logout_positive_function_not_supported_is_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_FUNCTION_NOT_SUPPORTED))
    monkeypatch.setattr(tv, "_raw_logout", lambda *_a, **_k: int(CKR_OK))
    monkeypatch.setattr(tv, "raw_open_session", lambda *_a, **_k: 2)
    monkeypatch.setattr(tv, "close_session_quietly", lambda *_a, **_k: None)
    assert_skips(
        tv.TestLoginLogoutCycle().test_c_login_user_then_logout,
        _session_with_login_user(),
        _Cfg(),
        match="C_LoginUser",
    )


def test_session_cancel_function_not_supported_is_skip() -> None:
    assert_skips(
        tv._handle_cancel_rv,
        int(CKR_FUNCTION_NOT_SUPPORTED),
        "C_SessionCancel",
        match="C_SessionCancel",
    )


def test_session_cancel_device_error_still_xfails() -> None:
    """A genuine clean-reject CKR (not FNS) must stay xfail, not turn into a skip."""
    with pytest.raises(XFailed):
        tv._handle_cancel_rv(int(CKR_DEVICE_ERROR), "C_SessionCancel")


# ---------------------------------------------------------------------------
# F6: no-active-operation context-specific login negatives. Canonical
# CKR_OPERATION_NOT_INITIALIZED passes; CKR_USER_NOT_LOGGED_IN is a
# failure-like nonspec_reject xfail (never canonical); CKR_OK is a hard
# failure; the C_LoginUser fallback must carry operation="C_LoginUser".
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_v30_context_classifications() -> Any:
    classification.clear()
    yield
    classification.clear()


def _drive_context_login(monkeypatch: pytest.MonkeyPatch, method: str, rv: int) -> SimpleNamespace:
    session = _session_with_login_user()
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    if method == "test_context_specific_via_c_login_user":
        monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(rv))
    else:
        monkeypatch.setattr(tv, "_raw_login", lambda *_a, **_k: int(rv))
    return session


@pytest.mark.parametrize(
    "method",
    [
        "test_context_specific_login_without_active_op",
        "test_context_specific_login_uses_c_login",
        "test_context_specific_via_c_login_user",
    ],
)
def test_context_login_not_logged_in_is_nonspec_reject_xfail(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    """CKR_USER_NOT_LOGGED_IN is not canonical here -> failure-like xfail."""
    session = _drive_context_login(monkeypatch, method, int(CKR_USER_NOT_LOGGED_IN))
    with pytest.raises(XFailed):
        getattr(tv.TestContextSpecificLogin(), method)(session, _Cfg())
    record = classification.get_records()[-1]
    assert record.reason == "nonspec_reject"
    assert record.outcome == "xfail"
    assert record.actual_ckr == "CKR_USER_NOT_LOGGED_IN"
    assert record.expected_ckr == ["CKR_OPERATION_NOT_INITIALIZED"]


@pytest.mark.parametrize(
    "method",
    [
        "test_context_specific_login_without_active_op",
        "test_context_specific_login_uses_c_login",
        "test_context_specific_via_c_login_user",
    ],
)
def test_context_login_not_initialized_passes(monkeypatch: pytest.MonkeyPatch, method: str) -> None:
    session = _drive_context_login(monkeypatch, method, int(CKR_OPERATION_NOT_INITIALIZED))
    getattr(tv.TestContextSpecificLogin(), method)(session, _Cfg())
    assert classification.get_records() == []


@pytest.mark.parametrize(
    "method",
    [
        "test_context_specific_login_without_active_op",
        "test_context_specific_login_uses_c_login",
        "test_context_specific_via_c_login_user",
    ],
)
def test_context_login_accepted_is_a_hard_failure(
    monkeypatch: pytest.MonkeyPatch, method: str
) -> None:
    session = _drive_context_login(monkeypatch, method, int(CKR_OK))
    with pytest.raises(pytest.fail.Exception, match="active operation"):
        getattr(tv.TestContextSpecificLogin(), method)(session, _Cfg())


def test_context_login_via_login_user_fallback_labels_c_login_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _drive_context_login(
        monkeypatch, "test_context_specific_via_c_login_user", int(CKR_DEVICE_ERROR)
    )
    with pytest.raises(XFailed):
        tv.TestContextSpecificLogin().test_context_specific_via_c_login_user(session, _Cfg())
    record = classification.get_records()[-1]
    assert record.operation == "C_LoginUser"
    assert record.actual_ckr == "CKR_DEVICE_ERROR"
