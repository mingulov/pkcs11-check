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

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_OK,
    CKR_USER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases import test_v30_session as tv


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


def test_login_user_already_logged_in_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tv, "_pin_bytes", lambda _cfg: b"1234")
    monkeypatch.setattr(tv, "_raw_login_user", lambda *_a, **_k: int(CKR_USER_ALREADY_LOGGED_IN))
    tv.TestCLoginUser().test_c_login_user_empty_username_user_type(
        _session_with_login_user(), _Cfg()
    )


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
