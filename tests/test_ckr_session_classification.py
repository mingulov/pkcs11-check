"""Classification meta-tests for ckr/test_ckr_session wrong-PIN (Phase 6 C).

The wrong-PIN negative test now:
- token login-state preventing the test -> xfail (was a non-capability skip),
- wrong PIN accepted (CKR_OK) -> fail,
- CKR_PIN_INCORRECT -> pass,
- any other clean reject -> xfail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_USER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases.ckr import test_ckr_session as tcs


def _session(login_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_Login=lambda *_a, **_k: int(login_rv))
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(tcs, "open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tcs, "close_session_quietly", lambda *_a, **_k: None)
    tcs.TestLoginErrors().test_wrong_pin(_session(login_rv))


def test_token_state_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed):
        _run(monkeypatch, int(CKR_USER_ALREADY_LOGGED_IN))


def test_wrong_pin_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_pin_incorrect_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_PIN_INCORRECT))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(XFailed):
        _run(monkeypatch, int(CKR_FUNCTION_FAILED))
