"""Regression tests for user-PIN wrong-accept classification (F-3)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_USER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases import test_pin


def _login_session(login_rv: int) -> SimpleNamespace:
    raw = SimpleNamespace(C_Login=lambda *_a, **_k: int(login_rv))
    return SimpleNamespace(raw=raw, sh=1, slot_id=0)


def _run_wrong_pin(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(test_pin, "raw_open_session", lambda *_a, **_k: 5)
    monkeypatch.setattr(test_pin, "close_session_quietly", lambda *_a, **_k: None)
    test_pin.TestWrongPIN().test_wrong_pin_does_not_reveal_objects(_login_session(login_rv))


def test_wrong_pin_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wrong PIN that logs in is an authentication bypass (fail)."""
    with pytest.raises(Failed) as ei:
        _run_wrong_pin(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)

    records = C.get_records()
    assert len(records) == 1
    record = records[0]
    assert record.reason == "accepted_invalid"
    assert record.outcome == "fail"
    assert record.severity == "HIGH"
    assert record.kind is None
    assert record.label == "C_Login with a wrong PIN"
    assert record.mechanism is None
    assert record.operation == "C_Login"
    assert record.expected_ckr is None
    assert record.actual_ckr == "CKR_OK"
    assert record.summary == "module accepted a wrong PIN (authentication bypass)"
    assert record.spec_ref == "PKCS#11 v3.2 · C_Login"
    assert record.detail is None


def test_wrong_pin_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_wrong_pin(monkeypatch, int(CKR_PIN_INCORRECT))
    assert C.get_records() == []


def test_wrong_pin_already_logged_in_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _run_wrong_pin(monkeypatch, int(CKR_USER_ALREADY_LOGGED_IN))
    assert C.get_records() == []
