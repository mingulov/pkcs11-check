"""Runtime classification meta-tests for test_session_info R/O keygen (F-007).

``test_ro_session_cannot_generate_token_objects`` must condition its oracle
on authentication: only when logged in can it claim the read-only
restriction (CKR_SESSION_READ_ONLY) was the deciding condition. Without a
PIN, CKR_USER_NOT_LOGGED_IN is a legitimate deciding condition. The
SO-login-specific CKR_SESSION_READ_ONLY_EXISTS is never an acceptable
pass for a user-context R/O probe -- it is a deviation (xfail).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases import test_session_info as tsi


def _run_ro_token_keygen(
    monkeypatch: pytest.MonkeyPatch, *, pin: bytes | None, keygen_rv: int
) -> None:
    monkeypatch.setattr(tsi, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tsi, "get_pin_bytes", lambda *_a, **_k: pin)
    monkeypatch.setattr(tsi, "login_user", lambda *_a, **_k: None)
    monkeypatch.setattr(tsi, "gen_aes_key_or_xfail", lambda *_a, **_k: 1)
    monkeypatch.setattr(tsi, "close_session_quietly", lambda *_a, **_k: None)
    raw = SimpleNamespace(
        C_GenerateKey=lambda *_a, **_k: int(keygen_rv),
        C_DestroyObject=lambda *_a, **_k: int(CKR_OK),
    )
    tsi.TestSessionInfo().test_ro_session_cannot_generate_token_objects(
        SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True),
        SimpleNamespace(),
    )


def test_ro_keygen_logged_in_so_code_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-007: SO-specific READ_ONLY_EXISTS is a deviation, never a pass."""
    with pytest.raises(pytest.xfail.Exception):
        _run_ro_token_keygen(monkeypatch, pin=b"1234", keygen_rv=int(CKR_SESSION_READ_ONLY_EXISTS))


def test_ro_keygen_logged_in_not_logged_in_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-007: NOT_LOGGED_IN while authenticated contradicts the login -> xfail."""
    with pytest.raises(pytest.xfail.Exception):
        _run_ro_token_keygen(monkeypatch, pin=b"1234", keygen_rv=int(CKR_USER_NOT_LOGGED_IN))


def test_ro_keygen_logged_in_ok_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-007: TOKEN object created on an R/O session is a real bypass -> fail."""
    with pytest.raises(Failed) as ei:
        _run_ro_token_keygen(monkeypatch, pin=b"1234", keygen_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_ro_keygen_anonymous_ok_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-007: bypass fails even without authentication."""
    with pytest.raises(Failed) as ei:
        _run_ro_token_keygen(monkeypatch, pin=None, keygen_rv=int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_ro_keygen_logged_in_read_only_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_ro_token_keygen(monkeypatch, pin=b"1234", keygen_rv=int(CKR_SESSION_READ_ONLY))


def test_ro_keygen_anonymous_not_logged_in_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-007: without a PIN, NOT_LOGGED_IN is a legitimate deciding condition."""
    _run_ro_token_keygen(monkeypatch, pin=None, keygen_rv=int(CKR_USER_NOT_LOGGED_IN))


def test_ro_keygen_anonymous_read_only_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_ro_token_keygen(monkeypatch, pin=None, keygen_rv=int(CKR_SESSION_READ_ONLY))
