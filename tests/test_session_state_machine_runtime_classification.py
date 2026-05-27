"""Runtime classification meta-tests for test_session_state_machine (Phase 4 N2).

Login/session-state conflict guards check that a conflicting login or write
rejects. Converted from a flat ``assert rv in (...)`` to a 3-way
``classify_negative_rv``:

- ``CKR_OK`` (the conflicting login / write succeeded) -> ``fail``,
- the spec-preferred code -> ``pass``,
- any other clean reject code -> ``xfail``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.types_std import (
    CKR_OK,
    CKR_SESSION_READ_ONLY,
    CKR_SESSION_READ_ONLY_EXISTS,
    CKR_USER_TYPE_INVALID,
)
from pkcs11_check.testcases import test_session_state_machine as tsm


def _session(login_rv: int) -> SimpleNamespace:
    def _login(*_a: object, **_k: object) -> int:
        return int(login_rv)

    raw = SimpleNamespace(C_Login=_login)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(tsm, "get_pin_bytes", lambda *_a, **_k: b"1234")
    monkeypatch.setattr(tsm, "raw_open_session", lambda *_a, **_k: 9)
    monkeypatch.setattr(tsm, "_logout_safe", lambda *_a, **_k: None)
    monkeypatch.setattr(tsm, "close_session_quietly", lambda *_a, **_k: None)
    tsm.TestROvsRWSessionState().test_so_login_requires_rw_session(
        _session(login_rv), SimpleNamespace()
    )


def test_conflicting_login_accepted_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run(monkeypatch, int(CKR_OK))
    assert not isinstance(ei.value, XFailed)


def test_spec_reject_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_SESSION_READ_ONLY_EXISTS))


def test_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_USER_TYPE_INVALID))


def test_other_reject_session_read_only_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_SESSION_READ_ONLY))
