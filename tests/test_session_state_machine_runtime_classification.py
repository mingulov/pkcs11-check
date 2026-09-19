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
    CKS_RW_PUBLIC_SESSION,
    CKS_RW_USER_FUNCTIONS,
)
from pkcs11_check.testcases import test_session_state_machine as tsm


def _session(login_rv: int) -> SimpleNamespace:
    def _login(*_a: object, **_k: object) -> int:
        return int(login_rv)

    def _token_info(_slot_id: object, info_ref: object) -> int:
        info_ref._obj.flags = 0  # type: ignore[attr-defined]
        return int(CKR_OK)

    raw = SimpleNamespace(C_Login=_login, C_GetTokenInfo=_token_info)
    return SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(tsm, "raw_open_session", lambda *_a, **_k: 9)
    monkeypatch.setattr(tsm, "_logout_safe", lambda *_a, **_k: None)
    monkeypatch.setattr(tsm, "close_session_quietly", lambda *_a, **_k: None)
    tsm.TestROvsRWSessionState().test_so_login_requires_rw_session(
        _session(login_rv), SimpleNamespace(pin="1234", so_pin=None)
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


# --- F-008: test_open_session_is_public --------------------------------------
# Login is token-wide, so a fresh handle does not imply public state. The
# test must settle to logged-out and prove public state with an explicit
# C_GetSessionInfo observation before the visibility probe.


def _run_open_is_public(monkeypatch: pytest.MonkeyPatch, *, state: int, found: list[int]) -> None:
    monkeypatch.setattr(tsm, "raw_open_session", lambda *_a, **_k: 7)
    monkeypatch.setattr(tsm, "_logout_safe", lambda *_a, **_k: None)
    monkeypatch.setattr(tsm, "get_session_info", lambda *_a, **_k: {"state": int(state)})
    monkeypatch.setattr(tsm, "find_objects", lambda *_a, **_k: list(found))
    monkeypatch.setattr(tsm, "close_session_quietly", lambda *_a, **_k: None)
    tsm.TestLoginStateTransitions().test_open_session_is_public(
        SimpleNamespace(raw=object(), sh=1, slot_id=0, has_mechanism=lambda n: True),
        SimpleNamespace(),
    )


def test_open_is_public_unestablished_state_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-008: still logged in after settling -> precondition unmet -> xfail."""
    with pytest.raises(pytest.xfail.Exception):
        _run_open_is_public(monkeypatch, state=int(CKS_RW_USER_FUNCTIONS), found=[])


def test_open_is_public_logged_in_with_keys_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-008: no public-state claim, so visible keys must not fail."""
    with pytest.raises(pytest.xfail.Exception):
        _run_open_is_public(monkeypatch, state=int(CKS_RW_USER_FUNCTIONS), found=[9])


def test_open_is_public_private_visible_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-008: private keys visible in a proven-public session -> fail."""
    with pytest.raises(Failed) as ei:
        _run_open_is_public(monkeypatch, state=int(CKS_RW_PUBLIC_SESSION), found=[9])
    assert not isinstance(ei.value, XFailed)


def test_open_is_public_empty_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_open_is_public(monkeypatch, state=int(CKS_RW_PUBLIC_SESSION), found=[])
