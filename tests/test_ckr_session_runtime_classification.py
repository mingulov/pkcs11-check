"""Runtime classification meta-tests for ckr/test_ckr_session logout errors.

F-005 -- login state is token-wide and the fixture may already have logged
in, so ``test_logout_when_not_logged_in`` must establish the logged-out
state with a settling ``C_Logout`` before probing:

- settling logout neither OK nor NOT_LOGGED_IN -> ``xfail`` (precondition
  unestablished; the old code raised a bare ``assert`` here).
- probe logout returns NOT_LOGGED_IN -> ``pass``.
- probe logout returns any other clean code (including CKR_OK -- some
  modules do not error on logout without login) -> ``xfail`` as a recorded
  deviation, never a silent pass and never a provider-bug fail.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_OK,
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.ckr import test_ckr_session as tcs


def _run_logout(monkeypatch: pytest.MonkeyPatch, logout_rvs: list[int]) -> None:
    monkeypatch.setattr(tcs, "open_session", lambda *_a, **_k: 9)
    monkeypatch.setattr(tcs, "close_session_quietly", lambda *_a, **_k: None)
    rvs = [int(v) for v in logout_rvs]
    raw = SimpleNamespace(C_Logout=lambda *_a, **_k: rvs.pop(0))
    tcs.TestLogoutErrors().test_logout_when_not_logged_in(
        SimpleNamespace(raw=raw, sh=1, slot_id=0, has_mechanism=lambda n: True)
    )


def test_logout_setup_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-005: settling logout declined -> precondition unestablished -> xfail."""
    with pytest.raises(pytest.xfail.Exception):
        _run_logout(
            monkeypatch,
            [int(CKR_FUNCTION_FAILED), int(CKR_USER_NOT_LOGGED_IN)],
        )


def test_logout_probe_ok_after_settling_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-005: OK on the probe is a recorded deviation, not a silent pass."""
    with pytest.raises(pytest.xfail.Exception):
        _run_logout(monkeypatch, [int(CKR_USER_NOT_LOGGED_IN), int(CKR_OK)])


def test_logout_probe_unexpected_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-005: other clean probe codes are deviations, not passes."""
    with pytest.raises(pytest.xfail.Exception):
        _run_logout(
            monkeypatch,
            [int(CKR_USER_NOT_LOGGED_IN), int(CKR_USER_ALREADY_LOGGED_IN)],
        )


def test_logout_logged_in_token_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-005: settling OK (was logged in) + probe NOT_LOGGED_IN -> pass."""
    _run_logout(monkeypatch, [int(CKR_OK), int(CKR_USER_NOT_LOGGED_IN)])


def test_logout_already_out_token_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """F-005: settling NOT_LOGGED_IN (already out) + probe NOT_LOGGED_IN -> pass."""
    _run_logout(
        monkeypatch,
        [int(CKR_USER_NOT_LOGGED_IN), int(CKR_USER_NOT_LOGGED_IN)],
    )
