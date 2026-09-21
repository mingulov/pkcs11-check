"""Runtime classification meta-test for SO-after-USER login (M-19).

Per ``C_Login`` return values, logging in as SO on a session already logged
in as USER (a *different* user type) returns
``CKR_USER_ANOTHER_ALREADY_LOGGED_IN``; ``CKR_USER_ALREADY_LOGGED_IN`` is the
same-type double-login code. The suite's own CKR table
(``CKR_SESSION["login_user_another_logged_in"]``) agrees, so the live test
must expect the spec sibling -- the wrong sibling is a noted deviation,
not a spec-correct pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check.raw.types_std import (
    CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
)
from pkcs11_check.testcases import test_so_pin


def _run(monkeypatch: pytest.MonkeyPatch, login_rv: int) -> None:
    monkeypatch.setattr(test_so_pin, "resolve_so_pin", lambda _cfg: (b"87654321", True))
    monkeypatch.setattr(test_so_pin, "guard_so_lockout", lambda *_a, **_k: None)
    raw = SimpleNamespace(C_Login=lambda *_a, **_k: int(login_rv))
    rs = SimpleNamespace(raw=raw, sh=7, slot_id=0)
    test_so_pin.TestSOLogin().test_user_and_so_cannot_coexist(rs, SimpleNamespace())


def test_so_after_user_spec_sibling_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run(monkeypatch, int(CKR_USER_ANOTHER_ALREADY_LOGGED_IN))


def test_so_after_user_wrong_sibling_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run(monkeypatch, int(CKR_USER_ALREADY_LOGGED_IN))


def test_expected_code_matches_ckr_table() -> None:
    """The live oracle and the CKR table must name the same spec code (M-19)."""
    from pkcs11_check.testcases.ckr._ckr_spec import CKR_SESSION

    assert (
        CKR_SESSION["login_user_another_logged_in"].spec_ckr == CKR_USER_ANOTHER_ALREADY_LOGGED_IN
    )
