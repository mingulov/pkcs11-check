"""Runtime classification meta-tests for ckr/test_ckr_codes Type-B + Type-C.

Type B -- test_ckr_attribute_sensitive: claimed=CKA_SENSITIVE=True read-back,
violated=CKA_VALUE actually readable -> fail; not claimed -> xfail.

Type C -- test_ckr_object_handle_invalid_after_destroy: a negative op on a
destroyed handle. C_GetAttributeValue is issued *directly* and the raw rv is
classified: CKR_OBJECT_HANDLE_INVALID / CKR_SESSION_HANDLE_INVALID (spec-correct
rejection) -> pass; CKR_OK (read succeeded on a destroyed handle =
use-after-destroy) -> fail; any other clean reject -> xfail. The direct call
avoids re-raising the correct rejection inside the read_attributes recipe.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.types_std import (
    CKA_SENSITIVE,
    CKA_VALUE,
    CKR_FUNCTION_FAILED,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases.ckr import test_ckr_codes


def _real_fail(ei: pytest.ExceptionInfo[Failed]) -> None:
    assert not isinstance(ei.value, XFailed)


# --- Type B: sensitive value read -----------------------------------------


def _run_sensitive(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, readable: bool) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_codes, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict:
        if CKA_SENSITIVE in attrs:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 32} if readable else {}
        return {}

    monkeypatch.setattr(test_ckr_codes, "read_attributes", _read)
    test_ckr_codes.TestCKRAttributeErrors().test_ckr_attribute_sensitive(
        SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)
    )


def test_sensitive_claimed_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_sensitive(monkeypatch, claimed=True, readable=True)
    _real_fail(ei)


def test_sensitive_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_sensitive(monkeypatch, claimed=False, readable=True)


def test_sensitive_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_sensitive(monkeypatch, claimed=True, readable=False)


# --- Type C: use-after-destroy ---------------------------------------------


def _run_uad(monkeypatch: pytest.MonkeyPatch, *, getattr_rv: int) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(CKR_OK),
        C_GetAttributeValue=lambda *_a, **_k: int(getattr_rv),
    )
    test_ckr_codes.TestCKRObjectErrors().test_ckr_object_handle_invalid_after_destroy(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_uad_read_succeeds_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # CKR_OK on a destroyed handle = use-after-destroy -> fail.
    with pytest.raises(Failed) as ei:
        _run_uad(monkeypatch, getattr_rv=int(CKR_OK))
    _real_fail(ei)


def test_uad_object_handle_invalid_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Spec-correct rejection of a destroyed handle -> pass. This is the real
    # softhsm2 behavior that previously surfaced as a false-positive failure
    # because read_attributes re-raised the correct CKR_OBJECT_HANDLE_INVALID.
    _run_uad(monkeypatch, getattr_rv=int(CKR_OBJECT_HANDLE_INVALID))


def test_uad_session_handle_invalid_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_uad(monkeypatch, getattr_rv=int(CKR_SESSION_HANDLE_INVALID))


def test_uad_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_uad(monkeypatch, getattr_rv=int(CKR_FUNCTION_FAILED))
