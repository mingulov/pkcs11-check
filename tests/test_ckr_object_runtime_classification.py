"""Runtime classification meta-tests for ckr/test_ckr_object Type-B + Type-C.

Type B -- sensitive value read (test_sensitive_value): claimed = key reports
CKA_SENSITIVE=True; violated = CKA_VALUE actually readable -> fail.

Type C -- use-after-destroy and read-only setattr: claimed_success = the prior
op (destroy / setattr) returned CKR_OK; effect_observed = the contradicting
effect (tagged object survives / value actually changed) -> fail. Honest decline
(prior op did not claim success) -> xfail. No contradiction -> pass.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw import recipes as raw_recipes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_SENSITIVE,
    CKA_VALUE,
    CKO_DATA,
    CKO_SECRET_KEY,
    CKR_FUNCTION_FAILED,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
    CKR_SESSION_HANDLE_INVALID,
)
from pkcs11_check.testcases.ckr import test_ckr_object


def _assert_real_fail(excinfo: pytest.ExceptionInfo[Failed]) -> None:
    assert not isinstance(excinfo.value, XFailed)


# --- Type B: sensitive value read -----------------------------------------


def _run_sensitive(monkeypatch: pytest.MonkeyPatch, *, claimed: bool, readable: bool) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_object, "destroy_quietly", lambda *_a, **_k: None)

    def _read(_raw: object, _sh: object, _h: object, attrs: list[int]) -> dict:
        if CKA_SENSITIVE in attrs:
            return {CKA_SENSITIVE: True} if claimed else {CKA_SENSITIVE: False}
        if CKA_VALUE in attrs:
            return {CKA_VALUE: b"\x00" * 32} if readable else {}
        return {}

    monkeypatch.setattr(test_ckr_object, "read_attributes", _read)
    test_ckr_object.TestGetAttributeErrors().test_sensitive_value(
        SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda n: True)
    )


def test_sensitive_claimed_readable_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_sensitive(monkeypatch, claimed=True, readable=True)
    _assert_real_fail(ei)


def test_sensitive_not_claimed_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_sensitive(monkeypatch, claimed=False, readable=True)


def test_sensitive_protected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_sensitive(monkeypatch, claimed=True, readable=False)


# --- Type C: use-after-destroy (C_GetAttributeValue) -----------------------


def _run_destroyed_handle(monkeypatch: pytest.MonkeyPatch, *, getattr_rv: int) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(CKR_OK),
        C_GetAttributeValue=lambda *_a, **_k: int(getattr_rv),
    )
    test_ckr_object.TestGetAttributeErrors().test_destroyed_handle(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_destroyed_handle_read_succeeds_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # CKR_OK on a destroyed handle = use-after-destroy -> fail.
    with pytest.raises(Failed) as ei:
        _run_destroyed_handle(monkeypatch, getattr_rv=int(CKR_OK))
    _assert_real_fail(ei)


def test_destroyed_handle_object_handle_invalid_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Spec-correct rejection -> pass. This is the real softhsm2 behavior that
    # previously surfaced as a false positive (read_attributes re-raised the
    # correct CKR_OBJECT_HANDLE_INVALID as a setup error).
    _run_destroyed_handle(monkeypatch, getattr_rv=int(CKR_OBJECT_HANDLE_INVALID))


def test_destroyed_handle_session_handle_invalid_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_destroyed_handle(monkeypatch, getattr_rv=int(CKR_SESSION_HANDLE_INVALID))


def test_destroyed_handle_other_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_destroyed_handle(monkeypatch, getattr_rv=int(CKR_FUNCTION_FAILED))


# --- Type C: copy destroyed handle -----------------------------------------


def _run_copy_destroyed(monkeypatch: pytest.MonkeyPatch, *, destroy_rv: int, copy_rv: int) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_object, "destroy_quietly", lambda *_a, **_k: None)

    def _copy(_sh: object, _src: object, _ptr: object, _cnt: object, out_ref: object) -> int:
        if int(copy_rv) == int(CKR_OK):
            out_ref._obj.value = 99  # produced a new object
        return int(copy_rv)

    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(destroy_rv),
        C_CopyObject=_copy,
    )
    test_ckr_object.TestCopyObjectErrors().test_copy_destroyed_handle(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_copy_destroyed_succeeds_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_copy_destroyed(monkeypatch, destroy_rv=int(CKR_OK), copy_rv=int(CKR_OK))
    _assert_real_fail(ei)


def test_copy_destroyed_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_copy_destroyed(monkeypatch, destroy_rv=int(CKR_OK), copy_rv=int(CKR_OBJECT_HANDLE_INVALID))


def test_copy_destroyed_destroy_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_copy_destroyed(monkeypatch, destroy_rv=int(CKR_FUNCTION_FAILED), copy_rv=int(CKR_OK))


# --- Type C: double destroy ------------------------------------------------


def _run_double_destroy(monkeypatch: pytest.MonkeyPatch, *, first_rv: int, survives: bool) -> None:
    monkeypatch.setattr(raw_recipes, "gen_aes_key", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_object, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_ckr_object,
        "find_objects",
        lambda *_a, **_k: [1] if survives else [],
    )
    raw = SimpleNamespace(
        C_DestroyObject=lambda *_a, **_k: int(first_rv),
        C_SetAttributeValue=lambda *_a, **_k: int(CKR_OK),
    )
    test_ckr_object.TestDestroyObjectErrors().test_destroy_already_destroyed(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_double_destroy_survives_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_double_destroy(monkeypatch, first_rv=int(CKR_OK), survives=True)
    _assert_real_fail(ei)


def test_double_destroy_gone_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_double_destroy(monkeypatch, first_rv=int(CKR_OK), survives=False)


def test_double_destroy_first_declined_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_double_destroy(monkeypatch, first_rv=int(CKR_FUNCTION_FAILED), survives=False)


# --- Type C: read-only setattr (CKA_CLASS) ---------------------------------


def _run_setattr(monkeypatch: pytest.MonkeyPatch, *, setattr_rv: int, changed: bool) -> None:
    monkeypatch.setattr(test_ckr_object, "create_object", lambda *_a, **_k: 1)
    monkeypatch.setattr(test_ckr_object, "destroy_quietly", lambda *_a, **_k: None)
    monkeypatch.setattr(
        test_ckr_object, "skip_unless_create_object_supported", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        test_ckr_object,
        "read_attributes",
        lambda *_a, **_k: {CKA_CLASS: CKO_SECRET_KEY if changed else CKO_DATA},
    )
    raw = SimpleNamespace(C_SetAttributeValue=lambda *_a, **_k: int(setattr_rv))
    test_ckr_object.TestSetAttributeErrors().test_set_readonly_class(
        SimpleNamespace(raw=raw, sh=1, has_mechanism=lambda n: True)
    )


def test_setattr_changed_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Failed) as ei:
        _run_setattr(monkeypatch, setattr_rv=int(CKR_OK), changed=True)
    _assert_real_fail(ei)


def test_setattr_noop_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(pytest.xfail.Exception):
        _run_setattr(monkeypatch, setattr_rv=int(CKR_OK), changed=False)


def test_setattr_rejected_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    _run_setattr(monkeypatch, setattr_rv=int(CKR_FUNCTION_FAILED), changed=False)
