"""Meta-tests for verify_roundtrip (B1): local oracle is the always-run judge.

These tests monkeypatch the module-side ``verify_single`` and a fake ``rs`` so no
PKCS#11 module is touched.  The classify-assertion pattern is copied from
``tests/test_classification_emit.py``: ``xfail_as``/``fail_as`` route through
``classification.classify``, which raises ``pytest.fail`` (-> ``Failed``) or
``pytest.xfail`` (-> ``XFailed``) and records into ``classification.get_records()``;
we catch the outcome exception and assert ``get_records()[-1].reason``.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import clear, get_records, xfail_as
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_OPERATION_ACTIVE,
)
from pkcs11_check.testcases import _local_verify
from pkcs11_check.testcases._local_verify import MalformedSignature, verify_roundtrip


class _FakeRS:
    """Minimal stand-in for a raw session: only ``.raw`` and ``.sh`` are read."""

    def __init__(self) -> None:
        self.raw = object()
        self.sh = 1


def _ckr(rv: int) -> CkrAssertionError:
    """Construct a CkrAssertionError carrying a specific ``.rv`` (message, rv)."""
    return CkrAssertionError(f"unexpected {rv}", int(rv))


def _patch_verify_single(monkeypatch: pytest.MonkeyPatch, behavior: Any) -> None:
    """Replace the module-side verify_single with a fake.

    *behavior* is either a bool (returned) or an exception instance (raised).
    """

    def fake(*_args: Any, **_kwargs: Any) -> bool:
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior

    monkeypatch.setattr(_local_verify, "verify_single", fake)


def _call(local: Any) -> None:
    verify_roundtrip(
        _FakeRS(),
        mechanism=0x40,  # arbitrary CKM int; verify_single is faked
        data=b"data",
        signature=b"sig",
        local=local,
        module_pub_handle=7,
        label="RSA-PKCS:verify",
    )


# (a) local True + module True -> returns None, no classify raised.
def test_both_valid_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, True)
    assert _call(lambda: True) is None
    assert get_records() == []


# (b) local False -> fail with reason wrong_result.
def test_local_false_fails_wrong_result(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, True)
    with pytest.raises(Failed):
        _call(lambda: False)
    rec = get_records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"
    assert rec.outcome == "fail"


# (c) module raises FUNCTION_NOT_SUPPORTED (local True) -> returns None (pass).
def test_module_function_not_supported_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_FUNCTION_NOT_SUPPORTED))
    assert _call(lambda: True) is None
    assert get_records() == []


# (d) module raises KEY_HANDLE_INVALID (local True) -> returns None.
def test_module_key_handle_invalid_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_KEY_HANDLE_INVALID))
    assert _call(lambda: True) is None
    assert get_records() == []


# (e) module raises OPERATION_ACTIVE -> routes through signature_rejected_or_xfail
# (NOT a bare re-raise of CkrAssertionError). Asserted via spy + xfail outcome.
def test_module_operation_active_routes_to_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_OPERATION_ACTIVE))

    seen: list[tuple[AssertionError, str]] = []

    def spy(exc: AssertionError, label: str) -> bool:
        seen.append((exc, label))
        # mirror the real helper for a non-clean reject CKR: xfail (never re-raise)
        xfail_as("nonspec_reject", kind="metadata", label=label, summary=f"{label}: spy")

    monkeypatch.setattr(_local_verify, "signature_rejected_or_xfail", spy)

    with pytest.raises(XFailed):
        _call(lambda: True)

    assert len(seen) == 1
    assert isinstance(seen[0][0], CkrAssertionError)
    assert seen[0][0].rv == int(CKR_OPERATION_ACTIVE)
    assert get_records()[-1].outcome == "xfail"


def test_module_operation_active_real_helper_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """With the real signature_rejected_or_xfail, OPERATION_ACTIVE -> xfail, not a re-raise."""
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_OPERATION_ACTIVE))
    with pytest.raises(XFailed):
        _call(lambda: True)


# (f) module returns False (local True) -> fail with reason self_contradiction.
def test_module_false_fails_self_contradiction(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, False)
    with pytest.raises(Failed):
        _call(lambda: True)
    rec = get_records()[-1]
    assert rec.reason == "self_contradiction"
    assert rec.kind == "crypto"
    assert rec.outcome == "fail"


# (g) local raises MalformedSignature -> xfail with reason nonspec_reject.
def test_malformed_signature_xfails_nonspec_reject(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, True)

    def bad_local() -> bool:
        raise MalformedSignature("bad width")

    with pytest.raises(XFailed):
        _call(bad_local)
    rec = get_records()[-1]
    assert rec.reason == "nonspec_reject"
    assert rec.outcome == "xfail"
