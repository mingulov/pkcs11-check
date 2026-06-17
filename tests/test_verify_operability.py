"""Meta-tests for classify_module_verify (Task 6).

Drive ``classify_module_verify`` with a fake ``rs`` and monkeypatched
``verify_single`` so no PKCS#11 module is touched.  Detection pattern is
the same as ``tests/test_verify_roundtrip.py``:
``xfail_as``/``fail_as`` route through ``classification.classify``, raising
``pytest.fail`` (-> ``Failed``) or ``pytest.xfail`` (-> ``XFailed``) and
recording into ``classification.get_records()``; we catch the outcome
exception and assert ``get_records()[-1].reason``.
"""

from __future__ import annotations

from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKM_ECDSA_SHA256,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
)
from pkcs11_check.testcases import test_verify_operability
from pkcs11_check.testcases.test_verify_operability import classify_module_verify


class _FakeRS:
    """Minimal stand-in for a RawSession: only ``.raw`` and ``.sh`` are read."""

    def __init__(self) -> None:
        self.raw = object()
        self.sh = 1


def _ckr(rv: int) -> CkrAssertionError:
    """Construct a CkrAssertionError carrying a specific ``.rv``."""
    return CkrAssertionError(f"unexpected {rv:#010x}", int(rv))


def _patch_verify_single(monkeypatch: pytest.MonkeyPatch, behavior: Any) -> None:
    """Replace ``verify_single`` inside test_verify_operability with a fake.

    *behavior* is either a bool (returned) or an exception instance (raised).
    """

    def fake(*_args: Any, **_kwargs: Any) -> bool:
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior  # type: ignore[return-value]

    monkeypatch.setattr(test_verify_operability, "verify_single", fake)


def _call() -> None:
    classify_module_verify(
        _FakeRS(),
        mechanism=int(CKM_ECDSA_SHA256),
        pub_handle=7,
        data=b"data",
        sig=b"sig",
        label="ECDSA-SHA256:verify-operability",
    )


# (a) verify_single returns True -> returns None, no classify record.
def test_returns_none_when_verify_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, True)
    assert _call() is None
    assert get_records() == []


# (b) raises CkrAssertionError(KEY_HANDLE_INVALID) -> xfail not_operational.
def test_key_handle_invalid_xfails_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_KEY_HANDLE_INVALID))
    with pytest.raises(XFailed):
        _call()
    rec = get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "lifecycle"
    assert rec.outcome == "xfail"


# (c) raises CkrAssertionError(FUNCTION_NOT_SUPPORTED) -> xfail not_operational.
def test_function_not_supported_xfails_not_operational(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, _ckr(CKR_FUNCTION_NOT_SUPPORTED))
    with pytest.raises(XFailed):
        _call()
    rec = get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "lifecycle"
    assert rec.outcome == "xfail"


# (d) verify_single returns False -> fail self_contradiction (crypto).
def test_false_result_fails_self_contradiction(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    _patch_verify_single(monkeypatch, False)
    with pytest.raises(Failed):
        _call()
    rec = get_records()[-1]
    assert rec.reason == "self_contradiction"
    assert rec.kind == "crypto"
    assert rec.outcome == "fail"


# (e) raises CkrAssertionError with unexpected rv (DEVICE_ERROR) -> propagates.
def test_unexpected_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    clear()
    exc = _ckr(CKR_DEVICE_ERROR)
    _patch_verify_single(monkeypatch, exc)
    with pytest.raises(CkrAssertionError) as exc_info:
        _call()
    assert exc_info.value.rv == int(CKR_DEVICE_ERROR)
    # No classification record was emitted — it is a real finding.
    assert get_records() == []
