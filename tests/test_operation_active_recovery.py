"""Reactive recovery from a stale active operation on a shared session.

Regression test for the CKR_OPERATION_ACTIVE cascade. Some providers
(kryoptic v1.5.0, tpm2-pkcs11) violate the spec by leaving a verify operation
active after C_Verify rejects a signature; on the shared module-scoped session
the next test's C_*Init then returns CKR_OPERATION_ACTIVE. Recovery is tiered
and fires ONLY when CKR_OPERATION_ACTIVE actually occurs, so the common clean
path stays free of extra round-trips (no regression for RPC-bound providers
like BouncyHSM):

1. C_SessionCancel + retry (works in place on v3.0+, e.g. kryoptic).
2. If still active (e.g. tpm2-pkcs11: v2.40, no C_SessionCancel, no working
   in-place cancel), request a session reopen; the holder reopens before the
   next handout so the cascade stops at one collateral failure.

The genuine provider bug is surfaced separately as a FAIL by
``testcases/test_operation_termination.py``; this only prevents the cascade.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from pkcs11_check.raw.recipes import (
    _init_or_recover,
    consume_session_reopen_request,
    request_session_reopen,
)
from pkcs11_check.raw.types_std import CKR_OK, CKR_OPERATION_ACTIVE


@pytest.fixture(autouse=True)
def _clear_reopen_flag() -> Iterator[None]:
    # The reopen request is a process-global; clear it before and after each test
    # so cases do not leak into one another.
    consume_session_reopen_request()
    yield
    consume_session_reopen_request()


class _RecordingRaw:
    def __init__(self) -> None:
        self.cancels: list[tuple[int, int]] = []

    def C_SessionCancel(self, sh: int, flags: int) -> int:  # noqa: N802
        self.cancels.append((sh, int(flags)))
        return CKR_OK


class _PreV30Raw:
    """No C_SessionCancel attribute (pre-v3.0 module)."""


class _ErroringCancelRaw:
    """C_SessionCancel is present but returns a failure code (e.g. a v3.x module
    that advertises it but cannot cancel, or returns CKR_FUNCTION_NOT_SUPPORTED)."""

    def __init__(self) -> None:
        self.cancels = 0

    def C_SessionCancel(self, sh: int, flags: int) -> int:  # noqa: N802
        self.cancels += 1
        return 0x00000054  # CKR_FUNCTION_NOT_SUPPORTED -- arbitrary non-OK code


class _RaisingCancelRaw:
    """C_SessionCancel call itself raises (e.g. ctypes-level failure)."""

    def C_SessionCancel(self, sh: int, flags: int) -> int:  # noqa: N802
        raise OSError("simulated cancel call failure")


def test_recovers_in_place_when_cancel_clears_the_op() -> None:
    raw = _RecordingRaw()
    attempts = {"n": 0}

    def init_fn() -> int:
        attempts["n"] += 1
        # First init trips on a prior test's leftover op; cancel clears it, second OK.
        return CKR_OPERATION_ACTIVE if attempts["n"] == 1 else CKR_OK

    rv = _init_or_recover(raw, 7, init_fn)  # type: ignore[arg-type]

    assert rv == CKR_OK
    assert attempts["n"] == 2, "init must be retried exactly once after recovery"
    assert raw.cancels and raw.cancels[-1][0] == 7
    assert not consume_session_reopen_request(), "in-place recovery needs no reopen"


def test_clean_path_does_not_cancel_retry_or_reopen() -> None:
    raw = _RecordingRaw()
    attempts = {"n": 0}

    def init_fn() -> int:
        attempts["n"] += 1
        return CKR_OK

    rv = _init_or_recover(raw, 7, init_fn)  # type: ignore[arg-type]

    assert rv == CKR_OK
    assert attempts["n"] == 1, "clean init must not be retried"
    assert raw.cancels == [], "no cancel on the clean path (zero overhead)"
    assert not consume_session_reopen_request()


def test_unclearable_op_requests_a_session_reopen() -> None:
    # Provider has C_SessionCancel but it does not clear the op -> init still active.
    raw = _RecordingRaw()

    rv = _init_or_recover(raw, 7, lambda: CKR_OPERATION_ACTIVE)  # type: ignore[arg-type]

    assert rv == CKR_OPERATION_ACTIVE
    assert len(raw.cancels) == 1, "exactly one in-place recovery attempt"
    assert consume_session_reopen_request(), "must request reopen when it cannot clear in place"


def test_pre_v30_module_requests_reopen_without_raising() -> None:
    # tpm2-like: no C_SessionCancel attribute -> AttributeError swallowed, op stays
    # active -> a reopen is requested (and no exception leaks).
    rv = _init_or_recover(_PreV30Raw(), 7, lambda: CKR_OPERATION_ACTIVE)  # type: ignore[arg-type]
    assert rv == CKR_OPERATION_ACTIVE
    assert consume_session_reopen_request()


def test_consume_is_one_shot() -> None:
    request_session_reopen()
    assert consume_session_reopen_request() is True
    assert consume_session_reopen_request() is False, "request must clear after one consume"


def test_cancel_returning_an_error_code_still_escalates_to_reopen() -> None:
    # C_SessionCancel present but returns a failure code: the rv is ignored and the
    # retry (still active) drives the reopen -- the effect is verified, not the claim.
    raw = _ErroringCancelRaw()
    rv = _init_or_recover(raw, 7, lambda: CKR_OPERATION_ACTIVE)  # type: ignore[arg-type]
    assert rv == CKR_OPERATION_ACTIVE
    assert raw.cancels == 1
    assert consume_session_reopen_request()


def test_cancel_call_raising_is_swallowed_and_escalates_to_reopen() -> None:
    # If the cancel call itself raises (ctypes-level failure), recovery must not
    # turn that into a hard error -- it falls through to the reopen request.
    rv = _init_or_recover(_RaisingCancelRaw(), 7, lambda: CKR_OPERATION_ACTIVE)  # type: ignore[arg-type]
    assert rv == CKR_OPERATION_ACTIVE
    assert consume_session_reopen_request()
