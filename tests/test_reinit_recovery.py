"""Reactive recovery from a lost C_Initialize state (library de-initialized).

When a proxied PKCS#11 provider crashes and pkcs11-proxy-ng restarts it, the
loaded client module survives but loses its init/connection context: subsequent
calls return ``CKR_CRYPTOKI_NOT_INITIALIZED`` (or, with a stale handle,
``CKR_SESSION_HANDLE_INVALID`` / ``CKR_SESSION_CLOSED``, or a transport-level
``CKR_DEVICE_ERROR`` / ``CKR_DEVICE_REMOVED``) until the library is
re-initialized.

A provider/proxy restart is **not instantaneous** -- it takes seconds. So
recovery is a *bounded wait-and-reconnect loop with backoff* at the next session
bootstrap (``C_Finalize`` best-effort + ``C_Initialize`` to reconnect, then
re-open + re-login), so one provider crash mid-file does not cascade onto every
remaining test in that file while the proxy comes back.

The triggering test records its real result (recorded as-is); recovery is for
*subsequent* tests. The crash finding itself is captured by the triggering test
and the CK_RV trace; a warning + ``reinit_count`` surface how many restarts were
recovered. The loop is bounded (attempt + time budget) so a genuinely dead
provider fails as a finding, never hangs. Mirrors the ``CKR_OPERATION_ACTIVE``
tiered-recovery pattern.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from pkcs11_check import fixtures
from pkcs11_check.core.loader import P11Module
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_DEVICE_ERROR,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_SESSION_HANDLE_INVALID,
)


class _ReinitRaw:
    """Fake raw that records C_Finalize/C_Initialize and returns CKR_OK."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def C_Finalize(self, _arg: Any) -> int:  # noqa: N802
        self.calls.append("C_Finalize")
        return CKR_OK

    def C_Initialize(self, _arg: Any) -> int:  # noqa: N802
        self.calls.append("C_Initialize")
        return CKR_OK


class _FakeModule:
    """Minimal stand-in for P11Module: counts reinitialize() calls."""

    def __init__(self) -> None:
        self.reinit_count = 0

    def reinitialize(self) -> None:
        self.reinit_count += 1


def _spy_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the backoff sleep with a recorder; returns the list of delays."""
    delays: list[float] = []
    monkeypatch.setattr(fixtures.time, "sleep", lambda d: delays.append(d))
    return delays


def _restart_then_ok(fail_times: int, rv: int) -> Any:
    """Build a fake _open_raw_session: raise ``rv`` for the first ``fail_times``
    calls, then succeed. Tracks call count on the returned function's ``.calls``."""

    state = {"n": 0}

    def fake_open(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        state["n"] += 1
        if state["n"] <= fail_times:
            raise CkrAssertionError("restart in progress", int(rv))
        return ("raw", 7, 0, True)

    fake_open.calls = state  # type: ignore[attr-defined]
    return fake_open


# --------------------------------------------------------------------------
# loader.reinitialize -- unchanged behavior
# --------------------------------------------------------------------------


def test_module_reinitialize_finalizes_then_initializes() -> None:
    raw = _ReinitRaw()
    module = P11Module(path=Path("x.so"), _raw=raw)  # type: ignore[arg-type]
    assert module.reinit_count == 0

    module.reinitialize()

    # Finalize first to drop any stale "initialized" belief, then re-init.
    assert raw.calls == ["C_Finalize", "C_Initialize"]
    assert module.reinit_count == 1


def test_module_reinitialize_surfaces_finalize_access_violation() -> None:
    class _Raw(_ReinitRaw):
        def C_Finalize(self, _arg: Any) -> int:  # noqa: N802
            raise OSError("exception: access violation reading 0x0")

    module = P11Module(path=Path("x.so"), _raw=_Raw())  # type: ignore[arg-type]

    with pytest.raises(OSError, match="access violation"):
        module.reinitialize()

    assert module.reinit_count == 0


# --------------------------------------------------------------------------
# clean path -- no reinit, no latency
# --------------------------------------------------------------------------


def test_open_or_reinit_no_reinit_on_clean_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fixtures, "_open_raw_session", lambda _m, _c: ("raw", 1, 0, True))
    delays = _spy_sleep(monkeypatch)
    module = _FakeModule()

    assert fixtures._open_or_reinit(module, None) == ("raw", 1, 0, True)
    assert module.reinit_count == 0
    assert delays == []  # clean path never sleeps (zero added latency)


# --------------------------------------------------------------------------
# single-attempt recovery on each restart-signature code
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rv",
    [CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_SESSION_HANDLE_INVALID],
)
def test_open_or_reinit_recovers_on_restart_signature(
    monkeypatch: pytest.MonkeyPatch, rv: Any
) -> None:
    fake_open = _restart_then_ok(fail_times=1, rv=int(rv))
    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.warns(UserWarning, match="reconnect|re-initialized"):
        result = fixtures._open_or_reinit(module, None)

    assert result == ("raw", 7, 0, True)
    assert fake_open.calls["n"] == 2  # type: ignore[attr-defined]  # failed once, then retried
    assert module.reinit_count == 1


def test_open_or_reinit_does_not_retry_general_error_on_initial_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_open = _restart_then_ok(fail_times=1, rv=int(CKR_GENERAL_ERROR))
    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    delays = _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.raises(CkrAssertionError):
        fixtures._open_or_reinit(module, None)

    assert fake_open.calls["n"] == 1  # type: ignore[attr-defined]
    assert module.reinit_count == 0
    assert delays == []


def test_open_or_reinit_recovers_general_error_when_reopen_allows_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_open = _restart_then_ok(fail_times=1, rv=int(CKR_GENERAL_ERROR))
    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.warns(UserWarning, match="reconnect|re-initialized"):
        result = fixtures._open_or_reinit(
            module,
            None,
            recover_ambiguous_bootstrap_general_error=True,
        )

    assert result == ("raw", 7, 0, True)
    assert fake_open.calls["n"] == 2  # type: ignore[attr-defined]
    assert module.reinit_count == 1


def test_module_session_holder_allows_general_error_recovery_only_after_existing_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Raw:
        call_log: dict[str, int] = {}

        def C_GetSessionInfo(self, *_args: Any) -> int:  # noqa: N802
            return CKR_GENERAL_ERROR

    class _Mod:
        raw = _Raw()

    recover_flags: list[bool] = []

    def fake_open(
        _module: Any,
        _config: Any,
        *,
        recover_ambiguous_bootstrap_general_error: bool = False,
    ) -> tuple[Any, int, int, bool]:
        recover_flags.append(recover_ambiguous_bootstrap_general_error)
        return (_module.raw, 9, 0, False)

    monkeypatch.setattr(fixtures, "_open_or_reinit", fake_open)
    holder = fixtures._ModuleSessionHolder(_Mod(), object())  # type: ignore[arg-type]

    holder.get_session()
    holder.get_session()

    assert recover_flags == [False, True]


# --------------------------------------------------------------------------
# multi-attempt wait loop -- the core fix (a real restart takes seconds)
# --------------------------------------------------------------------------


def test_open_or_reinit_waits_across_multi_attempt_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Provider stays down for 3 reconnect attempts, then proxy-ng restores access.
    fake_open = _restart_then_ok(fail_times=3, rv=int(CKR_CRYPTOKI_NOT_INITIALIZED))
    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.warns(UserWarning):
        result = fixtures._open_or_reinit(module, None)

    assert result == ("raw", 7, 0, True)
    assert fake_open.calls["n"] == 4  # type: ignore[attr-defined]  # 3 failures bridged
    assert module.reinit_count == 3  # one reconnect per failed loop attempt


def test_open_or_reinit_backoff_is_capped_and_non_decreasing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_open = _restart_then_ok(fail_times=4, rv=int(CKR_DEVICE_ERROR))
    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    delays = _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.warns(UserWarning):
        fixtures._open_or_reinit(module, None)

    assert delays, "expected backoff sleeps between reconnect attempts"
    assert delays[0] == pytest.approx(fixtures._RECONNECT_INITIAL_DELAY_S)
    assert delays == sorted(delays)  # non-decreasing
    assert all(d <= fixtures._RECONNECT_MAX_DELAY_S for d in delays)  # capped


# --------------------------------------------------------------------------
# bounded give-up -- never an infinite loop, surfaces the finding
# --------------------------------------------------------------------------


def test_open_or_reinit_gives_up_after_bounded_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A provider that never returns -> propagate after a bounded number of
    attempts (no infinite loop). The real CKR is re-raised (finding, not hidden)."""

    def always_down(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        raise CkrAssertionError("still lost", int(CKR_CRYPTOKI_NOT_INITIALIZED))

    monkeypatch.setattr(fixtures, "_open_raw_session", always_down)
    monkeypatch.setattr(fixtures, "_RECONNECT_MAX_ATTEMPTS", 3)
    _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.raises(CkrAssertionError):
        fixtures._open_or_reinit(module, None)
    assert module.reinit_count == 3  # bounded by the attempt budget


# --------------------------------------------------------------------------
# genuine non-restart errors propagate immediately (no recovery, no wait)
# --------------------------------------------------------------------------


def test_open_or_reinit_propagates_non_restart_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_open(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        raise CkrAssertionError("bad pin", int(CKR_PIN_INCORRECT))

    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    delays = _spy_sleep(monkeypatch)
    module = _FakeModule()

    with pytest.raises(CkrAssertionError):
        fixtures._open_or_reinit(module, None)
    assert module.reinit_count == 0  # a clean auth error is not a restart signature
    assert delays == []  # no wait for a non-restart error
