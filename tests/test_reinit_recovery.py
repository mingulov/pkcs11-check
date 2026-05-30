"""Reactive recovery from a lost C_Initialize state (library de-initialized).

When a proxied PKCS#11 provider crashes and the proxy restarts, the loaded
client module survives but loses its init/connection context: subsequent calls
return ``CKR_CRYPTOKI_NOT_INITIALIZED`` until the library is re-initialized.
Recovery re-establishes it at the next session bootstrap (``C_Finalize``
best-effort + ``C_Initialize``), so one provider crash mid-file does not cascade
``CKR_CRYPTOKI_NOT_INITIALIZED`` onto every remaining test in that file.

The triggering test records its real result (recorded as-is); recovery is for
*subsequent* tests. The crash finding itself is captured by the triggering test
and the CK_RV trace; a warning + ``reinit_count`` surface how many restarts were
recovered (~one per provider crash). Mirrors the ``CKR_OPERATION_ACTIVE``
tiered-recovery pattern (``test_operation_active_recovery.py``).
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
    CKR_OK,
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


def test_module_reinitialize_finalizes_then_initializes() -> None:
    raw = _ReinitRaw()
    module = P11Module(path=Path("x.so"), _raw=raw)  # type: ignore[arg-type]
    assert module.reinit_count == 0

    module.reinitialize()

    # Finalize first to drop any stale "initialized" belief, then re-init.
    assert raw.calls == ["C_Finalize", "C_Initialize"]
    assert module.reinit_count == 1


def test_open_or_reinit_recovers_on_not_initialized(monkeypatch: pytest.MonkeyPatch) -> None:
    opens = {"n": 0}

    def fake_open(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        opens["n"] += 1
        if opens["n"] == 1:
            raise CkrAssertionError("lost init", int(CKR_CRYPTOKI_NOT_INITIALIZED))
        return ("raw", 7, 0, True)

    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    module = _FakeModule()

    with pytest.warns(UserWarning, match="re-initialized"):
        result = fixtures._open_or_reinit(module, None)

    assert result == ("raw", 7, 0, True)
    assert opens["n"] == 2  # retried once after the reinit
    assert module.reinit_count == 1


def test_open_or_reinit_propagates_other_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_open(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        raise CkrAssertionError("device error", int(CKR_DEVICE_ERROR))

    monkeypatch.setattr(fixtures, "_open_raw_session", fake_open)
    module = _FakeModule()

    with pytest.raises(CkrAssertionError):
        fixtures._open_or_reinit(module, None)
    assert module.reinit_count == 0  # only CKR_CRYPTOKI_NOT_INITIALIZED triggers reinit


def test_open_or_reinit_no_reinit_on_clean_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fixtures, "_open_raw_session", lambda _m, _c: ("raw", 1, 0, True))
    module = _FakeModule()
    assert fixtures._open_or_reinit(module, None) == ("raw", 1, 0, True)
    assert module.reinit_count == 0


def test_open_or_reinit_gives_up_after_one_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second NOT_INITIALIZED (reinit didn't help) propagates -- no infinite loop."""

    def always_not_init(_m: Any, _c: Any) -> tuple[str, int, int, bool]:
        raise CkrAssertionError("still lost", int(CKR_CRYPTOKI_NOT_INITIALIZED))

    monkeypatch.setattr(fixtures, "_open_raw_session", always_not_init)
    module = _FakeModule()

    with pytest.raises(CkrAssertionError):
        fixtures._open_or_reinit(module, None)
    assert module.reinit_count == 1  # attempted exactly once, then gave up
