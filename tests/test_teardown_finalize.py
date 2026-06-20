"""Normal-teardown ``C_Finalize`` for the pkcs11-check pytest plugin.

The framework initializes the library exactly once (the session-scoped
``p11_module`` fixture is a plain ``return``, so pytest has no teardown phase
for it) and historically never finalized it on a normal run -- only the
crash-recovery ``reinitialize()`` path ever called ``C_Finalize``. That leaks
per-process resources on stateful shared backends (a wolfTPM fwTPM leaks one
SRK transient object per file).

The fix adds a ``C_Finalize`` step to ``pytest_sessionfinish`` -- the unique
seam that fires once per process, after every test outcome is recorded, on both
pass and fail paths, in both isolation modes. It runs AFTER the coverage
emission and is fully guarded (non-OK rv / exception / hang) so a misbehaving
``C_Finalize`` can never change the run's pass/fail verdict and is never hidden:
the outcome is recorded via an additive ``TeardownFinalize`` report-log record,
never via ``classify()`` / ``pytest.fail`` / ``pytest.xfail``.

These are hermetic, in-process meta-tests driving ``pytest_sessionfinish`` with
a counting spy raw (modeled on ``test_reinit_recovery.py``'s ``_ReinitRaw`` and
``test_plugin.py``'s ``pytest_sessionfinish`` drivers). No real module is
loaded.
"""

from __future__ import annotations

import signal
import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

import pkcs11_check.plugin as plugin_mod
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_OK

_HAS_SIGALRM = getattr(signal, "SIGALRM", None) is not None


class _SpyRaw:
    """Counting spy raw: records C_Finalize calls + serves the coverage reads.

    ``finalize_rv`` is the rv ``C_Finalize`` returns; ``raises`` (if set) is
    raised instead; ``block`` (if set) is an Event the call waits on, standing
    in for a hung module so the watchdog can abandon it.
    """

    def __init__(
        self,
        *,
        finalize_rv: int = CKR_OK,
        raises: BaseException | None = None,
        block: threading.Event | None = None,
    ) -> None:
        self.calls: list[str] = []
        self.finalized = False
        self._finalize_rv = finalize_rv
        self._raises = raises
        self._block = block
        # Coverage-block reads (pytest_sessionfinish touches these before
        # finalize); kept inert so the test isolates the finalize behavior.
        self.call_log: dict[str, int] = {}
        self.used_mechanisms: set[int] = set()
        self.mechanism_counts: dict[int, int] = {}
        self.mechanism_rv_counts: dict[int, dict[int, int]] = {}

    def available_function_names(self) -> set[str]:
        return set()

    def C_Finalize(self, _arg: Any) -> int:  # noqa: N802
        self.calls.append("C_Finalize")
        if self._block is not None:
            # Wait to be interrupted by the watchdog (or, as a safety net,
            # released by the test). A real hang never returns.
            self._block.wait(timeout=30.0)
        if self._raises is not None:
            raise self._raises
        self.finalized = True
        return self._finalize_rv


def _make_config(
    raw: _SpyRaw | None,
    report_log: Any,
    *,
    p11_module: object | None = "/tmp/module.so",
) -> SimpleNamespace:
    """Build a fake pytest config with the full coverage-emission stash.

    ``p11_module is None`` models a meta/no-module run (early return).
    ``raw is None`` models a run where no testcase ever populated ``_RAW_INSTANCE``.
    """

    stash: dict[Any, Any] = {
        plugin_mod._CUMULATIVE_FUNCTIONS: set(),
        plugin_mod._CUMULATIVE_MECHANISMS: set(),
        plugin_mod._CUMULATIVE_USED_MECHANISMS: set(),
        plugin_mod._CUMULATIVE_MECHANISM_DETAILS: set(),
        plugin_mod._CUMULATIVE_FUNCTION_COUNTS: {},
        plugin_mod._CUMULATIVE_MECHANISM_COUNTS: {},
        plugin_mod._CUMULATIVE_DETAIL_COUNTS: {},
        plugin_mod._BOOTSTRAP_FUNCTION_COUNTS: {},
        plugin_mod._SELECTION_TELEMETRY_KEY: {},
    }
    if raw is not None:
        stash[plugin_mod._RAW_INSTANCE] = raw
    return SimpleNamespace(
        stash=stash,
        getoption=lambda name, default=None: {"p11_module": p11_module}.get(name, default),
        _report_log_plugin=report_log,
    )


class _FakeReportLogPlugin:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def _write_json_data(self, payload: dict[str, object]) -> None:
        self.records.append(payload)


def _teardown_records(report_log: _FakeReportLogPlugin) -> list[dict[str, object]]:
    return [r for r in report_log.records if r.get("$report_type") == "TeardownFinalize"]


def _run(config: SimpleNamespace) -> None:
    # SimpleNamespace is intentional: hermetic fake; cast to satisfy Pyright.
    plugin_mod.pytest_sessionfinish(cast(pytest.Session, SimpleNamespace(config=config)), 0)


# --------------------------------------------------------------------------
# 1. Finalize happens exactly once, on the normal path, AFTER coverage.
# --------------------------------------------------------------------------


def test_finalize_called_once_on_clean_teardown() -> None:
    raw = _SpyRaw()
    report_log = _FakeReportLogPlugin()
    config = _make_config(raw, report_log)

    _run(config)

    assert raw.calls == ["C_Finalize"]  # exactly one finalize
    assert raw.finalized is True  # resource-release breadcrumb flipped
    # Ordered AFTER the coverage emission (CoverageReport precedes TeardownFinalize).
    types = [r.get("$report_type") for r in report_log.records]
    assert "CoverageReport" in types
    assert types.index("CoverageReport") < types.index("TeardownFinalize")

    records = _teardown_records(report_log)
    assert len(records) == 1
    assert records[0]["outcome"] == "ok"
    assert records[0]["rv"] == int(CKR_OK)
    assert records[0]["rv_name"] == "CKR_OK"


# --------------------------------------------------------------------------
# 2. Guard: non-OK rv is recorded, never raised / never a verdict.
# --------------------------------------------------------------------------


def test_non_ok_rv_recorded_not_raised() -> None:
    raw = _SpyRaw(finalize_rv=int(CKR_GENERAL_ERROR))
    report_log = _FakeReportLogPlugin()
    config = _make_config(raw, report_log)

    _run(config)  # must not raise

    records = _teardown_records(report_log)
    assert len(records) == 1
    assert records[0]["outcome"] == "error"
    assert records[0]["rv"] == int(CKR_GENERAL_ERROR)
    assert records[0]["rv_name"] == "CKR_GENERAL_ERROR"
    # No test-verdict channel was used (no classification/fail record).
    assert all(
        r.get("$report_type") not in ("Classification", "TestReport") for r in report_log.records
    )


# --------------------------------------------------------------------------
# 3. Guard: an exception from C_Finalize does not escape.
# --------------------------------------------------------------------------


def test_exception_swallowed_and_recorded() -> None:
    raw = _SpyRaw(raises=OSError("boom in C_Finalize"))
    report_log = _FakeReportLogPlugin()
    config = _make_config(raw, report_log)

    _run(config)  # must not raise

    records = _teardown_records(report_log)
    assert len(records) == 1
    assert records[0]["outcome"] == "error"
    # Exact error preserved in the record (framework rule: exact errors).
    assert "boom in C_Finalize" in str(records[0]["error"])


# --------------------------------------------------------------------------
# 4. Guard: a hang is bounded by the watchdog (recorded timeout, no escape).
# --------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_SIGALRM, reason="SIGALRM watchdog is POSIX-only")
def test_hang_is_bounded_and_recorded_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    block = threading.Event()
    raw = _SpyRaw(block=block)
    report_log = _FakeReportLogPlugin()
    config = _make_config(raw, report_log)
    # Tiny budget so the watchdog fires quickly.
    monkeypatch.setattr(plugin_mod, "_TEARDOWN_FINALIZE_TIMEOUT_S", 1)

    try:
        _run(config)  # must not hang past the budget, must not raise
    finally:
        block.set()  # safety net: never leave a stuck thread

    records = _teardown_records(report_log)
    assert len(records) == 1
    assert records[0]["outcome"] == "timeout"
    assert raw.finalized is False  # finalize was abandoned, not completed


# --------------------------------------------------------------------------
# 5. Idempotency: a second sessionfinish is a no-op (no double-finalize).
# --------------------------------------------------------------------------


def test_idempotent_no_double_finalize() -> None:
    raw = _SpyRaw()
    report_log = _FakeReportLogPlugin()
    config = _make_config(raw, report_log)

    _run(config)
    _run(config)

    assert raw.calls == ["C_Finalize"]  # still exactly one
    assert len(_teardown_records(report_log)) == 1


# --------------------------------------------------------------------------
# 6. Meta / no-module run: finalize is never attempted (early return).
# --------------------------------------------------------------------------


def test_meta_run_is_a_noop() -> None:
    report_log = _FakeReportLogPlugin()
    config = _make_config(None, report_log, p11_module=None)

    _run(config)

    assert report_log.records == []  # nothing emitted at all


# --------------------------------------------------------------------------
# 7. No raw stashed (no testcase ran): finalize is skipped, no crash.
# --------------------------------------------------------------------------


def test_no_raw_instance_is_a_noop() -> None:
    report_log = _FakeReportLogPlugin()
    config = _make_config(None, report_log)

    _run(config)  # must not raise

    # Coverage block early-returns when _RAW_INSTANCE is absent; no finalize.
    assert _teardown_records(report_log) == []
