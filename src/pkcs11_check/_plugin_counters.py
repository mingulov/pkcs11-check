"""Per-test call-counter windows and the session CallCountersReport (fw#73).

Registered from ``plugin.py::pytest_configure`` as a separate pluggy plugin so the
phase attribution stays out of the main plugin module. Every hook starts with the
``p11_module``-absent guard and the testcase-item guard, so meta-test runs
(no ``--p11-module``) pass every hook through untouched and their report streams
stay byte-identical to before this feature.

Phase attribution: the setup wrapper snapshots a baseline and sets the
``setup_teardown`` phase; the call wrapper sets ``test``; the teardown wrapper
sets ``setup_teardown`` again and, once the phase is over, diffs baseline to
now and stashes the per-test entry. The makereport wrapper attaches the stashed
entry to the teardown report (setup/call reports are emitted before the entry
exists, so they always no-op). Phases always restore: every set is a
``_phase`` context manager (try/finally), and the teardown diff lives in
an outer finally so a failing teardown still yields an entry.

The item-stash keys below are private to this module (no other module reads or
writes them); shared keys keep their single home in ``_plugin_state``.
"""

from __future__ import annotations

import os
import warnings
from typing import Any

import pytest

from pkcs11_check._plugin_state import _is_testcase_item
from pkcs11_check.core.call_counters import (
    CALL_COUNTERS_PROPERTY,
    CALL_COUNTERS_REPORT_TYPE,
    ISOLATION_ENV,
    RUN_ID_ENV,
    CounterPersistenceError,
    Snapshot,
    _phase,
    current_consumed,
    current_receipts,
    diff_snapshots,
    flush_counters,
    get_worker_uuid,
    lost_probe_keys,
    pending_marker,
    probes_lost,
    publish_test_window,
    serialize_current,
    take_snapshot,
)

_BASELINE_KEY: pytest.StashKey[Snapshot] = pytest.StashKey()
_ENTRY_KEY: pytest.StashKey[dict[str, Any]] = pytest.StashKey()
_RECEIPTS_MARK_KEY: pytest.StashKey[frozenset[tuple[str, int]]] = pytest.StashKey()
_CONSUMED_MARK_KEY: pytest.StashKey[frozenset[tuple[str, int]]] = pytest.StashKey()


# Note on the wrapper protocol: pluggy replaces the hook outcome with a
# new-style wrapper's return value, so every path below returns exactly what it
# received (`result = yield ... return result`). Falling off the end would
# replace the outcome with None (fatal for the firstresult makereport hook).


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> Any:
    """Snapshot the counter baseline and attribute setup-phase calls."""
    if item.config.getoption("p11_module", default=None) is None:
        result = yield
        return result
    if not _is_testcase_item(item):
        result = yield
        return result
    item.stash[_BASELINE_KEY] = take_snapshot()
    item.stash[_RECEIPTS_MARK_KEY] = frozenset(
        (receipt["worker_uuid"], receipt["probe_seq"]) for receipt in current_receipts()
    )
    item.stash[_CONSUMED_MARK_KEY] = frozenset(
        (proof["worker_uuid"], proof["probe_seq"]) for proof in current_consumed()
    )
    with _phase("setup_teardown"):
        result = yield
        return result


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_call(item: pytest.Item) -> Any:
    """Attribute test-body calls to the ``test`` bucket."""
    if item.config.getoption("p11_module", default=None) is None:
        result = yield
        return result
    if not _is_testcase_item(item):
        result = yield
        return result
    with _phase("test"):
        result = yield
        return result


@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> Any:
    """Attribute teardown-phase calls, then stash the per-test window entry.

    The diff runs in a finally so a skipped/failed setup or a raising teardown
    still yields an entry (setup-only when the call phase never ran).
    """
    if item.config.getoption("p11_module", default=None) is None:
        result = yield
        return result
    if not _is_testcase_item(item):
        result = yield
        return result
    try:
        with _phase("setup_teardown"):
            result = yield
            return result
    finally:
        baseline = item.stash.get(_BASELINE_KEY, None)
        if baseline is not None:
            entry: dict[str, Any] = {"pid": os.getpid(), "worker_uuid": get_worker_uuid()}
            # Isolation stamp (rc2 Task 5): crash-fallback rows inherit
            # this; entries without it (bare pytest) read as "unknown".
            entry["isolation"] = os.environ.get(ISOLATION_ENV, "unknown")
            run_id = os.environ.get(RUN_ID_ENV)
            if run_id is not None:
                entry["run_id"] = run_id
            mark = item.stash.get(_RECEIPTS_MARK_KEY, frozenset())
            window_receipts = sorted(
                {(receipt["worker_uuid"], receipt["probe_seq"]) for receipt in current_receipts()}
                - set(mark)
            )
            if window_receipts:
                entry["receipts"] = [
                    {"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in window_receipts
                ]
            consumed_mark = item.stash.get(_CONSUMED_MARK_KEY, frozenset())
            window_consumed = sorted(
                {(proof["worker_uuid"], proof["probe_seq"]) for proof in current_consumed()}
                - set(consumed_mark)
            )
            if window_consumed:
                # Anti-double-fold proofs for fallback absorptions in
                # this window (codex RC4-R3): collection claims them
                # before orphan adoption, so an entry that survives a
                # failed journal publish still suppresses the retained
                # orphan. Never read by the extractor: no rows earned.
                entry["consumed_probes"] = [
                    {"worker_uuid": uuid, "probe_seq": seq} for uuid, seq in window_consumed
                ]
            entry.update(diff_snapshots(baseline, take_snapshot()))
            item.stash[_ENTRY_KEY] = entry
            _publish_window_best_effort(item.nodeid, entry)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Any:
    """Attach the stashed per-test entry to the report before serialization."""
    if item.config.getoption("p11_module", default=None) is None:
        result = yield
        return result
    if not _is_testcase_item(item):
        result = yield
        return result
    report = yield
    attach_call_counters(item, report)
    return report


def attach_call_counters(item: pytest.Item, report: Any) -> None:
    """Attach the stashed per-test counter entry to ``report``.

    Mirrors ``_attach_rv_trace_to_report``: called at makereport time, no-op when
    the entry is absent (setup/call reports, whose phase predates the
    teardown-post computation) or empty (no calls in the window). The guards
    live in the hooks -- an entry can only exist when they passed.
    """
    user_properties = getattr(report, "user_properties", None)
    if not isinstance(user_properties, list):
        return
    entry = item.stash.get(_ENTRY_KEY, None)
    if not entry or not entry.get("total_calls"):
        return
    if not any(name == CALL_COUNTERS_PROPERTY for name, _ in user_properties):
        user_properties.append((CALL_COUNTERS_PROPERTY, entry))


def _publish_window_best_effort(nodeid: str, entry: dict[str, Any]) -> None:
    """Publish one test window to the durability journal (loud, never fatal).

    A persistence failure warns (it cannot fail the test: verdicts stay
    untouched by counter plumbing); the unrecovered tail is named by the
    collector's lost record instead. No-op when disengaged.
    """
    block = {"total_calls": entry["total_calls"], "by_module": entry["by_module"]}
    try:
        publish_test_window(nodeid, block)
    except CounterPersistenceError as exc:
        warnings.warn(f"call-counter publish failed for {nodeid}: {exc}", UserWarning, stacklevel=3)


def build_session_record() -> dict[str, Any]:
    """Build the session CallCountersReport record from the global counters.

    Carries ``probes_lost`` only (there is no ``probes_completed`` field)
    plus the process ``worker_uuid`` and the folded-probe ``receipts``
    (omitted when empty); counters serialize module-first. A surviving
    pending-persistence marker rides as ``persistence_pending`` (omitted
    when clear); the extractor reads it as counter-specific incomplete.
    Keyed losses ride as ``lost_keys`` (omitted when empty).
    """
    record: dict[str, Any] = {
        "$report_type": CALL_COUNTERS_REPORT_TYPE,
        "pid": os.getpid(),
        "worker_uuid": get_worker_uuid(),
        "isolation": os.environ.get(ISOLATION_ENV, "unknown"),
        "probes_lost": probes_lost(),
    }
    marker = pending_marker()
    if marker is not None:
        record["persistence_pending"] = marker
    keys = lost_probe_keys()
    if keys:
        record["lost_keys"] = keys
    # Per-round attribution: the CLI seeds one run_id per invocation; direct
    # pytest runs have no seed, so the key is omitted (never null) and the
    # extractor folds such records into the implicit "" round.
    run_id = os.environ.get(RUN_ID_ENV)
    if run_id is not None:
        record["run_id"] = run_id
    receipts = current_receipts()
    if receipts:
        record["receipts"] = receipts
    record.update(serialize_current())
    return record


def emit_session_record(config: pytest.Config) -> None:
    """Write one CallCountersReport record via the report-log plugin when present.

    Boundary-flushes first (best effort, warns on persistence failure), so
    the sidecar carries the final in-progress snapshot even when the
    report-log write itself is lost.
    """
    try:
        flush_counters()
    except CounterPersistenceError as exc:
        warnings.warn(f"call-counter session flush failed: {exc}", UserWarning, stacklevel=2)
    report_log_plugin = getattr(config, "_report_log_plugin", None)
    if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
        report_log_plugin._write_json_data(build_session_record())
