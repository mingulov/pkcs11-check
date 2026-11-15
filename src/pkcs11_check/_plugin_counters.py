"""Per-test call-counter windows and the session CallCountersReport (fw#73).

Registered from ``plugin.py::pytest_configure`` as a separate pluggy plugin so the
phase attribution stays out of the main plugin module. Every hook starts with the
``p11_module``-absent guard and the testcase-item guard, so meta-test runs
(no ``--p11-module``) pass every hook through untouched and their report streams
stay byte-identical to before this feature.

Phase attribution: the setup wrapper snapshots a baseline and pushes the
``setup_teardown`` bucket; the call wrapper pushes ``test``; the teardown wrapper
pushes ``setup_teardown`` again and, once the phase is over, diffs baseline to
now and stashes the per-test entry. The makereport wrapper attaches the stashed
entry to the teardown report (setup/call reports are emitted before the entry
exists, so they always no-op). Buckets always balance: every push is a
``counted_bucket`` context manager (try/finally), and the teardown diff lives in
an outer finally so a failing teardown still yields an entry.

The item-stash keys below are private to this module (no other module reads or
writes them); shared keys keep their single home in ``_plugin_state``.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from pkcs11_check._plugin_state import _is_testcase_item
from pkcs11_check.core.call_counters import (
    CALL_COUNTERS_PROPERTY,
    CALL_COUNTERS_REPORT_TYPE,
    ISOLATION_ENV,
    Snapshot,
    counted_bucket,
    diff_snapshots,
    probes_lost,
    serialize_current,
    take_snapshot,
)

_BASELINE_KEY: pytest.StashKey[Snapshot] = pytest.StashKey()
_ENTRY_KEY: pytest.StashKey[dict[str, Any]] = pytest.StashKey()


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
    with counted_bucket("setup_teardown"):
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
    with counted_bucket("test"):
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
        with counted_bucket("setup_teardown"):
            result = yield
            return result
    finally:
        baseline = item.stash.get(_BASELINE_KEY, None)
        if baseline is not None:
            entry: dict[str, Any] = {"pid": os.getpid()}
            entry.update(diff_snapshots(baseline, take_snapshot()))
            item.stash[_ENTRY_KEY] = entry


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


def build_session_record() -> dict[str, Any]:
    """Build the session CallCountersReport record from the global counters.

    Carries ``probes_lost`` only (there is no ``probes_completed`` field).
    """
    record: dict[str, Any] = {
        "$report_type": CALL_COUNTERS_REPORT_TYPE,
        "pid": os.getpid(),
        "isolation": os.environ.get(ISOLATION_ENV, "unknown"),
        "probes_lost": probes_lost(),
    }
    record.update(serialize_current())
    return record


def emit_session_record(config: pytest.Config) -> None:
    """Write one CallCountersReport record via the report-log plugin when present."""
    report_log_plugin = getattr(config, "_report_log_plugin", None)
    if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
        report_log_plugin._write_json_data(build_session_record())
