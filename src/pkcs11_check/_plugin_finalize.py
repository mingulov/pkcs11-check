"""Teardown-time finalization for the pytest plugin: bounded module finalize and
the provisioning report builder.

Moved verbatim from plugin.py (god-module split, 2026-07-17); hooks stay in plugin.py.
"""

from __future__ import annotations

import signal
import threading
from collections import Counter
from typing import Any

import pytest

from pkcs11_check._plugin_report_attach import (
    _RV_TRACE_RAW_SOURCES as _RV_TRACE_RAW_SOURCES,
)
from pkcs11_check._plugin_report_attach import (
    _accumulate_module_session_health_metrics as _accumulate_module_session_health_metrics,
)
from pkcs11_check._plugin_report_attach import (
    _append_missing_compliance_notes as _append_missing_compliance_notes,
)
from pkcs11_check._plugin_report_attach import (
    _append_missing_rv_trace as _append_missing_rv_trace,
)
from pkcs11_check._plugin_report_attach import (
    _attach_claimed_op_to_report as _attach_claimed_op_to_report,
)
from pkcs11_check._plugin_report_attach import (
    _attach_classification_to_report as _attach_classification_to_report,
)
from pkcs11_check._plugin_report_attach import (
    _attach_compliance_notes_to_report as _attach_compliance_notes_to_report,
)
from pkcs11_check._plugin_report_attach import (
    _attach_rv_trace_to_report as _attach_rv_trace_to_report,
)
from pkcs11_check._plugin_report_attach import (
    _convert_missing_function_to_skip as _convert_missing_function_to_skip,
)
from pkcs11_check._plugin_report_attach import (
    _drain_rv_trace as _drain_rv_trace,
)
from pkcs11_check._plugin_report_attach import (
    _is_previous_item_setup_failure as _is_previous_item_setup_failure,
)
from pkcs11_check._plugin_report_attach import (
    _last_rv_trace as _last_rv_trace,
)
from pkcs11_check._plugin_report_attach import (
    _nonempty_rv_trace_from_props as _nonempty_rv_trace_from_props,
)
from pkcs11_check._plugin_report_attach import (
    _remember_module_session_call_outcome as _remember_module_session_call_outcome,
)
from pkcs11_check._plugin_report_attach import (
    _remember_rv_trace as _remember_rv_trace,
)
from pkcs11_check._plugin_report_attach import (
    _report_is_fail_or_xfail as _report_is_fail_or_xfail,
)
from pkcs11_check._plugin_report_attach import (
    _report_needs_rv_trace as _report_needs_rv_trace,
)
from pkcs11_check._plugin_report_attach import (
    _report_text as _report_text,
)
from pkcs11_check._plugin_report_attach import (
    _rv_trace_properties as _rv_trace_properties,
)
from pkcs11_check._plugin_report_attach import (
    _rv_trace_properties_from_previous_failure as _rv_trace_properties_from_previous_failure,
)
from pkcs11_check._plugin_report_attach import (
    _rv_trace_properties_from_report as _rv_trace_properties_from_report,
)
from pkcs11_check._plugin_report_attach import (
    _synthetic_unclassified_record as _synthetic_unclassified_record,
)
from pkcs11_check._plugin_selection import (
    _build_one_stacked_string as _build_one_stacked_string,
)
from pkcs11_check._plugin_selection import (
    _build_stacked_strings as _build_stacked_strings,
)
from pkcs11_check._plugin_selection import (
    _ensure_manifest as _ensure_manifest,
)
from pkcs11_check._plugin_selection import (
    _ensure_mechanism_catalog as _ensure_mechanism_catalog,
)
from pkcs11_check._plugin_selection import (
    _manifest_failure_message as _manifest_failure_message,
)
from pkcs11_check._plugin_selection import (
    _mechanism_rv_state_names as _mechanism_rv_state_names,
)
from pkcs11_check._plugin_selection import (
    _name_set as _name_set,
)
from pkcs11_check._plugin_selection import (
    _record_selection_decision as _record_selection_decision,
)
from pkcs11_check._plugin_selection import (
    _reported_names_for_mechanism as _reported_names_for_mechanism,
)
from pkcs11_check._plugin_selection import (
    _runtime_skip_reason as _runtime_skip_reason,
)
from pkcs11_check._plugin_selection import (
    _selected_entries_for_scenario as _selected_entries_for_scenario,
)
from pkcs11_check._plugin_selection import (
    _selection_param_cache as _selection_param_cache,
)
from pkcs11_check._plugin_selection import (
    _selection_state_names as _selection_state_names,
)
from pkcs11_check._plugin_selection import (
    _selection_telemetry_store as _selection_telemetry_store,
)
from pkcs11_check._plugin_selection import (
    _serialize_selection_telemetry as _serialize_selection_telemetry,
)
from pkcs11_check._plugin_state import (
    _BOOTSTRAP_COLLECTED as _BOOTSTRAP_COLLECTED,
)
from pkcs11_check._plugin_state import (
    _BOOTSTRAP_FUNCTION_COUNTS as _BOOTSTRAP_FUNCTION_COUNTS,
)
from pkcs11_check._plugin_state import (
    _COVERAGE_DATA as _COVERAGE_DATA,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_DETAIL_COUNTS as _CUMULATIVE_DETAIL_COUNTS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_FUNCTION_COUNTS as _CUMULATIVE_FUNCTION_COUNTS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_FUNCTION_OK_COUNTS as _CUMULATIVE_FUNCTION_OK_COUNTS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_FUNCTIONS as _CUMULATIVE_FUNCTIONS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_MECHANISM_COUNTS as _CUMULATIVE_MECHANISM_COUNTS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_MECHANISM_DETAILS as _CUMULATIVE_MECHANISM_DETAILS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_MECHANISMS as _CUMULATIVE_MECHANISMS,
)
from pkcs11_check._plugin_state import (
    _CUMULATIVE_USED_MECHANISMS as _CUMULATIVE_USED_MECHANISMS,
)
from pkcs11_check._plugin_state import (
    _LAST_RV_TRACE as _LAST_RV_TRACE,
)
from pkcs11_check._plugin_state import (
    _MANIFEST_KEY as _MANIFEST_KEY,
)
from pkcs11_check._plugin_state import (
    _MECHANISM_CATALOG_KEY as _MECHANISM_CATALOG_KEY,
)
from pkcs11_check._plugin_state import (
    _MODULE_SESSION_HEALTH_METRICS as _MODULE_SESSION_HEALTH_METRICS,
)
from pkcs11_check._plugin_state import (
    _P11_MODULE as _P11_MODULE,
)
from pkcs11_check._plugin_state import (
    _PROVISIONING_COUNTS as _PROVISIONING_COUNTS,
)
from pkcs11_check._plugin_state import (
    _RAW_INSTANCE as _RAW_INSTANCE,
)
from pkcs11_check._plugin_state import (
    _SELECTION_PARAM_CACHE_KEY as _SELECTION_PARAM_CACHE_KEY,
)
from pkcs11_check._plugin_state import (
    _SELECTION_TELEMETRY_KEY as _SELECTION_TELEMETRY_KEY,
)
from pkcs11_check._plugin_state import (
    _TEARDOWN_FINALIZED as _TEARDOWN_FINALIZED,
)
from pkcs11_check._plugin_state import (
    _has_dynamic_markers as _has_dynamic_markers,
)
from pkcs11_check._plugin_state import (
    _is_testcase_item as _is_testcase_item,
)

# Re-export fixtures so pytest discovers them
from pkcs11_check.fixtures import (  # noqa: F401
    MODULE_SESSION_CALL_FAILED_ATTR,
    RawSession,
    _p11_module_session_holder,
    p11_config,
    p11_interface_version,
    p11_module,
    p11_module_session,
    p11_raw_session,
    p11_session,
)
from pkcs11_check.raw.types_std import (
    CKR_OK,
)

# Bounded budget (seconds) for the normal-teardown C_Finalize.
# The SIGALRM watchdog bounds a *Python-level* hang (e.g. a spin-wait in a
# ctypes callback or a Python-side stall that yields to the eval loop).  It
# does NOT interrupt a module stuck inside native C code: SIGALRM only
# delivers to the CPython eval loop, so pure-C hangs inside the C_Finalize
# dlsym are backstopped by the outer per-file subprocess deadline instead.
_TEARDOWN_FINALIZE_TIMEOUT_S = 5


class _TeardownFinalizeTimeoutError(Exception):
    """Raised by the SIGALRM watchdog when a teardown C_Finalize overruns."""


def _finalize_on_teardown(config: pytest.Config, raw: Any) -> None:
    """Call ``C_Finalize`` once on normal per-process teardown.

    Runs at ``pytest_sessionfinish`` -- AFTER every test outcome and the
    coverage report are already recorded -- so it CANNOT change any test's
    verdict (segfault-survival model). A non-OK rv, an exception, or a hang is
    *recorded* via an additive ``TeardownFinalize`` report-log record, never via
    ``classify()`` / ``pytest.fail`` / ``pytest.xfail`` (no false-accusation of
    a compliant provider) and never silently swallowed (no hidden finding).

    Mirrors the best-effort shape of ``P11Module.reinitialize()``
    (``core/loader.py``). A Python-level hang (spin-wait in a ctypes callback
    or any stall that yields to the CPython eval loop) is bounded by a SIGALRM
    watchdog (``_TEARDOWN_FINALIZE_TIMEOUT_S``).  A module stuck *inside* native
    C code is NOT interrupted by SIGALRM -- that is backstopped by the outer
    per-file subprocess deadline.  On platforms without ``SIGALRM`` the call
    runs unguarded-for-hang (still guarded for rv / raise).
    """
    from pkcs11_check.raw.rv import ckr_name

    # Idempotency: at most one normal-teardown finalize per process.
    if config.stash.get(_TEARDOWN_FINALIZED, False):
        return
    config.stash[_TEARDOWN_FINALIZED] = True

    module = config.stash.get(_P11_MODULE, None)
    reinit_count = getattr(module, "reinit_count", None)

    outcome = "ok"
    rv: int | None = None
    rv_name: str | None = None
    error: str | None = None

    # SIGALRM watchdog: POSIX-only, and signal.signal/setitimer only work on the
    # main thread. Off the main thread or on a SIGALRM-less platform, the call
    # runs unguarded-for-hang (still guarded for non-OK rv and for any raise).
    use_watchdog = hasattr(signal, "SIGALRM") and (
        threading.current_thread() is threading.main_thread()
    )
    previous_handler: Any = None
    # Saved return value of setitimer when we arm the watchdog; used in
    # finally to *restore* any pre-existing ITIMER_REAL rather than zero it.
    old_timer: tuple[float, float] | None = None

    def _on_alarm(_signum: int, _frame: Any) -> None:
        raise _TeardownFinalizeTimeoutError

    try:
        if use_watchdog:
            previous_handler = signal.signal(signal.SIGALRM, _on_alarm)
            # setitimer returns (old_value, old_interval); capture to restore.
            old_timer = signal.setitimer(signal.ITIMER_REAL, float(_TEARDOWN_FINALIZE_TIMEOUT_S))
        rv_int = int(raw.C_Finalize(None))
        rv = rv_int
        rv_name = ckr_name(rv_int)
        if rv_int != int(CKR_OK):
            outcome = "error"
    except _TeardownFinalizeTimeoutError:
        outcome = "timeout"
        error = f"C_Finalize exceeded {_TEARDOWN_FINALIZE_TIMEOUT_S}s teardown budget"
    except Exception as exc:  # noqa: BLE001
        # Best-effort teardown (mirrors P11Module.reinitialize): a non-OK rv is
        # handled above; any raise -- AttributeError / OSError /
        # ctypes.ArgumentError / a module-specific ctypes fault -- is recorded
        # here with its exact text, never propagated (it would abort report
        # writing) and never turned into a test verdict.
        outcome = "error"
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if use_watchdog and old_timer is not None:
            # Restore the previous timer (value, interval), not unconditionally
            # zero -- cancelling an outer ITIMER_REAL would be a silent hazard.
            signal.setitimer(signal.ITIMER_REAL, *old_timer)
            if previous_handler is not None:
                signal.signal(signal.SIGALRM, previous_handler)

    record: dict[str, Any] = {
        "$report_type": "TeardownFinalize",
        "outcome": outcome,
        "rv": rv,
        "rv_name": rv_name,
        "reinit_count": reinit_count,
    }
    if error is not None:
        record["error"] = error

    report_log_plugin = getattr(config, "_report_log_plugin", None)
    if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
        report_log_plugin._write_json_data(record)


def _build_provisioning_report(counts: Counter[tuple[str, str]]) -> dict[str, Any]:
    """Build the ProvisioningReport payload from a per-(obj_class, method) counter.

    Pure function — no I/O, fully unit-testable.
    """
    by_class: dict[str, dict[str, int]] = {}
    for (obj_class, method), n in counts.items():
        by_class.setdefault(obj_class, {})[method] = n
    methods = ("ran_via_create", "ran_via_unwrap", "ran_via_external", "skipped_no_path")
    totals = {m: sum(c.get(m, 0) for c in by_class.values()) for m in methods}
    return {"by_class": by_class, "totals": totals}
