"""Per-report attach machinery for the pytest plugin: rv-trace, claimed-op,
compliance notes, at-source classification, and module-session health metrics.

Moved verbatim from plugin.py (god-module split, 2026-07-17); hooks stay in plugin.py
and call these helpers in unchanged order from pytest_runtest_makereport/teardown.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

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
from pkcs11_check.core.nodeids import item_nodeid
from pkcs11_check.core.process_observation import drain_process_observations
from pkcs11_check.core.subprocess_trace import (
    drain_subprocess_rv_trace,
    extract_subprocess_rv_trace,
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

_RV_TRACE_RAW_SOURCES = ("p11_raw_session", "p11_session", "p11_module_session", "p11_module")


def _rv_trace_properties(item: pytest.Item) -> list[tuple[str, Any]]:
    """Return CK_RV trace user properties for ``item`` when tracing is enabled."""
    subprocess_trace = drain_subprocess_rv_trace()
    if subprocess_trace:
        return [("pkcs11_rv_trace", subprocess_trace)]

    funcargs = getattr(item, "funcargs", None)
    if not isinstance(funcargs, dict):
        return []
    for name in _RV_TRACE_RAW_SOURCES:
        raw = getattr(funcargs.get(name), "raw", None)
        if raw is None:
            continue
        if not getattr(raw, "rv_trace_enabled", False):
            return []
        props: list[tuple[str, Any]] = [("pkcs11_rv_trace", raw.rv_trace)]
        if raw.rv_trace_dropped:
            props.append(("pkcs11_rv_trace_dropped", raw.rv_trace_dropped))
        return props
    return []


def _append_missing_rv_trace(
    user_properties: list[tuple[str, Any]], trace_props: list[tuple[str, Any]]
) -> None:
    for name, value in trace_props:
        replaced = False
        for index, (existing_name, existing_value) in enumerate(user_properties):
            if existing_name != name:
                continue
            if existing_value in (None, "", [], {}) and value not in (None, "", [], {}):
                user_properties[index] = (name, value)
            replaced = True
            break
        if not replaced:
            user_properties.append((name, value))


def _nonempty_rv_trace_from_props(user_properties: Any) -> list[dict[str, Any]]:
    if not isinstance(user_properties, list):
        return []
    for name, value in user_properties:
        if name in ("pkcs11_rv_trace", "pkcs11_rv_trace_compact") and isinstance(value, list):
            trace = [entry for entry in value if isinstance(entry, dict)]
            if trace:
                return trace
    return []


def _last_rv_trace(item: pytest.Item) -> list[dict[str, Any]]:
    config = getattr(item, "config", None)
    stash = getattr(config, "stash", None)
    if stash is None:
        return []
    return cast("list[dict[str, Any]]", stash.get(_LAST_RV_TRACE, []))


def _remember_rv_trace(item: pytest.Item, report: Any) -> None:
    trace = _nonempty_rv_trace_from_props(getattr(report, "user_properties", None))
    if not trace:
        return
    config = getattr(item, "config", None)
    stash = getattr(config, "stash", None)
    if stash is not None:
        stash[_LAST_RV_TRACE] = trace


def _report_text(report: Any) -> str:
    longrepr = getattr(report, "longrepr", None)
    if isinstance(longrepr, dict):
        crash = longrepr.get("reprcrash")
        if isinstance(crash, dict):
            return str(crash.get("message", ""))
        return json.dumps(longrepr)
    return str(longrepr or "")


def _is_previous_item_setup_failure(report: Any) -> bool:
    return getattr(
        report, "when", None
    ) == "setup" and "previous item was not torn down properly" in _report_text(report)


def _rv_trace_properties_from_report(report: Any) -> list[tuple[str, Any]]:
    trace = extract_subprocess_rv_trace(_report_text(report))
    if not trace:
        return []
    return [("pkcs11_rv_trace", trace)]


def _rv_trace_properties_from_previous_failure(
    item: pytest.Item, report: Any
) -> list[tuple[str, Any]]:
    if not _is_previous_item_setup_failure(report):
        return []
    trace = _last_rv_trace(item)
    if not trace:
        return []
    return [("pkcs11_rv_trace", trace)]


def _attach_claimed_op_to_report(item: pytest.Item, report: Any) -> None:
    """Attach the test's claimed productive operation (pkcs11_claimed_op) to its PASSED call report.

    The hollow-pass oracle (quality_audit) groups PASSED records with ``when == "call"`` by this
    property. Attaching in teardown would land it on the *teardown* TestReport record instead
    (report-log writes a separate record per phase), which the collector never reads -- so the
    denominator would always be empty. So attach here, on the passed call report, mirroring
    _attach_rv_trace_to_report. The value comes from classification.current_claimed_op(), which is
    gated on set_mechanism(expect_success=True): a negative/rejection vector passes without a
    productive CKR_OK and must not be counted. No-op unless a productive claim was declared.
    """
    if getattr(report, "when", None) != "call" or getattr(report, "outcome", None) != "passed":
        return
    if not _is_testcase_item(item):
        return
    from pkcs11_check.classification import current_claimed_op

    op = current_claimed_op()
    if not op:
        return
    user_properties = getattr(report, "user_properties", None)
    if not isinstance(user_properties, list):
        return
    if not any(name == "pkcs11_claimed_op" for name, _ in user_properties):
        user_properties.append(("pkcs11_claimed_op", op))


def _drain_rv_trace(item: pytest.Item) -> None:
    """Attach the per-test CK_RV trace to ``item.user_properties`` when enabled.

    Independent of coverage draining (not gated on the coverage stash). The
    trace lands on the teardown TestReport record for successful tests; failed
    and xfail/xpass call reports get the same trace in ``pytest_runtest_makereport``.
    ``report.jsonl`` is byte-identical when tracing is off. See docs/rv-trace-design.md.
    """
    user_properties = getattr(item, "user_properties", None)
    if not isinstance(user_properties, list):
        return
    _append_missing_rv_trace(user_properties, _rv_trace_properties(item))


def _report_needs_rv_trace(report: Any) -> bool:
    return (
        getattr(report, "outcome", None) == "failed"
        or getattr(report, "wasxfail", None) is not None
    )


def _attach_process_observations_to_report(item: pytest.Item, report: Any) -> None:
    """Attach nested probe observations to the executing call report."""
    if getattr(report, "when", None) != "call":
        return
    user_properties = getattr(report, "user_properties", None)
    if not isinstance(user_properties, list):
        return
    observations = drain_process_observations()
    if not observations:
        return
    nodeid = getattr(report, "nodeid", None)
    enriched = []
    for observation in observations:
        copied = dict(observation)
        copied["parent_nodeid"] = nodeid
        enriched.append(copied)
    user_properties.append(("pkcs11_process_observations", enriched))


def _attach_rv_trace_to_report(item: pytest.Item, report: Any) -> None:
    """Attach CK_RV trace directly to failed/xfail reports before report-log writes them."""
    _attach_process_observations_to_report(item, report)
    if not _is_testcase_item(item) or not _report_needs_rv_trace(report):
        return
    user_properties = getattr(report, "user_properties", None)
    if not isinstance(user_properties, list):
        return
    trace_props = (
        _rv_trace_properties(item)
        or _rv_trace_properties_from_report(report)
        or _rv_trace_properties_from_previous_failure(item, report)
    )
    _append_missing_rv_trace(user_properties, trace_props)
    _remember_rv_trace(item, report)


def _append_missing_compliance_notes(
    user_properties: list[tuple[str, Any]], notes: list[dict[str, str]]
) -> None:
    if not notes:
        return
    for index, (existing_name, existing_value) in enumerate(user_properties):
        if existing_name != "pkcs11_compliance_notes":
            continue
        if isinstance(existing_value, list):
            existing_value.extend(notes)
        else:
            user_properties[index] = ("pkcs11_compliance_notes", notes)
        return
    user_properties.append(("pkcs11_compliance_notes", notes))


def _attach_compliance_notes_to_report(item: pytest.Item, report: Any) -> None:
    """Attach compliance notes to call reports before report-log serializes them."""
    if not _is_testcase_item(item) or getattr(report, "when", None) != "call":
        return
    user_properties = getattr(report, "user_properties", None)
    if not isinstance(user_properties, list):
        return

    from pkcs11_check.compliance import get_notes, serialize_notes

    notes = serialize_notes(get_notes(), nodeid=item_nodeid(item))
    _append_missing_compliance_notes(user_properties, notes)


def _report_is_fail_or_xfail(report: Any) -> bool:
    """True when a call report represents a hard fail or an imperative xfail.

    ``pytest.fail()`` yields ``outcome == "failed"``; ``pytest.xfail()`` yields a
    ``skipped`` report carrying a ``wasxfail`` attribute. Both are the un-migrated
    raw-site shapes the unclassified gate must cover.
    """
    return (
        getattr(report, "outcome", None) == "failed"
        or getattr(report, "wasxfail", None) is not None
    )


def _synthetic_unclassified_record(item: pytest.Item, report: Any) -> Any:
    """Build the synthetic ``unclassified`` record for a raw fail/xfail testcase.

    A testcase that ends as fail/xfail without emitting a :func:`classify` record
    is part of the un-migrated backlog; injecting one synthetic record keeps the
    report 100% covered so the live ``unclassified`` count IS the migration backlog.
    """
    from pkcs11_check.classification import Classification

    return Classification(
        reason="unclassified",
        outcome="fail",
        severity="HIGH",
        label=item_nodeid(item),
        summary=_report_text(report) or "raw pytest.fail/xfail with no classification",
        detail={"raw": True},
    )


def _attach_classification_to_report(item: pytest.Item, report: Any) -> None:
    """Attach structured classifications before report-log serializes them.

    Real emitted records always take precedence. When a testcase item ends as a
    raw fail/xfail with no emitted record, a single synthetic ``unclassified``
    record is injected so every testcase outcome stays covered (Phase 5.1 gate).
    """
    if getattr(report, "when", None) != "call":
        return
    from pkcs11_check.classification import get_records, serialize

    collected = get_records()
    if not collected and _is_testcase_item(item) and _report_is_fail_or_xfail(report):
        collected = [_synthetic_unclassified_record(item, report)]
    records = serialize(collected)
    if not records:
        return
    props = list(getattr(report, "user_properties", []) or [])
    props = [(k, v) for (k, v) in props if k != "pkcs11_classification"]
    props.append(("pkcs11_classification", records))
    report.user_properties = props


def _convert_missing_function_to_skip(report: Any, call: pytest.CallInfo[Any]) -> None:
    """A PKCS#11 function absent from the module's function list is a capability
    gap, not a test error.

    The function dispatcher (``raw/api.py``) raises
    ``AttributeError("<C_Fn> not available in this module")`` when a test calls a
    function the loaded module does not implement (common on minimal modules).
    Per the classification model a genuinely-absent capability is
    a ``skip``, so convert that specific uncaught error into a skip rather than
    letting it surface as a hard error. Full modules expose all standard
    functions, so this never fires for them.
    """
    if getattr(report, "when", None) not in ("setup", "call"):
        return
    if getattr(report, "outcome", None) != "failed":
        return
    excinfo = getattr(call, "excinfo", None)
    if excinfo is None or not issubclass(excinfo.type, AttributeError):
        return
    message = str(excinfo.value)
    if not message.endswith("not available in this module"):
        return
    report.outcome = "skipped"
    lineno = item_location[1] if (item_location := getattr(report, "location", None)) else 0
    report.longrepr = (str(getattr(report, "fspath", "")), (lineno or 0) + 1, f"Skipped: {message}")


def _remember_module_session_call_outcome(item: pytest.Item, report: Any) -> None:
    """Mark failed call phases so fast shared-session reuse checks before reuse."""
    if getattr(report, "when", None) != "call":
        return
    if getattr(report, "outcome", None) == "failed":
        setattr(item, MODULE_SESSION_CALL_FAILED_ATTR, True)


def _accumulate_module_session_health_metrics(
    total: dict[str, int | float],
    delta: Any,
) -> None:
    if not isinstance(delta, dict):
        return
    total["checks"] = int(total.get("checks", 0)) + int(delta.get("checks", 0) or 0)
    total["duration_s"] = float(total.get("duration_s", 0.0)) + float(
        delta.get("duration_s", 0.0) or 0.0
    )
