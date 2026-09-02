"""pytest plugin entry point for pkcs11-check."""

from __future__ import annotations

import faulthandler
import os
import sys
import threading
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check._plugin_finalize import (
    _TEARDOWN_FINALIZE_TIMEOUT_S as _TEARDOWN_FINALIZE_TIMEOUT_S,
)
from pkcs11_check._plugin_finalize import (
    _build_provisioning_report as _build_provisioning_report,
)
from pkcs11_check._plugin_finalize import (
    _finalize_on_teardown as _finalize_on_teardown,
)
from pkcs11_check._plugin_finalize import (
    _TeardownFinalizeTimeoutError as _TeardownFinalizeTimeoutError,
)
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
    _CUMULATIVE_MECHANISM_RV_COUNTS as _CUMULATIVE_MECHANISM_RV_COUNTS,
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
from pkcs11_check.core.nodeids import normalize_nodeid
from pkcs11_check.core.test_selection import parse_disabled_nodeids

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
from pkcs11_check.markers import MARKER_DEFINITIONS
from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
    CKF_MESSAGE_DECRYPT,
    CKF_MESSAGE_ENCRYPT,
    CKF_MESSAGE_SIGN,
    CKF_MESSAGE_VERIFY,
)
from pkcs11_check.testcases.mechanism_selection import (
    ENCRYPT_ROUNDTRIP,
    MULTIPART_ENCRYPT_ROUNDTRIP,
    MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    SIGN_VERIFY_ROUNDTRIP,
    WRAP_ROUNDTRIP,
)

_SCENARIO_BY_FIXTURE: dict[str, str] = {
    "mech_wrap_entry": WRAP_ROUNDTRIP,
    "mech_encrypt_entry": ENCRYPT_ROUNDTRIP,
    "mech_sign_entry": SIGN_VERIFY_ROUNDTRIP,
    "mech_multipart_encrypt_entry": MULTIPART_ENCRYPT_ROUNDTRIP,
    "mech_multipart_sign_entry": MULTIPART_SIGN_VERIFY_ROUNDTRIP,
}

_LEGACY_FLAG_BY_FIXTURE: dict[str, int] = {
    "mech_digest_entry": int(CKF_DIGEST),
    "mech_keygen_entry": int(CKF_GENERATE) | int(CKF_GENERATE_KEY_PAIR),
    "mech_derive_entry": int(CKF_DERIVE),
    "mech_message_encrypt_entry": int(CKF_MESSAGE_ENCRYPT),
    "mech_message_decrypt_entry": int(CKF_MESSAGE_DECRYPT),
    "mech_message_sign_entry": int(CKF_MESSAGE_SIGN),
    "mech_message_verify_entry": int(CKF_MESSAGE_VERIFY),
    "mech_any_entry": 0,
}


# --- per-test timeout, owned so a hang is reported as a timeout -------------------
#
# pytest-timeout's signal method cannot interrupt a thread blocked in an FFI call, and
# its thread method exits with os._exit(1) -- pytest's ordinary "tests failed" code --
# so a provider deadlock would be recorded as ordinary failures. The runner already maps
# 124 to `timeout` and already preserves partial report records on that path, so owning
# the timer and exiting 124 is the whole fix.
#
# pytest_timeout_set_timer is a firstresult=True hookspec and pytest-timeout implements
# it `trylast`, so this implementation wins while pytest-timeout keeps doing settings
# resolution, marker precedence, cancellation and pdb suppression.
UNIT_CHILD_ENV = "PKCS11_CHECK_UNIT_CHILD"

# Kept local rather than imported from core.file_runner: importing the runner from the
# pytest plugin would make every child pull in the orchestration layer it is run BY.
_TIMEOUT_EXIT_CODE = 124


def _on_timeout_expired(item: Any) -> None:
    """Dump every thread's stack, then exit with the framework's timeout code.

    Runs on a watchdog thread, so it works while the main thread is stuck in native
    code -- which is the entire point. os._exit is deliberate: the main thread cannot be
    unwound, so a clean shutdown is not available. Records already written to the report
    log survive, because pytest-reportlog opens line-buffered and flushes per record.
    """
    # Suspend pytest's capture FIRST. It redirects stdout/stderr at the fd level, and
    # os._exit discards the capture buffer, so anything written while capture is active
    # is lost -- verified against a real native hang, where the exit code was correct but
    # the stack dump never reached the unit log. That dump is most of the diagnostic
    # value: without it a deadlock is only "a timeout happened", with no hung frame.
    try:
        capman = item.config.pluginmanager.getplugin("capturemanager")
        if capman is not None:
            capman.suspend_global_capture(in_=True)
    except Exception as exc:  # noqa: BLE001 - never let diagnosis block the exit
        sys.stderr.write(f"(could not suspend capture: {exc!r})\n")
    sys.stderr.write(f"\n=== pkcs11-check: per-test timeout expired in {item.nodeid} ===\n")
    sys.stderr.flush()
    try:
        faulthandler.dump_traceback(file=sys.stderr, all_threads=True)
    except Exception as exc:  # noqa: BLE001 - diagnosis is best-effort; the exit is not
        sys.stderr.write(f"(stack dump unavailable: {exc!r})\n")
    sys.stderr.flush()
    sys.stdout.flush()
    os._exit(_TIMEOUT_EXIT_CODE)


def pytest_timeout_set_timer(item: Any, settings: Any) -> bool | None:
    """Arm our own timer for isolated child units; delegate for in-process runs.

    Returning None lets pytest-timeout's own (trylast) implementation handle it. That
    matters for `--isolation none`, where pytest.main() runs inside the CLI process: a
    self-exit there would skip results.json assembly and produce no output at all.
    """
    if not os.environ.get(UNIT_CHILD_ENV):
        return None
    timer = threading.Timer(settings.timeout, _on_timeout_expired, (item,))
    timer.name = f"pkcs11-check-timeout:{item.nodeid}"
    timer.daemon = True
    item._pkcs11_check_timeout_timer = timer
    timer.start()
    return True


def pytest_timeout_cancel_timer(item: Any) -> bool | None:
    timer = getattr(item, "_pkcs11_check_timeout_timer", None)
    if timer is None:
        return None
    timer.cancel()
    del item._pkcs11_check_timeout_timer
    return True


def pytest_addoption(parser: Any) -> None:
    """Register pkcs11-check CLI options with pytest."""
    group = parser.getgroup("pkcs11-check", "PKCS#11 testing")
    group.addoption(
        "--p11-module",
        dest="p11_module",
        default=None,
        help="Path to PKCS#11 module (.so/.dll/.dylib)",
    )
    group.addoption(
        "--p11-interface",
        dest="p11_interface",
        default=None,
        help="Force interface version: auto, 2.40, 3.0, 3.1, 3.2 (default: auto)",
    )
    group.addoption(
        "--p11-slot",
        dest="p11_slot",
        type=int,
        default=None,
        help="Slot index (default: 0)",
    )
    group.addoption(
        "--p11-pin",
        dest="p11_pin",
        default=None,
        help="PIN (prefer P11TEST_PIN env var)",
    )
    group.addoption(
        "--p11-so-pin",
        dest="p11_so_pin",
        default=None,
        help="SO PIN for CKU_SO tests (prefer P11TEST_SO_PIN env var)",
    )
    group.addoption(
        "--p11-destructive",
        dest="p11_destructive",
        action="store_true",
        default=False,
        help="Enable destructive tests",
    )
    group.addoption(
        "--p11-skip-unsupported",
        dest="p11_skip_unsupported",
        action="store_true",
        default=True,
        help="Auto-skip tests for unsupported mechanisms (default: on)",
    )
    group.addoption(
        "--p11-thread-safe",
        dest="p11_thread_safe",
        action="store_true",
        default=False,
        help="Enable concurrent same-session tests (may crash some modules)",
    )
    group.addoption(
        "--p11-manifest",
        dest="p11_manifest",
        default=None,
        help="Path to a precomputed PKCS#11 capability manifest",
    )
    group.addoption(
        "--p11-rv-trace",
        dest="p11_rv_trace",
        action="store_true",
        default=False,
        help="Record each C_* call's raw CK_RV per test into report.jsonl user_properties",
    )
    group.addoption(
        "--p11-rv-trace-compact",
        dest="p11_rv_trace_compact",
        type=int,
        default=None,
        metavar="N",
        help="Keep only the last N CK_RV trace entries per test (implies --p11-rv-trace)",
    )
    group.addoption(
        "--p11-key-inject",
        dest="p11_key_inject",
        default="off",
        help="Key-provisioning injection mode: off, unwrap, force-unwrap (default: off)",
    )
    group.addoption(
        "--p11-wrap-key-source",
        dest="p11_wrap_key_source",
        default="bootstrap",
        help="Wrapping KEK source: bootstrap (auto-generate) or configured (default: bootstrap)",
    )
    group.addoption(
        "--p11-wrap-key-label",
        dest="p11_wrap_key_label",
        default=None,
        help="Label of the configured wrapping key",
    )
    group.addoption(
        "--p11-wrap-key-handle",
        dest="p11_wrap_key_handle",
        type=int,
        default=None,
        help="Handle of the configured wrapping key",
    )
    group.addoption(
        "--p11-wrap-key-value",
        dest="p11_wrap_key_value",
        default=None,
        help="Hex value of a symmetric configured KEK",
    )
    group.addoption(
        "--p11-wrap-mech",
        dest="p11_wrap_mech",
        default=None,
        help="Override auto-selected unwrap mechanism (e.g. CKM_RSA_AES_KEY_WRAP)",
    )
    group.addoption(
        "--p11-wrap-rsa-bits",
        dest="p11_wrap_rsa_bits",
        type=int,
        default=2048,
        help="RSA key size in bits for bootstrap wrapping key (default: 2048)",
    )
    group.addoption(
        "--p11-wrap-oaep-hash",
        dest="p11_wrap_oaep_hash",
        default="auto",
        help="OAEP hash for wrapping: auto, sha1, or sha256 (default: auto)",
    )
    group.addoption(
        "--p11-allow-external-provision",
        dest="p11_allow_external_provision",
        action="store_true",
        default=False,
        help=(
            "Strict acknowledgement enabling external-tool provisioning "
            "(requires --p11-external-provision-cmd)"
        ),
    )
    group.addoption(
        "--p11-external-provision-cmd",
        dest="p11_external_provision_cmd",
        default=None,
        help=(
            "Operator command template loading a key into the backend; "
            "placeholders {keyfile} {label} {key_type} {key_class}"
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    """Register pkcs11-check custom markers and inject --report-log for non-isolated runs."""
    for marker in MARKER_DEFINITIONS:
        config.addinivalue_line("markers", f"{marker.name}: {marker.description}")
    config.stash[_MANIFEST_KEY] = None
    config.stash[_MECHANISM_CATALOG_KEY] = None
    config.stash[_CUMULATIVE_FUNCTIONS] = set()
    config.stash[_CUMULATIVE_MECHANISMS] = set()
    config.stash[_RAW_INSTANCE] = None
    config.stash[_COVERAGE_DATA] = {}
    config.stash[_CUMULATIVE_USED_MECHANISMS] = set()
    config.stash[_CUMULATIVE_MECHANISM_DETAILS] = set()
    config.stash[_CUMULATIVE_FUNCTION_COUNTS] = Counter()
    config.stash[_CUMULATIVE_FUNCTION_OK_COUNTS] = Counter()
    config.stash[_CUMULATIVE_MECHANISM_COUNTS] = Counter()
    mechanism_rv_counts: defaultdict[int, Counter[int]] = defaultdict(Counter)
    config.stash[_CUMULATIVE_MECHANISM_RV_COUNTS] = mechanism_rv_counts
    config.stash[_CUMULATIVE_DETAIL_COUNTS] = Counter()
    config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = {}
    config.stash[_BOOTSTRAP_COLLECTED] = False
    config.stash[_MODULE_SESSION_HEALTH_METRICS] = {"checks": 0, "duration_s": 0.0}
    config.stash[_LAST_RV_TRACE] = []
    config.stash[_SELECTION_TELEMETRY_KEY] = {}
    config.stash[_SELECTION_PARAM_CACHE_KEY] = {}
    config.stash[_PROVISIONING_COUNTS] = Counter()

    # Inject --report-log when PKCS11_CHECK_REPORT_LOG is set (by test_cmd.py for
    # --isolation none JSON runs).  Guard against meta-tests (no --p11-module) and
    # cases where the user already supplied --report-log on the command line.
    if config.getoption("p11_module", default=None) is None:
        return  # Not a pkcs11-check run (e.g. meta-tests)
    if config.getoption("report_log", default=None) is not None:
        return  # User already passed --report-log
    report_log_path = os.environ.get("PKCS11_CHECK_REPORT_LOG")
    if report_log_path:
        config.option.report_log = report_log_path


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize mechanism-driven tests from the module's mechanism list."""
    requested = None
    for name in (*_SCENARIO_BY_FIXTURE, *_LEGACY_FLAG_BY_FIXTURE):
        if name in metafunc.fixturenames:
            requested = name
            break
    if requested is None:
        return

    catalog = _ensure_mechanism_catalog(metafunc.config)

    entries: list[Any] = []
    if catalog is not None:
        if requested in _SCENARIO_BY_FIXTURE:
            entries = _selected_entries_for_scenario(
                catalog,
                metafunc.config,
                _SCENARIO_BY_FIXTURE[requested],
            )
        else:
            flag = _LEGACY_FLAG_BY_FIXTURE[requested]
            if flag == 0:
                entries = [e for e in catalog.all_entries() if e.config is not None]
            else:
                entries = catalog.filter_registered(flag)

    if not entries:
        # No catalog or no matching entries -- use a sentinel that triggers skip
        entries = [pytest.param(None, marks=pytest.mark.skip("No mechanism catalog"))]
        ids = ["no_catalog"]
    else:
        ids = [e.mech_name for e in entries]

    metafunc.parametrize(requested, entries, ids=ids, indirect=False)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply collection-safe static skips and file-based deselection."""
    # File-based deselect: read nodeids from env-specified file and remove
    # matching items.  Used by the iterative deselect loop in file_runner.py
    # to avoid ARG_MAX limits on --deselect arguments.
    deselect_file = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
    if deselect_file:
        try:
            deselect_nodeids = set(
                parse_disabled_nodeids(Path(deselect_file).read_text(encoding="utf-8"))
            )
        except (FileNotFoundError, OSError):
            deselect_nodeids = set()
        if deselect_nodeids:
            remaining: list[pytest.Item] = []
            deselected: list[pytest.Item] = []
            for item in items:
                if normalize_nodeid(item.nodeid) in deselect_nodeids:
                    deselected.append(item)
                else:
                    remaining.append(item)
            if deselected:
                config.hook.pytest_deselected(items=deselected)
                items[:] = remaining

    module_path = config.getoption("p11_module", default=None)

    # If no module specified, skip all tests in testcases/
    if module_path is None:
        for item in items:
            if _is_testcase_item(item):
                item.add_marker(pytest.mark.skip(reason="No --p11-module specified"))
        return

    destructive_enabled = config.getoption("p11_destructive", default=False)
    thread_safe_enabled = config.getoption("p11_thread_safe", default=False)

    for item in items:
        if not _is_testcase_item(item):
            continue

        if item.get_closest_marker("destructive") and not destructive_enabled:
            item.add_marker(
                pytest.mark.skip(reason="Destructive test (use --p11-destructive to enable)")
            )

        if item.get_closest_marker("thread_safe") and not thread_safe_enabled:
            item.add_marker(
                pytest.mark.skip(
                    reason="Concurrent same-session test (use --p11-thread-safe to enable)"
                )
            )


def pytest_collection_finish(session: pytest.Session) -> None:
    """Prepare a capability manifest after collection, never during module import."""
    config = session.config
    if config.getoption("collectonly", default=False):
        return
    if not any(_is_testcase_item(item) and _has_dynamic_markers(item) for item in session.items):
        return
    _ensure_manifest(config)


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Apply dynamic skip decisions from the capability manifest at runtime."""
    if not _is_testcase_item(item) or not _has_dynamic_markers(item):
        return

    manifest = _ensure_manifest(item.config)
    reason = _runtime_skip_reason(item, item.config, manifest)
    if reason is not None:
        pytest.skip(reason)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Any:
    outcome = yield
    report = outcome.get_result()
    _convert_missing_function_to_skip(report, call)
    _attach_rv_trace_to_report(item, report)
    _attach_compliance_notes_to_report(item, report)
    _attach_classification_to_report(item, report, call=call)
    _remember_module_session_call_outcome(item, report)
    _attach_claimed_op_to_report(item, report)


def _accumulate_mechanism_rv_counts(
    target: defaultdict[int, Counter[int]],
    incoming: Any,
) -> None:
    if not isinstance(incoming, dict):
        return
    for mechanism, counts in incoming.items():
        if isinstance(mechanism, int) and isinstance(counts, dict):
            target[mechanism].update(counts)


def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> None:
    """Clear per-item state after each test to prevent cross-item leakage."""
    if _is_testcase_item(item):
        _drain_rv_trace(item)

        from pkcs11_check.compliance import clear_notes

        clear_notes()

    # Classification records can originate from ANY test (attach is likewise ungated);
    # clear unconditionally to prevent cross-item leakage.
    from pkcs11_check.classification import clear as clear_classifications

    clear_classifications()

    # Provisioning events can originate from any test file; drain and clear unconditionally.
    from pkcs11_check.testcases._provisioning import (
        clear_provisioning_events,
        get_provisioning_events,
    )

    _prov_session = getattr(item, "session", None)
    prov_counts = (
        _prov_session.config.stash.get(_PROVISIONING_COUNTS, None)
        if _prov_session is not None
        else None
    )
    if prov_counts is not None:
        for ev in get_provisioning_events():
            prov_counts[(ev.obj_class, ev.method)] += 1
    clear_provisioning_events()

    if not _is_testcase_item(item):
        return

    session = getattr(item, "session", None)
    if session is None:
        return

    try:
        cumulative = session.config.stash[_CUMULATIVE_FUNCTIONS]
    except (KeyError, AttributeError):
        return

    raw_ref = None
    try:
        raw_ref = session.config.stash[_RAW_INSTANCE]
    except KeyError:
        pass

    funcargs = getattr(item, "funcargs", None)
    if funcargs and isinstance(funcargs, dict):
        # Stash the live P11Module (carries reinit_count) once, so the
        # teardown-finalize record can report it. Cheap and side-effect free.
        if _P11_MODULE not in session.config.stash:
            module = funcargs.get("p11_module")
            if module is not None:
                session.config.stash[_P11_MODULE] = module
        for name in ("p11_raw_session", "p11_session", "p11_module_session"):
            rs = funcargs.get(name)
            if rs is not None and hasattr(rs, "raw"):
                cumulative.update(rs.raw.call_log.keys())
                if raw_ref is None:
                    session.config.stash[_RAW_INSTANCE] = rs.raw
                # Accumulate function call counts (+ CKR_OK "productive" counts)
                try:
                    fc = session.config.stash[_CUMULATIVE_FUNCTION_COUNTS]
                    fc.update(rs.raw.call_log)
                    session.config.stash[_CUMULATIVE_FUNCTION_OK_COUNTS].update(rs.raw.call_log_ok)
                except KeyError:
                    pass
                # Collect bootstrap counts once
                try:
                    if not session.config.stash.get(_BOOTSTRAP_COLLECTED, False):
                        bootstrap = getattr(rs, "bootstrap_call_counts", {})
                        if bootstrap:
                            session.config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = dict(bootstrap)
                            session.config.stash[_BOOTSTRAP_COLLECTED] = True
                except KeyError:
                    pass
                # Track reusable-session health-check overhead separately from
                # test-body C_* calls so setup-bound provider runs are measurable.
                try:
                    health_metrics = session.config.stash[_MODULE_SESSION_HEALTH_METRICS]
                    _accumulate_module_session_health_metrics(
                        health_metrics,
                        getattr(rs, "module_session_health_metrics", {}),
                    )
                except KeyError:
                    pass
                # Collect mechanism names used by this session
                if hasattr(rs, "mechanisms"):
                    try:
                        mech_cumulative = session.config.stash[_CUMULATIVE_MECHANISMS]
                        mech_cumulative.update(rs.mechanisms)
                    except (KeyError, AttributeError):
                        pass
                # Collect actually-invoked mechanism IDs
                try:
                    used = session.config.stash[_CUMULATIVE_USED_MECHANISMS]
                    used.update(rs.raw.used_mechanisms)
                except (KeyError, AttributeError):
                    pass
                # Accumulate mechanism counts
                try:
                    mc = session.config.stash[_CUMULATIVE_MECHANISM_COUNTS]
                    mc.update(rs.raw.mechanism_counts)
                except (KeyError, AttributeError):
                    pass
                try:
                    _accumulate_mechanism_rv_counts(
                        session.config.stash[_CUMULATIVE_MECHANISM_RV_COUNTS],
                        rs.raw.mechanism_rv_counts,
                    )
                except (KeyError, AttributeError):
                    pass
                break

    # Drain subprocess coverage (from _raw_subprocess and _subprocess_preamble tests)
    try:
        from pkcs11_check.testcases._raw_subprocess import get_raw_subprocess_coverage

        sub_func, _sub_mech, sub_func_ok, sub_mech_rv = get_raw_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            try:
                session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
                session.config.stash[_CUMULATIVE_FUNCTION_OK_COUNTS].update(sub_func_ok)
            except KeyError:
                pass
        if _sub_mech:
            try:
                session.config.stash[_CUMULATIVE_MECHANISM_COUNTS].update(_sub_mech)
                session.config.stash[_CUMULATIVE_USED_MECHANISMS].update(_sub_mech)
            except KeyError:
                pass
        try:
            _accumulate_mechanism_rv_counts(
                session.config.stash[_CUMULATIVE_MECHANISM_RV_COUNTS],
                sub_mech_rv,
            )
        except KeyError:
            pass
    except ImportError:
        pass
    try:
        from pkcs11_check.testcases._subprocess_preamble import get_preamble_subprocess_coverage

        sub_func, _sub_mech, sub_func_ok, sub_mech_rv = get_preamble_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            try:
                session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
                session.config.stash[_CUMULATIVE_FUNCTION_OK_COUNTS].update(sub_func_ok)
            except KeyError:
                pass
        if _sub_mech:
            try:
                session.config.stash[_CUMULATIVE_MECHANISM_COUNTS].update(_sub_mech)
                session.config.stash[_CUMULATIVE_USED_MECHANISMS].update(_sub_mech)
            except KeyError:
                pass
        try:
            _accumulate_mechanism_rv_counts(
                session.config.stash[_CUMULATIVE_MECHANISM_RV_COUNTS],
                sub_mech_rv,
            )
        except KeyError:
            pass
    except ImportError:
        pass

    # Drain stacked mechanism details from PackedMechanism.byref() calls
    try:
        from pkcs11_check.raw.pack import drain_mechanism_details

        details = drain_mechanism_details()
        if details:
            detail_set = session.config.stash[_CUMULATIVE_MECHANISM_DETAILS]
            detail_counts = session.config.stash.get(_CUMULATIVE_DETAIL_COUNTS, None)
            for mech_id, subs in details:
                detail_set.add((mech_id, frozenset(subs.items())))
                if detail_counts is not None:
                    detail_str = _build_one_stacked_string(mech_id, subs)
                    detail_counts[detail_str] += 1
    except (KeyError, ImportError):
        pass


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    config = session.config
    if config.getoption("p11_module", default=None) is None:
        return

    selection_telemetry = config.stash.get(_SELECTION_TELEMETRY_KEY, {})
    if selection_telemetry:
        selection_report = {
            "selection_coverage": _serialize_selection_telemetry(selection_telemetry),
        }
        report_log_plugin = getattr(config, "_report_log_plugin", None)
        if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
            report_log_plugin._write_json_data(
                {
                    "$report_type": "SelectionReport",
                    **selection_report,
                }
            )

    raw = config.stash.get(_RAW_INSTANCE, None)
    if raw is None:
        return

    from pkcs11_check.fixtures import _build_ckm_alias_map
    from pkcs11_check.raw.api import ckm_name

    # Function coverage
    cumulative = config.stash[_CUMULATIVE_FUNCTIONS]
    available = raw.available_function_names()

    # Mechanism coverage (available from module info)
    mech_available = config.stash.get(_CUMULATIVE_MECHANISMS, set())
    mech_ckm = sorted(n for n in mech_available if n.startswith("CKM_"))

    # Actually-invoked mechanisms (from _call() tracking)
    # Expand each invoked ID to all its alias names so that alias mechanisms
    # (e.g. CKM_ECDSA_KEY_PAIR_GEN == CKM_EC_KEY_PAIR_GEN) are not falsely
    # listed as not_invoked when their canonical name was invoked.
    used_ids = config.stash.get(_CUMULATIVE_USED_MECHANISMS, set())
    ckm_alias_map = _build_ckm_alias_map()
    invoked_names_set: set[str] = set()
    for mid in used_ids:
        invoked_names_set.add(ckm_name(mid))
        for alias in ckm_alias_map.get(mid, []):
            invoked_names_set.add(alias)
    invoked_names = sorted(invoked_names_set)
    available_set = set(mech_ckm)
    not_invoked = sorted(available_set - invoked_names_set)
    attempted_names_set = set()
    for mid in used_ids:
        attempted_names_set.update(
            _reported_names_for_mechanism(mid, ckm_alias_map, ckm_name, available_set)
        )
    selected_names_set, selection_rejected_names_set = _selection_state_names(selection_telemetry)
    mechanism_rv_counts_for_report: Any = config.stash.get(_CUMULATIVE_MECHANISM_RV_COUNTS, None)
    if mechanism_rv_counts_for_report is None:
        mechanism_rv_counts_for_report = getattr(raw, "mechanism_rv_counts", {})
    accepted_names_set, rejected_cleanly_names_set = _mechanism_rv_state_names(
        mechanism_rv_counts_for_report,
        ckm_alias_map,
        ckm_name,
        available_set,
    )

    # Stacked mechanism details
    detail_set = config.stash.get(_CUMULATIVE_MECHANISM_DETAILS, set())
    stacked = _build_stacked_strings(detail_set)

    # Call counts
    func_counts = config.stash.get(_CUMULATIVE_FUNCTION_COUNTS, Counter())
    func_ok_counts = config.stash.get(_CUMULATIVE_FUNCTION_OK_COUNTS, Counter())
    mech_counts_raw = config.stash.get(_CUMULATIVE_MECHANISM_COUNTS, Counter())
    detail_counts = config.stash.get(_CUMULATIVE_DETAIL_COUNTS, Counter())
    bootstrap = config.stash.get(_BOOTSTRAP_FUNCTION_COUNTS, {})
    module_session_health = config.stash.get(
        _MODULE_SESSION_HEALTH_METRICS,
        {"checks": 0, "duration_s": 0.0},
    )

    # Resolve mechanism int IDs to names for JSON output
    mech_counts_named: dict[str, int] = {}
    for mid, count in mech_counts_raw.items():
        name = ckm_name(mid)
        mech_counts_named[name] = mech_counts_named.get(name, 0) + count

    # Bootstrap functions join called_names
    bootstrap_func_names = set(bootstrap.keys())
    called = sorted((cumulative | bootstrap_func_names) & available)
    uncalled = sorted(available - cumulative - bootstrap_func_names)

    coverage_data: dict[str, Any] = {
        "function_coverage": {
            "available": len(available),
            "called": len(called),
            "called_names": called,
            "called_counts": dict(sorted(func_counts.items())),
            "ok_counts": dict(sorted(func_ok_counts.items())),
            "bootstrap_counts": bootstrap,
            "module_session_health": {
                "checks": int(module_session_health.get("checks", 0)),
                "duration_s": float(module_session_health.get("duration_s", 0.0)),
            },
            "uncalled_names": uncalled,
        },
        "mechanism_coverage": {
            "available": len(mech_ckm),
            "available_names": mech_ckm,
            "advertised_names": mech_ckm,
            "selected_names": sorted(selected_names_set),
            "selection_rejected_names": sorted(selection_rejected_names_set),
            "attempted_names": sorted(attempted_names_set),
            "invoked": len(invoked_names),
            "invoked_names": invoked_names,
            "invoked_counts": dict(sorted(mech_counts_named.items())),
            "not_invoked": len(not_invoked),
            "not_invoked_names": not_invoked,
            "invoked_detail": stacked,
            "invoked_detail_counts": dict(sorted(detail_counts.items())),
            "accepted_names": sorted(accepted_names_set),
            "rejected_cleanly_names": sorted(rejected_cleanly_names_set),
            "skipped_by_capability_names": [],
            "crashed_names": [],
            "timeout_names": [],
        },
    }
    config.stash[_COVERAGE_DATA] = coverage_data

    # Emit CoverageReport to JSONL (for file_runner merging)
    report_log_plugin = getattr(config, "_report_log_plugin", None)
    if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
        report_log_plugin._write_json_data(
            {
                "$report_type": "CoverageReport",
                **coverage_data,
            }
        )

    # Emit ProvisioningReport to JSONL (always, even if all-zero counts).
    provisioning_data = _build_provisioning_report(
        config.stash.get(_PROVISIONING_COUNTS, Counter())
    )
    if report_log_plugin is not None and hasattr(report_log_plugin, "_write_json_data"):
        report_log_plugin._write_json_data(
            {"$report_type": "ProvisioningReport", **provisioning_data}
        )

    # Release per-process module resources after every ordinary test verdict and
    # coverage read. A lifecycle finding is additive, but the process must still
    # be non-green so isolated and non-isolated callers cannot accept it.
    finalize_outcome = _finalize_on_teardown(config, raw)
    if (
        finalize_outcome not in {None, "ok"}
        and getattr(session, "exitstatus", exitstatus) == pytest.ExitCode.OK
    ):
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
