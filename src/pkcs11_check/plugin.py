"""pytest plugin entry point for pkcs11-check."""

from __future__ import annotations

import json
import os
import signal
import tempfile
import threading
from collections import Counter
from pathlib import Path
from typing import Any, cast

import pytest

from pkcs11_check.core.preflight import (
    CapabilityManifest,
    load_manifest,
    run_preflight_subprocess,
)
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
    CKR_OK,
)
from pkcs11_check.testcases._mock_gating import is_pkcs11_mock_target, should_skip_on_mock
from pkcs11_check.testcases._subprocess_trace import (
    drain_subprocess_rv_trace,
    extract_subprocess_rv_trace,
)
from pkcs11_check.testcases.mechanism_selection import (
    ENCRYPT_ROUNDTRIP,
    MULTIPART_ENCRYPT_ROUNDTRIP,
    MULTIPART_SIGN_VERIFY_ROUNDTRIP,
    SIGN_VERIFY_ROUNDTRIP,
    WRAP_ROUNDTRIP,
    select_for_scenario,
)

_MANIFEST_KEY: pytest.StashKey[CapabilityManifest | None] = pytest.StashKey()
_MECHANISM_CATALOG_KEY: pytest.StashKey[Any] = pytest.StashKey()
_SELECTION_TELEMETRY_KEY: pytest.StashKey[dict[str, dict[str, Any]]] = pytest.StashKey()
_SELECTION_PARAM_CACHE_KEY: pytest.StashKey[dict[str, list[Any]]] = pytest.StashKey()
_CUMULATIVE_FUNCTIONS: pytest.StashKey[set[str]] = pytest.StashKey()
_CUMULATIVE_MECHANISMS: pytest.StashKey[set[str]] = pytest.StashKey()
_RAW_INSTANCE: pytest.StashKey[Any] = pytest.StashKey()
_COVERAGE_DATA: pytest.StashKey[dict[str, Any]] = pytest.StashKey()
_CUMULATIVE_USED_MECHANISMS: pytest.StashKey[set[int]] = pytest.StashKey()
_CUMULATIVE_MECHANISM_DETAILS: pytest.StashKey[set[tuple[int, frozenset[tuple[str, int]]]]] = (
    pytest.StashKey()
)
_CUMULATIVE_FUNCTION_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()
_CUMULATIVE_MECHANISM_COUNTS: pytest.StashKey[Counter[int]] = pytest.StashKey()
_CUMULATIVE_DETAIL_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()
_BOOTSTRAP_FUNCTION_COUNTS: pytest.StashKey[dict[str, int]] = pytest.StashKey()
_BOOTSTRAP_COLLECTED: pytest.StashKey[bool] = pytest.StashKey()
_MODULE_SESSION_HEALTH_METRICS: pytest.StashKey[dict[str, int | float]] = pytest.StashKey()
_LAST_RV_TRACE: pytest.StashKey[list[dict[str, Any]]] = pytest.StashKey()
# Live P11Module (carries reinit_count) -- populated opportunistically in
# pytest_runtest_teardown so the teardown-finalize record is self-describing.
_P11_MODULE: pytest.StashKey[Any] = pytest.StashKey()
# Guard flag: pytest_sessionfinish may be entered more than once; the
# normal-teardown C_Finalize must run at most once per process.
_TEARDOWN_FINALIZED: pytest.StashKey[bool] = pytest.StashKey()

# Bounded budget (seconds) for the normal-teardown C_Finalize. A misbehaving
# module that hangs in C_Finalize is abandoned by a SIGALRM watchdog and the
# event recorded as a timeout, rather than hanging the whole unit until the
# outer subprocess deadline fires and mis-attributes a timeout to a passed unit.
_TEARDOWN_FINALIZE_TIMEOUT_S = 5

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
        help="Enable concurrent same-session tests (may crash SoftHSM2)",
    )
    group.addoption(
        "--p11-manifest",
        dest="p11_manifest",
        default=None,
        help="Path to a precomputed PKCS#11 capability manifest",
    )
    group.addoption(
        "--p11-allow-mock-conformance",
        dest="p11_allow_mock_conformance",
        action="store_true",
        default=False,
        help=(
            "Run KAT/ACVP/Wycheproof/security/etc. suites against pkcs11-mock "
            "(default: gated, since the mock returns canned values and these "
            "suites produce only noise). For harness development only."
        ),
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
    config.stash[_CUMULATIVE_MECHANISM_COUNTS] = Counter()
    config.stash[_CUMULATIVE_DETAIL_COUNTS] = Counter()
    config.stash[_BOOTSTRAP_FUNCTION_COUNTS] = {}
    config.stash[_BOOTSTRAP_COLLECTED] = False
    config.stash[_MODULE_SESSION_HEALTH_METRICS] = {"checks": 0, "duration_s": 0.0}
    config.stash[_LAST_RV_TRACE] = []
    config.stash[_SELECTION_TELEMETRY_KEY] = {}
    config.stash[_SELECTION_PARAM_CACHE_KEY] = {}

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


def _is_testcase_item(item: pytest.Item) -> bool:
    item_path = getattr(item, "path", None)
    if item_path is not None:
        return "testcases" in str(item_path)
    return "testcases" in str(item.fspath)


def _has_dynamic_markers(item: pytest.Item) -> bool:
    return any(
        item.get_closest_marker(marker_name)
        for marker_name in (
            "needs_mechanism",
            "needs_function",
        )
    )


def _manifest_failure_message(manifest: CapabilityManifest) -> str:
    detail = manifest.error or "unknown error"
    return f"PKCS#11 preflight {manifest.status}: {detail}"


def _ensure_manifest(config: pytest.Config) -> CapabilityManifest | None:
    cached = config.stash[_MANIFEST_KEY]
    if cached is not None:
        return cached

    module_path = config.getoption("p11_module", default=None)
    if module_path is None:
        return None

    manifest_option = config.getoption("p11_manifest", default=None)
    if manifest_option:
        try:
            manifest = load_manifest(Path(manifest_option))
        except Exception as exc:
            pytest.exit(f"Unable to load p11 manifest: {exc}", returncode=2)
        config.stash[_MANIFEST_KEY] = manifest
        return manifest

    manifest_fd, manifest_raw_path = tempfile.mkstemp(
        prefix="pkcs11-check-manifest-", suffix=".json"
    )
    os.close(manifest_fd)
    manifest_path = Path(manifest_raw_path)
    interface_option = config.getoption("p11_interface", default=None)
    interface = "auto" if interface_option is None else str(interface_option)
    slot_option = config.getoption("p11_slot", default=None)
    slot = 0 if slot_option is None else int(slot_option)
    try:
        manifest = run_preflight_subprocess(
            Path(module_path),
            interface=interface,
            slot=slot,
            timeout=30,
            output_path=manifest_path,
        )
    finally:
        manifest_path.unlink(missing_ok=True)

    if manifest.status != "ok":
        pytest.exit(_manifest_failure_message(manifest), returncode=2)

    config.stash[_MANIFEST_KEY] = manifest
    return manifest


def _ensure_mechanism_catalog(config: pytest.Config) -> Any:
    """Lazily build mechanism catalog from preflight manifest."""
    cached = config.stash.get(_MECHANISM_CATALOG_KEY, None)
    if cached is not None:
        return cached
    manifest = _ensure_manifest(config)
    if manifest is None:
        return None
    mech_info = getattr(manifest, "mechanism_info", None)
    if mech_info is None:
        return None
    from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog

    catalog = MechanismCatalog.from_manifest(manifest)
    config.stash[_MECHANISM_CATALOG_KEY] = catalog
    return catalog


def _selection_telemetry_store(config: pytest.Config) -> dict[str, dict[str, Any]]:
    """Return the per-scenario selection telemetry store, creating it if needed."""
    telemetry = config.stash.get(_SELECTION_TELEMETRY_KEY, None)
    if telemetry is None:
        telemetry = {}
        config.stash[_SELECTION_TELEMETRY_KEY] = telemetry
    return telemetry


def _selection_param_cache(config: pytest.Config) -> dict[str, list[Any]]:
    """Return the scenario parametrization cache, creating it if needed."""
    cache = config.stash.get(_SELECTION_PARAM_CACHE_KEY, None)
    if cache is None:
        cache = {}
        config.stash[_SELECTION_PARAM_CACHE_KEY] = cache
    return cache


def _record_selection_decision(
    config: pytest.Config,
    scenario: str,
    entry: Any,
    decision: Any,
) -> None:
    """Accumulate scenario-level selection telemetry for later reporting."""
    telemetry = _selection_telemetry_store(config)
    scenario_data = telemetry.setdefault(
        scenario,
        {
            "selected_mechanisms": set(),
            "rejected_mechanisms": set(),
            "rejected_reason_counts": Counter(),
        },
    )
    if decision.selected:
        scenario_data["selected_mechanisms"].add(entry.mech_name)
        return

    scenario_data["rejected_mechanisms"].add(entry.mech_name)
    scenario_data["rejected_reason_counts"].update(reason.code for reason in decision.reasons)


def _serialize_selection_telemetry(
    telemetry: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Convert selection telemetry to report-log friendly data."""
    selection_coverage: dict[str, dict[str, Any]] = {}
    for scenario, data in sorted(telemetry.items()):
        selection_coverage[scenario] = {
            "selected_mechanisms": sorted(data["selected_mechanisms"]),
            "rejected_mechanisms": sorted(data["rejected_mechanisms"]),
            "rejected_reason_counts": dict(sorted(data["rejected_reason_counts"].items())),
        }
    return selection_coverage


def _name_set(value: Any) -> set[str]:
    if not isinstance(value, (set, list, tuple)):
        return set()
    return {str(item) for item in value if item is not None}


def _selection_state_names(telemetry: dict[str, dict[str, Any]]) -> tuple[set[str], set[str]]:
    selected: set[str] = set()
    rejected: set[str] = set()
    for data in telemetry.values():
        selected.update(_name_set(data.get("selected_mechanisms")))
        rejected.update(_name_set(data.get("rejected_mechanisms")))
    return selected, rejected


def _reported_names_for_mechanism(
    mechanism_id: int,
    ckm_alias_map: dict[int, list[str]],
    ckm_name_fn: Any,
    advertised_names: set[str],
) -> set[str]:
    names = {ckm_name_fn(mechanism_id), *ckm_alias_map.get(mechanism_id, [])}
    advertised_matches = names & advertised_names
    if advertised_matches:
        return advertised_matches
    return {ckm_name_fn(mechanism_id)}


def _mechanism_rv_state_names(
    mechanism_rv_counts: Any,
    ckm_alias_map: dict[int, list[str]],
    ckm_name_fn: Any,
    advertised_names: set[str],
) -> tuple[set[str], set[str]]:
    accepted: set[str] = set()
    rejected_cleanly: set[str] = set()
    if not isinstance(mechanism_rv_counts, dict):
        return accepted, rejected_cleanly
    for raw_mid, raw_counts in mechanism_rv_counts.items():
        if not isinstance(raw_mid, int) or not isinstance(raw_counts, dict):
            continue
        names = _reported_names_for_mechanism(
            raw_mid,
            ckm_alias_map,
            ckm_name_fn,
            advertised_names,
        )
        for raw_rv, raw_count in raw_counts.items():
            if not isinstance(raw_rv, int) or not isinstance(raw_count, int) or raw_count <= 0:
                continue
            if raw_rv == int(CKR_OK):
                accepted.update(names)
            else:
                rejected_cleanly.update(names)
    return accepted, rejected_cleanly


def _selected_entries_for_scenario(
    catalog: Any,
    config: pytest.Config,
    scenario: str,
) -> list[Any]:
    """Select and cache mechanism entries for a semantic scenario."""
    cache = _selection_param_cache(config)
    cached = cache.get(scenario)
    if cached is not None:
        return cached

    entries: list[Any] = []
    for entry in catalog.all_entries():
        decision = select_for_scenario(entry, scenario)
        _record_selection_decision(config, scenario, entry, decision)
        if decision.selected:
            entries.append(entry)

    cache[scenario] = entries
    return entries


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


def _runtime_skip_reason(
    item: pytest.Item,
    config: pytest.Config,
    manifest: CapabilityManifest | None,
) -> str | None:
    if manifest is None:
        return None

    function_marker = item.get_closest_marker("needs_function")
    if function_marker and function_marker.args:
        needed_fn = str(function_marker.args[0])
        if needed_fn not in manifest.functions:
            return f"Function {needed_fn} not present in module"

    if config.getoption("p11_skip_unsupported", default=True):
        marker = item.get_closest_marker("needs_mechanism")
        if marker and marker.args:
            needed = str(marker.args[0])
            if needed not in manifest.mechanisms:
                return f"Mechanism {needed} not supported by module"

    return None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Apply collection-safe static skips and file-based deselection."""
    # File-based deselect: read nodeids from env-specified file and remove
    # matching items.  Used by the iterative deselect loop in file_runner.py
    # to avoid ARG_MAX limits on --deselect arguments.
    deselect_file = os.environ.get("PKCS11_CHECK_DESELECT_FILE")
    if deselect_file:
        try:
            deselect_nodeids = set(parse_disabled_nodeids(Path(deselect_file).read_text()))
        except (FileNotFoundError, OSError):
            deselect_nodeids = set()
        if deselect_nodeids:
            remaining: list[pytest.Item] = []
            deselected: list[pytest.Item] = []
            for item in items:
                if item.nodeid in deselect_nodeids:
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
    allow_mock_conformance = config.getoption("p11_allow_mock_conformance", default=False)
    backend_module_path = os.environ.get("PKCS11_CHECK_BACKEND_MODULE")
    gate_mock = not allow_mock_conformance and is_pkcs11_mock_target(
        str(module_path), backend_module_path
    )

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

        if gate_mock:
            item_marker_names = {m.name for m in item.iter_markers()}
            if should_skip_on_mock(item_marker_names):
                item.add_marker(
                    pytest.mark.skip(
                        reason=(
                            "pkcs11-mock returns canned values; conformance/"
                            "security/KAT suites are meaningless against it "
                            "(use --p11-allow-mock-conformance to override)"
                        )
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


def _build_one_stacked_string(mech_id: int, subs: dict[str, int]) -> str:
    """Build one stacked string like CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256]."""
    from pkcs11_check.raw.api import ckm_name, sub_param_name

    base = ckm_name(mech_id)
    if subs:
        parts = ",".join(f"{k}={sub_param_name(k, v)}" for k, v in sorted(subs.items()))
        return f"{base}[{parts}]"
    return base


def _build_stacked_strings(
    detail_set: set[tuple[int, frozenset[tuple[str, int]]]],
) -> list[str]:
    """Build sorted stacked strings like CKM_RSA_PKCS_OAEP[hashAlg=CKM_SHA256]."""
    return sorted(
        _build_one_stacked_string(mech_id, dict(subs_frozen)) for mech_id, subs_frozen in detail_set
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


def _attach_rv_trace_to_report(item: pytest.Item, report: Any) -> None:
    """Attach CK_RV trace directly to failed/xfail reports before report-log writes them."""
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

    notes = serialize_notes(get_notes(), nodeid=str(getattr(item, "nodeid", "")))
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
        label=str(getattr(item, "nodeid", "")),
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
    function the loaded module does not implement (common on minimal modules such
    as corePKCS11). Per the classification model a genuinely-absent capability is
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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Any:
    outcome = yield
    report = outcome.get_result()
    _convert_missing_function_to_skip(report, call)
    _remember_module_session_call_outcome(item, report)
    _attach_rv_trace_to_report(item, report)
    _attach_compliance_notes_to_report(item, report)
    _attach_classification_to_report(item, report)


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
                # Accumulate function call counts
                try:
                    fc = session.config.stash[_CUMULATIVE_FUNCTION_COUNTS]
                    fc.update(rs.raw.call_log)
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
                break

    # Drain subprocess coverage (from _raw_subprocess and _subprocess_preamble tests)
    try:
        from pkcs11_check.testcases._raw_subprocess import get_raw_subprocess_coverage

        sub_func, _sub_mech = get_raw_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            try:
                session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
            except KeyError:
                pass
    except ImportError:
        pass
    try:
        from pkcs11_check.testcases._subprocess_preamble import get_preamble_subprocess_coverage

        sub_func, _sub_mech = get_preamble_subprocess_coverage()
        if sub_func:
            cumulative.update(sub_func.keys())
            try:
                session.config.stash[_CUMULATIVE_FUNCTION_COUNTS].update(sub_func)
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
    (``core/loader.py``). A hang is bounded by a SIGALRM watchdog so the outer
    subprocess deadline never mis-attributes a timeout to an already-passed
    unit; on platforms without ``SIGALRM`` the call runs unguarded-for-hang
    (still guarded for rv / raise).
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

    def _on_alarm(_signum: int, _frame: Any) -> None:
        raise _TeardownFinalizeTimeoutError

    try:
        if use_watchdog:
            previous_handler = signal.signal(signal.SIGALRM, _on_alarm)
            signal.setitimer(signal.ITIMER_REAL, float(_TEARDOWN_FINALIZE_TIMEOUT_S))
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
        if use_watchdog:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
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
    accepted_names_set, rejected_cleanly_names_set = _mechanism_rv_state_names(
        getattr(raw, "mechanism_rv_counts", {}),
        ckm_alias_map,
        ckm_name,
        available_set,
    )

    # Stacked mechanism details
    detail_set = config.stash.get(_CUMULATIVE_MECHANISM_DETAILS, set())
    stacked = _build_stacked_strings(detail_set)

    # Call counts
    func_counts = config.stash.get(_CUMULATIVE_FUNCTION_COUNTS, Counter())
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

    # Release per-process module resources: C_Finalize the live library on
    # normal teardown. MUST be last -- after every test outcome AND the coverage
    # report (which reads `raw`) are recorded -- so a slow/failing/crashing
    # C_Finalize cannot change any test's verdict (segfault-survival model). The
    # event is recorded only via the additive TeardownFinalize record.
    _finalize_on_teardown(config, raw)
