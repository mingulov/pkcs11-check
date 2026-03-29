"""pytest plugin entry point for pkcs11-check."""

from __future__ import annotations

import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from pkcs11_check.core.preflight import (
    CapabilityManifest,
    load_manifest,
    run_preflight_subprocess,
)

# Re-export fixtures so pytest discovers them
from pkcs11_check.fixtures import (  # noqa: F401
    RawSession,
    p11_config,
    p11_interface_version,
    p11_module,
    p11_raw_session,
    p11_session,
)
from pkcs11_check.markers import MARKER_DEFINITIONS, should_skip_for_version
from pkcs11_check.raw.types_std import (
    CKF_DERIVE,
    CKF_DIGEST,
    CKF_GENERATE,
    CKF_GENERATE_KEY_PAIR,
)
from pkcs11_check.testcases.mechanism_selection import (
    ENCRYPT_ROUNDTRIP,
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

_SCENARIO_BY_FIXTURE: dict[str, str] = {
    "mech_wrap_entry": WRAP_ROUNDTRIP,
    "mech_encrypt_entry": ENCRYPT_ROUNDTRIP,
    "mech_sign_entry": SIGN_VERIFY_ROUNDTRIP,
}

_LEGACY_FLAG_BY_FIXTURE: dict[str, int] = {
    "mech_digest_entry": int(CKF_DIGEST),
    "mech_keygen_entry": int(CKF_GENERATE) | int(CKF_GENERATE_KEY_PAIR),
    "mech_derive_entry": int(CKF_DERIVE),
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
        default="auto",
        help="Force interface version: auto, 2.40, 3.0, 3.1, 3.2",
    )
    group.addoption(
        "--p11-slot",
        dest="p11_slot",
        type=int,
        default=0,
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
        for marker_name in ("requires_v30", "requires_v32", "needs_mechanism")
    )


def _manifest_failure_message(manifest: CapabilityManifest) -> str:
    detail = manifest.error or "unknown error"
    return f"PKCS#11 preflight {manifest.status}: {detail}"


def _marker_version_label(marker_name: str) -> str:
    return marker_name.removeprefix("requires_")


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
    try:
        manifest = run_preflight_subprocess(
            Path(module_path),
            interface=config.getoption("p11_interface", default="auto"),
            slot=config.getoption("p11_slot", default=0),
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
    telemetry = config.stash.get(_SELECTION_TELEMETRY_KEY)
    if telemetry is None:
        telemetry = {}
        config.stash[_SELECTION_TELEMETRY_KEY] = telemetry
    return telemetry


def _selection_param_cache(config: pytest.Config) -> dict[str, list[Any]]:
    """Return the scenario parametrization cache, creating it if needed."""
    cache = config.stash.get(_SELECTION_PARAM_CACHE_KEY)
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
        # No catalog or no matching entries — use a sentinel that triggers skip
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

    for marker_name in ("requires_v30", "requires_v32"):
        if item.get_closest_marker(marker_name) and manifest.interface_version is not None:
            if should_skip_for_version(marker_name, manifest.interface_version):
                return (
                    f"Requires {_marker_version_label(marker_name)}, "
                    f"module has v{manifest.interface_version}"
                )

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
            deselect_nodeids = set(
                line.strip()
                for line in Path(deselect_file).read_text().splitlines()
                if line.strip()
            )
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
        _build_one_stacked_string(mech_id, dict(subs_frozen))
        for mech_id, subs_frozen in detail_set
    )


def pytest_runtest_teardown(item: pytest.Item, nextitem: pytest.Item | None) -> None:
    """Clear compliance notes after each testcase item to prevent leakage."""
    if not _is_testcase_item(item):
        return
    from pkcs11_check.compliance import clear_notes

    clear_notes()

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
        for name in ("p11_raw_session", "p11_session"):
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

    # Stacked mechanism details
    detail_set = config.stash.get(_CUMULATIVE_MECHANISM_DETAILS, set())
    stacked = _build_stacked_strings(detail_set)

    # Call counts
    func_counts = config.stash.get(_CUMULATIVE_FUNCTION_COUNTS, Counter())
    mech_counts_raw = config.stash.get(_CUMULATIVE_MECHANISM_COUNTS, Counter())
    detail_counts = config.stash.get(_CUMULATIVE_DETAIL_COUNTS, Counter())
    bootstrap = config.stash.get(_BOOTSTRAP_FUNCTION_COUNTS, {})

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
            "uncalled_names": uncalled,
        },
        "mechanism_coverage": {
            "available": len(mech_ckm),
            "available_names": mech_ckm,
            "invoked": len(invoked_names),
            "invoked_names": invoked_names,
            "invoked_counts": dict(sorted(mech_counts_named.items())),
            "not_invoked": len(not_invoked),
            "not_invoked_names": not_invoked,
            "invoked_detail": stacked,
            "invoked_detail_counts": dict(sorted(detail_counts.items())),
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
