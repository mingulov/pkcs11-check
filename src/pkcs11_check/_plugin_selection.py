"""Mechanism-selection machinery for the pytest plugin: manifest/catalog access,
selection telemetry, scenario entry selection, and stacked-string building.

Moved verbatim from plugin.py (god-module split, 2026-07-17); hooks stay in plugin.py.
"""

from __future__ import annotations

import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

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
from pkcs11_check.core.preflight import (
    CapabilityManifest,
    load_manifest,
    run_preflight_subprocess,
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
from pkcs11_check.testcases.mechanism_selection import (
    select_for_scenario,
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
    else:
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
