"""Shared pytest-plugin state: config StashKeys and testcase-item predicates.

Moved verbatim from plugin.py (god-module split, 2026-07-17).  Every StashKey has
exactly ONE home (keys are identity-based); plugin.py and the _plugin_* helper
modules all import them from here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

import pytest

from pkcs11_check.core.preflight import (
    CapabilityManifest,
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

# Per-function CKR_OK ("productive") invocation counts, for the hollow-pass oracle.
_CUMULATIVE_FUNCTION_OK_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()

_CUMULATIVE_MECHANISM_COUNTS: pytest.StashKey[Counter[int]] = pytest.StashKey()

_CUMULATIVE_MECHANISM_RV_COUNTS: pytest.StashKey[defaultdict[int, Counter[int]]] = pytest.StashKey()

_CUMULATIVE_DETAIL_COUNTS: pytest.StashKey[Counter[str]] = pytest.StashKey()

_PROVISIONING_COUNTS: pytest.StashKey[Counter[tuple[str, str]]] = pytest.StashKey()

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
