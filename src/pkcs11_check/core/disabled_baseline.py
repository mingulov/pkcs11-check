"""Resolve the disabled-tests baseline for any command that selects tests (GH #6).

``test`` resolved the baseline inline (config value, else auto-discovery, else none) while
``list-tests`` did not resolve it at all, so the two commands disagreed about which
node-ids are in play -- and list-tests exists precisely to build those baseline files.
One resolver, used by both, so they cannot drift again.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pkcs11_check.core.test_selection import (
    auto_discover_disabled_baseline,
    load_disabled_baseline,
)

NO_BASELINE_FINGERPRINT = "disabled-baseline:none"


def resolve_disabled_nodeids(
    *,
    disabled_tests_file: Path | None,
    ignore: bool = False,
    on_auto_discover: object = None,
) -> tuple[set[str], str]:
    """Return the disabled node-ids and the baseline fingerprint.

    Resolution order matches the four-layer config: an explicitly configured path (CLI, env
    or TOML) wins, otherwise a ``disabled-tests.txt`` auto-discovered in the data directory.
    ``ignore`` skips the baseline entirely.

    A configured path that does not exist raises FileNotFoundError: silently running the
    full suite because a baseline path was mistyped would hide exactly the tests the
    operator meant to exclude.

    ``on_auto_discover`` is an optional callable notified with the auto-discovered path, so
    a CLI can tell the user which file it picked up.
    """
    if ignore:
        return set(), NO_BASELINE_FINGERPRINT
    path = disabled_tests_file
    if path is None:
        path = auto_discover_disabled_baseline()
        if path is not None and callable(on_auto_discover):
            on_auto_discover(path)
    baseline = load_disabled_baseline(path)
    if baseline is None:
        return set(), NO_BASELINE_FINGERPRINT
    return set(baseline.disabled_nodeids), baseline.fingerprint


def format_disabled_baseline_banner(
    *,
    nodeid_count: int,
    excluded_units: int,
    per_file_deselected: int,
    fingerprint: str,
) -> str:
    """Format the loud one-line summary of what the baseline removed (H-7).

    Excluded units never run and per-file deselections hide inside child
    output, so both counts are printed on the console for every run with a
    non-empty baseline -- including the suspicious all-zeros case of a stale
    baseline that matches nothing. The short fingerprint correlates the line
    with the ``disabled_baseline`` block in results.json.
    """
    return (
        f"Disabled baseline [{fingerprint[:12]}]: {nodeid_count} nodeids, "
        f"{excluded_units} unit(s) fully excluded, "
        f"{per_file_deselected} deselected in scheduled units"
    )


def build_disabled_baseline_block(
    *,
    fingerprint: str | None,
    deselect_by_file: Mapping[str, set[str]],
    excluded_units: int,
) -> dict[str, Any] | None:
    """Build the machine-auditable ``disabled_baseline`` results.json block (H-7).

    Returns ``None`` when no baseline is active so the key stays absent (existing
    payload shape unchanged); otherwise reports the fingerprint, the fully
    excluded unit count, and per-file deselection counts -- zeroed but present
    when the baseline matched nothing, so staleness is visible, not silent.
    """
    if fingerprint is None or fingerprint == NO_BASELINE_FINGERPRINT:
        return None
    per_file = {unit: len(nodeids) for unit, nodeids in deselect_by_file.items()}
    return {
        "fingerprint": fingerprint,
        "excluded_units": excluded_units,
        "per_file_deselected": per_file,
        "total_per_file_deselected": sum(per_file.values()),
    }
