"""pkcs11-check list-tests command - enumerate node-ids matching a selection.

Prints matching pytest node-ids one per line to stdout (pipeable into a disabled-tests
file); count and diagnostics go to stderr. Collection-only: no provider run.
"""

from __future__ import annotations

from pathlib import Path

from pkcs11_check.cli.test_cmd import _TESTCASES_DIR, _combine_marker
from pkcs11_check.core.file_runner import collect_pytest_nodeids


def _build_list_selection_args(
    *,
    match: str | None,
    marker: str | None,
    category: str | None,
    skip_slow: bool,
    only_slow: bool,
    module: Path | None,
    interface: str,
    slot: int,
) -> list[str]:
    """Build the pytest args for the collection subprocess (module trio + -m/-k selection)."""
    args: list[str] = []
    if module is not None:
        args += ["--p11-module", str(module), "--p11-interface", interface, "--p11-slot", str(slot)]
    combined_marker = _combine_marker(marker, skip_slow=skip_slow, only_slow=only_slow)
    if combined_marker:
        args += ["-m", combined_marker]
    if match:
        args += ["-k", match]
    elif category:
        args += ["-k", category]
    return args


def enumerate_nodeids(
    targets: list[str],
    *,
    match: str | None,
    marker: str | None,
    category: str | None,
    skip_slow: bool,
    only_slow: bool,
    module: Path | None,
    interface: str,
    slot: int,
) -> list[str]:
    """Collect node-ids matching the selection, sorted and de-duplicated.

    Empty ``targets`` defaults to the testcases dir. Raises ValueError on a pytest
    collection error (propagated from collect_pytest_nodeids)."""
    collect_targets = targets or [_TESTCASES_DIR]
    args = _build_list_selection_args(
        match=match,
        marker=marker,
        category=category,
        skip_slow=skip_slow,
        only_slow=only_slow,
        module=module,
        interface=interface,
        slot=slot,
    )
    return sorted(set(collect_pytest_nodeids(collect_targets, args)))
