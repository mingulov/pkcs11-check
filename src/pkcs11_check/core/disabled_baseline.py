"""Resolve the disabled-tests baseline for any command that selects tests (GH #6).

``test`` resolved the baseline inline (config value, else auto-discovery, else none) while
``list-tests`` did not resolve it at all, so the two commands disagreed about which
node-ids are in play -- and list-tests exists precisely to build those baseline files.
One resolver, used by both, so they cannot drift again.
"""

from __future__ import annotations

from pathlib import Path

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
