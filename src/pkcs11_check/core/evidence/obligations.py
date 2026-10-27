"""Obligation inventory: profile-selected case IDs plus the unselected remainder."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ObligationInventory:
    """Profile-selected obligations plus the catalog remainder.

    ``members``: the profile-selected case IDs — the admission obligations,
    consumed by ``admit_lane``'s ``obligations_executed`` predicate (every
    member must appear as a row node_id, else admission FAILs naming the
    case). ``unselected``: catalog IDs the profile did NOT select. Admission
    surfaces these as ``unselected_obligation`` warnings (warn, never fail),
    so dropped coverage stays visible instead of silently absent.
    """

    members: frozenset[str]
    unselected: frozenset[str] = frozenset()

    def __contains__(self, case_id: object) -> bool:
        """Return True when ``case_id`` is a selected obligation member."""
        return case_id in self.members


def compile_obligations(
    catalog: Mapping[str, Any], profile: Mapping[str, Any]
) -> ObligationInventory:
    """Build the inventory from a case catalog and a selecting profile.

    ``catalog`` maps every known case ID to its entry; ``profile`` selects
    via its exact ``"cases"`` key. Returns members = profile-selected IDs
    and unselected = catalog IDs minus the selection.

    Unknown selected IDs (not in the catalog) raise ``ValueError``, never
    pass silently; so do a missing/non-list ``"cases"`` key and non-mapping
    inputs.
    """
    if not isinstance(catalog, Mapping):
        raise ValueError(f"compile_obligations: catalog is {type(catalog).__name__}, not a mapping")
    if not isinstance(profile, Mapping):
        raise ValueError(f"compile_obligations: profile is {type(profile).__name__}, not a mapping")
    if "cases" not in profile:
        raise ValueError('compile_obligations: profile lacks the exact "cases" key')
    selected = profile["cases"]
    if not isinstance(selected, (list, tuple)) or not all(
        isinstance(case_id, str) for case_id in selected
    ):
        raise ValueError('compile_obligations: profile "cases" is not a list of strings')
    unknown = sorted({case_id for case_id in selected if case_id not in catalog})
    if unknown:
        raise ValueError(f"compile_obligations: profile selects unknown case IDs: {unknown}")
    members = frozenset(selected)
    unselected = frozenset(key for key in catalog if isinstance(key, str) and key not in members)
    return ObligationInventory(members=members, unselected=unselected)
