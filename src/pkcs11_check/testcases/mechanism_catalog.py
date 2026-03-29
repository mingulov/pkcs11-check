"""Mechanism catalog for test parametrization.

Built from CapabilityManifest + MechanismRegistry. Provides filtered
lists of (mech_id, mech_name, info, config) tuples for pytest parametrization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pkcs11_check.raw.metadata_std import MECHANISM_NAMES
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY, MechConfig


@dataclass
class MechEntry:
    """A single mechanism entry with runtime info + registry config."""

    mech_id: int
    mech_name: str
    flags: int
    min_key_size: int
    max_key_size: int
    config: MechConfig | None  # None for unregistered/vendor mechanisms


class MechanismCatalog:
    """Catalog of mechanisms available on the current module."""

    def __init__(self, entries: dict[int, MechEntry]) -> None:
        self._entries = entries

    @classmethod
    def from_manifest(cls, manifest: Any) -> MechanismCatalog:
        """Build from a CapabilityManifest with mechanism_info."""
        entries: dict[int, MechEntry] = {}
        mech_info = getattr(manifest, "mechanism_info", {}) or {}

        # Build reverse map: name → int (accept both "CKM_AES_CBC" and "AES_CBC")
        name_to_id: dict[str, int] = {}
        for mid, mname in MECHANISM_NAMES.items():
            name_to_id[mname] = mid
            short = mname.removeprefix("CKM_")
            if short != mname:
                name_to_id[short] = mid

        for mname, info in mech_info.items():
            mech_id = name_to_id.get(mname)
            if mech_id is None:
                continue
            config = MECHANISM_REGISTRY.get(mech_id)
            entries[mech_id] = MechEntry(
                mech_id=mech_id,
                mech_name=mname,
                flags=info.get("flags", 0),
                min_key_size=info.get("min_key_size", 0),
                max_key_size=info.get("max_key_size", 0),
                config=config,
            )
        return cls(entries)

    def filter_by_flag(self, flag: int) -> list[MechEntry]:
        """Return entries where flags & flag is non-zero."""
        return [e for e in self._entries.values() if e.flags & flag]

    def filter_registered(self, flag: int) -> list[MechEntry]:
        """Return entries with flag AND a registry config."""
        return [
            e
            for e in self._entries.values()
            if (e.flags & flag) and e.config is not None
        ]

    def filter_for_scenario(self, scenario: str) -> list[MechEntry]:
        """Return entries selected for a semantic scenario."""
        from pkcs11_check.testcases.mechanism_selection import select_for_scenario

        return [
            entry
            for entry in self._entries.values()
            if select_for_scenario(entry, scenario).selected
        ]

    def filter_unregistered(self) -> list[MechEntry]:
        """Return entries with no registry config (vendor/unknown)."""
        return [e for e in self._entries.values() if e.config is None]

    def all_entries(self) -> list[MechEntry]:
        return list(self._entries.values())

    def get(self, mech_id: int) -> MechEntry | None:
        return self._entries.get(mech_id)
