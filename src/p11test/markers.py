"""pytest marker definitions for p11test."""

from __future__ import annotations

from dataclasses import dataclass

_VERSION_ORDER = {"2.40": 0, "3.0": 1, "3.2": 2}

_MARKER_MIN_VERSION: dict[str, str] = {
    "requires_v30": "3.0",
    "requires_v32": "3.2",
}


@dataclass(frozen=True)
class MarkerDef:
    """A pytest marker registered by p11test."""

    name: str
    description: str


MARKER_DEFINITIONS: list[MarkerDef] = [
    MarkerDef("requires_v30", "Test requires PKCS#11 v3.0 or later"),
    MarkerDef("requires_v32", "Test requires PKCS#11 v3.2 or later"),
    MarkerDef("destructive", "Test modifies token state (requires --p11-destructive)"),
    MarkerDef("pqc", "Post-quantum cryptography test"),
    MarkerDef("slow", "Long-running test"),
    MarkerDef("needs_mechanism", "Test needs a specific PKCS#11 mechanism"),
]


def should_skip_for_version(marker_name: str, interface_version: str) -> bool:
    """Return True if a test with this marker should be skipped for the given version."""
    min_version = _MARKER_MIN_VERSION.get(marker_name)
    if min_version is None:
        return False
    return _VERSION_ORDER.get(interface_version, 0) < _VERSION_ORDER[min_version]
