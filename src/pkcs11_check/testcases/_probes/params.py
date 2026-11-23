"""Typed probe parameters, passed parent -> child as a JSON file (never the PIN)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Any key containing one of these substrings (case-insensitive) in a params
# object is a credential leak attempt (Invariant I3): the PIN travels only via
# the _P11CHECK_PIN env var, never serialized into params/argv/source.
# Substring (S8), not exact spelling, so respellings (userPin, token_pin,
# P11TEST_PIN, password, ...) cannot smuggle credentials past the guard.
# Verified safe: no legitimate probe-read key contains these substrings
# (96-key survey of the _probes tree; only _P11CHECK_PIN itself hits, and
# that name must never appear as a params key either). `passwd` extends the
# review's triple: the standard credential abbreviation, same reasoning.
# Known tradeoff: an innocent future key containing one of these (e.g. a
# hypothetical `wrapping_mech`) fails LOUDLY here at development time and
# must be renamed -- fail-closed by design, never a silent leak.
_PIN_SUBSTRINGS: tuple[str, ...] = ("pin", "password", "passwd", "secret")


class PinInParamsError(ValueError):
    """Raised when probe params carry a PIN-bearing key."""


def _check_no_pin(data: Mapping[str, Any]) -> None:
    """Reject a PIN-bearing key at ANY depth (I3), not just the top level.

    Params can nest under ``extra`` (and lists therein), and the whole object is serialized to
    the temp params file, so the check must recurse to be a real guarantee, not a top-level one.
    """

    def _walk(obj: Any) -> None:
        if isinstance(obj, Mapping):
            leaked = sorted(
                k
                for k in obj
                if isinstance(k, str) and any(sub in k.lower() for sub in _PIN_SUBSTRINGS)
            )
            if leaked:
                # Do NOT include the value (it could be the PIN); name the keys only.
                raise PinInParamsError(
                    f"credential-bearing keys forbidden in probe params: {leaked}"
                )
            for value in obj.values():
                _walk(value)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                _walk(item)

    _walk(data)


@dataclass(frozen=True)
class ProbeParams:
    module_path: str
    slot_id: int | None = None
    slot_label: str | None = None
    interface: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def dump(cls, params: Mapping[str, Any]) -> dict[str, Any]:
        """Validate a params mapping for serialization (parent side). Rejects PIN keys."""
        _check_no_pin(params)
        if "module_path" not in params:
            raise ValueError("probe params must include 'module_path'")
        return dict(params)

    @classmethod
    def load(cls, path: str) -> ProbeParams:
        """Load + validate params from a JSON file (child side). Rejects PIN keys."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("probe params JSON must be a JSON object")
        _check_no_pin(data)
        if "module_path" not in data:
            raise ValueError("probe params must include 'module_path'")
        if "extra" in data and not isinstance(data["extra"], dict):
            raise ValueError("probe params 'extra' must be an object")
        known = {"module_path", "slot_id", "slot_label", "interface", "extra"}
        extra = {k: v for k, v in data.items() if k not in known}
        if "extra" in data and isinstance(data["extra"], dict):
            extra.update(data["extra"])
        return cls(
            module_path=data["module_path"],
            slot_id=data.get("slot_id"),
            slot_label=data.get("slot_label"),
            interface=data.get("interface"),
            extra=extra,
        )
