"""Typed probe parameters, passed parent -> child as a JSON file (never the PIN)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Any of these keys in a params object is a PIN leak attempt (Invariant I3): the PIN
# travels only via the _P11CHECK_PIN env var, never serialized into params/argv/source.
PIN_KEYS: frozenset[str] = frozenset(
    {"pin", "PIN", "user_pin", "so_pin", "so_pin_value", "_P11CHECK_PIN"}
)


class PinInParamsError(ValueError):
    """Raised when probe params carry a PIN-bearing key."""


def _check_no_pin(data: Mapping[str, Any]) -> None:
    """Reject a PIN-bearing key at ANY depth (I3), not just the top level.

    Params can nest under ``extra`` (and lists therein), and the whole object is serialized to
    the temp params file, so the check must recurse to be a real guarantee, not a top-level one.
    """

    def _walk(obj: Any) -> None:
        if isinstance(obj, Mapping):
            leaked = PIN_KEYS & set(obj)
            if leaked:
                # Do NOT include the value (it could be the PIN); name the keys only.
                raise PinInParamsError(
                    f"PIN-bearing keys forbidden in probe params: {sorted(leaked)}"
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
        data = json.loads(Path(path).read_text())
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
