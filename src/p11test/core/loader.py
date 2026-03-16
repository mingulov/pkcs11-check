"""PKCS#11 module loading and interface negotiation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pkcs11

# Alias to allow mocking in tests
pkcs11_lib = pkcs11.lib


@dataclass
class P11Module:
    """A loaded PKCS#11 module with negotiated interface."""

    path: Path
    lib: Any  # pkcs11.Lib
    interface_version: str = "2.40"

    def get_slots(self, token_present: bool = False) -> list[Any]:
        """Return available slots."""
        return self.lib.get_slots(token_present=token_present)  # type: ignore[no-any-return]

    def get_token(self, slot_index: int = 0) -> Any:
        """Return the token at the given slot index."""
        slots = self.get_slots(token_present=True)
        if slot_index >= len(slots):
            msg = f"Slot {slot_index} not found (available: {len(slots)})"
            raise IndexError(msg)
        return slots[slot_index].get_token()


def load_module(
    path: Path,
    interface: str = "auto",
) -> P11Module:
    """Load a PKCS#11 module and negotiate the interface version.

    For Phase 1, only v2.40 (C_GetFunctionList) is supported.
    v3.0/v3.2 negotiation will be added with the python-pkcs11 fork.
    """
    if not path.exists():
        msg = f"Module not found: {path}"
        raise FileNotFoundError(msg)

    if interface not in ("auto", "2.40"):
        msg = f"Interface v{interface} not supported yet (v2.40 only in Phase 1)"
        raise RuntimeError(msg)

    lib = pkcs11_lib(str(path))

    return P11Module(
        path=path,
        lib=lib,
        interface_version="2.40",
    )
