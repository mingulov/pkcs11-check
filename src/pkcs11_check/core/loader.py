"""PKCS#11 module loading and interface negotiation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pkcs11

# Alias to allow mocking in tests
pkcs11_lib = pkcs11.lib

SUPPORTED_INTERFACES = ("auto", "2.40", "3.0", "3.1", "3.2")


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

    Supports v2.40 (C_GetFunctionList) and v3.0/v3.1/v3.2 (C_GetInterface).
    When ``interface="auto"`` (default), tries v3.2, v3.1, v3.0 in descending
    order, then falls back to v2.40 for modules that do not export
    ``C_GetInterface``.

    :param path: Path to the PKCS#11 shared library.
    :param interface: Requested interface version: ``"auto"``, ``"2.40"``,
        ``"3.0"``, ``"3.1"``, or ``"3.2"``.
    :raises FileNotFoundError: If the module file does not exist.
    :raises ValueError: If ``interface`` is not a recognised value.
    :raises RuntimeError: If the requested interface cannot be negotiated.
    """
    if not path.exists():
        msg = f"Module not found: {path}"
        raise FileNotFoundError(msg)

    if interface not in SUPPORTED_INTERFACES:
        msg = f"Unknown interface {interface!r}; must be one of {SUPPORTED_INTERFACES}"
        raise ValueError(msg)

    lib = pkcs11_lib(str(path), interface=interface)

    return P11Module(
        path=path,
        lib=lib,
        interface_version=lib.interface_version,
    )
