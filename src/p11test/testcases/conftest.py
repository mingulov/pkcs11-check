"""Shared fixtures for p11test PKCS#11 test cases.

Note: Test skipping for missing module, version, and destructive markers
is handled in plugin.py's pytest_collection_modifyitems hook.
"""

from __future__ import annotations

from typing import Any


def mech_name(m: Any) -> str:
    """Get mechanism name safely — handles both Mechanism enum and raw int."""
    name = getattr(m, "name", None)
    if isinstance(name, str):
        return name
    if name is not None:
        return str(name)
    if isinstance(m, int):
        return f"0x{m:08x}"
    return str(m)
