"""Human-readable rendering helpers for raw PKCS#11 values."""

from __future__ import annotations

from .extensions import lookup_symbol_name
from .pack import PackedMechanism


def _render_symbol(namespace: str, value: int) -> str:
    return lookup_symbol_name(namespace, value) or f"0x{value:08x}"


def render_mechanism(mechanism: PackedMechanism) -> str:
    """Render a packed mechanism using symbolic naming when available."""
    name = _render_symbol("mechanisms", int(mechanism.ck.mechanism))
    return f"{name} (0x{int(mechanism.ck.mechanism):08x}, len={int(mechanism.ck.ulParameterLen)})"
