"""Namespace-isolated extension registry for raw PKCS#11 helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import metadata_std

_STANDARD_TABLES = {
    "attrs": metadata_std.ATTR_NAMES,
    "mechanisms": metadata_std.MECHANISM_NAMES,
    "key_types": metadata_std.KEY_TYPE_NAMES,
    "object_classes": metadata_std.OBJECT_CLASS_NAMES,
    "rvs": metadata_std.RV_NAMES,
}

_ALIASES = {
    "attr": "attrs",
    "attribute": "attrs",
    "attributes": "attrs",
    "mechanism": "mechanisms",
    "key_type": "key_types",
    "object_class": "object_classes",
    "rv": "rvs",
}


@dataclass
class ExtensionNamespace:
    """One vendor namespace worth of extension registrations."""

    names: dict[str, dict[int, str]] = field(
        default_factory=lambda: {category: {} for category in _STANDARD_TABLES}
    )
    structs: dict[str, Any] = field(default_factory=dict)
    packers: dict[str, Any] = field(default_factory=dict)
    inspectors: dict[str, Any] = field(default_factory=dict)


_EXTENSIONS: dict[str, ExtensionNamespace] = {}


def _canonical_symbol_namespace(namespace: str) -> str:
    key = namespace.strip().lower()
    return _ALIASES.get(key, key)


def _canonical_vendor_namespace(namespace: str) -> str:
    key = namespace.strip().lower()
    if not key:
        raise ValueError("namespace must be non-empty")
    return key


def _vendor(namespace: str) -> ExtensionNamespace:
    key = _canonical_vendor_namespace(namespace)
    return _EXTENSIONS.setdefault(key, ExtensionNamespace())


def register_extension(
    *,
    namespace: str,
    mechanisms: Mapping[int, str] | None = None,
    attrs: Mapping[int, str] | None = None,
    key_types: Mapping[int, str] | None = None,
    object_classes: Mapping[int, str] | None = None,
    rvs: Mapping[int, str] | None = None,
    structs: Mapping[str, Any] | None = None,
    packers: Mapping[str, Any] | None = None,
    inspectors: Mapping[str, Any] | None = None,
) -> None:
    """Register vendor-specific names and helper objects."""
    vendor = _vendor(namespace)
    name_mappings = {
        "mechanisms": mechanisms,
        "attrs": attrs,
        "key_types": key_types,
        "object_classes": object_classes,
        "rvs": rvs,
    }
    for category, values in name_mappings.items():
        if values is not None:
            vendor.names[category].update(values)
    if structs is not None:
        vendor.structs.update(structs)
    if packers is not None:
        vendor.packers.update(packers)
    if inspectors is not None:
        vendor.inspectors.update(inspectors)


def _lookup_unique(values: list[Any]) -> Any | None:
    if not values:
        return None
    first = values[0]
    if all(value == first for value in values[1:]):
        return first
    return None


def lookup_symbol_name(category: str, value: int, *, namespace: str | None = None) -> str | None:
    """Return a standard or vendor-registered symbolic name for a numeric identifier."""
    symbol_category = _canonical_symbol_namespace(category)
    standard = _STANDARD_TABLES.get(symbol_category)
    if standard is None:
        raise KeyError(f"Unknown symbol namespace: {category}")
    if value in standard:
        return standard[value]
    if namespace is not None:
        return _vendor(namespace).names[symbol_category].get(value)
    matches = [
        vendor.names[symbol_category][value]
        for vendor in _EXTENSIONS.values()
        if value in vendor.names[symbol_category]
    ]
    return _lookup_unique(matches)


def lookup_struct(name: str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension struct by namespace or by unique global match."""
    if namespace is not None:
        return _vendor(namespace).structs.get(name)
    matches = [vendor.structs[name] for vendor in _EXTENSIONS.values() if name in vendor.structs]
    return _lookup_unique(matches)


def lookup_packer(name: str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension packer by namespace or by unique global match."""
    if namespace is not None:
        return _vendor(namespace).packers.get(name)
    matches = [vendor.packers[name] for vendor in _EXTENSIONS.values() if name in vendor.packers]
    return _lookup_unique(matches)


def lookup_inspector(name: str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension inspector by namespace or by unique global match."""
    if namespace is not None:
        return _vendor(namespace).inspectors.get(name)
    matches = [vendor.inspectors[name] for vendor in _EXTENSIONS.values() if name in vendor.inspectors]
    return _lookup_unique(matches)
