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
    packers: dict[int | str, Any] = field(default_factory=dict)
    inspectors: dict[int | str, Any] = field(default_factory=dict)


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


def _vendor_or_none(namespace: str) -> ExtensionNamespace | None:
    key = _canonical_vendor_namespace(namespace)
    return _EXTENSIONS.get(key)


def clear_extensions(namespace: str | None = None) -> None:
    """Clear all extension registrations or a single vendor namespace."""
    if namespace is None:
        _EXTENSIONS.clear()
        return
    key = _canonical_vendor_namespace(namespace)
    _EXTENSIONS.pop(key, None)


def _validate_helper_string_keys(
    namespace: str,
    keys: Mapping[int | str, Any] | None,
    same_call_mechanisms: Mapping[int, str] | None,
) -> None:
    if not keys:
        return
    vendor = _vendor_or_none(namespace)
    vendor_names = set(vendor.names["mechanisms"].values()) if vendor is not None else set()
    if same_call_mechanisms is not None:
        vendor_names.update(same_call_mechanisms.values())
    for key in keys:
        if isinstance(key, str) and key not in vendor_names:
            raise ValueError(f"unknown vendor mechanism helper key: {key}")


def _validate_helper_numeric_keys(keys: Mapping[int | str, Any] | None) -> None:
    if not keys:
        return
    for key in keys:
        if isinstance(key, int) and key in _STANDARD_TABLES["mechanisms"]:
            raise ValueError(f"standard mechanism ids are not allowed in extension helpers: 0x{key:08x}")


def _validate_vendor_mechanism_ids(mechanisms: Mapping[int, str] | None) -> None:
    if not mechanisms:
        return
    for mechanism_id in mechanisms:
        if mechanism_id in _STANDARD_TABLES["mechanisms"]:
            raise ValueError(
                f"standard mechanism ids are not allowed in vendor extensions: 0x{mechanism_id:08x}"
            )


def register_extension(
    *,
    namespace: str,
    mechanisms: Mapping[int, str] | None = None,
    attrs: Mapping[int, str] | None = None,
    key_types: Mapping[int, str] | None = None,
    object_classes: Mapping[int, str] | None = None,
    rvs: Mapping[int, str] | None = None,
    structs: Mapping[str, Any] | None = None,
    packers: Mapping[int | str, Any] | None = None,
    inspectors: Mapping[int | str, Any] | None = None,
) -> None:
    """Register vendor-specific names and helper objects."""
    _validate_vendor_mechanism_ids(mechanisms)
    _validate_helper_numeric_keys(packers)
    _validate_helper_numeric_keys(inspectors)
    _validate_helper_string_keys(namespace, packers, mechanisms)
    _validate_helper_string_keys(namespace, inspectors, mechanisms)
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


def _lookup_single_namespace(matches: list[tuple[str, Any]]) -> Any | None:
    if len(matches) != 1:
        return None
    return matches[0][1]


def lookup_symbol_name(category: str, value: int, *, namespace: str | None = None) -> str | None:
    """Return a standard or vendor-registered symbolic name for a numeric identifier."""
    symbol_category = _canonical_symbol_namespace(category)
    standard = _STANDARD_TABLES.get(symbol_category)
    if standard is None:
        raise KeyError(f"Unknown symbol namespace: {category}")
    if value in standard:
        return standard[value]
    if namespace is not None:
        vendor = _vendor_or_none(namespace)
        if vendor is None:
            return None
        return vendor.names[symbol_category].get(value)
    matches = [
        (vendor_name, vendor.names[symbol_category][value])
        for vendor_name, vendor in _EXTENSIONS.items()
        if value in vendor.names[symbol_category]
    ]
    return _lookup_single_namespace(matches)


def lookup_struct(name: str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension struct by namespace or by unique global match."""
    if namespace is not None:
        vendor = _vendor_or_none(namespace)
        if vendor is None:
            return None
        return vendor.structs.get(name)
    matches = [
        (vendor_name, vendor.structs[name])
        for vendor_name, vendor in _EXTENSIONS.items()
        if name in vendor.structs
    ]
    return _lookup_single_namespace(matches)


def _lookup_vendor_helper(
    vendor: ExtensionNamespace,
    helper_type: str,
    value: int | str,
) -> Any | None:
    helpers = vendor.packers if helper_type == "packers" else vendor.inspectors
    if isinstance(value, str):
        return helpers.get(value)
    if value in helpers:
        return helpers[value]
    symbol = vendor.names["mechanisms"].get(value)
    if symbol is None:
        return None
    return helpers.get(symbol)


def _vendor_knows_mechanism_id(vendor: ExtensionNamespace, value: int) -> bool:
    return (
        value in vendor.names["mechanisms"]
        or value in vendor.packers
        or value in vendor.inspectors
    )


def lookup_packer(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension packer by namespace or by unique global match."""
    if namespace is not None:
        vendor = _vendor_or_none(namespace)
        if vendor is None:
            return None
        return _lookup_vendor_helper(vendor, "packers", value)
    if isinstance(value, int):
        matching_vendors = [
            (vendor_name, vendor)
            for vendor_name, vendor in _EXTENSIONS.items()
            if _vendor_knows_mechanism_id(vendor, value)
        ]
        if len(matching_vendors) != 1:
            return None
        return _lookup_vendor_helper(matching_vendors[0][1], "packers", value)
    matches = [
        (vendor_name, helper)
        for vendor_name, vendor in _EXTENSIONS.items()
        if (helper := _lookup_vendor_helper(vendor, "packers", value)) is not None
    ]
    return _lookup_single_namespace(matches)


def lookup_inspector(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Return a registered extension inspector by namespace or by unique global match."""
    if namespace is not None:
        vendor = _vendor_or_none(namespace)
        if vendor is None:
            return None
        return _lookup_vendor_helper(vendor, "inspectors", value)
    if isinstance(value, int):
        matching_vendors = [
            (vendor_name, vendor)
            for vendor_name, vendor in _EXTENSIONS.items()
            if _vendor_knows_mechanism_id(vendor, value)
        ]
        if len(matching_vendors) != 1:
            return None
        return _lookup_vendor_helper(matching_vendors[0][1], "inspectors", value)
    matches = [
        (vendor_name, helper)
        for vendor_name, vendor in _EXTENSIONS.items()
        if (helper := _lookup_vendor_helper(vendor, "inspectors", value)) is not None
    ]
    return _lookup_single_namespace(matches)
