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
    "flags": metadata_std.FLAG_NAMES,
}

_ALIASES = {
    "attr": "attrs",
    "attribute": "attrs",
    "attributes": "attrs",
    "mechanism": "mechanisms",
    "key_type": "key_types",
    "object_class": "object_classes",
    "rv": "rvs",
    "flag": "flags",
}

_STANDARD_MECHANISM_NAMES = set(_STANDARD_TABLES["mechanisms"].values())


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
        if not isinstance(key, (int, str)):
            raise ValueError(f"helper keys must be int or str, got {type(key).__name__}")
        if isinstance(key, int) and key in _STANDARD_TABLES["mechanisms"]:
            raise ValueError(
                f"standard mechanism ids are not allowed in extension helpers: 0x{key:08x}"
            )


def _validate_name_mapping(
    category: str,
    mapping: Mapping[int, str] | None,
    *,
    namespace: str,
) -> None:
    if not mapping:
        return
    for key in mapping:
        if not isinstance(key, int):
            raise ValueError(f"name mapping keys must be int, got {type(key).__name__}")
        if not isinstance(mapping[key], str):
            raise ValueError(f"name mapping values must be str, got {type(mapping[key]).__name__}")
        if category == "mechanisms" and mapping[key] in _STANDARD_MECHANISM_NAMES:
            raise ValueError("standard mechanism names are not allowed in vendor extensions")
        if key in _STANDARD_TABLES[category]:
            if category == "mechanisms":
                raise ValueError(
                    f"standard mechanism ids are not allowed in vendor extensions: 0x{key:08x}"
                )
            raise ValueError(
                f"standard symbol ids are not allowed in vendor extensions: 0x{key:08x}"
            )
    if category != "mechanisms":
        return
    vendor = _vendor_or_none(namespace)
    if vendor is not None:
        for key, value in mapping.items():
            existing = vendor.names["mechanisms"].get(key)
            if existing is not None and existing != value:
                raise ValueError("mechanism id already mapped in namespace")
    existing_names = set(vendor.names["mechanisms"].values()) if vendor is not None else set()
    new_names = list(mapping.values())
    if len(new_names) != len(set(new_names)):
        raise ValueError("duplicate mechanism name in namespace")
    if existing_names.intersection(new_names):
        raise ValueError("duplicate mechanism name in namespace")


def _validate_namespace_mapping_update(
    existing: Mapping[Any, Any], new_values: Mapping[Any, Any] | None
) -> None:
    if not new_values:
        return
    for key, value in new_values.items():
        if key in existing and existing[key] != value:
            raise ValueError("existing namespace entry differs")


def _validate_helper_alias_consistency(
    namespace: str,
    helper_type: str,
    mechanisms: Mapping[int, str] | None,
    helpers: Mapping[int | str, Any] | None,
) -> None:
    if not helpers:
        return
    vendor = _vendor_or_none(namespace)
    mechanism_names: dict[int, str] = {}
    if vendor is not None:
        mechanism_names.update(vendor.names["mechanisms"])
    if mechanisms is not None:
        mechanism_names.update(mechanisms)

    resolved: dict[int, Any] = {}
    for key, value in helpers.items():
        mechanism_id: int | None
        if isinstance(key, int):
            mechanism_id = key
        elif isinstance(key, str):
            mechanism_id = next(
                (
                    candidate_id
                    for candidate_id, candidate_name in mechanism_names.items()
                    if candidate_name == key
                ),
                None,
            )
            if mechanism_id is None:
                continue
        else:
            continue
        if mechanism_id in resolved and resolved[mechanism_id] != value:
            raise ValueError("conflicting helper registration")
        resolved[mechanism_id] = value

    existing_helpers = None
    if vendor is not None:
        existing_helpers = vendor.packers if helper_type == "packers" else vendor.inspectors
    if existing_helpers is None:
        return
    for mechanism_id, helper in resolved.items():
        mechanism_name = mechanism_names.get(mechanism_id)
        existing_numeric = existing_helpers.get(mechanism_id)
        existing_symbolic = (
            existing_helpers.get(mechanism_name) if mechanism_name is not None else None
        )
        for existing in (existing_numeric, existing_symbolic):
            if existing is not None and existing != helper:
                raise ValueError("existing namespace entry differs")


def register_extension(
    *,
    namespace: str,
    mechanisms: Mapping[int, str] | None = None,
    attrs: Mapping[int, str] | None = None,
    key_types: Mapping[int, str] | None = None,
    object_classes: Mapping[int, str] | None = None,
    rvs: Mapping[int, str] | None = None,
    flags: Mapping[int, str] | None = None,
    structs: Mapping[str, Any] | None = None,
    packers: Mapping[int | str, Any] | None = None,
    inspectors: Mapping[int | str, Any] | None = None,
) -> None:
    """Register vendor-specific names and helper objects."""
    _validate_name_mapping("mechanisms", mechanisms, namespace=namespace)
    _validate_name_mapping("attrs", attrs, namespace=namespace)
    _validate_name_mapping("key_types", key_types, namespace=namespace)
    _validate_name_mapping("object_classes", object_classes, namespace=namespace)
    _validate_name_mapping("rvs", rvs, namespace=namespace)
    _validate_name_mapping("flags", flags, namespace=namespace)
    _validate_helper_numeric_keys(packers)
    _validate_helper_numeric_keys(inspectors)
    _validate_helper_string_keys(namespace, packers, mechanisms)
    _validate_helper_string_keys(namespace, inspectors, mechanisms)
    _validate_helper_alias_consistency(namespace, "packers", mechanisms, packers)
    _validate_helper_alias_consistency(namespace, "inspectors", mechanisms, inspectors)
    vendor = _vendor(namespace)
    name_mappings = {
        "mechanisms": mechanisms,
        "attrs": attrs,
        "key_types": key_types,
        "object_classes": object_classes,
        "rvs": rvs,
        "flags": flags,
    }
    for category, values in name_mappings.items():
        if values is not None:
            _validate_namespace_mapping_update(vendor.names[category], values)
    _validate_namespace_mapping_update(vendor.structs, structs)
    _validate_namespace_mapping_update(vendor.packers, packers)
    _validate_namespace_mapping_update(vendor.inspectors, inspectors)
    for category, values in name_mappings.items():
        if values is not None:
            vendor.names[category].update(values)
    if structs is not None:
        vendor.structs.update(structs)
    if packers is not None:
        vendor.packers.update(packers)
    if inspectors is not None:
        vendor.inspectors.update(inspectors)


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
        direct = helpers.get(value)
        if direct is not None:
            return direct
        mechanism_id = next(
            (
                candidate_id
                for candidate_id, candidate_name in vendor.names["mechanisms"].items()
                if candidate_name == value
            ),
            None,
        )
        if mechanism_id is None:
            return None
        return helpers.get(mechanism_id)
    if value in helpers:
        return helpers[value]
    symbol = vendor.names["mechanisms"].get(value)
    if symbol is None:
        return None
    return helpers.get(symbol)


def _lookup_helper(category: str, value: int | str, *, namespace: str | None = None) -> Any | None:
    """Look up a vendor-registered helper (packer or inspector) by mechanism."""
    if namespace is not None:
        vendor = _vendor_or_none(namespace)
        if vendor is None:
            return None
        return _lookup_vendor_helper(vendor, category, value)
    matches: list[tuple[str, Any]] = [
        (vendor_name, helper)
        for vendor_name, vendor in _EXTENSIONS.items()
        if (helper := _lookup_vendor_helper(vendor, category, value)) is not None
    ]
    if isinstance(value, int) and len(matches) != 1:
        return None
    return _lookup_single_namespace(matches)


def lookup_packer(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Look up a mechanism parameter packer function."""
    return _lookup_helper("packers", value, namespace=namespace)


def lookup_inspector(value: int | str, *, namespace: str | None = None) -> Any | None:
    """Look up a mechanism parameter inspector function."""
    return _lookup_helper("inspectors", value, namespace=namespace)


__all__ = [
    "ExtensionNamespace",
    "clear_extensions",
    "lookup_inspector",
    "lookup_packer",
    "lookup_struct",
    "lookup_symbol_name",
    "register_extension",
]
