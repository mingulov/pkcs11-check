"""Extension name registry layered on top of generated PKCS#11 metadata."""

from __future__ import annotations

from collections.abc import Mapping

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

_EXTENSIONS: dict[str, dict[int, str]] = {name: {} for name in _STANDARD_TABLES}


def _canonical_namespace(namespace: str) -> str:
    key = namespace.strip().lower()
    return _ALIASES.get(key, key)


def register_extension(
    *,
    namespace: str,
    mechanisms: Mapping[int, str] | None = None,
    attrs: Mapping[int, str] | None = None,
    key_types: Mapping[int, str] | None = None,
    object_classes: Mapping[int, str] | None = None,
    rvs: Mapping[int, str] | None = None,
) -> None:
    """Register vendor-specific symbolic names for later rendering."""
    if not namespace.strip():
        raise ValueError("namespace must be non-empty")

    mappings = {
        "mechanisms": mechanisms,
        "attrs": attrs,
        "key_types": key_types,
        "object_classes": object_classes,
        "rvs": rvs,
    }
    for category, values in mappings.items():
        if values is None:
            continue
        _EXTENSIONS[category].update(values)


def lookup_symbol_name(namespace: str, value: int) -> str | None:
    """Return a standard or registered symbolic name for a numeric identifier."""
    category = _canonical_namespace(namespace)
    standard = _STANDARD_TABLES.get(category)
    if standard is None:
        raise KeyError(f"Unknown symbol namespace: {namespace}")
    return _EXTENSIONS[category].get(value, standard.get(value))
