"""Sentinel-value simulation: run contract tests with a collapsed sentinel.

Activated only when ``PKCS11_CHECK_SIM_LLP64=1`` (see ``tests/conftest.py``).
It patches the *Python int* sentinel constants so the platform spelling of
``CK_UNAVAILABLE_INFORMATION`` equals the 32-bit spelling ``0xFFFFFFFF``,
exactly as on a 4-byte ``CK_ULONG`` host. Value-level verdict logic that
assumes the two spellings are distinct then inverts on Linux, pre-push.

This is a sentinel-VALUE simulation only. It does not resize any ctypes
type or struct, does not truncate field assignments, and loads no DLL --
it is never proof about the real LLP64 ABI, which stays CI-only evidence.

The patch table is census-pinned by ``tests/test_llp64_sim_census.py`` over
the production seam modules plus every file in
``tests/_llp64_sim_files.txt``: a new sentinel consumer there fails the
census rather than silently leaving this simulation partial. Any binding
still holding the uncollapsed value at collection time fails loud here.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType
from typing import Any

COLLAPSED_SENTINEL = 0xFFFFFFFF
_SENTINEL_NAME = "CK_UNAVAILABLE_INFORMATION"

#: (module, attribute) bindings collapsed to the 32-bit spelling. Plain int
#: attributes (``_UNAVAILABLE_64``/``_U64``) receive the int; CK_CONSTANT
#: attributes receive a CK_CONSTANT with the collapsed value.
PATCH_SITES: tuple[tuple[str, str], ...] = (
    ("pkcs11_check.raw.types_std", _SENTINEL_NAME),
    ("pkcs11_check.raw.recipes", _SENTINEL_NAME),
    ("pkcs11_check.testcases.test_sensitivity", _SENTINEL_NAME),
    ("pkcs11_check.testcases.test_sensitivity", "_UNAVAILABLE_64"),
    ("test_byte_kdf_protection_contract", "_U64"),
    ("test_copy_attribute_contract", "_U64"),
    ("test_logout_object_lifetime_contract", "_UNAVAILABLE"),
    ("test_object_policy_effect_contract", "_U64"),
    ("test_protected_component_contract", _SENTINEL_NAME),
    ("test_protected_component_contract", "_U64"),
)

#: Production modules imported eagerly at patch time (before collection, so
#: their ``from types_std import ...`` bindings see the collapsed value).
_EAGER_MODULES = (
    "pkcs11_check.raw.types_std",
    "pkcs11_check.raw.recipes",
    "pkcs11_check.testcases.test_sensitivity",
)

_applied = False


def _collapsed_for(module: ModuleType, attr: str) -> Any:
    current = getattr(module, attr)
    if attr == _SENTINEL_NAME:
        return type(current)(COLLAPSED_SENTINEL, _SENTINEL_NAME)
    return COLLAPSED_SENTINEL


def _patch_module(module: ModuleType) -> list[str]:
    patched: list[str] = []
    for modname, attr in PATCH_SITES:
        if modname != module.__name__ or not hasattr(module, attr):
            continue
        if int(getattr(module, attr)) != COLLAPSED_SENTINEL:
            setattr(module, attr, _collapsed_for(module, attr))
        patched.append(f"{modname}.{attr}")
    return patched


def apply_sim_patch() -> list[str]:
    """Collapse every reachable sentinel binding; return patched sites.

    Idempotent. A patch-site module that is not importable yet (the test
    module itself, before collection) is patched later by
    :func:`patch_collected_modules`; a site whose binding is absent is the
    census test's business (it pins this table against the sources).
    """
    global _applied
    types_std = importlib.import_module("pkcs11_check.raw.types_std")
    patched = _patch_module(types_std)
    for modname in _EAGER_MODULES[1:]:
        patched.extend(_patch_module(importlib.import_module(modname)))
    # Any module imported before us that bound the sentinel by name.
    collapsed = getattr(types_std, _SENTINEL_NAME)
    for module in list(sys.modules.values()):
        if module is None:
            continue
        namespace = getattr(module, "__dict__", None)
        if namespace is not None and _SENTINEL_NAME in namespace:
            if int(namespace[_SENTINEL_NAME]) != COLLAPSED_SENTINEL:
                namespace[_SENTINEL_NAME] = collapsed
                patched.append(f"{module.__name__}.{_SENTINEL_NAME}")
    _applied = True
    return patched


def patch_collected_modules(items: list[Any]) -> None:
    """Patch collected test modules, then assert nothing stayed uncollapsed.

    Called from ``pytest_collection_modifyitems`` (see ``tests/conftest.py``).
    Fails loud when any reachable binding still holds the uncollapsed
    sentinel: a partial simulation would be false confidence.
    """
    if not _applied:
        apply_sim_patch()
    modules: dict[str, ModuleType] = {}
    for item in items:
        module = getattr(item, "module", None)
        if isinstance(module, ModuleType):
            modules[module.__name__] = module
    for module in modules.values():
        _patch_module(module)
    uncollapsed: list[str] = []
    for modname, attr in PATCH_SITES:
        module = sys.modules.get(modname)
        if module is not None and hasattr(module, attr):
            if int(getattr(module, attr)) != COLLAPSED_SENTINEL:
                uncollapsed.append(f"{modname}.{attr}")
    for module in list(sys.modules.values()):
        if module is None:
            continue
        namespace = getattr(module, "__dict__", None)
        if namespace is not None and _SENTINEL_NAME in namespace:
            if int(namespace[_SENTINEL_NAME]) != COLLAPSED_SENTINEL:
                uncollapsed.append(f"{module.__name__}.{_SENTINEL_NAME}")
    if uncollapsed:
        raise RuntimeError(
            "sentinel-value simulation is partial; uncollapsed bindings remain: "
            + ", ".join(sorted(set(uncollapsed)))
        )
