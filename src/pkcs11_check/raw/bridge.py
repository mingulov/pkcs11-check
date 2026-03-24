"""Bridge helpers from python-pkcs11 loaded libraries to RawPKCS11."""

from __future__ import annotations

from typing import Any

from .api import RawPKCS11


def raw_from_lib(lib: Any) -> RawPKCS11:
    """Build a RawPKCS11 view from a loaded python-pkcs11 library."""
    return RawPKCS11(
        lib._raw_funclist_ptr,
        funclist3_ptr=getattr(lib, "_raw_funclist3_ptr", 0),
        funclist32_ptr=getattr(lib, "_raw_funclist32_ptr", 0),
    )


def raw_from_module(module: Any) -> RawPKCS11:
    """Build a RawPKCS11 view from a pkcs11_check loader module wrapper."""
    return raw_from_lib(module.lib)
