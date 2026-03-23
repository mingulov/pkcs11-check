"""Compatibility wrapper for the raw PKCS#11 API."""

from __future__ import annotations

from .api import RawPKCS11
from .types_std import *  # noqa: F401,F403

CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2

__all__ = [
    "RawPKCS11",
    "CKU_SO",
    "CKU_USER",
    "CKU_CONTEXT_SPECIFIC",
]
__all__ += [name for name in globals() if name.startswith("CK") and name not in __all__]
