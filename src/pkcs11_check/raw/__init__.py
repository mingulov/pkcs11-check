"""Raw PKCS#11 access and helper utilities for pkcs11-check."""

from __future__ import annotations

from . import extensions, metadata_std, recipes, types_std
from .api import RawPKCS11
from .bootstrap import close_session_quietly, get_slot_ids, login_user, open_session
from .bridge import raw_from_lib, raw_from_module
# Removed wildcard import to prevent namespace pollution.
# Existing tests that need standard constants should import them from .types_std.
from .types_std import (
    CK_ATTRIBUTE,
    CK_CONSTANT,
    CK_MECHANISM,
    CKA,
    CKC,
    CKD,
    CKF,
    CKG,
    CKH,
    CKK,
    CKM,
    CKN,
    CKO,
    CKP,
    CKR,
    CKR_OK,
    CKS,
    CKT,
    CKU,
    CKV,
    CKZ,
)

from_lib = raw_from_lib
from_module = raw_from_module

__all__ = [
    "CK_ATTRIBUTE",
    "CK_CONSTANT",
    "CK_MECHANISM",
    "CKA",
    "CKC",
    "CKD",
    "CKF",
    "CKG",
    "CKH",
    "CKK",
    "CKM",
    "CKN",
    "CKO",
    "CKP",
    "CKR",
    "CKR_OK",
    "CKS",
    "CKT",
    "CKU",
    "CKV",
    "CKZ",
    "RawPKCS11",
    "close_session_quietly",
    "get_slot_ids",
    "login_user",
    "metadata_std",
    "types_std",
    "open_session",
    "from_lib",
    "from_module",
    "raw_from_lib",
    "raw_from_module",
    "recipes",
    "extensions",
]
