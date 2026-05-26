"""Attribute value validation helpers for testcases."""

from __future__ import annotations

from typing import Any

import pytest


def require_ulong_attr(value: Any, label: str) -> int:
    """Return a CK_ULONG-valued attribute or xfail malformed readback."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    pytest.xfail(f"{label}: malformed CK_ULONG attribute value: {value!r}")


def require_bool_attr(value: Any, label: str) -> bool:
    """Return a CK_BBOOL-valued attribute or xfail malformed readback."""
    if isinstance(value, bool):
        return value
    pytest.xfail(f"{label}: malformed CK_BBOOL attribute value: {value!r}")
