"""Helpers for ACVP vectors that collapse to one PKCS#11-visible operation."""

from __future__ import annotations

from collections.abc import Callable, Hashable
from typing import Any

import pytest

_DUPLICATE_MARKER = "_pkcs11_duplicate_of"


def mark_duplicate_pkcs11_inputs(
    vectors: list[tuple[str, dict[str, Any]]],
    key_func: Callable[[dict[str, Any]], Hashable],
) -> list[tuple[str, dict[str, Any]]]:
    """Mark vectors whose ACVP-only inputs cannot be supplied through PKCS#11."""
    seen: dict[Hashable, str] = {}
    for vec_id, vec in vectors:
        key = key_func(vec)
        if key in seen:
            vec[_DUPLICATE_MARKER] = seen[key]
        else:
            seen[key] = vec_id
    return vectors


def skip_duplicate_pkcs11_input(vec: dict[str, Any], label: str) -> None:
    """Skip duplicate ACVP vectors after capability checks have passed."""
    duplicate_of = vec.get(_DUPLICATE_MARKER)
    if isinstance(duplicate_of, str):
        pytest.skip(
            f"Duplicate ACVP {label} input; provider-visible parameters covered by {duplicate_of}"
        )
