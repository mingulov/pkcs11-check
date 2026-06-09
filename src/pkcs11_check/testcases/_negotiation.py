"""Request negotiation (Pillar 1): adapt a positive request to a module's accepted shape.

The module's own clean reject tells us our request shape is wrong; we retry with a
spec-equivalent variant. No provider identity. See the design spec, guardrails G1-G6.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKK_GENERIC_SECRET,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

TEMPLATE_SHAPE_REJECTS: tuple[int, ...] = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
)

VALUE_LEN_ON_UNWRAP_OK: frozenset[int] = frozenset({int(CKK_GENERIC_SECRET)})

MECH_DETERMINED_LENGTH: frozenset[int] = frozenset(
    {int(CKM_AES_KEY_WRAP), int(CKM_AES_KEY_WRAP_KWP)}
)


def value_len_variant_allowed(key_type: int, mechanism: int) -> bool:
    """G3: a CKA_VALUE_LEN variant is only permitted for an allowlisted (key_type, mech)."""
    return int(key_type) in VALUE_LEN_ON_UNWRAP_OK and int(mechanism) in MECH_DETERMINED_LENGTH


def negotiate_request[T](
    attempt: Callable[[Mapping[int, Any]], T],
    variants: Sequence[Mapping[int, Any]],
    *,
    label: str,
) -> tuple[T, int]:
    """Try spec-equivalent request variants against the live module, canonical-first.

    variants[0] MUST be the most spec-conformant request (G1). attempt runs the operation
    with one variant's template/param delta and returns its result or raises a
    CkrAssertionError. Returns (result, winning_index). Retries to the next variant ONLY on
    a clean template-shape reject (G2); any other rejection propagates immediately. If every
    variant is shape-rejected, the last exception is re-raised. Positive ops only (G6);
    single-shot recipe ops only (G5).
    """
    last_exc: CkrAssertionError | None = None
    for idx, delta in enumerate(variants):
        try:
            return attempt(delta), idx
        except CkrAssertionError as exc:
            if exc.rv not in TEMPLATE_SHAPE_REJECTS:
                raise
            last_exc = exc
    assert last_exc is not None
    raise last_exc
