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

# G3: key types for which a CKA_VALUE_LEN variant is permitted in a C_UnwrapKey template.
# Restricted to CKK_GENERIC_SECRET: NSS *requires* CKA_VALUE_LEN for a variable-length generic
# secret, while modules that derive the length from the blob (softhsm2/opencryptoki) reject it
# as CKR_ATTRIBUTE_READ_ONLY. For CKK_AES, softhsm2 rejects CKA_VALUE_LEN outright (probed
# 2026-06-09) and opencryptoki does not require it, so AES is deliberately excluded.
VALUE_LEN_ON_UNWRAP_OK: frozenset[int] = frozenset({int(CKK_GENERIC_SECRET)})

# G3: mechanisms whose recovered length is unambiguously determined, so a supplied
# CKA_VALUE_LEN is a redundant restatement (rejected on conflict), not a truncation control.
# Excludes every C_DeriveKey length-bearing mech (ECDH1_DERIVE, HKDF, PBKDF2) and every *_PAD
# unwrap mech by omission -- there CKA_VALUE_LEN IS the length control and present-vs-absent
# changes the output, so the per-MECHANISM gate keeps derive/PAD out.
MECH_DETERMINED_LENGTH: frozenset[int] = frozenset(
    {int(CKM_AES_KEY_WRAP), int(CKM_AES_KEY_WRAP_KWP)}
)


def value_len_variant_allowed(key_type: int, mechanism: int) -> bool:
    """G3: a CKA_VALUE_LEN variant is only permitted for an allowlisted (key_type, mech).

    Both gates must pass: the key type must permit CKA_VALUE_LEN on unwrap, AND the mechanism
    must determine the recovered length. The mechanism gate is what excludes derive/PAD mechs
    (where CKA_VALUE_LEN controls output length) even when the target key type is allowlisted.
    """
    return int(key_type) in VALUE_LEN_ON_UNWRAP_OK and int(mechanism) in MECH_DETERMINED_LENGTH


def negotiate_request[T](
    attempt: Callable[[Mapping[int, Any]], T],
    variants: Sequence[Mapping[int, Any]],
    *,
    label: str,
    shape_rejects: Sequence[int] = TEMPLATE_SHAPE_REJECTS,
) -> tuple[T, int]:
    """Try spec-equivalent request variants against the live module, canonical-first.

    variants[0] MUST be the most spec-conformant request (G1). attempt runs the operation
    with one variant's template/param delta and returns its result or raises a
    CkrAssertionError. Returns (result, winning_index). Retries to the next variant ONLY on
    a clean template-shape reject (G2); any other rejection propagates immediately. If every
    variant is shape-rejected, the last exception is re-raised. Positive ops only (G6);
    single-shot recipe ops only (G5).

    shape_rejects is the per-call-site set of clean rejects that mean "request shape",
    not "operation failed". The default stays the narrow template set; widening it is a
    per-site decision (e.g. C_CreateObject storage-shape rejects) so codes that are real
    findings at one site never become retryable everywhere.
    """
    last_exc: CkrAssertionError | None = None
    for idx, delta in enumerate(variants):
        try:
            return attempt(delta), idx
        except CkrAssertionError as exc:
            if exc.rv not in shape_rejects:
                raise
            last_exc = exc
    assert last_exc is not None
    raise last_exc
