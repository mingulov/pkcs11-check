"""Storage-shape import negotiation (extracted from conftest.py; Tier-4 god-module split).

``create_object_negotiated`` retries spec-equivalent storage variants (unique label, then
token, then dropping benign policy attrs) when a storage-oriented module cleanly rejects the
caller's spec-minimal template, caching the winning variant per template shape. conftest.py
re-exports these names, so ``from ...conftest import create_object_negotiated, ...`` is unchanged.
"""

from __future__ import annotations

import itertools
from collections.abc import Mapping
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
)

# C_CreateObject storage-shape rejects: the template rejects plus the clean codes
# storage-oriented modules use for storage-model constraints (observed on some modules
# 2026-06-09: missing CKA_LABEL -> CKR_ARGUMENTS_BAD, CKA_TOKEN=False ->
# CKR_ATTRIBUTE_VALUE_INVALID, CKA_SENSITIVE unknown to the HMAC key parser ->
# CKR_ATTRIBUTE_TYPE_INVALID). Import-site only: at other sites these codes stay
# real findings (see negotiate_request).
IMPORT_STORAGE_SHAPE_REJECTS: tuple[int, ...] = (
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_ATTRIBUTE_READ_ONLY,
)

# Benign policy attributes a storage variant may DROP on a clean shape reject
# (mirrors unwrap_key_for_mechanism_roundtrip): their absence does not change
# what the KAT asserts. Crypto-visible attributes are never touched.
_IMPORT_DROPPABLE_POLICY_ATTRS: tuple[Any, ...] = (CKA_SENSITIVE, CKA_EXTRACTABLE)

_import_label_counter = itertools.count(1)

# Winning storage-variant cache, keyed by template shape (class, key type,
# attr-type set). One negotiation walk per shape per process; subsequent
# imports go straight to the learned variant instead of re-rejecting the
# canonical thousands of times. A cached winner that stops working falls back
# to the full canonical-first sequence and re-learns.
_IMPORT_SHAPE_WINNERS: dict[tuple[Any, ...], int] = {}


def reset_import_negotiation_cache() -> None:
    """Test hook: forget learned storage-variant winners."""
    _IMPORT_SHAPE_WINNERS.clear()


def _next_import_label() -> bytes:
    """Unique short label for label-keyed object stores (max 32 bytes)."""
    return f"p11chk-import-{next(_import_label_counter)}".encode()


def _storage_variants(base: dict[Any, Any]) -> list[dict[Any, Any]]:
    """Spec-equivalent storage variants, canonical-minimal first (G1)."""
    variants: list[dict[Any, Any]] = [base]
    labeled = base if CKA_LABEL in base else {**base, CKA_LABEL: _next_import_label()}
    if labeled is not base:
        variants.append(labeled)
    tokened = labeled if base.get(CKA_TOKEN, False) else {**labeled, CKA_TOKEN: True}
    if tokened is not labeled:
        variants.append(tokened)
    dropped = {k: v for k, v in tokened.items() if k not in _IMPORT_DROPPABLE_POLICY_ATTRS}
    if dropped != tokened:
        variants.append(dropped)
    return variants


def _import_shape_key(base: Mapping[Any, Any]) -> tuple[Any, ...]:
    return (
        base.get(CKA_CLASS),
        base.get(CKA_KEY_TYPE),
        tuple(sorted(int(k) for k in base)),
    )


def create_object_negotiated(
    rs: Any,
    attrs: Mapping[Any, Any],
    *,
    purpose: str = "key import",
) -> int:
    """Create an object, negotiating storage-shape requirements (label / token).

    Variant 0 is the caller's spec-minimal template. Storage-oriented modules reject
    it cleanly: some modules require CKA_LABEL on every key object (CKR_ARGUMENTS_BAD
    when absent), support only token objects (CKR_ATTRIBUTE_VALUE_INVALID for
    CKA_TOKEN=False) and reject policy attributes their parsers do not know
    (CKR_ATTRIBUTE_TYPE_INVALID for CKA_SENSITIVE). Retry variants add a unique
    CKA_LABEL, then CKA_TOKEN=True, then drop the benign policy attrs -- storage
    shape only; crypto-visible attributes are never changed and no provider
    identity is consulted. The winning variant is cached per template shape per
    process (see _IMPORT_SHAPE_WINNERS); callers destroy the object in their
    cleanup path regardless of which variant won.
    """
    from pkcs11_check.raw.recipes import create_object
    from pkcs11_check.raw.rv import CkrAssertionError as _CkrError
    from pkcs11_check.testcases._negotiation import negotiate_request

    base = dict(attrs)
    variants = _storage_variants(base)
    shape_key = _import_shape_key(base)

    def attempt(delta: Mapping[Any, Any]) -> int:
        return create_object(rs.raw, rs.sh, dict(delta))

    cached = _IMPORT_SHAPE_WINNERS.get(shape_key)
    if cached is not None and 0 < cached < len(variants):
        try:
            return attempt(variants[cached])
        except _CkrError as exc:
            if exc.rv == CKR_FUNCTION_NOT_SUPPORTED:
                pytest.skip("Module does not implement C_CreateObject")
            if exc.rv not in IMPORT_STORAGE_SHAPE_REJECTS:
                raise
            # The learned winner stopped working: re-learn from canonical.

    try:
        result, idx = negotiate_request(
            attempt, variants, label=purpose, shape_rejects=IMPORT_STORAGE_SHAPE_REJECTS
        )
    except _CkrError as exc:
        # No C_CreateObject at all (Cloud-KMS-class / no-import module):
        # every import setup site routes here, so skip uniformly rather
        # than hard-failing each. Capability absent -> skip (genuine), not xfail.
        if exc.rv == CKR_FUNCTION_NOT_SUPPORTED:
            pytest.skip("Module does not implement C_CreateObject")
        raise
    _IMPORT_SHAPE_WINNERS[shape_key] = idx
    return result
