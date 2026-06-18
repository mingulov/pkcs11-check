"""C_SetAttributeValue restricted-attribute mutation tests.

Covers the four mutations that PKCS#11 forbids on a sensitive, non-extractable
secret key:
  1. Downgrading CKA_SENSITIVE from True to False (one-way: can only tighten).
  2. Upgrading CKA_EXTRACTABLE from False to True (one-way: can only tighten).
  3. Flipping CKA_PRIVATE from True to False.
  4. Mutating CKA_CLASS (always read-only after creation).

Design rule: verify the *effect*, not the return code.  A module that returns
CKR_OK but leaves the attribute unchanged PASSES (no actual harm done); a
finding requires the protection to be actually removed (re-read confirms change).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import attr_bool, attr_ulong, template
from pkcs11_check.raw.recipes import destroy_quietly, read_attributes
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_EXTRACTABLE,
    CKA_PRIVATE,
    CKA_SENSITIVE,
    CKA_TOKEN,
    CKO_DATA,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_OK,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    classify_policy_enforcement,
    gen_aes_key_or_xfail,
    is_known_error,
)

pytestmark = [pytest.mark.security]

# Reject codes expected for a CKA_CLASS mutation attempt.
_CLASS_MUTATION_REJECT_RVS = (
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_TEMPLATE_INCONSISTENT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_protected_key(rs: Any) -> int:
    """Generate a sensitive, non-extractable, private AES-256 session key.

    Returns the object handle.  Skips if AES_KEY_GEN is not advertised or the
    template is cleanly rejected (genuine capability absence).
    """
    return gen_aes_key_or_xfail(
        rs,
        256,
        attrs={
            CKA_SENSITIVE: True,
            CKA_EXTRACTABLE: False,
            CKA_PRIVATE: True,
            CKA_TOKEN: False,
        },
        purpose="protected-key setup",
    )


def _set_bool(rs: Any, handle: int, attr: int, value: bool) -> int:
    """C_SetAttributeValue with a single boolean attribute; returns the raw CK_RV.

    Calls raw C_SetAttributeValue directly (not the recipe that raises on
    non-CKR_OK) so callers can inspect the rv to distinguish a clean reject
    from CKR_OK-but-no-effect.
    """
    tmpl = template(attr_bool(attr, value))
    return int(rs.raw.C_SetAttributeValue(rs.sh, handle, tmpl.ptr, tmpl.count))


def _read_bool(rs: Any, handle: int, attr: int) -> bool | None:
    """Read a boolean attribute; returns None if the attribute is unavailable.

    Uses the ``read_attributes`` recipe, which tolerates CKR_ATTRIBUTE_SENSITIVE
    and CKR_ATTRIBUTE_TYPE_INVALID by omitting the attribute from the result dict.
    """
    try:
        attrs = read_attributes(rs.raw, rs.sh, handle, [attr])
    except AssertionError as exc:
        if is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID}):
            return None
        raise
    val = attrs.get(int(attr))
    if val is None:
        return None
    return bool(val)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cannot_downgrade_sensitive_to_false(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not clear CKA_SENSITIVE.

    PKCS#11 v3.2 §10.7: CKA_SENSITIVE is one-way — it can be set to True at
    creation or tightened later, but a True→False downgrade must be rejected.
    A module that removes sensitivity exposes the raw key material to extraction.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    try:
        initial = _read_bool(rs, key, CKA_SENSITIVE)
        if initial is None:
            pytest.skip("Module does not expose CKA_SENSITIVE — cannot verify the protection")
        rv = _set_bool(rs, key, CKA_SENSITIVE, False)
        after = _read_bool(rs, key, CKA_SENSITIVE)
        classify_policy_enforcement(
            claimed=initial is True,
            violated=(rv == CKR_OK and after is False),
            label="C_SetAttributeValue CKA_SENSITIVE->FALSE",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)


def test_cannot_upgrade_extractable_to_true(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not set CKA_EXTRACTABLE=True.

    PKCS#11 v3.2 §10.7: CKA_EXTRACTABLE is one-way — once False it must stay
    False.  A module that allows the upgrade lets an attacker export key material.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    try:
        initial_extractable = _read_bool(rs, key, CKA_EXTRACTABLE)
        if initial_extractable is None:
            pytest.skip("Module does not expose CKA_EXTRACTABLE — cannot verify the protection")
        rv = _set_bool(rs, key, CKA_EXTRACTABLE, True)
        after = _read_bool(rs, key, CKA_EXTRACTABLE)
        classify_policy_enforcement(
            claimed=initial_extractable is False,
            violated=(rv == CKR_OK and after is True),
            label="C_SetAttributeValue CKA_EXTRACTABLE->TRUE",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)


def test_cannot_flip_private(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not clear CKA_PRIVATE.

    CKA_PRIVATE=True means the object is accessible only after USER login.
    Downgrading it to False exposes a private key to public (unauthenticated)
    sessions — a security boundary bypass.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    try:
        initial_private = _read_bool(rs, key, CKA_PRIVATE)
        if initial_private is None:
            pytest.skip("Module does not expose CKA_PRIVATE — cannot verify the protection")
        rv = _set_bool(rs, key, CKA_PRIVATE, False)
        after = _read_bool(rs, key, CKA_PRIVATE)
        classify_policy_enforcement(
            claimed=initial_private is True,
            violated=(rv == CKR_OK and after is False),
            label="C_SetAttributeValue CKA_PRIVATE->FALSE",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)


def test_cannot_mutate_class(p11_raw_session: Any) -> None:
    """C_SetAttributeValue must not change CKA_CLASS.

    CKA_CLASS is always read-only after creation (PKCS#11 v3.2 Table 12).
    Accepting a class mutation can produce type-confused objects that bypass
    key-type enforcement in subsequent operations.
    """
    rs = p11_raw_session
    key = _make_protected_key(rs)
    try:
        # Attempt to change the class from CKO_SECRET_KEY to CKO_DATA.
        # Any conformant module must reject this.
        tmpl = template(attr_ulong(CKA_CLASS, CKO_DATA))
        rv = int(rs.raw.C_SetAttributeValue(rs.sh, key, tmpl.ptr, tmpl.count))

        # Read back to note whether the class actually changed (enriches the
        # label / detail), but the verdict is solely determined by the rv.
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_CLASS])
            class_after = attrs.get(CKA_CLASS)
        except AssertionError as exc:
            if not is_known_error(exc, {CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID}):
                raise
            class_after = None

        detail = (
            " (class changed to CKO_DATA)"
            if class_after is not None and int(class_after) == CKO_DATA
            else ""
        )
        # CKA_CLASS is always read-only: CKR_OK to a set attempt is itself the violation,
        # so classify on rv (no effect re-read needed).
        classify_negative_rv(
            rv,
            _CLASS_MUTATION_REJECT_RVS,
            label=f"C_SetAttributeValue CKA_CLASS mutation{detail}",
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, key)
