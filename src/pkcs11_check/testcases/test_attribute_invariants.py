"""Derived-attribute invariant tests (classification model Type D).

PKCS#11 defines several *derived* attributes whose value is fixed by the
history of a key, not set independently by the caller:

- ``CKA_NEVER_EXTRACTABLE`` is ``CK_TRUE`` iff ``CKA_EXTRACTABLE`` has been
  ``CK_FALSE`` for the entire lifetime of the key (PKCS#11 v3.1 Sec.4.9.4).
- ``CKA_ALWAYS_SENSITIVE`` is ``CK_TRUE`` iff ``CKA_SENSITIVE`` has been
  ``CK_TRUE`` for the entire lifetime of the key (Sec.4.9.4).

This suite generates its own keys and never mutates them, so the history is
known: a key created ``CKA_EXTRACTABLE=False`` and never changed MUST report
``CKA_NEVER_EXTRACTABLE=True``; a key created ``CKA_SENSITIVE=True`` and never
changed MUST report ``CKA_ALWAYS_SENSITIVE=True``.

Classification (Type D, derived-invariant contradiction):

- precondition holds (the base attribute reads back the protective value) AND
  the derived attribute contradicts it -> ``fail`` (the module contradicts its
  own derived invariant -- broken for any provider),
- the derived attribute is absent / unsupported -> ``xfail`` (honest
  non-support, provider-dependent),
- the base attribute itself did not take effect (an isolated wrong value, not
  the derived-invariant contradiction under test) -> ``xfail``,
- precondition holds and the derived attribute agrees -> ``pass``.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_aes_key,
    read_attributes,
)
from pkcs11_check.raw.types_std import (
    CKA_ALWAYS_SENSITIVE,
    CKA_EXTRACTABLE,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
)
from pkcs11_check.testcases.conftest import require_operational_aes_keygen

pytestmark = pytest.mark.security


def _classify_derived_invariant(
    *,
    base_holds: bool,
    derived_present: bool,
    derived_value: Any,
    label: str,
) -> None:
    """Type-D derived-attribute invariant classifier.

    Args:
        base_holds: the base attribute (e.g. ``CKA_EXTRACTABLE=False``) actually
            took effect on the suite-generated, never-modified key. If it did
            not, the invariant under test cannot be evaluated.
        derived_present: the module reported the derived attribute at all.
        derived_value: the value the module reported for the derived attribute;
            for a key whose base attribute held the whole lifetime this MUST be
            ``True``.
        label: provider-neutral description of the invariant.

    - not ``base_holds`` -> ``xfail`` (isolated wrong value elsewhere; the
      module ignored the requested base attribute, which is a separate honest
      deviation, not the derived-invariant contradiction under test).
    - not ``derived_present`` -> ``xfail`` (the module does not support the
      derived attribute -- honest non-support).
    - ``derived_value is not True`` -> ``fail`` (the module reported the base
      attribute held the entire lifetime, then denied the derived invariant --
      a self-contradiction).
    - otherwise -> ``pass``.
    """
    if not base_holds:
        pytest.xfail(
            f"{label}: base attribute did not take effect (isolated deviation, not the invariant)"
        )
    if not derived_present:
        pytest.xfail(f"{label}: derived attribute not reported (honest non-support)")
    if derived_value is not True:
        pytest.fail(
            f"{label}: base attribute held the whole lifetime but derived attribute "
            f"is {derived_value!r}, must be True (self-contradiction)"
        )


class TestDerivedAttributeInvariants:
    """Derived-attribute invariants on suite-generated, never-modified keys."""

    def test_never_extractable_when_created_non_extractable(self, p11_raw_session: Any) -> None:
        """A key created EXTRACTABLE=False and never changed must be NEVER_EXTRACTABLE=True."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_EXTRACTABLE: False})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_EXTRACTABLE, CKA_NEVER_EXTRACTABLE])
            base_holds = attrs.get(CKA_EXTRACTABLE) is False
            _classify_derived_invariant(
                base_holds=base_holds,
                derived_present=CKA_NEVER_EXTRACTABLE in attrs,
                derived_value=attrs.get(CKA_NEVER_EXTRACTABLE),
                label="CKA_NEVER_EXTRACTABLE on a key created EXTRACTABLE=False and never changed "
                "(PKCS#11 v3.1 Sec.4.9.4)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_always_sensitive_when_created_sensitive(self, p11_raw_session: Any) -> None:
        """A key created SENSITIVE=True and never changed must be ALWAYS_SENSITIVE=True."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256, attrs={CKA_SENSITIVE: True})
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE])
            base_holds = attrs.get(CKA_SENSITIVE) is True
            _classify_derived_invariant(
                base_holds=base_holds,
                derived_present=CKA_ALWAYS_SENSITIVE in attrs,
                derived_value=attrs.get(CKA_ALWAYS_SENSITIVE),
                label="CKA_ALWAYS_SENSITIVE on a key created SENSITIVE=True and never changed "
                "(PKCS#11 v3.1 Sec.4.9.4)",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
