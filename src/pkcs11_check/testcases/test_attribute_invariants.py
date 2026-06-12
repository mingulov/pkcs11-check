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
    CKA_KEY_GEN_MECHANISM,
    CKA_LOCAL,
    CKA_NEVER_EXTRACTABLE,
    CKA_SENSITIVE,
    CKM_AES_KEY_GEN,
)
from pkcs11_check.testcases._attribute_values import require_ulong_attr
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


def _classify_generated_key_origin_invariant(
    *,
    local_present: bool,
    local_value: Any,
    mechanism_present: bool,
    mechanism_value: Any,
    expected_mechanism: int,
    label: str,
) -> None:
    """Classify linked generated-key origin attributes.

    A generated key should report ``CKA_LOCAL=True`` and identify the mechanism
    that created it. If the module honestly omits either attribute, or reports
    only the isolated ``CKA_LOCAL`` value wrong, this test cannot evaluate the
    linked-origin contradiction and records xfail. Once the module claims the
    key is local, a wrong ``CKA_KEY_GEN_MECHANISM`` contradicts the generated
    key's known origin and is a failure.
    """
    if not local_present:
        pytest.xfail(f"{label}: CKA_LOCAL not reported (honest non-support)")
    if local_value is not True:
        pytest.xfail(f"{label}: CKA_LOCAL is {local_value!r} (isolated wrong value)")
    if not mechanism_present:
        pytest.xfail(f"{label}: CKA_KEY_GEN_MECHANISM not reported (honest non-support)")

    actual_mechanism = require_ulong_attr(mechanism_value, "CKA_KEY_GEN_MECHANISM")
    if actual_mechanism != expected_mechanism:
        pytest.fail(
            f"{label}: CKA_LOCAL=True but CKA_KEY_GEN_MECHANISM is "
            f"{actual_mechanism:#x}, expected {expected_mechanism:#x} "
            "(linked-origin self-contradiction)"
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

    def test_generated_aes_key_reports_local_key_gen_mechanism(
        self, p11_raw_session: Any
    ) -> None:
        """A locally generated AES key must report CKM_AES_KEY_GEN as its origin."""
        rs = p11_raw_session
        require_operational_aes_keygen(rs)
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            attrs = read_attributes(rs.raw, rs.sh, key, [CKA_LOCAL, CKA_KEY_GEN_MECHANISM])
            _classify_generated_key_origin_invariant(
                local_present=CKA_LOCAL in attrs,
                local_value=attrs.get(CKA_LOCAL),
                mechanism_present=CKA_KEY_GEN_MECHANISM in attrs,
                mechanism_value=attrs.get(CKA_KEY_GEN_MECHANISM),
                expected_mechanism=int(CKM_AES_KEY_GEN),
                label="CKA_LOCAL/CKA_KEY_GEN_MECHANISM on an AES key generated by "
                "CKM_AES_KEY_GEN",
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
