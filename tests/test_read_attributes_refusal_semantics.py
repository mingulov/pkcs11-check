"""Regressions for the read_attributes/attr_or_record refusal-semantics fixes.

Background (see .superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/):

- DEFECT 1 (M5): CKR_ATTRIBUTE_SENSITIVE and CKR_ATTRIBUTE_TYPE_INVALID both surfaced
  as one undifferentiated omission, so a caller could not tell "the module correctly
  refused a legitimately-sensitive attribute" from "the module does not recognise
  this attribute type" (a real deviation). ``read_attributes`` now returns an
  ``AttrReadResult`` carrying an additive ``refusals`` channel with the actual CKR
  observed, and ``attr_or_record`` gained a ``sensitive_is_conformant`` flag that only
  the CALL SITE may set (whether an attribute can legitimately be sensitive is not
  decidable by the generic helper) -- a plain absence with no CKR observed still
  carries no CKR (never invented).

- DEFECT 2 (N12): a module answering CKR_ATTRIBUTE_SENSITIVE/CKR_ATTRIBUTE_TYPE_INVALID
  but still writing a real length/bytes into the template used to be silently returned
  as a normal present value by read_attributes -- a harness-side secret-leak path. Such
  a refusal-with-data self-contradiction is now never returned as present, and is
  recorded (bounded length metadata only, never the bytes) via
  AttrRefusal.leaked_len / attr_or_record's "self_contradiction" path.

- A CKR_ATTRIBUTE_TYPE_INVALID (or CKR_ATTRIBUTE_SENSITIVE) refusal that used a real
  zero-length buffer instead of the CK_UNAVAILABLE_INFORMATION sentinel used to surface
  as a *present* empty value (b"" / "" / []) rather than an absence -- evidence
  corruption. For a single-attribute read this is now unambiguous and is treated as a
  refusal (with no leaked_len, since no bytes were actually written).
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.classification import get_records
from pkcs11_check.raw.recipes import AttrRefusal, read_attributes
from pkcs11_check.raw.types_std import (
    CK_UNAVAILABLE_INFORMATION,
    CKA_LABEL,
    CKA_PRIVATE_EXPONENT,
    CKA_VALUE,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._attribute_values import (
    MISSING_ATTRIBUTE,
    attr_or_record,
    require_bool_attr,
    require_ulong_attr,
)


def _raw(get_attribute: Any) -> SimpleNamespace:
    return SimpleNamespace(C_GetAttributeValue=get_attribute)


# ---------------------------------------------------------------------------
# read_attributes: sentinel-based refusals (DEFECT 1)
# ---------------------------------------------------------------------------


def test_sensitive_refusal_via_sentinel_is_absent_with_observed_ckr() -> None:
    """A conformant CKR_ATTRIBUTE_SENSITIVE refusal is absent from the dict and carries
    the actual CKR in ``refusals`` -- never collapsed with CKR_ATTRIBUTE_TYPE_INVALID.

    Mutation used: change ``result.append`` (recipes.py) so
    ``if _observed_refusal_ckr is not None: result.refusals[at] = ...`` used
    CKR_ATTRIBUTE_TYPE_INVALID unconditionally instead of ``_observed_refusal_ckr`` --
    the ``== CKR_ATTRIBUTE_SENSITIVE`` assertion below caught it (red).
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_SENSITIVE)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE])
    assert CKA_VALUE not in result
    refusal = result.refusals[CKA_VALUE]
    assert refusal.ckr == int(CKR_ATTRIBUTE_SENSITIVE)
    assert refusal.leaked_len is None


def test_type_invalid_refusal_via_sentinel_stays_distinguishable() -> None:
    """CKR_ATTRIBUTE_TYPE_INVALID (an unrecognised attribute -- a real deviation) is
    carried separately from CKR_ATTRIBUTE_SENSITIVE, not collapsed into it.

    Mutation used: hardcode ``AttrRefusal(ckr=int(CKR_ATTRIBUTE_SENSITIVE))`` in the
    sentinel branch regardless of which CKR was observed -- this test's
    ``== CKR_ATTRIBUTE_TYPE_INVALID`` assertion caught it (red).
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.ckr == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert refusal.leaked_len is None


def test_multi_attribute_sentinel_refusal_does_not_taint_other_attribute() -> None:
    """One attribute refused via the sentinel does not affect a sibling's present value."""
    label_bytes = b"p11chk"

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 2
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        if attrs[1].pValue:
            ctypes.memmove(attrs[1].pValue, label_bytes, len(label_bytes))
        attrs[1].ulValueLen = len(label_bytes)
        return int(CKR_ATTRIBUTE_SENSITIVE)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE, CKA_LABEL])
    assert CKA_VALUE not in result
    assert result.refusals[CKA_VALUE].ckr == int(CKR_ATTRIBUTE_SENSITIVE)
    assert result[CKA_LABEL] == "p11chk"
    assert CKA_LABEL not in result.refusals


# ---------------------------------------------------------------------------
# read_attributes: refusal-with-data self-contradiction (DEFECT 2)
# ---------------------------------------------------------------------------


def test_refusal_with_data_is_never_returned_as_present() -> None:
    """A module that says CKR_ATTRIBUTE_SENSITIVE but writes real bytes anyway must
    never hand back a decoded value -- this is the harness-side leak path (N12).

    Mutation used: removed the ``count == 1`` self-contradiction branch entirely (fell
    through to the normal decode path) -- this test's
    ``CKA_PRIVATE_EXPONENT not in result`` assertion caught the leak (red): the secret
    bytes were returned as a present value.
    """
    secret = b"\x13\x37\xde\xad"

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        attrs[0].ulValueLen = len(secret)  # no CK_UNAVAILABLE_INFORMATION sentinel
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, secret, len(secret))
        return int(CKR_ATTRIBUTE_SENSITIVE)

    result = read_attributes(_raw(_get), 1, 1, [CKA_PRIVATE_EXPONENT])
    assert CKA_PRIVATE_EXPONENT not in result
    refusal = result.refusals[CKA_PRIVATE_EXPONENT]
    assert refusal.ckr == int(CKR_ATTRIBUTE_SENSITIVE)
    assert refusal.leaked_len == len(secret)
    # The bytes themselves must never be reachable through the refusal channel --
    # AttrRefusal structurally carries only ckr/leaked_len, never a value field.
    assert not hasattr(refusal, "value")
    assert not hasattr(refusal, "bytes")


def test_type_invalid_without_sentinel_zero_length_is_not_a_present_empty_value() -> None:
    """A refusal signalled via a real (zero) length instead of the sentinel must not
    surface as a present empty value -- that is an absence being reported as data.
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = 0  # no sentinel, no bytes written
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.ckr == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert refusal.leaked_len is None


def test_plain_ok_read_is_unaffected() -> None:
    """A normal CKR_OK read is decoded exactly as before -- no refusal recorded."""
    label_bytes = b"ordinary"

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, label_bytes, len(label_bytes))
        attrs[0].ulValueLen = len(label_bytes)
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert result[CKA_LABEL] == "ordinary"
    assert result.refusals == {}


# ---------------------------------------------------------------------------
# attr_or_record: caller-site conformance decisions (DEFECT 1, corrected framing)
# ---------------------------------------------------------------------------


def test_attr_or_record_never_invents_a_ckr_for_a_plain_absence() -> None:
    """A plain dict with no ``refusals`` channel at all must never gain an invented CKR.

    Mutation used: changed the final fallback ``actual=refusal.ckr if refusal is not
    None else None`` to unconditionally pass ``actual=CKR_ATTRIBUTE_SENSITIVE`` -- this
    test's ``actual_ckr is None`` assertion caught the invented CKR (red).
    """
    value = attr_or_record(
        {},
        CKA_VALUE,
        label="plain absence, no CKR observed",
        reason="honest_deviation",
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.actual_ckr is None


def test_sensitive_refusal_on_legitimately_sensitive_attribute_is_conformant() -> None:
    """CKA_VALUE of a CKA_SENSITIVE key: a clean CKR_ATTRIBUTE_SENSITIVE refusal is
    conformant when the call site says so (sensitive_is_conformant=True) -- never
    hard-coded inside the helper.

    Mutation used: dropped the ``sensitive_is_conformant`` guard so the sanctioned-
    refusal branch always fired -- test_sensitive_refusal_defect_still_reported (below)
    then failed to see a deviation for the non-legitimate case (red).
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_SENSITIVE)

    attrs = read_attributes(_raw(_get), 1, 1, [CKA_VALUE])
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label="CKA_VALUE on a CKA_SENSITIVE key",
        reason="honest_deviation",
        sensitive_is_conformant=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "sanctioned_refusal"
    assert record.outcome == "pass"
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"


def test_sensitive_refusal_defect_still_reported_when_not_legitimately_sensitive() -> None:
    """CKA_CLASS/CKA_LABEL/etc. can never legitimately be sensitive: a module refusing
    to disclose one is a real defect and must stay a visible deviation even though the
    observed CKR is CKR_ATTRIBUTE_SENSITIVE -- the default (sensitive_is_conformant not
    passed) must NOT collapse this into "conformant, no finding".
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_SENSITIVE)

    attrs = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    value = attr_or_record(
        attrs,
        CKA_LABEL,
        label="CKA_LABEL refused as sensitive (never legitimate)",
        reason="honest_deviation",
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.outcome == "xfail"
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"


def test_sensitive_is_conformant_does_not_suppress_type_invalid() -> None:
    """sensitive_is_conformant=True only ever demotes an observed
    CKR_ATTRIBUTE_SENSITIVE -- CKR_ATTRIBUTE_TYPE_INVALID stays a deviation regardless.

    Mutation used: relaxed the ``refusal.ckr == CKR_ATTRIBUTE_SENSITIVE`` check in
    attr_or_record to accept either refusal code -- this test's
    ``record.reason == "honest_deviation"`` assertion caught it (red, got
    "sanctioned_refusal").
    """

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = CK_UNAVAILABLE_INFORMATION
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    attrs = read_attributes(_raw(_get), 1, 1, [CKA_PRIVATE_EXPONENT])
    value = attr_or_record(
        attrs,
        CKA_PRIVATE_EXPONENT,
        label="CKA_PRIVATE_EXPONENT",
        reason="honest_deviation",
        sensitive_is_conformant=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"


def test_refusal_with_data_is_always_self_contradiction_even_if_legitimately_sensitive() -> None:
    """A refusal-with-data contradiction is a finding regardless of
    sensitive_is_conformant -- writing real bytes after claiming sensitivity
    contradicts the module's own claim no matter how legitimate the sensitivity claim
    would otherwise be. Only bounded length metadata is ever recorded.
    """
    secret = b"\xaa\xbb\xcc\xdd\xee"

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        attrs[0].ulValueLen = len(secret)
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, secret, len(secret))
        return int(CKR_ATTRIBUTE_SENSITIVE)

    attrs = read_attributes(_raw(_get), 1, 1, [CKA_PRIVATE_EXPONENT])
    value = attr_or_record(
        attrs,
        CKA_PRIVATE_EXPONENT,
        label="CKA_PRIVATE_EXPONENT",
        reason="honest_deviation",
        sensitive_is_conformant=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.outcome == "fail"
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert record.detail is not None
    assert record.detail["leaked_len"] == len(secret)
    # Bounded metadata only -- the secret bytes must never appear anywhere in the record.
    rendered = repr(record.detail) + record.summary
    assert secret.hex() not in rendered
    for byte in secret:
        assert f"\\x{byte:02x}" not in rendered


# ---------------------------------------------------------------------------
# require_ulong_attr / require_bool_attr (previously zero coverage)
# ---------------------------------------------------------------------------


def test_require_ulong_attr_returns_valid_int() -> None:
    assert require_ulong_attr(7, label="x") == 7


def test_require_ulong_attr_rejects_bool() -> None:
    """bool is an int subclass; require_ulong_attr must not accept it as CK_ULONG.

    Mutation used: dropped ``and not isinstance(value, bool)`` from the guard -- this
    test then observed a plain return of ``True`` instead of an xfail (red).
    """
    with pytest.raises(pytest.xfail.Exception):
        require_ulong_attr(True, label="malformed ulong")
    assert get_records()[-1].reason == "not_operational"


def test_require_ulong_attr_rejects_non_int() -> None:
    with pytest.raises(pytest.xfail.Exception):
        require_ulong_attr("not-an-int", label="malformed ulong")
    assert get_records()[-1].reason == "not_operational"


def test_require_ulong_attr_fed_missing_attribute_unguarded_emits_xfail_with_object_repr() -> None:
    """Documents current behaviour: an unguarded MISSING_ATTRIBUTE sentinel produces a
    misleading second record whose summary embeds the sentinel's ``<object object at
    ...>`` repr rather than a clean "attribute absent" message. Locked in as a
    regression since this helper had zero test coverage.
    """
    with pytest.raises(pytest.xfail.Exception):
        require_ulong_attr(MISSING_ATTRIBUTE, label="fed MISSING_ATTRIBUTE unguarded")
    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert "<object object at" in record.summary


def test_require_bool_attr_returns_valid_bool() -> None:
    assert require_bool_attr(True, label="x") is True
    assert require_bool_attr(False, label="x") is False


def test_require_bool_attr_rejects_int() -> None:
    """1/0 are not CK_BBOOL True/False in this codebase's decoding -- only real bool.

    Mutation used: changed the guard to ``isinstance(value, int)`` -- this test's
    ``pytest.raises(pytest.xfail.Exception)`` then failed to see any exception (red,
    since 1 is an int).
    """
    with pytest.raises(pytest.xfail.Exception):
        require_bool_attr(1, label="malformed bool")
    assert get_records()[-1].reason == "not_operational"


def test_require_bool_attr_fed_missing_attribute_unguarded_emits_xfail_with_object_repr() -> None:
    with pytest.raises(pytest.xfail.Exception):
        require_bool_attr(MISSING_ATTRIBUTE, label="fed MISSING_ATTRIBUTE unguarded")
    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert "<object object at" in record.summary


def test_attr_refusal_equality_and_defaults() -> None:
    assert AttrRefusal(ckr=1) == AttrRefusal(ckr=1)
    assert AttrRefusal(ckr=1).leaked_len is None
    assert AttrRefusal(ckr=1, leaked_len=4) != AttrRefusal(ckr=1)
