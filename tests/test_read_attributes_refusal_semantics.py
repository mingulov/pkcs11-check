"""Regressions for the read_attributes/attr_or_record refusal-semantics fixes.

Background (see .superpowers/sdd/2026-09-08-v020-reporting-integrity-fixes/):

- DEFECT 1 (BRANCH-REVIEW M5): CKR_ATTRIBUTE_SENSITIVE and CKR_ATTRIBUTE_TYPE_INVALID
  both surfaced as one undifferentiated omission, so a caller could not tell "the module
  correctly refused a legitimately-sensitive attribute" from "the module does not
  recognise this attribute type" (a real deviation). ``read_attributes`` now returns an
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
from _pytest.outcomes import Failed, XFailed

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
    assert refusal.reported_len == len(secret)
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
    assert refusal.malformed is True


def test_retained_finite_length_without_write_is_malformed_not_leaked() -> None:
    """R8-1: a bare retained length is not proof of a write (no false leak)."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        attrs[0].ulValueLen = 1  # retained from the size query; buffer untouched
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.ckr == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert refusal.leaked_len is None
    assert refusal.malformed is True
    assert refusal.reported_len == 1


def test_write_behind_sentinel_is_still_a_leak() -> None:
    """R8-1: proven-written bytes count as leaked even under the sentinel."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            attrs[0].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
            ctypes.memmove(attrs[0].pValue, b"\xab", 1)
        else:
            attrs[0].ulValueLen = 1
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.ckr == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert refusal.leaked_len == 1
    assert refusal.reported_len is None


def test_false_write_is_detected_despite_zero_bytes() -> None:
    """R9-1: a FALSE/zero write differs from the canary (the twin case)."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, b"\x00", 1)
        attrs[0].ulValueLen = 1
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.leaked_len == 1
    assert refusal.reported_len == 1
    assert refusal.malformed is False


def test_success_without_write_omits_bool_with_unproved_mark() -> None:
    """R11-2: untouched bool success omits visibly (never a fill value)."""
    from pkcs11_check.raw.types_std import CKA_TOKEN

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        attrs[0].ulValueLen = 1  # claims a byte, writes nothing
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_TOKEN])
    assert CKA_TOKEN not in result
    assert result.refusals == {}
    assert result.unavailable_without_ckr == set()
    assert result.unproved_delivery == {int(CKA_TOKEN)}


def test_untouched_kcv_flagged_unproved_not_silenced() -> None:
    """R12-2: untouched bytes stay present but flagged for strict callers."""
    from pkcs11_check.raw.recipes import _PATTERN_BLOCK
    from pkcs11_check.raw.types_std import CKA_CHECK_VALUE

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        attrs[0].ulValueLen = 3  # claims KCV bytes, writes nothing
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_CHECK_VALUE])
    assert result[CKA_CHECK_VALUE] == bytes(_PATTERN_BLOCK[:3])
    assert result.refusals == {}
    assert result.unproved_delivery == {int(CKA_CHECK_VALUE)}


def test_verify_retry_accepts_stable_partial_content() -> None:
    """R12-3: byte-stable content across fills is proven genuine (no mark)."""
    from pkcs11_check.raw.recipes import _PATTERN_BLOCK, _PATTERN_BLOCK_ALT

    blob = bytes([_PATTERN_BLOCK[0], _PATTERN_BLOCK_ALT[1], 0x00, 0x01])

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, blob, len(blob))
        attrs[0].ulValueLen = len(blob)
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert result[CKA_VALUE] == blob
    assert result.unproved_delivery == set()


def test_verify_retry_flags_fill_following_tail() -> None:
    """R12-3: a tail that follows the fill stays unproved (marked, kept)."""
    calls: list[bytes] = []

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 3
        else:
            calls.append(bytes(ctypes.string_at(attrs[0].pValue, 3)))
            ctypes.memmove(attrs[0].pValue, b"\x66\x00\x00", 1)
            attrs[0].ulValueLen = 3
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert len(calls) == 2
    assert result[CKA_VALUE] == b"\x66" + calls[1][1:]
    assert result.unproved_delivery == {int(CKA_VALUE)}


def test_verify_retry_disagreeing_full_content_stays_unproved() -> None:
    """R13-1: a retry that disagrees with the first read never passes clean."""
    data_calls = 0

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal data_calls
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 3
        else:
            data_calls += 1
            if data_calls == 1:
                ctypes.memmove(attrs[0].pValue, b"\x66", 1)
            else:
                ctypes.memmove(attrs[0].pValue, b"\x12\x34\x56", 3)
            attrs[0].ulValueLen = 3
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert data_calls == 2
    assert result.unproved_delivery == {int(CKA_VALUE)}


def test_verify_retry_refusal_after_success_stays_visible() -> None:
    """R13-1: a retry refusal cannot erase a first-read success into a skip."""
    from pkcs11_check.raw.types_std import CKA_CHECK_VALUE

    calls = 0

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal calls
        assert count == 1
        calls += 1
        if calls == 1:
            attrs[0].ulValueLen = 3
            return int(CKR_OK)
        if calls == 2:
            ctypes.memmove(attrs[0].pValue, b"\x66", 1)
            attrs[0].ulValueLen = 3
            return int(CKR_OK)
        attrs[0].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
        return int(CKR_ATTRIBUTE_TYPE_INVALID)

    result = read_attributes(_raw(_get), 1, 1, [CKA_CHECK_VALUE], verify_delivery=True)
    assert calls == 4
    assert result.refusals[CKA_CHECK_VALUE].ckr == int(CKR_ATTRIBUTE_TYPE_INVALID)
    assert result.unproved_delivery == {int(CKA_CHECK_VALUE)}
    value = attr_or_record(
        result,
        CKA_CHECK_VALUE,
        label="KCV",
        reason="honest_deviation",
        optional_if_absent=True,
        strict_delivery=True,
    )
    assert value is MISSING_ATTRIBUTE
    assert get_records()[-1].detail.get("unproved_delivery") is True


def test_verify_retry_resolves_exact_fill_collision() -> None:
    """R13-2: a wholly matching verified read retries; stable bytes pass clean."""
    from pkcs11_check.raw.recipes import _PATTERN_BLOCK

    data_calls = 0

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal data_calls
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 3
        else:
            data_calls += 1
            ctypes.memmove(attrs[0].pValue, bytes(_PATTERN_BLOCK[:3]), 3)
            attrs[0].ulValueLen = 3
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert data_calls == 2
    assert result[CKA_VALUE] == bytes(_PATTERN_BLOCK[:3])
    assert result.unproved_delivery == set()


def test_verify_retry_untouched_buffer_retries_then_marks() -> None:
    """R13-2: untouched verified reads retry once, then stay marked."""
    data_calls = 0

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal data_calls
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 3
        else:
            data_calls += 1
            attrs[0].ulValueLen = 3
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert data_calls == 2
    assert result.unproved_delivery == {int(CKA_VALUE)}


def test_verify_retry_releases_first_buffer_before_realloc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R13-3: the retry never holds two provider buffers at once."""
    import weakref

    from pkcs11_check.raw import recipes as raw_recipes

    live: list[weakref.ReferenceType[Any]] = []
    max_live = 0
    orig = raw_recipes._alloc_module_output

    def _tracking(size: int, *, what: str) -> Any:
        nonlocal max_live
        buf = orig(size, what=what)
        live[:] = [ref for ref in live if ref() is not None]
        live.append(weakref.ref(buf))
        max_live = max(max_live, len(live))
        return buf

    monkeypatch.setattr(raw_recipes, "_alloc_module_output", _tracking)
    n = 1024 * 1024

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = n
        else:
            ctypes.memmove(attrs[0].pValue, b"\x66", 1)
            attrs[0].ulValueLen = 3
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert result.unproved_delivery == {int(CKA_VALUE)}
    assert max_live == 1


def test_verify_retry_zero_length_after_success_stays_marked() -> None:
    """R14-3: a zero-length retry contradicts the baseline length."""
    data_calls = 0

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        nonlocal data_calls
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 0 if data_calls else 3
        else:
            data_calls += 1
            if data_calls == 1:
                ctypes.memmove(attrs[0].pValue, b"\x66", 1)
                attrs[0].ulValueLen = 3
            else:
                attrs[0].ulValueLen = 0
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert data_calls == 2
    assert result[CKA_VALUE] == b""
    assert result.unproved_delivery == {int(CKA_VALUE)}


def _overrun_get(_session: int, _handle: int, attrs: Any, count: int) -> int:
    """CKR_OK claiming 3 bytes in a 1-byte buffer (N-003 overrun shape)."""
    assert count == 1
    if attrs[0].pValue is None:
        attrs[0].ulValueLen = 1
    else:
        ctypes.memmove(attrs[0].pValue, b"\x66", 1)
        attrs[0].ulValueLen = 3
    return int(CKR_OK)


def test_overrun_length_verified_read_raises_typed() -> None:
    """R15-1: CKR_OK claiming past capacity fails closed, never stabilizes."""
    from pkcs11_check.raw.recipes import OutputLengthOverrunError

    with pytest.raises(OutputLengthOverrunError) as exc_info:
        read_attributes(_raw(_overrun_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert exc_info.value.call == "C_GetAttributeValue"
    assert exc_info.value.capacity == 1
    assert exc_info.value.reported == 3


def test_overrun_length_unverified_read_raises_typed() -> None:
    """R15-1: the overrun guard is not gated on verification."""
    from pkcs11_check.raw.recipes import OutputLengthOverrunError

    with pytest.raises(OutputLengthOverrunError):
        read_attributes(_raw(_overrun_get), 1, 1, [CKA_VALUE])


def test_overrun_length_multi_attribute_read_raises_typed() -> None:
    """R16-1: CKR_OK past capacity fails closed on every attribute."""
    from pkcs11_check.raw.recipes import OutputLengthOverrunError

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 2
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 2
            attrs[1].ulValueLen = 4
        else:
            ctypes.memmove(attrs[0].pValue, b"\x01\x02", 2)
            ctypes.memmove(attrs[1].pValue, b"copy", 4)
            attrs[0].ulValueLen = 2
            attrs[1].ulValueLen = 5
        return int(CKR_OK)

    with pytest.raises(OutputLengthOverrunError) as exc_info:
        read_attributes(_raw(_get), 1, 1, [CKA_VALUE, CKA_LABEL])
    assert exc_info.value.capacity == 4
    assert exc_info.value.reported == 5


def test_overrun_length_beats_cached_size_query_refusal() -> None:
    """R16-2: a successful overrun data call is not routed as a refusal."""
    from pkcs11_check.raw.recipes import OutputLengthOverrunError

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 1
            return int(CKR_ATTRIBUTE_TYPE_INVALID)
        attrs[0].ulValueLen = 3
        return int(CKR_OK)

    with pytest.raises(OutputLengthOverrunError) as exc_info:
        read_attributes(_raw(_get), 1, 1, [CKA_VALUE], verify_delivery=True)
    assert exc_info.value.capacity == 1
    assert exc_info.value.reported == 3


def test_attr_or_record_marked_clean_refusal_retains_ckr() -> None:
    """R15-2: the mark record keeps a known refusal CKR."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_TYPE_INVALID))
    attrs.unproved_delivery.add(CKA_VALUE)
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label="marked clean refusal",
        reason="honest_deviation",
        optional_if_absent=True,
        strict_delivery=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.detail is not None
    assert record.detail.get("unproved_delivery") is True


def test_attr_or_record_leak_beats_unproved_mark() -> None:
    """R14-2: refusal-with-write stays a hard finding under a retry mark."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.refusals[CKA_VALUE] = AttrRefusal(
        ckr=int(CKR_ATTRIBUTE_SENSITIVE), leaked_len=1, reported_len=1
    )
    attrs.unproved_delivery.add(CKA_VALUE)
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label="leak under mark",
        reason="honest_deviation",
        strict_delivery=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "self_contradiction"
    assert record.actual_ckr == "CKR_ATTRIBUTE_SENSITIVE"
    assert record.detail is not None
    assert record.detail["leaked_len"] == 1
    assert record.detail.get("unproved_delivery") is True


def test_attr_or_record_malformed_beats_unproved_mark() -> None:
    """R14-2b: a malformed retry refusal keeps its CKR under a retry mark."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.refusals[CKA_VALUE] = AttrRefusal(
        ckr=int(CKR_ATTRIBUTE_TYPE_INVALID), malformed=True, reported_len=1
    )
    attrs.unproved_delivery.add(CKA_VALUE)
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label="malformed under mark",
        reason="honest_deviation",
        strict_delivery=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.detail is not None
    assert record.detail.get("malformed_refusal") is True
    assert record.detail.get("unproved_delivery") is True


def test_attr_or_record_strict_marks_unproved_delivery_visible() -> None:
    """R12-2: strict callers deviate on unproved delivery, even if optional."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.unproved_delivery.add(CKA_VALUE)
    value = attr_or_record(
        attrs,
        CKA_VALUE,
        label="unproved delivery",
        reason="honest_deviation",
        optional_if_absent=True,
        strict_delivery=True,
    )
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert "unproved" in (record.summary or "")
    assert record.detail.get("unproved_delivery") is True


def test_attr_or_record_lenient_keeps_today_shape_on_unproved() -> None:
    """R12-2: lenient callers keep today's shape (no strict deviation)."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.unproved_delivery.add(CKA_VALUE)
    value = attr_or_record(attrs, CKA_VALUE, label="unproved delivery", reason="honest_deviation")
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert (record.detail or {}).get("unproved_delivery") is not True
    assert record.summary == "unproved delivery: attribute unavailable"


def test_canary_valued_bytes_still_decode() -> None:
    """R10-2: arbitrary-byte values decode even when canary-valued (never dropped)."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, b"\xa5" * 16, 16)
        attrs[0].ulValueLen = 16
        return int(CKR_OK)

    result = read_attributes(_raw(_get), 1, 1, [CKA_VALUE])
    assert result[CKA_VALUE] == b"\xa5" * 16


def test_out_of_range_write_does_not_validate_bool() -> None:
    """R10-1: a write outside the returned range leaves the bool unproved."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue is None:
            attrs[0].ulValueLen = 2
        else:
            ctypes.memmove(attrs[0].pValue + 1, b"\x00", 1)
            attrs[0].ulValueLen = 1
        return int(CKR_OK)

    from pkcs11_check.raw.types_std import CKA_TOKEN

    result = read_attributes(_raw(_get), 1, 1, [CKA_TOKEN])
    assert CKA_TOKEN not in result
    assert result.refusals == {}


def test_canary_collision_undercounts_transparently() -> None:
    """R9-1: leaked is proven-changed (lower bound); reported keeps the claim."""

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            ctypes.memmove(attrs[0].pValue, b"\xa5\x01", 2)
        attrs[0].ulValueLen = 2
        return int(CKR_ATTRIBUTE_SENSITIVE)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.leaked_len == 1
    assert refusal.reported_len == 2


def test_large_compare_stays_bounded_without_int_list() -> None:
    """R9-2: buffer comparison never materializes an int list (MemoryError fix)."""
    import tracemalloc

    from pkcs11_check.raw.recipes import _changed_byte_count, _fill_pattern

    n = 4 * 1024 * 1024
    buf = (ctypes.c_ubyte * n)()
    _fill_pattern(buf, n)
    tracemalloc.start()
    try:
        assert _changed_byte_count(buf, n) == 0
        buf[n - 1] = 0x00
        assert _changed_byte_count(buf, n) == 1
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < n


def test_large_sentinel_refusal_survives_snapshot() -> None:
    """R9-2: multi-megabyte reads reach the data call and record refusals."""
    n = 4 * 1024 * 1024

    def _get(_session: int, _handle: int, attrs: Any, count: int) -> int:
        assert count == 1
        if attrs[0].pValue:
            attrs[0].ulValueLen = int(CK_UNAVAILABLE_INFORMATION)
        else:
            attrs[0].ulValueLen = n
        return int(CKR_ATTRIBUTE_SENSITIVE)

    result = read_attributes(_raw(_get), 1, 1, [CKA_LABEL])
    assert CKA_LABEL not in result
    refusal = result.refusals[CKA_LABEL]
    assert refusal.ckr == int(CKR_ATTRIBUTE_SENSITIVE)
    assert refusal.leaked_len is None


def test_attr_or_record_reports_malformed_refusal_as_named_deviation() -> None:
    """R8-1: malformed refusals deviate by name, never forward as clean."""
    from pkcs11_check.raw.recipes import AttrReadResult

    attrs = AttrReadResult()
    attrs.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_TYPE_INVALID), malformed=True)
    value = attr_or_record(attrs, CKA_VALUE, label="malformed refusal", reason="honest_deviation")
    assert value is MISSING_ATTRIBUTE
    record = get_records()[-1]
    assert record.reason == "honest_deviation"
    assert "malformed" in (record.summary or "")
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID"
    assert record.detail.get("malformed_refusal") is True


def test_refusal_rv_for_withholds_malformed_refusal() -> None:
    """R8-1: malformed refusals stay out of negative-operation classifiers."""
    from pkcs11_check.raw.recipes import AttrReadResult
    from pkcs11_check.testcases._attribute_values import refusal_rv_for

    attrs = AttrReadResult()
    attrs.refusals[CKA_VALUE] = AttrRefusal(ckr=int(CKR_ATTRIBUTE_TYPE_INVALID), malformed=True)
    assert refusal_rv_for(attrs, CKA_VALUE) is None


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
    test then observed a plain return of ``True`` instead of a fail (red).
    """
    with pytest.raises(Failed) as ei:
        require_ulong_attr(True, label="malformed ulong")
    assert not isinstance(ei.value, XFailed)
    assert get_records()[-1].reason == "wrong_result"


def test_require_ulong_attr_rejects_non_int() -> None:
    with pytest.raises(Failed) as ei:
        require_ulong_attr("not-an-int", label="malformed ulong")
    assert not isinstance(ei.value, XFailed)
    assert get_records()[-1].reason == "wrong_result"


def test_require_ulong_attr_missing_unguarded_xfails_absent() -> None:
    """F-006: an unguarded MISSING_ATTRIBUTE sentinel xfails with a clean
    "attribute absent" message (the absence itself was already recorded
    upstream); only present-malformed values fail.
    """
    with pytest.raises(pytest.xfail.Exception):
        require_ulong_attr(MISSING_ATTRIBUTE, label="fed MISSING_ATTRIBUTE unguarded")
    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert "attribute absent" in record.summary
    assert "<object object at" not in record.summary


def test_require_bool_attr_returns_valid_bool() -> None:
    assert require_bool_attr(True, label="x") is True
    assert require_bool_attr(False, label="x") is False


def test_require_bool_attr_rejects_int() -> None:
    """1/0 are not CK_BBOOL True/False in this codebase's decoding -- only real bool.

    Mutation used: changed the guard to ``isinstance(value, int)`` -- this test's
    ``pytest.raises(Failed)`` then failed to see any exception (red,
    since 1 is an int).
    """
    with pytest.raises(Failed) as ei:
        require_bool_attr(1, label="malformed bool")
    assert not isinstance(ei.value, XFailed)
    assert get_records()[-1].reason == "wrong_result"


def test_require_bool_attr_missing_unguarded_xfails_absent() -> None:
    """F-006: missing stays not_operational/xfail with a clean absent message."""
    with pytest.raises(pytest.xfail.Exception):
        require_bool_attr(MISSING_ATTRIBUTE, label="fed MISSING_ATTRIBUTE unguarded")
    record = get_records()[-1]
    assert record.reason == "not_operational"
    assert "attribute absent" in record.summary
    assert "<object object at" not in record.summary


def test_require_ulong_attr_present_malformed_fails() -> None:
    """F-006: a present value with the wrong ABI shape is wrong_result (fail).

    Same rule as the enforcement analog (``_record_malformed_attribute``) and
    the access-levels validator: successfully returned malformed metadata
    differs from a clean refusal or a missing value.
    """
    with pytest.raises(Failed) as ei:
        require_ulong_attr(b"\x01\x02", label="malformed ulong")
    assert not isinstance(ei.value, XFailed)
    assert get_records()[-1].reason == "wrong_result"


def test_require_bool_attr_present_malformed_fails() -> None:
    """F-006: a present value with the wrong ABI shape is wrong_result (fail)."""
    with pytest.raises(Failed) as ei:
        require_bool_attr(b"\x01\x02", label="malformed bool")
    assert not isinstance(ei.value, XFailed)
    assert get_records()[-1].reason == "wrong_result"


def test_attr_refusal_equality_and_defaults() -> None:
    assert AttrRefusal(ckr=1) == AttrRefusal(ckr=1)
    assert AttrRefusal(ckr=1).leaked_len is None
    assert AttrRefusal(ckr=1, leaked_len=4) != AttrRefusal(ckr=1)
