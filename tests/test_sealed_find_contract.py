"""Contract tests for find-by-sealed-component verdicts (#54.2, B1)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DEVICE_ERROR,
    CKR_OK,
)
from pkcs11_check.testcases import test_sensitivity as sens

_OK = int(CKR_OK)


def _out(
    init: int = _OK,
    find: int = _OK,
    final: int = _OK,
    handles: tuple[int, ...] = (),
    complete: bool = True,
) -> sens._FindOutcome:
    return sens._FindOutcome(
        init_rv=init, find_rv=find, final_rv=final, handles=handles, complete=complete
    )


class _PagedRaw:
    """Find surface with scripted pages, Init/Final RVs, and call counts."""

    def __init__(
        self,
        pages: list[tuple[int, ...] | int],
        *,
        init_rv: int = _OK,
        final_rv: int = _OK,
    ) -> None:
        self._pages = [list(p) if isinstance(p, tuple) else p for p in pages]
        self._init_rv = init_rv
        self._final_rv = final_rv
        self.find_calls = 0
        self.final_calls = 0

    def C_FindObjectsInit(self, _sh: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
        return self._init_rv

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, found_ptr: Any) -> int:  # noqa: N802
        import ctypes

        from pkcs11_check.raw.types_std import CK_ULONG

        self.find_calls += 1
        if not self._pages:
            page: tuple[int, ...] | int = ()
        else:
            page = self._pages.pop(0)
        if isinstance(page, int):
            ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = 0
            return page
        for i, handle in enumerate(page[:max_count]):
            handles[i] = handle
        ctypes.cast(found_ptr, ctypes.POINTER(CK_ULONG)).contents.value = len(page)
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        self.final_calls += 1
        return self._final_rv


def _page_tmpl() -> Any:
    import ctypes

    return SimpleNamespace(ptr=ctypes.c_void_p(None), count=0)


def test_screen_member_match_xfails_spec_silent() -> None:
    # v3.2 §5.7.7 implies byte-exact match with no sensitivity
    # carve-out: a sealed match is recorded oracle surface (xfail),
    # never a conformance defect (fail).
    with pytest.raises(XFailed):
        sens._screen_sealed_find(outcome=_out(handles=(7, 42)), handle=42, label="sealed")


def test_screen_foreign_hits_without_member_pass_screen() -> None:
    """B1: hits not containing the sealed handle are not a sealed match."""
    sens._screen_sealed_find(outcome=_out(handles=(7,)), handle=42, label="sealed")
    assert classification.get_records() == []


def test_screen_undefined_rv_fails() -> None:
    with pytest.raises(Failed):
        sens._screen_sealed_find(outcome=_out(find=0xDEAD), handle=42, label="sealed")


def test_screen_incomplete_without_member_skips() -> None:
    """R2A3: an unfinished search cannot prove absence: unproved."""
    with pytest.raises(Skipped):
        sens._screen_sealed_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), handles=(7,), complete=False),
            handle=42,
            label="sealed",
        )


def test_screen_member_survives_final_refusal() -> None:
    """R2A3: delivering pages prove the match even when Final refuses."""
    with pytest.raises(XFailed):
        sens._screen_sealed_find(
            outcome=_out(final=int(CKR_ATTRIBUTE_VALUE_INVALID), handles=(42,)),
            handle=42,
            label="sealed",
        )


def test_screen_undefined_final_behind_refused_find_fails() -> None:
    """R2A3: per-stage scan; no collapse hides an undefined Final."""
    with pytest.raises(Failed):
        sens._screen_sealed_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), final=0xDEAD, complete=False),
            handle=42,
            label="sealed",
        )


def test_control_incomplete_skips() -> None:
    """R2A3: a short page cannot prove exactly-one: unproved."""
    with pytest.raises(Skipped):
        sens._judge_find_control(
            outcome=_out(find=int(CKR_DEVICE_ERROR), handles=(42,), complete=False),
            handle=42,
            label="control",
        )


def test_control_exact_handle_passes() -> None:
    sens._judge_find_control(outcome=_out(handles=(42,)), handle=42, label="control")
    assert classification.get_records() == []


def test_control_zero_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(outcome=_out(handles=()), handle=42, label="control")


def test_control_two_fails() -> None:
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(handles=(42, 43)), handle=42, label="control")


def test_control_wrong_member_fails() -> None:
    """B1: exactly one hit that is not the control is a wrong result."""
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(handles=(43,)), handle=42, label="control")


def test_control_refused_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(
            outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), handle=42, label="control"
        )


def test_control_undefined_rv_fails() -> None:
    """B1: validity-first applies to the control leg too."""
    with pytest.raises(Failed):
        sens._judge_find_control(outcome=_out(find=0xDEAD), handle=42, label="control")


def test_negative_no_match_with_control_passes() -> None:
    sens._judge_sealed_negative(outcome=_out(handles=()), label="sealed", control_proved=True)
    assert classification.get_records() == []


def test_negative_no_match_without_control_skips() -> None:
    """B1: without control mechanics a no-match proves nothing (ML-DSA leg)."""
    with pytest.raises(Skipped):
        sens._judge_sealed_negative(outcome=_out(handles=()), label="sealed", control_proved=False)


def test_negative_clean_refusal_passes() -> None:
    sens._judge_sealed_negative(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)),
        label="sealed",
        control_proved=False,
    )
    (record,) = classification.get_records()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.outcome == "pass", record.summary
    assert record.operation == "C_FindObjectsInit", record.operation
    assert record.actual_ckr == "CKR_ATTRIBUTE_TYPE_INVALID", record.summary


def test_negative_device_error_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_sealed_negative(
            outcome=_out(find=int(CKR_DEVICE_ERROR)), label="sealed", control_proved=True
        )


def test_effective_rv_is_first_non_ok_stage() -> None:
    assert _out().effective_rv == _OK
    assert _out(init=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)
    assert _out(find=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)
    assert _out(final=int(CKR_DEVICE_ERROR)).effective_rv == int(CKR_DEVICE_ERROR)


def test_screen_init_refusal_reaches_negative() -> None:
    """R3F4: a clean Init refusal returns for the negative judge, never skips."""
    sens._screen_sealed_find(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), handle=7, label="L"
    )
    # No raise: the negative judge sanctions it.
    sens._judge_sealed_negative(
        outcome=_out(init=int(CKR_ATTRIBUTE_TYPE_INVALID)), label="L", control_proved=False
    )
    (record,) = classification.get_records()
    assert record.reason == "sanctioned_refusal", record.summary


def test_screen_final_refusal_with_empty_pages_skips() -> None:
    """R3F4: empty pages plus a refused Final cannot pass absence."""
    with pytest.raises(Skipped):
        sens._screen_sealed_find(
            outcome=_out(final=int(CKR_DEVICE_ERROR), complete=False), handle=7, label="L"
        )


def test_undefined_init_names_init_operation() -> None:
    """R3F4: undefined stage RVs carry their own operation."""
    with pytest.raises(Failed):
        sens._fail_undefined_find_rv("L", _out(init=0xDEAD))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.operation == "C_FindObjectsInit", record.operation
    assert "Init" in (record.summary or ""), record.summary


def test_undefined_final_names_final_operation() -> None:
    with pytest.raises(Failed):
        sens._fail_undefined_find_rv("L", _out(final=0xDEAD))
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.operation == "C_FindObjectsFinal", record.operation


def test_oversized_page_retained_sibling_graded() -> None:
    """R3F4: an oversized page records without raising; siblings still run."""
    raw = _PagedRaw([tuple(range(9))])
    outcome = sens._find_page(raw, 7, _page_tmpl())
    assert len(outcome.retained) == 1, outcome
    assert outcome.retained[0].reason == "self_contradiction"
    assert outcome.complete is False
    assert raw.final_calls == 1, "Final still runs after the retained defect"
    # Sibling evidence grades independently afterwards.
    with pytest.raises(Failed):
        classification.raise_for_record(outcome.retained[0])


def test_unbounded_pages_stop_at_cap_incomplete() -> None:
    """R3F4: a never-empty search stops at the paging bound, inconclusive."""
    raw = _PagedRaw([(9,)] * 1000)
    outcome = sens._find_page(raw, 7, _page_tmpl())
    assert outcome.complete is False
    assert raw.find_calls == sens._FIND_MAX_PAGES, raw.find_calls
    assert outcome.handles == (9,) * sens._FIND_MAX_PAGES


def test_match_recorded_before_control_skip() -> None:
    """R3F4: a sealed match journals before a control skip voids the verdict."""
    match = sens._record_sealed_match(outcome=_out(handles=(7,)), handle=7, label="L")
    assert match is not None
    with pytest.raises(Skipped):
        sens._judge_find_control(
            outcome=_out(find=int(CKR_DEVICE_ERROR)), handle=8, label="control"
        )
    journaled = [rec for rec in classification.get_records() if rec.reason == "honest_deviation"]
    assert len(journaled) == 1 and "oracle surface" in (journaled[0].summary or "")


def test_wrong_value_nonempty_fails() -> None:
    """R3F4: an absent value matching objects proves find is not selective."""
    with pytest.raises(Failed):
        sens._judge_wrong_value_find(outcome=_out(handles=(3,)), label="wrong")
    (record,) = [rec for rec in classification.get_records() if rec.outcome == "fail"]
    assert record.reason == "wrong_result", record.summary
    assert "not selective" in (record.summary or ""), record.summary


def test_wrong_value_empty_passes_refused_skips() -> None:
    sens._judge_wrong_value_find(outcome=_out(handles=()), label="wrong")
    with pytest.raises(Skipped):
        sens._judge_wrong_value_find(outcome=_out(init=int(CKR_DEVICE_ERROR)), label="wrong")
    with pytest.raises(Skipped):
        sens._judge_wrong_value_find(
            outcome=_out(find=int(CKR_DEVICE_ERROR), complete=False), label="wrong"
        )


def test_unreadable_proof_skips_when_readable() -> None:
    """R3F4: flags claiming sealed while bytes serve voids the premise."""
    from pkcs11_check.raw.rv import CkrAssertionError

    class _ReadableRaw:
        def C_GetAttributeValue(self, _sh: int, _handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
            for i in range(int(count)):
                tmpl[i].ulValueLen = 1
                if tmpl[i].pValue is not None:
                    import ctypes

                    ctypes.memmove(tmpl[i].pValue, b"\x00", 1)
            return _OK

    class _RefusingRaw:
        def C_GetAttributeValue(self, _sh: int, _handle: int, _tmpl: Any, _count: int) -> int:  # noqa: N802
            from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_SENSITIVE

            raise CkrAssertionError("sensitive", int(CKR_ATTRIBUTE_SENSITIVE))

    from types import SimpleNamespace

    from pkcs11_check.raw.types_std import CKA_VALUE

    with pytest.raises(Skipped):
        sens._skip_unless_sealed_unreadable(
            SimpleNamespace(raw=_ReadableRaw(), sh=1),
            7,
            int(CKA_VALUE),
            label="L",
            attr_name="CKA_VALUE",
        )
    sens._skip_unless_sealed_unreadable(
        SimpleNamespace(raw=_RefusingRaw(), sh=1),
        7,
        int(CKA_VALUE),
        label="L",
        attr_name="CKA_VALUE",
    )


def test_seed_import_validity_grades() -> None:
    """R3F4: fixture import refusals grade validity before the leg voids."""
    from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

    sens._grade_seed_import_rv(int(CKR_DEVICE_ERROR), label="L")
    with pytest.raises(XFailed):
        sens._grade_seed_import_rv(0x80000001, label="L")
    with pytest.raises(Failed):
        sens._grade_seed_import_rv(0xDEAD, label="L")
