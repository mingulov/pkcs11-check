"""Contract tests for find-by-sealed-component verdicts (#54.2, B1)."""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed

from pkcs11_check import classification
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_TYPE_INVALID,
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
) -> sens._FindOutcome:
    return sens._FindOutcome(init_rv=init, find_rv=find, final_rv=final, handles=handles)


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


def test_screen_full_page_without_member_skips() -> None:
    """B1: a full page may hide the sealed handle on page 2: unproved."""
    with pytest.raises(Skipped):
        sens._screen_sealed_find(outcome=_out(handles=tuple(range(8))), handle=42, label="sealed")


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
    assert classification.get_records() == []


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
