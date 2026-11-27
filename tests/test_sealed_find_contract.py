"""Contract tests for find-by-sealed-component verdicts (#54.2)."""

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


def test_sealed_find_match_xfails_spec_silent() -> None:
    # v3.2 §5.7.7 implies byte-exact match with no sensitivity
    # carve-out: a sealed match is recorded oracle surface (xfail),
    # never a conformance defect (fail).
    with pytest.raises(XFailed):
        sens._judge_sealed_find(rv=int(CKR_OK), count=1, label="sealed")


def test_sealed_find_no_match_passes() -> None:
    sens._judge_sealed_find(rv=int(CKR_OK), count=0, label="sealed")
    assert classification.get_records() == []


def test_sealed_find_clean_refusal_passes() -> None:
    sens._judge_sealed_find(rv=int(CKR_ATTRIBUTE_TYPE_INVALID), count=-1, label="sealed")
    assert classification.get_records() == []


def test_sealed_find_device_error_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_sealed_find(rv=int(CKR_DEVICE_ERROR), count=-1, label="sealed")


def test_sealed_find_undefined_rv_fails() -> None:
    with pytest.raises(Failed):
        sens._judge_sealed_find(rv=0xDEAD, count=-1, label="sealed")


def test_find_control_exact_one_passes() -> None:
    sens._judge_find_control(rv=int(CKR_OK), count=1, label="control")
    assert classification.get_records() == []


def test_find_control_zero_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(rv=int(CKR_OK), count=0, label="control")


def test_find_control_two_fails() -> None:
    with pytest.raises(Failed):
        sens._judge_find_control(rv=int(CKR_OK), count=2, label="control")


def test_find_control_refused_skips() -> None:
    with pytest.raises(Skipped):
        sens._judge_find_control(rv=int(CKR_ATTRIBUTE_TYPE_INVALID), count=-1, label="control")
