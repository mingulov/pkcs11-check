"""Step 1 — failing test: assert_ckr must emit structured Classification records.

These tests will FAIL until Step 2 wires assert_ckr to classification.classify().
They verify that each assert_ckr decision branch emits a Classification record
with the correct reason and metadata, while preserving the existing outcome.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.raw.types_std import (
    CKR_DATA_INVALID,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
    CKR_PIN_INCORRECT,
    CKR_VENDOR_DEFINED,
)
from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation, assert_ckr

EXP = CkrExpectation(
    function="C_Decrypt",
    condition="malformed_ct",
    spec_ckr=CKR_DATA_INVALID,
    compat_tuple=(CKR_DATA_INVALID,),
    spec_ref="PKCS#11 v3.2 §6.13",
    kind="crypto",
)


# ---------------------------------------------------------------------------
# Compat mode: accepted_invalid (CKR_OK without allow_success)
# ---------------------------------------------------------------------------


def test_accept_is_fail_accepted_invalid() -> None:
    """CKR_OK without allow_success -> fail with reason=accepted_invalid."""
    C.clear()
    with pytest.raises(Failed):
        assert_ckr(EXP, CKR_OK, strict=False)
    rec = C.get_records()[-1]
    assert rec.reason == "accepted_invalid"
    assert rec.kind == "crypto"
    assert rec.spec_ref == "PKCS#11 v3.2 §6.13"


def test_nonspec_clean_code_is_xfail() -> None:
    """A compat-acceptable but non-spec code (CKR_DEVICE_ERROR) -> xfail, reason=nonspec_reject."""
    C.clear()
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(EXP, CKR_DEVICE_ERROR, strict=False)
    assert C.get_records()[-1].reason == "nonspec_reject"


# ---------------------------------------------------------------------------
# Compat mode: spec-correct rejection -> pass (no record emitted)
# ---------------------------------------------------------------------------


def test_spec_correct_rejection_emits_no_record() -> None:
    """Spec-correct rejection -> pass; no Classification record emitted."""
    C.clear()
    assert_ckr(EXP, CKR_DATA_INVALID, strict=False)
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# F-023: compat outside-set aligns with the directional rule
# ---------------------------------------------------------------------------


def test_outside_set_standard_clean_is_xfail() -> None:
    """F-023: a clean standard code outside the set -> xfail, like conftest."""
    C.clear()
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(EXP, CKR_PIN_INCORRECT, strict=False)
    rec = C.get_records()[-1]
    assert rec.reason == "nonspec_reject"
    assert rec.outcome == "xfail"


def test_outside_set_vendor_defined_is_xfail() -> None:
    """F-023: a vendor-defined code outside the set -> xfail, like conftest."""
    C.clear()
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(EXP, int(CKR_VENDOR_DEFINED) + 1, strict=False)
    rec = C.get_records()[-1]
    assert rec.reason == "nonspec_reject"
    assert rec.outcome == "xfail"


def test_outside_set_undefined_is_fail() -> None:
    """F-023: an arbitrary non-CKR integer is NOT a clean code -> fail."""
    C.clear()
    with pytest.raises(Failed) as ei:
        assert_ckr(EXP, 0x12345678, strict=False)
    assert not isinstance(ei.value, XFailed)
    rec = C.get_records()[-1]
    assert rec.reason == "self_contradiction"
    assert rec.kind == "metadata"
    assert rec.outcome == "fail"


# ---------------------------------------------------------------------------
# Compat mode: allow_success -> pass (no record emitted)
# ---------------------------------------------------------------------------


def test_allow_success_ok_emits_no_record() -> None:
    """CKR_OK with allow_success -> pass; no Classification record emitted."""
    exp_allow = CkrExpectation(
        function="C_Decrypt",
        condition="cbc_pad",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=(CKR_DATA_INVALID,),
        spec_ref="r",
        allow_success=True,
        kind="crypto",
    )
    C.clear()
    assert_ckr(exp_allow, CKR_OK, strict=False)
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# Strict mode: CKR_OK without allow_success -> fail
# ---------------------------------------------------------------------------


def test_strict_ok_without_allow_success_emits_accepted_invalid() -> None:
    """Strict mode: CKR_OK without allow_success -> fail with reason=accepted_invalid."""
    C.clear()
    with pytest.raises(Failed):
        assert_ckr(EXP, CKR_OK, strict=True)
    recs = C.get_records()
    assert recs, "expected a Classification record"
    rec = recs[-1]
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"


# ---------------------------------------------------------------------------
# Strict mode: non-spec code -> fail (outcome preserved)
# ---------------------------------------------------------------------------


def test_strict_nonspec_code_emits_fail_record() -> None:
    """Strict mode: a compat-acceptable code that is not spec -> fail (outcome preserved)."""
    # CKR_FUNCTION_FAILED is compat-acceptable (universal) but not spec for EXP.
    C.clear()
    with pytest.raises(Failed):
        assert_ckr(EXP, CKR_FUNCTION_FAILED, strict=True)
    recs = C.get_records()
    assert recs, "expected a Classification record"
    assert recs[-1].outcome == "fail"


# ---------------------------------------------------------------------------
# Strict mode: allow_success + CKR_OK -> pass (no record)
# ---------------------------------------------------------------------------


def test_strict_allow_success_ok_emits_no_record() -> None:
    """Strict mode: allow_success + CKR_OK -> pass; no record emitted."""
    exp_allow = CkrExpectation(
        function="C_Decrypt",
        condition="cbc_pad",
        spec_ckr=CKR_DATA_INVALID,
        compat_tuple=(CKR_DATA_INVALID,),
        spec_ref="r",
        allow_success=True,
        kind="crypto",
    )
    C.clear()
    assert_ckr(exp_allow, CKR_OK, strict=True)
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# Strict mode: spec-correct code -> pass (no record)
# ---------------------------------------------------------------------------


def test_strict_spec_correct_emits_no_record() -> None:
    """Strict mode: spec-correct code -> pass; no Classification record emitted."""
    C.clear()
    assert_ckr(EXP, CKR_DATA_INVALID, strict=True)
    assert C.get_records() == []


# ---------------------------------------------------------------------------
# Record fields: operation, label, spec_ref
# ---------------------------------------------------------------------------


def test_record_carries_function_and_condition() -> None:
    """The emitted record carries operation=function and label=condition."""
    C.clear()
    with pytest.raises(Failed):
        assert_ckr(EXP, CKR_OK, strict=False)
    rec = C.get_records()[-1]
    assert rec.operation == "C_Decrypt"
    assert rec.label == "malformed_ct"


def test_xfail_record_carries_expected_ckr() -> None:
    """The xfail record lists spec_ckr as expected."""
    C.clear()
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(EXP, CKR_DEVICE_ERROR, strict=False)
    rec = C.get_records()[-1]
    assert rec.expected_ckr is not None
    assert any("CKR_DATA_INVALID" in e for e in rec.expected_ckr)


def test_xfail_record_carries_key_function_not_permitted() -> None:
    """Verify nonspec_reject record when using a different expectation."""
    exp2 = CkrExpectation(
        function="C_EncryptInit",
        condition="key_func_not_permitted",
        spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
        compat_tuple=(CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_FUNCTION_FAILED),
        spec_ref="PKCS#11 v3.1 Sec.5.8.1",
        kind="policy",
    )
    C.clear()
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(exp2, CKR_FUNCTION_FAILED, strict=False)
    rec = C.get_records()[-1]
    assert rec.reason == "nonspec_reject"
    assert rec.kind == "policy"
    assert rec.operation == "C_EncryptInit"
