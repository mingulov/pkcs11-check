"""Meta-tests for the table-centric classification model (classification-model-plan Phase 1).

These tests drive the classification helpers in isolation (no PKCS#11 provider),
asserting the three-way pass / xfail / fail behavior described in
docs/classification-model-design.md.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_OK,
    CKR_PIN_INCORRECT,
)
from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation, assert_ckr
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    reject_or_classify,
)


def test_ckr_expectation_kind_default_policy() -> None:
    e = CkrExpectation(
        function="f",
        condition="c",
        spec_ckr=0x70,
        compat_tuple=(0x70,),
        spec_ref="r",
    )
    assert e.kind == "policy"


# ---------------------------------------------------------------------------
# Task 2 — 3-way assert_ckr (other-reject -> xfail, CKR_OK -> fail)
# ---------------------------------------------------------------------------

_E = CkrExpectation(
    function="C_EncryptInit",
    condition="key_func_not_permitted",
    spec_ckr=CKR_KEY_FUNCTION_NOT_PERMITTED,
    compat_tuple=(CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_FUNCTION_FAILED),
    spec_ref="PKCS#11 v3.1 Sec.5.8.1",
)


def test_expected_passes() -> None:
    assert_ckr(_E, CKR_KEY_FUNCTION_NOT_PERMITTED, strict=False)


def test_other_clean_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(_E, CKR_FUNCTION_FAILED, strict=False)


def test_accepted_invalid_fails() -> None:
    with pytest.raises(Failed):
        assert_ckr(_E, CKR_OK, strict=False)


def test_outside_set_fails() -> None:
    # NOTE: plan snippet used CKR_DEVICE_ERROR, but that is a token-universal code
    # injected by full_compat(), so it lands in the xfail band rather than failing.
    # CKR_PIN_INCORRECT is genuinely outside the acceptable set, exercising the
    # "not in acceptable set -> fail" branch the test intends.
    with pytest.raises(Failed):
        assert_ckr(_E, CKR_PIN_INCORRECT, strict=False)


def test_allow_success_ok() -> None:
    e = CkrExpectation(
        function="C_Decrypt",
        condition="cbc_pad",
        spec_ckr=0x21,
        compat_tuple=(0x21,),
        spec_ref="r",
        allow_success=True,
    )
    assert_ckr(e, CKR_OK, strict=False)


def test_strict_wrong_code_fails() -> None:
    with pytest.raises(Failed):
        assert_ckr(_E, CKR_FUNCTION_FAILED, strict=True)


# ---------------------------------------------------------------------------
# Task 3 — negative helpers (rv-shaped + exception-shaped)
# ---------------------------------------------------------------------------


def _exc(rv: int) -> CkrAssertionError:
    # NOTE: CkrAssertionError.__init__ requires (message, rv); the plan snippet's
    # single-arg form + attribute assignment would not construct. Adapted minimally.
    return CkrAssertionError(f"rv={rv}", rv)


def test_rv_ok_fails() -> None:
    with pytest.raises(Failed):
        classify_negative_rv(CKR_OK, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")


def test_rv_expected_passes() -> None:
    classify_negative_rv(
        CKR_KEY_FUNCTION_NOT_PERMITTED, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x"
    )


def test_rv_other_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        classify_negative_rv(CKR_FUNCTION_FAILED, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")


def test_exc_none_is_fail() -> None:
    with pytest.raises(Failed):
        reject_or_classify(None, (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")


def test_exc_expected_passes() -> None:
    reject_or_classify(
        _exc(CKR_KEY_FUNCTION_NOT_PERMITTED), (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x"
    )


def test_exc_other_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        reject_or_classify(_exc(CKR_FUNCTION_FAILED), (CKR_KEY_FUNCTION_NOT_PERMITTED,), label="x")
