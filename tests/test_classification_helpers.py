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
    classify_lifecycle_effect,
    classify_negative_rv,
    classify_policy_enforcement,
    is_known_error,
    reject_or_classify,
    xfail_if_known_ckr,
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


def test_device_error_xfails_neutrally() -> None:
    """CKR_DEVICE_ERROR -> xfail with a provider-neutral message (H-CLASS-2).

    This is the classifier safety net that the deleted provider-named
    ``if rv == CKR_DEVICE_ERROR: pytest.xfail("Kryoptic ...")`` pre-guards in
    the ckr/ verify tests relied on: CKR_DEVICE_ERROR is token-universal
    (injected by full_compat) so it lands in the xfail band, never naming a
    provider.
    """
    from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR

    with pytest.raises(pytest.xfail.Exception) as ei:
        assert_ckr(_E, CKR_DEVICE_ERROR, strict=False)
    msg = str(ei.value).lower()
    assert "kryoptic" not in msg
    assert "tpm2" not in msg


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


# ---------------------------------------------------------------------------
# Task 4 — Type-B / Type-C self-contradiction classifiers
# ---------------------------------------------------------------------------


def test_policy_claimed_violated_fails() -> None:
    with pytest.raises(Failed):
        classify_policy_enforcement(claimed=True, violated=True, label="x")


def test_policy_not_claimed_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        classify_policy_enforcement(claimed=False, violated=True, label="x")


def test_policy_claimed_ok_passes() -> None:
    classify_policy_enforcement(claimed=True, violated=False, label="x")


def test_lifecycle_claimed_effect_fails() -> None:
    with pytest.raises(Failed):
        classify_lifecycle_effect(claimed_success=True, effect_observed=True, label="x")


# ---------------------------------------------------------------------------
# M3 — substring CKR matching must not match an EXPECTED name in the message
# ---------------------------------------------------------------------------

# A CkrAssertionError carries the offending rv as .rv; expect_rv builds a
# message of the form:
#   "Unexpected CK_RV <ACTUAL>; expected one of: <EXPECTED...>"
# A naive substring scan of the whole message can match one of the EXPECTED
# names even though the ACTUAL return differs -- wrongly classifying a genuine
# failure as a "known" CKR and routing it to xfail/skip.
_KNOWN = (CKR_KEY_FUNCTION_NOT_PERMITTED,)


def test_is_known_error_prefers_exact_rv_when_present() -> None:
    """With .rv set, matching uses the actual rv, ignoring expected names in msg."""
    # Actual rv (CKR_FUNCTION_FAILED) is NOT in the known set; the expected name
    # IS in the message text. Must return False (real fail surfaces).
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_FUNCTION_FAILED,
    )
    assert is_known_error(exc, set(_KNOWN)) is False
    # Conversely, when the actual rv IS in the known set -> True.
    exc2 = CkrAssertionError(
        "Unexpected CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED", CKR_KEY_FUNCTION_NOT_PERMITTED
    )
    assert is_known_error(exc2, set(_KNOWN)) is True


def test_is_known_error_substring_fallback_ignores_expected_portion() -> None:
    """Without .rv, the fallback must only consider the ACTUAL-rv portion.

    The expected-names tail ("; expected one of: ...") must not be matched, so a
    plain AssertionError whose actual code differs is NOT treated as known.
    """
    exc = AssertionError(
        "Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_KEY_FUNCTION_NOT_PERMITTED"
    )
    assert is_known_error(exc, set(_KNOWN)) is False


def test_is_known_error_substring_fallback_matches_actual() -> None:
    """Without .rv, a genuine match on the ACTUAL-rv portion is still honored."""
    exc = AssertionError(
        "Unexpected CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED; expected one of: CKR_FUNCTION_FAILED"
    )
    assert is_known_error(exc, set(_KNOWN)) is True


def test_xfail_if_known_ckr_reraises_on_prefix_collision() -> None:
    """A real failure (actual not in known set) must propagate, not become xfail."""
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_FUNCTION_FAILED; expected one of: CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_FUNCTION_FAILED,
    )
    with pytest.raises(CkrAssertionError):
        try:
            raise exc
        except CkrAssertionError as e:
            xfail_if_known_ckr(e, set(_KNOWN), "ckr probe")
