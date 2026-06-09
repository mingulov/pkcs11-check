"""Meta-tests for classify_discrimination (Pillar 2). No module needed."""
from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_GENERAL_ERROR
from pkcs11_check.testcases.conftest import classify_discrimination


def _clean(rv: int) -> CkrAssertionError:
    return CkrAssertionError("rejected", rv)


def test_discriminated_passes_regardless_of_code() -> None:
    # valid accepted + tampered rejected with a catch-all code -> returns (pass), no raise
    classify_discrimination(
        valid_accepted=True, invalid_outcome=_clean(CKR_DEVICE_ERROR), label="t"
    )
    classify_discrimination(
        valid_accepted=True, invalid_outcome=_clean(CKR_GENERAL_ERROR), label="t"
    )


def test_accepted_tampered_input_fails() -> None:
    # a produced handle (int) on the tampered input == acceptance == break
    with pytest.raises(pytest.fail.Exception):
        classify_discrimination(valid_accepted=True, invalid_outcome=12345, label="t")


def test_broken_valid_leg_fails() -> None:
    with pytest.raises(pytest.fail.Exception):
        classify_discrimination(
            valid_accepted=False, invalid_outcome=_clean(CKR_DEVICE_ERROR), label="t"
        )


def test_non_ckr_assertion_reraises_not_treated_as_reject() -> None:
    # D2: a harness AssertionError (no .rv) must re-raise, NOT count as detection
    with pytest.raises(AssertionError):
        classify_discrimination(
            valid_accepted=True, invalid_outcome=AssertionError("ctypes bug"), label="t"
        )
