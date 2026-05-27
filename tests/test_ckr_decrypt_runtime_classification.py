"""Runtime classification meta-tests for ckr/test_ckr_decrypt Type-A reclassification.

Wrong-length RSA ciphertext that decrypts is a crypto-correctness break: the
rsa_ciphertext_wrong_length expectation must no longer carry allow_success, so
the 3-way assert_ckr fails on CKR_OK, passes on the expected reject, and xfails
on another clean reject.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_DECRYPT, assert_ckr

_EXP = CKR_DECRYPT["rsa_ciphertext_wrong_length"]


def test_wrong_length_expectation_drops_allow_success() -> None:
    assert _EXP.allow_success is False


def test_accepted_wrong_length_fails() -> None:
    with pytest.raises(Failed):
        assert_ckr(_EXP, CKR_OK, strict=False)


def test_expected_reject_passes() -> None:
    assert_ckr(_EXP, int(CKR_ENCRYPTED_DATA_LEN_RANGE), strict=False)


def test_other_clean_reject_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(_EXP, int(CKR_DEVICE_ERROR), strict=False)
