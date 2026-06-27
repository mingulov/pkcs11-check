"""Runtime classification meta-tests for ckr/test_ckr_verify crypto reclassification.

Two key-type / signature-length confusion conditions are crypto-correctness
breaks: an AES key accepted with an RSA verify mechanism, and a wrong-length
RSA signature accepted at C_Verify. Their expectations must drop allow_success
so the 3-way assert_ckr fails on CKR_OK, passes on the expected reject, and
xfails on another clean reject.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed

from pkcs11_check.raw.types_std import (
    CKR_DEVICE_ERROR,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_OK,
    CKR_SIGNATURE_LEN_RANGE,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_VERIFY, assert_ckr

_KEY_TYPE = CKR_VERIFY["init_key_type_inconsistent"]
_SIG_LEN = CKR_VERIFY["signature_len_range"]


def test_expectations_drop_allow_success() -> None:
    assert _KEY_TYPE.allow_success is False
    assert _SIG_LEN.allow_success is False


def test_key_type_accepted_fails() -> None:
    with pytest.raises(Failed):
        assert_ckr(_KEY_TYPE, CKR_OK, strict=False)


def test_key_type_expected_passes() -> None:
    assert_ckr(_KEY_TYPE, int(CKR_KEY_TYPE_INCONSISTENT), strict=False)


def test_key_type_other_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(_KEY_TYPE, int(CKR_DEVICE_ERROR), strict=False)


def test_sig_len_accepted_fails() -> None:
    with pytest.raises(Failed):
        assert_ckr(_SIG_LEN, CKR_OK, strict=False)


def test_sig_len_expected_passes() -> None:
    assert_ckr(_SIG_LEN, int(CKR_SIGNATURE_LEN_RANGE), strict=False)


def test_sig_len_other_xfails() -> None:
    with pytest.raises(pytest.xfail.Exception):
        assert_ckr(_SIG_LEN, int(CKR_DEVICE_ERROR), strict=False)
