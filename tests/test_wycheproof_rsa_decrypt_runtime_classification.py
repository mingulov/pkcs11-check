"""Regression tests for Wycheproof RSA decrypt runtime reject classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_KEY_TYPE_INCONSISTENT
from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_decrypt


def test_rsa_pkcs1_decrypt_key_type_inconsistent_is_xfail() -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_KEY_TYPE_INCONSISTENT",
        int(CKR_KEY_TYPE_INCONSISTENT),
    )

    try:
        raise exc
    except AssertionError as caught:
        with pytest.raises(pytest.xfail.Exception, match="CKR_KEY_TYPE_INCONSISTENT"):
            test_wycheproof_rsa_decrypt._xfail_if_rsa_pkcs1_decrypt_runtime_reject(
                caught,
                "rsa_pkcs1_valid_vector",
            )
