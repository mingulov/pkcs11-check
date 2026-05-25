"""Regression tests for Wycheproof PBES2 runtime-result classification."""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_GENERAL_ERROR
from pkcs11_check.testcases.wycheproof import test_wycheproof_pbes2


@pytest.mark.parametrize(
    ("rv", "operation"),
    [
        (CKR_DEVICE_ERROR, "key derivation"),
        (CKR_GENERAL_ERROR, "decrypt"),
    ],
)
def test_pbes2_valid_runtime_rejects_are_xfail(rv: int, operation: str) -> None:
    """Advertised PBES2 setup/use rejects are findings, not raw failures."""
    exc = CkrAssertionError("Unexpected CK_RV", int(rv))

    with pytest.raises(pytest.xfail.Exception, match=f"PBES2 {operation}"):
        test_wycheproof_pbes2._xfail_if_pbes2_runtime_reject(
            exc,
            "pbes2_hmacsha1_aes_128_test.json:tc1-valid",
            operation,
        )
