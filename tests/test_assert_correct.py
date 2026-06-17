"""Regression tests for assert_correct() KAT helper."""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed

from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import assert_correct


def test_mismatch_is_wrong_result_crypto_fail() -> None:
    C.clear()
    with pytest.raises(Failed):
        assert_correct(
            actual=b"\x01",
            expected=b"\x02",
            label="AES-KDF KAT",
            operation="C_DeriveKey",
            mechanism="CKM_SP800_108_COUNTER_KDF",
        )
    rec = C.get_records()[-1]
    assert rec.reason == "wrong_result" and rec.kind == "crypto" and rec.severity == "CRITICAL"


def test_match_passes_silently() -> None:
    C.clear()
    assert_correct(actual=b"\x01", expected=b"\x01", label="KAT")
    assert C.get_records() == []
