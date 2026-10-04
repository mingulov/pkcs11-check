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


def test_mismatch_inherit_mechanism_false_keeps_none() -> None:
    C.clear()
    C.set_mechanism("CKM_AES_ECB", operation="C_Encrypt", expect_success=False)
    try:
        with pytest.raises(Failed):
            assert_correct(
                actual=b"\x01",
                expected=b"\x02",
                label="CKO_DATA value readback",
                operation="C_GetAttributeValue",
                kind="metadata",
                inherit_mechanism=False,
            )
    finally:
        C.set_mechanism(None, operation=None)
    rec = C.get_records()[-1]
    assert rec.mechanism is None


def test_mismatch_inherits_active_mechanism_by_default() -> None:
    C.clear()
    C.set_mechanism("CKM_AES_ECB", operation="C_Encrypt", expect_success=False)
    try:
        with pytest.raises(Failed):
            assert_correct(
                actual=b"\x01",
                expected=b"\x02",
                label="AES-KDF KAT",
                operation="C_DeriveKey",
            )
    finally:
        C.set_mechanism(None, operation=None)
    rec = C.get_records()[-1]
    assert rec.mechanism == "CKM_AES_ECB"
