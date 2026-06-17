"""Tests for classify_policy_enforcement emitting structured Classification records."""

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import classify_policy_enforcement


def test_claimed_then_violated_is_self_contradiction_fail() -> None:
    C.clear()
    with pytest.raises(Failed):
        classify_policy_enforcement(claimed=True, violated=True, label="CKA_SENSITIVE")
    rec = C.get_records()[-1]
    assert rec.reason == "self_contradiction" and rec.kind == "policy"


def test_not_claimed_is_honest_deviation_xfail() -> None:
    C.clear()
    with pytest.raises(XFailed):
        classify_policy_enforcement(claimed=False, violated=False, label="CKA_SENSITIVE")
    assert C.get_records()[-1].reason == "honest_deviation"
