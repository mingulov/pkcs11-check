"""Tests for classify_lifecycle_effect emitting structured Classification records."""

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check import classification as C
from pkcs11_check.testcases.conftest import classify_lifecycle_effect


def test_success_then_contradicted_is_self_contradiction_fail() -> None:
    C.clear()
    with pytest.raises(Failed):
        classify_lifecycle_effect(claimed_success=True, effect_observed=True, label="destroy")
    rec = C.get_records()[-1]
    assert rec.reason == "self_contradiction" and rec.kind == "lifecycle"


def test_no_success_claim_is_honest_deviation_xfail() -> None:
    C.clear()
    with pytest.raises(XFailed):
        classify_lifecycle_effect(claimed_success=False, effect_observed=False, label="destroy")
    assert C.get_records()[-1].reason == "honest_deviation"
