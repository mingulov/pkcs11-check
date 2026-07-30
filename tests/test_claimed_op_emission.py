"""The hollow-pass oracle's claimed-op signal must (HIGH-1) land on the passed CALL report,
not the teardown record the collector never reads, and (HIGH-3) only be emitted for tests that
actually EXPECT the operation to succeed productively -- a correctly-rejected negative vector
passes without any CKR_OK and must not inflate claimed_passes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pkcs11_check import classification
from pkcs11_check.classification import current_claimed_op, current_operation, set_mechanism
from pkcs11_check.plugin import _attach_claimed_op_to_report


@pytest.fixture(autouse=True)
def _clear_classification():
    classification.clear()
    yield
    classification.clear()


def _item(path: str = "/repo/src/pkcs11_check/testcases/wycheproof/test_x.py"):
    return SimpleNamespace(path=path, user_properties=[])


def _report(when: str, outcome: str):
    return SimpleNamespace(when=when, outcome=outcome, user_properties=[])


# ---- HIGH-3: expect_success gates the productive claim (classification layer) ----


def test_expect_success_true_declares_claim():
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    assert current_claimed_op() == "C_Verify"
    # operation metadata is unaffected (still used by classify records)
    assert current_operation() == "C_Verify"


def test_expect_success_false_declares_no_claim_but_keeps_operation():
    # A negative/rejection vector: the op is under test (metadata) but a pass does NOT
    # imply a productive CKR_OK invocation, so it must not count as a productive claim.
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=False)
    assert current_claimed_op() is None
    assert current_operation() == "C_Verify"


def test_expect_success_defaults_false():
    set_mechanism("CKM_ECDSA", operation="C_Verify")
    assert current_claimed_op() is None


# ---- HIGH-1: emission lands on the passed CALL report ----


def test_attach_puts_claimed_op_on_passed_call_report():
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    report = _report("call", "passed")
    _attach_claimed_op_to_report(_item(), report)
    assert ("pkcs11_claimed_op", "C_Verify") in report.user_properties


def test_attach_ignores_teardown_report():
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    report = _report("teardown", "passed")
    _attach_claimed_op_to_report(_item(), report)
    assert report.user_properties == []


def test_attach_ignores_failed_call_report():
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    report = _report("call", "failed")
    _attach_claimed_op_to_report(_item(), report)
    assert report.user_properties == []


def test_attach_ignores_non_testcase_item():
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=True)
    report = _report("call", "passed")
    _attach_claimed_op_to_report(_item(path="/repo/tests/test_meta.py"), report)
    assert report.user_properties == []


def test_attach_skips_negative_vector_pass():
    # HIGH-3 end effect: a passing rejection test declared expect_success=False -> no claim.
    set_mechanism("CKM_ECDSA", operation="C_Verify", expect_success=False)
    report = _report("call", "passed")
    _attach_claimed_op_to_report(_item(), report)
    assert report.user_properties == []
