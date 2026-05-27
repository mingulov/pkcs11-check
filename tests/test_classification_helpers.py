"""Meta-tests for the table-centric classification model (classification-model-plan Phase 1).

These tests drive the classification helpers in isolation (no PKCS#11 provider),
asserting the three-way pass / xfail / fail behavior described in
docs/classification-model-design.md.
"""

from __future__ import annotations

from pkcs11_check.testcases.ckr._ckr_spec import CkrExpectation


def test_ckr_expectation_kind_default_policy() -> None:
    e = CkrExpectation(
        function="f",
        condition="c",
        spec_ckr=0x70,
        compat_tuple=(0x70,),
        spec_ref="r",
    )
    assert e.kind == "policy"
