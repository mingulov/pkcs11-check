"""Meta-tests for the MODULE_VERIFY_UNUSABLE_RVS branch in signature_rejected_or_xfail.

Each CKR in MODULE_VERIFY_UNUSABLE_RVS must produce an xfail with reason
``not_operational`` when passed through ``signature_rejected_or_xfail``.
``CKR_SIGNATURE_INVALID`` (a SIGNATURE_REJECT_RVS member) must still return False
(no xfail) -- confirming the two sets do not overlap.

Detection pattern mirrors ``tests/test_verify_roundtrip.py``: xfail_as / fail_as
route through classification.classify which raises pytest.xfail (-> XFailed) or
pytest.fail (-> Failed); we catch the outcome exception and inspect
``get_records()[-1].reason``.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_SIGNATURE_INVALID
from pkcs11_check.testcases._signature_policy import (
    MODULE_VERIFY_UNUSABLE_RVS,
    signature_rejected_or_xfail,
)


def _ckr(rv: int) -> CkrAssertionError:
    """Construct a CkrAssertionError with a specific rv (message, rv)."""
    return CkrAssertionError(f"unexpected {rv}", int(rv))


@pytest.mark.parametrize("rv", MODULE_VERIFY_UNUSABLE_RVS)
def test_unusable_rvs_xfail_not_operational(rv: object) -> None:
    """Every MODULE_VERIFY_UNUSABLE_RVS member -> xfail with reason not_operational."""
    clear()
    exc = _ckr(int(rv))  # type: ignore[arg-type]
    with pytest.raises(XFailed):
        signature_rejected_or_xfail(exc, "test-label")
    rec = get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.kind == "lifecycle"
    assert rec.outcome == "xfail"


def test_signature_invalid_returns_false() -> None:
    """CKR_SIGNATURE_INVALID is a clean reject -> returns False, no xfail."""
    clear()
    exc = _ckr(int(CKR_SIGNATURE_INVALID))
    result = signature_rejected_or_xfail(exc, "test-label")
    assert result is False
    assert get_records() == []
