"""Pure verdict logic for the over-delivery boundary probe."""

from __future__ import annotations

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_GENERAL_ERROR, CKR_KEY_SIZE_RANGE
from pkcs11_check.testcases.test_capability_boundary import (
    BoundaryCase,
    classify_boundary_outcome,
)


def _refused(rv: int) -> CkrAssertionError:
    return CkrAssertionError("refused", rv)


def test_refused_with_enforced_code_is_pass() -> None:
    # performed=False, a refusal with KEY_SIZE_RANGE -> enforced -> pass (None, no raise)
    assert (
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN,
            performed=False,
            refusal=_refused(int(CKR_KEY_SIZE_RANGE)),
            weak=True,
        )
        is None
    )


def test_refused_with_other_clean_code_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(
            BoundaryCase.BELOW_MIN,
            performed=False,
            refusal=_refused(int(CKR_GENERAL_ERROR)),
            weak=True,
        )


def test_performed_below_min_is_fail() -> None:
    with pytest.raises(Failed):
        classify_boundary_outcome(BoundaryCase.BELOW_MIN, performed=True, refusal=None, weak=True)


def test_performed_above_max_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(BoundaryCase.ABOVE_MAX, performed=True, refusal=None, weak=False)


def test_performed_unadvertised_known_weak_is_fail() -> None:
    with pytest.raises(Failed):
        classify_boundary_outcome(
            BoundaryCase.UNADVERTISED_MECH, performed=True, refusal=None, weak=True
        )


def test_performed_unadvertised_benign_is_xfail() -> None:
    with pytest.raises(XFailed):
        classify_boundary_outcome(
            BoundaryCase.UNADVERTISED_MECH, performed=True, refusal=None, weak=False
        )
