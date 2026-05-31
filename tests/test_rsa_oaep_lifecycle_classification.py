"""Regression test for PC-4.3: RSA-OAEP wrap/unwrap lifecycle legs that
return a clean OAEP-runtime reject (``CKR_ARGUMENTS_BAD``, etc.) must
classify as ``xfail`` (advertised but not operational), not a hard fail.

A clean reject NOT in the set (e.g. ``CKR_DEVICE_ERROR``) must propagate
as a real AssertionError -- the test fails honestly rather than xfailing
on an unrecognized signal.

Catalog: PC-4.3, softhsm2-recheck-20260528 evidence shows
``CkrAssertionError(rv=CKR_ARGUMENTS_BAD)`` at the wrap_key call site
in ``test_mech_lifecycle.py``.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
)
from pkcs11_check.testcases.conftest import xfail_if_known_ckr
from pkcs11_check.testcases.test_mech_lifecycle import (
    _RSA_OAEP_RUNTIME_REJECT_RVS,
)


def _exc(rv: int, ckr_name: str) -> CkrAssertionError:
    return CkrAssertionError(f"Unexpected CK_RV {ckr_name}; expected one of: CKR_OK", rv)


def test_wrap_reject_xfails() -> None:
    """softhsm2 case: wrap_key raises CkrAssertionError(rv=CKR_ARGUMENTS_BAD)
    -> xfail_if_known_ckr matches the OAEP runtime-reject set -> xfail.
    """
    with pytest.raises(pytest.xfail.Exception):
        try:
            raise _exc(int(CKR_ARGUMENTS_BAD), "CKR_ARGUMENTS_BAD")
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _RSA_OAEP_RUNTIME_REJECT_RVS,
                "RSA-OAEP wrap advertised but not operational",
            )


def test_unwrap_reject_xfails() -> None:
    """Symmetric: a clean OAEP-runtime reject at the unwrap leg also xfails."""
    with pytest.raises(pytest.xfail.Exception):
        try:
            raise _exc(int(CKR_FUNCTION_NOT_SUPPORTED), "CKR_FUNCTION_NOT_SUPPORTED")
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _RSA_OAEP_RUNTIME_REJECT_RVS,
                "RSA-OAEP unwrap advertised but not operational",
            )


def test_unknown_ckr_propagates() -> None:
    """CKR_DEVICE_ERROR is not in the OAEP runtime-reject set -> the
    classifier re-raises -> the test legitimately fails (no silent xfail).
    """
    with pytest.raises(AssertionError) as ei:
        try:
            raise _exc(int(CKR_DEVICE_ERROR), "CKR_DEVICE_ERROR")
        except AssertionError as exc:
            xfail_if_known_ckr(
                exc,
                _RSA_OAEP_RUNTIME_REJECT_RVS,
                "RSA-OAEP not operational",
            )
    # Confirm it is NOT an xfail outcome (xfail.Exception is also subclass
    # of BaseException; AssertionError is what we want).
    assert not isinstance(ei.value, pytest.xfail.Exception)
