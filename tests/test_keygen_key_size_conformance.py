"""Meta-tests for classify_over_max_keygen.

Drives the helper directly (no PKCS#11 module needed) using the same
CkrAssertionError/outcome-detection pattern as tests/test_verify_roundtrip.py.

Cases:
  (a) exc=None (keygen succeeded) -> xfail "honest_deviation"
  (b) CkrAssertionError with CKR_KEY_SIZE_RANGE -> returns None (PASS)
  (c) CkrAssertionError with CKR_FUNCTION_NOT_SUPPORTED -> xfail "nonspec_reject"
  (d) CkrAssertionError with CKR_MECHANISM_INVALID -> xfail "nonspec_reject"
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_SIZE_RANGE,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases.acvp.test_keygen_key_size_conformance import (
    classify_over_max_keygen,
)

_LABEL = "RSA_PKCS_KEY_PAIR_GEN:5120-bit"


def _ckr(rv: int) -> CkrAssertionError:
    """Construct a CkrAssertionError carrying a specific .rv."""
    return CkrAssertionError(f"unexpected 0x{rv:08x}", int(rv))


# (a) keygen succeeded (exc=None) -> xfail "honest_deviation"
def test_success_gives_honest_deviation() -> None:
    clear()
    with pytest.raises(XFailed):
        classify_over_max_keygen(None, label=_LABEL)
    records = get_records()
    assert records, "expected a classification record"
    assert records[-1].reason == "honest_deviation"


# (b) CKR_KEY_SIZE_RANGE -> PASS (returns None, no record)
def test_key_size_range_is_pass() -> None:
    clear()
    result = classify_over_max_keygen(_ckr(int(CKR_KEY_SIZE_RANGE)), label=_LABEL)
    assert result is None
    assert get_records() == []


# (c) CKR_FUNCTION_NOT_SUPPORTED -> xfail "nonspec_reject"
def test_function_not_supported_gives_nonspec_reject() -> None:
    clear()
    with pytest.raises(XFailed):
        classify_over_max_keygen(_ckr(int(CKR_FUNCTION_NOT_SUPPORTED)), label=_LABEL)
    records = get_records()
    assert records, "expected a classification record"
    assert records[-1].reason == "nonspec_reject"


# (d) CKR_MECHANISM_INVALID -> xfail "nonspec_reject"
def test_mechanism_invalid_gives_nonspec_reject() -> None:
    clear()
    with pytest.raises(XFailed):
        classify_over_max_keygen(_ckr(int(CKR_MECHANISM_INVALID)), label=_LABEL)
    records = get_records()
    assert records, "expected a classification record"
    assert records[-1].reason == "nonspec_reject"
