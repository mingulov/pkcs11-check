"""Meta-tests for C_Digest undersized-buffer classification.

The probe declares a 1-byte output buffer (``*pulDigestLen = 1``) over a larger
real allocation and counts bytes written past the declared boundary, so the
return code and an actual OOB write are independent signals. A real buffer
overflow (overwritten > 0) is a security ``fail``; a CKR_OK with no overflow is
a clean PKCS#11 §5.10.2 return-code deviation (``xfail``), not a SECURITY break.
The original check conflated the two and hard-failed every provider.
"""

from __future__ import annotations

import pytest

from pkcs11_check.testcases.ckr.test_ckr_raw_buffer import (
    classify_undersized_digest_outcome,
)


def test_real_oob_write_is_security_fail() -> None:
    """Bytes written past the declared 1-byte boundary = real OOB write -> fail."""
    with pytest.raises(pytest.fail.Exception, match="out-of-bounds write"):
        classify_undersized_digest_outcome(overwritten=31, ckr_ok=True)


def test_oob_write_fails_even_with_buffer_too_small_code() -> None:
    """An OOB write is a finding regardless of the return code."""
    with pytest.raises(pytest.fail.Exception, match="out-of-bounds write"):
        classify_undersized_digest_outcome(overwritten=5, ckr_ok=False)


def test_ckr_ok_without_overflow_is_xfail_not_security() -> None:
    """CKR_OK with no overflow = benign §5.10.2 return-code deviation -> xfail.

    This is what every probed provider does (softhsm2: CKR_OK, 0 overwritten).
    """
    with pytest.raises(pytest.xfail.Exception, match="clean return-code deviation"):
        classify_undersized_digest_outcome(overwritten=0, ckr_ok=True)


def test_buffer_too_small_without_overflow_returns_for_retry_checks() -> None:
    """The spec-correct path (CKR_BUFFER_TOO_SMALL, no overflow) is neither fail
    nor xfail here -- it returns so the caller runs the size-query retry checks."""
    assert classify_undersized_digest_outcome(overwritten=0, ckr_ok=False) is None
