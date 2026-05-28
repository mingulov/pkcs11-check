"""Regression test for PC-4.2: bit-flipped AES-KEY-WRAP ciphertext unwrap
that returns ``CKR_GENERAL_ERROR`` (softhsm2) must classify as ``xfail``
(noted deviation: not the RFC 3394 ICV-specific code), while acceptance
of the bit-flipped ciphertext (``CKR_OK``) still hard-fails (Type-A
security break).

Catalog: PC-4.2, softhsm2-recheck-20260528 evidence shows
``CkrAssertionError(rv=CKR_GENERAL_ERROR)`` at the unwrap_key call site
in ``test_authenticated_wrap.py``.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_GENERAL_ERROR,
    CKR_WRAPPED_KEY_INVALID,
)
from pkcs11_check.testcases.conftest import reject_or_classify

# The accepted set in production combines RFC 3394 ICV codes + per-module
# quirk_extras. The meta-test exercises the classifier semantics with a
# minimal subset; the production code passes the full set including
# quirk_extras() output.
_SPEC_ICV_CKRS = (int(CKR_WRAPPED_KEY_INVALID),)


def _exc(rv: int, ckr_name: str) -> CkrAssertionError:
    return CkrAssertionError(
        f"Unexpected CK_RV {ckr_name}; expected one of: CKR_OK", rv
    )


def test_icv_reject_passes() -> None:
    """CKR_WRAPPED_KEY_INVALID is the RFC 3394 ICV-specific code -> pass."""
    reject_or_classify(
        _exc(int(CKR_WRAPPED_KEY_INVALID), "CKR_WRAPPED_KEY_INVALID"),
        _SPEC_ICV_CKRS,
        label=(
            "AES-KEY-WRAP unwrap of bit-flipped ciphertext "
            "(expected RFC 3394 ICV reject)"
        ),
    )


def test_other_clean_reject_xfails() -> None:
    """The softhsm2-recheck case: CKR_GENERAL_ERROR is a clean reject but
    not the RFC 3394 ICV-specific code, so the classifier xfails (noted
    deviation), not hard-fails.
    """
    with pytest.raises(pytest.xfail.Exception):
        reject_or_classify(
            _exc(int(CKR_GENERAL_ERROR), "CKR_GENERAL_ERROR"),
            _SPEC_ICV_CKRS,
            label=(
                "AES-KEY-WRAP unwrap of bit-flipped ciphertext "
                "(expected RFC 3394 ICV reject)"
            ),
        )


def test_acceptance_still_fails() -> None:
    """Verify the ``reject_or_classify`` API contract on the ``exc=None``
    branch: calling it with ``None`` triggers ``pytest.fail``.

    Note: this branch is NOT exercised in production for this site. In
    production, ``CKR_OK`` (acceptance of bit-flipped ciphertext) means
    the ``except`` block is never entered; the Type-A acceptance guard
    is the post-``except`` ``pytest.fail("SECURITY: ...")`` at the
    bottom of ``test_aes_key_wrap_bit_flip_detected``. This test pins
    the classifier contract so a future refactor that changes the
    ``None`` semantics surfaces here.
    """
    from _pytest.outcomes import Failed

    with pytest.raises(Failed):
        reject_or_classify(
            None,
            _SPEC_ICV_CKRS,
            label="AES-KEY-WRAP unwrap of bit-flipped ciphertext",
        )
