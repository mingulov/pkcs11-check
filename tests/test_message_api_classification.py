"""Classification meta-tests for v3.0 message-API legs (Phase 6 P3).

Past the function-list/CKF_MESSAGE_* capability gate the op is advertised, so a
clean reject at use is advertised-but-rejecting -> ``xfail`` (not ``skip``). A
non-CKR error propagates.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_message as tmm


def test_message_init_helper_ok_returns() -> None:
    tmm._xfail_if_message_init_rejected(int(CKR_OK), label="x")  # no raise


def test_message_init_helper_clean_reject_xfails() -> None:
    with pytest.raises(XFailed):
        tmm._xfail_if_message_init_rejected(int(CKR_FUNCTION_FAILED), label="x")


def test_message_init_helper_other_code_falls_through() -> None:
    # A code outside the reject set returns (caller's `assert rv == CKR_OK` then
    # surfaces it as a real failure) -- it is neither pass nor xfail here.
    tmm._xfail_if_message_init_rejected(0x12345678, label="x")


def test_message_crypto_advertised_reject_xfails() -> None:
    # The message_crypto encrypt leg now xfails (not skips) on a clean reject.
    from pkcs11_check.testcases import test_message_crypto as tmc

    exc = CkrAssertionError("CKR_FUNCTION_NOT_SUPPORTED", int(CKR_FUNCTION_NOT_SUPPORTED))
    with pytest.raises(XFailed):
        try:
            raise exc
        except CkrAssertionError as e:
            tmc.xfail_if_known_ckr(e, tmc._MESSAGE_OP_REJECT_RVS, "advertised message encrypt")


def test_message_crypto_non_ckr_propagates() -> None:
    from pkcs11_check.testcases import test_message_crypto as tmc

    # A non-CKR assertion (no CKR name in the message) must re-raise, not xfail.
    with pytest.raises(AssertionError, match="python decoder bug") as ei:
        try:
            raise AssertionError("python decoder bug")
        except AssertionError as e:
            tmc.xfail_if_known_ckr(e, tmc._MESSAGE_OP_REJECT_RVS, "advertised message encrypt")
    assert not isinstance(ei.value, XFailed)
