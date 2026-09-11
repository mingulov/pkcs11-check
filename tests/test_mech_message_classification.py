"""Regression tests for test_mech_message._xfail_if_message_init_rejected.

CKR_FUNCTION_NOT_SUPPORTED from C_Message*Init is capability absence (the
optional v3.0 message function itself is unimplemented) -- skip, never an
"advertised but not operational" xfail deviation. A genuine mechanism-level
clean reject (e.g. CKR_MECHANISM_INVALID) must stay xfail.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.types_std import (
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases import test_mech_message as tmm
from tests._skip_assert import assert_skips


def test_message_init_ok_returns_quietly() -> None:
    tmm._xfail_if_message_init_rejected(int(CKR_OK), label="C_MessageEncryptInit (CKM_AES_GCM)")


def test_message_init_function_not_supported_is_skip() -> None:
    assert_skips(
        tmm._xfail_if_message_init_rejected,
        int(CKR_FUNCTION_NOT_SUPPORTED),
        label="C_MessageEncryptInit (CKM_AES_GCM)",
        match="C_MessageEncryptInit",
    )


def test_message_init_mechanism_invalid_stays_xfail() -> None:
    with pytest.raises(pytest.xfail.Exception, match="CKR_MECHANISM_INVALID"):
        tmm._xfail_if_message_init_rejected(
            int(CKR_MECHANISM_INVALID), label="C_MessageEncryptInit (CKM_AES_GCM)"
        )
