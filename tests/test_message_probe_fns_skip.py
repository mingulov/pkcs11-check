"""Regression tests for probe-level CKR_FUNCTION_NOT_SUPPORTED handling.

Both ``_probes/recover_length.py`` and ``_probes/_ffi_length_message.py`` drive
optional v3.0/v3.2 functions (C_SignRecoverInit/C_VerifyRecoverInit,
C_Message*Init/C_*MessageBegin). A clean CKR_FUNCTION_NOT_SUPPORTED from one of
those specific calls is capability absence, not a deviation: the child must print
a ``SKIP:`` line (for the parent to ``pytest.skip()`` on) instead of the generic
``SETUP_XFAIL:`` line reserved for genuine mechanism-level setup rejects.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED, CKR_MECHANISM_INVALID
from pkcs11_check.testcases._probes import _ffi_length_message as ffi_msg
from pkcs11_check.testcases._probes import recover_length


def test_recover_length_init_reject_skips_on_fns(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(recover_length._SetupXfailError):
        recover_length._setup_skip_if_init_not_supported(
            int(CKR_FUNCTION_NOT_SUPPORTED), "C_SignRecoverInit rejected"
        )
    out = capsys.readouterr().out
    assert out.startswith("SKIP:C_SignRecoverInit rejected")
    assert "SETUP_XFAIL:" not in out


def test_recover_length_init_reject_ignores_other_ckr(capsys: pytest.CaptureFixture[str]) -> None:
    # Must return quietly (no print, no raise) so the caller's own
    # _setup_xfail_if_known(...) call runs next and handles the mechanism-level reject.
    recover_length._setup_skip_if_init_not_supported(
        int(CKR_MECHANISM_INVALID), "C_SignRecoverInit rejected"
    )
    assert capsys.readouterr().out == ""


def test_ffi_length_message_setup_reject_skips_on_fns(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(ffi_msg._SetupRejected):
        ffi_msg._message_setup_reject(int(CKR_FUNCTION_NOT_SUPPORTED), "C_MessageEncryptInit")
    out = capsys.readouterr().out
    assert out.startswith("SKIP:C_MessageEncryptInit rejected")
    assert "SETUP_XFAIL:" not in out


def test_ffi_length_message_setup_reject_xfails_on_mechanism_invalid(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(ffi_msg._SetupRejected):
        ffi_msg._message_setup_reject(int(CKR_MECHANISM_INVALID), "C_MessageEncryptInit")
    out = capsys.readouterr().out
    assert out.startswith("SETUP_XFAIL:C_MessageEncryptInit rejected")
    assert "SKIP:" not in out
