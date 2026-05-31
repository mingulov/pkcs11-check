"""PC-5 regression: a KWP/KW wrap-setup rejection inside the crash-isolated child
must be classified (emit a SETUP_XFAIL marker the parent turns into pytest.xfail),
not propagate as an unhandled Python error the parent reports as a generic
"subprocess failed with exit code 1". An UNKNOWN reject must NOT be swallowed --
it re-raises so a real provider bug/crash still surfaces.
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR, CKR_KEY_FUNCTION_NOT_PERMITTED
from pkcs11_check.testcases.security.conftest import child_setup_reject_known


def test_known_wrap_reject_emits_setup_xfail_marker(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exc = CkrAssertionError(
        "Unexpected CK_RV CKR_KEY_FUNCTION_NOT_PERMITTED",
        int(CKR_KEY_FUNCTION_NOT_PERMITTED),
    )
    handled = child_setup_reject_known(
        exc, (int(CKR_KEY_FUNCTION_NOT_PERMITTED),), "AES key wrap setup rejected"
    )
    assert handled is True
    out = capsys.readouterr().out
    assert out.startswith("SETUP_XFAIL:AES key wrap setup rejected: CKR_KEY_FUNCTION_NOT_PERMITTED")


def test_unknown_reject_returns_false_and_stays_silent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exc = CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))
    handled = child_setup_reject_known(
        exc, (int(CKR_KEY_FUNCTION_NOT_PERMITTED),), "AES key wrap setup rejected"
    )
    assert handled is False
    assert capsys.readouterr().out == ""
