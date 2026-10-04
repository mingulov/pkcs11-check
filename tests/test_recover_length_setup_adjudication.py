"""Recover-length probe: per-site adjudication of setup refusal RVs.

Probe login is skipped when no PIN is configured, so CKR_USER_NOT_LOGGED_IN
from a *private-key* setup step is a conformant prerequisite failure
(not_operational), not a loud probe error. At public-key/keygen steps the
same RV is unexpected and must stay loud.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKR_DATA_LEN_RANGE,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases._probes import recover_length
from pkcs11_check.testcases._probes.recover_length import _SetupXfailError


class _RefuseInit:
    """Fake raw: keygen succeeds; one Init refused with USER_NOT_LOGGED_IN."""

    def __init__(self, op: str) -> None:
        self._op = op

    def C_GenerateKeyPair(self, *args: Any) -> int:  # noqa: N802
        args[-2]._obj.value = 7
        args[-1]._obj.value = 8
        return 0

    def C_SignRecoverInit(self, *args: Any) -> int:  # noqa: N802
        return int(CKR_USER_NOT_LOGGED_IN) if self._op == "C_SignRecoverInit" else 0

    def C_VerifyRecoverInit(self, *args: Any) -> int:  # noqa: N802
        return int(CKR_USER_NOT_LOGGED_IN) if self._op == "C_VerifyRecoverInit" else 0


def test_sign_init_login_required_xfails_not_operational(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Private-key C_SignRecoverInit refused for login -> SETUP_XFAIL, no raise."""
    with pytest.raises(_SetupXfailError):
        recover_length._sign_recover(
            _RefuseInit("C_SignRecoverInit"), 1, CK_OBJECT_HANDLE(8), b"\x00" * 256
        )
    out = capsys.readouterr().out
    assert "SETUP_XFAIL" in out
    assert "USER_NOT_LOGGED_IN" in out


def test_verify_init_login_required_stays_loud() -> None:
    """Public-key C_VerifyRecoverInit refused for login is unexpected -> loud."""
    from pkcs11_check.testcases._probes.session import ProbeContext

    ctx = ProbeContext(
        raw=_RefuseInit("C_VerifyRecoverInit"),  # type: ignore[arg-type]
        sh=1,
        slot_id=1,
        cleanup=lambda: None,
        module_path="test-module",
    )
    with pytest.raises(AssertionError, match="C_VerifyRecoverInit returned"):
        recover_length._run_verify_huge_sig_len(ctx, {"sig_len": 256})


def test_sign_init_unexpected_rv_stays_loud() -> None:
    """A non-clean RV at C_SignRecoverInit is still a loud probe error."""

    class _RefuseDataLen(_RefuseInit):
        def C_SignRecoverInit(self, *args: Any) -> int:  # noqa: N802
            return int(CKR_DATA_LEN_RANGE)

    with pytest.raises(AssertionError, match="C_SignRecoverInit returned"):
        recover_length._sign_recover(
            _RefuseDataLen("C_SignRecoverInit"), 1, CK_OBJECT_HANDLE(8), b"\x00" * 256
        )
