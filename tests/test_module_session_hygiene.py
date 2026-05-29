"""The shared module-scoped session must hand out a CLEAN session each test.

Regression test for the CKR_OPERATION_ACTIVE cascade. Some providers
(kryoptic v1.5.0, tpm2-pkcs11) violate the PKCS#11 spec by leaving a
verification operation active after C_Verify rejects a signature
(CKR_SIGNATURE_INVALID / CKR_SIGNATURE_LEN_RANGE) -- the spec says "a call to
C_Verify always terminates the active verification operation." Because
``p11_module_session`` shares ONE session across every test in a file, that
single dangling operation made every subsequent C_VerifyInit return
CKR_OPERATION_ACTIVE, cascading thousands of spurious failures onto unrelated
tests.

The holder must proactively cancel any dangling operation on each handout so a
single provider misbehavior cannot corrupt sibling tests. (The genuine finding
-- that the provider failed to terminate the op -- is surfaced separately by
``testcases/test_operation_termination.py``; this hygiene step only prevents
the collateral cascade.)
"""

from __future__ import annotations

from pkcs11_check.fixtures import _ModuleSessionHolder
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT,
    CKF_DIGEST,
    CKF_ENCRYPT,
    CKF_SIGN,
    CKF_SIGN_RECOVER,
    CKF_VERIFY,
    CKF_VERIFY_RECOVER,
    CKR_OK,
)


class _RecordingRaw:
    """Minimal RawPKCS11 stand-in that reports a healthy session and records
    every C_SessionCancel call."""

    def __init__(self) -> None:
        self.cancel_calls: list[tuple[int, int]] = []

    def C_GetSessionInfo(self, sh: int, info_ptr: object) -> int:  # noqa: N802
        return CKR_OK

    def C_SessionCancel(self, sh: int, flags: int) -> int:  # noqa: N802
        self.cancel_calls.append((sh, int(flags)))
        return CKR_OK


class _PreV30Raw:
    """Pre-v3.0 module: healthy session but no C_SessionCancel attribute."""

    def C_GetSessionInfo(self, sh: int, info_ptr: object) -> int:  # noqa: N802
        return CKR_OK


class _Module:
    def __init__(self, raw: object) -> None:
        self.raw = raw


def _holder_with(raw: object) -> _ModuleSessionHolder:
    # _Module/object are minimal stubs; config is unused while the session is healthy.
    holder = _ModuleSessionHolder(_Module(raw), object())  # type: ignore[arg-type]
    holder._sh = 42
    holder._slot_id = 0
    holder._logged_in = False  # skip the login-state branch of the health check
    return holder


def test_handout_cancels_dangling_operations() -> None:
    raw = _RecordingRaw()
    holder = _holder_with(raw)

    sh, slot_id, _ = holder.get_session()

    assert (sh, slot_id) == (42, 0)
    assert raw.cancel_calls, "get_session must C_SessionCancel on every handout"
    sh_arg, flags = raw.cancel_calls[-1]
    assert sh_arg == 42
    # Every single-shot crypto operation class must be covered so a leftover op
    # of ANY type is cleared, not just verify.
    for flag in (
        CKF_ENCRYPT,
        CKF_DECRYPT,
        CKF_DIGEST,
        CKF_SIGN,
        CKF_SIGN_RECOVER,
        CKF_VERIFY,
        CKF_VERIFY_RECOVER,
    ):
        assert flags & flag, f"cancel mask missing operation flag 0x{flag:x}"


def test_handout_tolerates_pre_v30_modules_without_session_cancel() -> None:
    # Pre-v3.0 modules lack C_SessionCancel; the handout must not raise.
    holder = _holder_with(_PreV30Raw())
    sh, slot_id, _ = holder.get_session()
    assert (sh, slot_id) == (42, 0)
