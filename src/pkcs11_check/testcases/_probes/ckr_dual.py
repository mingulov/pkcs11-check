"""Probe: operation-state CKR checks driven through a logged-in RawPKCS11 session.

Two cross-operation state-machine violations, ported verbatim from the legacy
``ckr/test_ckr_dual.py`` child scripts.

Dispatch on ``extra["probe"]``:
  ``"encrypt_without_init"`` -> ``C_Encrypt`` with no preceding ``C_EncryptInit`` must
      return ``CKR_OPERATION_NOT_INITIALIZED``; emits ``OK:encrypt_without_init``.
  ``"double_digest_init"``   -> two ``C_DigestInit`` calls: the first must be ``CKR_OK``,
      the second ``CKR_OPERATION_ACTIVE``; emits ``OK:double_digest_init_active``.

Runs through ``probe_main`` at ``Level.LOGIN``: the infra does C_Initialize + slot
discovery + ``C_OpenSession`` + (only when ``_P11CHECK_PIN`` is set) ``C_Login`` before
handing the probe ``ctx.raw`` / ``ctx.sh`` -- mirroring the legacy child, which opened a
session and logged in *only* when a PIN was configured.  The PIN travels ONLY via the
``_P11CHECK_PIN`` env var; it is never read, printed, or embedded here or in the probe
params.  This CLOSES the legacy leak that formatted the PIN literal into the generated
child-script source (Invariant I3).  Session teardown + rv-trace are handled by
``probe_main`` atexit, matching the legacy ``_p11check_cleanup_session`` / rv-trace setup.

Output protocol (byte-identical to the legacy child, for ``_assert_operation_subprocess_ok``):
  ``OK:encrypt_without_init``       -- encrypt-without-init probe reached its expected CKR
  ``OK:double_digest_init_active``  -- double-DigestInit probe reached OPERATION_ACTIVE

A wrong CK_RV makes ``expect_rv`` raise (non-zero exit) -> the parent reports a child
failure; a crash (returncode < 0) is a provider crash finding.

Required ``extra`` keys:
  ``"probe"`` -- ``"encrypt_without_init"`` or ``"double_digest_init"``

Launch with ``coverage="session"`` and ``pin=pin_from_config(p11_config)``.
"""

from __future__ import annotations

from ctypes import byref
from typing import Any

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import to_ubyte_buf
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKM_SHA256,
    CKR_OK,
    CKR_OPERATION_ACTIVE,
    CKR_OPERATION_NOT_INITIALIZED,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main


def _encrypt_without_init(ctx: ProbeContext) -> None:
    """C_Encrypt with no C_EncryptInit -> CKR_OPERATION_NOT_INITIALIZED."""
    data = to_ubyte_buf(b"\x00" * 16)
    out_len = CK_ULONG(0)
    rv = ctx.raw.C_Encrypt(ctx.sh, data, len(data), None, byref(out_len))
    expect_rv(rv, CKR_OPERATION_NOT_INITIALIZED)
    print("OK:encrypt_without_init")


def _double_digest_init(ctx: ProbeContext) -> None:
    """Two C_DigestInit calls: first CKR_OK, second CKR_OPERATION_ACTIVE."""
    mech = mech_simple(CKM_SHA256)
    rv = ctx.raw.C_DigestInit(ctx.sh, mech.byref())
    expect_rv(rv, CKR_OK)
    rv = ctx.raw.C_DigestInit(ctx.sh, mech.byref())
    expect_rv(rv, CKR_OPERATION_ACTIVE)
    print("OK:double_digest_init_active")


def _run(ctx: ProbeContext, extra: dict[str, Any]) -> None:
    probe = extra["probe"]
    if probe == "encrypt_without_init":
        _encrypt_without_init(ctx)
    elif probe == "double_digest_init":
        _double_digest_init(ctx)
    else:
        raise ValueError(f"unknown probe {probe!r}")


if __name__ == "__main__":
    probe_main(_run, level=Level.LOGIN)
