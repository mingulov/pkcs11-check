"""Probe: CKM_AES_KEY_WRAP_PAD C_Encrypt with an oversized ulDataLen.

Overflow probe for the AES_KEY_WRAP_PAD path: generate an AES-256 wrapping key,
call C_EncryptInit(CKM_AES_KEY_WRAP_PAD), then call C_Encrypt with a small real
pData buffer (64 bytes) but ulDataLen = CK_ULONG_MAX (all-bits-set on the host ABI).
A conformant module validates the length before any allocation and returns a clean
error code.  A module missing the 64-bit length guard may wrap an internal allocation
size and corrupt heap memory.

Output protocol (preserved verbatim for parent classifier):
  SETUP_XFAIL:<reason>  — setup rejected; parent xfails as not_operational
  ENCRYPT_RV:0x%08x     — return value from C_Encrypt
"""

from __future__ import annotations

import ctypes
from typing import Any

from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CK_MECHANISM,
    CK_ULONG,
    CKA_ENCRYPT,
    CKA_TOKEN,
    CKA_WRAP,
    CKM_AES_KEY_WRAP_PAD,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases._probes.session import Level, ProbeContext, probe_main
from pkcs11_check.testcases.security.conftest import child_setup_reject_known

# CK_ULONG-width max: 2^64-1 on LP64, 2^32-1 on Win64 LLP64.
# Width-relative so it is representable in the child's CK_ULONG.
_OVERSIZED_DATALEN = ctypes.c_ulong(-1).value

# Clean, advertised-but-not-operational rejections acceptable during setup.
_SETUP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)


def _main(ctx: ProbeContext, _extra: dict[str, Any]) -> None:
    """Perform the C_Encrypt oversized-length probe against CKM_AES_KEY_WRAP_PAD."""
    raw = ctx.raw
    assert ctx.sh is not None, "probe requires a session (Level.LOGIN)"
    sh: int = ctx.sh

    wrap_key = 0
    try:
        try:
            wrap_key = gen_aes_key(
                raw,
                sh,
                256,
                attrs={
                    CKA_ENCRYPT: True,
                    CKA_WRAP: True,
                    CKA_TOKEN: False,
                },
            )
        except AssertionError as _exc:
            if child_setup_reject_known(
                _exc, _SETUP_REJECT_RVS, "AES-256 wrap-key generation rejected"
            ):
                return
            raise

        mech = CK_MECHANISM()
        mech.mechanism = CKM_AES_KEY_WRAP_PAD
        mech.pParameter = None
        mech.ulParameterLen = 0

        init_rv = raw.C_EncryptInit(sh, ctypes.byref(mech), wrap_key)
        if init_rv != CKR_OK:
            exc = CkrAssertionError(f"C_EncryptInit returned 0x{init_rv:08x}", init_rv)
            if child_setup_reject_known(
                exc, _SETUP_REJECT_RVS, "C_EncryptInit(CKM_AES_KEY_WRAP_PAD) rejected"
            ):
                return
            raise exc  # unexpected EncryptInit failure must surface, not be silenced

        # Small real pData (64 bytes); ulDataLen is the oversized probe value.
        # A conformant module must reject the length before reading pData.
        pdata = (ctypes.c_ubyte * 64)(*range(64))
        out_buf = (ctypes.c_ubyte * 128)()
        out_len = CK_ULONG(128)
        encrypt_rv = raw.C_Encrypt(
            sh,
            pdata,
            _OVERSIZED_DATALEN,
            out_buf,
            ctypes.byref(out_len),
        )
        print(f"ENCRYPT_RV:0x{encrypt_rv:08x}")
    finally:
        if wrap_key:
            destroy_quietly(raw, sh, wrap_key)


if __name__ == "__main__":
    probe_main(_main, level=Level.LOGIN)
