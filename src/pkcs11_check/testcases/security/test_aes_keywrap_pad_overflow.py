"""Crash probe for ``CKM_AES_KEY_WRAP_PAD`` ``C_Encrypt`` with an oversized
``ulDataLen`` value.

``CKM_AES_KEY_WRAP_PAD`` ``C_Encrypt`` must reject an oversized ``ulDataLen``
(one that does not fit in 32 bits) before any allocation or copy.  A module
missing the length guard may wrap the allocation size and overflow it when
copying the caller's ``pData``.

Test shape (same shape as the GCM length-guard probe): we pass a small real
``pData`` buffer with an oversized ``ulDataLen = 0xFFFFFFFFFFFFFFFF``.
A conformant module rejects the length (``CKR_DATA_LEN_RANGE`` /
``CKR_ARGUMENTS_BAD`` / …) before any alloc/copy.  A buggy module wraps the
allocation and crashes or corrupts memory.

``CKR_OK`` is explicitly rejected: accepting a 2^64-byte wrap makes no sense.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]

# Oversized length = CK_ULONG max for the host ABI (2^64-1 on LP64, 2^32-1 on Win64
# LLP64): never allocated, just passed to C_Encrypt as ulDataLen while pData points at a
# small real buffer. Width-relative so it is representable in the child's CK_ULONG.
_OVERSIZED_DATALEN = ctypes.c_ulong(-1).value

# Expected spec-correct rejections for an oversized-length encrypt call.
# CKR_OK is intentionally absent: accepting a 2^64-byte wrap is always wrong.
_ENCRYPT_REJECT_RVS = (
    CKR_DATA_LEN_RANGE,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_GENERAL_ERROR,
    CKR_MECHANISM_INVALID,
)


def _preamble(p11_config: Any) -> str:
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=pin_from_config(p11_config),
        slot_label="pkcs11-check",
    )


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-300:]}")


class TestAesKeyWrapPadOversizedLength:
    """``CKM_AES_KEY_WRAP_PAD`` ``C_Encrypt`` with ``ulDataLen = 0xFFFFFFFFFFFFFFFF``.

    A missing 64-bit length guard in the KWP-PAD path causes a heap-buffer
    overflow when a huge ``ulDataLen`` wraps the allocation size.  A conformant
    module must reject the length before allocating or reading pData.
    """

    def test_aes_keywrap_pad_oversized_datalen_no_crash(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """``C_Encrypt(CKM_AES_KEY_WRAP_PAD, ulDataLen=2^64-1)`` must reject, not crash.

        Probe shape: generate an AES-256 wrapping key (CKA_ENCRYPT=TRUE,
        CKA_WRAP=TRUE), call ``C_EncryptInit(CKM_AES_KEY_WRAP_PAD)``, then
        call ``C_Encrypt`` with a small real pData (64 bytes) but
        ``ulDataLen = 0xFFFFFFFFFFFFFFFF``.  A conformant module validates the
        length before any allocation and returns a clean error.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_KEY_WRAP_PAD"):
            pytest.skip("CKM_AES_KEY_WRAP_PAD not advertised")

        script = (
            _preamble(p11_config)
            + f"""
import ctypes
from pkcs11_check.raw.recipes import gen_aes_key, destroy_quietly
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.testcases.security.conftest import child_setup_reject_known
from pkcs11_check.raw.types_std import (
    CKA_ENCRYPT,
    CKA_WRAP,
    CKA_TOKEN,
    CKM_AES_KEY_WRAP_PAD,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CK_MECHANISM,
    CK_ULONG,
)

_SETUP_REJECT_RVS = (
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
)

wrap_key = 0
try:
    try:
        wrap_key = gen_aes_key(raw, sh, 256, attrs={{
            CKA_ENCRYPT: True,
            CKA_WRAP: True,
            CKA_TOKEN: False,
        }})
    except AssertionError as _exc:
        if child_setup_reject_known(
            _exc, _SETUP_REJECT_RVS, "AES-256 wrap-key generation rejected"
        ):
            raise SystemExit(0)
        raise

    mech = CK_MECHANISM()
    mech.mechanism = CKM_AES_KEY_WRAP_PAD
    mech.pParameter = None
    mech.ulParameterLen = 0

    init_rv = raw.C_EncryptInit(sh, ctypes.byref(mech), wrap_key)
    if init_rv != CKR_OK:
        exc = CkrAssertionError(f"C_EncryptInit returned 0x{{init_rv:08x}}", init_rv)
        if child_setup_reject_known(
            exc, _SETUP_REJECT_RVS, "C_EncryptInit(CKM_AES_KEY_WRAP_PAD) rejected"
        ):
            raise SystemExit(0)
        raise exc   # unexpected EncryptInit failure must surface, not be silenced

    # Small real pData (64 bytes); ulDataLen is the oversized probe value.
    # A conformant module must reject the length before reading pData.
    pdata = (ctypes.c_ubyte * 64)(*range(64))
    out_buf = (ctypes.c_ubyte * 128)()
    out_len = CK_ULONG(128)
    encrypt_rv = raw.C_Encrypt(
        sh,
        pdata,
        {_OVERSIZED_DATALEN},
        out_buf,
        ctypes.byref(out_len),
    )
    print(f"ENCRYPT_RV:0x{{encrypt_rv:08x}}")
finally:
    if wrap_key:
        destroy_quietly(raw, sh, wrap_key)
cleanup()
"""
        )

        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context=(f"C_Encrypt(CKM_AES_KEY_WRAP_PAD, ulDataLen={_OVERSIZED_DATALEN:#x})"),
        )

        # assert_subprocess_no_crash already ended the test via xfail_as() if a
        # SETUP_XFAIL line was present.  Only reach here on a live probe.
        encrypt_rv = _parse_prefixed_int(stdout, "ENCRYPT_RV:")
        classify_negative_rv(
            encrypt_rv,
            _ENCRYPT_REJECT_RVS,
            label=(f"C_Encrypt(CKM_AES_KEY_WRAP_PAD, ulDataLen={_OVERSIZED_DATALEN:#x})"),
        )
