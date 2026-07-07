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
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
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

        result = run_probe(
            "aes_keywrap_pad",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
            },
            pin=pin_from_config(p11_config),
            timeout=15,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=(f"C_Encrypt(CKM_AES_KEY_WRAP_PAD, ulDataLen={_OVERSIZED_DATALEN:#x})"),
        )

        # assert_subprocess_no_crash already ended the test via xfail_as() if a
        # SETUP_XFAIL line was present.  Only reach here on a live probe.
        encrypt_rv = _parse_prefixed_int(result.stdout, "ENCRYPT_RV:")
        classify_negative_rv(
            encrypt_rv,
            _ENCRYPT_REJECT_RVS,
            label=(f"C_Encrypt(CKM_AES_KEY_WRAP_PAD, ulDataLen={_OVERSIZED_DATALEN:#x})"),
        )
