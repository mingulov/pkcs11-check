"""mmap-backed probe for C_GenerateRandom / C_SeedRandom 64-bit length truncation.

``C_GenerateRandom`` and ``C_SeedRandom`` must honour the full 64-bit
``ulRandomLen`` / ``ulSeedLen`` value.  A module that casts the length to a
32-bit integer silently truncates it: ``C_GenerateRandom(ptr, 0x100000008)``
writes only 8 bytes but returns ``CKR_OK``, leaving the rest of the output
buffer unfilled -- a cryptographic-contract violation.

Safety: the probe uses a ``MAP_PRIVATE | MAP_ANONYMOUS`` demand-zero mapping for
the 4 GiB+ buffer.  A truncating module touches at most the first 8 bytes (one
partial page); a rejecting module returns an error before touching anything.
Only a fully-honoring module would fault all pages.  No out-of-bounds write
occurs in any case.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.compliance import ComplianceLevel, note
from pkcs11_check.raw.types_std import (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_RANDOM_NO_RNG,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
)
from pkcs11_check.testcases._probes.runner import run_probe
from pkcs11_check.testcases._subprocess_preamble import pin_from_config
from pkcs11_check.testcases.conftest import classify_negative_rv
from pkcs11_check.testcases.security._boundary_values import requires_64bit_ck_ulong
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [
    pytest.mark.security,
    pytest.mark.subprocess,
    pytest.mark.slow,
    requires_64bit_ck_ulong,
]

# 0x100000008: low 32 bits == 8, so a (int)/(word32) truncation writes only 8 bytes.
_OVERSIZE_LEN = (1 << 32) + 8

# CKRs that constitute a conformant rejection of an oversized random length.
_GENRAND_REJECT_RVSS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_RANDOM_NO_RNG,
)

# CKRs that constitute a conformant rejection for C_SeedRandom.
_SEEDRAND_REJECT_RVSS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_RANDOM_NO_RNG,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
)


def _parse_prefixed_int(output: str, prefix: str) -> int:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    raise AssertionError(f"Missing {prefix!r} line in subprocess output: {output[-400:]}")


def _parse_prefixed_int_optional(output: str, prefix: str) -> int | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return int(line.removeprefix(prefix), 0)
    return None


class TestGenerateRandomLengthTruncation:
    """C_GenerateRandom must not silently truncate a 64-bit output length.

    Probe: request ``0x100000008`` (4 GiB + 8) bytes of random data into a
    demand-zero mmap region.  A truncating module casts the length to a 32-bit
    integer, obtains 8, writes 8 bytes, and returns CKR_OK -- leaving all bytes
    past offset 8 as zero.  This is a cryptographic-contract violation.
    """

    def test_generate_random_oversized_length_rejects_or_honors(
        self,
        p11_config: Any,
    ) -> None:
        """C_GenerateRandom must reject or fully honor a 4 GiB+ output length.

        A 32-bit cast of ``ulRandomLen`` silently truncates to its low 32 bits,
        writing far fewer bytes than requested while returning ``CKR_OK``.
        """
        result = run_probe(
            "random_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "generate",
                "length": _OVERSIZE_LEN,
            },
            pin=pin_from_config(p11_config),
            # Timeout: a truncating module measures ~0s; a correctly honoring module could
            # take significant time filling 4 GiB.  180 s is generous for an honoring
            # module while keeping slow CI bounded.
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_GenerateRandom(ptr, len=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(result.stdout, "GENRAND_RV:")
        underfill = _parse_prefixed_int_optional(result.stdout, "UNDERFILL:")

        assert rv != 0 or underfill is not None, (
            f"GENRAND_RV=CKR_OK but UNDERFILL line missing: {result.stdout[-300:]}"
        )

        if rv != 0:
            # Module rejected the oversized length -- classify (pass or xfail).
            classify_negative_rv(
                rv,
                _GENRAND_REJECT_RVSS,
                label="C_GenerateRandom rejects oversized 64-bit length",
            )
        elif underfill == 1:
            # CKR_OK but only ~8 bytes written: silent truncation.
            classify_negative_rv(
                rv,
                _GENRAND_REJECT_RVSS,
                label=(
                    "C_GenerateRandom 64-bit length truncated (silent under-fill): "
                    "returned CKR_OK but wrote only truncated-low-32 bytes"
                ),
            )
        else:
            # CKR_OK and buffer filled: module honored the full 4 GiB request.
            note(
                "C_GenerateRandom honored a 4 GiB+ output length (0x100000008 bytes): "
                "conformant -- no truncation observed",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 §5.8 C_GenerateRandom",
                test_id=(
                    "TestGenerateRandomLengthTruncation"
                    ".test_generate_random_oversized_length_rejects_or_honors"
                ),
            )


class TestSeedRandomLengthTruncation:
    """C_SeedRandom must not silently truncate a 64-bit seed length.

    For C_SeedRandom there is no observable output -- we can only check the
    return code.  A reject is a clean conformant response; CKR_OK is ambiguous
    (cannot distinguish truncation from honor by return code alone).
    """

    def test_seed_random_oversized_length_return_code(
        self,
        p11_config: Any,
    ) -> None:
        """C_SeedRandom with a 4 GiB+ seed length must reject or return CKR_OK cleanly.

        Seed-path length truncation cannot be distinguished from a full honor by
        return code alone; detection is limited to checking for a clean reject.
        """
        result = run_probe(
            "random_length",
            {
                "module_path": str(p11_config.module),
                "slot_id": p11_config.slot,
                "which": "seed",
                "length": _OVERSIZE_LEN,
            },
            pin=pin_from_config(p11_config),
            timeout=180,
            coverage="session",
        )
        assert_subprocess_no_crash(
            result.returncode,
            result.stdout,
            result.stderr,
            context=f"C_SeedRandom(ptr, len=0x{_OVERSIZE_LEN:x})",
        )

        rv = _parse_prefixed_int(result.stdout, "SEEDRAND_RV:")

        if rv != 0:
            # Module rejected the oversized seed length -- classify (pass or xfail).
            classify_negative_rv(
                rv,
                _SEEDRAND_REJECT_RVSS,
                label="C_SeedRandom rejects oversized 64-bit length",
            )
        else:
            # CKR_OK: cannot distinguish truncation from honor by return code alone.
            # Record as a compliance note only -- not a fail.
            note(
                "C_SeedRandom returned CKR_OK for a 4 GiB+ seed (0x100000008 bytes): "
                "cannot determine truncation vs. honor by return code alone",
                ComplianceLevel.EXTENDED,
                reference="PKCS#11 3.1 §5.8 C_SeedRandom",
                test_id=(
                    "TestSeedRandomLengthTruncation.test_seed_random_oversized_length_return_code"
                ),
            )
