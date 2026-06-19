"""CKR compliance tests for C_SeedRandom and C_GenerateRandom.

Source: PKCS#11 v3.2-5.18.2.
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import classify, fail_as
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CK_ULONG,
    CKR_ARGUMENTS_BAD,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_OK,
    CKR_RANDOM_SEED_NOT_SUPPORTED,
)
from pkcs11_check.testcases.conftest import classify_negative_rv

pytestmark = pytest.mark.access


class TestSeedRandomErrors:
    """Error conditions for C_SeedRandom (Sec.5.18.1)."""

    def test_seed_random(self, p11_raw_session: Any) -> None:
        """C_SeedRandom - should accept or return RANDOM_SEED_NOT_SUPPORTED."""
        rs = p11_raw_session
        seed = (ctypes.c_ubyte * 32)(*([0x42] * 32))
        rv = rs.raw.C_SeedRandom(rs.sh, seed, 32)
        if rv != CKR_OK:
            classify_negative_rv(
                rv,
                (CKR_RANDOM_SEED_NOT_SUPPORTED, CKR_FUNCTION_NOT_SUPPORTED),
                label="C_SeedRandom",
            )


class TestGenerateRandomErrors:
    """Error conditions for C_GenerateRandom (Sec.5.18.2)."""

    def test_generate_random_zero(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom(0) - should return empty or error."""
        rs = p11_raw_session
        buf = (ctypes.c_ubyte * 1)()  # minimal buffer
        rv = rs.raw.C_GenerateRandom(rs.sh, buf, CK_ULONG(0))
        # Zero-length is a genuinely ambiguous edge case: spec-correct to accept
        # (CKR_OK) or to reject with CKR_ARGUMENTS_BAD. Anything else is a deviation.
        classify_negative_rv(
            rv,
            (CKR_ARGUMENTS_BAD,),
            label="C_GenerateRandom with zero length",
            allow_ok=True,
        )

    @pytest.mark.slow
    def test_generate_random_large(self, p11_raw_session: Any) -> None:
        """C_GenerateRandom(1MB) - large request."""
        rs = p11_raw_session
        size = 1024 * 1024
        buf = (ctypes.c_ubyte * size)()
        rv = rs.raw.C_GenerateRandom(rs.sh, buf, CK_ULONG(size))
        if rv == CKR_OK:
            if len(bytes(buf)) != size:
                fail_as(
                    "wrong_result",
                    kind="crypto",
                    label="C_GenerateRandom large request output length",
                    actual=len(bytes(buf)),
                    expected=size,
                    summary="C_GenerateRandom returned CKR_OK but short buffer",
                )
        else:
            classify(
                "not_operational",
                label="C_GenerateRandom large (1MB) request",
                actual=rv,
                summary=f"large random request rejected with {ckr_name(rv)}",
            )
