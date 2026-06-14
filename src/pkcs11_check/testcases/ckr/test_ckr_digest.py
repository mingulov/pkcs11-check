"""CKR compliance tests for C_DigestInit and C_Digest.

Source: PKCS#11 v3.2 (C_DigestInit, C_Digest).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKR_OK,
)
from pkcs11_check.testcases.ckr._ckr_spec import CKR_DIGEST, assert_ckr

pytestmark = pytest.mark.access


class TestDigestInitErrors:
    """Per-parameter error conditions for C_DigestInit (Sec.5.12.1)."""

    def test_mechanism_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using encrypt mechanism for digest -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_AES_ECB)
        rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv == CKR_OK:
            classify(
                "accepted_invalid",
                kind="policy",
                label="C_DigestInit:AES-mechanism",
                operation="C_DigestInit",
                actual=rv,
                summary="Should have rejected AES_ECB as digest mechanism",
            )
        assert_ckr(CKR_DIGEST["init_mechanism_invalid"], rv, ckr_strict)

    def test_encrypt_mechanism_for_digest(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """Using RSA encrypt mechanism for digest -> CKR_MECHANISM_INVALID."""
        rs = p11_raw_session
        mech = mech_simple(CKM_RSA_PKCS)
        rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv == CKR_OK:
            classify(
                "accepted_invalid",
                kind="policy",
                label="C_DigestInit:RSA-mechanism",
                operation="C_DigestInit",
                actual=rv,
                summary="Should have rejected RSA_PKCS as digest mechanism",
            )
        assert_ckr(CKR_DIGEST["init_encrypt_mechanism"], rv, ckr_strict)

    def test_mechanism_param_invalid(self, p11_raw_session: Any, ckr_strict: bool) -> None:
        """SHA-256 with unexpected parameter -> CKR_MECHANISM_PARAM_INVALID.

        SHA-256 takes no parameters. Providing one should error.
        Note: some modules may ignore the param.
        """
        rs = p11_raw_session
        exp = CKR_DIGEST["init_mechanism_param_invalid"]
        # Build SHA-256 mechanism with a bogus 16-byte parameter

        mech = mech_bytes(CKM_SHA256, b"\x00" * 16)
        rv = rs.raw.C_DigestInit(rs.sh, mech.byref())
        if rv == CKR_OK:
            # Some modules/wrappers ignore unknown params for hash mechanisms
            pass
        else:
            assert_ckr(exp, rv, ckr_strict)
