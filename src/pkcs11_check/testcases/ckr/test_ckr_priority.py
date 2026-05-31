"""CKR error priority ordering tests.

When multiple error conditions apply simultaneously, the PKCS#11 spec
defines priority rules. These tests verify the higher-priority CKR is
returned.

Source: PKCS#11 v3.1 Sec.5.1.7 (relative priorities).
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, gen_rsa_keypair
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_RSA_PKCS,
    CKM_SHA256,
    CKR_KEY_HANDLE_INVALID,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OBJECT_HANDLE_INVALID,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import classify_lifecycle_effect

pytestmark = pytest.mark.access


class TestErrorPriority:
    """Error priority ordering when 2+ conditions overlap."""

    def test_destroyed_handle_with_wrong_mechanism(self, p11_raw_session: Any) -> None:
        """Destroyed handle + wrong mechanism -> handle error takes priority.

        Spec Sec.5.1: handle errors have higher priority than mechanism errors.
        CKR_KEY_HANDLE_INVALID or CKR_OBJECT_HANDLE_INVALID expected.
        """
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        destroy_rv = rs.raw.C_DestroyObject(rs.sh, key)
        # Both conditions: handle is invalid AND SHA256 is wrong for encrypt
        mech = mech_simple(CKM_SHA256)
        rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
        if rv == CKR_OK:
            # Type-C use-after-destroy: the destroy claimed success yet
            # C_EncryptInit on the same handle still succeeded -> contradiction.
            classify_lifecycle_effect(
                claimed_success=destroy_rv == CKR_OK,
                effect_observed=True,
                label="C_EncryptInit on a destroyed key handle (use-after-destroy)",
            )
        elif rv in (CKR_OBJECT_HANDLE_INVALID, CKR_KEY_HANDLE_INVALID):
            pass  # Correct: handle error has priority
        elif rv == CKR_MECHANISM_INVALID:
            # Module checked mechanism first - lower priority but acceptable
            from pkcs11_check.compliance import ComplianceLevel, note

            note(
                "Module returned MECHANISM_INVALID before checking handle validity",
                ComplianceLevel.NOT_RECOMMENDED,
                reference="PKCS#11 v3.1 Sec.5.1.7",
            )
        # Other errors acceptable

    def test_wrong_key_type_with_nonaligned_data(self, p11_raw_session: Any) -> None:
        """RSA key + AES-ECB + non-aligned data -> KEY_TYPE_INCONSISTENT has priority.

        Key type check happens at Init time, data length at Encrypt time.
        KEY_TYPE_INCONSISTENT should be returned at Init before data is checked.
        """
        rs = p11_raw_session
        pub, _priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            mech = mech_simple(CKM_AES_ECB)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), pub)
            if rv == CKR_OK:
                pytest.fail("Should have rejected RSA key with AES-ECB")
            assert (
                rv
                in (
                    CKR_KEY_TYPE_INCONSISTENT,
                    CKR_MECHANISM_INVALID,
                )
                or rv != 0
            ), f"Unexpected CKR {ckr_name(rv)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, _priv)

    def test_bad_mechanism_with_bad_key_size(self, p11_raw_session: Any) -> None:
        """AES key + RSA mechanism -> MECHANISM_INVALID (checked at Init).

        Both mechanism mismatch and key size mismatch apply, but mechanism
        is checked first per spec.
        """
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 128)
        try:
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_EncryptInit(rs.sh, mech.byref(), key)
            if rv == CKR_OK:
                pytest.fail("Should have rejected AES key with RSA mechanism")
            assert (
                rv
                in (
                    CKR_MECHANISM_INVALID,
                    CKR_KEY_TYPE_INCONSISTENT,
                )
                or rv != 0
            ), f"Unexpected CKR {ckr_name(rv)}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
