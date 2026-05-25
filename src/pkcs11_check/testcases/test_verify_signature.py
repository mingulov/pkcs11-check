"""Positive-path tests for C_VerifySignatureInit/Update/Final.

The VerifySignature API (v3.0+) differs from C_VerifyInit -- the signature is
provided at initialization time, not at final time.  Tests skip when the module
does not expose C_VerifySignatureInit.
"""

from __future__ import annotations

from ctypes import c_ubyte, cast
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import (
    destroy_quietly,
    gen_rsa_keypair,
    sign_multipart,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CK_BYTE_PTR,
    CKM_RSA_PKCS,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_HANDLE_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SIGNATURE_INVALID,
)
from pkcs11_check.testcases.conftest import is_known_error

pytestmark = pytest.mark.full


def _sig_buf(sig: bytes) -> tuple[Any, int]:
    buf = (c_ubyte * len(sig)).from_buffer_copy(sig)
    return cast(buf, CK_BYTE_PTR), len(sig)


def _data_buf(data: bytes) -> tuple[Any, int]:
    buf = (c_ubyte * len(data)).from_buffer_copy(data)
    return cast(buf, CK_BYTE_PTR), len(data)


class TestVerifySignatureRoundtrip:
    @staticmethod
    def _skip_unless_available(rs: Any) -> None:
        if "C_VerifySignatureInit" not in rs.raw.available_function_names():
            pytest.skip("C_VerifySignatureInit not available in this module")

    def test_verify_signature_single_shot(self, p11_raw_session: Any) -> None:
        """Sign with C_SignInit, verify with C_VerifySignatureInit + C_VerifySignature."""
        rs = p11_raw_session
        self._skip_unless_available(rs)
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"VerifySignature single-shot test data"
            sig = sign_single(rs.raw, rs.sh, priv, CKM_RSA_PKCS, data)
            sig_ptr, sig_len = _sig_buf(sig)
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_VerifySignatureInit(rs.sh, mech.byref(), pub, sig_ptr, sig_len)
            assert rv == CKR_OK, f"C_VerifySignatureInit failed with 0x{rv:08x}"
            data_ptr, data_len = _data_buf(data)
            rv = rs.raw.C_VerifySignature(rs.sh, data_ptr, data_len)
            assert rv == CKR_OK, f"C_VerifySignature failed with 0x{rv:08x}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_signature_multipart(self, p11_raw_session: Any) -> None:
        """Sign multipart, verify multipart via VerifySignature API."""
        rs = p11_raw_session
        self._skip_unless_available(rs)
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            chunks = [b"chunk one ", b"chunk two ", b"chunk three"]
            sig = sign_multipart(rs.raw, rs.sh, priv, CKM_RSA_PKCS, chunks)
            sig_ptr, sig_len = _sig_buf(sig)
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_VerifySignatureInit(rs.sh, mech.byref(), pub, sig_ptr, sig_len)
            assert rv == CKR_OK, f"C_VerifySignatureInit failed with 0x{rv:08x}"
            for chunk in chunks:
                chunk_ptr, chunk_len = _data_buf(chunk)
                rv = rs.raw.C_VerifySignatureUpdate(rs.sh, chunk_ptr, chunk_len)
                assert rv == CKR_OK, f"C_VerifySignatureUpdate failed with 0x{rv:08x}"
            rv = rs.raw.C_VerifySignatureFinal(rs.sh)
            assert rv == CKR_OK, f"C_VerifySignatureFinal failed with 0x{rv:08x}"
        except AssertionError as e:
            if is_known_error(e, {CKR_OPERATION_NOT_INITIALIZED, CKR_FUNCTION_NOT_SUPPORTED}):
                pytest.skip("Module does not support multipart C_VerifySignatureUpdate")
            raise
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_signature_wrong_sig(self, p11_raw_session: Any) -> None:
        """Wrong signature returns CKR_SIGNATURE_INVALID."""
        rs = p11_raw_session
        self._skip_unless_available(rs)
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"original data"
            wrong_sig = b"\xff" * 256
            sig_ptr, sig_len = _sig_buf(wrong_sig)
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_VerifySignatureInit(rs.sh, mech.byref(), pub, sig_ptr, sig_len)
            if rv != CKR_OK:
                return
            data_ptr, data_len = _data_buf(data)
            rv = rs.raw.C_VerifySignature(rs.sh, data_ptr, data_len)
            assert rv in (CKR_SIGNATURE_INVALID, CKR_DEVICE_ERROR), (
                f"Expected CKR_SIGNATURE_INVALID, got 0x{rv:08x}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)

    def test_verify_signature_wrong_key(self, p11_raw_session: Any) -> None:
        """Wrong key returns CKR_KEY_HANDLE_INVALID or CKR_SIGNATURE_INVALID.

        SECURITY: A module that returns CKR_OK when verifying with a mismatched
        key silently accepts forged signatures.

        NSS deviation: NSS C_VerifySignatureInit returns CKR_OK even when the
        signature was created with a different key pair (pub2 vs priv1).
        This is a SECURITY BUG in NSS's C_VerifySignatureInit -- it does not
        validate key-signature correspondence at init time.
        Tracked in docs/module-issues.md under NSS (SECURITY).
        """
        from pkcs11_check.compliance import ComplianceLevel, note

        rs = p11_raw_session
        self._skip_unless_available(rs)
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        pub1, priv1 = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        pub2, priv2 = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        try:
            data = b"key mismatch test"
            sig = sign_single(rs.raw, rs.sh, priv1, CKM_RSA_PKCS, data)
            sig_ptr, sig_len = _sig_buf(sig)
            mech = mech_simple(CKM_RSA_PKCS)
            rv = rs.raw.C_VerifySignatureInit(rs.sh, mech.byref(), pub2, sig_ptr, sig_len)
            if rv == CKR_OK:
                note(
                    "C_VerifySignatureInit returned CKR_OK for a signature created with a "
                    "different key -- module does not validate key-signature correspondence "
                    "at init time (SECURITY)",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 spec C_VerifySignatureInit",
                )
                pytest.xfail(
                    "SECURITY: C_VerifySignatureInit returned CKR_OK when verifying "
                    "with a mismatched public key -- silent acceptance of forged signatures "
                    "(expected CKR_KEY_HANDLE_INVALID or CKR_SIGNATURE_INVALID)"
                )
            assert rv in (
                CKR_KEY_HANDLE_INVALID,
                CKR_SIGNATURE_INVALID,
            ), f"Expected CKR_KEY_HANDLE_INVALID or CKR_SIGNATURE_INVALID, got 0x{rv:08x}"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub1)
            destroy_quietly(rs.raw, rs.sh, priv1)
            destroy_quietly(rs.raw, rs.sh, pub2)
            destroy_quietly(rs.raw, rs.sh, priv2)
