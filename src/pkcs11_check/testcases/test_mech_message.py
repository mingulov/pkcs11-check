"""Mechanism-driven message-based operation tests (v3.0+).

The message-based API (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal
and the decrypt equivalents) was introduced in PKCS#11 v3.0.  It allows a single
session initialisation to be reused for many independent messages with per-message
parameters (e.g. different GCM IVs) without a round-trip C_*Init call per message.

Reference: PKCS#11 v3.1 Sec.5.4 (Message-based encryption functions).
"""

from __future__ import annotations

import ctypes
import os
from ctypes import byref

import pytest

from pkcs11_check.fixtures import RawSession

pytestmark = [
    pytest.mark.mechanism_coverage,
    pytest.mark.message_based,
    pytest.mark.requires_v30,
]


def _to_ubyte_buf(data: bytes) -> ctypes.Array[ctypes.c_ubyte]:
    return (ctypes.c_ubyte * len(data))(*data)


class TestMessageEncrypt:
    """v3.0 C_MessageEncrypt* API tests."""

    def test_message_encrypt_decrypt_aes_gcm(self, p11_raw_session: RawSession) -> None:
        """Single-message AES-GCM encrypt/decrypt roundtrip via message-based API.

        Verifies the full CK_GCM_MESSAGE_PARAMS packing path through
        C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal and
        the matching decrypt side.

        Reference: PKCS#11 v3.1 Sec.5.4 (Message-based encryption functions).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.pack_mechanisms import mech_gcm_message
        from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, get_mechanism_info
        from pkcs11_check.raw.types_std import (
            CK_ULONG,
            CKA_DECRYPT,
            CKA_ENCRYPT,
            CKA_TOKEN,
            CKF_MESSAGE_DECRYPT,
            CKF_MESSAGE_ENCRYPT,
            CKM_AES_GCM,
            CKR_MECHANISM_INVALID,
            CKR_OK,
        )

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        for fname in ("C_MessageEncryptInit", "C_EncryptMessage", "C_MessageEncryptFinal"):
            if not hasattr(rs.raw, fname):
                pytest.skip(f"{fname} not available on this module")

        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            # --- Encrypt side ---
            init_iv = os.urandom(12)
            init_mech = mech_gcm_message(CKM_AES_GCM, init_iv, tag_bits=128)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, init_mech.byref(), key)
            if rv == CKR_MECHANISM_INVALID:
                pytest.skip("C_MessageEncryptInit: CKR_MECHANISM_INVALID for CKM_AES_GCM")
            assert rv == CKR_OK, f"C_MessageEncryptInit failed: 0x{rv:08x}"

            # Build per-message CK_GCM_MESSAGE_PARAMS for C_EncryptMessage.
            # A fresh IV is required for each message; pTag receives the auth tag.
            from pkcs11_check.raw.types_std import CK_GCM_MESSAGE_PARAMS

            msg_iv = os.urandom(12)
            iv_buf = (ctypes.c_ubyte * 12)(*msg_iv)
            tag_buf = (ctypes.c_ubyte * 16)()
            msg_params = CK_GCM_MESSAGE_PARAMS()
            msg_params.pIv = ctypes.cast(iv_buf, ctypes.c_void_p)
            msg_params.ulIvLen = 12
            msg_params.ulIvFixedBits = 0
            msg_params.ivGenerator = 0
            msg_params.pTag = ctypes.cast(tag_buf, ctypes.c_void_p)
            msg_params.ulTagBits = 128

            plaintext = b"Hello message-based AEAD!"
            aad = b"additional-data"
            pt_buf = _to_ubyte_buf(plaintext)
            aad_buf = _to_ubyte_buf(aad)

            # Size query
            ct_len = CK_ULONG(0)
            rv = rs.raw.C_EncryptMessage(
                rs.sh,
                byref(msg_params),
                ctypes.sizeof(msg_params),
                aad_buf,
                len(aad),
                pt_buf,
                len(plaintext),
                None,
                byref(ct_len),
            )
            assert rv == CKR_OK, f"C_EncryptMessage (size query) failed: 0x{rv:08x}"

            ct_buf = (ctypes.c_ubyte * ct_len.value)()
            # Reset pTag pointer — may have been updated during size query
            msg_params.pTag = ctypes.cast(tag_buf, ctypes.c_void_p)
            rv = rs.raw.C_EncryptMessage(
                rs.sh,
                byref(msg_params),
                ctypes.sizeof(msg_params),
                aad_buf,
                len(aad),
                pt_buf,
                len(plaintext),
                ct_buf,
                byref(ct_len),
            )
            assert rv == CKR_OK, f"C_EncryptMessage failed: 0x{rv:08x}"
            ciphertext = bytes(ct_buf[: ct_len.value])
            auth_tag = bytes(tag_buf)

            rv = rs.raw.C_MessageEncryptFinal(rs.sh)
            assert rv == CKR_OK, f"C_MessageEncryptFinal failed: 0x{rv:08x}"

            assert len(ciphertext) > 0
            assert ciphertext != plaintext

            # --- Decrypt side ---
            if not (info["flags"] & int(CKF_MESSAGE_DECRYPT)):
                # Encrypt validated; decrypt flag not advertised — acceptable.
                return

            for fname in ("C_MessageDecryptInit", "C_DecryptMessage", "C_MessageDecryptFinal"):
                if not hasattr(rs.raw, fname):
                    pytest.skip(f"{fname} not available on this module")

            dec_init_iv = os.urandom(12)
            dec_init_mech = mech_gcm_message(CKM_AES_GCM, dec_init_iv, tag_bits=128)
            rv = rs.raw.C_MessageDecryptInit(rs.sh, dec_init_mech.byref(), key)
            assert rv == CKR_OK, f"C_MessageDecryptInit failed: 0x{rv:08x}"

            # Reconstruct the ciphertext+tag blob that the token expects.
            # GCM ciphertext from C_EncryptMessage may or may not include the tag;
            # we pass the tag separately via pTag in the per-message params.
            dec_iv_buf = (ctypes.c_ubyte * 12)(*msg_iv)
            dec_tag_buf = (ctypes.c_ubyte * 16)(*auth_tag)
            dec_params = CK_GCM_MESSAGE_PARAMS()
            dec_params.pIv = ctypes.cast(dec_iv_buf, ctypes.c_void_p)
            dec_params.ulIvLen = 12
            dec_params.ulIvFixedBits = 0
            dec_params.ivGenerator = 0
            dec_params.pTag = ctypes.cast(dec_tag_buf, ctypes.c_void_p)
            dec_params.ulTagBits = 128

            ct_in_buf = _to_ubyte_buf(ciphertext)

            # Size query
            pt_out_len = CK_ULONG(0)
            rv = rs.raw.C_DecryptMessage(
                rs.sh,
                byref(dec_params),
                ctypes.sizeof(dec_params),
                aad_buf,
                len(aad),
                ct_in_buf,
                len(ciphertext),
                None,
                byref(pt_out_len),
            )
            assert rv == CKR_OK, f"C_DecryptMessage (size query) failed: 0x{rv:08x}"

            pt_out_buf = (ctypes.c_ubyte * pt_out_len.value)()
            dec_params.pTag = ctypes.cast(dec_tag_buf, ctypes.c_void_p)
            rv = rs.raw.C_DecryptMessage(
                rs.sh,
                byref(dec_params),
                ctypes.sizeof(dec_params),
                aad_buf,
                len(aad),
                ct_in_buf,
                len(ciphertext),
                pt_out_buf,
                byref(pt_out_len),
            )
            assert rv == CKR_OK, f"C_DecryptMessage failed: 0x{rv:08x}"

            rv = rs.raw.C_MessageDecryptFinal(rs.sh)
            assert rv == CKR_OK, f"C_MessageDecryptFinal failed: 0x{rv:08x}"

            assert bytes(pt_out_buf[: pt_out_len.value]) == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_sign_aes_gmac(self, p11_raw_session: RawSession) -> None:
        """Message-based sign flag check for CKM_AES_GMAC.

        Verifies that when CKF_MESSAGE_SIGN is advertised, the corresponding
        C_MessageSignInit function exists on the module.  Full invocation is
        deferred pending CK_GCM_MESSAGE_PARAMS support.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GMAC"):
            pytest.skip("CKM_AES_GMAC not supported")

        from pkcs11_check.raw.recipes import get_mechanism_info
        from pkcs11_check.raw.types_std import CKF_MESSAGE_SIGN, CKM_AES_GMAC

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GMAC)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_AES_GMAC does not advertise CKF_MESSAGE_SIGN")

        assert hasattr(rs.raw, "C_MessageSignInit"), (
            "Module advertises CKF_MESSAGE_SIGN for AES_GMAC but C_MessageSignInit is absent"
        )
