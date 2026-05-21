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
from pkcs11_check.raw.recipes import to_ubyte_buf

pytestmark = [
    pytest.mark.mechanism_coverage,
    pytest.mark.message_based,
    pytest.mark.requires_v30,
]


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
            pt_buf = to_ubyte_buf(plaintext)
            aad_buf = to_ubyte_buf(aad)

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
            # Reset pTag pointer -- may have been updated during size query
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
                # Encrypt validated; decrypt flag not advertised -- acceptable.
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

            ct_in_buf = to_ubyte_buf(ciphertext)

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

    def test_message_encrypt_aes_gcm_generated_iv_writeback(
        self, p11_raw_session: RawSession
    ) -> None:
        """C_EncryptMessage with CKG_GENERATE writes the generated IV to pIv.

        This is the standard PKCS#11 v3.x version of provider-generated AEAD
        IV handling. Unlike legacy CKM_AES_GCM parameter mutation, ivGenerator
        support is part of CK_GCM_MESSAGE_PARAMS.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from pkcs11_check.compliance import ComplianceLevel, note
        from pkcs11_check.raw.pack_mechanisms import (
            mech_gcm_message,
            mech_gcm_message_generated_iv,
        )
        from pkcs11_check.raw.recipes import destroy_quietly, get_mechanism_info, import_secret_key
        from pkcs11_check.raw.types_std import (
            CK_ULONG,
            CKA_DECRYPT,
            CKA_ENCRYPT,
            CKA_TOKEN,
            CKF_MESSAGE_ENCRYPT,
            CKG_GENERATE,
            CKK_AES,
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

        note(
            "CK_GCM_MESSAGE_PARAMS ivGenerator writes the generated IV back to pIv",
            ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.x CK_GCM_MESSAGE_PARAMS ivGenerator",
        )

        key_bytes = bytes(range(32))
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            init_mech = mech_gcm_message(CKM_AES_GCM, b"\x00" * 12, tag_bits=128)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, init_mech.byref(), key)
            if rv == CKR_MECHANISM_INVALID:
                pytest.skip("C_MessageEncryptInit: CKR_MECHANISM_INVALID for CKM_AES_GCM")
            assert rv == CKR_OK, f"C_MessageEncryptInit failed: 0x{rv:08x}"

            msg_mech = mech_gcm_message_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                iv_generator=int(CKG_GENERATE),
                tag_bits=128,
            )
            msg_params = msg_mech.params

            plaintext = b"generated IV through message API"
            aad = b"message-generated-iv-aad"
            pt_buf = to_ubyte_buf(plaintext)
            aad_buf = to_ubyte_buf(aad)
            ct_len = CK_ULONG(len(plaintext) + 16)
            ct_buf = (ctypes.c_ubyte * ct_len.value)()

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

            rv = rs.raw.C_MessageEncryptFinal(rs.sh)
            assert rv == CKR_OK, f"C_MessageEncryptFinal failed: 0x{rv:08x}"

            iv = msg_mech.buffer_bytes("iv")
            tag = msg_mech.buffer_bytes("tag")
            ciphertext = bytes(ct_buf[: ct_len.value])
            assert any(iv), "C_EncryptMessage did not write generated IV to pIv"
            assert any(tag), "C_EncryptMessage did not write GCM tag to pTag"
            assert AESGCM(key_bytes).decrypt(iv, ciphertext + tag, aad) == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_aes_ccm_generated_nonce_writeback(
        self, p11_raw_session: RawSession
    ) -> None:
        """C_EncryptMessage with CKG_GENERATE writes AES-CCM nonce and MAC outputs."""
        rs = p11_raw_session
        if not rs.has_mechanism("AES_CCM"):
            pytest.skip("CKM_AES_CCM not supported")

        from cryptography.hazmat.primitives.ciphers.aead import AESCCM

        from pkcs11_check.compliance import ComplianceLevel, note
        from pkcs11_check.raw.pack_mechanisms import mech_ccm, mech_ccm_message_generated_nonce
        from pkcs11_check.raw.recipes import destroy_quietly, get_mechanism_info, import_secret_key
        from pkcs11_check.raw.types_std import (
            CK_ULONG,
            CKA_DECRYPT,
            CKA_ENCRYPT,
            CKA_TOKEN,
            CKF_MESSAGE_ENCRYPT,
            CKG_GENERATE,
            CKK_AES,
            CKM_AES_CCM,
            CKR_MECHANISM_INVALID,
            CKR_OK,
        )

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_CCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_CCM does not advertise CKF_MESSAGE_ENCRYPT")

        for fname in ("C_MessageEncryptInit", "C_EncryptMessage", "C_MessageEncryptFinal"):
            if not hasattr(rs.raw, fname):
                pytest.skip(f"{fname} not available on this module")

        note(
            "CK_CCM_MESSAGE_PARAMS nonceGenerator writes generated nonce and MAC outputs",
            ComplianceLevel.STANDARD,
            reference="PKCS#11 v3.x CK_CCM_MESSAGE_PARAMS nonceGenerator",
        )

        key_bytes = bytes(range(16))
        plaintext = b"generated nonce through message API"
        aad = b"message-generated-ccm-aad"
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_AES,
            key_bytes,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            init_mech = mech_ccm(CKM_AES_CCM, b"\x00" * 12, data_len=len(plaintext), mac_len=16)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, init_mech.byref(), key)
            if rv == CKR_MECHANISM_INVALID:
                pytest.skip("C_MessageEncryptInit: CKR_MECHANISM_INVALID for CKM_AES_CCM")
            assert rv == CKR_OK, f"C_MessageEncryptInit failed: 0x{rv:08x}"

            msg_mech = mech_ccm_message_generated_nonce(
                CKM_AES_CCM,
                data_len=len(plaintext),
                nonce_len=12,
                nonce_generator=int(CKG_GENERATE),
                mac_len=16,
            )
            msg_params = msg_mech.params
            pt_buf = to_ubyte_buf(plaintext)
            aad_buf = to_ubyte_buf(aad)
            ct_len = CK_ULONG(len(plaintext))
            ct_buf = (ctypes.c_ubyte * ct_len.value)()

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

            rv = rs.raw.C_MessageEncryptFinal(rs.sh)
            assert rv == CKR_OK, f"C_MessageEncryptFinal failed: 0x{rv:08x}"

            nonce = msg_mech.buffer_bytes("nonce")
            mac = msg_mech.buffer_bytes("mac")
            ciphertext = bytes(ct_buf[: ct_len.value])
            assert any(nonce), "C_EncryptMessage did not write generated nonce"
            assert any(mac), "C_EncryptMessage did not write CCM MAC"
            assert (
                AESCCM(key_bytes, tag_length=16).decrypt(nonce, ciphertext + mac, aad) == plaintext
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_encrypt_rejects_decrypt_only_key(self, p11_raw_session: RawSession) -> None:
        """C_MessageEncryptInit must reject a key with CKA_ENCRYPT=False.

        Phase 4.5 GAP-A3 closure: the v3.0 message-based API has separate
        code paths from the classical C_EncryptInit / C_DecryptInit flow.
        Key-usage enforcement (CKA_ENCRYPT, CKA_DECRYPT) must apply in
        both paths; a module that only checks usage at C_EncryptInit and
        skips the check at C_MessageEncryptInit allows a decrypt-only
        key to be used for encryption — bypass of the usage attribute.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.pack_mechanisms import mech_gcm_message
        from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, get_mechanism_info
        from pkcs11_check.raw.types_std import (
            CKA_DECRYPT,
            CKA_ENCRYPT,
            CKA_TOKEN,
            CKF_MESSAGE_ENCRYPT,
            CKM_AES_GCM,
            CKR_KEY_FUNCTION_NOT_PERMITTED,
            CKR_KEY_HANDLE_INVALID,
            CKR_KEY_TYPE_INCONSISTENT,
            CKR_OK,
        )

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")
        if not hasattr(rs.raw, "C_MessageEncryptInit"):
            pytest.skip("C_MessageEncryptInit not available on this module")

        # Decrypt-only key: explicitly NOT encrypt-capable.
        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: False, CKA_DECRYPT: True},
        )
        try:
            iv = os.urandom(12)
            mech = mech_gcm_message(CKM_AES_GCM, iv, tag_bits=128)
            rv = rs.raw.C_MessageEncryptInit(rs.sh, mech.byref(), key)

            if rv == CKR_OK:
                # Module accepted a decrypt-only key for message-encrypt
                # init — usage enforcement bypass on the v3.0 message API.
                from pkcs11_check.compliance import ComplianceLevel, note

                note(
                    "C_MessageEncryptInit accepted CKA_ENCRYPT=False key — "
                    "key-usage enforcement bypass on the v3.0 message-"
                    "based API. The classical C_EncryptInit path enforces "
                    "CKA_ENCRYPT; the message API must do the same.",
                    ComplianceLevel.CRITICAL,
                    reference="PKCS#11 v3.1 Sec.4.7 (CKA_ENCRYPT) / Sec.5.4 "
                    "(message-based encryption)",
                )
                # Try to clean up — if MessageEncryptFinal exists, cancel.
                if hasattr(rs.raw, "C_MessageEncryptFinal"):
                    rs.raw.C_MessageEncryptFinal(rs.sh)
                pytest.fail(
                    "SECURITY: C_MessageEncryptInit accepted a key with "
                    "CKA_ENCRYPT=False — usage-attribute enforcement "
                    "missing on the v3.0 message-based API path."
                )

            accepted_rejection = (
                CKR_KEY_FUNCTION_NOT_PERMITTED,
                CKR_KEY_HANDLE_INVALID,
                CKR_KEY_TYPE_INCONSISTENT,
            )
            assert rv in accepted_rejection, (
                f"C_MessageEncryptInit on CKA_ENCRYPT=False key returned "
                f"0x{rv:08x}; expected one of "
                f"{[hex(c) for c in accepted_rejection]}"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_sign_aes_gmac(self, p11_raw_session: RawSession) -> None:
        """Message-based sign init/final roundtrip for CKM_AES_GMAC.

        Verifies that C_MessageSignInit accepts a CKM_AES_GMAC mechanism built
        with CK_GCM_MESSAGE_PARAMS and that C_MessageSignFinal cleanly ends the
        session, exercising the full message-based sign init/cleanup path.

        Reference: PKCS#11 v3.1 Sec.5.5 (Message-based signing functions).
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GMAC"):
            pytest.skip("CKM_AES_GMAC not supported")

        from pkcs11_check.raw.pack_mechanisms import mech_gcm_message
        from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, get_mechanism_info
        from pkcs11_check.raw.types_std import (
            CKA_SIGN,
            CKA_TOKEN,
            CKF_MESSAGE_SIGN,
            CKM_AES_GMAC,
            CKR_MECHANISM_INVALID,
            CKR_OK,
        )

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GMAC)
        if not (info["flags"] & int(CKF_MESSAGE_SIGN)):
            pytest.skip("CKM_AES_GMAC does not advertise CKF_MESSAGE_SIGN")

        if not hasattr(rs.raw, "C_MessageSignInit"):
            pytest.skip("C_MessageSignInit not available on this module")

        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_SIGN: True},
        )
        try:
            iv = os.urandom(12)
            mech = mech_gcm_message(CKM_AES_GMAC, iv, tag_bits=128)
            rv = rs.raw.C_MessageSignInit(rs.sh, mech.byref(), key)
            if rv == CKR_MECHANISM_INVALID:
                pytest.skip("C_MessageSignInit: CKR_MECHANISM_INVALID for CKM_AES_GMAC")
            assert rv == CKR_OK, f"C_MessageSignInit failed: 0x{rv:08x}"

            if hasattr(rs.raw, "C_MessageSignFinal"):
                rv = rs.raw.C_MessageSignFinal(rs.sh)
                assert rv == CKR_OK, f"C_MessageSignFinal failed: 0x{rv:08x}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
