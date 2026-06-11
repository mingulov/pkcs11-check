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
from typing import Any

import pytest

from pkcs11_check.fixtures import RawSession
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.recipes import destroy_quietly, to_ubyte_buf
from pkcs11_check.raw.types_std import CKM, CKR_OK
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_helpers import (
    generate_key_for_encrypt,
    generate_key_for_sign,
    make_mech_param_or_skip,
)

pytestmark = [
    pytest.mark.mechanism_coverage,
    pytest.mark.message_based,
]


def _xfail_if_message_init_rejected(rv: int, *, label: str) -> None:
    """Phase 6 P3: classify a C_Message*Init result on an advertised mechanism.

    The caller has already confirmed the mechanism advertises the message flag
    (CKF_MESSAGE_*) and the function is present, so the op is *advertised*:

    - ``CKR_OK`` -> return (pass; caller proceeds),
    - a known clean reject code -> ``xfail`` (advertised but not operational),
    - any other code -> caller's ``assert rv == CKR_OK`` fails (unexpected).

    Previously only ``CKR_MECHANISM_INVALID`` was treated as xfail; a different
    clean reject (e.g. CKR_FUNCTION_FAILED) wrongly hard-failed.
    """
    from pkcs11_check.raw.rv import ckr_name
    from pkcs11_check.raw.types_std import (
        CKR_DEVICE_ERROR,
        CKR_FUNCTION_FAILED,
        CKR_FUNCTION_NOT_SUPPORTED,
        CKR_GENERAL_ERROR,
        CKR_MECHANISM_INVALID,
        CKR_MECHANISM_PARAM_INVALID,
        CKR_OK,
    )

    if rv == int(CKR_OK):
        return
    reject = (
        int(CKR_MECHANISM_INVALID),
        int(CKR_MECHANISM_PARAM_INVALID),
        int(CKR_FUNCTION_NOT_SUPPORTED),
        int(CKR_FUNCTION_FAILED),
        int(CKR_DEVICE_ERROR),
        int(CKR_GENERAL_ERROR),
    )
    if rv in reject:
        pytest.xfail(f"{label}: advertised message op rejected with {ckr_name(rv)}")


def _require_message_functions(rs: RawSession, *function_names: str) -> None:
    for function_name in function_names:
        if not hasattr(rs.raw, function_name):
            pytest.skip(f"{function_name} not available on this module")


def _message_init_mech_or_skip(entry: MechEntry) -> Any:
    config = entry.config
    if config is None:
        pytest.skip(f"{entry.mech_name}: no registry config")

    if config.param_required and config.param_recipe.style == "gcm":
        from pkcs11_check.raw.pack_mechanisms import mech_gcm_message

        defaults = config.param_recipe.defaults
        return mech_gcm_message(
            CKM(entry.mech_id),
            os.urandom(int(defaults.get("iv_len", 12))),
            tag_bits=int(defaults.get("tag_bits", 128)),
        )

    if config.param_required and config.param_recipe.style == "ccm":
        from pkcs11_check.raw.pack_mechanisms import mech_ccm

        defaults = config.param_recipe.defaults
        return mech_ccm(
            CKM(entry.mech_id),
            os.urandom(int(defaults.get("nonce_len", 12))),
            data_len=int(defaults.get("data_len", 32)),
            mac_len=int(defaults.get("mac_len", 16)),
        )

    mech_param = make_mech_param_or_skip(entry)
    return mech_param if mech_param is not None else mech_simple(CKM(entry.mech_id))


def _message_init_or_xfail(
    rs: RawSession,
    entry: MechEntry,
    *,
    key: int,
    init_name: str,
) -> None:
    init = getattr(rs.raw, init_name)
    mech = _message_init_mech_or_skip(entry)
    rv = init(rs.sh, mech.byref(), key)
    _xfail_if_message_init_rejected(rv, label=f"{init_name} (CKM_{entry.mech_name})")
    assert rv == CKR_OK, f"{init_name}(CKM_{entry.mech_name}) failed: 0x{rv:08x}"


def _message_final_or_fail(rs: RawSession, entry: MechEntry, *, final_name: str) -> None:
    final = getattr(rs.raw, final_name)
    rv = final(rs.sh)
    assert rv == CKR_OK, f"{final_name}(CKM_{entry.mech_name}) failed: 0x{rv:08x}"


class TestRegistryMessageInit:
    """Registry-driven message-init smoke coverage for advertised CKF_MESSAGE_* flags."""

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_registry_message_encrypt_init(
        self,
        p11_module_session: RawSession,
        mech_message_encrypt_entry: MechEntry,
    ) -> None:
        rs = p11_module_session
        entry = mech_message_encrypt_entry
        config = entry.config
        assert config is not None
        _require_message_functions(rs, "C_MessageEncryptInit", "C_MessageEncryptFinal")

        encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
        try:
            _message_init_or_xfail(
                rs,
                entry,
                key=encrypt_key,
                init_name="C_MessageEncryptInit",
            )
            _message_final_or_fail(rs, entry, final_name="C_MessageEncryptFinal")
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    @pytest.mark.needs_function("C_MessageDecryptInit")
    def test_registry_message_decrypt_init(
        self,
        p11_module_session: RawSession,
        mech_message_decrypt_entry: MechEntry,
    ) -> None:
        rs = p11_module_session
        entry = mech_message_decrypt_entry
        config = entry.config
        assert config is not None
        _require_message_functions(rs, "C_MessageDecryptInit", "C_MessageDecryptFinal")

        encrypt_key, decrypt_key = generate_key_for_encrypt(rs, entry, config)
        try:
            _message_init_or_xfail(
                rs,
                entry,
                key=decrypt_key if decrypt_key is not None else encrypt_key,
                init_name="C_MessageDecryptInit",
            )
            _message_final_or_fail(rs, entry, final_name="C_MessageDecryptFinal")
        finally:
            destroy_quietly(rs.raw, rs.sh, encrypt_key)
            if decrypt_key is not None:
                destroy_quietly(rs.raw, rs.sh, decrypt_key)

    @pytest.mark.needs_function("C_MessageSignInit")
    def test_registry_message_sign_init(
        self,
        p11_module_session: RawSession,
        mech_message_sign_entry: MechEntry,
    ) -> None:
        rs = p11_module_session
        entry = mech_message_sign_entry
        config = entry.config
        assert config is not None
        _require_message_functions(rs, "C_MessageSignInit", "C_MessageSignFinal")

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        try:
            _message_init_or_xfail(
                rs,
                entry,
                key=sign_key,
                init_name="C_MessageSignInit",
            )
            _message_final_or_fail(rs, entry, final_name="C_MessageSignFinal")
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)

    @pytest.mark.needs_function("C_MessageVerifyInit")
    def test_registry_message_verify_init(
        self,
        p11_module_session: RawSession,
        mech_message_verify_entry: MechEntry,
    ) -> None:
        rs = p11_module_session
        entry = mech_message_verify_entry
        config = entry.config
        assert config is not None
        _require_message_functions(rs, "C_MessageVerifyInit", "C_MessageVerifyFinal")

        sign_key, verify_key = generate_key_for_sign(rs, entry, config)
        try:
            _message_init_or_xfail(
                rs,
                entry,
                key=verify_key if verify_key is not None else sign_key,
                init_name="C_MessageVerifyInit",
            )
            _message_final_or_fail(rs, entry, final_name="C_MessageVerifyFinal")
        finally:
            destroy_quietly(rs.raw, rs.sh, sign_key)
            if verify_key is not None:
                destroy_quietly(rs.raw, rs.sh, verify_key)


class TestMessageEncrypt:
    """v3.0 C_MessageEncrypt* API tests."""

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_message_encrypt_decrypt_aes_gcm(self, p11_module_session: RawSession) -> None:
        """Single-message AES-GCM encrypt/decrypt roundtrip via message-based API.

        Verifies the full CK_GCM_MESSAGE_PARAMS packing path through
        C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal and
        the matching decrypt side.

        Reference: PKCS#11 v3.1 Sec.5.4 (Message-based encryption functions).
        """
        rs = p11_module_session
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
            _xfail_if_message_init_rejected(rv, label="C_MessageEncryptInit (CKM_AES_GCM)")
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

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_message_encrypt_aes_gcm_generated_iv_writeback(
        self, p11_module_session: RawSession
    ) -> None:
        """C_EncryptMessage with CKG_GENERATE writes the generated IV to pIv.

        This is the standard PKCS#11 v3.x version of provider-generated AEAD
        IV handling. Unlike legacy CKM_AES_GCM parameter mutation, ivGenerator
        support is part of CK_GCM_MESSAGE_PARAMS.
        """
        rs = p11_module_session
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
            _xfail_if_message_init_rejected(rv, label="C_MessageEncryptInit (CKM_AES_GCM)")
            assert rv == CKR_OK, f"C_MessageEncryptInit failed: 0x{rv:08x}"

            msg_mech = mech_gcm_message_generated_iv(
                CKM_AES_GCM,
                iv_len=12,
                iv_generator=CKG_GENERATE,
                tag_bits=128,
            )
            msg_params = msg_mech.params
            guard = 0x9C
            guard_size = 32

            class GeneratedOutputProbe(ctypes.Structure):
                _fields_ = [
                    ("iv", ctypes.c_ubyte * 12),
                    ("iv_guard", ctypes.c_ubyte * guard_size),
                    ("tag", ctypes.c_ubyte * 16),
                    ("tag_guard", ctypes.c_ubyte * guard_size),
                ]

            probe = GeneratedOutputProbe()
            for idx in range(guard_size):
                probe.iv_guard[idx] = guard
                probe.tag_guard[idx] = guard
            msg_params.pIv = ctypes.cast(probe.iv, ctypes.c_void_p)
            msg_params.pTag = ctypes.cast(probe.tag, ctypes.c_void_p)

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

            iv_overwritten = sum(1 for byte in probe.iv_guard if byte != guard)
            tag_overwritten = sum(1 for byte in probe.tag_guard if byte != guard)
            assert iv_overwritten == 0, (
                "C_EncryptMessage wrote past CK_GCM_MESSAGE_PARAMS.pIv: "
                f"{iv_overwritten} guard byte(s) changed"
            )
            assert tag_overwritten == 0, (
                "C_EncryptMessage wrote past CK_GCM_MESSAGE_PARAMS.pTag: "
                f"{tag_overwritten} guard byte(s) changed"
            )
            iv = bytes(probe.iv)
            tag = bytes(probe.tag)
            ciphertext = bytes(ct_buf[: ct_len.value])
            assert any(iv), "C_EncryptMessage did not write generated IV to pIv"
            assert any(tag), "C_EncryptMessage did not write GCM tag to pTag"
            assert AESGCM(key_bytes).decrypt(iv, ciphertext + tag, aad) == plaintext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_message_encrypt_aes_ccm_generated_nonce_writeback(
        self, p11_module_session: RawSession
    ) -> None:
        """C_EncryptMessage with CKG_GENERATE writes AES-CCM nonce and MAC outputs."""
        rs = p11_module_session
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
            _xfail_if_message_init_rejected(rv, label="C_MessageEncryptInit (CKM_AES_CCM)")
            assert rv == CKR_OK, f"C_MessageEncryptInit failed: 0x{rv:08x}"

            msg_mech = mech_ccm_message_generated_nonce(
                CKM_AES_CCM,
                data_len=len(plaintext),
                nonce_len=12,
                nonce_generator=CKG_GENERATE,
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

    @pytest.mark.needs_function("C_MessageEncryptInit")
    def test_message_encrypt_rejects_decrypt_only_key(self, p11_module_session: RawSession) -> None:
        """C_MessageEncryptInit must reject a key with CKA_ENCRYPT=False.

        Phase 4.5 GAP-A3 closure: the v3.0 message-based API has separate
        code paths from the classical C_EncryptInit / C_DecryptInit flow.
        Key-usage enforcement (CKA_ENCRYPT, CKA_DECRYPT) must apply in
        both paths; a module that only checks usage at C_EncryptInit and
        skips the check at C_MessageEncryptInit allows a decrypt-only
        key to be used for encryption — bypass of the usage attribute.
        """
        rs = p11_module_session
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

            # CKR_OK was handled above (security finding -> fail). Here the op
            # was rejected: the spec codes pass; any other clean reject is a
            # noted deviation (xfail), not a hard failure (Phase 6 P3/N2).
            from pkcs11_check.testcases.conftest import classify_negative_rv

            accepted_rejection = (
                CKR_KEY_FUNCTION_NOT_PERMITTED,
                CKR_KEY_HANDLE_INVALID,
                CKR_KEY_TYPE_INCONSISTENT,
            )
            classify_negative_rv(
                rv,
                accepted_rejection,
                label="C_MessageEncryptInit on a CKA_ENCRYPT=False key",
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    @pytest.mark.needs_function("C_MessageSignInit")
    def test_message_sign_aes_gmac(self, p11_module_session: RawSession) -> None:
        """Message-based sign init/final roundtrip for CKM_AES_GMAC.

        Verifies that C_MessageSignInit accepts a CKM_AES_GMAC mechanism built
        with CK_GCM_MESSAGE_PARAMS and that C_MessageSignFinal cleanly ends the
        session, exercising the full message-based sign init/cleanup path.

        Reference: PKCS#11 v3.1 Sec.5.5 (Message-based signing functions).
        """
        rs = p11_module_session
        if not rs.has_mechanism("AES_GMAC"):
            pytest.skip("CKM_AES_GMAC not supported")

        from pkcs11_check.raw.pack_mechanisms import mech_gcm_message
        from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, get_mechanism_info
        from pkcs11_check.raw.types_std import (
            CKA_SIGN,
            CKA_TOKEN,
            CKF_MESSAGE_SIGN,
            CKM_AES_GMAC,
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
            _xfail_if_message_init_rejected(rv, label="C_MessageSignInit (CKM_AES_GMAC)")
            assert rv == CKR_OK, f"C_MessageSignInit failed: 0x{rv:08x}"

            if hasattr(rs.raw, "C_MessageSignFinal"):
                rv = rs.raw.C_MessageSignFinal(rs.sh)
                assert rv == CKR_OK, f"C_MessageSignFinal failed: 0x{rv:08x}"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
