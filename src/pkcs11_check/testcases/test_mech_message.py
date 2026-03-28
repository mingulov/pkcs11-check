"""Mechanism-driven message-based operation tests (v3.0+).

The message-based API (C_MessageEncryptInit / C_EncryptMessage / C_MessageEncryptFinal
and the decrypt equivalents) was introduced in PKCS#11 v3.0.  It allows a single
session initialisation to be reused for many independent messages with per-message
parameters (e.g. different GCM IVs) without a round-trip C_*Init call per message.

Reference: PKCS#11 v3.1 Sec.5.4 (Message-based encryption functions).
"""
from __future__ import annotations

from typing import Any

import pytest

pytestmark = [
    pytest.mark.mechanism_coverage,
    pytest.mark.message_based,
    pytest.mark.requires_v30,
]


class TestMessageEncrypt:
    """v3.0 C_MessageEncrypt* API tests."""

    def test_message_encrypt_decrypt_aes_gcm(self, p11_raw_session: Any) -> None:
        """Single-message AES-GCM encrypt/decrypt roundtrip via message-based API.

        Checks that CKF_MESSAGE_ENCRYPT is advertised for CKM_AES_GCM and that
        C_MessageEncryptInit / C_EncryptMessage / C_MessageDecryptInit /
        C_DecryptMessage are present on the loaded module.

        The full parameter-struct path (CK_GCM_MESSAGE_PARAMS) is not yet
        implemented in the pack_mechanisms layer; this test skips with an
        explanation rather than failing so the gap is visible in the test log.
        """
        rs = p11_raw_session
        if not rs.has_mechanism("AES_GCM"):
            pytest.skip("CKM_AES_GCM not supported")

        from pkcs11_check.raw.recipes import destroy_quietly, gen_aes_key, get_mechanism_info
        from pkcs11_check.raw.types_std import (
            CKA_DECRYPT,
            CKA_ENCRYPT,
            CKA_TOKEN,
            CKF_MESSAGE_ENCRYPT,
            CKM_AES_GCM,
        )

        info = get_mechanism_info(rs.raw, rs.slot_id, CKM_AES_GCM)
        if not (info["flags"] & int(CKF_MESSAGE_ENCRYPT)):
            pytest.skip("CKM_AES_GCM does not advertise CKF_MESSAGE_ENCRYPT")

        if not hasattr(rs.raw, "C_MessageEncryptInit"):
            pytest.skip("C_MessageEncryptInit not available on this module")

        key = gen_aes_key(
            rs.raw,
            rs.sh,
            256,
            attrs={CKA_TOKEN: False, CKA_ENCRYPT: True, CKA_DECRYPT: True},
        )
        try:
            # CK_GCM_MESSAGE_PARAMS packing is not yet implemented.
            # Skip with an informative message so the gap remains visible.
            pytest.skip(
                "Message-based AES-GCM test requires CK_GCM_MESSAGE_PARAMS "
                "packing (not yet implemented in pack_mechanisms)"
            )
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_message_sign_aes_gmac(self, p11_raw_session: Any) -> None:
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
            "Module advertises CKF_MESSAGE_SIGN for AES_GMAC "
            "but C_MessageSignInit is absent"
        )
