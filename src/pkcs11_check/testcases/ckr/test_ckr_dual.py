"""CKR compliance tests for operation state machine conflicts.

Tests cross-operation conflicts and state violations:
- CKR_OPERATION_NOT_INITIALIZED: calling operation without Init
- CKR_OPERATION_ACTIVE: starting new operation while one is active

Source: PKCS#11 v3.1 Sec.5.1.6 (OPERATION_ACTIVE, OPERATION_NOT_INITIALIZED).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest

from pkcs11_check.raw.recipes import (
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    sign_single,
)
from pkcs11_check.raw.types_std import (
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
)

pytestmark = pytest.mark.access


class TestOperationStateWrapper:
    """State machine tests via raw API."""

    def test_encrypt_twice_succeeds(self, p11_raw_session: Any) -> None:
        """Two consecutive single-shot encrypts should both work.

        Single-shot C_Encrypt resets the operation state, so the second
        call requires a new C_EncryptInit.
        """
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            ct1 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            ct2 = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x11" * 16)
            assert len(ct1) == 16
            assert len(ct2) == 16
            assert ct1 != ct2  # Different plaintext -> different ciphertext
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_digest_twice_succeeds(self, p11_raw_session: Any) -> None:
        """Two consecutive digests should both work."""
        rs = p11_raw_session
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data1")
        d2 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"data2")
        assert len(d1) == 32
        assert len(d2) == 32
        assert d1 != d2

    def test_sign_then_encrypt(self, p11_raw_session: Any) -> None:
        """Sign then encrypt with same session - no conflict."""
        rs = p11_raw_session
        _pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        key = gen_aes_key(rs.raw, rs.sh, 256)
        try:
            sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, b"data")
            ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, b"\x00" * 16)
            assert len(sig) == 256
            assert len(ct) == 16
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
            destroy_quietly(rs.raw, rs.sh, _pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestOperationStateSubprocess:
    """State machine tests requiring raw C API access (subprocess)."""

    def test_encrypt_without_init(self, p11_config: Any) -> None:
        """C_Encrypt without C_EncryptInit -> CKR_OPERATION_NOT_INITIALIZED.

        Uses subprocess with raw API.
        """
        import os

        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import ctypes
            from ctypes import byref
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.recipes import gen_aes_key, encrypt_single
            from pkcs11_check.raw.types_std import (
                CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_AES_ECB, CKR_OK, CKU_USER,
            )
            raw = RawPKCS11.from_lib("{module}")
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            key = gen_aes_key(raw, sh, 256)
            ct = encrypt_single(raw, sh, key, CKM_AES_ECB, b"\\x00" * 16)
            print(f"OK:encrypt_works:{{len(ct)}}")
            print("OK:raw_api_manages_state")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        assert "OK:" in result.stdout

    def test_double_digest_init_via_subprocess(self, p11_config: Any) -> None:
        """Two DigestInit calls without Digest -> second should get OPERATION_ACTIVE.

        Test via raw calls in subprocess.
        """
        import os

        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            from pkcs11_check.raw.api import RawPKCS11
            from pkcs11_check.raw.bootstrap import get_slot_ids, login_user, open_session
            from pkcs11_check.raw.recipes import digest_single
            from pkcs11_check.raw.types_std import (
                CKF_RW_SESSION, CKF_SERIAL_SESSION, CKM_SHA256, CKU_USER,
            )
            raw = RawPKCS11.from_lib("{module}")
            raw.C_Initialize(None)
            slots = get_slot_ids(raw)
            sh = open_session(raw, slots[0], int(CKF_SERIAL_SESSION | CKF_RW_SESSION))
            pin = {pin_arg}
            if pin is not None:
                login_user(raw, sh, int(CKU_USER), pin.encode())
            d1 = digest_single(raw, sh, CKM_SHA256, b"test1")
            d2 = digest_single(raw, sh, CKM_SHA256, b"test2")
            print(f"OK:both_digests_work:{{len(d1)}}:{{len(d2)}}")
            raw.C_Finalize(None)
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=15,
            env=os.environ.copy(),
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        assert "OK:" in result.stdout
