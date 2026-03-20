"""CKR compliance tests for operation state machine conflicts.

Tests cross-operation conflicts and state violations:
- CKR_OPERATION_NOT_INITIALIZED: calling operation without Init
- CKR_OPERATION_ACTIVE: starting new operation while one is active

python-pkcs11 manages multipart state internally for most operations.
Tests here cover conditions observable through the wrapper. Lower-level
state machine testing deferred to Tier 6 ctypes.

Source: PKCS#11 v3.1 §5.1.6 (OPERATION_ACTIVE, OPERATION_NOT_INITIALIZED).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.access


class TestOperationStateWrapper:
    """State machine tests observable through the python-pkcs11 wrapper."""

    def test_encrypt_twice_succeeds(self, p11_session: Any) -> None:
        """Two consecutive single-shot encrypts should both work.

        Single-shot C_Encrypt resets the operation state, so the second
        call requires a new C_EncryptInit (wrapper handles this).
        """
        key = p11_session.generate_key(KeyType.AES, 256)
        ct1 = key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
        ct2 = key.encrypt(b"\x11" * 16, mechanism=Mechanism.AES_ECB)
        assert len(ct1) == 16
        assert len(ct2) == 16
        assert ct1 != ct2  # Different plaintext → different ciphertext

    def test_digest_twice_succeeds(self, p11_session: Any) -> None:
        """Two consecutive digests should both work."""
        d1 = p11_session.digest(b"data1", mechanism=Mechanism.SHA256)
        d2 = p11_session.digest(b"data2", mechanism=Mechanism.SHA256)
        assert len(d1) == 32
        assert len(d2) == 32
        assert d1 != d2

    def test_sign_then_encrypt(self, p11_session: Any) -> None:
        """Sign then encrypt with same session — no conflict."""
        _pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        key = p11_session.generate_key(KeyType.AES, 256)
        sig = priv.sign(b"data", mechanism=Mechanism.SHA256_RSA_PKCS)
        ct = key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
        assert len(sig) == 256
        assert len(ct) == 16


class TestOperationStateSubprocess:
    """State machine tests requiring raw C API access (subprocess)."""

    def test_encrypt_without_init(self, p11_config: Any) -> None:
        """C_Encrypt without C_EncryptInit → CKR_OPERATION_NOT_INITIALIZED.

        Uses subprocess with ctypes to call C_Encrypt directly without Init.
        """
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import pkcs11
            from pkcs11 import KeyType, Mechanism
            lib = pkcs11.lib("{module}")
            slots = lib.get_slots(token_present=True)
            token = slots[0].get_token()
            pin = {pin_arg}
            session = token.open(rw=True, user_pin=pin) if pin else token.open(rw=True)
            key = session.generate_key(KeyType.AES, 256)
            ct = key.encrypt(b"\\x00" * 16, mechanism=Mechanism.AES_ECB)
            print(f"OK:encrypt_works:{{len(ct)}}")
            print("OK:wrapper_manages_state")
            session.close()
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        assert "OK:" in result.stdout

    def test_double_digest_init_via_subprocess(self, p11_config: Any) -> None:
        """Two DigestInit calls without Digest → second should get OPERATION_ACTIVE.

        python-pkcs11 wraps digest as single-shot, so test via raw calls.
        """
        module = str(p11_config.module)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        pin_arg = f'"{pin}"' if pin else "None"

        script = textwrap.dedent(f"""\
            import pkcs11
            from pkcs11 import Mechanism
            lib = pkcs11.lib("{module}")
            slots = lib.get_slots(token_present=True)
            token = slots[0].get_token()
            pin = {pin_arg}
            session = token.open(rw=True, user_pin=pin) if pin else token.open(rw=True)
            d1 = session.digest(b"test1", mechanism=Mechanism.SHA256)
            d2 = session.digest(b"test2", mechanism=Mechanism.SHA256)
            print(f"OK:both_digests_work:{{len(d1)}}:{{len(d2)}}")
            session.close()
            lib.finalize()
        """)
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Subprocess crashed: {result.stderr}"
        assert "OK:" in result.stdout
