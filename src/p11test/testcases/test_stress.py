"""Concurrency and stress tests for PKCS#11 modules.

Tests multi-session behavior, rapid operation cycling, and
resource limits. These help find threading bugs and leaks
that only manifest under sustained load.
"""

from __future__ import annotations

import time
from typing import Any

import pkcs11
import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.stress


class TestMultiSessionConcurrency:
    """Test concurrent operations across multiple sessions.

    NOTE: Many PKCS#11 modules (including SoftHSM2) have limited thread
    safety. These tests verify the module doesn't crash under concurrency,
    even if some operations fail.
    """

    def test_sequential_multi_session(self, p11_module: Any, p11_config: Any) -> None:
        """Open multiple sessions sequentially and operate independently."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        # Open first session with login
        with token.open(rw=True, user_pin=pin) as session1:
            key1 = session1.generate_key(KeyType.AES, 128, label="multi-s1")
            # Open second session (already logged in)
            with token.open(rw=True) as session2:
                key2 = session2.generate_key(KeyType.AES, 128, label="multi-s2")
                key2.destroy()
            key1.destroy()

    def test_sequential_digest_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Multiple sessions can each compute independent digests."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        digests = []
        with token.open(rw=False, user_pin=pin) as session1:
            d1 = session1.digest(b"session 1 data", mechanism=Mechanism.SHA256)
            digests.append(d1)
            with token.open(rw=False) as session2:
                d2 = session2.digest(b"session 2 data", mechanism=Mechanism.SHA256)
                digests.append(d2)

        assert len(digests) == 2
        assert digests[0] != digests[1]  # Different data → different digest


class TestRapidOperations:
    """Test rapid cycling of operations without pause."""

    def test_rapid_encrypt_decrypt_1000(self, p11_session: Any) -> None:
        """1000 encrypt/decrypt cycles in quick succession."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"rapid cycling!!!"  # 16 bytes

        start = time.monotonic()
        for _ in range(1000):
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == plaintext
        elapsed = time.monotonic() - start

        key.destroy()
        # Should complete in reasonable time (<30s for 1000 cycles)
        assert elapsed < 30, f"1000 encrypt/decrypt cycles took {elapsed:.1f}s"

    def test_rapid_digest_1000(self, p11_session: Any) -> None:
        """1000 SHA-256 digest operations."""
        data = b"rapid digest test data"
        expected = p11_session.digest(data, mechanism=Mechanism.SHA256)

        start = time.monotonic()
        for _ in range(1000):
            result = p11_session.digest(data, mechanism=Mechanism.SHA256)
            assert result == expected
        elapsed = time.monotonic() - start

        assert elapsed < 10, f"1000 digests took {elapsed:.1f}s"

    def test_rapid_random_1000(self, p11_session: Any) -> None:
        """1000 random generation calls."""
        start = time.monotonic()
        seen = set()
        for _ in range(1000):
            data = p11_session.generate_random(256)
            seen.add(data)
        elapsed = time.monotonic() - start

        assert len(seen) == 1000, "Random generation produced duplicates"
        assert elapsed < 10, f"1000 random generations took {elapsed:.1f}s"

    def test_rapid_sign_verify_100(self, p11_session: Any) -> None:
        """100 RSA sign/verify cycles."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"rapid sign test"

        start = time.monotonic()
        for _ in range(100):
            sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
            assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)
        elapsed = time.monotonic() - start

        pub.destroy()
        priv.destroy()
        assert elapsed < 60, f"100 RSA sign/verify took {elapsed:.1f}s"


class TestSessionStress:
    """Test session lifecycle under stress."""

    def test_session_open_close_100(self, p11_module: Any, p11_config: Any) -> None:
        """Open and close 100 sessions rapidly."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        for i in range(100):
            try:
                with token.open(rw=True, user_pin=pin) as session:
                    session.generate_random(64)
            except pkcs11.exceptions.UserAlreadyLoggedIn:
                with token.open(rw=True) as session:
                    session.generate_random(64)

    def test_create_destroy_cycle(self, p11_session: Any) -> None:
        """Create and destroy 500 keys rapidly."""
        for i in range(500):
            key = p11_session.generate_key(KeyType.AES, 128)
            key.destroy()
