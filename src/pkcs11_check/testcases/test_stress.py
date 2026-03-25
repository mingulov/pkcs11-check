"""Concurrency and stress tests for PKCS#11 modules.

Tests multi-session behavior, rapid operation cycling, and
resource limits. These help find threading bugs and leaks
that only manifest under sustained load.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import (
    close_session_quietly,
    login_user,
    open_session,
)
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    gen_rsa_keypair,
    generate_random,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.types_std import (
    CKA_LABEL,
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_SHA256,
    CKM_SHA256_RSA_PKCS,
)
from pkcs11_check.testcases.conftest import get_pin_bytes

pytestmark = pytest.mark.stress


class TestMultiSessionConcurrency:
    """Test concurrent operations across multiple sessions.

    NOTE: Many PKCS#11 modules (including SoftHSM2) have limited thread
    safety. These tests verify the module doesn't crash under concurrency,
    even if some operations fail.
    """

    def test_sequential_multi_session(
        self, p11_raw_session: Any, p11_config: Any,
    ) -> None:
        """Open multiple sessions sequentially and operate independently."""
        rs = p11_raw_session
        pin_bytes = get_pin_bytes(p11_config)
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)

        # Open first session (p11_raw_session already has one)
        # Generate a key in the existing session
        key1 = gen_aes_key(
            rs.raw, rs.sh, 128,
            attrs={int(CKA_LABEL): b"multi-s1"},
        )

        # Open second session (already logged in at token level)
        sh2 = open_session(rs.raw, rs.slot_id, flags)
        try:
            key2 = gen_aes_key(
                rs.raw, sh2, 128,
                attrs={int(CKA_LABEL): b"multi-s2"},
            )
            destroy_quietly(rs.raw, sh2, key2)
        finally:
            close_session_quietly(rs.raw, sh2)
        destroy_quietly(rs.raw, rs.sh, key1)

    def test_sequential_digest_sessions(
        self, p11_raw_session: Any, p11_config: Any,
    ) -> None:
        """Multiple sessions can each compute independent digests."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)

        digests = []
        d1 = digest_single(rs.raw, rs.sh, CKM_SHA256, b"session 1 data")
        digests.append(d1)

        sh2 = open_session(rs.raw, rs.slot_id, flags)
        try:
            d2 = digest_single(rs.raw, sh2, CKM_SHA256, b"session 2 data")
            digests.append(d2)
        finally:
            close_session_quietly(rs.raw, sh2)

        assert len(digests) == 2
        assert digests[0] != digests[1]  # Different data -> different digest


class TestRapidOperations:
    """Test rapid cycling of operations without pause."""

    def test_rapid_encrypt_decrypt_1000(self, p11_raw_session: Any) -> None:
        """1000 encrypt/decrypt cycles in quick succession."""
        rs = p11_raw_session
        key = gen_aes_key(rs.raw, rs.sh, 256)
        plaintext = b"rapid cycling!!!"  # 16 bytes

        try:
            start = time.monotonic()
            for _ in range(1000):
                ct = encrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, plaintext)
                pt = decrypt_single(rs.raw, rs.sh, key, CKM_AES_ECB, ct)
                assert pt == plaintext
            elapsed = time.monotonic() - start

            # Should complete in reasonable time (<30s for 1000 cycles)
            assert elapsed < 30, f"1000 encrypt/decrypt cycles took {elapsed:.1f}s"
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_rapid_digest_1000(self, p11_raw_session: Any) -> None:
        """1000 SHA-256 digest operations."""
        rs = p11_raw_session
        data = b"rapid digest test data"
        expected = digest_single(rs.raw, rs.sh, CKM_SHA256, data)

        start = time.monotonic()
        for _ in range(1000):
            result = digest_single(rs.raw, rs.sh, CKM_SHA256, data)
            assert result == expected
        elapsed = time.monotonic() - start

        assert elapsed < 10, f"1000 digests took {elapsed:.1f}s"

    def test_rapid_random_1000(self, p11_raw_session: Any) -> None:
        """1000 random generation calls."""
        rs = p11_raw_session
        start = time.monotonic()
        seen: set[bytes] = set()
        for _ in range(1000):
            data = generate_random(rs.raw, rs.sh, 32)
            seen.add(data)
        elapsed = time.monotonic() - start

        assert len(seen) == 1000, "Random generation produced duplicates"
        assert elapsed < 10, f"1000 random generations took {elapsed:.1f}s"

    def test_rapid_sign_verify_100(self, p11_raw_session: Any) -> None:
        """100 RSA sign/verify cycles."""
        rs = p11_raw_session
        pub, priv = gen_rsa_keypair(rs.raw, rs.sh, 2048)
        data = b"rapid sign test"

        try:
            start = time.monotonic()
            for _ in range(100):
                sig = sign_single(rs.raw, rs.sh, priv, CKM_SHA256_RSA_PKCS, data)
                assert verify_single(
                    rs.raw, rs.sh, pub, CKM_SHA256_RSA_PKCS, data, sig,
                ) is True
            elapsed = time.monotonic() - start

            assert elapsed < 60, f"100 RSA sign/verify took {elapsed:.1f}s"
        finally:
            destroy_quietly(rs.raw, rs.sh, pub)
            destroy_quietly(rs.raw, rs.sh, priv)


class TestSessionStress:
    """Test session lifecycle under stress."""

    def test_session_open_close_100(
        self, p11_raw_session: Any, p11_config: Any,
    ) -> None:
        """Open and close 100 sessions rapidly."""
        rs = p11_raw_session
        flags = int(CKF_SERIAL_SESSION) | int(CKF_RW_SESSION)

        for _i in range(100):
            sh = open_session(rs.raw, rs.slot_id, flags)
            try:
                generate_random(rs.raw, sh, 64)
            finally:
                close_session_quietly(rs.raw, sh)

    def test_create_destroy_cycle(self, p11_raw_session: Any) -> None:
        """Create and destroy 500 keys rapidly."""
        rs = p11_raw_session
        for _i in range(500):
            key = gen_aes_key(rs.raw, rs.sh, 128)
            destroy_quietly(rs.raw, rs.sh, key)
