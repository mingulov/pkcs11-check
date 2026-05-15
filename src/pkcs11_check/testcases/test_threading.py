"""Threading and concurrency tests.

Tests that PKCS#11 operations work correctly under thread contention.
The raw PKCS#11 API releases the GIL for all C_* calls, so multiple
threads can call the module concurrently.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly, open_session
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    gen_aes_key,
    generate_random,
)
from pkcs11_check.raw.types_std import (
    CKF_RW_SESSION,
    CKF_SERIAL_SESSION,
    CKM_AES_ECB,
    CKM_SHA256,
)

pytestmark = pytest.mark.stress


class TestThreadedOperations:
    """Run PKCS#11 operations from multiple threads.

    Stateful operations (digest, encrypt) require one session per thread because
    PKCS#11 sessions can only have one active operation at a time. Stateless calls
    (C_GenerateRandom) can share a session.
    """

    def test_threaded_digest(self, p11_raw_session: Any) -> None:
        """Multiple threads computing digests concurrently, each with own session."""
        rs = p11_raw_session
        data_items = [f"thread-digest-{i}".encode() for i in range(20)]
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        def digest_one(data: bytes) -> bytes:
            sh = open_session(rs.raw, rs.slot_id, flags)
            try:
                return digest_single(rs.raw, sh, CKM_SHA256, data)
            finally:
                close_session_quietly(rs.raw, sh)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(digest_one, d) for d in data_items]
            results = [f.result() for f in futures]

        assert len(results) == 20
        assert all(len(r) == 32 for r in results)
        # Each different input should produce different output
        assert len(set(results)) == 20

    def test_threaded_random(self, p11_raw_session: Any) -> None:
        """Multiple threads generating random data concurrently."""
        rs = p11_raw_session

        def gen_random(_: int) -> bytes:
            return generate_random(rs.raw, rs.sh, 32)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(gen_random, i) for i in range(20)]
            results = [f.result() for f in futures]

        assert len(results) == 20
        assert all(len(r) == 32 for r in results)
        assert len(set(results)) == 20  # All unique

    def test_threaded_keygen_destroy(self, p11_raw_session: Any) -> None:
        """Multiple threads generating and destroying keys concurrently."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        def keygen_destroy(_: int) -> bool:
            sh = open_session(rs.raw, rs.slot_id, flags)
            try:
                key = gen_aes_key(rs.raw, sh, 128)
                destroy_quietly(rs.raw, sh, key)
                return True
            finally:
                close_session_quietly(rs.raw, sh)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(keygen_destroy, i) for i in range(20)]
            results = [f.result() for f in futures]

        assert all(results)


class TestMultiSessionThreads:
    """Each thread opens its own session for independent operations."""

    @pytest.mark.thread_safe
    def test_independent_sessions(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Each thread gets its own session and operates independently."""
        rs = p11_raw_session
        flags = CKF_SERIAL_SESSION | CKF_RW_SESSION

        def thread_work(thread_id: int) -> tuple[int, int, bytes]:
            # Open a new session per thread (reuse token-level login)
            sh = open_session(rs.raw, rs.slot_id, flags)
            try:
                key = gen_aes_key(rs.raw, sh, 256)
                data = f"thread-{thread_id}-data!".encode().ljust(16, b"\x00")
                ct = encrypt_single(rs.raw, sh, key, CKM_AES_ECB, data)
                pt = decrypt_single(rs.raw, sh, key, CKM_AES_ECB, ct)
                destroy_quietly(rs.raw, sh, key)
                return (thread_id, len(ct), pt)
            finally:
                close_session_quietly(rs.raw, sh)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(thread_work, i) for i in range(8)]
            results = [f.result() for f in futures]

        assert len(results) == 8
        for tid, ct_len, pt in results:
            expected = f"thread-{tid}-data!".encode().ljust(16, b"\x00")
            assert ct_len == 16
            assert pt == expected
