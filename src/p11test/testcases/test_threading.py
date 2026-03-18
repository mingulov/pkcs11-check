"""Threading and concurrency tests.

Tests that PKCS#11 operations work correctly under thread contention.
python-pkcs11 releases the GIL for all C_* calls, so multiple threads
can call the module concurrently.
"""

from __future__ import annotations

import concurrent.futures
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.stress


class TestThreadedOperations:
    """Run PKCS#11 operations from multiple threads sharing one session."""

    def test_threaded_digest(self, p11_session: Any) -> None:
        """Multiple threads computing digests concurrently."""
        data_items = [f"thread-digest-{i}".encode() for i in range(20)]
        results: list[bytes] = []

        def digest_one(data: bytes) -> bytes:
            return p11_session.digest(data, mechanism=Mechanism.SHA256)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(digest_one, d) for d in data_items]
            results = [f.result() for f in futures]

        assert len(results) == 20
        assert all(len(r) == 32 for r in results)
        # Each different input should produce different output
        assert len(set(results)) == 20

    def test_threaded_random(self, p11_session: Any) -> None:
        """Multiple threads generating random data concurrently."""

        def gen_random(_: int) -> bytes:
            return p11_session.generate_random(256)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(gen_random, i) for i in range(20)]
            results = [f.result() for f in futures]

        assert len(results) == 20
        assert all(len(r) == 32 for r in results)
        assert len(set(results)) == 20  # All unique

    def test_threaded_keygen_destroy(self, p11_session: Any) -> None:
        """Multiple threads generating and destroying keys concurrently."""

        def keygen_destroy(_: int) -> bool:
            key = p11_session.generate_key(KeyType.AES, 128)
            key.destroy()
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(keygen_destroy, i) for i in range(20)]
            results = [f.result() for f in futures]

        assert all(results)


class TestMultiSessionThreads:
    """Each thread opens its own session for independent operations."""

    def test_independent_sessions(self, p11_session: Any, p11_module: Any, p11_config: Any) -> None:
        """Each thread gets its own session and operates independently."""
        token = p11_module.get_token()

        def thread_work(thread_id: int) -> tuple[int, int, bytes]:
            # Open a new session per thread (reuse token-level login)
            session = token.open(rw=True)
            try:
                key = session.generate_key(KeyType.AES, 256)
                data = f"thread-{thread_id}-data!".encode().ljust(16, b"\x00")
                ct = key.encrypt(data, mechanism=Mechanism.AES_ECB)
                pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
                key.destroy()
                return (thread_id, len(ct), pt)
            finally:
                session.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(thread_work, i) for i in range(8)]
            results = [f.result() for f in futures]

        assert len(results) == 8
        for tid, ct_len, pt in results:
            expected = f"thread-{tid}-data!".encode().ljust(16, b"\x00")
            assert ct_len == 16
            assert pt == expected
