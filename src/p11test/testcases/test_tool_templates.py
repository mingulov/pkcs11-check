"""Default tool template tests and concurrent stress.

Tests key creation patterns used by common tools (pkcs11-tool, Java keytool)
and concurrent object operations.

References: Tookan paper (default templates), SoftHSM2 #845 (SQLite stress),
rep11.md Iteration 2 (session/object hidden failures).
"""

from __future__ import annotations

import concurrent.futures
import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import PKCS11Error

pytestmark = pytest.mark.security


class TestDefaultToolTemplates:
    """Test key templates that pkcs11-tool and Java keytool use (task 7.10)."""

    def test_pkcs11_tool_rsa_defaults(self, p11_session: Any) -> None:
        """pkcs11-tool RSA keygen defaults: sign+verify+encrypt+decrypt+wrap+unwrap.

        This is the Tookan-risky template that most tools use.
        Module should accept but ideally warn about security policy.
        """
        pub, priv = p11_session.generate_keypair(
            KeyType.RSA,
            2048,
            public_template={
                Attribute.ENCRYPT: True,
                Attribute.VERIFY: True,
                Attribute.WRAP: True,
            },
            private_template={
                Attribute.DECRYPT: True,
                Attribute.SIGN: True,
                Attribute.UNWRAP: True,
                Attribute.SENSITIVE: True,
                Attribute.EXTRACTABLE: False,
            },
        )
        # Key must work — this is the standard tool pattern
        data = b"tool-template-test"
        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_pkcs11_tool_aes_defaults(self, p11_session: Any) -> None:
        """pkcs11-tool AES keygen: encrypt+decrypt+wrap+unwrap."""
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            template={
                Attribute.ENCRYPT: True,
                Attribute.DECRYPT: True,
                Attribute.WRAP: True,
                Attribute.UNWRAP: True,
            },
        )
        ct = key.encrypt(b"\x00" * 16, mechanism=Mechanism.AES_ECB)
        pt = key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        assert pt == b"\x00" * 16


class TestConcurrentFindObjects:
    """FindObjects while other sessions modify objects (task 7.11)."""

    def test_find_during_sequential_create_destroy(self, p11_session: Any) -> None:
        """Sequential create/destroy interleaved with search — must not crash.

        Note: Truly concurrent multi-thread operations on a single PKCS#11
        session can segfault SoftHSM2 (SQLite concurrency, #845).
        This test uses sequential interleaving instead.
        """
        prefix = f"conc-find-{uuid.uuid4().hex[:6]}"
        for i in range(20):
            key = p11_session.generate_key(KeyType.AES, 128, label=f"{prefix}-{i}")
            # Search while objects exist
            found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
            assert len(found) >= 1
            key.destroy()

        # All destroyed
        found = list(p11_session.get_objects({Attribute.LABEL: f"{prefix}-0"}))
        assert len(found) == 0


class TestDBStress:
    """Database stress under sequential writes (task 7.12)."""

    def test_rapid_keygen_destroy_500(self, p11_session: Any) -> None:
        """500 key gen+destroy cycles. Tests SQLite transaction handling.

        Note: SoftHSM2 #845 — SQLite transaction errors under load.
        Concurrent multi-thread on same session causes segfaults.
        Sequential rapid cycles are safer and still catch DB issues.
        """
        for i in range(500):
            key = p11_session.generate_key(KeyType.AES, 128)
            key.destroy()
