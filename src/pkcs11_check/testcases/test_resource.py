"""Memory, handle, and resource safety tests.

Tests for leaks, exhaustion, use-after-destroy, and cleanup behavior.
These help catch bugs that only manifest under sustained load.
"""

from __future__ import annotations

from typing import Any

import pkcs11
import psutil
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.stress


def _get_rss_mb() -> float:
    """Get current process RSS in megabytes."""
    return psutil.Process().memory_info().rss / (1024 * 1024)  # type: ignore[no-any-return]


class TestMemoryLeaks:
    """Check for memory leaks during repeated operations."""

    def test_key_generation_no_leak(self, p11_session: Any) -> None:
        """Generate and destroy 1000 keys -- RSS should not grow significantly."""
        rss_before = _get_rss_mb()
        for _ in range(1000):
            key = p11_session.generate_key(KeyType.AES, 256)
            key.destroy()
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 key gen/destroy cycles"

    def test_encrypt_cycle_no_leak(self, p11_session: Any) -> None:
        """1000 encrypt/decrypt cycles -- RSS should not grow significantly."""
        key = p11_session.generate_key(KeyType.AES, 256)
        plaintext = b"leak test data!!"  # 16 bytes

        rss_before = _get_rss_mb()
        for _ in range(1000):
            ct = key.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
            key.decrypt(ct, mechanism=Mechanism.AES_ECB)
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 encrypt cycles"
        key.destroy()

    def test_digest_cycle_no_leak(self, p11_session: Any) -> None:
        """1000 digest operations -- no leak."""
        data = b"X" * 1024
        rss_before = _get_rss_mb()
        for _ in range(1000):
            p11_session.digest(data, mechanism=Mechanism.SHA256)
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 1000 digest cycles"


class TestUseAfterDestroy:
    """Verify that using destroyed objects fails cleanly (no crash)."""

    def test_encrypt_after_destroy(self, p11_session: Any) -> None:
        """Using a destroyed key for encryption must fail, not crash."""
        key = p11_session.generate_key(KeyType.AES, 256)
        key.destroy()
        with pytest.raises((pkcs11.exceptions.PKCS11Error, AttributeError)):
            key.encrypt(b"0123456789abcdef", mechanism=Mechanism.AES_ECB)

    def test_sign_after_destroy(self, p11_session: Any) -> None:
        """Using a destroyed key for signing must fail, not crash."""
        _, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        priv.destroy()
        with pytest.raises((pkcs11.exceptions.PKCS11Error, AttributeError)):
            priv.sign(b"data", mechanism=Mechanism.SHA256_RSA_PKCS)

    def test_double_destroy(self, p11_session: Any) -> None:
        """Destroying an already-destroyed object must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 128)
        key.destroy()
        try:
            key.destroy()  # Should fail or be no-op -- must not crash
        except pkcs11.exceptions.PKCS11Error:
            pass  # Expected

    def test_read_attribute_after_destroy(self, p11_session: Any) -> None:
        """Reading attributes of destroyed object must fail cleanly."""
        key = p11_session.generate_key(KeyType.AES, 256, label="destroy-attr")
        key.destroy()
        with pytest.raises((pkcs11.exceptions.PKCS11Error, AttributeError)):
            _ = key.label


class TestSessionChurn:
    """Test rapid session open/close cycles."""

    def test_rapid_session_cycles(self, p11_module: Any, p11_config: Any) -> None:
        """Open and close 100 sessions rapidly -- no leak or crash."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        rss_before = _get_rss_mb()
        for _ in range(100):
            try:
                with token.open(rw=True, user_pin=pin):
                    pass
            except (pkcs11.exceptions.UserAlreadyLoggedIn, pkcs11.exceptions.UserTypeInvalid):
                session = token.open(rw=True)
                session.close()
        rss_after = _get_rss_mb()
        growth = rss_after - rss_before
        assert growth < 50, f"RSS grew by {growth:.1f}MB during 100 session cycles"


class TestBulkOperations:
    """Test creating many objects simultaneously."""

    def test_100_keys_coexist(self, p11_session: Any) -> None:
        """Create 100 keys, verify all exist, then destroy all."""
        keys = []
        for i in range(100):
            key = p11_session.generate_key(KeyType.AES, 128, label=f"bulk100-{i:03d}")
            keys.append(key)

        # Verify all exist
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.SECRET_KEY}))
        assert len(found) >= 100

        # Destroy all
        for key in keys:
            key.destroy()

        # Verify cleanup
        found = list(p11_session.get_objects({Attribute.LABEL: "bulk100-000"}))
        assert len(found) == 0
