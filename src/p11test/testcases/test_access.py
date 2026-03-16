"""Tests for PKCS#11 session types, login states, and access control.

Covers the session/login matrix from the OASIS specification:
R/O vs R/W sessions, public vs user vs SO login states,
object visibility rules, and session lifecycle.
"""

from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.access


class TestSessionTypes:
    """Test R/O and R/W session behavior differences."""

    def test_rw_session_can_generate_key(self, p11_session: Any) -> None:
        """R/W session (our default fixture) can generate keys."""
        key = p11_session.generate_key(KeyType.AES, 256)
        assert key is not None
        key.destroy()

    def test_ro_session_can_create_session_objects(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session can create session objects (not token objects).

        Per PKCS#11 spec, R/O sessions restrict token object modification,
        but session objects are allowed.
        """
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        with token.open(rw=False, user_pin=pin) as ro_session:
            # Session objects should be creatable in R/O sessions
            key = ro_session.generate_key(KeyType.AES, 256)
            assert key is not None
            key.destroy()

    def test_ro_session_can_read(self, p11_module: Any, p11_config: Any) -> None:
        """R/O session can still read objects and generate random."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None
        with token.open(rw=False, user_pin=pin) as ro_session:
            random_data = ro_session.generate_random(256)
            assert len(random_data) == 32


class TestLoginStates:
    """Test behavior in different login states."""

    def test_public_session_no_private_keys(self, p11_module: Any) -> None:
        """Without login, private objects should not be visible."""
        token = p11_module.get_token()
        with token.open(rw=False) as pub_session:
            priv_keys = list(pub_session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
            # Should be empty (no login = no access to private objects)
            assert len(priv_keys) == 0

    def test_user_session_can_see_private(self, p11_session: Any) -> None:
        """Logged-in user session can create and find private objects."""
        # Create a keypair (private key is a private object)
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        assert priv is not None

        # Should be findable
        found = list(p11_session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}))
        assert len(found) >= 1

        pub.destroy()
        priv.destroy()


class TestMultipleSessions:
    """Test behavior with multiple concurrent sessions."""

    def test_two_sessions_independent(self, p11_module: Any, p11_config: Any) -> None:
        """Two sessions can operate independently."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        with token.open(rw=True, user_pin=pin) as session1:
            # Second session: don't re-login (already logged in on this token)
            with token.open(rw=True) as session2:
                key1 = session1.generate_key(KeyType.AES, 128, label="sess1")
                key2 = session2.generate_key(KeyType.AES, 128, label="sess2")
                assert key1 is not None
                assert key2 is not None
                key1.destroy()
                key2.destroy()

    def test_session_object_visible_in_other_session(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Session objects created in one session are visible in another.

        Per PKCS#11 spec, session objects are visible to all sessions of the
        same application on the same token.
        """
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        with token.open(rw=True, user_pin=pin) as session1:
            key = session1.generate_key(KeyType.AES, 128, label="session-obj-test")
            with token.open(rw=True) as session2:
                found = list(session2.get_objects({Attribute.LABEL: "session-obj-test"}))
                assert len(found) >= 1  # Should be visible
            key.destroy()


class TestSessionLifecycle:
    """Test session object lifetime behavior."""

    def test_session_object_destroyed_on_close(self, p11_module: Any, p11_config: Any) -> None:
        """Session objects should be destroyed when session closes."""
        token = p11_module.get_token(p11_config.slot)
        pin = p11_config.pin.get_secret_value() if p11_config.pin else None

        # Create object in a session, then close it
        with token.open(rw=True, user_pin=pin) as temp_session:
            temp_session.generate_key(KeyType.AES, 128, label="lifecycle-test")

        # Object should be gone in a new session
        with token.open(rw=True, user_pin=pin) as new_session:
            found = list(new_session.get_objects({Attribute.LABEL: "lifecycle-test"}))
            assert len(found) == 0
