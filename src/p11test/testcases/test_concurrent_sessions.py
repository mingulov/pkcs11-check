"""Concurrent session attack tests.

Verifies that PKCS#11 modules handle multiple sessions safely:
- Two sessions operating on the same object concurrently
- Create/destroy races
- Object visibility across concurrent sessions
- Session isolation of session objects

Note: PKCS#11 login is per-token (not per-session). A second session
opened while logged in on the same token shares the login state.
We open the second session RW without re-logging.
"""

from __future__ import annotations

import uuid
from typing import Any

import pkcs11 as p11
import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

pytestmark = pytest.mark.security


def _unique_label(prefix: str = "conc") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _open_second_session(token: Any, pin_str: str) -> Any:
    """Open a second RW session, handling already-logged-in gracefully."""
    session = token.open(rw=True)
    try:
        session.login(p11.UserType.USER, pin_str)
    except (p11.exceptions.UserAlreadyLoggedIn, p11.exceptions.UserTypeInvalid):
        pass  # Expected — token-level login already active
    return session


class TestConcurrentSessions:
    """Two sessions operating concurrently on the same token."""

    def test_two_sessions_see_same_token_object(self, p11_module: Any, p11_config: Any) -> None:
        """Object created in session A with TOKEN=True is visible in session B."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label("vis")

        with token.open(rw=True, user_pin=pin_str) as s1:
            s1.generate_key(
                KeyType.AES,
                256,
                label=label,
                template={Attribute.TOKEN: True},
            )

            # Open a second session (already logged in at token level)
            s2 = _open_second_session(token, pin_str)
            try:
                found = list(s2.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1, "Token object not visible in concurrent session"
            finally:
                s2.close()

            # Cleanup
            for obj in s1.get_objects({Attribute.LABEL: label}):
                obj.destroy()

    def test_destroy_in_one_session_reflected_in_other(
        self, p11_module: Any, p11_config: Any
    ) -> None:
        """Destroying a token object in session A is reflected in session B."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label("destr")

        with token.open(rw=True, user_pin=pin_str) as s1:
            key = s1.generate_key(
                KeyType.AES,
                256,
                label=label,
                template={Attribute.TOKEN: True},
            )

            s2 = _open_second_session(token, pin_str)
            try:
                # Visible in s2
                found = list(s2.get_objects({Attribute.LABEL: label}))
                assert len(found) >= 1

                # Destroy in s1
                key.destroy()

                # Should be gone in s2
                found = list(s2.get_objects({Attribute.LABEL: label}))
                assert len(found) == 0, "Destroyed object still visible in other session"
            finally:
                s2.close()

    def test_use_key_from_concurrent_session(self, p11_module: Any, p11_config: Any) -> None:
        """Token key created in session A can be used for crypto in session B."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label("use")
        plaintext = b"concurrent-test!" * 2  # 32 bytes

        with token.open(rw=True, user_pin=pin_str) as s1:
            s1.generate_key(
                KeyType.AES,
                256,
                label=label,
                template={
                    Attribute.TOKEN: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                },
            )

            s2 = _open_second_session(token, pin_str)
            try:
                keys = list(s2.get_objects({Attribute.LABEL: label}))
                assert len(keys) >= 1
                key2 = keys[0]

                ct = key2.encrypt(plaintext, mechanism=Mechanism.AES_ECB)
                pt = key2.decrypt(ct, mechanism=Mechanism.AES_ECB)
                assert pt == plaintext
            finally:
                s2.close()

            # Cleanup
            for obj in s1.get_objects({Attribute.LABEL: label}):
                obj.destroy()


class TestConcurrentObjectCreation:
    """Test rapid object creation/destruction across sessions."""

    def test_rapid_create_destroy_cycle(self, p11_module: Any, p11_config: Any) -> None:
        """Create and immediately destroy objects in rapid succession — no leak."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        with token.open(rw=True, user_pin=pin_str) as session:
            labels = []
            for i in range(20):
                label = _unique_label(f"rapid-{i}")
                labels.append(label)
                key = session.generate_key(
                    KeyType.AES,
                    128,
                    label=label,
                    template={Attribute.TOKEN: True},
                )
                key.destroy()

            # Verify none leaked
            for label in labels:
                found = list(session.get_objects({Attribute.LABEL: label}))
                assert len(found) == 0, f"Object '{label}' leaked after destroy"

    def test_create_in_both_sessions_no_conflict(self, p11_module: Any, p11_config: Any) -> None:
        """Creating objects in two concurrent sessions doesn't cause conflicts."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)

        label_a = _unique_label("sA")
        label_b = _unique_label("sB")

        with token.open(rw=True, user_pin=pin_str) as s1:
            s2 = _open_second_session(token, pin_str)
            try:
                key_a = s1.generate_key(
                    KeyType.AES,
                    128,
                    label=label_a,
                    template={Attribute.TOKEN: True},
                )
                key_b = s2.generate_key(
                    KeyType.AES,
                    128,
                    label=label_b,
                    template={Attribute.TOKEN: True},
                )

                # Both should be visible in both sessions
                found_a = list(s2.get_objects({Attribute.LABEL: label_a}))
                found_b = list(s1.get_objects({Attribute.LABEL: label_b}))
                assert len(found_a) >= 1
                assert len(found_b) >= 1

                key_a.destroy()
                key_b.destroy()
            finally:
                s2.close()


class TestConcurrentDataObjects:
    """Test CKO_DATA objects across concurrent sessions."""

    def test_data_object_visible_across_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """CKO_DATA with TOKEN=True visible in concurrent session."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label("data")

        with token.open(rw=True, user_pin=pin_str) as s1:
            s1.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: label,
                    Attribute.VALUE: b"shared-data",
                    Attribute.TOKEN: True,
                }
            )

            s2 = _open_second_session(token, pin_str)
            try:
                found = list(
                    s2.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
                )
                assert len(found) >= 1
                assert found[0][Attribute.VALUE] == b"shared-data"
            finally:
                s2.close()

            # Cleanup
            for obj in s1.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}):
                obj.destroy()
