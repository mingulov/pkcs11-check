"""Token (persistent) object tests.

All other tests use TOKEN: False (session objects). These tests verify
that TOKEN: True objects persist across session close/reopen and have
correct visibility semantics.

Marked @destructive because they create persistent objects on the token.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism

pytestmark = [pytest.mark.keymgmt, pytest.mark.destructive]


def _unique_label() -> str:
    """Generate a unique label to avoid collisions across test runs."""
    return f"p11test-tok-{uuid.uuid4().hex[:8]}"


class TestTokenObjectLifecycle:
    """Create, find, use, and destroy persistent token objects."""

    def test_create_token_aes_key(self, p11_session: Any) -> None:
        """AES key with TOKEN=True is created and findable."""
        label = _unique_label()
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            label=label,
            template={Attribute.TOKEN: True},
        )
        assert key is not None
        assert key[Attribute.TOKEN] is True

        # Findable by label
        found = list(p11_session.get_objects({Attribute.LABEL: label}))
        assert len(found) >= 1

        # Cleanup
        key.destroy()

    def test_token_object_survives_session(self, p11_module: Any, p11_config: Any) -> None:
        """Token object created in one session is visible in a new session."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label()

        # Session 1: create
        with token.open(rw=True, user_pin=pin_str) as session1:
            session1.generate_key(
                KeyType.AES,
                256,
                label=label,
                template={Attribute.TOKEN: True},
            )

        # Session 2: find
        with token.open(rw=True, user_pin=pin_str) as session2:
            found = list(session2.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1, f"Token object '{label}' not found in new session"

            # Cleanup
            for obj in found:
                obj.destroy()

    def test_token_key_usable_across_sessions(self, p11_module: Any, p11_config: Any) -> None:
        """Token key created in session A can encrypt in session B."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label()
        plaintext = b"persistent key!!"  # 16 bytes

        # Session 1: create + encrypt
        with token.open(rw=True, user_pin=pin_str) as s1:
            key1 = s1.generate_key(
                KeyType.AES,
                256,
                label=label,
                template={Attribute.TOKEN: True, Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
            )
            ct = key1.encrypt(plaintext, mechanism=Mechanism.AES_ECB)

        # Session 2: find + decrypt
        with token.open(rw=True, user_pin=pin_str) as s2:
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) >= 1
            key2 = found[0]
            pt = key2.decrypt(ct, mechanism=Mechanism.AES_ECB)
            assert pt == plaintext

            key2.destroy()

    def test_session_object_not_visible_after_close(self, p11_module: Any, p11_config: Any) -> None:
        """Session object (TOKEN=False) disappears when session closes."""
        token = p11_module.get_token()
        pin = p11_config.pin
        pin_str = pin.get_secret_value() if hasattr(pin, "get_secret_value") else str(pin)
        label = _unique_label()

        # Session 1: create session object
        with token.open(rw=True, user_pin=pin_str) as s1:
            s1.generate_key(KeyType.AES, 256, label=label)
            # Visible in same session
            assert len(list(s1.get_objects({Attribute.LABEL: label}))) >= 1

        # Session 2: should NOT be visible
        with token.open(rw=True, user_pin=pin_str) as s2:
            found = list(s2.get_objects({Attribute.LABEL: label}))
            assert len(found) == 0, "Session object survived session close"

    def test_destroy_token_object(self, p11_session: Any) -> None:
        """Destroying a token object removes it permanently."""
        label = _unique_label()
        key = p11_session.generate_key(
            KeyType.AES,
            256,
            label=label,
            template={Attribute.TOKEN: True},
        )
        key.destroy()

        found = list(p11_session.get_objects({Attribute.LABEL: label}))
        assert len(found) == 0


class TestTokenObjectAttributes:
    """Verify attributes of token objects."""

    def test_token_flag_readable(self, p11_session: Any) -> None:
        """CKA_TOKEN attribute is True for token objects, False for session."""
        label_tok = _unique_label()
        label_ses = _unique_label()

        tok_key = p11_session.generate_key(
            KeyType.AES,
            256,
            label=label_tok,
            template={Attribute.TOKEN: True},
        )
        ses_key = p11_session.generate_key(KeyType.AES, 256, label=label_ses)

        assert tok_key[Attribute.TOKEN] is True
        assert ses_key[Attribute.TOKEN] is False

        tok_key.destroy()
